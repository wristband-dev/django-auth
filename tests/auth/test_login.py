from unittest.mock import patch

import pytest
from django.conf import settings
from django.http import HttpResponse
from django.test import RequestFactory

from tests.utilities import (
    assert_authorize_query_params,
    assert_redirect_no_cache,
    assert_single_login_cookie_valid,
    decrypt_login_state,
    test_login_state_secret,
)
from wristband.django_auth.auth import WristbandAuth
from wristband.django_auth.models import AuthConfig, LoginConfig, LoginState, OAuthAuthorizeUrlConfig

# Configure Django settings for tests
urlpatterns = []
if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY="test-secret-key-for-testing-purposes-only",
        USE_TZ=True,
        DEFAULT_CHARSET="utf-8",
        USE_I18N=False,
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF=__name__,
    )


class TestWristbandAuthLogin:
    """Test cases for WristbandAuth login method."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            scopes=["openid", "offline_access", "email"],
            auto_configure_enabled=False,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)
        self.factory = RequestFactory()

    def test_login_with_no_tenant_info_redirects_to_app_login(self) -> None:
        """Test login redirects to app-level login when no tenant info is available."""
        request = self.factory.get("/login")
        response = self.wristband_auth.login(request)

        # Validate redirect response
        expected_url = f"https://{self.auth_config.wristband_application_vanity_domain}/login"
        _, query_params = assert_redirect_no_cache(response, expected_url)
        assert query_params["client_id"] == [self.auth_config.client_id]

        # Ensure no login state cookies are set
        login_cookies = [(key, response.cookies[key]) for key in response.cookies.keys() if key.startswith("login#")]
        assert len(login_cookies) == 0, f"Expected 0 login cookies, found {len(login_cookies)}"

    def test_login_with_custom_application_login_page_url(self) -> None:
        """Test login uses custom application login page URL when configured and no tenant info available."""
        custom_url = "https://custom.example.com/login"
        config_with_custom = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            custom_application_login_page_url=custom_url,
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_with_custom)

        request = self.factory.get("/login")
        response = wristband_auth.login(request)

        # Validate redirect response
        expected_url = f"{custom_url}?client_id={config_with_custom.client_id}"
        _, query_params = assert_redirect_no_cache(response, expected_url)
        assert query_params["client_id"] == [self.auth_config.client_id]

        # Ensure no login state cookies are set
        login_cookies = [(key, response.cookies[key]) for key in response.cookies.keys() if key.startswith("login#")]
        assert len(login_cookies) == 0, f"Expected 0 login cookies, found {len(login_cookies)}"

    def test_login_with_tenant_name_creates_oauth_url(self) -> None:
        """Test login creates full OAuth URL when tenant name is available."""
        request = self.factory.get("/login?tenant_name=test-tenant")
        response = self.wristband_auth.login(request)

        # Validate redirect response
        expected_url = "https://test-tenant-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(query_params, "test_client_id", "https://app.example.com/callback")

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)

    def test_login_with_login_config_custom_state(self) -> None:
        """Test login passes custom state from LoginConfig."""
        request = self.factory.get("/login?tenant_name=test-tenant")
        custom_state = {"user_preference": "dark_mode"}
        login_config = LoginConfig(custom_state=custom_state)

        response = self.wristband_auth.login(request, login_config)

        # Validate redirect response
        expected_url = "https://test-tenant-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(query_params, "test_client_id", "https://app.example.com/callback")

        # Validate login state cookie is set
        _, cookie_value = assert_single_login_cookie_valid(response)

        # Validate custom state
        login_state = decrypt_login_state(cookie_value)
        assert login_state
        assert login_state.code_verifier
        assert login_state.state
        assert login_state.redirect_uri == "https://app.example.com/callback"
        assert login_state.return_url is None
        assert login_state.custom_state
        assert login_state.custom_state["user_preference"] == "dark_mode"

    def test_login_with_tenant_custom_domain_param(self) -> None:
        """01: Test login uses tenant custom domain from params as top priority."""
        request = self.factory.get(
            "/login?tenant_name=tenantA&tenant_custom_domain=tenantA.custom.com", HTTP_HOST="sub.custom.com"
        )
        login_config = LoginConfig(
            default_tenant_name="default-tenant",
            default_tenant_custom_domain="default.custom.com",
        )

        response = self.wristband_auth.login(request, login_config)

        # Validate redirect response
        expected_url = "https://tenantA.custom.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(query_params, "test_client_id", "https://app.example.com/callback")

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)

    def test_login_with_tenant_subdomain(self) -> None:
        """02a: Test login uses tenant subdomain as 2nd top priority."""
        temp_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_name}.auth.example.com/login",
            redirect_uri="https://{tenant_name}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="custom.com",
            scopes=["openid", "email"],
            auto_configure_enabled=False,
        )
        temp_wristband_auth = WristbandAuth(temp_config)

        request = self.factory.get("/login?tenant_name=tenantA", HTTP_HOST="sub.custom.com")
        login_config = LoginConfig(
            default_tenant_name="default-tenant",
            default_tenant_custom_domain="default.custom.com",
        )

        response = temp_wristband_auth.login(request, login_config)

        # Validate redirect response
        expected_url = "https://sub-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(
            query_params, "test_client_id", "https://{tenant_name}.app.example.com/callback", "openid email"
        )

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)

    def test_login_with_tenant_name_param(self) -> None:
        """02b: Test login uses tenant name param as next priority."""
        request = self.factory.get("/login?tenant_name=tenantA")
        login_config = LoginConfig(
            default_tenant_name="default-tenant",
            default_tenant_custom_domain="default.custom.com",
        )

        response = self.wristband_auth.login(request, login_config)

        # Validate redirect response
        expected_url = "https://tenantA-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(query_params, "test_client_id", "https://app.example.com/callback")

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)

    def test_login_with_default_tenant_custom_domain(self) -> None:
        """Test login uses default tenant custom domain from LoginConfig."""
        request = self.factory.get("/login")
        login_config = LoginConfig(
            default_tenant_name="default-tenant",
            default_tenant_custom_domain="default.custom.com",
        )

        response = self.wristband_auth.login(request, login_config)

        # Validate redirect response
        expected_url = "https://default.custom.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(query_params, "test_client_id", "https://app.example.com/callback")

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)

    def test_login_with_default_tenant_name_only(self) -> None:
        """Test login uses default tenant name from LoginConfig when no other tenant values found."""
        request = self.factory.get("/login")
        login_config = LoginConfig(
            default_tenant_name="default-tenant",
        )

        response = self.wristband_auth.login(request, login_config)

        # Validate redirect response
        expected_url = "https://default-tenant-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(query_params, "test_client_id", "https://app.example.com/callback")

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)

    def test_login_with_return_url_from_login_config_takes_precedence(self) -> None:
        """Test that LoginConfig return_url takes precedence over query parameter."""
        request = self.factory.get("/login?tenant_name=test-tenant&return_url=https://query.example.com/dashboard")
        login_config = LoginConfig(return_url="https://config.example.com/preferred")

        response = self.wristband_auth.login(request, login_config)

        # Validate redirect response
        expected_url = "https://test-tenant-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(query_params, "test_client_id", "https://app.example.com/callback")

        # Validate login state cookie contains LoginConfig return_url, not query param
        _, cookie_value = assert_single_login_cookie_valid(response)
        login_state = decrypt_login_state(cookie_value)
        assert login_state.return_url == "https://config.example.com/preferred"

    def test_login_with_return_url_from_query_param_when_no_config(self) -> None:
        """Test that query parameter return_url is used when LoginConfig return_url is None."""
        request = self.factory.get("/login?tenant_name=test-tenant&return_url=https://query.example.com/dashboard")
        login_config = LoginConfig()  # return_url is None by default

        response = self.wristband_auth.login(request, login_config)

        # Validate redirect response
        expected_url = "https://test-tenant-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(query_params, "test_client_id", "https://app.example.com/callback")

        # Validate login state cookie contains query param return_url
        _, cookie_value = assert_single_login_cookie_valid(response)
        login_state = decrypt_login_state(cookie_value)
        assert login_state.return_url == "https://query.example.com/dashboard"

    def test_login_with_empty_string_return_url_in_config_uses_query_param(self) -> None:
        """Test that empty string return_url in LoginConfig falls back to query param (falsy behavior)."""
        request = self.factory.get("/login?tenant_name=test-tenant&return_url=https://query.example.com/dashboard")
        login_config = LoginConfig(return_url="")  # Empty string is falsy

        response = self.wristband_auth.login(request, login_config)

        # Validate login state cookie - empty string is falsy, so query param is used
        _, cookie_value = assert_single_login_cookie_valid(response)
        login_state = decrypt_login_state(cookie_value)
        assert login_state.return_url == "https://query.example.com/dashboard"

    def test_login_with_no_return_url_anywhere(self) -> None:
        """Test that no return_url is set when neither LoginConfig nor query param provide it."""
        request = self.factory.get("/login?tenant_name=test-tenant")
        login_config = LoginConfig()  # return_url is None

        response = self.wristband_auth.login(request, login_config)

        # Validate login state cookie has no return_url
        _, cookie_value = assert_single_login_cookie_valid(response)
        login_state = decrypt_login_state(cookie_value)
        assert login_state.return_url is None


class TestWristbandAuthCreateLoginState:
    """Test cases for _create_login_state method."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)
        self.factory = RequestFactory()

    def test_create_login_state_with_return_url(self) -> None:
        """Test _create_login_state captures return_url from request."""
        request = self.factory.get("/login?return_url=https://app.example.com/dashboard")

        result = self.wristband_auth._create_login_state(
            request,
            self.auth_config.redirect_uri or "",
            None,  # custom_state
            None,  # return_url (will use query param)
        )

        assert result.return_url == "https://app.example.com/dashboard"
        assert result.redirect_uri == self.auth_config.redirect_uri
        assert result.state is not None
        assert result.code_verifier is not None

    def test_create_login_state_multiple_return_urls_raises_error(self) -> None:
        """Test _create_login_state raises error when multiple return_url params exist."""
        request = self.factory.get("/login?return_url=url1&return_url=url2")

        with pytest.raises(TypeError, match="More than one \\[return_url\\] query parameter was encountered"):
            self.wristband_auth._create_login_state(request, self.auth_config.redirect_uri or "", None, None)

    def test_create_login_state_no_return_url(self) -> None:
        """Test _create_login_state handles missing return_url."""
        request = self.factory.get("/login")

        result = self.wristband_auth._create_login_state(request, self.auth_config.redirect_uri or "", None, None)

        assert result.return_url is None
        assert result.redirect_uri == self.auth_config.redirect_uri

    def test_create_login_state_with_custom_state(self) -> None:
        """Test _create_login_state includes custom state."""
        request = self.factory.get("/login")
        custom_state = {"app": "test", "user": "123"}

        result = self.wristband_auth._create_login_state(
            request, self.auth_config.redirect_uri or "", custom_state, None
        )

        assert result.custom_state == custom_state


class TestWristbandAuthGenerateRandomString:
    """Test cases for _generate_random_string method."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)

    def test_generate_random_string_default_length(self) -> None:
        """Test _generate_random_string with default length."""
        result = self.wristband_auth._generate_random_string()

        assert len(result) == 32
        assert isinstance(result, str)

    def test_generate_random_string_custom_length(self) -> None:
        """Test _generate_random_string with custom length."""
        result = self.wristband_auth._generate_random_string(64)

        assert len(result) == 64
        assert isinstance(result, str)

    def test_generate_random_string_different_calls_produce_different_results(self) -> None:
        """Test that multiple calls produce different results."""
        result1 = self.wristband_auth._generate_random_string()
        result2 = self.wristband_auth._generate_random_string()

        assert result1 != result2


class TestWristbandAuthEncryptDecryptLoginState:
    """Test cases for login state encryption/decryption methods."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)

    def test_encrypt_decrypt_login_state_roundtrip(self) -> None:
        """Test encryption and decryption work together."""
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url="https://app.example.com/dashboard",
            custom_state={"key": "value"},
        )

        encrypted = self.wristband_auth._encrypt_login_state(login_state)
        decrypted = self.wristband_auth._decrypt_login_state(encrypted)

        assert decrypted.state == login_state.state
        assert decrypted.code_verifier == login_state.code_verifier
        assert decrypted.redirect_uri == login_state.redirect_uri
        assert decrypted.return_url == login_state.return_url
        assert decrypted.custom_state == login_state.custom_state

    def test_encrypt_login_state_exceeds_4kb_raises_error(self) -> None:
        """Test that encrypting login state raises error when resulting cookie exceeds 4kB."""
        # Create a login state with very large custom_state to exceed 4kB after encryption
        large_custom_state = {f"key_{i}": "x" * 200 for i in range(100)}  # Create large nested data

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url="https://app.example.com/dashboard",
            custom_state=large_custom_state,
        )

        with pytest.raises(TypeError, match="Login state cookie exceeds 4kB in size"):
            self.wristband_auth._encrypt_login_state(login_state)


class TestWristbandAuthGenerateCodeChallenge:
    """Test cases for _generate_code_challenge method."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)

    def test_generate_code_challenge_produces_consistent_result(self) -> None:
        """Test _generate_code_challenge produces consistent results for same input."""
        code_verifier = "test_code_verifier_123456789"

        result1 = self.wristband_auth._generate_code_challenge(code_verifier)
        result2 = self.wristband_auth._generate_code_challenge(code_verifier)

        assert result1 == result2
        assert isinstance(result1, str)
        assert len(result1) > 0

    def test_generate_code_challenge_different_inputs_produce_different_results(self) -> None:
        """Test different code verifiers produce different challenges."""
        result1 = self.wristband_auth._generate_code_challenge("verifier1")
        result2 = self.wristband_auth._generate_code_challenge("verifier2")

        assert result1 != result2


class TestWristbandAuthGetOAuthAuthorizeUrl:
    """Test cases for _get_oauth_authorize_url method."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            scopes=["openid", "email", "profile"],
            auto_configure_enabled=False,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)
        self.factory = RequestFactory()

    def test_get_oauth_authorize_url_with_tenant_custom_domain(self) -> None:
        """Test _get_oauth_authorize_url uses tenant custom domain when available."""
        request = self.factory.get("/login")

        oauth_config = OAuthAuthorizeUrlConfig(
            client_id="test_client_id",
            redirect_uri=self.auth_config.redirect_uri or "",
            code_verifier="test_verifier",
            scopes=["openid", "email", "profile"],
            state="test_state",
            tenant_custom_domain="custom.tenant.com",
            tenant_name="tenant1",
            default_tenant_custom_domain=None,
            default_tenant_name=None,
            is_application_custom_domain_active=False,
            wristband_application_vanity_domain="auth.example.com",
        )

        result = self.wristband_auth._get_oauth_authorize_url(request, oauth_config)

        assert result.startswith("https://custom.tenant.com/api/v1/oauth2/authorize")
        assert "client_id=test_client_id" in result
        assert "state=test_state" in result
        assert "scope=openid+email+profile" in result

    def test_get_oauth_authorize_url_with_tenant_name(self) -> None:
        """Test _get_oauth_authorize_url uses tenant name when custom domain not available."""
        request = self.factory.get("/login")

        oauth_config = OAuthAuthorizeUrlConfig(
            client_id="test_client_id",
            redirect_uri=self.auth_config.redirect_uri or "",
            code_verifier="test_verifier",
            scopes=["openid", "email", "profile"],
            state="test_state",
            tenant_custom_domain=None,
            tenant_name="tenant1",
            default_tenant_custom_domain=None,
            default_tenant_name=None,
            is_application_custom_domain_active=False,
            wristband_application_vanity_domain="auth.example.com",
        )

        result = self.wristband_auth._get_oauth_authorize_url(request, oauth_config)

        expected_domain = f"tenant1-{self.auth_config.wristband_application_vanity_domain}"
        assert result.startswith(f"https://{expected_domain}/api/v1/oauth2/authorize")

    def test_get_oauth_authorize_url_with_login_hint(self) -> None:
        """Test _get_oauth_authorize_url includes login_hint when present."""
        request = self.factory.get("/login?login_hint=user@example.com")

        oauth_config = OAuthAuthorizeUrlConfig(
            client_id="test_client_id",
            redirect_uri=self.auth_config.redirect_uri or "",
            code_verifier="test_verifier",
            scopes=["openid", "email", "profile"],
            state="test_state",
            tenant_custom_domain="custom.tenant.com",
            tenant_name=None,
            default_tenant_custom_domain=None,
            default_tenant_name=None,
            is_application_custom_domain_active=False,
            wristband_application_vanity_domain="auth.example.com",
        )

        result = self.wristband_auth._get_oauth_authorize_url(request, oauth_config)

        assert "login_hint=user%40example.com" in result

    def test_get_oauth_authorize_url_multiple_login_hints_raises_error(self) -> None:
        """Test _get_oauth_authorize_url raises error when multiple login_hint params exist."""
        request = self.factory.get("/login?login_hint=user1@example.com&login_hint=user2@example.com")

        oauth_config = OAuthAuthorizeUrlConfig(
            client_id="test_client_id",
            redirect_uri=self.auth_config.redirect_uri or "",
            code_verifier="test_verifier",
            scopes=["openid", "email", "profile"],
            state="test_state",
            tenant_custom_domain="custom.tenant.com",
            tenant_name=None,
            default_tenant_custom_domain=None,
            default_tenant_name=None,
            is_application_custom_domain_active=False,
            wristband_application_vanity_domain="auth.example.com",
        )

        with pytest.raises(TypeError, match="More than one \\[login_hint\\] query parameter was encountered"):
            self.wristband_auth._get_oauth_authorize_url(request, oauth_config)


class TestWristbandAuthCookieManagement:
    """Test cases for login state cookie management methods."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)
        self.factory = RequestFactory()

    def test_get_login_state_cookie_finds_matching_cookie(self) -> None:
        """Test _get_login_state_cookie finds cookie matching state parameter."""
        request = self.factory.get("/callback?state=test_state_123")
        request.COOKIES = {
            "login#test_state_123#1640995200000": "encrypted_data_1",
            "login#other_state#1640995201000": "encrypted_data_2",
            "unrelated_cookie": "unrelated_value",
        }

        cookie_name, cookie_value = self.wristband_auth._get_login_state_cookie(request)

        assert cookie_name == "login#test_state_123#1640995200000"
        assert cookie_value == "encrypted_data_1"

    def test_get_login_state_cookie_no_matching_cookie(self) -> None:
        """Test _get_login_state_cookie returns None when no matching cookie found."""
        request = self.factory.get("/callback?state=missing_state")
        request.COOKIES = {
            "login#other_state#1640995200000": "encrypted_data",
            "unrelated_cookie": "unrelated_value",
        }

        cookie_name, cookie_value = self.wristband_auth._get_login_state_cookie(request)

        assert cookie_name is None
        assert cookie_value is None

    def test_get_login_state_cookie_no_state_parameter(self) -> None:
        """Test _get_login_state_cookie handles missing state parameter."""
        request = self.factory.get("/callback")
        request.COOKIES = {"login#some_state#1640995200000": "encrypted_data"}

        cookie_name, cookie_value = self.wristband_auth._get_login_state_cookie(request)

        assert cookie_name is None
        assert cookie_value is None


class TestWristbandAuthBuildTenantLoginUrl:
    """Test cases for _build_tenant_login_url method."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)

    def test_build_tenant_login_url_with_subdomain_parsing(self) -> None:
        """Test _build_tenant_login_url with subdomain parsing enabled."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_name}.auth.example.com/login",
            redirect_uri="https://{tenant_name}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        result = wristband_auth._build_tenant_login_url(
            login_url="https://{tenant_name}.auth.example.com/login",
            tenant_name="tenant1",
            tenant_custom_domain=None,
            parse_tenant_from_root_domain="auth.example.com",
        )

        assert result == "https://tenant1.auth.example.com/login"

    def test_build_tenant_login_url_without_subdomain_parsing(self) -> None:
        """Test _build_tenant_login_url without subdomain parsing."""
        result = self.wristband_auth._build_tenant_login_url(
            login_url="https://auth.example.com/login",
            tenant_name="tenant1",
            tenant_custom_domain=None,
            parse_tenant_from_root_domain=None,
        )

        assert result == "https://auth.example.com/login?tenant_name=tenant1"

    def test_build_tenant_login_url_with_tenant_custom_domain(self) -> None:
        """Test _build_tenant_login_url adds tenant_custom_domain parameter."""
        result = self.wristband_auth._build_tenant_login_url(
            login_url="https://auth.example.com/login",
            tenant_name="tenant1",
            tenant_custom_domain="custom.tenant.com",
            parse_tenant_from_root_domain=None,
        )

        expected = "https://auth.example.com/login?tenant_name=tenant1&tenant_custom_domain=custom.tenant.com"
        assert result == expected


class TestWristbandAuthResolveTenantMethods:
    """Test cases for tenant resolution helper methods."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)
        self.factory = RequestFactory()

    def test_resolve_tenant_name_from_subdomain(self) -> None:
        """Test _resolve_tenant_name extracts tenant from subdomain."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_name}.auth.example.com/login",
            redirect_uri="https://{tenant_name}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = self.factory.get("/login")
        with patch.object(request, "get_host", return_value="tenant1.auth.example.com"):
            result = wristband_auth._resolve_tenant_name(request, "auth.example.com")

        assert result == "tenant1"

    def test_resolve_tenant_name_from_query_param(self) -> None:
        """Test _resolve_tenant_name gets tenant from query parameter."""
        request = self.factory.get("/login?tenant_name=tenant1")

        result = self.wristband_auth._resolve_tenant_name(request, None)

        assert result == "tenant1"

    def test_resolve_tenant_custom_domain_param_success(self) -> None:
        """Test _resolve_tenant_custom_domain_param extracts custom domain."""
        request = self.factory.get("/login?tenant_custom_domain=custom.tenant.com")

        result = self.wristband_auth._resolve_tenant_custom_domain_param(request)

        assert result == "custom.tenant.com"

    def test_resolve_tenant_custom_domain_param_missing(self) -> None:
        """Test _resolve_tenant_custom_domain_param returns None when parameter missing."""
        request = self.factory.get("/login")

        result = self.wristband_auth._resolve_tenant_custom_domain_param(request)

        assert result is None

    def test_resolve_tenant_name_from_subdomain_with_port(self) -> None:
        """Test _resolve_tenant_name extracts tenant from subdomain and strips port."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_name}.auth.example.com/login",
            redirect_uri="https://{tenant_name}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = self.factory.get("/login")
        with patch.object(request, "get_host", return_value="tenant1.auth.example.com:8080"):
            result = wristband_auth._resolve_tenant_name(request, "auth.example.com")

        assert result == "tenant1"

    def test_resolve_tenant_name_from_subdomain_with_https_port(self) -> None:
        """Test _resolve_tenant_name extracts tenant from subdomain and strips HTTPS port."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_name}.auth.example.com/login",
            redirect_uri="https://{tenant_name}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = self.factory.get("/login")
        with patch.object(request, "get_host", return_value="tenant1.auth.example.com:443"):
            result = wristband_auth._resolve_tenant_name(request, "auth.example.com")

        assert result == "tenant1"

    def test_resolve_tenant_name_from_subdomain_mismatched_root_domain(self) -> None:
        """Test _resolve_tenant_name returns None when root domain doesn't match."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_name}.auth.example.com/login",
            redirect_uri="https://{tenant_name}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = self.factory.get("/login")
        with patch.object(request, "get_host", return_value="tenant1.wrong.com"):
            result = wristband_auth._resolve_tenant_name(request, "auth.example.com")

        assert result is None

    def test_resolve_tenant_name_from_subdomain_no_subdomain(self) -> None:
        """Test _resolve_tenant_name returns None when no subdomain present."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_name}.auth.example.com/login",
            redirect_uri="https://{tenant_name}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = self.factory.get("/login")
        with patch.object(request, "get_host", return_value="auth.example.com"):
            result = wristband_auth._resolve_tenant_name(request, "auth.example.com")

        assert result is None

    def test_resolve_tenant_name_from_subdomain_no_dots(self) -> None:
        """Test _resolve_tenant_name returns None when hostname has no dots."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_name}.auth.example.com/login",
            redirect_uri="https://{tenant_name}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = self.factory.get("/login")
        with patch.object(request, "get_host", return_value="localhost"):
            result = wristband_auth._resolve_tenant_name(request, "auth.example.com")

        assert result is None

    def test_resolve_tenant_name_from_subdomain_with_port_and_no_dots(self) -> None:
        """Test _resolve_tenant_name returns None when hostname with port has no dots."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_name}.auth.example.com/login",
            redirect_uri="https://{tenant_name}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = self.factory.get("/login")
        with patch.object(request, "get_host", return_value="localhost:8080"):
            result = wristband_auth._resolve_tenant_name(request, "auth.example.com")

        assert result is None


class TestWristbandAuthAssertSingleParam:
    """Test cases for _assert_single_param helper method."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)
        self.factory = RequestFactory()

    def test_assert_single_param_single_value(self) -> None:
        """Test _assert_single_param returns single parameter value."""
        request = self.factory.get("/test?param=value")

        result = self.wristband_auth._assert_single_param(request, "param")

        assert result == "value"

    def test_assert_single_param_missing_value(self) -> None:
        """Test _assert_single_param returns None for missing parameter."""
        request = self.factory.get("/test")

        result = self.wristband_auth._assert_single_param(request, "param")

        assert result is None

    def test_assert_single_param_multiple_values_raises_error(self) -> None:
        """Test _assert_single_param raises error for duplicate parameters."""
        request = self.factory.get("/test?param=value1&param=value2")

        with pytest.raises(
            TypeError, match="More than one instance of the query parameter \\[param\\] was present in the request"
        ):
            self.wristband_auth._assert_single_param(request, "param")

    def test_assert_single_param_empty_value(self) -> None:
        """Test _assert_single_param handles empty parameter value."""
        request = self.factory.get("/test?param=")

        result = self.wristband_auth._assert_single_param(request, "param")

        assert result == ""


class TestClearOldestLoginStateCooie:
    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)
        self.factory = RequestFactory()

    def test_clear_oldest_login_state_cookie_with_fewer_than_three_cookies(self) -> None:
        """Test _clear_oldest_login_state_cookie does nothing when fewer than 3 login cookies exist."""

        request = self.factory.get("/login")
        request.COOKIES = {
            "login#state1#1640995200000": "encrypted_data_1",
            "login#state2#1640995201000": "encrypted_data_2",
            "unrelated_cookie": "unrelated_value",
        }
        response = HttpResponse()

        self.wristband_auth._clear_oldest_login_state_cookie(request, response, False)

        # No cookies should be cleared (max_age=0 means cleared)
        cleared_cookies = [key for key, cookie in response.cookies.items() if cookie.get("max-age") == 0]
        assert len(cleared_cookies) == 0

    def test_clear_oldest_login_state_cookie_clears_oldest_when_three_or_more(self) -> None:
        """Test _clear_oldest_login_state_cookie clears oldest cookies when 3+ exist."""
        request = self.factory.get("/login")
        request.COOKIES = {
            "login#state1#1640995200000": "encrypted_data_1",  # oldest
            "login#state2#1640995201000": "encrypted_data_2",  # middle
            "login#state3#1640995202000": "encrypted_data_3",  # newest
            "unrelated_cookie": "unrelated_value",
        }
        response = HttpResponse()

        self.wristband_auth._clear_oldest_login_state_cookie(request, response, False)

        # Only the oldest cookie should be cleared
        cleared_cookies = [key for key, cookie in response.cookies.items() if cookie.get("max-age") == 0]
        assert len(cleared_cookies) == 1
        assert "login#state1#1640995200000" in cleared_cookies

        # Verify the cleared cookie has correct attributes
        cleared_cookie = response.cookies["login#state1#1640995200000"]
        assert cleared_cookie.value == ""
        assert cleared_cookie.get("max-age") == 0
        assert cleared_cookie.get("path") == "/"
        assert cleared_cookie.get("httponly") is True
        assert cleared_cookie.get("secure") is True

    def test_clear_oldest_login_state_cookie_clears_multiple_old_cookies(self) -> None:
        """Test _clear_oldest_login_state_cookie clears multiple old cookies when more than 3 exist."""
        request = self.factory.get("/login")
        request.COOKIES = {
            "login#state1#1640995200000": "encrypted_data_1",  # oldest - should be cleared
            "login#state2#1640995201000": "encrypted_data_2",  # old - should be cleared
            "login#state3#1640995202000": "encrypted_data_3",  # middle - should be cleared
            "login#state4#1640995203000": "encrypted_data_4",  # second newest - should be kept
            "login#state5#1640995204000": "encrypted_data_5",  # newest - should be kept
            "unrelated_cookie": "unrelated_value",
        }
        response = HttpResponse()

        self.wristband_auth._clear_oldest_login_state_cookie(request, response, False)

        # The 3 oldest cookies should be cleared, keeping only the 2 newest
        cleared_cookies = [key for key, cookie in response.cookies.items() if cookie.get("max-age") == 0]
        assert len(cleared_cookies) == 3
        assert "login#state1#1640995200000" in cleared_cookies
        assert "login#state2#1640995201000" in cleared_cookies
        assert "login#state3#1640995202000" in cleared_cookies

    def test_clear_oldest_login_state_cookie_ignores_malformed_cookie_names(self) -> None:
        """Test _clear_oldest_login_state_cookie handles malformed login cookie names gracefully."""
        request = self.factory.get("/login")
        request.COOKIES = {
            "login#state1": "encrypted_data_1",  # missing timestamp
            "login#state2#invalid": "encrypted_data_2",  # invalid timestamp
            "login#state3#1640995202000": "encrypted_data_3",  # valid - oldest
            "login#state4#1640995203000": "encrypted_data_4",  # valid - middle
            "login#state5#1640995204000": "encrypted_data_5",  # valid - newest
        }
        response = HttpResponse()

        self.wristband_auth._clear_oldest_login_state_cookie(request, response, False)

        # Should only process cookies with valid timestamp format
        # With 5 total login cookies (>=3), it keeps 2 newest valid timestamps and clears the rest
        cleared_cookies = [key for key, cookie in response.cookies.items() if cookie.get("max-age") == 0]
        assert len(cleared_cookies) == 2
        assert "login#state3#1640995202000" in cleared_cookies
        assert "login#state4#1640995203000" in cleared_cookies

    def test_clear_oldest_login_state_cookie_with_secure_cookies_disabled(self) -> None:
        """Test _clear_oldest_login_state_cookie respects dangerously_disable_secure_cookies setting."""
        # Create config with secure cookies disabled
        insecure_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            dangerously_disable_secure_cookies=True,
            auto_configure_enabled=False,
        )
        insecure_auth = WristbandAuth(insecure_config)

        request = self.factory.get("/login")
        request.COOKIES = {
            "login#state1#1640995200000": "encrypted_data_1",
            "login#state2#1640995201000": "encrypted_data_2",
            "login#state3#1640995202000": "encrypted_data_3",
        }
        response = HttpResponse()

        insecure_auth._clear_oldest_login_state_cookie(request, response, True)

        # Verify the cleared cookie has secure=False
        cleared_cookies = [key for key, cookie in response.cookies.items() if cookie.get("max-age") == 0]
        assert len(cleared_cookies) == 1
        cleared_cookie = response.cookies[cleared_cookies[0]]
        # When secure=False, Django doesn't set the secure attribute, so it's falsy (empty string)
        assert not cleared_cookie.get("secure")

    def test_clear_oldest_login_state_cookie_ignores_non_login_cookies(self) -> None:
        """Test _clear_oldest_login_state_cookie only processes login state cookies."""
        request = self.factory.get("/login")
        request.COOKIES = {
            "login#state1#1640995200000": "encrypted_data_1",
            "login#state2#1640995201000": "encrypted_data_2",
            "login#state3#1640995202000": "encrypted_data_3",
            "session_id": "session_value",
            "csrf_token": "csrf_value",
            "other_login_like": "other_value",  # doesn't start with exact prefix
        }
        response = HttpResponse()

        self.wristband_auth._clear_oldest_login_state_cookie(request, response, False)

        # Only login state cookies should be considered
        cleared_cookies = [key for key, cookie in response.cookies.items() if cookie.get("max-age") == 0]
        assert len(cleared_cookies) == 1
        assert cleared_cookies[0].startswith("login#")

        # Non-login cookies should not be affected
        assert "session_id" not in cleared_cookies
        assert "csrf_token" not in cleared_cookies
        assert "other_login_like" not in cleared_cookies


class TestWristbandAuthLoginBackwardCompatibility:
    """Test cases for backward compatibility with {tenant_domain} placeholder in login."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()

    def test_login_with_tenant_domain_placeholder_in_login_url(self) -> None:
        """Test login works with {tenant_domain} placeholder in login_url."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            scopes=["openid", "offline_access", "email"],
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config)

        # Fixed: Use HTTP_HOST to provide subdomain when parse_tenant_from_root_domain is set
        request = self.factory.get("/login", HTTP_HOST="tenant1.auth.example.com")
        response = wristband_auth.login(request)

        # Validate redirect response uses tenant_name in subdomain
        expected_url = "https://tenant1-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(
            query_params, "test_client_id", "https://{tenant_domain}.app.example.com/callback"
        )

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)

    def test_login_with_tenant_domain_placeholder_and_subdomain_parsing(self) -> None:
        """Test login with {tenant_domain} placeholder extracts tenant from subdomain."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            scopes=["openid", "offline_access", "email"],
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config)

        request = self.factory.get("/login", HTTP_HOST="tenant1.auth.example.com")
        response = wristband_auth.login(request)

        # Validate redirect response substitutes {tenant_domain} with tenant1
        expected_url = "https://tenant1-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(
            query_params, "test_client_id", "https://{tenant_domain}.app.example.com/callback"
        )

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)

    def test_login_mixed_tenant_name_and_tenant_domain_placeholders(self) -> None:
        """Test login works when mixing {tenant_name} and {tenant_domain} placeholders."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_name}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            scopes=["openid", "offline_access", "email"],
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config)

        # Fixed: Use HTTP_HOST when parse_tenant_from_root_domain is set
        request = self.factory.get("/login", HTTP_HOST="tenant1.auth.example.com")
        response = wristband_auth.login(request)

        # Validate redirect response - both placeholders work
        expected_url = "https://tenant1-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params - redirect_uri uses {tenant_name}
        assert_authorize_query_params(query_params, "test_client_id", "https://{tenant_name}.app.example.com/callback")

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)

    def test_login_with_tenant_domain_and_custom_domain_param(self) -> None:
        """Test login with {tenant_domain} placeholder and tenant_custom_domain param."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            scopes=["openid", "offline_access", "email"],
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config)

        # tenant_custom_domain takes priority over subdomain
        request = self.factory.get(
            "/login?tenant_custom_domain=custom.tenant.com", HTTP_HOST="tenant1.auth.example.com"
        )
        response = wristband_auth.login(request)

        # Should use custom domain, not tenant subdomain
        expected_url = "https://custom.tenant.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(
            query_params, "test_client_id", "https://{tenant_domain}.app.example.com/callback"
        )

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)

    def test_login_with_tenant_domain_without_subdomain_parsing(self) -> None:
        """Test login with {tenant_domain} placeholder using tenant_name query param (no subdomain parsing)."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            # No parse_tenant_from_root_domain - uses tenant_name param
            scopes=["openid", "offline_access", "email"],
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config)

        request = self.factory.get("/login?tenant_name=tenant1")
        response = wristband_auth.login(request)

        # Should use tenant_name param to build URL
        expected_url = "https://tenant1-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(query_params, "test_client_id", "https://app.example.com/callback")

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)

    def test_build_tenant_login_url_with_tenant_domain_placeholder(self) -> None:
        """Test _build_tenant_login_url works with {tenant_domain} placeholder."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config)

        result = wristband_auth._build_tenant_login_url(
            login_url="https://{tenant_domain}.auth.example.com/login",
            tenant_name="tenant1",
            tenant_custom_domain=None,
            parse_tenant_from_root_domain="auth.example.com",
        )

        # {tenant_domain} should be substituted with tenant1
        assert result == "https://tenant1.auth.example.com/login"

    def test_oauth_authorize_url_with_tenant_domain_placeholder(self) -> None:
        """Test _get_oauth_authorize_url works with {tenant_domain} placeholder."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            scopes=["openid", "email", "profile"],
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config)

        request = self.factory.get("/login")

        oauth_config = OAuthAuthorizeUrlConfig(
            client_id="test_client_id",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            code_verifier="test_verifier",
            scopes=["openid", "email", "profile"],
            state="test_state",
            tenant_custom_domain=None,
            tenant_name="tenant1",
            default_tenant_custom_domain=None,
            default_tenant_name=None,
            is_application_custom_domain_active=False,
            wristband_application_vanity_domain="auth.example.com",
        )

        result = wristband_auth._get_oauth_authorize_url(request, oauth_config)

        # Should use tenant_name with separator
        expected_domain = "tenant1-auth.example.com"
        assert result.startswith(f"https://{expected_domain}/api/v1/oauth2/authorize")
        assert "client_id=test_client_id" in result
        assert "state=test_state" in result
