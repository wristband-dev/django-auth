from unittest.mock import patch

import pytest
from django.conf import settings
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

    def test_login_with_tenant_domain_creates_oauth_url(self) -> None:
        """Test login creates full OAuth URL when tenant domain is available."""
        request = self.factory.get("/login?tenant_domain=test-tenant")
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
        request = self.factory.get("/login?tenant_domain=test-tenant")
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
            "/login?tenant_domain=tenantA&tenant_custom_domain=tenantA.custom.com", HTTP_HOST="sub.custom.com"
        )
        login_config = LoginConfig(
            default_tenant_domain="default-tenant",
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
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="custom.com",
            scopes=["openid", "email"],
        )
        temp_wristband_auth = WristbandAuth(temp_config)

        request = self.factory.get("/login?tenant_domain=tenantA", HTTP_HOST="sub.custom.com")
        login_config = LoginConfig(
            default_tenant_domain="default-tenant",
            default_tenant_custom_domain="default.custom.com",
        )

        response = temp_wristband_auth.login(request, login_config)

        # Validate redirect response
        expected_url = "https://sub-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(
            query_params, "test_client_id", "https://{tenant_domain}.app.example.com/callback", "openid email"
        )

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)

    def test_login_with_tenant_domain_param(self) -> None:
        """02b: Test login uses tenant domain param as next priority."""
        request = self.factory.get("/login?tenant_domain=tenantA")
        login_config = LoginConfig(
            default_tenant_domain="default-tenant",
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
            default_tenant_domain="default-tenant",
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

    def test_login_with_default_tenant_domain_only(self) -> None:
        """Test login uses default tenant domain from LoginConfig when no other tenant values found."""
        request = self.factory.get("/login")
        login_config = LoginConfig(
            default_tenant_domain="default-tenant",
        )

        response = self.wristband_auth.login(request, login_config)

        # Validate redirect response
        expected_url = "https://default-tenant-auth.example.com/api/v1/oauth2/authorize"
        _, query_params = assert_redirect_no_cache(response, expected_url)

        # Validate query params
        assert_authorize_query_params(query_params, "test_client_id", "https://app.example.com/callback")

        # Validate login state cookie is set
        assert_single_login_cookie_valid(response)


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
        )
        self.wristband_auth = WristbandAuth(self.auth_config)
        self.factory = RequestFactory()

    def test_create_login_state_with_return_url(self) -> None:
        """Test _create_login_state captures return_url from request."""
        request = self.factory.get("/login?return_url=https://app.example.com/dashboard")

        result = self.wristband_auth._create_login_state(request, None)

        assert result.return_url == "https://app.example.com/dashboard"
        assert result.redirect_uri == self.auth_config.redirect_uri
        assert result.state is not None
        assert result.code_verifier is not None

    def test_create_login_state_multiple_return_urls_raises_error(self) -> None:
        """Test _create_login_state raises error when multiple return_url params exist."""
        request = self.factory.get("/login?return_url=url1&return_url=url2")

        with pytest.raises(TypeError, match="More than one \\[return_url\\] query parameter was encountered"):
            self.wristband_auth._create_login_state(request, None)

    def test_create_login_state_no_return_url(self) -> None:
        """Test _create_login_state handles missing return_url."""
        request = self.factory.get("/login")

        result = self.wristband_auth._create_login_state(request, None)

        assert result.return_url is None
        assert result.redirect_uri == self.auth_config.redirect_uri

    def test_create_login_state_with_custom_state(self) -> None:
        """Test _create_login_state includes custom state."""
        request = self.factory.get("/login")
        custom_state = {"app": "test", "user": "123"}

        result = self.wristband_auth._create_login_state(request, custom_state)

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
        )
        self.wristband_auth = WristbandAuth(self.auth_config)
        self.factory = RequestFactory()

    def test_get_oauth_authorize_url_with_tenant_custom_domain(self) -> None:
        """Test _get_oauth_authorize_url uses tenant custom domain when available."""
        request = self.factory.get("/login")
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri=self.auth_config.redirect_uri,
            return_url=None,
            custom_state=None,
        )
        oauth_config = OAuthAuthorizeUrlConfig(
            login_state=login_state,
            tenant_custom_domain="custom.tenant.com",
            tenant_domain_name="tenant1",
            default_tenant_custom_domain=None,
            default_tenant_domain_name=None,
        )

        result = self.wristband_auth._get_oauth_authorize_url(request, oauth_config)

        assert result.startswith("https://custom.tenant.com/api/v1/oauth2/authorize")
        assert "client_id=test_client_id" in result
        assert "state=test_state" in result
        assert "scope=openid+email+profile" in result

    def test_get_oauth_authorize_url_with_tenant_domain_name(self) -> None:
        """Test _get_oauth_authorize_url uses tenant domain name when custom domain not available."""
        request = self.factory.get("/login")
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri=self.auth_config.redirect_uri,
            return_url=None,
            custom_state=None,
        )
        oauth_config = OAuthAuthorizeUrlConfig(
            login_state=login_state,
            tenant_custom_domain=None,
            tenant_domain_name="tenant1",
            default_tenant_custom_domain=None,
            default_tenant_domain_name=None,
        )

        result = self.wristband_auth._get_oauth_authorize_url(request, oauth_config)

        expected_domain = f"tenant1-{self.auth_config.wristband_application_vanity_domain}"
        assert result.startswith(f"https://{expected_domain}/api/v1/oauth2/authorize")

    def test_get_oauth_authorize_url_with_login_hint(self) -> None:
        """Test _get_oauth_authorize_url includes login_hint when present."""
        request = self.factory.get("/login?login_hint=user@example.com")
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri=self.auth_config.redirect_uri,
            return_url=None,
            custom_state=None,
        )
        oauth_config = OAuthAuthorizeUrlConfig(
            login_state=login_state,
            tenant_custom_domain="custom.tenant.com",
            tenant_domain_name=None,
            default_tenant_custom_domain=None,
            default_tenant_domain_name=None,
        )

        result = self.wristband_auth._get_oauth_authorize_url(request, oauth_config)

        assert "login_hint=user%40example.com" in result

    def test_get_oauth_authorize_url_multiple_login_hints_raises_error(self) -> None:
        """Test _get_oauth_authorize_url raises error when multiple login_hint params exist."""
        request = self.factory.get("/login?login_hint=user1@example.com&login_hint=user2@example.com")
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri=self.auth_config.redirect_uri,
            return_url=None,
            custom_state=None,
        )
        oauth_config = OAuthAuthorizeUrlConfig(
            login_state=login_state,
            tenant_custom_domain="custom.tenant.com",
            tenant_domain_name=None,
            default_tenant_custom_domain=None,
            default_tenant_domain_name=None,
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
        )
        self.wristband_auth = WristbandAuth(self.auth_config)

    def test_build_tenant_login_url_with_subdomain_parsing(self) -> None:
        """Test _build_tenant_login_url with subdomain parsing enabled."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        result = wristband_auth._build_tenant_login_url("tenant1")

        assert result == "https://tenant1.auth.example.com/login"

    def test_build_tenant_login_url_without_subdomain_parsing(self) -> None:
        """Test _build_tenant_login_url without subdomain parsing."""
        result = self.wristband_auth._build_tenant_login_url("tenant1")

        assert result == "https://auth.example.com/login?tenant_domain=tenant1"

    def test_build_tenant_login_url_with_tenant_custom_domain(self) -> None:
        """Test _build_tenant_login_url adds tenant_custom_domain parameter."""
        result = self.wristband_auth._build_tenant_login_url("tenant1", "custom.tenant.com")

        expected = "https://auth.example.com/login?tenant_domain=tenant1&tenant_custom_domain=custom.tenant.com"
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
        )
        self.wristband_auth = WristbandAuth(self.auth_config)
        self.factory = RequestFactory()

    def test_resolve_tenant_domain_name_from_subdomain(self) -> None:
        """Test _resolve_tenant_domain_name extracts tenant from subdomain."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = self.factory.get("/login")
        with patch.object(request, "get_host", return_value="tenant1.auth.example.com"):
            result = wristband_auth._resolve_tenant_domain_name(request)

        assert result == "tenant1"

    def test_resolve_tenant_domain_name_from_query_param(self) -> None:
        """Test _resolve_tenant_domain_name gets tenant from query parameter."""
        request = self.factory.get("/login?tenant_domain=tenant1")

        result = self.wristband_auth._resolve_tenant_domain_name(request)

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
            TypeError, match="Duplicate query parameter \\[param\\] passed from Wristband during callback"
        ):
            self.wristband_auth._assert_single_param(request, "param")

    def test_assert_single_param_empty_value(self) -> None:
        """Test _assert_single_param handles empty parameter value."""
        request = self.factory.get("/test?param=")

        result = self.wristband_auth._assert_single_param(request, "param")

        assert result == ""
