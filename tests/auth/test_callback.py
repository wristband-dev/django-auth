from unittest.mock import patch

import pytest
from django.conf import settings
from django.test import RequestFactory

from tests.utilities import (
    test_login_state_secret,
)
from wristband.django_auth.auth import WristbandAuth
from wristband.django_auth.exceptions import InvalidGrantError, WristbandError
from wristband.django_auth.models import (
    AuthConfig,
    CallbackFailureReason,
    CompletedCallbackResult,
    LoginState,
    RedirectRequiredCallbackResult,
    UserInfo,
    WristbandTokenResponse,
)

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


class TestWristbandAuthCallback:
    """Test cases for WristbandAuth callback method."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            token_expiration_buffer=60,
            auto_configure_enabled=False,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)
        self.factory = RequestFactory()

    def test_callback_missing_state_raises_error(self) -> None:
        """Test callback raises TypeError when state parameter is missing."""
        request = self.factory.get("/callback?code=auth_code&tenant_name=tenant1")

        with pytest.raises(
            TypeError, match="Invalid query parameter \\[state\\] passed from Wristband during callback"
        ):
            self.wristband_auth.callback(request)

    def test_callback_empty_state_raises_error(self) -> None:
        """Test callback raises TypeError when state parameter is empty."""
        request = self.factory.get("/callback?code=auth_code&state=&tenant_name=tenant1")

        with pytest.raises(
            TypeError, match="Invalid query parameter \\[state\\] passed from Wristband during callback"
        ):
            self.wristband_auth.callback(request)

    def test_callback_missing_tenant_name_with_subdomain_parsing_raises_error(self) -> None:
        """Test callback raises WristbandError when tenant subdomain missing with subdomain parsing enabled."""
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

        request = self.factory.get("/callback?code=auth_code&state=test_state", HTTP_HOST="invalid.domain.com")

        with pytest.raises(WristbandError) as exc_info:
            wristband_auth.callback(request)

        # Check the error message contains expected content
        assert "missing_tenant_subdomain" in str(exc_info.value)
        assert "tenant subdomain" in str(exc_info.value)

    def test_callback_missing_tenant_name_without_subdomain_parsing_raises_error(self) -> None:
        """Test callback raises WristbandError when tenant_name param missing without subdomain parsing."""
        request = self.factory.get("/callback?code=auth_code&state=test_state")

        with pytest.raises(WristbandError) as exc_info:
            self.wristband_auth.callback(request)

        assert "missing_tenant_name" in str(exc_info.value)
        assert "tenant_name" in str(exc_info.value)

    def test_callback_with_error_login_required_returns_redirect(self) -> None:
        """Test callback returns redirect when error=login_required."""
        request = self.factory.get("/callback?error=login_required&state=test_state&tenant_name=tenant1")

        result = self.wristband_auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.redirect_url == "https://auth.example.com/login?tenant_name=tenant1"

    def test_callback_with_other_error_raises_wristband_error(self) -> None:
        """Test callback raises WristbandError for non-login_required errors."""
        request = self.factory.get(
            "/callback?error=access_denied&error_description=User denied access&state=test_state&tenant_name=tenant1"
        )

        with pytest.raises(WristbandError) as exc_info:
            self.wristband_auth.callback(request)

        # Check that the error contains the expected content
        assert "access_denied" in str(exc_info.value)
        assert "User denied access" in str(exc_info.value)

    def test_callback_with_error_no_description_uses_empty_string(self) -> None:
        """Test callback uses empty description when error_description missing."""
        request = self.factory.get("/callback?error=access_denied&state=test_state&tenant_name=tenant1")

        with pytest.raises(WristbandError) as exc_info:
            self.wristband_auth.callback(request)

        # Check that the error contains the expected content
        assert "access_denied" in str(exc_info.value)

    def test_callback_no_login_state_cookie_returns_redirect(self) -> None:
        """Test callback returns redirect when no valid login state cookie found."""
        request = self.factory.get("/callback?code=auth_code&state=test_state&tenant_name=tenant1")
        # No cookies set on request

        result = self.wristband_auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.redirect_url == "https://auth.example.com/login?tenant_name=tenant1"

    def test_callback_mismatched_state_returns_redirect(self) -> None:
        """Test callback returns redirect when state from cookie doesn't match param."""
        request = self.factory.get("/callback?code=auth_code&state=param_state&tenant_name=tenant1")

        # Set cookie with different state using actual LoginState object
        login_state = LoginState(
            state="cookie_state",  # Different from param_state
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        request.COOKIES = {"login#param_state#1640995200000": encrypted_cookie}

        result = self.wristband_auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.redirect_url == "https://auth.example.com/login?tenant_name=tenant1"

    def test_callback_missing_code_after_validation_raises_error(self) -> None:
        """Test callback raises ValueError when code is missing after state validation."""
        request = self.factory.get("/callback?state=test_state&tenant_name=tenant1")  # No code param

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        request.COOKIES = {"login#test_state#1640995200000": encrypted_cookie}

        with pytest.raises(
            ValueError, match="Invalid query parameter \\[code\\] passed from Wristband during callback"
        ):
            self.wristband_auth.callback(request)

    @patch("wristband.django_auth.auth.time.time")
    def test_callback_successful_token_exchange_returns_completed(self, mock_time) -> None:
        """Test callback successfully exchanges code for tokens and returns completed result."""
        mock_time.return_value = 1640995200.0

        request = self.factory.get("/callback?code=auth_code&state=test_state&tenant_name=tenant1")

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url="https://app.example.com/dashboard",
            custom_state={"user": "123"},
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        request.COOKIES = {"login#test_state#1640995200000": encrypted_cookie}

        # Mock token response
        mock_token_response = WristbandTokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        # Mock user info
        mock_user_info = UserInfo(
            user_id="user_123",
            tenant_id="tenant_123",
            application_id="app_123",
            identity_provider_name="Wristband",
            email="user@example.com",
            email_verified=True,
        )

        with patch.object(self.wristband_auth._wristband_api, "get_tokens", return_value=mock_token_response):
            with patch.object(self.wristband_auth._wristband_api, "get_userinfo", return_value=mock_user_info):
                result = self.wristband_auth.callback(request)

        assert isinstance(result, CompletedCallbackResult)

        # Verify callback data
        callback_data = result.callback_data
        assert callback_data.access_token == "access_token_123"
        assert callback_data.id_token == "id_token_123"
        assert callback_data.expires_in == 3540  # 3600 - 60 (buffer)
        assert callback_data.expires_at == int((1640995200.0 + 3540) * 1000)
        assert callback_data.tenant_name == "tenant1"
        assert callback_data.user_info == mock_user_info
        assert callback_data.custom_state == {"user": "123"}
        assert callback_data.refresh_token == "refresh_token_123"
        assert callback_data.return_url == "https://app.example.com/dashboard"
        assert callback_data.tenant_custom_domain is None

    @patch("wristband.django_auth.auth.time.time")
    def test_callback_with_tenant_custom_domain_param(self, mock_time) -> None:
        """Test callback includes tenant_custom_domain in callback data when present."""
        mock_time.return_value = 1640995200.0

        request = self.factory.get(
            "/callback?code=auth_code&state=test_state&tenant_name=tenant1&tenant_custom_domain=custom.tenant.com"
        )

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        request.COOKIES = {"login#test_state#1640995200000": encrypted_cookie}

        mock_token_response = WristbandTokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        mock_user_info = UserInfo(
            user_id="user_123",
            tenant_id="tenant_123",
            application_id="app_123",
            identity_provider_name="Wristband",
            email="user@example.com",
            email_verified=True,
        )

        with patch.object(self.wristband_auth._wristband_api, "get_tokens", return_value=mock_token_response):
            with patch.object(self.wristband_auth._wristband_api, "get_userinfo", return_value=mock_user_info):
                result = self.wristband_auth.callback(request)

        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.tenant_custom_domain == "custom.tenant.com"

    @patch("wristband.django_auth.auth.time.time")
    def test_callback_with_no_token_expiration_buffer(self, mock_time) -> None:
        """Test callback handles missing token expiry buffer correctly."""
        mock_time.return_value = 1640995200.0

        config_no_buffer = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_no_buffer)

        request = self.factory.get("/callback?code=auth_code&state=test_state&tenant_name=tenant1")

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = wristband_auth._encrypt_login_state(login_state)
        request.COOKIES = {"login#test_state#1640995200000": encrypted_cookie}

        mock_token_response = WristbandTokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        mock_user_info = UserInfo(
            user_id="user_123",
            tenant_id="tenant_123",
            application_id="app_123",
            identity_provider_name="Wristband",
            email="user@example.com",
            email_verified=True,
        )

        with patch.object(wristband_auth._wristband_api, "get_tokens", return_value=mock_token_response):
            with patch.object(wristband_auth._wristband_api, "get_userinfo", return_value=mock_user_info):
                result = wristband_auth.callback(request)

        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.expires_in == 3540
        assert result.callback_data.expires_at == int((1640995200.0 + 3540) * 1000)

    def test_callback_invalid_grant_error_returns_redirect(self) -> None:
        """Test callback returns redirect when InvalidGrantError occurs during token exchange."""
        request = self.factory.get("/callback?code=invalid_code&state=test_state&tenant_name=tenant1")

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        request.COOKIES = {"login#test_state#1640995200000": encrypted_cookie}

        with patch.object(self.wristband_auth._wristband_api, "get_tokens") as mock_get_tokens:
            mock_get_tokens.side_effect = InvalidGrantError("Invalid authorization code")

            result = self.wristband_auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.redirect_url == "https://auth.example.com/login?tenant_name=tenant1"

    def test_callback_other_exception_gets_raised(self) -> None:
        """Test callback re-raises other exceptions that occur during token exchange."""
        request = self.factory.get("/callback?code=auth_code&state=test_state&tenant_name=tenant1")

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        request.COOKIES = {"login#test_state#1640995200000": encrypted_cookie}

        with patch.object(self.wristband_auth._wristband_api, "get_tokens") as mock_get_tokens:
            mock_get_tokens.side_effect = Exception("Network error")

            with pytest.raises(Exception, match="Network error"):
                self.wristband_auth.callback(request)

    def test_callback_duplicate_query_parameters_raise_error(self) -> None:
        """Test callback raises TypeError for duplicate query parameters."""
        request = self.factory.get("/callback?code=auth_code&code=duplicate_code&state=test_state&tenant_name=tenant1")

        with pytest.raises(
            TypeError, match="More than one instance of the query parameter \\[code\\] was present in the request"
        ):
            self.wristband_auth.callback(request)

    def test_callback_with_subdomain_parsing_extracts_tenant_correctly(self) -> None:
        """Test callback extracts tenant name from subdomain when subdomain parsing enabled."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_name}.auth.example.com/login",
            redirect_uri="https://{tenant_name}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            token_expiration_buffer=60,
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = self.factory.get("/callback?code=auth_code&state=test_state", HTTP_HOST="tenant1.auth.example.com")

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://tenant1.app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = wristband_auth._encrypt_login_state(login_state)
        request.COOKIES = {"login#test_state#1640995200000": encrypted_cookie}

        mock_token_response = WristbandTokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        mock_user_info = UserInfo(
            user_id="user_123",
            tenant_id="tenant_123",
            application_id="app_123",
            identity_provider_name="Wristband",
            email="user@example.com",
            email_verified=True,
        )

        with patch.object(wristband_auth._wristband_api, "get_tokens", return_value=mock_token_response):
            with patch.object(wristband_auth._wristband_api, "get_userinfo", return_value=mock_user_info):
                with patch("wristband.django_auth.auth.time.time", return_value=1640995200.0):
                    result = wristband_auth.callback(request)

        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.tenant_name == "tenant1"

    def test_callback_builds_tenant_login_url_with_custom_domain(self) -> None:
        """Test callback builds correct tenant login URL with custom domain for redirects."""
        expected_url = (
            "/callback?error=login_required&state=test_state&tenant_name=tenant1"
            "&tenant_custom_domain=custom.tenant.com"
        )
        request = self.factory.get(expected_url)

        result = self.wristband_auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert (
            result.redirect_url
            == "https://auth.example.com/login?tenant_name=tenant1&tenant_custom_domain=custom.tenant.com"
        )

    def test_callback_builds_tenant_login_url_with_subdomain_parsing(self) -> None:
        """Test callback builds correct tenant login URL with subdomain parsing for redirects."""
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

        request = self.factory.get(
            "/callback?error=login_required&state=test_state", HTTP_HOST="tenant1.auth.example.com"
        )

        result = wristband_auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.redirect_url == "https://tenant1.auth.example.com/login"

    @patch("wristband.django_auth.auth.time.time")
    def test_callback_with_zero_token_expiration_buffer(self, mock_time) -> None:
        """Test callback handles zero token expiry buffer correctly."""
        mock_time.return_value = 1640995200.0

        config_zero_buffer = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            token_expiration_buffer=0,  # Zero buffer
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_zero_buffer)

        request = self.factory.get("/callback?code=auth_code&state=test_state&tenant_name=tenant1")

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = wristband_auth._encrypt_login_state(login_state)
        request.COOKIES = {"login#test_state#1640995200000": encrypted_cookie}

        mock_token_response = WristbandTokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        mock_user_info = UserInfo(
            user_id="user_123",
            tenant_id="tenant_123",
            application_id="app_123",
            identity_provider_name="Wristband",
            email="user@example.com",
            email_verified=True,
        )

        with patch.object(wristband_auth._wristband_api, "get_tokens", return_value=mock_token_response):
            with patch.object(wristband_auth._wristband_api, "get_userinfo", return_value=mock_user_info):
                result = wristband_auth.callback(request)

        # Should not apply any buffer (3600 - 0 = 3600)
        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.expires_in == 3600  # No buffer applied
        assert result.callback_data.expires_at == int((1640995200.0 + 3600) * 1000)

    def test_callback_returns_correct_failure_reasons(self) -> None:
        """Test callback returns correct CallbackFailureReason for each failure case."""

        # Test MISSING_LOGIN_STATE
        request = self.factory.get("/callback?code=auth_code&state=test_state&tenant_name=tenant1")
        result = self.wristband_auth.callback(request)
        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.reason == CallbackFailureReason.MISSING_LOGIN_STATE

        # Test INVALID_LOGIN_STATE
        login_state = LoginState(
            state="different_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        request = self.factory.get("/callback?code=auth_code&state=test_state&tenant_name=tenant1")
        request.COOKIES = {"login#test_state#1640995200000": encrypted_cookie}
        result = self.wristband_auth.callback(request)
        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.reason == CallbackFailureReason.INVALID_LOGIN_STATE

        # Test LOGIN_REQUIRED
        request = self.factory.get("/callback?error=login_required&state=test_state&tenant_name=tenant1")
        result = self.wristband_auth.callback(request)
        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.reason == CallbackFailureReason.LOGIN_REQUIRED

        # Test INVALID_GRANT
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        request = self.factory.get("/callback?code=invalid_code&state=test_state&tenant_name=tenant1")
        request.COOKIES = {"login#test_state#1640995200000": encrypted_cookie}

        with patch.object(self.wristband_auth._wristband_api, "get_tokens") as mock_get_tokens:
            mock_get_tokens.side_effect = InvalidGrantError("Invalid authorization code")
            result = self.wristband_auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.reason == CallbackFailureReason.INVALID_GRANT

    def test_callback_duplicate_state_parameter_raises_error(self) -> None:
        """Test callback raises TypeError for duplicate state query parameter."""
        request = self.factory.get("/callback?code=auth_code&state=state1&state=state2&tenant_name=tenant1")

        with pytest.raises(
            TypeError, match="More than one instance of the query parameter \\[state\\] was present in the request"
        ):
            self.wristband_auth.callback(request)

    def test_callback_duplicate_tenant_name_parameter_raises_error(self) -> None:
        """Test callback raises TypeError for duplicate tenant_name query parameter."""
        request = self.factory.get("/callback?code=auth_code&state=test_state&tenant_name=tenant1&tenant_name=tenant2")

        with pytest.raises(
            TypeError,
            match="More than one instance of the query parameter \\[tenant_name\\] was present in the request",
        ):
            self.wristband_auth.callback(request)

    def test_callback_duplicate_tenant_custom_domain_parameter_raises_error(self) -> None:
        """Test callback raises TypeError for duplicate tenant_custom_domain query parameter."""
        request = self.factory.get(
            "/callback?code=auth_code&state=test_state&tenant_name=tenant1&tenant_custom_domain=custom1.com"
            + "&tenant_custom_domain=custom2.com"
        )

        with pytest.raises(
            TypeError,
            match="More than one instance of the query parameter \\[tenant_custom_domain\\] was present in the request",
        ):
            self.wristband_auth.callback(request)

    def test_callback_with_port_in_subdomain_strips_port(self) -> None:
        """Test callback strips port from hostname when parsing tenant subdomain."""
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

        # Request with port in hostname
        request = self.factory.get(
            "/callback?code=auth_code&state=test_state", HTTP_HOST="tenant1.auth.example.com:8000"
        )

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://tenant1.app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = wristband_auth._encrypt_login_state(login_state)
        request.COOKIES = {"login#test_state#1640995200000": encrypted_cookie}

        mock_token_response = WristbandTokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        mock_user_info = UserInfo(
            user_id="user_123",
            tenant_id="tenant_123",
            application_id="app_123",
            identity_provider_name="Wristband",
            email="user@example.com",
            email_verified=True,
        )

        with patch.object(wristband_auth._wristband_api, "get_tokens", return_value=mock_token_response):
            with patch.object(wristband_auth._wristband_api, "get_userinfo", return_value=mock_user_info):
                with patch("wristband.django_auth.auth.time.time", return_value=1640995200.0):
                    result = wristband_auth.callback(request)

        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.tenant_name == "tenant1"  # Port should be stripped

    def test_callback_with_localhost_and_subdomain_parsing_raises_error(self) -> None:
        """Test callback raises error when hostname is localhost with subdomain parsing enabled."""
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

        request = self.factory.get("/callback?code=auth_code&state=test_state", HTTP_HOST="localhost")

        with pytest.raises(WristbandError) as exc_info:
            wristband_auth.callback(request)

        assert "missing_tenant_subdomain" in str(exc_info.value)

    def test_callback_with_mismatched_root_domain_raises_error(self) -> None:
        """Test callback raises error when root domain doesn't match parse_tenant_from_root_domain."""
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

        request = self.factory.get("/callback?code=auth_code&state=test_state", HTTP_HOST="tenant1.wrongdomain.com")

        with pytest.raises(WristbandError) as exc_info:
            wristband_auth.callback(request)

        assert "missing_tenant_subdomain" in str(exc_info.value)

    def test_callback_with_empty_subdomain_raises_error(self) -> None:
        """Test callback raises error when subdomain is empty."""
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

        # Host with just root domain, no subdomain
        request = self.factory.get("/callback?code=auth_code&state=test_state", HTTP_HOST="auth.example.com")

        with pytest.raises(WristbandError) as exc_info:
            wristband_auth.callback(request)

        assert "missing_tenant_subdomain" in str(exc_info.value)


class TestWristbandAuthCallbackBackwardCompatibility:
    """Test cases for backward compatibility with {tenant_domain} placeholder in callback."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()

    def test_callback_with_tenant_domain_placeholder_in_login_url(self) -> None:
        """Test callback works with {tenant_domain} placeholder in login_url."""
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

        request = self.factory.get(
            "/callback?error=login_required&state=test_state", HTTP_HOST="tenant1.auth.example.com"
        )

        result = wristband_auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.redirect_url == "https://tenant1.auth.example.com/login"

    def test_callback_with_tenant_domain_placeholder_in_redirect_uri(self) -> None:
        """Test callback works with {tenant_domain} placeholder in redirect_uri."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="app.example.com",
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config)

        request = self.factory.get("/callback?code=auth_code&state=test_state", HTTP_HOST="tenant1.app.example.com")

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://tenant1.app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = wristband_auth._encrypt_login_state(login_state)
        request.COOKIES = {"login#test_state#1640995200000": encrypted_cookie}

        mock_token_response = WristbandTokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        mock_user_info = UserInfo(
            user_id="user_123",
            tenant_id="tenant_123",
            application_id="app_123",
            identity_provider_name="Wristband",
            email="user@example.com",
            email_verified=True,
        )

        with patch.object(wristband_auth._wristband_api, "get_tokens", return_value=mock_token_response):
            with patch.object(wristband_auth._wristband_api, "get_userinfo", return_value=mock_user_info):
                with patch("wristband.django_auth.auth.time.time", return_value=1640995200.0):
                    result = wristband_auth.callback(request)

        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.tenant_name == "tenant1"

    def test_callback_builds_login_url_with_tenant_domain_and_custom_domain_param(self) -> None:
        """Test callback builds correct login URL with {tenant_domain} placeholder and custom domain param."""
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

        request = self.factory.get(
            "/callback?error=login_required&state=test_state&tenant_custom_domain=custom.tenant.com",
            HTTP_HOST="tenant1.auth.example.com",
        )

        result = wristband_auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        # Should substitute tenant_domain with tenant1 and include custom domain param
        assert result.redirect_url == "https://tenant1.auth.example.com/login?tenant_custom_domain=custom.tenant.com"

    def test_callback_mixed_tenant_name_and_tenant_domain_placeholders(self) -> None:
        """Test callback works when mixing {tenant_name} and {tenant_domain} placeholders."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_name}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config)

        request = self.factory.get(
            "/callback?error=login_required&state=test_state", HTTP_HOST="tenant1.auth.example.com"
        )

        result = wristband_auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        # Both placeholders should be substituted with tenant1
        assert result.redirect_url == "https://tenant1.auth.example.com/login"
