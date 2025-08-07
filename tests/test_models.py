import pytest

from wristband.django_auth.models import (
    AuthConfig,
    CallbackData,
    CallbackResult,
    CallbackResultType,
    LoginConfig,
    LoginState,
    LogoutConfig,
    OAuthAuthorizeUrlConfig,
    TokenData,
    TokenResponse,
    UserInfo,
)


class TestAuthConfig:
    """Test cases for AuthConfig dataclass."""

    def test_auth_config_required_fields(self):
        """Test AuthConfig with only required fields."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret="very_long_secret_key_for_encryption_123456789",
            login_url="https://example.com/login",
            redirect_uri="https://example.com/callback",
            wristband_application_vanity_domain="app.wristband.dev",
        )

        assert config.client_id == "test_client_id"
        assert config.client_secret == "test_client_secret"
        assert config.login_state_secret == "very_long_secret_key_for_encryption_123456789"
        assert config.login_url == "https://example.com/login"
        assert config.redirect_uri == "https://example.com/callback"
        assert config.wristband_application_vanity_domain == "app.wristband.dev"

        # Test default values
        assert config.custom_application_login_page_url is None
        assert config.dangerously_disable_secure_cookies is False
        assert config.is_application_custom_domain_active is False
        assert config.parse_tenant_from_root_domain is None
        assert config.scopes == ["openid", "offline_access", "email"]
        assert config.token_expiration_buffer == 60

    def test_auth_config_all_fields(self):
        """Test AuthConfig with all fields specified."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret="very_long_secret_key_for_encryption_123456789",
            login_url="https://example.com/login",
            redirect_uri="https://example.com/callback",
            wristband_application_vanity_domain="app.wristband.dev",
            custom_application_login_page_url="https://custom.example.com/login",
            dangerously_disable_secure_cookies=True,
            is_application_custom_domain_active=True,
            parse_tenant_from_root_domain="example.com",
            scopes=["openid", "profile", "email"],
            token_expiration_buffer=120,
        )

        assert config.custom_application_login_page_url == "https://custom.example.com/login"
        assert config.dangerously_disable_secure_cookies is True
        assert config.is_application_custom_domain_active is True
        assert config.parse_tenant_from_root_domain == "example.com"
        assert config.scopes == ["openid", "profile", "email"]
        assert config.token_expiration_buffer == 120

    def test_auth_config_empty_scopes(self):
        """Test AuthConfig with empty scopes list."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret="very_long_secret_key_for_encryption_123456789",
            login_url="https://example.com/login",
            redirect_uri="https://example.com/callback",
            wristband_application_vanity_domain="app.wristband.dev",
            scopes=[],
        )

        assert config.scopes == []

    def test_auth_config_none_token_expiration_buffer(self):
        """Test AuthConfig with None token_expiration_buffer."""
        config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret="very_long_secret_key_for_encryption_123456789",
            login_url="https://example.com/login",
            redirect_uri="https://example.com/callback",
            wristband_application_vanity_domain="app.wristband.dev",
            token_expiration_buffer=None,
        )

        assert config.token_expiration_buffer is None


class TestLoginState:
    """Test cases for LoginState dataclass."""

    def test_login_state_creation(self):
        """Test LoginState creation with all fields."""
        custom_state = {"key": "value", "nested": {"inner": "data"}}
        login_state = LoginState(
            state="test_state",
            code_verifier="test_code_verifier",
            redirect_uri="https://example.com/callback",
            return_url="https://example.com/dashboard",
            custom_state=custom_state,
        )

        assert login_state.state == "test_state"
        assert login_state.code_verifier == "test_code_verifier"
        assert login_state.redirect_uri == "https://example.com/callback"
        assert login_state.return_url == "https://example.com/dashboard"
        assert login_state.custom_state == custom_state

    def test_login_state_with_none_values(self):
        """Test LoginState with None values for optional fields."""
        login_state = LoginState(
            state="test_state",
            code_verifier="test_code_verifier",
            redirect_uri="https://example.com/callback",
            return_url=None,
            custom_state=None,
        )

        assert login_state.return_url is None
        assert login_state.custom_state is None

    def test_login_state_to_dict(self):
        """Test LoginState to_dict method."""
        custom_state = {"key": "value"}
        login_state = LoginState(
            state="test_state",
            code_verifier="test_code_verifier",
            redirect_uri="https://example.com/callback",
            return_url="https://example.com/dashboard",
            custom_state=custom_state,
        )

        result = login_state.to_dict()
        expected = {
            "state": "test_state",
            "code_verifier": "test_code_verifier",
            "redirect_uri": "https://example.com/callback",
            "return_url": "https://example.com/dashboard",
            "custom_state": custom_state,
        }

        assert result == expected

    def test_login_state_to_dict_with_none_values(self):
        """Test LoginState to_dict with None values."""
        login_state = LoginState(
            state="test_state",
            code_verifier="test_code_verifier",
            redirect_uri="https://example.com/callback",
            return_url=None,
            custom_state=None,
        )

        result = login_state.to_dict()
        expected = {
            "state": "test_state",
            "code_verifier": "test_code_verifier",
            "redirect_uri": "https://example.com/callback",
            "return_url": None,
            "custom_state": None,
        }

        assert result == expected


class TestLoginConfig:
    """Test cases for LoginConfig dataclass."""

    def test_login_config_defaults(self):
        """Test LoginConfig with default values."""
        config = LoginConfig()

        assert config.custom_state is None
        assert config.default_tenant_custom_domain is None
        assert config.default_tenant_domain is None

    def test_login_config_all_fields(self):
        """Test LoginConfig with all fields specified."""
        custom_state = {"app": "test", "user_id": "123"}
        config = LoginConfig(
            custom_state=custom_state,
            default_tenant_custom_domain="custom.example.com",
            default_tenant_domain="tenant1",
        )

        assert config.custom_state == custom_state
        assert config.default_tenant_custom_domain == "custom.example.com"
        assert config.default_tenant_domain == "tenant1"


class TestOAuthAuthorizeUrlConfig:
    """Test cases for OAuthAuthorizeUrlConfig dataclass."""

    def test_oauth_authorize_url_config_creation(self):
        """Test OAuthAuthorizeUrlConfig creation."""
        login_state = LoginState(
            state="test_state",
            code_verifier="test_code_verifier",
            redirect_uri="https://example.com/callback",
            return_url=None,
            custom_state=None,
        )

        config = OAuthAuthorizeUrlConfig(
            login_state=login_state,
            tenant_domain_name="tenant1",
            tenant_custom_domain="custom.example.com",
            default_tenant_domain_name="default_tenant",
            default_tenant_custom_domain="default.example.com",
        )

        assert config.login_state == login_state
        assert config.tenant_domain_name == "tenant1"
        assert config.tenant_custom_domain == "custom.example.com"
        assert config.default_tenant_domain_name == "default_tenant"
        assert config.default_tenant_custom_domain == "default.example.com"

    def test_oauth_authorize_url_config_with_none_values(self):
        """Test OAuthAuthorizeUrlConfig with None values."""
        login_state = LoginState(
            state="test_state",
            code_verifier="test_code_verifier",
            redirect_uri="https://example.com/callback",
            return_url=None,
            custom_state=None,
        )

        config = OAuthAuthorizeUrlConfig(
            login_state=login_state,
            tenant_domain_name=None,
            tenant_custom_domain=None,
            default_tenant_domain_name=None,
            default_tenant_custom_domain=None,
        )

        assert config.tenant_domain_name is None
        assert config.tenant_custom_domain is None
        assert config.default_tenant_domain_name is None
        assert config.default_tenant_custom_domain is None


class TestCallbackResultType:
    """Test cases for CallbackResultType enum."""

    def test_callback_result_type_values(self):
        """Test CallbackResultType enum values."""
        assert CallbackResultType.COMPLETED.value == "COMPLETED"
        assert CallbackResultType.REDIRECT_REQUIRED.value == "REDIRECT_REQUIRED"

    def test_callback_result_type_comparison(self):
        """Test CallbackResultType enum comparison."""
        assert CallbackResultType.COMPLETED == CallbackResultType.COMPLETED
        assert CallbackResultType.REDIRECT_REQUIRED == CallbackResultType.REDIRECT_REQUIRED
        assert CallbackResultType.COMPLETED != CallbackResultType.REDIRECT_REQUIRED


class TestCallbackData:
    """Test cases for CallbackData dataclass."""

    def test_callback_data_creation(self):
        """Test CallbackData creation with all fields."""
        user_info = {"sub": "user123", "email": "user@example.com", "name": "Test User"}
        custom_state = {"app": "test"}

        callback_data = CallbackData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1640995200000,
            expires_in=3600,
            tenant_domain_name="tenant1",
            user_info=user_info,
            custom_state=custom_state,
            refresh_token="refresh_token_123",
            return_url="https://example.com/dashboard",
            tenant_custom_domain="custom.example.com",
        )

        assert callback_data.access_token == "access_token_123"
        assert callback_data.id_token == "id_token_123"
        assert callback_data.expires_at == 1640995200000
        assert callback_data.expires_in == 3600
        assert callback_data.tenant_domain_name == "tenant1"
        assert callback_data.user_info == user_info
        assert callback_data.custom_state == custom_state
        assert callback_data.refresh_token == "refresh_token_123"
        assert callback_data.return_url == "https://example.com/dashboard"
        assert callback_data.tenant_custom_domain == "custom.example.com"

    def test_callback_data_with_none_optional_fields(self):
        """Test CallbackData with None values for optional fields."""
        user_info = {"sub": "user123", "email": "user@example.com"}

        callback_data = CallbackData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1640995200000,
            expires_in=3600,
            tenant_domain_name="tenant1",
            user_info=user_info,
            custom_state=None,
            refresh_token=None,
            return_url=None,
            tenant_custom_domain=None,
        )

        assert callback_data.custom_state is None
        assert callback_data.refresh_token is None
        assert callback_data.return_url is None
        assert callback_data.tenant_custom_domain is None

    def test_callback_data_to_dict(self):
        """Test CallbackData to_dict method."""
        user_info = {"sub": "user123", "email": "user@example.com"}
        custom_state = {"app": "test"}

        callback_data = CallbackData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1640995200000,
            expires_in=3600,
            tenant_domain_name="tenant1",
            user_info=user_info,
            custom_state=custom_state,
            refresh_token="refresh_token_123",
            return_url="https://example.com/dashboard",
            tenant_custom_domain="custom.example.com",
        )

        result = callback_data.to_dict()
        expected = {
            "access_token": "access_token_123",
            "id_token": "id_token_123",
            "expires_at": 1640995200000,
            "expires_in": 3600,
            "tenant_domain_name": "tenant1",
            "user_info": user_info,
            "custom_state": custom_state,
            "refresh_token": "refresh_token_123",
            "return_url": "https://example.com/dashboard",
            "tenant_custom_domain": "custom.example.com",
        }

        assert result == expected


class TestTokenData:
    """Test cases for TokenData dataclass."""

    def test_token_data_creation(self):
        """Test TokenData creation."""
        token_data = TokenData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1640995200000,
            expires_in=3600,
            refresh_token="refresh_token_123",
        )

        assert token_data.access_token == "access_token_123"
        assert token_data.id_token == "id_token_123"
        assert token_data.expires_at == 1640995200000
        assert token_data.expires_in == 3600
        assert token_data.refresh_token == "refresh_token_123"


class TestCallbackResult:
    """Test cases for CallbackResult dataclass."""

    def test_callback_result_completed(self):
        """Test CallbackResult with COMPLETED type."""
        user_info = {"sub": "user123", "email": "user@example.com"}
        callback_data = CallbackData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1640995200000,
            expires_in=3600,
            tenant_domain_name="tenant1",
            user_info=user_info,
            custom_state=None,
            refresh_token=None,
            return_url=None,
            tenant_custom_domain=None,
        )

        result = CallbackResult(callback_data=callback_data, type=CallbackResultType.COMPLETED, redirect_url=None)

        assert result.callback_data == callback_data
        assert result.type == CallbackResultType.COMPLETED
        assert result.redirect_url is None

    def test_callback_result_redirect_required(self):
        """Test CallbackResult with REDIRECT_REQUIRED type."""
        result = CallbackResult(
            callback_data=None, type=CallbackResultType.REDIRECT_REQUIRED, redirect_url="https://example.com/login"
        )

        assert result.callback_data is None
        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert result.redirect_url == "https://example.com/login"


class TestTokenResponse:
    """Test cases for TokenResponse dataclass."""

    def test_token_response_creation(self):
        """Test TokenResponse creation."""
        token_response = TokenResponse(
            access_token="access_token_123",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="refresh_token_123",
            id_token="id_token_123",
            scope="openid email profile",
        )

        assert token_response.access_token == "access_token_123"
        assert token_response.token_type == "Bearer"
        assert token_response.expires_in == 3600
        assert token_response.refresh_token == "refresh_token_123"
        assert token_response.id_token == "id_token_123"
        assert token_response.scope == "openid email profile"

    def test_token_response_from_api_response(self):
        """Test TokenResponse.from_api_response method."""
        api_response = {
            "access_token": "access_token_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh_token_123",
            "id_token": "id_token_123",
            "scope": "openid email profile",
        }

        token_response = TokenResponse.from_api_response(api_response)

        assert token_response.access_token == "access_token_123"
        assert token_response.token_type == "Bearer"
        assert token_response.expires_in == 3600
        assert token_response.refresh_token == "refresh_token_123"
        assert token_response.id_token == "id_token_123"
        assert token_response.scope == "openid email profile"

    def test_token_response_from_api_response_missing_fields(self):
        """Test TokenResponse.from_api_response with missing fields."""
        api_response = {
            "access_token": "access_token_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            # Missing refresh_token, id_token, scope
        }

        with pytest.raises(KeyError):
            TokenResponse.from_api_response(api_response)

    def test_token_response_from_api_response_extra_fields(self):
        """Test TokenResponse.from_api_response with extra fields."""
        api_response = {
            "access_token": "access_token_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh_token_123",
            "id_token": "id_token_123",
            "scope": "openid email profile",
            "extra_field": "ignored",  # This should be ignored
        }

        token_response = TokenResponse.from_api_response(api_response)

        assert token_response.access_token == "access_token_123"
        assert token_response.token_type == "Bearer"
        assert token_response.expires_in == 3600
        assert token_response.refresh_token == "refresh_token_123"
        assert token_response.id_token == "id_token_123"
        assert token_response.scope == "openid email profile"
        # Extra field is not accessible on the TokenResponse object


class TestLogoutConfig:
    """Test cases for LogoutConfig dataclass."""

    def test_logout_config_defaults(self):
        """Test LogoutConfig with default values."""
        config = LogoutConfig()

        assert config.redirect_url is None
        assert config.refresh_token is None
        assert config.tenant_custom_domain is None
        assert config.tenant_domain_name is None

    def test_logout_config_all_fields(self):
        """Test LogoutConfig with all fields specified."""
        config = LogoutConfig(
            redirect_url="https://example.com/goodbye",
            refresh_token="refresh_token_123",
            tenant_custom_domain="custom.example.com",
            tenant_domain_name="tenant1",
        )

        assert config.redirect_url == "https://example.com/goodbye"
        assert config.refresh_token == "refresh_token_123"
        assert config.tenant_custom_domain == "custom.example.com"
        assert config.tenant_domain_name == "tenant1"

    def test_logout_config_partial_fields(self):
        """Test LogoutConfig with only some fields specified."""
        config = LogoutConfig(refresh_token="refresh_token_123", tenant_domain_name="tenant1")

        assert config.redirect_url is None
        assert config.refresh_token == "refresh_token_123"
        assert config.tenant_custom_domain is None
        assert config.tenant_domain_name == "tenant1"


class TestUserInfo:
    """Test cases for UserInfo type alias."""

    def test_user_info_type_alias(self):
        """Test that UserInfo is properly defined as a type alias."""
        # UserInfo is defined as: UserInfo = dict[str, Any]
        user_info: UserInfo = {
            "sub": "user123",
            "email": "user@example.com",
            "name": "Test User",
            "custom_claim": {"nested": "data"},
            "roles": ["admin", "user"],
            "active": True,
            "login_count": 42,
        }

        # Test that it works as expected with different value types
        assert isinstance(user_info, dict)
        assert user_info["sub"] == "user123"
        assert user_info["email"] == "user@example.com"
        assert user_info["name"] == "Test User"
        assert user_info["custom_claim"] == {"nested": "data"}
        assert user_info["roles"] == ["admin", "user"]
        assert user_info["active"] is True
        assert user_info["login_count"] == 42
