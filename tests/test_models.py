import pytest

from wristband.django_auth.models import (
    AuthConfig,
    AuthStrategy,
    CallbackData,
    CallbackFailureReason,
    CallbackResult,
    CallbackResultType,
    CompletedCallbackResult,
    JWTAuthConfig,
    JWTAuthResult,
    LoginConfig,
    LoginState,
    LogoutConfig,
    OAuthAuthorizeUrlConfig,
    RawUserInfo,
    RedirectRequiredCallbackResult,
    SdkConfiguration,
    SessionResponse,
    TokenData,
    TokenResponse,
    UnauthenticatedBehavior,
    UserInfo,
    UserInfoRole,
    WristbandTokenResponse,
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
        assert config.auto_configure_enabled is True
        assert config.custom_application_login_page_url is None
        assert config.dangerously_disable_secure_cookies is False
        assert config.is_application_custom_domain_active is None
        assert config.parse_tenant_from_root_domain is None
        assert config.scopes == ["openid", "offline_access", "email"]
        assert config.token_expiration_buffer == 60

    def test_auth_config_all_fields(self):
        """Test AuthConfig with all fields specified."""
        config = AuthConfig(
            auto_configure_enabled=False,
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

        assert config.auto_configure_enabled is False
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
        )

        assert config.token_expiration_buffer == 60


class TestSdkConfiguration:
    """Test cases for SdkConfiguration dataclass."""

    def test_sdk_configuration_creation(self):
        """Test SdkConfiguration creation with all fields."""
        config = SdkConfiguration(
            login_url="https://auth.wristband.dev/api/v1/oauth2/authorize",
            redirect_uri="https://example.com/callback",
            is_application_custom_domain_active=True,
            custom_application_login_page_url="https://custom.example.com/login",
            login_url_tenant_domain_suffix=".tenant.wristband.dev",
        )

        assert config.login_url == "https://auth.wristband.dev/api/v1/oauth2/authorize"
        assert config.redirect_uri == "https://example.com/callback"
        assert config.is_application_custom_domain_active is True
        assert config.custom_application_login_page_url == "https://custom.example.com/login"
        assert config.login_url_tenant_domain_suffix == ".tenant.wristband.dev"

    def test_sdk_configuration_minimal_required_fields(self):
        """Test SdkConfiguration with only required fields."""
        config = SdkConfiguration(
            login_url="https://auth.wristband.dev/api/v1/oauth2/authorize",
            redirect_uri="https://example.com/callback",
            is_application_custom_domain_active=False,
        )

        assert config.login_url == "https://auth.wristband.dev/api/v1/oauth2/authorize"
        assert config.redirect_uri == "https://example.com/callback"
        assert config.is_application_custom_domain_active is False
        assert config.custom_application_login_page_url is None
        assert config.login_url_tenant_domain_suffix is None

    def test_sdk_configuration_from_api_response(self):
        """Test SdkConfiguration.from_api_response method."""
        api_response = {
            "loginUrl": "https://auth.wristband.dev/api/v1/oauth2/authorize",
            "redirectUri": "https://example.com/callback",
            "isApplicationCustomDomainActive": True,
            "customApplicationLoginPageUrl": "https://custom.example.com/login",
            "loginUrlTenantDomainSuffix": ".tenant.wristband.dev",
        }

        config = SdkConfiguration.from_api_response(api_response)

        assert config.login_url == "https://auth.wristband.dev/api/v1/oauth2/authorize"
        assert config.redirect_uri == "https://example.com/callback"
        assert config.is_application_custom_domain_active is True
        assert config.custom_application_login_page_url == "https://custom.example.com/login"
        assert config.login_url_tenant_domain_suffix == ".tenant.wristband.dev"

    def test_sdk_configuration_from_api_response_minimal(self):
        """Test SdkConfiguration.from_api_response with minimal response."""
        api_response = {
            "loginUrl": "https://auth.wristband.dev/api/v1/oauth2/authorize",
            "redirectUri": "https://example.com/callback",
        }

        config = SdkConfiguration.from_api_response(api_response)

        assert config.login_url == "https://auth.wristband.dev/api/v1/oauth2/authorize"
        assert config.redirect_uri == "https://example.com/callback"
        assert config.is_application_custom_domain_active is False  # Default from .get()
        assert config.custom_application_login_page_url is None
        assert config.login_url_tenant_domain_suffix is None

    def test_sdk_configuration_from_api_response_with_false_custom_domain(self):
        """Test SdkConfiguration.from_api_response with explicit False for custom domain."""
        api_response = {
            "loginUrl": "https://auth.wristband.dev/api/v1/oauth2/authorize",
            "redirectUri": "https://example.com/callback",
            "isApplicationCustomDomainActive": False,
        }

        config = SdkConfiguration.from_api_response(api_response)

        assert config.is_application_custom_domain_active is False


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
        assert config.default_tenant_name is None
        assert config.return_url is None

    def test_login_config_all_fields(self):
        """Test LoginConfig with all fields specified."""
        custom_state = {"app": "test", "user_id": "123"}
        config = LoginConfig(
            custom_state=custom_state,
            default_tenant_custom_domain="custom.example.com",
            default_tenant_name="tenant1",
            return_url="https://myapp.com",
        )

        assert config.custom_state == custom_state
        assert config.default_tenant_custom_domain == "custom.example.com"
        assert config.default_tenant_name == "tenant1"
        assert config.return_url == "https://myapp.com"


class TestOAuthAuthorizeUrlConfig:
    """Test cases for OAuthAuthorizeUrlConfig dataclass."""

    def test_oauth_authorize_url_config_creation(self):
        """Test OAuthAuthorizeUrlConfig creation."""
        config = OAuthAuthorizeUrlConfig(
            client_id="test_client_id",
            code_verifier="test_code_verifier",
            redirect_uri="https://example.com/callback",
            scopes=["openid", "email"],
            state="test_state",
            wristband_application_vanity_domain="app.wristband.dev",
            tenant_name="tenant1",
            tenant_custom_domain="custom.example.com",
            default_tenant_name="default_tenant",
            default_tenant_custom_domain="default.example.com",
            is_application_custom_domain_active=True,
        )

        assert config.client_id == "test_client_id"
        assert config.code_verifier == "test_code_verifier"
        assert config.redirect_uri == "https://example.com/callback"
        assert config.scopes == ["openid", "email"]
        assert config.state == "test_state"
        assert config.wristband_application_vanity_domain == "app.wristband.dev"
        assert config.tenant_name == "tenant1"
        assert config.tenant_custom_domain == "custom.example.com"
        assert config.default_tenant_name == "default_tenant"
        assert config.default_tenant_custom_domain == "default.example.com"
        assert config.is_application_custom_domain_active is True

    def test_oauth_authorize_url_config_with_none_values(self):
        """Test OAuthAuthorizeUrlConfig with None values for optional fields."""
        config = OAuthAuthorizeUrlConfig(
            client_id="test_client_id",
            code_verifier="test_code_verifier",
            redirect_uri="https://example.com/callback",
            scopes=["openid"],
            state="test_state",
            wristband_application_vanity_domain="app.wristband.dev",
            tenant_name=None,
            tenant_custom_domain=None,
            default_tenant_name=None,
            default_tenant_custom_domain=None,
        )

        assert config.tenant_name is None
        assert config.tenant_custom_domain is None
        assert config.default_tenant_name is None
        assert config.default_tenant_custom_domain is None
        assert config.is_application_custom_domain_active is False  # Default value

    def test_oauth_authorize_url_config_minimal_required_fields(self):
        """Test OAuthAuthorizeUrlConfig with only required fields."""
        config = OAuthAuthorizeUrlConfig(
            client_id="test_client_id",
            code_verifier="test_code_verifier",
            redirect_uri="https://example.com/callback",
            scopes=["openid"],
            state="test_state",
            wristband_application_vanity_domain="app.wristband.dev",
        )

        assert config.client_id == "test_client_id"
        assert config.code_verifier == "test_code_verifier"
        assert config.redirect_uri == "https://example.com/callback"
        assert config.scopes == ["openid"]
        assert config.state == "test_state"
        assert config.wristband_application_vanity_domain == "app.wristband.dev"

        # Check default values for optional fields
        assert config.default_tenant_custom_domain is None
        assert config.default_tenant_name is None
        assert config.tenant_custom_domain is None
        assert config.tenant_name is None
        assert config.is_application_custom_domain_active is False


class TestCallbackResultType:
    """Test cases for CallbackResultType enum."""

    def test_callback_result_type_values(self):
        """Test CallbackResultType enum values."""
        assert CallbackResultType.COMPLETED.value == "completed"
        assert CallbackResultType.REDIRECT_REQUIRED.value == "redirect_required"

    def test_callback_result_type_comparison(self):
        """Test CallbackResultType enum comparison."""
        assert CallbackResultType.COMPLETED == CallbackResultType.COMPLETED
        assert CallbackResultType.REDIRECT_REQUIRED == CallbackResultType.REDIRECT_REQUIRED
        assert CallbackResultType.COMPLETED != CallbackResultType.REDIRECT_REQUIRED


class TestCallbackData:
    """Test cases for CallbackData dataclass."""

    def test_callback_data_creation(self):
        """Test CallbackData creation with all fields."""
        user_info = UserInfo(
            user_id="user123",
            tenant_id="tenant123",
            application_id="app123",
            identity_provider_name="Wristband",
            email="user@example.com",
            full_name="Test User",
        )
        custom_state = {"app": "test"}

        callback_data = CallbackData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1640995200000,
            expires_in=3600,
            tenant_name="tenant1",
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
        assert callback_data.tenant_name == "tenant1"
        assert callback_data.user_info == user_info
        assert callback_data.custom_state == custom_state
        assert callback_data.refresh_token == "refresh_token_123"
        assert callback_data.return_url == "https://example.com/dashboard"
        assert callback_data.tenant_custom_domain == "custom.example.com"

    def test_callback_data_with_none_optional_fields(self):
        """Test CallbackData with None values for optional fields."""
        user_info = UserInfo(
            user_id="user123",
            tenant_id="tenant123",
            application_id="app123",
            identity_provider_name="Wristband",
            email="user@example.com",
        )

        callback_data = CallbackData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1640995200000,
            expires_in=3600,
            tenant_name="tenant1",
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
        user_info = UserInfo(
            user_id="user123",
            tenant_id="tenant123",
            application_id="app123",
            identity_provider_name="Wristband",
            email="user@example.com",
        )
        custom_state = {"app": "test"}

        callback_data = CallbackData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1640995200000,
            expires_in=3600,
            tenant_name="tenant1",
            user_info=user_info,
            custom_state=custom_state,
            refresh_token="refresh_token_123",
            return_url="https://example.com/dashboard",
            tenant_custom_domain="custom.example.com",
        )

        result = callback_data.to_dict()

        # Verify key fields (user_info will be converted to dict by asdict())
        assert result["access_token"] == "access_token_123"
        assert result["id_token"] == "id_token_123"
        assert result["expires_at"] == 1640995200000
        assert result["expires_in"] == 3600
        assert result["tenant_name"] == "tenant1"
        assert result["custom_state"] == custom_state
        assert result["refresh_token"] == "refresh_token_123"
        assert result["return_url"] == "https://example.com/dashboard"
        assert result["tenant_custom_domain"] == "custom.example.com"

        # Verify user_info was converted to dict with expected fields
        assert isinstance(result["user_info"], dict)
        assert result["user_info"]["user_id"] == "user123"
        assert result["user_info"]["tenant_id"] == "tenant123"
        assert result["user_info"]["application_id"] == "app123"
        assert result["user_info"]["email"] == "user@example.com"


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


class TestCompletedCallbackResult:
    """Test cases for CompletedCallbackResult dataclass."""

    def test_completed_callback_result_creation(self):
        """Test CompletedCallbackResult creation."""
        user_info = UserInfo(
            user_id="user123", tenant_id="tenant123", application_id="app123", identity_provider_name="Wristband"
        )
        callback_data = CallbackData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1640995200000,
            expires_in=3600,
            tenant_name="tenant1",
            user_info=user_info,
            custom_state=None,
            refresh_token=None,
            return_url=None,
            tenant_custom_domain=None,
        )

        result = CompletedCallbackResult(callback_data=callback_data)

        assert result.type == CallbackResultType.COMPLETED
        assert result.callback_data == callback_data

    def test_completed_callback_result_type_is_readonly(self):
        """Test that type field is auto-set and readonly."""
        user_info = UserInfo(
            user_id="user123", tenant_id="tenant123", application_id="app123", identity_provider_name="Wristband"
        )
        callback_data = CallbackData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1640995200000,
            expires_in=3600,
            tenant_name="tenant1",
            user_info=user_info,
            custom_state=None,
            refresh_token=None,
            return_url=None,
            tenant_custom_domain=None,
        )

        # Should not be able to pass type in constructor due to init=False
        result = CompletedCallbackResult(callback_data=callback_data)
        assert result.type == CallbackResultType.COMPLETED


class TestRedirectRequiredCallbackResult:
    """Test cases for RedirectRequiredCallbackResult dataclass."""

    def test_redirect_required_callback_result_creation(self):
        """Test RedirectRequiredCallbackResult creation."""
        result = RedirectRequiredCallbackResult(
            redirect_url="https://example.com/login", reason=CallbackFailureReason.MISSING_LOGIN_STATE
        )

        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert result.redirect_url == "https://example.com/login"
        assert result.reason == CallbackFailureReason.MISSING_LOGIN_STATE

    def test_redirect_required_all_reasons(self):
        """Test RedirectRequiredCallbackResult with all failure reasons."""
        reasons = [
            CallbackFailureReason.MISSING_LOGIN_STATE,
            CallbackFailureReason.INVALID_LOGIN_STATE,
            CallbackFailureReason.LOGIN_REQUIRED,
            CallbackFailureReason.INVALID_GRANT,
        ]

        for reason in reasons:
            result = RedirectRequiredCallbackResult(redirect_url="https://example.com/login", reason=reason)
            assert result.reason == reason

    def test_redirect_required_type_is_readonly(self):
        """Test that type field is auto-set and readonly."""
        result = RedirectRequiredCallbackResult(
            redirect_url="https://example.com/login", reason=CallbackFailureReason.LOGIN_REQUIRED
        )
        assert result.type == CallbackResultType.REDIRECT_REQUIRED


class TestCallbackResult:
    """Test cases for CallbackResult Union type."""

    def test_callback_result_isinstance_completed(self):
        """Test isinstance check for CompletedCallbackResult."""
        user_info = UserInfo(
            user_id="user123", tenant_id="tenant123", application_id="app123", identity_provider_name="Wristband"
        )
        callback_data = CallbackData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1640995200000,
            expires_in=3600,
            tenant_name="tenant1",
            user_info=user_info,
            custom_state=None,
            refresh_token=None,
            return_url=None,
            tenant_custom_domain=None,
        )

        result: CallbackResult = CompletedCallbackResult(callback_data=callback_data)

        assert isinstance(result, CompletedCallbackResult)
        assert not isinstance(result, RedirectRequiredCallbackResult)
        assert result.type == CallbackResultType.COMPLETED

    def test_callback_result_isinstance_redirect(self):
        """Test isinstance check for RedirectRequiredCallbackResult."""
        result: CallbackResult = RedirectRequiredCallbackResult(
            redirect_url="https://example.com/login", reason=CallbackFailureReason.INVALID_GRANT
        )

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert not isinstance(result, CompletedCallbackResult)
        assert result.type == CallbackResultType.REDIRECT_REQUIRED

    def test_callback_result_type_narrowing(self):
        """Test type narrowing with isinstance checks."""
        user_info = UserInfo(
            user_id="user123", tenant_id="tenant123", application_id="app123", identity_provider_name="Wristband"
        )
        callback_data = CallbackData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1640995200000,
            expires_in=3600,
            tenant_name="tenant1",
            user_info=user_info,
            custom_state=None,
            refresh_token=None,
            return_url=None,
            tenant_custom_domain=None,
        )

        result: CallbackResult = CompletedCallbackResult(callback_data=callback_data)

        if isinstance(result, CompletedCallbackResult):
            # Type checker knows callback_data exists
            assert result.callback_data.access_token == "access_token_123"
        elif isinstance(result, RedirectRequiredCallbackResult):
            # Type checker knows redirect_url and reason exist
            assert result.redirect_url is not None
            assert result.reason is not None


class TestWristbandTokenResponse:
    """Test cases for WristbandTokenResponse dataclass."""

    def test_token_response_creation(self):
        """Test WristbandTokenResponse creation."""
        token_response = WristbandTokenResponse(
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
        """Test WristbandTokenResponse.from_api_response method."""
        api_response = {
            "access_token": "access_token_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh_token_123",
            "id_token": "id_token_123",
            "scope": "openid email profile",
        }

        token_response = WristbandTokenResponse.from_api_response(api_response)

        assert token_response.access_token == "access_token_123"
        assert token_response.token_type == "Bearer"
        assert token_response.expires_in == 3600
        assert token_response.refresh_token == "refresh_token_123"
        assert token_response.id_token == "id_token_123"
        assert token_response.scope == "openid email profile"

    def test_token_response_from_api_response_missing_fields(self):
        """Test WristbandTokenResponse.from_api_response with missing fields."""
        api_response = {
            "access_token": "access_token_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            # Missing refresh_token, id_token, scope
        }

        with pytest.raises(KeyError):
            WristbandTokenResponse.from_api_response(api_response)

    def test_token_response_from_api_response_extra_fields(self):
        """Test WristbandTokenResponse.from_api_response with extra fields."""
        api_response = {
            "access_token": "access_token_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh_token_123",
            "id_token": "id_token_123",
            "scope": "openid email profile",
            "extra_field": "ignored",  # This should be ignored
        }

        token_response = WristbandTokenResponse.from_api_response(api_response)

        assert token_response.access_token == "access_token_123"
        assert token_response.token_type == "Bearer"
        assert token_response.expires_in == 3600
        assert token_response.refresh_token == "refresh_token_123"
        assert token_response.id_token == "id_token_123"
        assert token_response.scope == "openid email profile"
        # Extra field is not accessible on the WristbandTokenResponse object


class TestLogoutConfig:
    """Test cases for LogoutConfig dataclass."""

    def test_logout_config_defaults(self):
        """Test LogoutConfig with default values."""
        config = LogoutConfig()

        assert config.redirect_url is None
        assert config.refresh_token is None
        assert config.state is None
        assert config.tenant_custom_domain is None
        assert config.tenant_name is None

    def test_logout_config_all_fields(self):
        """Test LogoutConfig with all fields specified."""
        config = LogoutConfig(
            redirect_url="https://example.com/goodbye",
            refresh_token="refresh_token_123",
            state="user_initiated_logout",
            tenant_custom_domain="custom.example.com",
            tenant_name="tenant1",
        )

        assert config.redirect_url == "https://example.com/goodbye"
        assert config.refresh_token == "refresh_token_123"
        assert config.state == "user_initiated_logout"
        assert config.tenant_custom_domain == "custom.example.com"
        assert config.tenant_name == "tenant1"

    def test_logout_config_partial_fields(self):
        """Test LogoutConfig with only some fields specified."""
        config = LogoutConfig(refresh_token="refresh_token_123", tenant_name="tenant1")

        assert config.redirect_url is None
        assert config.refresh_token == "refresh_token_123"
        assert config.state is None
        assert config.tenant_custom_domain is None
        assert config.tenant_name == "tenant1"


class TestCallbackFailureReason:
    """Test cases for CallbackFailureReason enum."""

    def test_callback_failure_reason_values(self):
        """Test CallbackFailureReason enum values."""
        assert CallbackFailureReason.MISSING_LOGIN_STATE.value == "missing_login_state"
        assert CallbackFailureReason.INVALID_LOGIN_STATE.value == "invalid_login_state"
        assert CallbackFailureReason.LOGIN_REQUIRED.value == "login_required"
        assert CallbackFailureReason.INVALID_GRANT.value == "invalid_grant"

    def test_callback_failure_reason_comparison(self):
        """Test CallbackFailureReason enum comparison."""
        assert CallbackFailureReason.MISSING_LOGIN_STATE == CallbackFailureReason.MISSING_LOGIN_STATE
        assert CallbackFailureReason.INVALID_GRANT != CallbackFailureReason.LOGIN_REQUIRED


class TestUserInfoRole:
    """Test cases for UserInfoRole dataclass."""

    def test_user_info_role_creation(self):
        """Test UserInfoRole creation with all fields."""
        role = UserInfoRole(id="role_123", name="app:myapp:admin", display_name="Admin Role")

        assert role.id == "role_123"
        assert role.name == "app:myapp:admin"
        assert role.display_name == "Admin Role"

    def test_user_info_role_from_api_response(self):
        """Test UserInfoRole.from_api_response with camelCase."""
        api_response = {"id": "role_123", "name": "app:myapp:admin", "displayName": "Admin Role"}

        role = UserInfoRole.from_api_response(api_response)

        assert role.id == "role_123"
        assert role.name == "app:myapp:admin"
        assert role.display_name == "Admin Role"

    def test_user_info_role_from_api_response_snake_case(self):
        """Test UserInfoRole.from_api_response with snake_case fallback."""
        api_response = {"id": "role_123", "name": "app:myapp:admin", "display_name": "Admin Role"}

        role = UserInfoRole.from_api_response(api_response)

        assert role.display_name == "Admin Role"

    def test_user_info_role_to_dict(self):
        """Test UserInfoRole.to_dict serializes to camelCase."""
        role = UserInfoRole(id="role_123", name="app:myapp:admin", display_name="Admin Role")

        result = role.to_dict()

        assert result == {"id": "role_123", "name": "app:myapp:admin", "displayName": "Admin Role"}

    def test_user_info_role_from_api_response_missing_display_name(self):
        """Test UserInfoRole.from_api_response when displayName is completely missing."""
        api_response = {
            "id": "role_123",
            "name": "app:myapp:admin",
            # No displayName or display_name key at all
        }

        role = UserInfoRole.from_api_response(api_response)

        assert role.id == "role_123"
        assert role.name == "app:myapp:admin"
        assert role.display_name == ""  # Should default to empty string


class TestUserInfo:
    """Test cases for UserInfo dataclass."""

    def test_user_info_creation_required_fields(self):
        """Test UserInfo creation with only required fields."""
        user_info = UserInfo(
            user_id="user123", tenant_id="tenant123", application_id="app123", identity_provider_name="Wristband"
        )

        assert user_info.user_id == "user123"
        assert user_info.tenant_id == "tenant123"
        assert user_info.application_id == "app123"
        assert user_info.identity_provider_name == "Wristband"

        # Optional fields should be None
        assert user_info.email is None
        assert user_info.full_name is None
        assert user_info.roles is None

    def test_user_info_creation_all_fields(self):
        """Test UserInfo creation with all fields."""
        role = UserInfoRole(id="role1", name="app:admin", display_name="Admin")

        user_info = UserInfo(
            user_id="user123",
            tenant_id="tenant123",
            application_id="app123",
            identity_provider_name="Wristband",
            full_name="Test User",
            given_name="Test",
            family_name="User",
            email="test@example.com",
            email_verified=True,
            roles=[role],
            custom_claims={"custom": "data"},
        )

        assert user_info.user_id == "user123"
        assert user_info.full_name == "Test User"
        assert user_info.email == "test@example.com"
        assert user_info.email_verified is True
        assert user_info.roles is not None
        assert len(user_info.roles) == 1
        assert user_info.roles[0].id == "role1"
        assert user_info.custom_claims == {"custom": "data"}

    def test_user_info_from_api_response_camel_case(self):
        """Test UserInfo.from_api_response with camelCase."""
        api_response = {
            "userId": "user123",
            "tenantId": "tenant123",
            "applicationId": "app123",
            "identityProviderName": "Wristband",
            "fullName": "Test User",
            "email": "test@example.com",
            "emailVerified": True,
            "roles": [{"id": "role1", "name": "app:admin", "displayName": "Admin"}],
            "customClaims": {"key": "value"},
        }

        user_info = UserInfo.from_api_response(api_response)

        assert user_info.user_id == "user123"
        assert user_info.tenant_id == "tenant123"
        assert user_info.full_name == "Test User"
        assert user_info.email == "test@example.com"
        assert user_info.email_verified is True
        assert user_info.roles is not None
        assert len(user_info.roles) == 1
        assert user_info.custom_claims == {"key": "value"}

    def test_user_info_from_raw_userinfo(self):
        """Test UserInfo.from_raw_userinfo conversion."""
        raw = RawUserInfo(
            sub="user123",
            tnt_id="tenant123",
            app_id="app123",
            idp_name="Wristband",
            name="Test User",
            email="test@example.com",
            preferred_username="testuser",
        )

        user_info = UserInfo.from_raw_userinfo(raw)

        assert user_info.user_id == "user123"
        assert user_info.tenant_id == "tenant123"
        assert user_info.full_name == "Test User"
        assert user_info.display_name == "testuser"
        assert user_info.email == "test@example.com"

    def test_user_info_to_dict(self):
        """Test UserInfo.to_dict serializes to camelCase."""
        role = UserInfoRole(id="role1", name="app:admin", display_name="Admin")

        user_info = UserInfo(
            user_id="user123",
            tenant_id="tenant123",
            application_id="app123",
            identity_provider_name="Wristband",
            email="test@example.com",
            email_verified=True,
            roles=[role],
        )

        result = user_info.to_dict()

        assert result["userId"] == "user123"
        assert result["tenantId"] == "tenant123"
        assert result["email"] == "test@example.com"
        assert result["emailVerified"] is True
        assert result["roles"][0]["displayName"] == "Admin"

    def test_user_info_to_dict_excludes_none_values(self):
        """Test UserInfo.to_dict only includes non-None values."""
        user_info = UserInfo(
            user_id="user123",
            tenant_id="tenant123",
            application_id="app123",
            identity_provider_name="Wristband",
            # All optional fields are None
        )

        result = user_info.to_dict()

        # Should only have required fields
        assert "userId" in result
        assert "tenantId" in result
        assert "applicationId" in result
        assert "identityProviderName" in result

        # Optional None fields should be excluded
        assert "email" not in result
        assert "fullName" not in result
        assert "roles" not in result
        assert "customClaims" not in result

    def test_user_info_from_api_response_snake_case(self):
        """Test UserInfo.from_api_response with snake_case fallback."""
        api_response = {
            "user_id": "user123",
            "tenant_id": "tenant123",
            "application_id": "app123",
            "identity_provider_name": "Wristband",
            "full_name": "Test User",
            "email": "test@example.com",
        }

        user_info = UserInfo.from_api_response(api_response)

        assert user_info.user_id == "user123"
        assert user_info.tenant_id == "tenant123"
        assert user_info.full_name == "Test User"
        assert user_info.email == "test@example.com"

    def test_user_info_from_api_response_prefers_camel_case_over_snake_case(self):
        """Test UserInfo.from_api_response prefers camelCase when both are present."""
        api_response = {
            "userId": "camel_user",
            "user_id": "snake_user",  # Should be ignored
            "tenantId": "camel_tenant",
            "tenant_id": "snake_tenant",  # Should be ignored
            "applicationId": "camel_app",
            "application_id": "snake_app",  # Should be ignored
            "identityProviderName": "CamelProvider",
            "identity_provider_name": "SnakeProvider",  # Should be ignored
            "fullName": "Camel Name",
            "full_name": "Snake Name",  # Should be ignored
        }

        user_info = UserInfo.from_api_response(api_response)

        # Should prefer camelCase
        assert user_info.user_id == "camel_user"
        assert user_info.tenant_id == "camel_tenant"
        assert user_info.application_id == "camel_app"
        assert user_info.identity_provider_name == "CamelProvider"
        assert user_info.full_name == "Camel Name"

    def test_user_info_from_api_response_empty_string_defaults(self):
        """Test UserInfo.from_api_response uses empty string when required fields missing."""
        api_response = {
            # All required fields missing - should default to empty strings
        }

        user_info = UserInfo.from_api_response(api_response)

        # Required fields should default to empty string from .get()
        assert user_info.user_id == ""
        assert user_info.tenant_id == ""
        assert user_info.application_id == ""
        assert user_info.identity_provider_name == ""

    def test_user_info_from_api_response_with_roles_empty_list(self):
        """Test UserInfo.from_api_response with empty roles list."""
        api_response = {
            "userId": "user123",
            "tenantId": "tenant123",
            "applicationId": "app123",
            "identityProviderName": "Wristband",
            "roles": [],  # Empty list
        }

        user_info = UserInfo.from_api_response(api_response)

        # Empty list should result in roles being None due to the `and response["roles"]` check
        assert user_info.roles is None

    def test_user_info_to_dict_includes_all_optional_fields_when_present(self):
        """Test UserInfo.to_dict includes all optional fields when they have values."""
        role = UserInfoRole(id="role1", name="app:admin", display_name="Admin")

        user_info = UserInfo(
            user_id="user123",
            tenant_id="tenant123",
            application_id="app123",
            identity_provider_name="Wristband",
            full_name="Test User",
            given_name="Given",
            family_name="Family",
            middle_name="Middle",
            nickname="Nick",
            display_name="Display",
            picture_url="https://example.com/pic.jpg",
            gender="male",
            birthdate="1990-01-01",
            time_zone="America/New_York",
            locale="en-US",
            updated_at=1640995200,
            email="test@example.com",
            email_verified=True,
            phone_number="+14155551234",
            phone_number_verified=False,
            roles=[role],
            custom_claims={"key": "value"},
        )

        result = user_info.to_dict()

        # Verify ALL optional fields are present when they have values
        assert "fullName" in result
        assert result["fullName"] == "Test User"
        assert "givenName" in result
        assert result["givenName"] == "Given"
        assert "familyName" in result
        assert result["familyName"] == "Family"
        assert "middleName" in result
        assert result["middleName"] == "Middle"
        assert "nickname" in result
        assert result["nickname"] == "Nick"
        assert "displayName" in result
        assert result["displayName"] == "Display"
        assert "pictureUrl" in result
        assert result["pictureUrl"] == "https://example.com/pic.jpg"
        assert "gender" in result
        assert result["gender"] == "male"
        assert "birthdate" in result
        assert result["birthdate"] == "1990-01-01"
        assert "timeZone" in result
        assert result["timeZone"] == "America/New_York"
        assert "locale" in result
        assert result["locale"] == "en-US"
        assert "updatedAt" in result
        assert result["updatedAt"] == 1640995200
        assert "email" in result
        assert result["email"] == "test@example.com"
        assert "emailVerified" in result
        assert result["emailVerified"] is True
        assert "phoneNumber" in result
        assert result["phoneNumber"] == "+14155551234"
        assert "phoneNumberVerified" in result
        assert result["phoneNumberVerified"] is False
        assert "roles" in result
        assert len(result["roles"]) == 1
        assert "customClaims" in result
        assert result["customClaims"] == {"key": "value"}


class TestRawUserInfo:
    """Test cases for RawUserInfo dataclass."""

    def test_raw_user_info_from_api_response(self):
        """Test RawUserInfo.from_api_response."""
        api_response = {
            "sub": "user123",
            "tnt_id": "tenant123",
            "app_id": "app123",
            "idp_name": "Wristband",
            "name": "Test User",
            "email": "test@example.com",
            "email_verified": True,
            "roles": [{"id": "role1", "name": "app:admin", "displayName": "Admin"}],
        }

        raw = RawUserInfo.from_api_response(api_response)

        assert raw.sub == "user123"
        assert raw.tnt_id == "tenant123"
        assert raw.name == "Test User"
        assert raw.email == "test@example.com"
        assert raw.roles is not None
        assert len(raw.roles) == 1

    def test_raw_user_info_creation(self):
        """Test RawUserInfo direct creation."""
        raw = RawUserInfo(
            sub="user123",
            tnt_id="tenant123",
            app_id="app123",
            idp_name="Wristband",
        )

        assert raw.sub == "user123"
        assert raw.tnt_id == "tenant123"
        assert raw.app_id == "app123"
        assert raw.idp_name == "Wristband"

        # Optional fields default to None
        assert raw.name is None
        assert raw.email is None
        assert raw.roles is None

    def test_raw_user_info_from_api_response_no_roles(self):
        """Test RawUserInfo.from_api_response without roles."""
        api_response = {
            "sub": "user123",
            "tnt_id": "tenant123",
            "app_id": "app123",
            "idp_name": "Wristband",
        }

        raw = RawUserInfo.from_api_response(api_response)

        assert raw.sub == "user123"
        assert raw.roles is None

    def test_raw_user_info_from_api_response_with_empty_roles_list(self):
        """Test RawUserInfo.from_api_response with empty roles list."""
        api_response = {
            "sub": "user123",
            "tnt_id": "tenant123",
            "app_id": "app123",
            "idp_name": "Wristband",
            "roles": [],  # Empty list
        }

        raw = RawUserInfo.from_api_response(api_response)

        assert raw.sub == "user123"
        # Empty list should result in roles being None due to the `and response["roles"]` check
        assert raw.roles is None


class TestSessionResponse:
    """Test cases for SessionResponse dataclass."""

    def test_session_response_creation(self):
        """Test SessionResponse creation with all fields."""
        metadata = {"email": "user@example.com", "role": "admin"}
        response = SessionResponse(tenant_id="tenant_abc123", user_id="user_xyz789", metadata=metadata)

        assert response.tenant_id == "tenant_abc123"
        assert response.user_id == "user_xyz789"
        assert response.metadata == metadata

    def test_session_response_empty_metadata(self):
        """Test SessionResponse with empty metadata dict."""
        response = SessionResponse(tenant_id="tenant_abc123", user_id="user_xyz789", metadata={})

        assert response.tenant_id == "tenant_abc123"
        assert response.user_id == "user_xyz789"
        assert response.metadata == {}

    def test_session_response_to_dict(self):
        """Test SessionResponse.to_dict serializes to camelCase."""
        metadata = {"email": "user@example.com", "custom_field": "value"}
        response = SessionResponse(tenant_id="tenant_abc123", user_id="user_xyz789", metadata=metadata)

        result = response.to_dict()

        assert result == {"tenantId": "tenant_abc123", "userId": "user_xyz789", "metadata": metadata}

    def test_session_response_to_dict_preserves_metadata_structure(self):
        """Test SessionResponse.to_dict preserves nested metadata."""
        metadata = {
            "email": "user@example.com",
            "preferences": {"theme": "dark", "notifications": True},
            "roles": ["admin", "user"],
        }
        response = SessionResponse(tenant_id="tenant_abc123", user_id="user_xyz789", metadata=metadata)

        result = response.to_dict()

        assert result["metadata"]["preferences"]["theme"] == "dark"
        assert result["metadata"]["roles"] == ["admin", "user"]

    def test_session_response_metadata_with_various_types(self):
        """Test SessionResponse metadata can contain various JSON-serializable types."""
        metadata = {
            "string": "value",
            "number": 42,
            "float": 3.14,
            "boolean": True,
            "null": None,
            "list": [1, 2, 3],
            "dict": {"nested": "value"},
        }
        response = SessionResponse(tenant_id="tenant_abc123", user_id="user_xyz789", metadata=metadata)

        result = response.to_dict()

        assert result["metadata"]["string"] == "value"
        assert result["metadata"]["number"] == 42
        assert result["metadata"]["float"] == 3.14
        assert result["metadata"]["boolean"] is True
        assert result["metadata"]["null"] is None
        assert result["metadata"]["list"] == [1, 2, 3]
        assert result["metadata"]["dict"]["nested"] == "value"


class TestTokenResponse:
    """Test cases for TokenResponse dataclass."""

    def test_token_response_creation(self):
        """Test TokenResponse creation with all fields."""
        response = TokenResponse(access_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", expires_at=1234567890)

        assert response.access_token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        assert response.expires_at == 1234567890

    def test_token_response_to_dict(self):
        """Test TokenResponse.to_dict serializes to camelCase."""
        response = TokenResponse(access_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", expires_at=1234567890)

        result = response.to_dict()

        assert result == {"accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "expiresAt": 1234567890}

    def test_token_response_with_long_token(self):
        """Test TokenResponse with a long JWT token."""
        long_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "a" * 500 + ".signature"
        response = TokenResponse(access_token=long_token, expires_at=1234567890)

        assert response.access_token == long_token
        assert len(response.access_token) > 500

    def test_token_response_expires_at_past_timestamp(self):
        """Test TokenResponse with a past timestamp (expired token)."""
        response = TokenResponse(access_token="expired_token", expires_at=1000000000)  # Old timestamp

        assert response.expires_at == 1000000000

    def test_token_response_expires_at_future_timestamp(self):
        """Test TokenResponse with a future timestamp."""
        response = TokenResponse(
            access_token="valid_token", expires_at=9999999999000  # Far future timestamp (milliseconds)
        )

        assert response.expires_at == 9999999999000


class TestAuthStrategy:
    """Test cases for AuthStrategy enum."""

    def test_auth_strategy_values(self):
        """Test AuthStrategy enum values."""
        assert AuthStrategy.SESSION.value == "session"
        assert AuthStrategy.JWT.value == "jwt"

    def test_auth_strategy_comparison(self):
        """Test AuthStrategy enum comparison."""
        assert AuthStrategy.SESSION == AuthStrategy.SESSION
        assert AuthStrategy.JWT == AuthStrategy.JWT
        assert AuthStrategy.SESSION != AuthStrategy.JWT

    def test_auth_strategy_string_equality(self):
        """Test AuthStrategy can be compared with strings."""
        assert AuthStrategy.SESSION == "session"
        assert AuthStrategy.JWT == "jwt"

    def test_auth_strategy_all_members(self):
        """Test all AuthStrategy members are present."""
        strategies = list(AuthStrategy)
        assert len(strategies) == 2
        assert AuthStrategy.SESSION in strategies
        assert AuthStrategy.JWT in strategies

    def test_auth_strategy_from_string(self):
        """Test creating AuthStrategy from string value."""
        session_strategy = AuthStrategy("session")
        jwt_strategy = AuthStrategy("jwt")

        assert session_strategy == AuthStrategy.SESSION
        assert jwt_strategy == AuthStrategy.JWT

    def test_auth_strategy_invalid_value(self):
        """Test creating AuthStrategy from invalid string raises error."""
        with pytest.raises(ValueError):
            AuthStrategy("invalid")


class TestUnauthenticatedBehavior:
    """Test cases for UnauthenticatedBehavior enum."""

    def test_unauthenticated_behavior_values(self):
        """Test UnauthenticatedBehavior enum values."""
        assert UnauthenticatedBehavior.REDIRECT.value == "redirect"
        assert UnauthenticatedBehavior.JSON.value == "json"

    def test_unauthenticated_behavior_comparison(self):
        """Test UnauthenticatedBehavior enum comparison."""
        assert UnauthenticatedBehavior.REDIRECT == UnauthenticatedBehavior.REDIRECT
        assert UnauthenticatedBehavior.JSON == UnauthenticatedBehavior.JSON
        assert UnauthenticatedBehavior.REDIRECT != UnauthenticatedBehavior.JSON

    def test_unauthenticated_behavior_string_equality(self):
        """Test UnauthenticatedBehavior can be compared with strings."""
        assert UnauthenticatedBehavior.REDIRECT == "redirect"
        assert UnauthenticatedBehavior.JSON == "json"

    def test_unauthenticated_behavior_all_members(self):
        """Test all UnauthenticatedBehavior members are present."""
        behaviors = list(UnauthenticatedBehavior)
        assert len(behaviors) == 2
        assert UnauthenticatedBehavior.REDIRECT in behaviors
        assert UnauthenticatedBehavior.JSON in behaviors

    def test_unauthenticated_behavior_from_string(self):
        """Test creating UnauthenticatedBehavior from string value."""
        redirect_behavior = UnauthenticatedBehavior("redirect")
        json_behavior = UnauthenticatedBehavior("json")

        assert redirect_behavior == UnauthenticatedBehavior.REDIRECT
        assert json_behavior == UnauthenticatedBehavior.JSON

    def test_unauthenticated_behavior_invalid_value(self):
        """Test creating UnauthenticatedBehavior from invalid string raises error."""
        with pytest.raises(ValueError):
            UnauthenticatedBehavior("invalid")


class TestJWTAuthConfig:
    """Test cases for JWTAuthConfig dataclass."""

    def test_jwt_auth_config_defaults(self):
        """Test JWTAuthConfig with default values."""
        config = JWTAuthConfig()

        assert config.jwks_cache_max_size == 20
        assert config.jwks_cache_ttl is None

    def test_jwt_auth_config_custom_values(self):
        """Test JWTAuthConfig with custom values."""
        config = JWTAuthConfig(jwks_cache_max_size=50, jwks_cache_ttl=3600)

        assert config.jwks_cache_max_size == 50
        assert config.jwks_cache_ttl == 3600

    def test_jwt_auth_config_zero_cache_size(self):
        """Test JWTAuthConfig with zero cache size."""
        config = JWTAuthConfig(jwks_cache_max_size=0)

        assert config.jwks_cache_max_size == 0

    def test_jwt_auth_config_zero_ttl(self):
        """Test JWTAuthConfig with zero TTL."""
        config = JWTAuthConfig(jwks_cache_ttl=0)

        assert config.jwks_cache_ttl == 0

    def test_jwt_auth_config_large_cache_size(self):
        """Test JWTAuthConfig with large cache size."""
        config = JWTAuthConfig(jwks_cache_max_size=10000)

        assert config.jwks_cache_max_size == 10000

    def test_jwt_auth_config_large_ttl(self):
        """Test JWTAuthConfig with large TTL value."""
        config = JWTAuthConfig(jwks_cache_ttl=86400 * 365)  # 1 year in seconds

        assert config.jwks_cache_ttl == 86400 * 365

    def test_jwt_auth_config_none_ttl_means_infinite(self):
        """Test JWTAuthConfig with None TTL means infinite cache."""
        config = JWTAuthConfig(jwks_cache_ttl=None)

        assert config.jwks_cache_ttl is None  # Infinite TTL


class TestJWTAuthResult:
    """Test cases for JWTAuthResult dataclass."""

    def test_jwt_auth_result_creation(self):
        """Test JWTAuthResult creation with mock payload."""
        from unittest.mock import Mock

        mock_payload = Mock()
        mock_payload.get.return_value = "user123"

        result = JWTAuthResult(jwt="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", payload=mock_payload)

        assert result.jwt == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        assert result.payload == mock_payload

    def test_jwt_auth_result_payload_access(self):
        """Test JWTAuthResult payload can be accessed."""
        from unittest.mock import Mock

        mock_payload = Mock()
        mock_payload.__getitem__ = Mock(
            side_effect=lambda key: {"sub": "user123", "tnt_id": "tenant456", "exp": 1234567890}[key]
        )

        result = JWTAuthResult(jwt="token", payload=mock_payload)

        assert result.payload["sub"] == "user123"
        assert result.payload["tnt_id"] == "tenant456"
        assert result.payload["exp"] == 1234567890

    def test_jwt_auth_result_with_long_jwt(self):
        """Test JWTAuthResult with a long JWT token."""
        from unittest.mock import Mock

        long_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "a" * 1000 + ".signature"
        mock_payload = Mock()

        result = JWTAuthResult(jwt=long_token, payload=mock_payload)

        assert result.jwt == long_token
        assert len(result.jwt) > 1000
