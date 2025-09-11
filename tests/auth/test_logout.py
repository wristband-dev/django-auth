from unittest.mock import patch

import pytest
from django.conf import settings
from django.test import RequestFactory

from tests.utilities import assert_redirect_no_cache, test_login_state_secret
from wristband.django_auth.auth import WristbandAuth
from wristband.django_auth.models import AuthConfig, LogoutConfig

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


class TestWristbandAuthLogout:
    """Test cases for WristbandAuth logout method."""

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

    def test_logout_with_config_tenant_custom_domain_priority_1(self) -> None:
        """Test logout uses config tenant custom domain as highest priority."""
        request = self.factory.get("/logout?tenant_domain=tenant1&tenant_custom_domain=tenant1.custom.com")
        logout_config = LogoutConfig(
            tenant_custom_domain="config.custom.com",
            tenant_domain_name="config-tenant",
            redirect_url="https://app.example.com/logged-out",
        )

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        # Should use config tenant custom domain (priority 1)
        expected_url = (
            "https://config.custom.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/logged-out"
        )
        assert_redirect_no_cache(response, expected_url)

    def test_logout_with_config_tenant_domain_priority_2(self) -> None:
        """Test logout uses config tenant domain as second priority."""
        request = self.factory.get("/logout?tenant_domain=tenant1&tenant_custom_domain=tenant1.custom.com")
        logout_config = LogoutConfig(
            tenant_domain_name="config-tenant", redirect_url="https://app.example.com/logged-out"
        )

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        # Should use config tenant domain (priority 2)
        expected_url = (
            "https://config-tenant-auth.example.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/logged-out"
        )
        assert_redirect_no_cache(response, expected_url)

    def test_logout_with_query_tenant_custom_domain_priority_3(self) -> None:
        """Test logout uses query tenant custom domain as third priority."""
        request = self.factory.get("/logout?tenant_domain=tenant1&tenant_custom_domain=tenant1.custom.com")
        logout_config = LogoutConfig()

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        # Should use query tenant custom domain (priority 3)
        expected_url = "https://tenant1.custom.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    def test_logout_with_query_tenant_domain_priority_4(self) -> None:
        """Test logout uses query tenant domain as fourth priority."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig()

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        # Should use query tenant domain (priority 4)
        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    def test_logout_with_subdomain_parsing_priority_4a(self) -> None:
        """Test logout uses subdomain parsing when enabled."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            is_application_custom_domain_active=True,  # Uses "." separator
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = self.factory.get("/logout")
        logout_config = LogoutConfig()

        with patch.object(request, "get_host", return_value="tenant1.auth.example.com"):
            with patch.object(wristband_auth._wristband_api, "revoke_refresh_token"):
                response = wristband_auth.logout(request, logout_config)

        # Should use subdomain with "." separator
        expected_url = "https://tenant1.auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    def test_logout_fallback_to_app_login_when_no_tenant_info(self) -> None:
        """Test logout falls back to app login URL when no tenant info available."""
        request = self.factory.get("/logout")
        logout_config = LogoutConfig()

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        # Should fallback to app login URL
        expected_url = (
            f"https://{self.auth_config.wristband_application_vanity_domain}/login"
            f"?client_id={self.auth_config.client_id}"
        )
        assert_redirect_no_cache(response, expected_url)

    def test_logout_fallback_to_custom_application_login_page(self) -> None:
        """Test logout falls back to custom application login page when configured."""
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

        request = self.factory.get("/logout")
        logout_config = LogoutConfig()

        with patch.object(wristband_auth._wristband_api, "revoke_refresh_token"):
            response = wristband_auth.logout(request, logout_config)

        # Should use custom login page as fallback
        expected_url = f"{custom_url}?client_id={config_with_custom.client_id}"
        assert_redirect_no_cache(response, expected_url)

    def test_logout_with_config_redirect_url_overrides_fallback(self) -> None:
        """Test logout uses config redirect_url to override fallback when no tenant info."""
        request = self.factory.get("/logout")
        logout_config = LogoutConfig(redirect_url="https://app.example.com/goodbye")

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        # Should use config redirect_url instead of app login fallback
        expected_url = "https://app.example.com/goodbye"
        assert_redirect_no_cache(response, expected_url)

    def test_logout_with_refresh_token_revokes_successfully(self) -> None:
        """Test logout revokes refresh token when provided."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig(refresh_token="valid_refresh_token")

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token") as mock_revoke:
            response = self.wristband_auth.logout(request, logout_config)

        # Should call revoke_refresh_token
        mock_revoke.assert_called_once_with("valid_refresh_token")

        # Should still redirect properly
        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    def test_logout_with_refresh_token_revoke_fails_continues_logout(self) -> None:
        """Test logout continues even if refresh token revocation fails."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig(refresh_token="invalid_refresh_token")

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token") as mock_revoke:
            mock_revoke.side_effect = Exception("Revocation failed")

            # Should not raise exception, just log warning
            response = self.wristband_auth.logout(request, logout_config)

        # Should still redirect properly despite revocation failure
        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    def test_logout_without_refresh_token_skips_revocation(self) -> None:
        """Test logout skips revocation when no refresh token provided."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig()

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token") as mock_revoke:
            response = self.wristband_auth.logout(request, logout_config)

        # Should not call revoke_refresh_token
        mock_revoke.assert_not_called()

        # Should still redirect properly
        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    def test_logout_builds_logout_path_with_redirect_url(self) -> None:
        """Test logout builds correct path with redirect_url parameter."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig(redirect_url="https://app.example.com/farewell")

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        expected_url = (
            "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/farewell"
        )
        assert_redirect_no_cache(response, expected_url)

    def test_logout_builds_logout_path_without_redirect_url(self) -> None:
        """Test logout builds correct path without redirect_url parameter."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig()

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    def test_logout_with_application_custom_domain_uses_dot_separator(self) -> None:
        """Test logout uses dot separator when application custom domain is active."""
        config_with_custom_domain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            is_application_custom_domain_active=True,
            auto_configure_enabled=False,
        )
        wristband_auth = WristbandAuth(config_with_custom_domain)

        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig()

        with patch.object(wristband_auth._wristband_api, "revoke_refresh_token"):
            response = wristband_auth.logout(request, logout_config)

        # Should use "." separator instead of "-"
        expected_url = "https://tenant1.auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    def test_logout_sets_cache_control_headers(self) -> None:
        """Test logout sets proper cache control headers."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig()

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        # Verify security headers are set
        assert response["Cache-Control"] == "no-store"
        assert response["Pragma"] == "no-cache"

    def test_logout_empty_config_values_are_ignored(self) -> None:
        """Test logout ignores empty string values in config."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig(
            tenant_custom_domain="",  # Empty string should be ignored
            tenant_domain_name="   ",  # Whitespace only should be ignored
        )

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        # Should fall back to query parameter since config values are empty/whitespace
        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    def test_logout_builds_logout_path_with_state(self) -> None:
        """Test logout builds correct path with state parameter."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig(state="custom_state_value")

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        expected_url = (
            "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id" "&state=custom_state_value"
        )
        assert_redirect_no_cache(response, expected_url)

    def test_logout_builds_logout_path_with_redirect_url_and_state(self) -> None:
        """Test logout builds correct path with both redirect_url and state parameters."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig(redirect_url="https://app.example.com/farewell", state="custom_state_value")

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        expected_url = (
            "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/farewell&state=custom_state_value"
        )
        assert_redirect_no_cache(response, expected_url)

    def test_logout_ignores_empty_string_state(self) -> None:
        """Test logout ignores empty string state parameter."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig(
            redirect_url="https://app.example.com/farewell", state=""  # Empty string should be ignored
        )

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        expected_url = (
            "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/farewell"
        )
        assert_redirect_no_cache(response, expected_url)

    def test_logout_ignores_whitespace_only_state(self) -> None:
        """Test logout ignores whitespace-only state parameter."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig(
            redirect_url="https://app.example.com/farewell", state="   "  # Whitespace only should be ignored
        )

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        expected_url = (
            "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/farewell"
        )
        assert_redirect_no_cache(response, expected_url)

    def test_logout_with_state_only_no_redirect_url(self) -> None:
        """Test logout includes state parameter even when no redirect_url is provided."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig(state="state_without_redirect")

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        expected_url = (
            "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id" "&state=state_without_redirect"
        )
        assert_redirect_no_cache(response, expected_url)

    def test_logout_with_state_and_tenant_custom_domain(self) -> None:
        """Test logout includes state parameter with tenant custom domain."""
        request = self.factory.get("/logout?tenant_domain=tenant1&tenant_custom_domain=tenant1.custom.com")
        logout_config = LogoutConfig(state="custom_domain_state")

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        expected_url = "https://tenant1.custom.com/api/v1/logout?client_id=test_client_id" "&state=custom_domain_state"
        assert_redirect_no_cache(response, expected_url)

    def test_logout_with_state_special_characters_url_encoded(self) -> None:
        """Test logout properly handles state with special characters that need URL encoding."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        logout_config = LogoutConfig(state="state with spaces & symbols")

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        # Note: The state is passed directly to the URL, so special characters should be properly encoded
        expected_url = (
            "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
            "&state=state with spaces & symbols"
        )
        assert_redirect_no_cache(response, expected_url)

    def test_logout_with_state_too_long_raises_value_error(self) -> None:
        """Test logout raises ValueError when state exceeds 512 characters."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        # Create a state string longer than 512 characters
        long_state = "a" * 513
        logout_config = LogoutConfig(state=long_state)

        with pytest.raises(ValueError, match="The \\[state\\] logout config cannot exceed 512 characters."):
            self.wristband_auth.logout(request, logout_config)

    def test_logout_with_state_exactly_512_characters_succeeds(self) -> None:
        """Test logout succeeds when state is exactly 512 characters."""
        request = self.factory.get("/logout?tenant_domain=tenant1")
        # Create a state string exactly 512 characters
        exact_state = "a" * 512
        logout_config = LogoutConfig(state=exact_state)

        with patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"):
            response = self.wristband_auth.logout(request, logout_config)

        # Should succeed and include the state
        expected_url = (
            f"https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id" f"&state={exact_state}"
        )
        assert_redirect_no_cache(response, expected_url)
