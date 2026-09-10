from unittest.mock import patch

from django.conf import settings
from django.test import RequestFactory

from tests.utilities import assert_redirect_no_cache, test_login_state_secret
from wristband.django_auth.auth import WristbandAuth
from wristband.django_auth.models import AuthConfig, LogoutConfig, RedirectRequiredCallbackResult

# Configure Django settings for tests
urlpatterns = []
if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY="test-secret-key",
        DEFAULT_CHARSET="utf-8",
        USE_I18N=False,
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF=__name__,
    )


def _auth_config() -> AuthConfig:
    return AuthConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        login_state_secret=test_login_state_secret,
        login_url="https://auth.example.com/login",
        redirect_uri="https://app.example.com/callback",
        wristband_application_vanity_domain="auth.example.com",
        auto_configure_enabled=False,
    )


class TestLoginTenantCustomDomainValidation:
    """Test cases for tenant custom domain validation during login()."""

    def setup_method(self) -> None:
        self.wristband_auth = WristbandAuth(_auth_config())
        self.factory = RequestFactory()

    def test_login_uses_verified_tenant_custom_domain(self) -> None:
        """A verified tenant custom domain is used directly in the authorize URL."""
        request = self.factory.get("/login?tenant_custom_domain=tenant.custom.com")

        with patch.object(
            self.wristband_auth._wristband_api, "validate_tenant_custom_domain", return_value=True
        ) as mock_validate:
            response = self.wristband_auth.login(request)

        mock_validate.assert_called_once_with("tenant.custom.com")
        assert response.status_code == 302
        assert response["Location"].startswith("https://tenant.custom.com/api/v1/oauth2/authorize")

    def test_login_skips_unverified_tenant_custom_domain_and_falls_back_to_tenant_name(self) -> None:
        """An unverified/invalid tenant custom domain is skipped, falling back to tenant_name."""
        request = self.factory.get("/login?tenant_custom_domain=bogus.custom.com&tenant_name=tenant1")

        with patch.object(
            self.wristband_auth._wristband_api, "validate_tenant_custom_domain", return_value=False
        ) as mock_validate:
            response = self.wristband_auth.login(request)

        mock_validate.assert_called_once_with("bogus.custom.com")
        assert response.status_code == 302
        # Falls through to tenant name resolution instead of the bogus custom domain.
        assert response["Location"].startswith("https://tenant1-auth.example.com/api/v1/oauth2/authorize")

    def test_login_skips_unverified_tenant_custom_domain_and_falls_back_to_app_login(self) -> None:
        """When no other tenant info is available, an unverified domain falls back to app-level login."""
        request = self.factory.get("/login?tenant_custom_domain=bogus.custom.com")

        with patch.object(
            self.wristband_auth._wristband_api, "validate_tenant_custom_domain", return_value=False
        ) as mock_validate:
            response = self.wristband_auth.login(request)

        mock_validate.assert_called_once_with("bogus.custom.com")
        assert response.status_code == 302
        assert response["Location"] == "https://auth.example.com/login?client_id=test_client_id"

    def test_login_does_not_validate_when_no_domain_param_present(self) -> None:
        """validate_tenant_custom_domain is never called when there's no domain param to validate."""
        request = self.factory.get("/login?tenant_name=tenant1")

        with patch.object(self.wristband_auth._wristband_api, "validate_tenant_custom_domain") as mock_validate:
            self.wristband_auth.login(request)

        mock_validate.assert_not_called()


class TestCallbackTenantCustomDomainValidation:
    """Test cases for tenant custom domain validation during callback()."""

    def setup_method(self) -> None:
        self.wristband_auth = WristbandAuth(_auth_config())
        self.factory = RequestFactory()

    def test_callback_uses_verified_domain_in_redirect_url(self) -> None:
        """A verified tenant custom domain param is included in the tenant login redirect URL."""
        request = self.factory.get(
            "/callback?error=login_required&state=test_state&tenant_name=tenant1"
            "&tenant_custom_domain=tenant.custom.com"
        )

        with patch.object(
            self.wristband_auth._wristband_api, "validate_tenant_custom_domain", return_value=True
        ) as mock_validate:
            result = self.wristband_auth.callback(request)

        mock_validate.assert_called_once_with("tenant.custom.com")
        assert isinstance(result, RedirectRequiredCallbackResult)
        assert (
            result.redirect_url
            == "https://auth.example.com/login?tenant_name=tenant1&tenant_custom_domain=tenant.custom.com"
        )

    def test_callback_skips_unverified_domain_in_redirect_url(self) -> None:
        """An unverified tenant custom domain param is skipped in the tenant login redirect URL."""
        request = self.factory.get(
            "/callback?error=login_required&state=test_state&tenant_name=tenant1"
            "&tenant_custom_domain=bogus.custom.com"
        )

        with patch.object(
            self.wristband_auth._wristband_api, "validate_tenant_custom_domain", return_value=False
        ) as mock_validate:
            result = self.wristband_auth.callback(request)

        mock_validate.assert_called_once_with("bogus.custom.com")
        assert isinstance(result, RedirectRequiredCallbackResult)
        # No tenant_custom_domain query param appended since it was invalid.
        assert result.redirect_url == "https://auth.example.com/login?tenant_name=tenant1"


class TestLogoutTenantCustomDomainValidation:
    """Test cases for tenant custom domain validation during logout()."""

    def setup_method(self) -> None:
        self.wristband_auth = WristbandAuth(_auth_config())
        self.factory = RequestFactory()

    def test_logout_uses_verified_query_tenant_custom_domain(self) -> None:
        request = self.factory.get("/logout?tenant_custom_domain=tenant.custom.com")

        with (
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
            patch.object(
                self.wristband_auth._wristband_api, "validate_tenant_custom_domain", return_value=True
            ) as mock_validate,
        ):
            response = self.wristband_auth.logout(request, LogoutConfig())

        mock_validate.assert_called_once_with("tenant.custom.com")
        assert_redirect_no_cache(response, "https://tenant.custom.com/api/v1/logout?client_id=test_client_id")

    def test_logout_skips_unverified_query_tenant_custom_domain_and_falls_back_to_app_login(self) -> None:
        request = self.factory.get("/logout?tenant_custom_domain=bogus.custom.com")

        with (
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
            patch.object(
                self.wristband_auth._wristband_api, "validate_tenant_custom_domain", return_value=False
            ) as mock_validate,
        ):
            response = self.wristband_auth.logout(request, LogoutConfig())

        mock_validate.assert_called_once_with("bogus.custom.com")
        assert_redirect_no_cache(response, "https://auth.example.com/login?client_id=test_client_id")

    def test_logout_skips_unverified_query_tenant_custom_domain_and_falls_back_to_tenant_name(self) -> None:
        request = self.factory.get("/logout?tenant_custom_domain=bogus.custom.com&tenant_name=tenant1")

        with (
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
            patch.object(
                self.wristband_auth._wristband_api, "validate_tenant_custom_domain", return_value=False
            ) as mock_validate,
        ):
            response = self.wristband_auth.logout(request, LogoutConfig())

        mock_validate.assert_called_once_with("bogus.custom.com")
        assert_redirect_no_cache(response, "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id")
