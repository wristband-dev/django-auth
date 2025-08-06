import pytest
from django.conf import settings
from django.test import RequestFactory

from tests.utilities import assert_redirect_no_cache, test_login_state_secret
from wristband.django_auth.auth import WristbandAuth
from wristband.django_auth.models import AuthConfig

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


class TestWristbandAuthCreateCallbackResponse:
    """Test cases for create_callback_response method."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            token_expiry_buffer=60,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)
        self.factory = RequestFactory()

    def test_create_callback_response_invalid_redirect_url_none(self) -> None:
        """Test raises TypeError when redirect_url is None."""
        request = self.factory.get("/callback")

        with pytest.raises(TypeError, match="redirect_url cannot be null or empty"):
            self.wristband_auth.create_callback_response(request, None)

    def test_create_callback_response_invalid_redirect_url_empty(self) -> None:
        """Test raises TypeError when redirect_url is empty string."""
        request = self.factory.get("/callback")

        with pytest.raises(TypeError, match="redirect_url cannot be null or empty"):
            self.wristband_auth.create_callback_response(request, "")

    def test_create_callback_response_invalid_redirect_url_whitespace(self) -> None:
        """Test raises TypeError when redirect_url is only whitespace."""
        request = self.factory.get("/callback")

        with pytest.raises(TypeError, match="redirect_url cannot be null or empty"):
            self.wristband_auth.create_callback_response(request, "   ")

    def test_create_callback_response_valid_redirect_no_cookie(self) -> None:
        """Test successful response creation when no login state cookie exists."""
        request = self.factory.get("/callback?state=test_state")
        redirect_url = "https://app.example.com/dashboard"

        response = self.wristband_auth.create_callback_response(request, redirect_url)

        # Validate redirect response
        assert_redirect_no_cache(response, redirect_url)

        # Verify no cookies are set (since none existed to clear)
        assert len(response.cookies) == 0

    def test_create_callback_response_valid_redirect_with_cookie(self) -> None:
        """Test successful response creation when login state cookie exists and gets cleared."""
        request = self.factory.get("/callback?state=test_state")
        request.COOKIES = {"login#test_state#1640995200000": "encrypted_data"}

        redirect_url = "https://app.example.com/dashboard"

        response = self.wristband_auth.create_callback_response(request, redirect_url)

        # Validate redirect response
        assert_redirect_no_cache(response, redirect_url)

        # Verify cookie was cleared (set with max_age=0)
        assert "login#test_state#1640995200000" in response.cookies
        cleared_cookie = response.cookies["login#test_state#1640995200000"]
        assert cleared_cookie.value == ""
        assert cleared_cookie["max-age"] == 0
        assert cleared_cookie["path"] == "/"
        assert cleared_cookie["httponly"] is True
        assert cleared_cookie["secure"] is True  # Default secure cookies enabled

    def test_create_callback_response_complex_redirect_url(self) -> None:
        """Test response creation with complex redirect URL containing query parameters."""
        request = self.factory.get("/callback?state=test_state")
        redirect_url = "https://app.example.com/dashboard?user=123&tab=profile&return_to=%2Fsettings"

        response = self.wristband_auth.create_callback_response(request, redirect_url)

        assert_redirect_no_cache(response, redirect_url)

    def test_create_callback_response_secure_cookies_disabled(self) -> None:
        """Test response creation with secure cookies disabled."""
        # Create config with secure cookies disabled
        config_insecure = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=test_login_state_secret,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            dangerously_disable_secure_cookies=True,
        )
        wristband_auth = WristbandAuth(config_insecure)

        request = self.factory.get("/callback?state=test_state")
        request.COOKIES = {"login#test_state#1640995200000": "encrypted_data"}

        redirect_url = "https://app.example.com/dashboard"

        response = wristband_auth.create_callback_response(request, redirect_url)

        # Validate redirect response
        assert_redirect_no_cache(response, redirect_url)

        # Verify cookie was cleared with secure=False (Django omits secure attribute when False)
        cleared_cookie = response.cookies["login#test_state#1640995200000"]
        assert cleared_cookie["secure"] == ""  # Django doesn't set secure attribute when False

    def test_create_callback_response_no_state_parameter(self) -> None:
        """Test response creation when no state parameter exists in request."""
        request = self.factory.get("/callback")  # No state parameter
        request.COOKIES = {"login#some_state#1640995200000": "encrypted_data"}

        redirect_url = "https://app.example.com/dashboard"

        response = self.wristband_auth.create_callback_response(request, redirect_url)

        # Should still create successful response
        assert_redirect_no_cache(response, redirect_url)

        # Should not clear any cookies since state is empty string
        assert len(response.cookies) == 0

    def test_create_callback_response_multiple_matching_cookies(self) -> None:
        """Test response creation when multiple cookies match the state."""
        request = self.factory.get("/callback?state=test_state")
        request.COOKIES = {
            "login#test_state#1640995200000": "encrypted_data_1",
            "login#test_state#1640995300000": "encrypted_data_2",
            "other_cookie": "other_value",
        }

        redirect_url = "https://app.example.com/dashboard"

        response = self.wristband_auth.create_callback_response(request, redirect_url)

        # Validate redirect response
        assert_redirect_no_cache(response, redirect_url)

        # Should clear exactly one matching cookie (the first one found)
        cleared_cookies = [name for name in response.cookies.keys() if name.startswith("login#test_state#")]
        assert len(cleared_cookies) == 1

        # Verify the cleared cookie has correct properties
        cleared_cookie_name = cleared_cookies[0]
        cleared_cookie = response.cookies[cleared_cookie_name]
        assert cleared_cookie.value == ""
        assert cleared_cookie["max-age"] == 0

    def test_create_callback_response_headers_set_correctly(self) -> None:
        """Test that Cache-Control and Pragma headers are set correctly."""
        request = self.factory.get("/callback?state=test_state")
        redirect_url = "https://app.example.com/dashboard"

        response = self.wristband_auth.create_callback_response(request, redirect_url)

        # Verify security headers are set
        assert response["Cache-Control"] == "no-store"
        assert response["Pragma"] == "no-cache"

        # Verify redirect properties
        assert response.status_code == 302
        assert response["Location"] == redirect_url
