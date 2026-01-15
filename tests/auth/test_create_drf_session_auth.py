"""
Unit tests for WristbandAuth.create_drf_session_auth() method.

Tests the DRF authentication class factory for session-based authentication.
"""

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from django.conf import settings
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import RequestFactory
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from wristband.django_auth import AuthConfig, TokenData, WristbandAuth


@pytest.fixture
def auth_config():
    """Create basic AuthConfig for testing."""
    return AuthConfig(
        client_id="test_client",
        client_secret="test_secret_at_least_32_characters_long_for_encryption",
        login_state_secret="login_state_secret_32_chars_minimum_required_length",
        wristband_application_vanity_domain="app.wristband.dev",
        login_url="https://app.wristband.dev/login",
        redirect_uri="https://example.com/callback",
        auto_configure_enabled=False,
    )


@pytest.fixture
def wristband_auth(auth_config):
    """Create WristbandAuth instance."""
    return WristbandAuth(auth_config)


@pytest.fixture
def mock_request():
    """Create a proper Django request with session."""
    # Ensure test settings
    if not settings.configured:
        settings.configure(
            SECRET_KEY="test-secret-key-for-sessions",
            SESSION_ENGINE="django.contrib.sessions.backends.cache",
            CACHES={
                "default": {
                    "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                }
            },
        )

    factory = RequestFactory()
    request = factory.get("/")

    # Add session to request
    middleware = SessionMiddleware(lambda req: HttpResponse())
    middleware.process_request(request)
    request.session.save()

    # Set session data
    request.session["is_authenticated"] = True
    request.session["access_token"] = "token_123"
    request.session["expires_at"] = 9999999999999
    request.session["user_id"] = "user_123"
    request.session["tenant_id"] = "tenant_abc"
    request.session["tenant_name"] = "acme"
    request.session.save()

    return request


class TestCreateDrfSessionAuthBasics:
    """Test basic DRF session auth class creation."""

    def test_create_drf_session_auth_returns_class(self, wristband_auth):
        """Test factory returns authentication class."""
        auth_class = wristband_auth.create_drf_session_auth()

        assert auth_class is not None
        assert hasattr(auth_class, "authenticate")
        assert hasattr(auth_class, "authenticate_header")

    def test_create_drf_session_auth_is_base_authentication(self, wristband_auth):
        """Test returned class is DRF BaseAuthentication subclass."""
        auth_class = wristband_auth.create_drf_session_auth()
        auth_instance = auth_class()

        assert isinstance(auth_instance, BaseAuthentication)

    def test_multiple_auth_classes_can_be_created(self, wristband_auth):
        """Test creating multiple auth classes."""
        auth_class_1 = wristband_auth.create_drf_session_auth()
        auth_class_2 = wristband_auth.create_drf_session_auth()

        assert auth_class_1 is not None
        assert auth_class_2 is not None
        # Each call creates a new class
        assert auth_class_1 is not auth_class_2


class TestDrfSessionAuthAuthenticate:
    """Test authenticate method behavior."""

    def test_authenticate_with_valid_session(self, wristband_auth, mock_request):
        """Test authenticate returns user tuple with valid session."""
        WristbandSessionAuth = wristband_auth.create_drf_session_auth()
        auth_instance = WristbandSessionAuth()

        result = auth_instance.authenticate(mock_request)

        assert result is not None
        user, auth = result
        assert user is not None
        assert hasattr(user, "is_authenticated")
        assert user.is_authenticated is True
        assert auth is None  # Session auth returns None for auth

    def test_authenticate_with_invalid_session(self, wristband_auth, mock_request):
        """Test authenticate returns None with invalid session."""
        mock_request.session["is_authenticated"] = False
        mock_request.session.save()

        WristbandSessionAuth = wristband_auth.create_drf_session_auth()
        auth_instance = WristbandSessionAuth()

        result = auth_instance.authenticate(mock_request)

        assert result is None

    def test_authenticate_with_missing_session(self, wristband_auth, mock_request):
        """Test authenticate returns None with missing session data."""
        mock_request.session.clear()
        mock_request.session.save()

        WristbandSessionAuth = wristband_auth.create_drf_session_auth()
        auth_instance = WristbandSessionAuth()

        result = auth_instance.authenticate(mock_request)

        assert result is None

    def test_authenticate_refreshes_expired_token(self, wristband_auth, mock_request):
        """Test authenticate refreshes expired access token."""
        mock_request.session["expires_at"] = 1000000000  # Expired
        mock_request.session["refresh_token"] = "refresh_123"
        mock_request.session.save()

        with patch.object(wristband_auth, "refresh_token_if_expired") as mock_refresh:
            mock_refresh.return_value = TokenData(
                access_token="new_token",
                id_token="new_id",
                expires_at=9999999999999,
                expires_in=3600,
                refresh_token="new_refresh",
            )

            WristbandSessionAuth = wristband_auth.create_drf_session_auth()
            auth_instance = WristbandSessionAuth()

            result = auth_instance.authenticate(mock_request)

            assert result is not None
            assert mock_request.session["access_token"] == "new_token"
            mock_refresh.assert_called_once()

    def test_authenticate_returns_none_on_refresh_failure(self, wristband_auth, mock_request):
        """Test authenticate returns None when token refresh fails."""
        mock_request.session["expires_at"] = 1000000000  # Expired
        mock_request.session["refresh_token"] = "refresh_123"
        mock_request.session.save()

        with patch.object(wristband_auth, "refresh_token_if_expired") as mock_refresh:
            mock_refresh.side_effect = Exception("Refresh failed")

            WristbandSessionAuth = wristband_auth.create_drf_session_auth()
            auth_instance = WristbandSessionAuth()

            result = auth_instance.authenticate(mock_request)

            assert result is None

    def test_authenticate_marks_session_modified(self, wristband_auth, mock_request):
        """Test authenticate marks session as modified for rolling sessions."""
        WristbandSessionAuth = wristband_auth.create_drf_session_auth()
        auth_instance = WristbandSessionAuth()

        auth_instance.authenticate(mock_request)

        assert mock_request.session.modified is True


class TestDrfSessionAuthWithDjangoUser:
    """Test authenticate with Django User model integration."""

    def test_authenticate_preserves_django_user(self, wristband_auth, mock_request):
        """Test authenticate preserves existing Django User."""
        with patch("django.contrib.auth.get_user") as mock_get_user:
            with patch("django.contrib.auth.get_user_model") as mock_get_model:
                # Mock Django User
                mock_user = Mock()
                mock_user.is_authenticated = True
                mock_user.username = "user_123"
                mock_get_user.return_value = mock_user
                mock_get_model.return_value = type(mock_user)

                WristbandSessionAuth = wristband_auth.create_drf_session_auth()
                auth_instance = WristbandSessionAuth()

                result = auth_instance.authenticate(mock_request)

                assert result is not None
                user, auth = result
                assert user is mock_user
                assert auth is None

    def test_authenticate_creates_lightweight_user_without_django_user(self, wristband_auth, mock_request):
        """Test authenticate creates lightweight user when Django User not available."""
        with patch("django.contrib.auth.get_user") as mock_get_user:
            mock_get_user.return_value = None

            WristbandSessionAuth = wristband_auth.create_drf_session_auth()
            auth_instance = WristbandSessionAuth()

            result = auth_instance.authenticate(mock_request)

            assert result is not None
            user, auth = result
            assert hasattr(user, "is_authenticated")
            assert user.is_authenticated is True


class TestDrfSessionAuthHeader:
    """Test authenticate_header method."""

    def test_authenticate_header_returns_session(self, wristband_auth, mock_request):
        """Test authenticate_header returns 'Session' scheme."""
        WristbandSessionAuth = wristband_auth.create_drf_session_auth()
        auth_instance = WristbandSessionAuth()

        header = auth_instance.authenticate_header(mock_request)

        assert header == "Session"


class TestDrfSessionAuthWithAPIView:
    """Test integration with DRF APIView."""

    def test_auth_class_works_with_apiview(self, wristband_auth, mock_request):
        """Test auth class works with DRF APIView."""
        WristbandSessionAuth = wristband_auth.create_drf_session_auth()

        class TestAPIView(APIView):
            authentication_classes = [WristbandSessionAuth]
            permission_classes = [IsAuthenticated]

            def get(self, request):
                return Response({"status": "ok"})

        view = TestAPIView.as_view()
        response = view(mock_request)

        assert response.status_code == 200
        assert response.data == {"status": "ok"}  # type: ignore[arg-type]

    def test_auth_class_blocks_unauthenticated_request(self, wristband_auth, mock_request):
        """Test auth class blocks unauthenticated request."""
        mock_request.session["is_authenticated"] = False
        mock_request.session.save()

        WristbandSessionAuth = wristband_auth.create_drf_session_auth()

        class TestAPIView(APIView):
            authentication_classes = [WristbandSessionAuth]
            permission_classes = [IsAuthenticated]

            def get(self, request):
                return Response({"status": "ok"})

        view = TestAPIView.as_view()
        response = view(mock_request)

        assert response.status_code == 401

    def test_auth_class_allows_access_to_session_data(self, wristband_auth, mock_request):
        """Test view can access session data."""
        WristbandSessionAuth = wristband_auth.create_drf_session_auth()

        class TestAPIView(APIView):
            authentication_classes = [WristbandSessionAuth]
            permission_classes = [IsAuthenticated]

            def get(self, request):
                return Response({"user_id": request.session["user_id"], "tenant_name": request.session["tenant_name"]})

        view = TestAPIView.as_view()
        response = view(mock_request)

        assert response.status_code == 200
        assert response.data["user_id"] == "user_123"  # type: ignore[arg-type]
        assert response.data["tenant_name"] == "acme"  # type: ignore[arg-type]

    def test_auth_class_can_be_used_with_multiple_views(self, wristband_auth, mock_request):
        """Test same auth class works with multiple views."""
        WristbandSessionAuth = wristband_auth.create_drf_session_auth()

        class View1(APIView):
            authentication_classes = [WristbandSessionAuth]
            permission_classes = [IsAuthenticated]

            def get(self, request):
                return Response({"view": "1"})

        class View2(APIView):
            authentication_classes = [WristbandSessionAuth]
            permission_classes = [IsAuthenticated]

            def get(self, request):
                return Response({"view": "2"})

        view1 = View1.as_view()
        view2 = View2.as_view()

        response1 = view1(mock_request)
        response2 = view2(mock_request)

        assert response1.status_code == 200
        assert response2.status_code == 200
        assert response1.data == {"view": "1"}  # type: ignore[arg-type]
        assert response2.data == {"view": "2"}  # type: ignore[arg-type]


class TestDrfSessionAuthEdgeCases:
    """Test edge cases and error handling."""

    def test_auth_without_session_middleware(self, wristband_auth):
        """Test auth handles missing session gracefully."""
        request_no_session = SimpleNamespace()

        WristbandSessionAuth = wristband_auth.create_drf_session_auth()
        auth_instance = WristbandSessionAuth()

        # Should not crash, just return None
        with pytest.raises(AttributeError):
            auth_instance.authenticate(request_no_session)

    def test_auth_with_expired_token_no_refresh_token(self, wristband_auth, mock_request):
        """Test auth with expired token but no refresh token."""
        mock_request.session["expires_at"] = 1000000000  # Expired
        # No refresh_token in session
        mock_request.session.save()

        WristbandSessionAuth = wristband_auth.create_drf_session_auth()
        auth_instance = WristbandSessionAuth()

        # Should still authenticate (token refresh is optional)
        result = auth_instance.authenticate(mock_request)

        assert result is not None

    def test_auth_revalidates_on_every_request(self, wristband_auth, mock_request):
        """Test auth revalidates session on every request."""
        WristbandSessionAuth = wristband_auth.create_drf_session_auth()
        auth_instance = WristbandSessionAuth()

        # First request
        result1 = auth_instance.authenticate(mock_request)
        assert result1 is not None

        # Invalidate session
        mock_request.session["is_authenticated"] = False
        mock_request.session.save()

        # Second request should fail
        result2 = auth_instance.authenticate(mock_request)
        assert result2 is None

    def test_auth_instance_can_be_reused(self, wristband_auth, mock_request):
        """Test auth instance can be reused for multiple requests."""
        WristbandSessionAuth = wristband_auth.create_drf_session_auth()
        auth_instance = WristbandSessionAuth()

        # Call authenticate multiple times
        result1 = auth_instance.authenticate(mock_request)
        result2 = auth_instance.authenticate(mock_request)

        assert result1 is not None
        assert result2 is not None


class TestDrfSessionAuthWithoutDRF:
    """Test behavior when DRF is not installed."""

    def test_create_drf_session_auth_raises_without_drf(self, wristband_auth):
        """Test factory raises ImportError when DRF not installed."""
        with patch.dict("sys.modules", {"rest_framework": None, "rest_framework.authentication": None}):
            with pytest.raises(ImportError, match="Django REST Framework is required"):
                wristband_auth.create_drf_session_auth()
