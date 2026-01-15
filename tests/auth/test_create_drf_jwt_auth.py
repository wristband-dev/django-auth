"""
Unit tests for WristbandAuth.create_drf_jwt_auth() method.

Tests the DRF authentication class factory for JWT bearer token authentication.
"""

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
from wristband.python_jwt import JwtValidationResult

from wristband.django_auth import AuthConfig, JWTAuthConfig, WristbandAuth


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
    """Create a proper Django request."""
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

    # Add session to request (some views might need it)
    middleware = SessionMiddleware(lambda req: HttpResponse())
    middleware.process_request(request)
    request.session.save()

    return request


class TestCreateDrfJwtAuthBasics:
    """Test basic DRF JWT auth class creation."""

    def test_create_drf_jwt_auth_returns_class(self, wristband_auth):
        """Test factory returns authentication class."""
        auth_class = wristband_auth.create_drf_jwt_auth()

        assert auth_class is not None
        assert hasattr(auth_class, "authenticate")
        assert hasattr(auth_class, "authenticate_header")

    def test_create_drf_jwt_auth_is_base_authentication(self, wristband_auth):
        """Test returned class is DRF BaseAuthentication subclass."""
        auth_class = wristband_auth.create_drf_jwt_auth()
        auth_instance = auth_class()

        assert isinstance(auth_instance, BaseAuthentication)

    def test_multiple_auth_classes_can_be_created(self, wristband_auth):
        """Test creating multiple auth classes."""
        auth_class_1 = wristband_auth.create_drf_jwt_auth()
        auth_class_2 = wristband_auth.create_drf_jwt_auth()

        assert auth_class_1 is not None
        assert auth_class_2 is not None
        # Each call creates a new class
        assert auth_class_1 is not auth_class_2

    def test_create_drf_jwt_auth_with_config(self, wristband_auth):
        """Test creating auth class with JWT config."""
        jwt_config = JWTAuthConfig(jwks_cache_max_size=50, jwks_cache_ttl=3600)

        auth_class = wristband_auth.create_drf_jwt_auth(jwt_config=jwt_config)

        assert auth_class is not None

    def test_create_drf_jwt_auth_with_none_config(self, wristband_auth):
        """Test creating auth class with None config."""
        auth_class = wristband_auth.create_drf_jwt_auth(jwt_config=None)

        assert auth_class is not None


class TestDrfJwtAuthAuthenticate:
    """Test authenticate method behavior."""

    def test_authenticate_with_valid_jwt(self, wristband_auth, mock_request):
        """Test authenticate returns user tuple with valid JWT."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc", "app_id": "app_xyz"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()
            auth_instance = WristbandJwtAuth()

            result = auth_instance.authenticate(mock_request)

            assert result is not None
            user, auth = result
            assert user is not None
            assert hasattr(user, "is_authenticated")
            assert user.is_authenticated is True
            assert auth is not None
            assert auth.jwt == "valid_jwt_token"
            assert auth.payload["sub"] == "user_123"

    def test_authenticate_with_missing_authorization_header(self, wristband_auth, mock_request):
        """Test authenticate returns None without Authorization header."""
        with patch.object(wristband_auth, "_create_jwt_validator"):
            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()
            auth_instance = WristbandJwtAuth()

            result = auth_instance.authenticate(mock_request)

            assert result is None

    def test_authenticate_with_invalid_jwt(self, wristband_auth, mock_request):
        """Test authenticate returns None with invalid JWT."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer invalid_jwt"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "invalid_jwt"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = False
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()
            auth_instance = WristbandJwtAuth()

            result = auth_instance.authenticate(mock_request)

            assert result is None

    def test_authenticate_with_malformed_header(self, wristband_auth, mock_request):
        """Test authenticate returns None with malformed header."""
        mock_request.META["HTTP_AUTHORIZATION"] = "NotBearer token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = None
            mock_create_validator.return_value = mock_validator

            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()
            auth_instance = WristbandJwtAuth()

            result = auth_instance.authenticate(mock_request)

            assert result is None

    def test_authenticate_sets_request_auth(self, wristband_auth, mock_request):
        """Test authenticate sets request.auth with JWT data."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()
            auth_instance = WristbandJwtAuth()

            result = auth_instance.authenticate(mock_request)

            assert result is not None
            assert hasattr(mock_request, "auth")
            assert mock_request.auth.jwt == "valid_jwt_token"
            assert mock_request.auth.payload["sub"] == "user_123"

    def test_authenticate_handles_validation_exception(self, wristband_auth, mock_request):
        """Test authenticate returns None when validation raises exception."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer bad_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "bad_token"
            mock_validator.validate.side_effect = Exception("Validation failed")
            mock_create_validator.return_value = mock_validator

            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()
            auth_instance = WristbandJwtAuth()

            result = auth_instance.authenticate(mock_request)

            assert result is None


class TestDrfJwtAuthWithDjangoUser:
    """Test authenticate with Django User model integration."""

    def test_authenticate_preserves_django_user_when_username_matches(self, wristband_auth, mock_request):
        """Test authenticate preserves Django User when username matches JWT sub."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            with patch("django.contrib.auth.get_user") as mock_get_user:
                with patch("django.contrib.auth.get_user_model") as mock_get_model:
                    # Mock Django User with matching username
                    mock_user = Mock()
                    mock_user.is_authenticated = True
                    mock_user.username = "user_123"
                    mock_get_user.return_value = mock_user
                    mock_get_model.return_value = type(mock_user)

                    WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()
                    auth_instance = WristbandJwtAuth()

                    result = auth_instance.authenticate(mock_request)

                    assert result is not None
                    user, auth = result
                    assert user is mock_user

    def test_authenticate_creates_jwt_user_when_username_not_matches(self, wristband_auth, mock_request):
        """Test authenticate creates JWT user when username doesn't match."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            with patch("django.contrib.auth.get_user") as mock_get_user:
                with patch("django.contrib.auth.get_user_model") as mock_get_model:
                    # Mock Django User with different username
                    mock_user = Mock()
                    mock_user.is_authenticated = True
                    mock_user.username = "different_user"
                    mock_get_user.return_value = mock_user
                    mock_get_model.return_value = type(mock_user)

                    WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()
                    auth_instance = WristbandJwtAuth()

                    result = auth_instance.authenticate(mock_request)

                    assert result is not None
                    user, auth = result
                    assert user is not mock_user
                    assert hasattr(user, "is_authenticated")
                    assert user.is_authenticated is True

    def test_authenticate_creates_jwt_user_without_django_user(self, wristband_auth, mock_request):
        """Test authenticate creates JWT user when no Django User exists."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            with patch("django.contrib.auth.get_user") as mock_get_user:
                mock_get_user.return_value = None

                WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()
                auth_instance = WristbandJwtAuth()

                result = auth_instance.authenticate(mock_request)

                assert result is not None
                user, auth = result
                assert hasattr(user, "is_authenticated")
                assert user.is_authenticated is True
                assert hasattr(user, "claims")
                assert user.id == "user_123"


class TestDrfJwtAuthHeader:
    """Test authenticate_header method."""

    def test_authenticate_header_returns_bearer(self, wristband_auth, mock_request):
        """Test authenticate_header returns Bearer realm."""
        with patch.object(wristband_auth, "_create_jwt_validator"):
            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()
            auth_instance = WristbandJwtAuth()

            header = auth_instance.authenticate_header(mock_request)

            assert header == 'Bearer realm="api"'


class TestDrfJwtAuthWithAPIView:
    """Test integration with DRF APIView."""

    def test_auth_class_works_with_apiview(self, wristband_auth, mock_request):
        """Test auth class works with DRF APIView."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()

            class TestAPIView(APIView):
                authentication_classes = [WristbandJwtAuth]
                permission_classes = [IsAuthenticated]

                def get(self, request):
                    return Response({"status": "ok"})

            view = TestAPIView.as_view()
            response = view(mock_request)

            assert response.status_code == 200
            assert response.data == {"status": "ok"}  # type: ignore[attr-defined]

    def test_auth_class_blocks_unauthenticated_request(self, wristband_auth, mock_request):
        """Test auth class blocks request without JWT."""
        with patch.object(wristband_auth, "_create_jwt_validator"):
            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()

            class TestAPIView(APIView):
                authentication_classes = [WristbandJwtAuth]
                permission_classes = [IsAuthenticated]

                def get(self, request):
                    return Response({"status": "ok"})

            view = TestAPIView.as_view()
            response = view(mock_request)

            assert response.status_code == 401

    def test_auth_class_allows_access_to_jwt_payload(self, wristband_auth, mock_request):
        """Test view can access JWT payload via request.auth."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc", "app_id": "app_xyz"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()

            class TestAPIView(APIView):
                authentication_classes = [WristbandJwtAuth]
                permission_classes = [IsAuthenticated]

                def get(self, request):
                    return Response(
                        {
                            "user_id": request.auth.payload["sub"],
                            "tenant_id": request.auth.payload["tnt_id"],
                            "app_id": request.auth.payload["app_id"],
                        }
                    )

            view = TestAPIView.as_view()
            response = view(mock_request)

            assert response.status_code == 200
            assert response.data["user_id"] == "user_123"  # type: ignore[attr-defined]
            assert response.data["tenant_id"] == "tenant_abc"  # type: ignore[attr-defined]
            assert response.data["app_id"] == "app_xyz"  # type: ignore[attr-defined]

    def test_auth_class_can_be_used_with_multiple_views(self, wristband_auth, mock_request):
        """Test same auth class works with multiple views."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()

            class View1(APIView):
                authentication_classes = [WristbandJwtAuth]
                permission_classes = [IsAuthenticated]

                def get(self, request):
                    return Response({"view": "1"})

            class View2(APIView):
                authentication_classes = [WristbandJwtAuth]
                permission_classes = [IsAuthenticated]

                def get(self, request):
                    return Response({"view": "2"})

            view1 = View1.as_view()
            view2 = View2.as_view()

            response1 = view1(mock_request)
            response2 = view2(mock_request)

            assert response1.status_code == 200
            assert response2.status_code == 200
            assert response1.data == {"view": "1"}  # type: ignore[attr-defined]
            assert response2.data == {"view": "2"}  # type: ignore[attr-defined]


class TestDrfJwtAuthEdgeCases:
    """Test edge cases and error handling."""

    def test_auth_caches_jwt_validator(self, wristband_auth, mock_request):
        """Test JWT validator is created once and cached."""
        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = None
            mock_create.return_value = mock_validator

            # Create auth class
            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()

            # Validator created once during class creation
            mock_create.assert_called_once()

            # Creating instances doesn't recreate validator
            auth1 = WristbandJwtAuth()
            auth2 = WristbandJwtAuth()

            auth1.authenticate(mock_request)
            auth2.authenticate(mock_request)

            # Still only called once
            mock_create.assert_called_once()

    def test_auth_instance_can_be_reused(self, wristband_auth, mock_request):
        """Test auth instance can be reused for multiple requests."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()
            auth_instance = WristbandJwtAuth()

            # Call authenticate multiple times
            result1 = auth_instance.authenticate(mock_request)
            result2 = auth_instance.authenticate(mock_request)

            assert result1 is not None
            assert result2 is not None

    def test_auth_validates_on_every_request(self, wristband_auth, mock_request):
        """Test auth validates JWT on every request."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            WristbandJwtAuth = wristband_auth.create_drf_jwt_auth()
            auth_instance = WristbandJwtAuth()

            # First request
            result1 = auth_instance.authenticate(mock_request)
            assert result1 is not None

            # Change to invalid token
            mock_result.is_valid = False

            # Second request should fail
            result2 = auth_instance.authenticate(mock_request)
            assert result2 is None


class TestDrfJwtAuthWithoutDRF:
    """Test behavior when DRF is not installed."""

    def test_create_drf_jwt_auth_raises_without_drf(self, wristband_auth):
        """Test factory raises ImportError when DRF not installed."""
        with patch.dict("sys.modules", {"rest_framework": None, "rest_framework.authentication": None}):
            with pytest.raises(ImportError, match="Django REST Framework is required"):
                wristband_auth.create_drf_jwt_auth()
