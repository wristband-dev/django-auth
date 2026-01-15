"""
Unit tests for WristbandAuth.create_auth_decorator() method.

Tests the decorator factory for function-based views with session
and JWT authentication strategies.
"""

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from django.contrib.sessions.backends.cache import SessionStore
from django.http import HttpRequest, HttpResponse, JsonResponse
from wristband.python_jwt import JwtValidationResult

from wristband.django_auth import (
    AuthConfig,
    AuthStrategy,
    JWTAuthConfig,
    TokenData,
    UnauthenticatedBehavior,
    WristbandAuth,
)


@pytest.fixture
def auth_config():
    """Create basic AuthConfig for testing."""
    return AuthConfig(
        client_id="test_client",
        client_secret="test_secret_at_least_32_characters_long_for_encryption",
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
    """Create a mock HttpRequest with session."""
    request = Mock(spec=HttpRequest)
    # Use real Django session (cache-based, in-memory)
    session = SessionStore()
    session.create()
    session["is_authenticated"] = True
    session["access_token"] = "token_123"
    session["expires_at"] = 9999999999999  # Far future
    session["user_id"] = "user_123"
    session.modified = False

    request.session = session
    request.headers = {}
    request.GET = {}
    return request


@pytest.fixture
def mock_view():
    """Create a mock view function."""

    def view(request):
        return HttpResponse("Success")

    return view


class TestCreateAuthDecoratorBasics:
    """Test basic decorator creation and validation."""

    def test_create_auth_decorator_with_session_strategy(self, wristband_auth):
        """Test creating decorator with session strategy."""
        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION])

        assert callable(decorator)

    def test_create_auth_decorator_with_jwt_strategy(self, wristband_auth):
        """Test creating decorator with JWT strategy."""
        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.JWT])

        assert callable(decorator)

    def test_create_auth_decorator_with_multiple_strategies(self, wristband_auth):
        """Test creating decorator with multiple strategies."""
        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])

        assert callable(decorator)

    def test_create_auth_decorator_raises_on_empty_strategies(self, wristband_auth):
        """Test that empty strategies list raises ValueError."""
        with pytest.raises(ValueError, match="At least one authentication strategy must be provided"):
            wristband_auth.create_auth_decorator(strategies=[])

    def test_create_auth_decorator_raises_on_duplicate_strategies(self, wristband_auth):
        """Test that duplicate strategies raise ValueError."""
        with pytest.raises(ValueError, match="Duplicate authentication strategies are not allowed"):
            wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION, AuthStrategy.SESSION])

    def test_create_auth_decorator_raises_on_invalid_strategy(self, wristband_auth):
        """Test that invalid strategy raises ValueError."""
        with pytest.raises(ValueError, match="Invalid authentication strategy"):
            wristband_auth.create_auth_decorator(strategies=["invalid"])  # type: ignore[list-item]

    def test_create_auth_decorator_raises_on_invalid_unauthenticated_behavior(self, wristband_auth):
        """Test that invalid on_unauthenticated raises ValueError."""
        with pytest.raises(ValueError, match="Invalid on_unauthenticated value"):
            wristband_auth.create_auth_decorator(
                strategies=[AuthStrategy.SESSION], on_unauthenticated="invalid"  # type: ignore[arg-type]
            )

    def test_create_auth_decorator_with_redirect_behavior(self, wristband_auth):
        """Test creating decorator with redirect behavior."""
        decorator = wristband_auth.create_auth_decorator(
            strategies=[AuthStrategy.SESSION], on_unauthenticated=UnauthenticatedBehavior.REDIRECT
        )

        assert callable(decorator)

    def test_create_auth_decorator_with_json_behavior(self, wristband_auth):
        """Test creating decorator with JSON behavior."""
        decorator = wristband_auth.create_auth_decorator(
            strategies=[AuthStrategy.SESSION], on_unauthenticated=UnauthenticatedBehavior.JSON
        )

        assert callable(decorator)

    def test_create_auth_decorator_with_jwt_config(self, wristband_auth):
        """Test creating decorator with JWT config."""
        jwt_config = JWTAuthConfig(jwks_cache_max_size=50, jwks_cache_ttl=3600)

        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.JWT], jwt_config=jwt_config)

        assert callable(decorator)


class TestCreateAuthDecoratorSessionAuth:
    """Test decorator with session authentication strategy."""

    def test_decorator_allows_authenticated_session(self, wristband_auth, mock_request, mock_view):
        """Test decorator allows request with valid session."""
        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION])
        decorated_view = decorator(mock_view)

        response = decorated_view(mock_request)

        assert response.status_code == 200
        assert response.content == b"Success"

    def test_decorator_rejects_unauthenticated_session_json(self, wristband_auth, mock_request, mock_view):
        """Test decorator returns 401 JSON for unauthenticated session."""
        mock_request.session["is_authenticated"] = False

        decorator = wristband_auth.create_auth_decorator(
            strategies=[AuthStrategy.SESSION], on_unauthenticated=UnauthenticatedBehavior.JSON
        )
        decorated_view = decorator(mock_view)

        response = decorated_view(mock_request)

        assert isinstance(response, JsonResponse)
        assert response.status_code == 401

    def test_decorator_redirects_unauthenticated_session(self, wristband_auth, mock_request, mock_view):
        """Test decorator redirects for unauthenticated session."""
        mock_request.session["is_authenticated"] = False

        decorator = wristband_auth.create_auth_decorator(
            strategies=[AuthStrategy.SESSION], on_unauthenticated=UnauthenticatedBehavior.REDIRECT
        )
        decorated_view = decorator(mock_view)

        response = decorated_view(mock_request)

        assert response.status_code == 302
        assert response.url == "https://app.wristband.dev/login"

    def test_decorator_refreshes_expired_token(self, wristband_auth, mock_request, mock_view):
        """Test decorator refreshes expired access token."""
        mock_request.session["expires_at"] = 1000000000  # Expired
        mock_request.session["refresh_token"] = "refresh_123"

        with patch.object(wristband_auth, "refresh_token_if_expired") as mock_refresh:
            mock_refresh.return_value = TokenData(
                access_token="new_token",
                id_token="new_id",
                expires_at=9999999999999,
                expires_in=3600,
                refresh_token="new_refresh",
            )

            decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION])
            decorated_view = decorator(mock_view)

            response = decorated_view(mock_request)

            assert response.status_code == 200
            assert mock_request.session["access_token"] == "new_token"
            mock_refresh.assert_called_once()

    def test_decorator_rejects_failed_token_refresh(self, wristband_auth, mock_request, mock_view):
        """Test decorator rejects when token refresh fails."""
        mock_request.session["expires_at"] = 1000000000  # Expired
        mock_request.session["refresh_token"] = "refresh_123"

        with patch.object(wristband_auth, "refresh_token_if_expired") as mock_refresh:
            mock_refresh.side_effect = Exception("Refresh failed")

            decorator = wristband_auth.create_auth_decorator(
                strategies=[AuthStrategy.SESSION], on_unauthenticated=UnauthenticatedBehavior.JSON
            )
            decorated_view = decorator(mock_view)

            response = decorated_view(mock_request)

            assert response.status_code == 401

    def test_decorator_marks_session_modified(self, wristband_auth, mock_request, mock_view):
        """Test decorator marks session as modified for rolling sessions."""
        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION])
        decorated_view = decorator(mock_view)

        decorated_view(mock_request)

        assert mock_request.session.modified is True

    def test_decorator_raises_without_session_middleware(self, wristband_auth, mock_view):
        """Test decorator raises RuntimeError when SessionMiddleware missing."""
        request_no_session = SimpleNamespace()  # Object without session attribute

        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION])
        decorated_view = decorator(mock_view)

        with pytest.raises(RuntimeError, match="Session not found"):
            decorated_view(request_no_session)


class TestCreateAuthDecoratorJWTAuth:
    """Test decorator with JWT authentication strategy."""

    def test_decorator_allows_valid_jwt(self, wristband_auth, mock_request, mock_view):
        """Test decorator allows request with valid JWT."""
        mock_request.headers = {"Authorization": "Bearer valid_jwt_token"}

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.JWT])
            decorated_view = decorator(mock_view)

            response = decorated_view(mock_request)

            assert response.status_code == 200
            assert hasattr(mock_request, "auth")

    def test_decorator_rejects_missing_jwt(self, wristband_auth, mock_request, mock_view):
        """Test decorator rejects request without Authorization header."""
        mock_request.headers = {}

        decorator = wristband_auth.create_auth_decorator(
            strategies=[AuthStrategy.JWT], on_unauthenticated=UnauthenticatedBehavior.JSON
        )
        decorated_view = decorator(mock_view)

        response = decorated_view(mock_request)

        assert response.status_code == 401

    def test_decorator_rejects_invalid_jwt(self, wristband_auth, mock_request, mock_view):
        """Test decorator rejects invalid JWT."""
        mock_request.headers = {"Authorization": "Bearer invalid_jwt"}

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "invalid_jwt"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = False
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            decorator = wristband_auth.create_auth_decorator(
                strategies=[AuthStrategy.JWT], on_unauthenticated=UnauthenticatedBehavior.JSON
            )
            decorated_view = decorator(mock_view)

            response = decorated_view(mock_request)

            assert response.status_code == 401

    def test_decorator_rejects_malformed_auth_header(self, wristband_auth, mock_request, mock_view):
        """Test decorator rejects malformed Authorization header."""
        mock_request.headers = {"Authorization": "InvalidFormat token"}

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = None
            mock_create_validator.return_value = mock_validator

            decorator = wristband_auth.create_auth_decorator(
                strategies=[AuthStrategy.JWT], on_unauthenticated=UnauthenticatedBehavior.JSON
            )
            decorated_view = decorator(mock_view)

            response = decorated_view(mock_request)

            assert response.status_code == 401

    def test_decorator_sets_request_auth(self, wristband_auth, mock_request, mock_view):
        """Test decorator sets request.auth with JWT payload."""
        mock_request.headers = {"Authorization": "Bearer valid_jwt_token"}

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc", "app_id": "app_xyz"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.JWT])
            decorated_view = decorator(mock_view)

            decorated_view(mock_request)

            assert hasattr(mock_request, "auth")
            assert mock_request.auth.jwt == "valid_jwt_token"
            assert mock_request.auth.payload["sub"] == "user_123"


class TestCreateAuthDecoratorMultipleStrategies:
    """Test decorator with multiple authentication strategies."""

    def test_decorator_tries_session_then_jwt(self, wristband_auth, mock_request, mock_view):
        """Test decorator tries session auth first, then JWT."""
        mock_request.session["is_authenticated"] = False
        mock_request.headers = {"Authorization": "Bearer valid_jwt"}

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])
            decorated_view = decorator(mock_view)

            response = decorated_view(mock_request)

            assert response.status_code == 200

    def test_decorator_succeeds_on_first_strategy(self, wristband_auth, mock_request, mock_view):
        """Test decorator succeeds on first valid strategy."""
        # Valid session - shouldn't need to check JWT
        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])
        decorated_view = decorator(mock_view)

        response = decorated_view(mock_request)

        assert response.status_code == 200

    def test_decorator_fails_when_all_strategies_fail(self, wristband_auth, mock_request, mock_view):
        """Test decorator fails when all strategies fail."""
        mock_request.session["is_authenticated"] = False
        mock_request.headers = {}

        decorator = wristband_auth.create_auth_decorator(
            strategies=[AuthStrategy.SESSION, AuthStrategy.JWT], on_unauthenticated=UnauthenticatedBehavior.JSON
        )
        decorated_view = decorator(mock_view)

        response = decorated_view(mock_request)

        assert response.status_code == 401


class TestCreateAuthDecoratorViewIntegration:
    """Test decorator integration with actual view functions."""

    def test_decorator_preserves_view_function_name(self, wristband_auth, mock_view):
        """Test decorator preserves original function name."""
        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION])
        decorated_view = decorator(mock_view)

        assert decorated_view.__name__ == mock_view.__name__

    def test_decorator_passes_args_to_view(self, wristband_auth, mock_request):
        """Test decorator passes args and kwargs to view."""

        def view_with_args(request, user_id, category="default"):
            return HttpResponse(f"user_id={user_id}, category={category}")

        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION])
        decorated_view = decorator(view_with_args)

        response = decorated_view(mock_request, "user123", category="premium")

        assert response.content == b"user_id=user123, category=premium"

    def test_decorator_allows_view_to_access_request(self, wristband_auth, mock_request):
        """Test view can access request object."""

        def view_using_request(request):
            return HttpResponse(f"user={request.session['user_id']}")

        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION])
        decorated_view = decorator(view_using_request)

        response = decorated_view(mock_request)

        assert response.content == b"user=user_123"

    def test_multiple_decorators_can_be_created(self, wristband_auth):
        """Test creating multiple decorators with different configs."""
        require_session = wristband_auth.create_auth_decorator(
            strategies=[AuthStrategy.SESSION], on_unauthenticated=UnauthenticatedBehavior.REDIRECT
        )

        require_jwt = wristband_auth.create_auth_decorator(
            strategies=[AuthStrategy.JWT], on_unauthenticated=UnauthenticatedBehavior.JSON
        )

        assert callable(require_session)
        assert callable(require_jwt)
        assert require_session is not require_jwt

    def test_decorator_can_be_applied_to_multiple_views(self, wristband_auth, mock_request):
        """Test same decorator can be applied to multiple views."""
        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.SESSION])

        def view1(request):
            return HttpResponse("View 1")

        def view2(request):
            return HttpResponse("View 2")

        decorated_view1 = decorator(view1)
        decorated_view2 = decorator(view2)

        response1 = decorated_view1(mock_request)
        response2 = decorated_view2(mock_request)

        assert response1.content == b"View 1"
        assert response2.content == b"View 2"


class TestCreateAuthDecoratorEdgeCases:
    """Test edge cases and error handling."""

    def test_decorator_with_none_jwt_config(self, wristband_auth):
        """Test decorator accepts None jwt_config."""
        decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.JWT], jwt_config=None)

        assert callable(decorator)

    def test_decorator_caches_jwt_validator(self, wristband_auth, mock_request, mock_view):
        """Test JWT validator is created once and reused."""
        mock_request.headers = {"Authorization": "Bearer token1"}

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = None
            mock_create.return_value = mock_validator

            decorator = wristband_auth.create_auth_decorator(strategies=[AuthStrategy.JWT])

            # Validator created once during decorator creation
            mock_create.assert_called_once()

            # Applying decorator multiple times doesn't recreate validator
            decorator(mock_view)
            decorator(mock_view)

            mock_create.assert_called_once()  # Still only once
