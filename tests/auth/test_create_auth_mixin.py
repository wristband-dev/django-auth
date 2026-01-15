"""
Unit tests for WristbandAuth.create_auth_mixin() method.
"""

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from django.conf import settings
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.test import RequestFactory
from django.views import View
from django.views.generic import TemplateView
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

    # Add session to request - fix the lambda to return HttpResponse
    middleware = SessionMiddleware(lambda req: HttpResponse())
    middleware.process_request(request)
    request.session.save()

    # Set session data
    request.session["is_authenticated"] = True
    request.session["access_token"] = "token_123"
    request.session["expires_at"] = 9999999999999
    request.session["user_id"] = "user_123"
    request.session.save()

    return request


class TestCreateAuthMixinBasics:
    """Test basic mixin creation and validation."""

    def test_create_auth_mixin_with_session_strategy(self, wristband_auth):
        """Test creating mixin with session strategy."""
        mixin_class = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

        assert mixin_class is not None
        assert hasattr(mixin_class, "dispatch")

    def test_create_auth_mixin_with_jwt_strategy(self, wristband_auth):
        """Test creating mixin with JWT strategy."""
        mixin_class = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.JWT])

        assert mixin_class is not None
        assert hasattr(mixin_class, "dispatch")

    def test_create_auth_mixin_with_multiple_strategies(self, wristband_auth):
        """Test creating mixin with multiple strategies."""
        mixin_class = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])

        assert mixin_class is not None
        assert hasattr(mixin_class, "dispatch")

    def test_create_auth_mixin_raises_on_empty_strategies(self, wristband_auth):
        """Test that empty strategies list raises ValueError."""
        with pytest.raises(ValueError, match="At least one authentication strategy must be provided"):
            wristband_auth.create_auth_mixin(strategies=[])

    def test_create_auth_mixin_raises_on_duplicate_strategies(self, wristband_auth):
        """Test that duplicate strategies raise ValueError."""
        with pytest.raises(ValueError, match="Duplicate authentication strategies are not allowed"):
            wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION, AuthStrategy.SESSION])

    def test_create_auth_mixin_raises_on_invalid_strategy(self, wristband_auth):
        """Test that invalid strategy raises ValueError."""
        with pytest.raises(ValueError, match="Invalid authentication strategy"):
            wristband_auth.create_auth_mixin(strategies=["invalid"])  # type: ignore[list-item]

    def test_create_auth_mixin_raises_on_invalid_unauthenticated_behavior(self, wristband_auth):
        """Test that invalid on_unauthenticated raises ValueError."""
        with pytest.raises(ValueError, match="Invalid on_unauthenticated value"):
            wristband_auth.create_auth_mixin(
                strategies=[AuthStrategy.SESSION], on_unauthenticated="invalid"  # type: ignore[arg-type]
            )

    def test_create_auth_mixin_with_redirect_behavior(self, wristband_auth):
        """Test creating mixin with redirect behavior."""
        mixin_class = wristband_auth.create_auth_mixin(
            strategies=[AuthStrategy.SESSION], on_unauthenticated=UnauthenticatedBehavior.REDIRECT
        )

        assert mixin_class is not None

    def test_create_auth_mixin_with_json_behavior(self, wristband_auth):
        """Test creating mixin with JSON behavior."""
        mixin_class = wristband_auth.create_auth_mixin(
            strategies=[AuthStrategy.SESSION], on_unauthenticated=UnauthenticatedBehavior.JSON
        )

        assert mixin_class is not None

    def test_create_auth_mixin_with_jwt_config(self, wristband_auth):
        """Test creating mixin with JWT config."""
        jwt_config = JWTAuthConfig(jwks_cache_max_size=50, jwks_cache_ttl=3600)

        mixin_class = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.JWT], jwt_config=jwt_config)

        assert mixin_class is not None


class TestCreateAuthMixinSessionAuth:
    """Test mixin with session authentication strategy."""

    def test_mixin_allows_authenticated_session(self, wristband_auth, mock_request):
        """Test mixin allows request with valid session."""
        SessionMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

        class TestView(SessionMixin, View):
            def get(self, request):
                return HttpResponse("Success")

        view = TestView.as_view()
        response = view(mock_request)

        assert isinstance(response, HttpResponse)
        assert response.status_code == 200
        assert response.content == b"Success"

    def test_mixin_rejects_unauthenticated_session_json(self, wristband_auth, mock_request):
        """Test mixin returns 401 JSON for unauthenticated session."""
        mock_request.session["is_authenticated"] = False
        mock_request.session.save()

        SessionMixin = wristband_auth.create_auth_mixin(
            strategies=[AuthStrategy.SESSION], on_unauthenticated=UnauthenticatedBehavior.JSON
        )

        class TestView(SessionMixin, View):
            def get(self, request):
                return HttpResponse("Success")

        view = TestView.as_view()
        response = view(mock_request)

        assert isinstance(response, JsonResponse)
        assert response.status_code == 401

    def test_mixin_redirects_unauthenticated_session(self, wristband_auth, mock_request):
        """Test mixin redirects for unauthenticated session."""
        mock_request.session["is_authenticated"] = False
        mock_request.session.save()

        SessionMixin = wristband_auth.create_auth_mixin(
            strategies=[AuthStrategy.SESSION], on_unauthenticated=UnauthenticatedBehavior.REDIRECT
        )

        class TestView(SessionMixin, View):
            def get(self, request):
                return HttpResponse("Success")

        view = TestView.as_view()
        response = view(mock_request)

        assert isinstance(response, HttpResponseRedirect)
        assert response.status_code == 302
        assert response.url == "https://app.wristband.dev/login"

    def test_mixin_refreshes_expired_token(self, wristband_auth, mock_request):
        """Test mixin refreshes expired access token."""
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

            SessionMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

            class TestView(SessionMixin, View):
                def get(self, request):
                    return HttpResponse("Success")

            view = TestView.as_view()
            response = view(mock_request)

            assert response.status_code == 200
            assert mock_request.session["access_token"] == "new_token"
            mock_refresh.assert_called_once()

    def test_mixin_rejects_failed_token_refresh(self, wristband_auth, mock_request):
        """Test mixin rejects when token refresh fails."""
        mock_request.session["expires_at"] = 1000000000  # Expired
        mock_request.session["refresh_token"] = "refresh_123"
        mock_request.session.save()

        with patch.object(wristband_auth, "refresh_token_if_expired") as mock_refresh:
            mock_refresh.side_effect = Exception("Refresh failed")

            SessionMixin = wristband_auth.create_auth_mixin(
                strategies=[AuthStrategy.SESSION], on_unauthenticated=UnauthenticatedBehavior.JSON
            )

            class TestView(SessionMixin, View):
                def get(self, request):
                    return HttpResponse("Success")

            view = TestView.as_view()
            response = view(mock_request)

            assert response.status_code == 401

    def test_mixin_marks_session_modified(self, wristband_auth, mock_request):
        """Test mixin marks session as modified for rolling sessions."""
        SessionMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

        class TestView(SessionMixin, View):
            def get(self, request):
                return HttpResponse("Success")

        view = TestView.as_view()
        view(mock_request)

        assert mock_request.session.modified is True

    def test_mixin_raises_without_session_middleware(self, wristband_auth):
        """Test mixin raises RuntimeError when SessionMiddleware missing."""
        request_no_session = SimpleNamespace()

        SessionMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

        class TestView(SessionMixin, View):
            def get(self, request):
                return HttpResponse("Success")

        view = TestView.as_view()

        with pytest.raises(RuntimeError, match="Session not found"):
            view(request_no_session)


class TestCreateAuthMixinJWTAuth:
    """Test mixin with JWT authentication strategy."""

    def test_mixin_allows_valid_jwt(self, wristband_auth, mock_request):
        """Test mixin allows request with valid JWT."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            JwtMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.JWT])

            class TestView(JwtMixin, View):
                def get(self, request):
                    return HttpResponse("Success")

            view = TestView.as_view()
            response = view(mock_request)

            assert response.status_code == 200
            assert hasattr(mock_request, "auth")

    def test_mixin_rejects_missing_jwt(self, wristband_auth, mock_request):
        """Test mixin rejects request without Authorization header."""
        with patch.object(wristband_auth, "_create_jwt_validator"):
            JwtMixin = wristband_auth.create_auth_mixin(
                strategies=[AuthStrategy.JWT], on_unauthenticated=UnauthenticatedBehavior.JSON
            )

            class TestView(JwtMixin, View):
                def get(self, request):
                    return HttpResponse("Success")

            view = TestView.as_view()
            response = view(mock_request)

            assert response.status_code == 401

    def test_mixin_rejects_invalid_jwt(self, wristband_auth, mock_request):
        """Test mixin rejects invalid JWT."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer invalid_jwt"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "invalid_jwt"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = False
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            JwtMixin = wristband_auth.create_auth_mixin(
                strategies=[AuthStrategy.JWT], on_unauthenticated=UnauthenticatedBehavior.JSON
            )

            class TestView(JwtMixin, View):
                def get(self, request):
                    return HttpResponse("Success")

            view = TestView.as_view()
            response = view(mock_request)

            assert response.status_code == 401

    def test_mixin_sets_request_auth(self, wristband_auth, mock_request):
        """Test mixin sets request.auth with JWT payload."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            JwtMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.JWT])

            class TestView(JwtMixin, View):
                def get(self, request):
                    return HttpResponse("Success")

            view = TestView.as_view()
            view(mock_request)

            assert hasattr(mock_request, "auth")
            assert mock_request.auth.jwt == "valid_jwt_token"


class TestCreateAuthMixinMultipleStrategies:
    """Test mixin with multiple authentication strategies."""

    def test_mixin_tries_session_then_jwt(self, wristband_auth, mock_request):
        """Test mixin tries session auth first, then JWT."""
        mock_request.session["is_authenticated"] = False
        mock_request.session.save()
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            MultiMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])

            class TestView(MultiMixin, View):
                def get(self, request):
                    return HttpResponse("Success")

            view = TestView.as_view()
            response = view(mock_request)

            assert response.status_code == 200

    def test_mixin_succeeds_on_first_strategy(self, wristband_auth, mock_request):
        """Test mixin succeeds on first valid strategy."""
        with patch.object(wristband_auth, "_create_jwt_validator"):
            MultiMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])

            class TestView(MultiMixin, View):
                def get(self, request):
                    return HttpResponse("Success")

            view = TestView.as_view()
            response = view(mock_request)

            assert response.status_code == 200

    def test_mixin_fails_when_all_strategies_fail(self, wristband_auth, mock_request):
        """Test mixin fails when all strategies fail."""
        mock_request.session["is_authenticated"] = False
        mock_request.session.save()

        with patch.object(wristband_auth, "_create_jwt_validator"):
            MultiMixin = wristband_auth.create_auth_mixin(
                strategies=[AuthStrategy.SESSION, AuthStrategy.JWT], on_unauthenticated=UnauthenticatedBehavior.JSON
            )

            class TestView(MultiMixin, View):
                def get(self, request):
                    return HttpResponse("Success")

            view = TestView.as_view()
            response = view(mock_request)

            assert response.status_code == 401


class TestCreateAuthMixinViewIntegration:
    """Test mixin integration with Django class-based views."""

    def test_mixin_works_with_view(self, wristband_auth, mock_request):
        """Test mixin works with basic View class."""
        SessionMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

        class TestView(SessionMixin, View):
            def get(self, request):
                return HttpResponse("GET Success")

        view = TestView.as_view()
        response = view(mock_request)

        assert isinstance(response, HttpResponse)
        assert response.status_code == 200
        assert response.content == b"GET Success"

    def test_mixin_works_with_template_view(self, wristband_auth, mock_request):
        """Test mixin works with TemplateView."""
        SessionMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

        class TestView(SessionMixin, TemplateView):
            def get(self, request, *args, **kwargs):
                return HttpResponse("Template View Success")

        view = TestView.as_view()
        response = view(mock_request)

        assert response.status_code == 200

    def test_mixin_passes_args_to_view(self, wristband_auth, mock_request):
        """Test mixin passes args and kwargs to view."""
        SessionMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

        class TestView(SessionMixin, View):
            def get(self, request, user_id, category="default"):
                return HttpResponse(f"user_id={user_id}, category={category}")

        view = TestView.as_view()
        response = view(mock_request, "user123", category="premium")

        assert isinstance(response, HttpResponse)
        assert response.content == b"user_id=user123, category=premium"

    def test_mixin_allows_view_to_access_request(self, wristband_auth, mock_request):
        """Test view can access request object."""
        SessionMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

        class TestView(SessionMixin, View):
            def get(self, request):
                return HttpResponse(f"user={request.session['user_id']}")

        view = TestView.as_view()
        response = view(mock_request)

        assert isinstance(response, HttpResponse)
        assert response.content == b"user=user_123"

    def test_multiple_mixins_can_be_created(self, wristband_auth):
        """Test creating multiple mixins with different configs."""
        SessionMixin = wristband_auth.create_auth_mixin(
            strategies=[AuthStrategy.SESSION], on_unauthenticated=UnauthenticatedBehavior.REDIRECT
        )

        with patch.object(wristband_auth, "_create_jwt_validator"):
            JwtMixin = wristband_auth.create_auth_mixin(
                strategies=[AuthStrategy.JWT], on_unauthenticated=UnauthenticatedBehavior.JSON
            )

        assert SessionMixin is not None
        assert JwtMixin is not None
        assert SessionMixin is not JwtMixin

    def test_mixin_can_be_applied_to_multiple_views(self, wristband_auth, mock_request):
        """Test same mixin can be applied to multiple views."""
        SessionMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

        class View1(SessionMixin, View):
            def get(self, request):
                return HttpResponse("View 1")

        class View2(SessionMixin, View):
            def get(self, request):
                return HttpResponse("View 2")

        view1 = View1.as_view()
        view2 = View2.as_view()

        response1 = view1(mock_request)
        response2 = view2(mock_request)

        assert isinstance(response1, HttpResponse)
        assert isinstance(response2, HttpResponse)
        assert response1.content == b"View 1"
        assert response2.content == b"View 2"

    def test_mixin_must_be_leftmost_in_inheritance(self, wristband_auth, mock_request):
        """Test mixin works correctly as leftmost class."""
        SessionMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

        # CORRECT: Mixin is leftmost
        class CorrectView(SessionMixin, View):
            def get(self, request):
                return HttpResponse("Success")

        view = CorrectView.as_view()
        response = view(mock_request)

        assert response.status_code == 200


class TestCreateAuthMixinEdgeCases:
    """Test edge cases and error handling."""

    def test_mixin_with_none_jwt_config(self, wristband_auth):
        """Test mixin accepts None jwt_config."""
        with patch.object(wristband_auth, "_create_jwt_validator"):
            mixin_class = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.JWT], jwt_config=None)

            assert mixin_class is not None

    def test_mixin_caches_jwt_validator(self, wristband_auth, mock_request):
        """Test JWT validator is created once and reused."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer token1"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = None
            mock_create.return_value = mock_validator

            mixin_class = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.JWT])

            # Validator created once during mixin creation
            mock_create.assert_called_once()

            # Using mixin multiple times doesn't recreate validator
            class View1(mixin_class, View):
                def get(self, request):
                    return HttpResponse("1")

            class View2(mixin_class, View):
                def get(self, request):
                    return HttpResponse("2")

            mock_create.assert_called_once()  # Still only once

    def test_mixin_dispatch_calls_super(self, wristband_auth, mock_request):
        """Test mixin dispatch properly calls super().dispatch()."""
        SessionMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

        dispatch_called = False

        class TestView(SessionMixin, View):
            def dispatch(self, request, *args, **kwargs):
                nonlocal dispatch_called
                dispatch_called = True
                return super().dispatch(request, *args, **kwargs)

            def get(self, request):
                return HttpResponse("Success")

        view = TestView.as_view()
        view(mock_request)

        assert dispatch_called is True

    def test_mixin_sets_request_auth_with_jwt_payload(self, wristband_auth, mock_request):
        """Test mixin sets request.auth with JWT payload and token."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc", "app_id": "app_xyz"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            JwtMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.JWT])

            class TestView(JwtMixin, View):
                def get(self, request):
                    # Verify request.auth is accessible in view
                    assert hasattr(request, "auth")
                    assert request.auth.jwt == "valid_jwt_token"
                    assert request.auth.payload["sub"] == "user_123"
                    assert request.auth.payload["tnt_id"] == "tenant_abc"
                    assert request.auth.payload["app_id"] == "app_xyz"
                    return HttpResponse("Success")

            view = TestView.as_view()
            response = view(mock_request)

            assert isinstance(response, HttpResponse)
            assert response.status_code == 200

    def test_mixin_request_auth_available_in_view_methods(self, wristband_auth, mock_request):
        """Test request.auth is available in all view methods."""
        mock_request.META["HTTP_AUTHORIZATION"] = "Bearer valid_jwt_token"

        with patch.object(wristband_auth, "_create_jwt_validator") as mock_create_validator:
            mock_validator = Mock()
            mock_validator.extract_bearer_token.return_value = "valid_jwt_token"

            mock_result = Mock(spec=JwtValidationResult)
            mock_result.is_valid = True
            mock_result.payload = {"sub": "user_123", "tnt_id": "tenant_abc"}
            mock_validator.validate.return_value = mock_result

            mock_create_validator.return_value = mock_validator

            JwtMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.JWT])

            class TestView(JwtMixin, View):
                def get(self, request):
                    user_id = request.auth.payload["sub"]
                    tenant_id = request.auth.payload["tnt_id"]
                    return HttpResponse(f"user={user_id},tenant={tenant_id}")

            view = TestView.as_view()
            response = view(mock_request)

            assert isinstance(response, HttpResponse)
            assert response.content == b"user=user_123,tenant=tenant_abc"

    def test_mixin_does_not_set_auth_for_session_strategy(self, wristband_auth, mock_request):
        """Test mixin does not set request.auth for session-only strategy."""
        SessionMixin = wristband_auth.create_auth_mixin(strategies=[AuthStrategy.SESSION])

        class TestView(SessionMixin, View):
            def get(self, request):
                # Session strategy should NOT set request.auth
                has_auth = hasattr(request, "auth")
                return HttpResponse(f"has_auth={has_auth}")

        view = TestView.as_view()
        response = view(mock_request)

        assert isinstance(response, HttpResponse)
        assert response.content == b"has_auth=False"
