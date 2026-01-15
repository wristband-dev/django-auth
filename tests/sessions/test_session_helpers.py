from typing import Union, get_origin, get_type_hints
from unittest.mock import MagicMock, Mock

import pytest
from django.contrib.sessions.backends.cache import SessionStore
from django.http import HttpRequest

from wristband.django_auth.models import CallbackData, SessionResponse, TokenResponse, UserInfo
from wristband.django_auth.sessions.session_helpers import (
    WristbandSessionData,
    get_session_response,
    get_token_response,
    session_from_callback,
)


@pytest.fixture
def mock_request():
    """Create a mock HttpRequest with a real cache-based session."""
    request = Mock(spec=HttpRequest)
    # Use Django's cache-based session (in-memory, no encryption needed)
    session = SessionStore()
    session.create()
    request.session = session
    return request


@pytest.fixture
def user_info_full():
    """Create UserInfo with full data."""
    return UserInfo(
        user_id="user_123",
        tenant_id="tenant_abc",
        application_id="app_xyz",
        identity_provider_name="wristband",
        email="user@example.com",
        given_name="John",
        family_name="Doe",
    )


@pytest.fixture
def callback_data_full(user_info_full):
    """Create CallbackData with all fields."""
    return CallbackData(
        access_token="access_token_123",
        id_token="id_token_123",
        refresh_token="refresh_token_123",
        expires_at=1700000000000,
        expires_in=3600,
        user_info=user_info_full,
        tenant_name="demo_tenant",
        tenant_custom_domain="custom.example.com",
    )


@pytest.fixture
def callback_data_minimal(user_info_full):
    """Create CallbackData with minimal fields (no refresh_token or custom_domain)."""
    return CallbackData(
        access_token="access_token_456",
        id_token="id_token_456",
        expires_at=1700000000000,
        expires_in=3600,
        user_info=user_info_full,
        tenant_name="demo_tenant",
    )


class TestSessionFromCallback:
    """Test session_from_callback() function."""

    def test_session_from_callback_stores_required_fields(self, mock_request, callback_data_full):
        """Test that required fields are stored in session."""
        session_from_callback(mock_request, callback_data_full)

        assert mock_request.session["is_authenticated"] is True
        assert mock_request.session["access_token"] == "access_token_123"
        assert mock_request.session["expires_at"] == 1700000000000
        assert mock_request.session["user_id"] == "user_123"
        assert mock_request.session["tenant_id"] == "tenant_abc"
        assert mock_request.session["tenant_name"] == "demo_tenant"
        assert mock_request.session["identity_provider_name"] == "wristband"

    def test_session_from_callback_stores_optional_fields(self, mock_request, callback_data_full):
        """Test that optional fields are stored when present."""
        session_from_callback(mock_request, callback_data_full)

        assert mock_request.session["refresh_token"] == "refresh_token_123"
        assert mock_request.session["tenant_custom_domain"] == "custom.example.com"

    def test_session_from_callback_excludes_none_optional_fields(self, mock_request, callback_data_minimal):
        """Test that optional fields are excluded when None."""
        session_from_callback(mock_request, callback_data_minimal)

        assert "refresh_token" not in mock_request.session
        assert "tenant_custom_domain" not in mock_request.session

    def test_session_from_callback_with_custom_fields(self, mock_request, callback_data_full):
        """Test that custom fields are merged into session."""
        custom_fields = {
            "email": "user@example.com",
            "role": "admin",
            "preferences": {"theme": "dark"},
        }

        session_from_callback(mock_request, callback_data_full, custom_fields=custom_fields)

        assert mock_request.session["email"] == "user@example.com"
        assert mock_request.session["role"] == "admin"
        assert mock_request.session["preferences"]["theme"] == "dark"

    def test_session_from_callback_custom_fields_override_defaults(self, mock_request, callback_data_full):
        """Test that custom fields can override default session fields."""
        custom_fields = {
            "user_id": "custom_user_id",  # Override default
            "custom_field": "value",
        }

        session_from_callback(mock_request, callback_data_full, custom_fields=custom_fields)

        # Custom field should override
        assert mock_request.session["user_id"] == "custom_user_id"
        assert mock_request.session["custom_field"] == "value"

    def test_session_from_callback_with_none_custom_fields(self, mock_request, callback_data_full):
        """Test that None custom_fields is handled gracefully."""
        session_from_callback(mock_request, callback_data_full, custom_fields=None)

        # Should still have base fields
        assert mock_request.session["user_id"] == "user_123"
        assert "email" not in mock_request.session  # No custom fields added

    def test_session_from_callback_with_empty_custom_fields(self, mock_request, callback_data_full):
        """Test that empty custom_fields dict is handled gracefully."""
        session_from_callback(mock_request, callback_data_full, custom_fields={})

        # Should still have base fields
        assert mock_request.session["user_id"] == "user_123"

    def test_session_from_callback_marks_session_modified(self, mock_request, callback_data_full):
        """Test that session.modified is set to True."""
        mock_request.session = MagicMock()
        mock_request.session.modified = False

        session_from_callback(mock_request, callback_data_full)

        assert mock_request.session.modified is True

    def test_session_from_callback_raises_on_none_callback_data(self, mock_request):
        """Test that ValueError is raised when callback_data is None."""
        with pytest.raises(ValueError, match="callback_data is required"):
            session_from_callback(mock_request, None)  # type: ignore[arg-type]

    def test_session_from_callback_raises_on_missing_user_info(self, mock_request):
        """Test that ValueError is raised when user_info is None."""
        callback_data = Mock()
        callback_data.user_info = None

        with pytest.raises(ValueError, match="callback_data.user_info is required"):
            session_from_callback(mock_request, callback_data)

    def test_session_from_callback_with_complex_custom_fields(self, mock_request, callback_data_full):
        """Test that complex nested custom fields are stored correctly."""
        custom_fields = {
            "nested": {
                "level1": {
                    "level2": ["item1", "item2"],
                }
            },
            "list": [1, 2, 3],
            "mixed": {"key": [{"inner": "value"}]},
        }

        session_from_callback(mock_request, callback_data_full, custom_fields=custom_fields)

        assert mock_request.session["nested"]["level1"]["level2"] == ["item1", "item2"]
        assert mock_request.session["list"] == [1, 2, 3]
        assert mock_request.session["mixed"]["key"][0]["inner"] == "value"

    def test_session_from_callback_stores_all_user_info_fields(self, mock_request):
        """Test that all required user_info fields are extracted."""
        user_info = UserInfo(
            user_id="user_abc",
            tenant_id="tenant_xyz",
            application_id="app_123",
            identity_provider_name="google",
        )
        callback_data = CallbackData(
            access_token="token",
            id_token="id",
            expires_at=1700000000000,
            expires_in=3600,
            user_info=user_info,
            tenant_name="my_tenant",
        )

        session_from_callback(mock_request, callback_data)

        assert mock_request.session["user_id"] == "user_abc"
        assert mock_request.session["tenant_id"] == "tenant_xyz"
        assert mock_request.session["identity_provider_name"] == "google"
        assert mock_request.session["tenant_name"] == "my_tenant"


class TestGetSessionResponse:
    """Test get_session_response() function."""

    def test_get_session_response_with_required_fields(self, mock_request):
        """Test get_session_response with tenant_id and user_id in session."""
        mock_request.session["tenant_id"] = "tenant_abc"
        mock_request.session["user_id"] = "user_123"

        response = get_session_response(mock_request)

        assert isinstance(response, SessionResponse)
        assert response.tenant_id == "tenant_abc"
        assert response.user_id == "user_123"
        assert response.metadata == {}

    def test_get_session_response_with_metadata(self, mock_request):
        """Test get_session_response with custom metadata."""
        mock_request.session["tenant_id"] = "tenant_abc"
        mock_request.session["user_id"] = "user_123"

        metadata = {"email": "user@example.com", "role": "admin"}
        response = get_session_response(mock_request, metadata=metadata)

        assert response.metadata == metadata

    def test_get_session_response_with_none_metadata(self, mock_request):
        """Test get_session_response with None metadata defaults to empty dict."""
        mock_request.session["tenant_id"] = "tenant_abc"
        mock_request.session["user_id"] = "user_123"

        response = get_session_response(mock_request, metadata=None)

        assert response.metadata == {}

    def test_get_session_response_with_nested_metadata(self, mock_request):
        """Test get_session_response with nested metadata."""
        mock_request.session["tenant_id"] = "tenant_abc"
        mock_request.session["user_id"] = "user_123"

        metadata = {
            "preferences": {"theme": "dark", "notifications": True},
            "roles": ["admin", "user"],
        }
        response = get_session_response(mock_request, metadata=metadata)

        assert response.metadata["preferences"]["theme"] == "dark"
        assert response.metadata["roles"] == ["admin", "user"]

    def test_get_session_response_raises_when_tenant_id_missing(self, mock_request):
        """Test get_session_response raises ValueError when tenant_id is missing."""
        mock_request.session["user_id"] = "user_123"
        # tenant_id is missing

        with pytest.raises(ValueError, match="Session must contain tenant_id and user_id"):
            get_session_response(mock_request)

    def test_get_session_response_raises_when_user_id_missing(self, mock_request):
        """Test get_session_response raises ValueError when user_id is missing."""
        mock_request.session["tenant_id"] = "tenant_abc"
        # user_id is missing

        with pytest.raises(ValueError, match="Session must contain tenant_id and user_id"):
            get_session_response(mock_request)

    def test_get_session_response_raises_when_both_missing(self, mock_request):
        """Test get_session_response raises ValueError when both IDs are missing."""
        # Both tenant_id and user_id are missing

        with pytest.raises(ValueError, match="Session must contain tenant_id and user_id"):
            get_session_response(mock_request)

    def test_get_session_response_raises_when_tenant_id_is_none(self, mock_request):
        """Test get_session_response raises when tenant_id is explicitly None."""
        mock_request.session["tenant_id"] = None
        mock_request.session["user_id"] = "user_123"

        with pytest.raises(ValueError, match="Session must contain tenant_id and user_id"):
            get_session_response(mock_request)

    def test_get_session_response_raises_when_user_id_is_empty_string(self, mock_request):
        """Test get_session_response raises when user_id is empty string."""
        mock_request.session["tenant_id"] = "tenant_abc"
        mock_request.session["user_id"] = ""

        with pytest.raises(ValueError, match="Session must contain tenant_id and user_id"):
            get_session_response(mock_request)

    def test_get_session_response_to_dict_format(self, mock_request):
        """Test get_session_response.to_dict() returns correct format."""
        mock_request.session["tenant_id"] = "tenant_abc"
        mock_request.session["user_id"] = "user_123"

        metadata = {"email": "user@example.com"}
        response = get_session_response(mock_request, metadata=metadata)

        result = response.to_dict()

        assert result == {
            "tenantId": "tenant_abc",
            "userId": "user_123",
            "metadata": {"email": "user@example.com"},
        }


class TestGetTokenResponse:
    """Test get_token_response() function."""

    def test_get_token_response_with_required_fields(self, mock_request):
        """Test get_token_response with access_token and expires_at in session."""
        mock_request.session["access_token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        mock_request.session["expires_at"] = 1700000000000

        response = get_token_response(mock_request)

        assert isinstance(response, TokenResponse)
        assert response.access_token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        assert response.expires_at == 1700000000000

    def test_get_token_response_raises_when_access_token_missing(self, mock_request):
        """Test get_token_response raises ValueError when access_token is missing."""
        mock_request.session["expires_at"] = 1700000000000
        # access_token is missing

        with pytest.raises(ValueError, match="Session must contain access_token and expires_at"):
            get_token_response(mock_request)

    def test_get_token_response_raises_when_expires_at_missing(self, mock_request):
        """Test get_token_response raises ValueError when expires_at is missing."""
        mock_request.session["access_token"] = "token"
        # expires_at is missing

        with pytest.raises(ValueError, match="Session must contain access_token and expires_at"):
            get_token_response(mock_request)

    def test_get_token_response_raises_when_both_missing(self, mock_request):
        """Test get_token_response raises ValueError when both fields are missing."""
        # Both access_token and expires_at are missing

        with pytest.raises(ValueError, match="Session must contain access_token and expires_at"):
            get_token_response(mock_request)

    def test_get_token_response_raises_when_access_token_is_none(self, mock_request):
        """Test get_token_response raises when access_token is explicitly None."""
        mock_request.session["access_token"] = None
        mock_request.session["expires_at"] = 1700000000000

        with pytest.raises(ValueError, match="Session must contain access_token and expires_at"):
            get_token_response(mock_request)

    def test_get_token_response_raises_when_expires_at_is_zero(self, mock_request):
        """Test get_token_response raises when expires_at is 0 (falsy)."""
        mock_request.session["access_token"] = "token"
        mock_request.session["expires_at"] = 0

        with pytest.raises(ValueError, match="Session must contain access_token and expires_at"):
            get_token_response(mock_request)

    def test_get_token_response_raises_when_access_token_is_empty_string(self, mock_request):
        """Test get_token_response raises when access_token is empty string."""
        mock_request.session["access_token"] = ""
        mock_request.session["expires_at"] = 1700000000000

        with pytest.raises(ValueError, match="Session must contain access_token and expires_at"):
            get_token_response(mock_request)

    def test_get_token_response_to_dict_format(self, mock_request):
        """Test get_token_response.to_dict() returns correct format."""
        mock_request.session["access_token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        mock_request.session["expires_at"] = 1700000000000

        response = get_token_response(mock_request)
        result = response.to_dict()

        assert result == {
            "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "expiresAt": 1700000000000,
        }

    def test_get_token_response_with_long_token(self, mock_request):
        """Test get_token_response handles long JWT tokens."""
        long_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "a" * 1000 + ".signature"
        mock_request.session["access_token"] = long_token
        mock_request.session["expires_at"] = 1700000000000

        response = get_token_response(mock_request)

        assert response.access_token == long_token
        assert len(response.access_token) > 1000


class TestWristbandSessionDataTyping:
    """Test WristbandSessionData TypedDict."""

    def test_wristband_session_data_type_hints(self):
        """Test WristbandSessionData provides correct type hints."""
        hints = get_type_hints(WristbandSessionData)

        assert hints["is_authenticated"] == bool
        assert hints["access_token"] == str
        assert hints["expires_at"] == int
        assert hints["user_id"] == str
        assert hints["tenant_id"] == str
        assert hints["tenant_name"] == str
        assert hints["identity_provider_name"] == str

    def test_wristband_session_data_optional_fields(self):
        """Test WristbandSessionData optional field types."""
        hints = get_type_hints(WristbandSessionData)

        # refresh_token and tenant_custom_domain should be Optional[str] (which is Union[str, None])
        refresh_token_type = hints["refresh_token"]
        tenant_custom_domain_type = hints["tenant_custom_domain"]

        # Check they're Union types (Optional[X] is Union[X, None])
        assert get_origin(refresh_token_type) is Union
        assert get_origin(tenant_custom_domain_type) is Union


class TestSessionIntegration:
    """Integration tests for session helper functions."""

    def test_full_session_workflow(self, mock_request, callback_data_full):
        """Test complete workflow: callback → session → response."""
        # Step 1: Populate session from callback
        session_from_callback(mock_request, callback_data_full, custom_fields={"email": "user@example.com"})

        # Step 2: Verify session data
        assert mock_request.session["is_authenticated"] is True
        assert mock_request.session["user_id"] == "user_123"
        assert mock_request.session["email"] == "user@example.com"

        # Step 3: Get session response for frontend
        session_response = get_session_response(mock_request, metadata={"email": mock_request.session["email"]})

        assert session_response.user_id == "user_123"
        assert session_response.metadata["email"] == "user@example.com"

        # Step 4: Get token response for frontend
        token_response = get_token_response(mock_request)

        assert token_response.access_token == "access_token_123"
        assert token_response.expires_at == 1700000000000

    def test_session_persists_across_function_calls(self, mock_request, callback_data_full):
        """Test that session data persists across multiple helper function calls."""
        # Populate session
        session_from_callback(mock_request, callback_data_full)

        # Multiple calls to get_session_response should return same data
        response1 = get_session_response(mock_request)
        response2 = get_session_response(mock_request)

        assert response1.user_id == response2.user_id
        assert response1.tenant_id == response2.tenant_id

        # Multiple calls to get_token_response should return same data
        token1 = get_token_response(mock_request)
        token2 = get_token_response(mock_request)

        assert token1.access_token == token2.access_token
        assert token1.expires_at == token2.expires_at


class TestSessionFromCallbackValidation:
    """Test validation logic in session_from_callback()."""

    def test_session_from_callback_raises_on_none_request(self, callback_data_full):
        """Test that ValueError is raised when request is None."""
        with pytest.raises(ValueError, match="request is required"):
            session_from_callback(None, callback_data_full)  # type: ignore[arg-type]

    def test_session_from_callback_raises_on_missing_session_middleware(self, callback_data_full):
        """Test that RuntimeError is raised when SessionMiddleware is not installed."""
        request = Mock(spec=HttpRequest)
        # Don't attach a session attribute
        
        with pytest.raises(RuntimeError, match="Session not found. Ensure SessionMiddleware is registered"):
            session_from_callback(request, callback_data_full)


class TestGetSessionResponseValidation:
    """Test validation logic in get_session_response()."""

    def test_get_session_response_raises_on_none_request(self):
        """Test that ValueError is raised when request is None."""
        with pytest.raises(ValueError, match="request is required"):
            get_session_response(None)  # type: ignore[arg-type]

    def test_get_session_response_raises_on_missing_session_middleware(self):
        """Test that RuntimeError is raised when SessionMiddleware is not installed."""
        request = Mock(spec=HttpRequest)
        # Don't attach a session attribute
        
        with pytest.raises(RuntimeError, match="Session not found. Ensure SessionMiddleware is registered"):
            get_session_response(request)


class TestGetTokenResponseValidation:
    """Test validation logic in get_token_response()."""

    def test_get_token_response_raises_on_none_request(self):
        """Test that ValueError is raised when request is None."""
        with pytest.raises(ValueError, match="request is required"):
            get_token_response(None)  # type: ignore[arg-type]

    def test_get_token_response_raises_on_missing_session_middleware(self):
        """Test that RuntimeError is raised when SessionMiddleware is not installed."""
        request = Mock(spec=HttpRequest)
        # Don't attach a session attribute
        
        with pytest.raises(RuntimeError, match="Session not found. Ensure SessionMiddleware is registered"):
            get_token_response(request)
