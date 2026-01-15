"""
Unit tests for WristbandAuthBackend.

Tests the Django authentication backend for syncing Wristband users
to Django User model.
"""

from unittest.mock import Mock, patch

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.contrib.sessions.backends.db import SessionStore

from wristband.django_auth.backends.auth.default_wristband_auth_backend_adapter import (
    DefaultWristbandAuthBackendAdapter,
)
from wristband.django_auth.backends.auth.wristband_auth_backend import WristbandAuthBackend
from wristband.django_auth.models import CallbackData, UserInfo, UserInfoRole

User = get_user_model()


@pytest.fixture
def backend():
    """Create a WristbandAuthBackend instance."""
    return WristbandAuthBackend()


@pytest.fixture
def mock_request():
    """Create a mock HttpRequest."""
    return Mock()


@pytest.fixture
def user_info_full():
    """Create UserInfo with full data."""
    return UserInfo(
        user_id="wristband_user_123",
        tenant_id="tenant_abc",
        application_id="app_xyz",
        identity_provider_name="wristband",
        email="user@example.com",
        email_verified=True,
        given_name="John",
        family_name="Doe",
        roles=[
            UserInfoRole(id="role1", name="app:demo:owner", display_name="Owner"),
        ],
    )


@pytest.fixture
def user_info_minimal():
    """Create UserInfo with minimal data (openid scope only)."""
    return UserInfo(
        user_id="wristband_user_456",
        tenant_id="tenant_def",
        application_id="app_xyz",
        identity_provider_name="wristband",
    )


@pytest.fixture
def callback_data_full(user_info_full):
    """Create CallbackData with full user info."""
    return CallbackData(
        access_token="access_token_123",
        id_token="id_token_123",
        refresh_token="refresh_token_123",
        expires_at=1700000000000,
        expires_in=3600,
        user_info=user_info_full,
        tenant_name="demo_tenant",
    )


@pytest.fixture
def callback_data_minimal(user_info_minimal):
    """Create CallbackData with minimal user info."""
    return CallbackData(
        access_token="access_token_456",
        id_token="id_token_456",
        expires_at=1700000000000,
        expires_in=3600,
        user_info=user_info_minimal,
        tenant_name="demo_tenant",
    )


@pytest.fixture(autouse=True)
def cleanup_users():
    """Clean up User objects after each test."""
    yield
    User.objects.all().delete()


class TestWristbandAuthBackendInit:
    """Test WristbandAuthBackend initialization."""

    def test_init_creates_backend(self):
        """Test that backend can be instantiated."""
        backend = WristbandAuthBackend()
        assert backend is not None
        assert isinstance(backend, WristbandAuthBackend)

    def test_init_sets_adapter_to_none(self):
        """Test that adapter is initially None (lazy loading)."""
        backend = WristbandAuthBackend()
        assert backend._adapter is None


class TestWristbandAuthBackendGetAdapter:
    """Test WristbandAuthBackend.get_adapter() method."""

    def test_get_adapter_returns_default_adapter(self, backend):
        """Test that get_adapter returns DefaultWristbandAuthBackendAdapter by default."""
        adapter = backend.get_adapter()
        assert isinstance(adapter, DefaultWristbandAuthBackendAdapter)

    def test_get_adapter_caches_instance(self, backend):
        """Test that adapter instance is cached after first call."""
        adapter1 = backend.get_adapter()
        adapter2 = backend.get_adapter()
        assert adapter1 is adapter2

    @patch("wristband.django_auth.backends.auth.wristband_auth_backend.import_string")
    def test_get_adapter_uses_custom_adapter_from_settings(self, mock_import_string, backend):
        """Test that get_adapter uses custom adapter path from settings."""

        # Create a custom adapter class
        class CustomAdapter(DefaultWristbandAuthBackendAdapter):
            pass

        mock_import_string.return_value = CustomAdapter

        with patch.object(settings, "WRISTBAND_AUTH_BACKEND_ADAPTER", "myapp.CustomAdapter", create=True):
            adapter = backend.get_adapter()
            assert isinstance(adapter, CustomAdapter)
            mock_import_string.assert_called_once_with("myapp.CustomAdapter")

    @patch("wristband.django_auth.backends.auth.wristband_auth_backend.import_string")
    def test_get_adapter_uses_default_path_when_setting_missing(self, mock_import_string, backend):
        """Test that get_adapter uses default path when setting is not configured."""
        mock_import_string.return_value = DefaultWristbandAuthBackendAdapter

        # Ensure setting doesn't exist
        if hasattr(settings, "WRISTBAND_AUTH_BACKEND_ADAPTER"):
            delattr(settings, "WRISTBAND_AUTH_BACKEND_ADAPTER")

        backend.get_adapter()
        mock_import_string.assert_called_once_with("wristband.django_auth.DefaultWristbandAuthBackendAdapter")

    @patch("wristband.django_auth.backends.auth.wristband_auth_backend.import_string")
    def test_get_adapter_raises_runtime_error_if_instantiation_fails(self, mock_import_string, backend):
        """Test that RuntimeError is raised if adapter instantiation returns None."""
        # Mock import_string to return a class that instantiates to None somehow
        # This is a corner case that shouldn't happen in practice
        mock_class = Mock(return_value=None)
        mock_import_string.return_value = mock_class

        with pytest.raises(RuntimeError, match="Failed to initialize WristbandAuthBackend adapter"):
            backend.get_adapter()


class TestWristbandAuthBackendAuthenticate:
    """Test WristbandAuthBackend.authenticate() method."""

    def test_authenticate_creates_new_user(self, backend, mock_request, callback_data_full):
        """Test that authenticate creates a new user on first login."""
        user = backend.authenticate(mock_request, callback_data=callback_data_full)

        assert user is not None
        assert user.username == "wristband_user_123"
        assert user.email == "user@example.com"
        assert user.first_name == "John"
        assert user.last_name == "Doe"
        assert user.is_active is True
        assert user.pk is not None  # User was saved

    def test_authenticate_updates_existing_user(self, backend, mock_request, callback_data_full):
        """Test that authenticate updates an existing user on subsequent login."""
        # Create existing user with old data
        existing_user = User.objects.create(
            username="wristband_user_123",
            email="old@example.com",
            first_name="OldFirst",
            last_name="OldLast",
        )

        user = backend.authenticate(mock_request, callback_data=callback_data_full)

        assert user.pk == existing_user.pk  # Same user object
        assert user.email == "user@example.com"  # Updated
        assert user.first_name == "John"  # Updated
        assert user.last_name == "Doe"  # Updated

    def test_authenticate_returns_none_when_callback_data_is_none(self, backend, mock_request):
        """Test that authenticate returns None when callback_data is None."""
        user = backend.authenticate(mock_request, callback_data=None)
        assert user is None

    def test_authenticate_returns_none_when_user_info_is_none(self, backend, mock_request):
        """Test that authenticate returns None when user_info is None."""
        callback_data = Mock(user_info=None)
        user = backend.authenticate(mock_request, callback_data=callback_data)
        assert user is None

    def test_authenticate_returns_none_when_user_id_is_none(self, backend, mock_request):
        """Test that authenticate returns None when user_id is None."""
        user_info = Mock(user_id=None)
        callback_data = Mock(user_info=user_info)
        user = backend.authenticate(mock_request, callback_data=callback_data)
        assert user is None

    def test_authenticate_returns_none_when_user_id_is_empty(self, backend, mock_request):
        """Test that authenticate returns None when user_id is empty string."""
        user_info = Mock(user_id="")
        callback_data = Mock(user_info=user_info)
        user = backend.authenticate(mock_request, callback_data=callback_data)
        assert user is None

    def test_authenticate_ignores_username_parameter(self, backend, mock_request, callback_data_full):
        """Test that authenticate ignores username parameter (for signature compatibility)."""
        user = backend.authenticate(mock_request, username="ignored_username", callback_data=callback_data_full)

        assert user is not None
        assert user.username == "wristband_user_123"  # Uses Wristband user_id, not username param

    def test_authenticate_ignores_password_parameter(self, backend, mock_request, callback_data_full):
        """Test that authenticate ignores password parameter (for signature compatibility)."""
        user = backend.authenticate(mock_request, password="ignored_password", callback_data=callback_data_full)

        assert user is not None
        # Password authentication not used - Wristband handles it

    def test_authenticate_passes_kwargs_to_adapter(self, backend, mock_request, callback_data_full):
        """Test that authenticate passes **kwargs to adapter.populate_user()."""
        with patch.object(backend, "get_adapter") as mock_get_adapter:
            mock_adapter = Mock(spec=DefaultWristbandAuthBackendAdapter)
            mock_user = Mock(spec=User)
            mock_adapter.populate_user.return_value = mock_user
            mock_get_adapter.return_value = mock_adapter

            # Create user to avoid database operations
            User.objects.create(username="wristband_user_123", is_active=True)

            backend.authenticate(
                mock_request, callback_data=callback_data_full, custom_data="test_value", another_kwarg=123
            )

            # Verify kwargs were passed to adapter
            call_kwargs = mock_adapter.populate_user.call_args[1]
            assert call_kwargs["custom_data"] == "test_value"
            assert call_kwargs["another_kwarg"] == 123

    def test_authenticate_saves_user(self, backend, mock_request, callback_data_full):
        """Test that authenticate saves the user to the database."""
        user = backend.authenticate(mock_request, callback_data=callback_data_full)

        # Verify user was saved by checking it exists in database
        saved_user = User.objects.get(username="wristband_user_123")
        assert saved_user.pk == user.pk
        assert saved_user.email == user.email  # type: ignore[attr-defined]

    def test_authenticate_sets_is_active_true_for_new_users(self, backend, mock_request, callback_data_full):
        """Test that new users are created with is_active=True."""
        user = backend.authenticate(mock_request, callback_data=callback_data_full)
        assert user.is_active is True

    def test_authenticate_preserves_is_active_for_existing_users(self, backend, mock_request, callback_data_full):
        """Test that is_active is preserved for existing users."""
        # Create inactive user
        User.objects.create(username="wristband_user_123", is_active=False)

        user = backend.authenticate(mock_request, callback_data=callback_data_full)

        # is_active should be preserved (adapter doesn't modify it)
        assert user.is_active is False

    def test_authenticate_with_minimal_user_info(self, backend, mock_request, callback_data_minimal):
        """Test authenticate with minimal user info (openid scope only)."""
        user = backend.authenticate(mock_request, callback_data=callback_data_minimal)

        assert user is not None
        assert user.username == "wristband_user_456"
        assert user.email == ""  # Not populated
        assert user.first_name == ""  # Not populated
        assert user.last_name == ""  # Not populated

    def test_authenticate_handles_concurrent_user_creation(self, backend, mock_request, callback_data_full):
        """Test that authenticate handles race condition in user creation gracefully."""
        # Simulate race condition: user created between get_or_create attempts
        original_get_or_create = User.objects.get_or_create

        call_count = 0

        def mock_get_or_create(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call creates the user
                return original_get_or_create(*args, **kwargs)
            else:
                # Second call finds existing user
                return User.objects.get(username=kwargs["username"]), False

        with patch.object(User.objects, "get_or_create", side_effect=mock_get_or_create):
            user = backend.authenticate(mock_request, callback_data=callback_data_full)
            assert user is not None

    def test_authenticate_uses_configured_adapter(self, backend, mock_request, callback_data_full):
        """Test that authenticate uses the configured adapter."""
        mock_adapter = Mock(spec=DefaultWristbandAuthBackendAdapter)
        backend._adapter = mock_adapter

        # Create user to avoid database operations
        mock_user = User.objects.create(username="wristband_user_123", is_active=True)
        mock_adapter.populate_user.return_value = mock_user

        result = backend.authenticate(mock_request, callback_data=callback_data_full)

        # Verify adapter was called
        mock_adapter.populate_user.assert_called_once()
        assert result == mock_user


class TestWristbandAuthBackendGetUser:
    """Test WristbandAuthBackend.get_user() method."""

    def test_get_user_returns_user_by_pk(self, backend):
        """Test that get_user returns user by primary key."""
        user = User.objects.create(username="test_user", email="test@example.com")

        retrieved_user = backend.get_user(user.pk)

        assert retrieved_user is not None
        assert retrieved_user.pk == user.pk
        assert retrieved_user.username == "test_user"

    def test_get_user_returns_none_for_nonexistent_user(self, backend):
        """Test that get_user returns None when user doesn't exist."""
        result = backend.get_user(99999)
        assert result is None

    def test_get_user_returns_none_for_deleted_user(self, backend):
        """Test that get_user returns None when user was deleted."""
        user = User.objects.create(username="test_user")
        user_id = user.pk
        user.delete()

        result = backend.get_user(user_id)
        assert result is None

    def test_get_user_with_string_pk(self, backend):
        """Test that get_user works with string primary keys."""
        # Note: Default User model uses integer pk, but custom models might use strings
        user = User.objects.create(username="test_user")

        # Django handles type conversion
        result = backend.get_user(str(user.pk))

        assert result is not None
        assert result.pk == user.pk

    def test_get_user_called_on_every_request(self, backend):
        """Test that get_user is optimized for repeated calls (Django handles caching)."""
        user = User.objects.create(username="test_user")

        # Simulate multiple requests
        for _ in range(10):
            retrieved_user = backend.get_user(user.pk)
            assert retrieved_user.pk == user.pk


class TestWristbandAuthBackendIntegration:
    """Integration tests for WristbandAuthBackend with Django auth system."""

    def test_backend_creates_user_then_login_succeeds(self, backend, mock_request, callback_data_full):
        """Test complete flow: authenticate creates user, then login works."""

        # Create a real session
        session = SessionStore()
        session.create()
        mock_request.session = session

        # Authenticate and create user
        user = backend.authenticate(mock_request, callback_data=callback_data_full)
        assert user is not None

        # Login should work
        login(mock_request, user, backend="wristband.django_auth.WristbandAuthBackend")
        assert mock_request.session.get("_auth_user_id") == str(user.pk)

    def test_multiple_logins_update_same_user(self, backend, mock_request):
        """Test that multiple logins update the same user."""
        # First login
        callback_data1 = CallbackData(
            access_token="token1",
            id_token="id1",
            expires_at=1700000000000,
            expires_in=3600,
            user_info=UserInfo(
                user_id="user_123",
                tenant_id="tenant_abc",
                application_id="app_xyz",
                identity_provider_name="wristband",
                email="first@example.com",
            ),
            tenant_name="tenant1",
        )

        user1 = backend.authenticate(mock_request, callback_data=callback_data1)

        # Second login with updated email
        callback_data2 = CallbackData(
            access_token="token2",
            id_token="id2",
            expires_at=1700000000000,
            expires_in=3600,
            user_info=UserInfo(
                user_id="user_123",  # Same user_id
                tenant_id="tenant_abc",
                application_id="app_xyz",
                identity_provider_name="wristband",
                email="updated@example.com",  # Updated email
            ),
            tenant_name="tenant1",
        )

        user2 = backend.authenticate(mock_request, callback_data=callback_data2)

        # Should be same user with updated data
        assert user1.pk == user2.pk
        assert user2.email == "updated@example.com"
        assert User.objects.count() == 1  # Only one user created


class TestWristbandAuthBackendWithCustomAdapter:
    """Test WristbandAuthBackend with custom adapter implementations."""

    def test_backend_uses_custom_adapter_logic(self, backend, mock_request):
        """Test that backend uses custom adapter's populate_user logic."""

        class CustomAdapter(DefaultWristbandAuthBackendAdapter):
            def populate_user(self, user, callback_data, **kwargs):
                # Custom logic: always set is_staff to True
                user = super().populate_user(user, callback_data, **kwargs)
                user.is_staff = True
                return user

        backend._adapter = CustomAdapter()

        callback_data = CallbackData(
            access_token="token",
            id_token="id",
            expires_at=1700000000000,
            expires_in=3600,
            user_info=UserInfo(
                user_id="user_123",
                tenant_id="tenant_abc",
                application_id="app_xyz",
                identity_provider_name="wristband",
            ),
            tenant_name="tenant",
        )

        user = backend.authenticate(mock_request, callback_data=callback_data)

        assert user.is_staff is True  # Custom adapter logic applied
