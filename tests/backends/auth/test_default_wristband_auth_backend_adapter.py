from unittest.mock import Mock

import pytest
from django.contrib.auth import get_user_model

from wristband.django_auth.backends.auth import DefaultWristbandAuthBackendAdapter
from wristband.django_auth.models import CallbackData, UserInfo, UserInfoRole

User = get_user_model()


@pytest.fixture
def adapter():
    """Create a DefaultWristbandAuthBackendAdapter instance."""
    return DefaultWristbandAuthBackendAdapter()


@pytest.fixture
def base_user():
    """Create an unsaved Django User instance."""
    return User(username="temp_user", is_active=True)


@pytest.fixture
def full_user_info():
    """Create UserInfo with all fields populated."""
    return UserInfo(
        user_id="wristband_user_123",
        tenant_id="tenant_abc",
        application_id="app_xyz",
        identity_provider_name="wristband",
        email="user@example.com",
        email_verified=True,
        given_name="John",
        family_name="Doe",
        full_name="John Doe",
        picture_url="https://example.com/photo.jpg",
        roles=[
            UserInfoRole(id="role1", name="app:demo:owner", display_name="Owner"),
            UserInfoRole(id="role2", name="app:demo:viewer", display_name="Viewer"),
        ],
    )


@pytest.fixture
def minimal_user_info():
    """Create UserInfo with only required fields (openid scope)."""
    return UserInfo(
        user_id="wristband_user_456",
        tenant_id="tenant_def",
        application_id="app_xyz",
        identity_provider_name="wristband",
    )


@pytest.fixture
def callback_data_full(full_user_info):
    """Create CallbackData with full user info."""
    return CallbackData(
        access_token="access_token_123",
        id_token="id_token_123",
        refresh_token="refresh_token_123",
        expires_at=1700000000000,
        expires_in=3600,
        user_info=full_user_info,
        tenant_name="demo_tenant",
    )


@pytest.fixture
def callback_data_minimal(minimal_user_info):
    """Create CallbackData with minimal user info."""
    return CallbackData(
        access_token="access_token_456",
        id_token="id_token_456",
        expires_at=1700000000000,
        expires_in=3600,
        user_info=minimal_user_info,
        tenant_name="demo_tenant",
    )


class TestDefaultWristbandAuthBackendAdapter:
    """Test suite for DefaultWristbandAuthBackendAdapter."""

    def test_populate_user_with_full_data(self, adapter, base_user, callback_data_full):
        """Test populating user with all available Wristband data."""
        result = adapter.populate_user(base_user, callback_data_full)

        assert result.username == "wristband_user_123"
        assert result.email == "user@example.com"
        assert result.first_name == "John"
        assert result.last_name == "Doe"
        assert result.is_active is True

    def test_populate_user_with_minimal_data(self, adapter, base_user, callback_data_minimal):
        """Test populating user with only openid scope data."""
        result = adapter.populate_user(base_user, callback_data_minimal)

        assert result.username == "wristband_user_456"
        # Email and name fields should remain empty
        assert result.email == ""
        assert result.first_name == ""
        assert result.last_name == ""

    def test_populate_user_with_no_user_info(self, adapter, base_user):
        """Test handling when user_info is None."""
        callback_data = Mock(spec=CallbackData)
        callback_data.user_info = None

        result = adapter.populate_user(base_user, callback_data)

        # User should be returned unchanged
        assert result.username == "temp_user"
        assert result.email == ""
        assert result.first_name == ""

    def test_populate_user_with_none_email(self, adapter, base_user, callback_data_minimal):
        """Test handling when email is None (email scope not requested)."""
        callback_data_minimal.user_info.email = None

        result = adapter.populate_user(base_user, callback_data_minimal)

        assert result.username == "wristband_user_456"
        assert result.email == ""  # Should remain empty

    def test_populate_user_with_none_given_name(self, adapter, base_user, callback_data_full):
        """Test handling when given_name is None."""
        callback_data_full.user_info.given_name = None

        result = adapter.populate_user(base_user, callback_data_full)

        assert result.username == "wristband_user_123"
        assert result.first_name == ""  # Should remain empty
        assert result.last_name == "Doe"  # Family name still set

    def test_populate_user_with_none_family_name(self, adapter, base_user, callback_data_full):
        """Test handling when family_name is None."""
        callback_data_full.user_info.family_name = None

        result = adapter.populate_user(base_user, callback_data_full)

        assert result.username == "wristband_user_123"
        assert result.first_name == "John"  # Given name still set
        assert result.last_name == ""  # Should remain empty

    def test_populate_user_with_empty_strings(self, adapter, base_user, callback_data_full):
        """Test handling when fields are empty strings."""
        callback_data_full.user_info.email = ""
        callback_data_full.user_info.given_name = ""
        callback_data_full.user_info.family_name = ""

        result = adapter.populate_user(base_user, callback_data_full)

        # Empty strings should NOT populate fields (falsy check)
        assert result.username == "wristband_user_123"
        assert result.email == ""
        assert result.first_name == ""
        assert result.last_name == ""

    def test_populate_user_with_existing_user_data(self, adapter, callback_data_full):
        """Test that adapter overwrites existing user data."""
        existing_user = User(
            username="old_username",
            email="old@example.com",
            first_name="OldFirst",
            last_name="OldLast",
            is_active=True,
        )

        result = adapter.populate_user(existing_user, callback_data_full)

        # All fields should be overwritten with Wristband data
        assert result.username == "wristband_user_123"
        assert result.email == "user@example.com"
        assert result.first_name == "John"
        assert result.last_name == "Doe"

    def test_populate_user_preserves_is_active(self, adapter, base_user, callback_data_full):
        """Test that is_active flag is preserved."""
        base_user.is_active = False

        result = adapter.populate_user(base_user, callback_data_full)

        # is_active should not be modified by adapter
        assert result.is_active is False

    def test_populate_user_with_kwargs(self, adapter, base_user, callback_data_full):
        """Test that **kwargs are accepted but ignored by default adapter."""
        # Should not raise an error
        result = adapter.populate_user(
            base_user,
            callback_data_full,
            custom_arg="value",
            another_arg=123,
        )

        assert result.username == "wristband_user_123"

    def test_populate_user_returns_same_instance(self, adapter, base_user, callback_data_full):
        """Test that the same user instance is returned (not a new one)."""
        result = adapter.populate_user(base_user, callback_data_full)

        assert result is base_user

    def test_populate_user_does_not_save(self, adapter, base_user, callback_data_full):
        """Test that adapter does not save the user (backend's responsibility)."""
        result = adapter.populate_user(base_user, callback_data_full)

        # User should not have a pk (not saved to database)
        assert result.pk is None

    def test_populate_user_with_special_characters_in_name(self, adapter, base_user, callback_data_full):
        """Test handling names with special characters."""
        callback_data_full.user_info.given_name = "Jean-François"
        callback_data_full.user_info.family_name = "O'Brien"

        result = adapter.populate_user(base_user, callback_data_full)

        assert result.first_name == "Jean-François"
        assert result.last_name == "O'Brien"

    def test_populate_user_with_long_email(self, adapter, base_user, callback_data_full):
        """Test handling very long email addresses."""
        long_email = "very.long.email.address.that.might.exceed.limits@" + "a" * 200 + ".com"
        callback_data_full.user_info.email = long_email

        result = adapter.populate_user(base_user, callback_data_full)

        assert result.email == long_email

    def test_populate_user_with_unicode_characters(self, adapter, base_user, callback_data_full):
        """Test handling Unicode characters in names."""
        callback_data_full.user_info.given_name = "山田"
        callback_data_full.user_info.family_name = "太郎"

        result = adapter.populate_user(base_user, callback_data_full)

        assert result.first_name == "山田"
        assert result.last_name == "太郎"

    def test_roles_not_used_by_default_adapter(self, adapter, base_user, callback_data_full):
        """Test that default adapter ignores roles (custom adapters handle these)."""
        # Default adapter should not modify is_staff or is_superuser
        base_user.is_staff = False
        base_user.is_superuser = False

        result = adapter.populate_user(base_user, callback_data_full)

        # Flags should remain unchanged
        assert result.is_staff is False
        assert result.is_superuser is False


class TestDefaultWristbandAuthBackendAdapterSubclassing:
    """Test subclassing DefaultWristbandAuthBackendAdapter for custom behavior."""

    def test_subclass_can_extend_populate_user(self, base_user, callback_data_full):
        """Test that subclasses can extend populate_user with custom logic."""

        class CustomAdapter(DefaultWristbandAuthBackendAdapter):
            def populate_user(self, user, callback_data, **kwargs):
                # Call parent
                user = super().populate_user(user, callback_data, **kwargs)

                # Custom logic: map roles to staff status
                roles = callback_data.user_info.roles or []
                if roles:
                    has_owner = any(r.name.endswith(":owner") for r in roles)
                    user.is_staff = has_owner

                return user

        adapter = CustomAdapter()
        result = adapter.populate_user(base_user, callback_data_full)

        assert result.username == "wristband_user_123"
        assert result.is_staff is True  # Custom logic applied

    def test_subclass_can_replace_populate_user(self, base_user, callback_data_full):
        """Test that subclasses can completely replace populate_user logic."""

        class MinimalAdapter(DefaultWristbandAuthBackendAdapter):
            def populate_user(self, user, callback_data, **kwargs):
                # Don't call super() - completely custom logic
                user.username = callback_data.user_info.user_id
                user.email = "default@example.com"  # Always use default
                return user

        adapter = MinimalAdapter()
        result = adapter.populate_user(base_user, callback_data_full)

        assert result.username == "wristband_user_123"
        assert result.email == "default@example.com"  # Custom default
        assert result.first_name == ""  # Not populated

    def test_subclass_can_use_kwargs(self, base_user, callback_data_full):
        """Test that subclasses can use **kwargs for custom data."""

        class KwargsAdapter(DefaultWristbandAuthBackendAdapter):
            def populate_user(self, user, callback_data, **kwargs):
                user = super().populate_user(user, callback_data, **kwargs)

                # Use custom kwarg
                external_data = kwargs.get("external_data", {})
                if external_data.get("is_premium"):  # type: ignore[attr-defined]
                    user.is_staff = True

                return user

        adapter = KwargsAdapter()
        result = adapter.populate_user(
            base_user,
            callback_data_full,
            external_data={"is_premium": True},
        )

        assert result.is_staff is True
