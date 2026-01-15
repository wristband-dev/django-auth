from typing import Any, Optional

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.base_user import AbstractBaseUser
from django.http import HttpRequest
from django.utils.module_loading import import_string

from wristband.django_auth.models import CallbackData

from .default_wristband_auth_backend_adapter import DefaultWristbandAuthBackendAdapter

User = get_user_model()


class WristbandAuthBackend(ModelBackend):
    """
    Django authentication backend that synchronizes Wristband users with Django's User model.

    This backend enables hybrid authentication by bridging Wristband's multi-tenant identity
    platform with Django's built-in authentication system. It creates or updates Django User
    instances based on Wristband authentication data, allowing you to leverage Django's
    permissions, groups, and admin interface while using Wristband for authentication.

    The backend works in conjunction with a configurable adapter (DefaultWristbandAuthBackendAdapter
    or a custom subclass) that controls how Wristband user data maps to Django User fields.
    This separation allows you to customize user synchronization logic without modifying
    the authentication flow.

    Configuration:
        Add to AUTHENTICATION_BACKENDS in settings.py:
        ```python
        AUTHENTICATION_BACKENDS = [
            'wristband.django_auth.WristbandAuthBackend',
            'django.contrib.auth.backends.ModelBackend',  # Keep for admin, etc.
        ]
        ```

        Optional: Configure a custom adapter:
        ```python
        WRISTBAND_AUTH_BACKEND_ADAPTER = 'myapp.adapters.MyWristbandAdapter'
        ```

    Usage in Callback View:
        After Wristband authentication succeeds, call authenticate() with callback_data,
        then log the user into Django's session:
        ```python
        from django.contrib.auth import authenticate, login

        def callback_view(request):
            callback_result = wristband_auth.callback(request)
            callback_data = callback_result.callback_data

            # Authenticate and sync user with Wristband data
            user = authenticate(request=request, callback_data=callback_data)

            # Log user into Django's auth system
            login(request, user)

            return redirect('/')
        ```

    How It Works:
        1. authenticate() is called with CallbackData from Wristband
        2. Backend extracts user_id from Wristband UserInfo
        3. Django User is retrieved or created with username=user_id
        4. Adapter populates User fields from Wristband data
        5. User is saved and returned for login()

    Advanced Usage:
        Pass custom data to the adapter via **kwargs:
        ```python
        user = authenticate(
            request=request,
            callback_data=callback_data,
            external_data={'subscription_tier': 'premium'}
        )
        ```

        Your custom adapter can then access this data:
        ```python
        class MyAdapter(DefaultWristbandAdapter):
            def populate_user(self, user, callback_data, **kwargs):
                user = super().populate_user(user, callback_data, **kwargs)
                tier = kwargs.get('external_data', {}).get('subscription_tier')
                if tier == 'premium':
                    user.is_staff = True
                return user
        ```

    Note:
        - The backend uses Wristband user_id as Django username (immutable identifier)
        - Email and name fields are only populated if corresponding scopes are requested
        - The backend does NOT validate passwords (authentication is handled by Wristband)
        - Users are created with is_active=True by default
        - The adapter can override any User fields, including permissions and groups
    """

    def __init__(self) -> None:
        """
        Initialize the authentication backend.

        Sets up the parent ModelBackend and initializes the adapter cache.
        The adapter is lazy-loaded on first use to avoid import issues during
        Django initialization.
        """
        super().__init__()
        self._adapter: Optional[DefaultWristbandAuthBackendAdapter] = None

    def get_adapter(self) -> DefaultWristbandAuthBackendAdapter:
        """Get the configured adapter instance"""
        if self._adapter is None:
            adapter_path = getattr(
                settings, "WRISTBAND_AUTH_BACKEND_ADAPTER", "wristband.django_auth.DefaultWristbandAuthBackendAdapter"
            )
            adapter_class = import_string(adapter_path)
            self._adapter = adapter_class()

        if self._adapter is None:
            raise RuntimeError("Failed to initialize WristbandAuthBackend adapter")

        return self._adapter

    def authenticate(
        self,
        request: Optional[HttpRequest],
        username: Optional[str] = None,
        password: Optional[str] = None,
        callback_data: Optional[CallbackData] = None,
        **kwargs: object,
    ) -> Optional[AbstractBaseUser]:
        """
        Authenticate a user using Wristband callback data and sync with Django User model.

        This method is called by Django's authenticate() function after successful Wristband
        authentication. It creates or retrieves a Django User based on the Wristband user_id,
        populates User fields with data from Wristband (via the configured adapter), and
        returns the User instance for logging in.

        The method follows Django's authentication backend protocol but uses Wristband data
        instead of username/password credentials. The username and password parameters are
        present for signature compatibility but are never used.

        Flow:
            1. Validate that callback_data and user_info are present
            2. Extract user_id from Wristband UserInfo
            3. Get or create Django User with username=user_id
            4. Call adapter to populate User fields from Wristband data
            5. Save User to database
            6. Return User for Django's login() function

        Args:
            request: The Django HttpRequest object (may be None). Not used directly but
                required by Django's authentication backend protocol.
            username: Unused parameter for signature compatibility with other Django
                authentication backends. Always None when called from Wristband callback.
            password: Unused parameter for signature compatibility with other Django
                authentication backends. Always None when called from Wristband callback.
            callback_data: CallbackData instance from wristband_auth.callback() containing:
                - user_info: UserInfo with claims from Wristband (sub, email, roles, etc.)
                - access_token: JWT access token for API calls
                - refresh_token: Optional refresh token (if offline_access scope requested)
                - expires_at: Token expiration timestamp
                - tenant_name: Name of the tenant the user belongs to
            **kwargs: Additional keyword arguments passed through to adapter.populate_user().
                Use this to pass custom data to your adapter implementation:
                ```python
                authenticate(
                    request=request,
                    callback_data=callback_data,
                    external_data={'role': 'admin'}
                )
                ```

        Returns:
            AbstractBaseUser: The authenticated Django User instance with fields populated
                from Wristband data. This User has been saved to the database and is ready
                for login() to establish a Django session.
            None: If authentication fails due to missing or invalid data. This tells Django
                to try the next backend in AUTHENTICATION_BACKENDS (if any).

        Raises:
            User.DoesNotExist: Should never happen - get_or_create() prevents this.
            IntegrityError: Could occur if multiple processes try to create the same user
                simultaneously, but Django's transaction handling typically prevents this.

        Example:
            Standard usage in callback view:
            ```python
            def callback_view(request):
                # Get Wristband callback data
                callback_result = wristband_auth.callback(request)
                callback_data = callback_result.callback_data

                # Create session data
                session_from_callback(request, callback_data, custom_fields={
                    'email': callback_data.user_info.email
                })

                # Authenticate and sync with Django User
                user = authenticate(request=request, callback_data=callback_data)

                # Log user into Django auth system
                login(request, user)

                return redirect('/')
            ```

            With custom adapter kwargs:
            ```python
            user = authenticate(
                request=request,
                callback_data=callback_data,
                extra_permissions=['can_export_data']
            )
            ```

        Note:
            - The User's username is set to Wristband's user_id (immutable identifier)
            - Users are created with is_active=True by default
            - The adapter controls which fields are populated (email, name, etc.)
            - Field availability depends on OAuth scopes requested during login
            - The User is saved automatically - don't call user.save() in your callback
        """
        if not callback_data:
            return None

        user_info = callback_data.user_info
        if not user_info:
            return None

        # Get unique user ID from Wristband
        user_id = user_info.user_id
        if not user_id:
            return None

        # Get or create user
        django_user, created = User.objects.get_or_create(username=user_id, defaults={"is_active": True})

        # Populate user fields via adapter
        adapter = self.get_adapter()
        user = adapter.populate_user(django_user, callback_data, **kwargs)  # type: ignore[arg-type]
        user.save()

        return user

    def get_user(self, user_id: Any) -> Optional[AbstractBaseUser]:
        """
        Retrieve a user by their primary key ID.

        This method is called by Django's authentication system on every request after
        a user has logged in. It retrieves the User instance from the session to populate
        request.user for permission checking, view access control, and other auth-related
        operations.

        Django calls this method automatically - you should never need to call it directly.
        It's invoked by AuthenticationMiddleware on each request to restore the authenticated
        user from the session.

        Args:
            user_id: The primary key (pk) of the User to retrieve. This is typically an
                integer for the default User model, but could be a different type if using
                a custom User model with a non-integer primary key.

        Returns:
            AbstractBaseUser: The User instance corresponding to the given ID.
            None: If no user with that ID exists (user was deleted after login, etc.).

        Example:
            Django calls this internally:
            ```python
            # In AuthenticationMiddleware (Django internal code):
            user_id = request.session[SESSION_KEY]  # Get user ID from session
            user = backend.get_user(user_id)  # Call this method
            request.user = user or AnonymousUser()
            ```

        Note:
            - This is called on EVERY authenticated request, so it should be fast
            - Django handles caching to minimize database queries
            - Returning None converts request.user to AnonymousUser
            - The method is defined in ModelBackend but documented here for clarity
        """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
