from typing import TYPE_CHECKING

from django.contrib.auth.base_user import AbstractBaseUser

from wristband.django_auth.models import CallbackData

if TYPE_CHECKING:
    from django.contrib.auth.models import User as UserType
else:
    UserType = AbstractBaseUser


class DefaultWristbandAuthBackendAdapter:
    """
        Default adapter for syncing Wristband authentication data to Django User models.

        This adapter provides a basic implementation that maps Wristband user information
        to Django's built-in User model fields. Subclass this adapter to customize how
        Wristband users are created and updated in your Django application.

        The adapter is called by WristbandAuthBackend during the authentication process,
        after a user successfully authenticates with Wristband. It receives the user data
        from Wristband and is responsible for populating the Django User instance.

        Example:
            Create a custom adapter to map Wristband roles to Django permissions:
    ```python
            from wristband.django_auth import DefaultWristbandAdapter

            class MyWristbandAdapter(DefaultWristbandAdapter):
                def populate_user(self, user, callback_data, **kwargs):
                    # Call parent to populate basic fields (username, email, name)
                    user = super().populate_user(user, callback_data, **kwargs)

                    # Map Wristband roles to Django permissions
                    roles = callback_data.user_info.roles or []
                    if roles:
                        role_names = [role.name for role in roles]
                        has_admin_role = any(
                            r.startswith("app:") and r.endswith(":admin")
                            for r in role_names
                        )
                        user.is_staff = has_admin_role
                        user.is_superuser = has_admin_role

                    return user
    ```

            Then configure it in settings.py:
    ```python
            WRISTBAND_AUTH_BACKEND_ADAPTER = "myapp.adapters.MyWristbandAdapter"
    ```

        Note:
            The availability of user data depends on the OAuth scopes requested during login:
            - 'openid' scope (required): Provides user_id, tenant_id, identity_provider_name
            - 'email' scope: Provides email and email_verified
            - 'profile' scope: Provides given_name, family_name, full_name, picture, etc.
            - 'roles' scope: Provides user's roles within the tenant

            Configure scopes in your WristbandAuth initialization:
    ```python
            auth_config = AuthConfig(
                client_id="...",
                client_secret="...",
                scopes=["openid", "offline_access", "email", "profile", "roles"]
            )
    ```
    """

    def populate_user(self, user: UserType, callback_data: CallbackData, **kwargs: object) -> UserType:
        """
        Populate Django User fields with data from Wristband authentication callback.

        This method is called by WristbandAuthBackend during authentication to sync
        Wristband user data into a Django User instance. The User may be newly created
        or an existing user being updated with fresh data from Wristband.

        The default implementation maps:
        - user_info.user_id → user.username (unique identifier from Wristband)
        - user_info.email → user.email (if 'email' scope requested)
        - user_info.given_name → user.first_name (if 'profile' scope requested)
        - user_info.family_name → user.last_name (if 'profile' scope requested)

        Override this method to add custom mappings, such as:
        - Mapping Wristband roles to Django groups or permissions
        - Storing additional user metadata in custom User model fields
        - Setting default values for new users
        - Implementing custom business logic based on tenant or role data

        Args:
            user: Django User instance to populate. May be unsaved if newly created.
                The user is guaranteed to have a username set to the Wristband user_id.
            callback_data: Complete authentication callback data from Wristband, including:
                - user_info: UserInfo object with user claims (sub, email, roles, etc.)
                - access_token: JWT access token for API calls
                - refresh_token: Optional refresh token (if 'offline_access' scope requested)
                - expires_at: Token expiration timestamp
                - tenant_name: Name of the tenant the user belongs to
            **kwargs: Additional keyword arguments for custom adapter implementations.
                These are passed through from the authenticate() call in your callback view.

        Returns:
            The User instance with populated fields.

        Note:
            - Field availability depends on requested OAuth scopes
            - User instance may have custom fields if using a custom User model
            - The user will be saved by the backend after this method returns
            - Avoid calling user.save() in this method - let the backend handle it
        """
        user_info = callback_data.user_info

        if not user_info:
            return user

        # user_id is ALWAYS available (from openid scope)
        user_id = user_info.user_id
        if user_id:
            user.username = user_id

        # Email might not be available if 'email' scope not requested
        email = user_info.email
        if email:
            user.email = email

        # Name fields might not be available if 'profile' scope not requested
        given_name = user_info.given_name
        family_name = user_info.family_name
        if given_name:
            user.first_name = given_name
        if family_name:
            user.last_name = family_name

        return user
