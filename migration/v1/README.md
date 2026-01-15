<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instructions from version 0.x to version 1.x
  </p>
  <p align="center">
    <b>
      <a href="https://wristband.dev">Website</a> • 
      <a href="https://docs.wristband.dev/">Documentation</a>
    </b>
  </p>
</div>

<br/>

---

<br/>

# Migration Instructions from Version 0.x to Version 1.x

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 1.x

<br>

## Table of Contents

- [Overview of Changes](#overview-of-changes)
- [Breaking Changes](#breaking-changes)
  - [Query Parameter and URL Placeholder Naming Changes](#query-parameter-and-url-placeholder-naming-changes)
  - [CallbackResult Structure Changes](#callbackresult-structure-changes)
  - [Session Management Changes](#session-management-changes)
  - [Authentication Protection Changes](#authentication-protection-changes)
  - [Django User Synchronization Changes](#django-user-synchronization-changes)
- [Recommended Updates](#recommended-updates)
  - [New API Endpoints for Frontend SDKs](#new-api-endpoints-for-frontend-sdks)
  - [Enhanced Authentication Strategies](#enhanced-authentication-strategies)

<br>

---

<br>

## Overview of Changes

Version 1.0 is a major release that:

- ✅ Adds JWT bearer token authentication support
- ✅ Adds multi-strategy authentication (SESSION + JWT)
- ✅ Introduces discriminated union pattern for `CallbackResult`
- ✅ Changes tenant domain placeholder and parameter naming for consistency
- ✅ Introduces encrypted cookie-based session engine
- ✅ Streamline session management with helper functions
- ✅ Updates authentication decorator/mixin creation
- ✅ Introduces authentication backend and adapter pattern for Django User synchronization
- ✅ Adds Django REST Framework (DRF) authentication support

<br>

## Breaking Changes

### CallbackResult Structure Changes

The `CallbackResult` model in v1.x now uses a discriminated union pattern with explicit variant types and a new `reason` field for redirect cases.

#### Type Checking Pattern

**v0.x:**
```python
callback_result = wristband_auth.callback(request)

- if callback_result.type == CallbackResultType.REDIRECT_REQUIRED:
-     assert callback_result.redirect_url is not None
-     return wristband_auth.create_callback_response(request, callback_result.redirect_url)

- assert callback_result.callback_data is not None
- # Create session from callback_data
```

**v1.x:**
```python
callback_result = wristband_auth.callback(request)

+ if isinstance(callback_result, RedirectRequiredCallbackResult):
+     return wristband_auth.create_callback_response(
+         request,
+         callback_result.redirect_url
+     )

+ # callback_result is now guaranteed to be CompletedCallbackResult
+ session_from_callback(request, callback_result.callback_data)
```

**Key Changes:**
- Use `isinstance()` checks instead of comparing `callback_result.type`
- No more `assert` statements needed - type narrowing is automatic
- Import the new result types: `CompletedCallbackResult`, `RedirectRequiredCallbackResult`

#### New Import Required

```python
- from wristband.django_auth import CallbackResultType
+ from wristband.django_auth import (
+     CompletedCallbackResult,
+     RedirectRequiredCallbackResult,
+ )
```

#### New `reason` Field

v1.x adds a `reason` field to `RedirectRequiredCallbackResult` that indicates why the redirect is required:

```python
if isinstance(callback_result, RedirectRequiredCallbackResult):
    # You can now inspect why redirect is needed
    print(f"Redirect reason: {callback_result.reason}")
    # Possible values: MISSING_LOGIN_STATE, INVALID_LOGIN_STATE, 
    #                  LOGIN_REQUIRED, INVALID_GRANT
```

See the [callback() documentation](../../README.md#callback) for the complete `CallbackFailureReason` enum values.

<br>

### Query Parameter and URL Placeholder Naming Changes

To improve consistency across the SDK, query parameter names have changed from `tenant_domain` to `tenant_name`.

#### Login Endpoint Query Parameters

**v0.x:**
```python
# Login with tenant domain query parameter
- GET https://yourapp.io/auth/login?tenant_domain=customer01
```

**v1.x:**
```python
# Login with tenant name query parameter
+ GET https://yourapp.io/auth/login?tenant_name=customer01
```

#### Logout Endpoint Query Parameters

**v0.x:**
```python
# Logout with tenant domain query parameter
- GET https://yourapp.io/auth/logout?tenant_domain=customer01
```

**v1.x:**
```python
# Logout with tenant name query parameter
+ GET https://yourapp.io/auth/logout?tenant_name=customer01
```

> **💡 Note:** The `tenant_custom_domain` query parameter name remains unchanged in both versions.

#### URL Placeholder Changes

**v0.x:**
```python
WRISTBAND_AUTH = {
    # ... other config
-   "login_url": "https://{tenant_domain}.yourapp.com/auth/login",
-   "redirect_uri": "https://{tenant_domain}.yourapp.com/auth/callback",
}
```

**v1.x:**
```python
WRISTBAND_AUTH = {
    # ... other config
+   "login_url": "https://{tenant_name}.yourapp.com/auth/login",
+   "redirect_uri": "https://{tenant_name}.yourapp.com/auth/callback",
}
```

> **⚠️ Important:**
>
> The old `{tenant_domain}` placeholder still works for backwards compatibility, but it is now deprecated and will be removed in a future major version. All new code should use `{tenant_name}`.

#### LoginConfig and LogoutConfig Field Changes

**v0.x:**
```python
# LoginConfig
- config = LoginConfig(default_tenant_domain_name="default")

# LogoutConfig
- config = LogoutConfig(tenant_domain_name="customer01")
```

**v1.x:**
```python
# LoginConfig
+ config = LoginConfig(default_tenant_name="default")

# LogoutConfig
+ config = LogoutConfig(tenant_name="customer01")
```

#### Session Field Changes

**v0.x:**
```python
# Accessing session data
- wristband_session = request.session.get('wristband', {})
- tenant_domain_name = wristband_session.get('tenant_domain_name')
```

**v1.x:**
```python
# Accessing session data
+ tenant_name = request.session['tenant_name']
```

<br>

### Session Management Changes

v1.x introduces an encrypted cookie-based session engine and a helper function for populating sessions from callback data. Session fields are now written directly to `request.session` rather than being nested under `request.session['wristband']`, and the `session_from_callback()` helper takes care of extracting and persisting the relevant values from `callback_data` automatically.

#### Session Engine Configuration

Wristband's encrypted cookie-based session engine must be configured for the authentication decorators, mixins, and DRF classes to work properly. Without this configuration, `request.session.is_authenticated` and other session fields will not be available.

> **💡 Using Alternative Session Engines**
>
> If you choose to use a session engine other than Wristband's encrypted cookies, you must manually set `request.session.is_authenticated = True` in your callback endpoint after successful authentication to ensure proper validation by authentication decorators, mixins, and DRF classes.

**v0.x:**
```python
# your_project/settings.py

# Using Django's default database session backend
- SESSION_ENGINE = 'django.contrib.sessions.backends.db'  # or other backends
```

**v1.x:**
```python
# your_project/settings.py

# Required: Use Wristband's encrypted cookie session engine
+ SESSION_ENGINE = 'wristband.django_auth.sessions.backends.encrypted_cookies'
+ SESSION_COOKIE_AGE = 3600  # 1 hour of inactivity, adjust as needed
+ SESSION_COOKIE_SECURE = True  # IMPORTANT: Set to True in Production!
+ SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookie
+ SESSION_COOKIE_SAMESITE = 'Lax'  # Reasonably secure default option

# Session encryption secret (32+ characters recommended)
# IMPORTANT: In production, use a strong, randomly-generated secret!
+ WRISTBAND_SESSION_SECRET = 'your-secret-key-at-least-32-characters-long'
```

#### Session Population

For convenience, it is now recommended to use the `session_from_callback()` helper function to map your Wristband callback data into your Django session instead of doing it manually.

**v0.x:**
```python
@require_GET
def callback_endpoint(request: HttpRequest) -> HttpResponse:
    callback_result = wristband_auth.callback(request)
    
    if callback_result.type == CallbackResultType.REDIRECT_REQUIRED:
        return wristband_auth.create_callback_response(request, callback_result.redirect_url)
    
-   # Manually create session data
-   callback_data = callback_result.callback_data
-   request.session['wristband'] = {
-       'access_token': callback_data.access_token,
-       'expires_at': callback_data.expires_at,
-       'refresh_token': callback_data.refresh_token,
-       'user_info': callback_data.user_info,
-       'tenant_domain_name': callback_data.tenant_domain_name,
-       'tenant_custom_domain': callback_data.tenant_custom_domain,
-   }
    
    post_callback_url = callback_data.return_url or '/'
    return wristband_auth.create_callback_response(request, post_callback_url)
```

**v1.x:**
```python
+ from wristband.django_auth import session_from_callback

@require_GET
def callback_endpoint(request: HttpRequest) -> HttpResponse:
    callback_result = wristband_auth.callback(request)
    
    if isinstance(callback_result, RedirectRequiredCallbackResult):
        return wristband_auth.create_callback_response(request, callback_result.redirect_url)
    
+   # Use helper function to populate session
+   session_from_callback(request, callback_result.callback_data)
    
    post_callback_url = callback_result.callback_data.return_url or '/'
    return wristband_auth.create_callback_response(request, post_callback_url)
```

#### Session Field Access

The previous SDK version demonstrated storing your callback data in `request.session.wristband`. When using the `session_from_callback()` function, session fields are written directly to `request.session` rather than being nested under `request.session['wristband']`.

**v0.x:**
```python
- wristband_session = request.session.get('wristband', {})
- access_token = wristband_session.get('access_token')
- user_info = wristband_session.get('user_info', {})
- user_id = user_info.user_id
# ...
```

**v1.x:**
```python
# Session fields are a flat structure
+ access_token = request.session.get('access_token')
+ user_id = request.session.get('user_id')
# ...
```

**Available Session Fields via session_from_callback() (v1.x):**

| Field | Type | Always Present |
| ----- | ---- | -------------- |
| `is_authenticated` | `bool` | Yes |
| `access_token` | `str` | Yes |
| `expires_at` | `int` | Yes |
| `user_id` | `str` | Yes |
| `tenant_id` | `str` | Yes |
| `tenant_name` | `str` | Yes |
| `identity_provider_name` | `str` | Yes |
| `refresh_token` | `str` | No (only if `offline_access` scope) |
| `tenant_custom_domain` | `str` | No (only if tenant uses custom domain) |

<br>

### Authentication Protection Changes

In v1.x, authentication enforcement moves out of user-defined Django middleware and into Wristband-provided factory functions. Instead of relying on the built-in “markers” of `@wristband_auth_required` and `WristbandAuthRequiredMixin` that required custom middleware to supply the actual logic, developers now create fully configured decorators and mixins via `create_auth_decorator()` and `create_auth_mixin()`. These instances encapsulate both the authentication strategies and unauthenticated behavior, eliminating the need to write or maintain custom auth middleware while allowing multiple, differently configured protections within the same app.

> **⚠️ Important:** `@wristband_auth_required` and `WristbandAuthRequiredMixin` have been removed in v1.x.

#### Decorator Creation

**v0.x:**
```python
# your_app/views.py
- from wristband.django_auth import wristband_auth_required

# This marker decorator would defer auth enforcement to a user-defined auth middleware.
- @wristband_auth_required
- def protected_view(request):
-     return render(request, 'protected.html')
```

**v1.x:**
```python
# your_app/wristband.py
+ from wristband.django_auth import AuthStrategy, UnauthenticatedBehavior

+ # Create decorator instance with your auth config
+ require_session = wristband_auth.create_auth_decorator(
+     strategies=[AuthStrategy.SESSION],
+     on_unauthenticated=UnauthenticatedBehavior.REDIRECT,
+ )

+ __all__ = ['wristband_auth', 'require_session']
```

```python
# your_app/views.py
+ from your_app.wristband import require_session

# Auth enforcement logic handled by the decorator directly.
+ @require_session
+ def protected_view(request):
+     return render(request, 'protected.html')
```

#### Mixin Creation

**v0.x:**
```python
# your_app/views.py
from django.views import View
- from wristband.django_auth import WristbandAuthRequiredMixin

# This marker mixin would defer auth enforcement to a user-defined auth middleware.
- class ProtectedView(WristbandAuthRequiredMixin, View):
-     def get(self, request):
-         return render(request, 'protected.html')
```

**v1.x:**
```python
# your_app/wristband.py
+ from wristband.django_auth import AuthStrategy, UnauthenticatedBehavior

+ # Create mixin instance with your auth config
+ SessionRequiredMixin = wristband_auth.create_auth_mixin(
+     strategies=[AuthStrategy.SESSION],
+     on_unauthenticated=UnauthenticatedBehavior.REDIRECT,
+ )

+ __all__ = ['wristband_auth', 'SessionRequiredMixin']
```

```python
# your_app/views.py
from django.views import View
+ from your_app.wristband import SessionRequiredMixin

# Auth enforcement logic handled by the mixin directly.
+ class ProtectedView(SessionRequiredMixin, View):
+     def get(self, request):
+         return render(request, 'protected.html')
```

<br>

### Django User Synchronization Changes

v1.x introduces a new authentication backend and adapter pattern for syncing Wristband users with Django's User model. If you were integrating with Django's built-in auth system, the synchronization approach has changed significantly.

#### Authentication Backend Configuration

**v0.x:**
```python
# your_app/auth_views.py
from django.contrib.auth import login
from django.contrib.auth.models import User, Group

@require_GET
def callback_endpoint(request: HttpRequest) -> HttpResponse:
    callback_result = wristband_auth.callback(request)
    
    if callback_result.type == CallbackResultType.REDIRECT_REQUIRED:
        return wristband_auth.create_callback_response(request, callback_result.redirect_url)
    
    callback_data = callback_result.callback_data
    request.session['wristband'] = {
        'access_token': callback_data.access_token,
        # ... other session fields
    }
    
-   # Manually create/update Django User
-   user_info = callback_data.user_info
-   email = user_info.get('email')
-   user_id = user_info.get('sub')
-   
-   user, created = User.objects.get_or_create(
-       username=user_id,
-       defaults={'email': email, 'is_active': True}
-   )
-   
-   if not created:
-       user.email = email
-       user.save()
-   
-   # Manually map roles to groups
-   roles = user_info.get('roles', [])
-   # ... custom role mapping logic ...
-   
-   login(request, user)
    
    post_callback_url = callback_data.return_url or '/'
    return wristband_auth.create_callback_response(request, post_callback_url)
```

**v1.x:**
```python
# your_project/settings.py
+ AUTHENTICATION_BACKENDS = [
+     'wristband.django_auth.WristbandAuthBackend',
+ ]
```

```python
# your_app/auth_views.py
+ from django.contrib.auth import authenticate, login
+ from wristband.django_auth import session_from_callback

@require_GET
def callback_endpoint(request: HttpRequest) -> HttpResponse:
    callback_result = wristband_auth.callback(request)
    
    if isinstance(callback_result, RedirectRequiredCallbackResult):
        return wristband_auth.create_callback_response(request, callback_result.redirect_url)
    
    session_from_callback(request, callback_result.callback_data)
    
+   # Authentication backend handles User creation/sync automatically
+   user = authenticate(request=request, callback_data=callback_result.callback_data)
+   login(request, user)
    
    post_callback_url = callback_result.callback_data.return_url or '/'
    return wristband_auth.create_callback_response(request, post_callback_url)
```

**Key Changes:**
- Add `WristbandAuthBackend` to `AUTHENTICATION_BACKENDS` in settings
- Use `authenticate()` instead of manually creating/updating User objects
- Backend automatically handles User creation, updates, and basic field mapping
- No need to manually call `User.objects.get_or_create()`

#### Custom Role Mapping with Adapters

**v0.x:**
```python
# Custom role mapping done inline in callback view
- roles = user_info.get('roles', [])
- if roles:
-     role_names = [role['name'] for role in roles]
-     has_owner_role = any(
-         role_name.startswith('app:') and role_name.endswith(':owner')
-         for role_name in role_names
-     )
-     
-     if has_owner_role:
-         user.groups.clear()
-         user.is_staff = True
-         user.is_superuser = True
-         owner_group, _ = Group.objects.get_or_create(name='Owners')
-         user.groups.add(owner_group)
-     else:
-         # ... viewer logic ...
-     
-     user.save()
```

**v1.x:**
```python
# your_app/adapters.py
+ from django.contrib.auth.models import Group
+ from wristband.django_auth import DefaultWristbandAuthBackendAdapter

+ class MyWristbandAdapter(DefaultWristbandAuthBackendAdapter):
+     """Custom adapter with role mapping logic."""
+     
+     def populate_user(self, user, callback_data, **kwargs):
+         # Populate basic fields from parent
+         user = super().populate_user(user, callback_data, **kwargs)
+         
+         # Add custom role mapping
+         user_info = callback_data.user_info
+         roles = user_info.roles
+         
+         if not roles:
+             user.groups.clear()
+             user.is_staff = False
+             user.is_superuser = False
+             viewer_group, _ = Group.objects.get_or_create(name="Viewers")
+             user.groups.add(viewer_group)
+         else:
+             role_names = [role.name for role in roles]
+             has_owner_role = any(
+                 role_name.startswith("app:") and role_name.endswith(":owner")
+                 for role_name in role_names
+             )
+             
+             if has_owner_role:
+                 user.groups.clear()
+                 user.is_staff = True
+                 user.is_superuser = True
+                 owner_group, _ = Group.objects.get_or_create(name="Owners")
+                 user.groups.add(owner_group)
+             else:
+                 user.groups.clear()
+                 user.is_staff = False
+                 user.is_superuser = False
+                 viewer_group, _ = Group.objects.get_or_create(name="Viewers")
+                 user.groups.add(viewer_group)
+         
+         return user
```

```python
# your_project/settings.py
+ WRISTBAND_AUTH_BACKEND_ADAPTER = 'your_app.adapters.MyWristbandAdapter'
```

**Key Changes:**
- Role mapping logic moves from callback view into a custom adapter class
- Subclass `DefaultWristbandAuthBackendAdapter` and override `populate_user()`
- Configure adapter in settings via `WRISTBAND_AUTH_BACKEND_ADAPTER`
- Adapter pattern separates authentication logic from user customization
- Parent adapter handles basic field mapping (email, first_name, last_name)

#### Required Scope Changes

**v0.x:**
```python
# Default scopes were sufficient for basic user sync
WRISTBAND_AUTH = {
    # ...
-   # scopes not explicitly set, defaults to ["openid", "offline_access", "email"]
}
```

**v1.x:**
```python
# Role mapping requires explicit 'roles' scope
WRISTBAND_AUTH = {
    # ... other config
+   "scopes": ["openid", "offline_access", "email", "profile", "roles"],
}
```

**Key Changes:**
- Must explicitly include `"profile"` scope for name fields (given_name, family_name)
- Must explicitly include `"roles"` scope for role mapping functionality
- Without these scopes, `user_info.roles` will be `None` and role mapping won't work

<br>

## Recommended Updates

### New API Endpoints for Frontend SDKs

While not strictly breaking changes, v1.x introduces new endpoints required when using Wristband frontend SDKs or building API-first applications.

#### Session Endpoint (Required for Frontend SDKs)

Add a Session Endpoint that returns authentication status in the format expected by Wristband frontend SDKs and use the `get_session_response()` helper function:

```python
# your_app/urls.py
urlpatterns = [
    # ... existing auth URLs ...
+   path('auth/session/', auth_views.session_endpoint, name='session'),
]
```

```python
# your_app/auth_views.py
+ from django.http import JsonResponse
+ from wristband.django_auth import get_session_response
+ from your_app.wristband import require_session

+ @require_session
+ @require_GET
+ def session_endpoint(request: HttpRequest) -> JsonResponse:
+     """Session endpoint for Wristband frontend SDKs"""
+     session_data = get_session_response(request, metadata={'foo': 'bar'})
+     response = JsonResponse(session_data)
+     response['Cache-Control'] = 'no-store'
+     response['Pragma'] = 'no-cache'
+     return response
```

#### Token Endpoint (Optional)

If your frontend needs to make direct API calls with access tokens, add a Token Endpoint and use the `get_token_response()` helper function:

```python
# your_app/urls.py
urlpatterns = [
    # ... existing auth URLs ...
+   path('auth/token/', auth_views.token_endpoint, name='token'),
]
```

```python
# your_app/auth_views.py
+ from wristband.django_auth import get_token_response

+ @require_session
+ @require_GET
+ def token_endpoint(request: HttpRequest) -> JsonResponse:
+     """Token endpoint for frontend access token retrieval"""
+     token_data = get_token_response(request)
+     response = JsonResponse(token_data)
+     response['Cache-Control'] = 'no-store'
+     response['Pragma'] = 'no-cache'
+     return response
```

<br>

### Enhanced Authentication Strategies

v1.x introduces support for multiple authentication strategies that can be combined.

#### JWT Authentication Support

If your application needs to support JWT bearer tokens:

```python
# your_app/wristband.py
+ from wristband.django_auth import AuthStrategy, JWTAuthConfig, UnauthenticatedBehavior

+ # Create JWT decorator
+ require_jwt = wristband_auth.create_auth_decorator(
+     strategies=[AuthStrategy.JWT],
+     on_unauthenticated=UnauthenticatedBehavior.JSON,
+ )
```

```python
# your_app/views.py
from your_app.wristband import require_jwt

@require_jwt
def api_endpoint(request):
    # JWT available in request.auth
    user_id = request.auth.payload.sub
    access_token = request.auth.jwt
    return JsonResponse({'user_id': user_id})
```

#### Multi-Strategy Authentication

Support both session and JWT authentication in the same application:

```python
# your_app/wristband.py
+ from wristband.django_auth import AuthStrategy

+ # Try session first, fall back to JWT
+ require_auth = wristband_auth.create_auth_decorator(
+     strategies=[AuthStrategy.SESSION, AuthStrategy.JWT],
+     on_unauthenticated=UnauthenticatedBehavior.JSON,
+ )
```

```python
# your_app/views.py
from your_app.wristband import require_auth

@require_auth
def flexible_api(request):
    # Check which strategy succeeded
    if hasattr(request, 'auth'):
        user_id = request.auth.payload.sub  # JWT
    else:
        user_id = request.session['user_id']  # Session
    
    return JsonResponse({'user_id': user_id})
```

#### Django REST Framework Support

For DRF applications, use the new DRF authentication classes:

```python
# your_app/wristband.py
+ DrfSessionAuth = wristband_auth.create_drf_session_auth()
+ DrfJwtAuth = wristband_auth.create_drf_jwt_auth()
```

```python
# your_app/views.py
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from your_app.wristband import DrfSessionAuth, DrfJwtAuth

class FlexibleAPIView(APIView):
    # DRF tries session auth first, then JWT
    authentication_classes = [DrfSessionAuth, DrfJwtAuth]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if hasattr(request, 'auth'):
            user_id = request.auth.payload.sub
        else:
            user_id = request.session['user_id']
        
        return Response({'user_id': user_id})
```

> **Note:** DRF authentication classes require `djangorestframework>=3.15.0`. Install with `pip install wristband-django-auth[drf]`.

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
