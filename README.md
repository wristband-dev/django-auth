<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Enterprise-ready auth that is secure by default, truly multi-tenant, and ungated for small businesses.
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

# Wristband Multi-Tenant Authentication SDK for Python Django

This module facilitates seamless interaction with Wristband for user authentication within multi-tenant [Django applications](https://www.djangoproject.com/). It follows OAuth 2.1 and OpenID standards.

Key functionalities encompass the following:

- Initiating a login request by redirecting to Wristband.
- Receiving callback requests from Wristband to complete a login request.
- Retrieving all necessary JWT tokens and userinfo to start an application session.
- Logging out a user from the application by revoking refresh tokens and redirecting to Wristband.
- Checking for expired access tokens and refreshing them automatically, if necessary.

You can learn more about how authentication works in Wristband in our documentation:

- [Backend Server Integration Pattern](https://docs.wristband.dev/docs/backend-server-integration)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [1) Configure Wristband Settings](#1-configure-wristband-settings)
  - [2) Initialize the SDK](#2-initialize-the-sdk)
  - [3) Set Up Session Storage](#3-set-up-session-storage)
  - [4) Add Auth Views/Endpoints](#4-add-auth-viewsendpoints)
    - [URL Configuration](#url-configuration)
    - [Login View/Endpoint](#login-viewendpoint)
    - [Callback View/Endpoint](#callback-viewendpoint)
    - [Logout View/Endpoint](#logout-viewendpoint)
  - [5) Add Template Context Processor](#5-add-template-context-processor)
  - [6) Protect Resources and Handle Token Refresh](#6-protect-resources-and-handle-token-refresh)
  - [7) Pass Your Access Token to Downstream APIs](#7-pass-your-access-token-to-downstream-apis)
  - [8) Configure CSRF Protection](#8-configure-csrf-protection)
- [Hybrid Authentication with Django's Built-in Auth System](#hybrid-authentication-with-djangos-built-in-auth-system)
  - [Enable Django Authentication Components](#enable-django-authentication-components)
  - [Sync Wristband Users to Django User Model and Groups](#sync-wristband-users-to-django-user-model-and-groups)
  - [Update Your Authentication Middleware](#update-your-authentication-middleware)
  - [Access Django Admin Through Wristband Authentication](#access-django-admin-through-wristband-authentication)
  - [Log users out of Django](#log-users-out-of-django)
- [Wristband Auth Configuration Options](#wristband-auth-configuration-options)
- [API](#api)
  - [`login()`](#loginself-request-httprequest-config-optionalloginconfig---httpresponse)
  - [`callback()`](#callbackself-request-httprequest---callbackresult)
  - [`logout()`](#logoutself-request-httprequest-config-optionallogoutconfig---httpresponse)
  - [`refresh_token_if_expired()`](#refresh_token_if_expiredself-refresh_token-optionalstr-expires_at-optionalint---tokendata--none)
- [Wristband Multi-Tenant Django Demo App](#wristband-multi-tenant-django-demo-app)
- [Questions](#questions)

<br/>

## Prerequisites

Before installing the SDK, ensure your environment meets the following requirements:
- [Python](https://www.python.org) ≥ 3.9
- [Django](https://www.djangoproject.com) ≥ 4.2 and < 6.0

<br/>

## Installation

**Install the package from PyPI**
```sh
pip install wristband-django-auth
```

**Or if using poetry**
```sh
poetry add wristband-django-auth
```

**Or if using pipenv**
```sh
pipenv install wristband-django-auth
```

<br>

## Usage

### 1) Configure Wristband Settings

First, add your Wristband configuration to your Django settings file. All necessary configurations for your application should correlate with how you've set it up in Wristband:

```python
# your_project/settings.py

WRISTBAND_AUTH = {
    "client_id": "<your_client_id>",
    "client_secret": "<your_client_secret>",
    "wristband_application_vanity_domain": "<your_wristband_application_vanity_domain>",
}
```

<br>

### 2) Initialize the SDK

Create an instance of `WristbandAuth` in a dedicated authentication module somewhere in your Django app (i.e., `your_app/wristband.py`). When creating an instance, provide all necessary Wristband configurations from your Django settings.

> [!NOTE]
> If you use Safari browser When developing and testing on `localhost`, you may need to set `dangerously_disable_secure_cookies=True`. Remember to set the value back to `False` for Production!

```python
# your_app/wristband.py
from django.conf import settings
from wristband.django_auth import AuthConfig, WristbandAuth

__all__ = ['wristband_auth']

# Configure Wristband authentication
def _create_wristband_auth() -> WristbandAuth:
    wristband_settings = settings.WRISTBAND_AUTH
    
    auth_config = AuthConfig(
        client_id=wristband_settings['client_id'],
        client_secret=wristband_settings['client_secret'],
        wristband_application_vanity_domain=wristband_settings['wristband_application_vanity_domain'],
    )
    return WristbandAuth(auth_config)

# Initialize Wristband auth instance
wristband_auth = _create_wristband_auth()
```

<br>

### 3) Set Up Session Storage

This Wristband authentication SDK is unopinionated about how you store and manage your application session data after the user has authenticated. It is common practice to leverage Django's built-in session framework for storing and managing your application session data. Django sessions are secure, well-tested, and provide flexible backend storage options.

Django sessions are enabled by default when you include the required middleware and apps in your settings:

```python
# your_project/settings.py

# ...

# Required for Django sessions
INSTALLED_APPS = [
    'django.contrib.sessions',  # Session framework
    # ... other apps
]

MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',  # Session middleware
    # ... other middleware
]
```

Django's session framework supports multiple options out of the box -- database sessions (default), cached sessions, file-based sessions, cookie-based sessions, and cached database sessions. The default database backend works well for most applications:

```python
# your_project/settings.py

# ...

# Database sessions (default) - stores in django_session table
SESSION_ENGINE = 'django.contrib.sessions.backends.db'

# Cookie-based sessions - stores signed (not encrypted) data in cookies
# SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'

# Cache sessions - stores in configured cache backend
# SESSION_ENGINE = 'django.contrib.sessions.backends.cache'

# Cached database sessions - fast reads with reliable persistence
# SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'
```

Make sure to configure Django sessions to work optimally with Wristband authentication, ensuring sessions stay active during user activity and expire after periods of inactivity:

> [!NOTE]
> If you use Safari browser When developing and testing on `localhost`, you may need to set `SESSION_COOKIE_SECURE = False`. Remember to set the value back to `True` for Production!

```python
# your_project/settings.py

# ...

# Session configuration
SESSION_SAVE_EVERY_REQUEST = True  # Keep a rolling session expiration time as long as user is active
SESSION_COOKIE_AGE = 3600  # 1 hour of inactivity, adjust as needed
SESSION_COOKIE_SECURE = True  # IMPORTANT: Set to True in Production!!
```

<br>

### 4) Add Auth Views/Endpoints

There are <ins>three core authentication views/endpoints</ins> your Django application should expose to facilitate both the Login and Logout workflows in Wristband. You'll need to add them to your Django URL configuration and create corresponding views.

#### URL Configuration

First, include your app's URLs in the main project URLs:

```python
# your_project/urls.py
from django.urls import path, include

urlpatterns = [
    # Your other project URLs...
    
    # Include your app's URLs
    path('', include('your_app.urls')),
]
```

Then, add the authentication URLs to your Django app:

```python
# your_app/urls.py
from django.urls import path
from . import auth_views

app_name = 'your_app'

urlpatterns = [
    # Your other app URLs...
    
    # Wristband Auth Endpoints (URL path values can be anything you want)
    path('auth/login/', auth_views.login_view, name='login'),
    path('auth/callback/', auth_views.callback_view, name='callback'),
    path('auth/logout/', auth_views.logout_view, name='logout'),
]
```

<br/>

#### Login View/Endpoint

The goal of the Login View/Endpoint is to initiate an auth request by redirecting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. Your application should redirect to this endpoint when users need to log in to your application.

```python
# your_app/auth_views.py
from django.http import HttpRequest, HttpResponse
from django.views.decorators.http import require_GET
from wristband.django_auth import CallbackResultType, LogoutConfig

# Import your configured Wristband auth instance
from .wristband import wristband_auth

@require_GET
def login_view(request: HttpRequest) -> HttpResponse:
    """Initiate authentication by redirecting to Wristband"""
    return wristband_auth.login(request)

# ...
```

<br>

#### Callback View/Endpoint

The goal of the Callback View/Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

```python
# your_app/auth_views.py
from django.http import HttpRequest, HttpResponse
from django.views.decorators.http import require_GET
from wristband.django_auth import CallbackResultType, LogoutConfig
from .wristband import wristband_auth

# ...

@require_GET
def callback_view(request: HttpRequest) -> HttpResponse:
    """Process OAuth callback and create session for authenticated user"""
    callback_result = wristband_auth.callback(request)
        
    # For certain edge cases, the SDK will require you to redirect back to login
    if callback_result.type == CallbackResultType.REDIRECT_REQUIRED:
        return wristband_auth.create_callback_response(request, callback_result.redirect_url)
        
    # Create session data for the authenticated user
    callback_data = callback_result.callback_data
    request.session['wristband'] = {
        'access_token': callback_data.access_token,
        'expires_at': callback_data.expires_at,
        'refresh_token': callback_data.refresh_token,
        'user_info': callback_data.user_info,
        'tenant_domain_name': callback_data.tenant_domain_name,
        'tenant_custom_domain': callback_data.tenant_custom_domain,
    }
        
    # Redirect to your app
    post_callback_url = callback_data.return_url or '/'
    return wristband_auth.create_callback_response(request, post_callback_url)

# ...
```

<br/>

#### Logout View/Endpoint

The goal of the Logout View/Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).


```python
# your_app/auth_views.py
from django.http import HttpRequest, HttpResponse
from django.views.decorators.http import require_GET
from wristband.django_auth import CallbackResultType, LogoutConfig
from .wristband import wristband_auth

# ...

@require_GET
def logout_view(request: HttpRequest) -> HttpResponse:
    """Log out user and redirect to Wristband logout endpoint"""
    # Get session data for logout configuration
    wristband_session = request.session.get('wristband', {})
        
    # Wristband SDK revokes the refresh token (if provided) and creates the proper redirect response.
    # Wristband Logout requires a tenant level domain. Custom domains take precedence (if present).
    response = wristband_auth.logout(
        request, 
        LogoutConfig(
            refresh_token=wristband_session.get('refresh_token'),
            tenant_domain_name=wristband_session.get('tenant_domain_name'),
            tenant_custom_domain=wristband_session.get('tenant_custom_domain'),
        )
    )
        
    # Destroy the user's session
    request.session.flush()
    
    return response
```

<br>

### 5) Add Template Context Processor

Django context processors allow you to make data available across all templates without manually passing it from each view. This is perfect for authenticated session data that you want to access in your templates for things like showing user information, login/logout links, and conditional content.

#### Create the Context Processor

Create a context processor to make Wristband authentication data available in all your templates:

```python
# your_app/context_processors.py
from typing import Dict, Any
from django.http import HttpRequest

def wristband_auth(request: HttpRequest) -> Dict[str, Any]:
    """
    Makes authentication data from Django sessions available to all templates
    via the 'wristband' context variable.
    """
    return {
        'wristband': request.session.get('wristband', {}),
    }
```

#### Register the Context Processor

Add your context processor to your Django settings:

```python
# your_project/settings.py

# ...

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                # your other context processors...

                'your_app.context_processors.wristband_auth',  # <-- Add this line
            ],
        },
    },
]
```

#### Using Authentication Data in Templates

Now you can access authenticated session data in any template:

```html
<!-- Check if user is authenticated -->
{% if wristband %}
    <div class="user-info">
        <p>Welcome, {{ wristband.user_info.email }}!</p>
        <p>Tenant: {{ wristband.tenant_domain_name }}</p>
        <a href="{% url 'your_app:logout' %}">Logout</a>
    </div>
{% else %}
    <a href="{% url 'your_app:login' %}">Login with Wristband</a>
{% endif %}

<!-- Access specific user data -->
{% if wristband.user_info %}
    <img src="{{ wristband.user_info.picture }}" alt="Profile">
    <span>{{ wristband.user_info.given_name }} {{ wristband.user_info.family_name }}</span>
{% endif %}
```

<br/>

### 6) Protect Resources and Handle Token Refresh

When it comes to protecting your Django application, you'll mark protected endpoints that require authentication and then create custom middleware that automatically:

- Determines which incoming requests need authentication
- Ensures users have valid, active sessions
- Automatically refreshes expired access tokens to maintain seamless user experience
- Redirects unauthenticated users or returns appropriate error responses

#### Use Decorators/Mixins on Views

The SDK provides flexible authentication markers to identify your protected endpoints:

- `@wristband_auth_required` decorator: Apply to function-based views that need authentication
- `WristbandAuthRequiredMixin` mixin: Inherit in class-based views to mark them as protected

These markers don't handle the actual authentication logic themselves. Instead, they serve as signals to your auth middleware, telling it which routes require user validation.

**Function-Based Protected Views:**
```python
# your_app/protected_views.py
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET
from wristband.django_auth import wristband_auth_required

@wristband_auth_required
@require_GET
def hello_world(request: HttpRequest) -> HttpResponse:
    """ Requires auth """
    return render(request, "your_app/hello_world.html")
```

**Class-based Protected Views:**
```python
# your_app/protected_views.py
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views import View
from wristband.django_auth import WristbandAuthRequiredMixin

class HelloWorld(WristbandAuthRequiredMixin, View):
    """ Requires auth """
    def get(self, request: HttpRequest) -> HttpResponse:
        return render(request, "your_app/hello_world.html")
```

#### Create the Authentication Middleware

Create authentication middleware to protect your application views/endpoints and handle automatic token refresh. This middleware acts as a security gateway, validating user sessions on protected routes and seamlessly managing token lifecycle to keep users authenticated.

The middleware will leverage two key Wristband SDK functions:

- `is_wristband_auth_required(request)`: Determines if the incoming request targets a protected endpoint
- `refresh_token_if_expired(refresh_token, expires_at)`: Automatically refreshes expired tokens with built-in retry logic and returns updated JWTs

> [!NOTE]
> There may be applications that do not want to utilize access tokens and/or refresh tokens. If that applies to your application, then you can ignore using the `refresh_token_if_expired()` functionality.

```python
# your_app/auth_middleware.py
from typing import Optional
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import redirect
from wristband.django_auth import is_wristband_auth_required
from .wristband import wristband_auth


class AuthMiddleware(MiddlewareMixin):
    """
    Authentication middleware that protects routes and handles token refresh.
    """
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        # Skip authentication for public paths
        if not is_wristband_auth_required(request):
            return None

        # Validate the user's authenticated session
        wristband_session = request.session.get('wristband')
        if not wristband_session:
            return self._auth_failure_response(request)

        try:
            # Check if token is expired and refresh if necessary
            refresh_token = wristband_session.get('refresh_token')
            expires_at = wristband_session.get('expires_at', 0)
            new_token_data = wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

            # Update session with new token data only if a refresh occured
            if new_token_data:
                wristband_session.update({
                    'access_token': new_token_data.access_token,
                    'refresh_token': new_token_data.refresh_token,
                    'expires_at': new_token_data.expires_at,
                })
                request.session['wristband'] = wristband_session

        except Exception as e:
            return self._auth_failure_response(request)

        return None

    def _auth_failure_response(self, request: HttpRequest) -> HttpResponse:
        # Clear invalid session
        request.session.flush()
        
        # You can return a JSON response for pure AJAX/API requests
        if request.path.startswith('/api/'):
            return JsonResponse({'error': 'Authentication required'}, status=401)

        # Otherwise, redirect to your Login Endpoint for page/template requests
        return redirect('/auth/login/')
```

#### Register the Auth Middleware

Lastly, add your authentication middleware to your Django settings. <ins>Place it AFTER SessionMiddleware but before any middleware that depends on authentication:</ins>

```python
# your_project/settings.py

# ...

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',  # <-- Must come before auth
    'django.middleware.common.CommonMiddleware',
    'your_app.middleware.AuthMiddleware',  # <-- Add your auth middleware here
    # your other middlewares ...
]
```

The middleware will now protect all your protected routes!

<br>

### 7) Pass Your Access Token to Downstream APIs

> [!NOTE]
> This is only applicable if you wish to call Wristband's APIs directly or protect your application's other downstream backend APIs.

If you intend to utilize Wristband APIs within your application or secure any backend APIs or downstream services using the access token provided by Wristband, you must include this token in the `Authorization` HTTP request header.

```
Authorization: Bearer <access_token_value>
```

For example, you would pass the access token from your Django session into the `Authorization` header of an API request as follows:

```python
# your_app/app_views.py
import requests
from django.http import HttpRequest, JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from wristband.django_auth import WristbandAuthRequiredMixin


class UpdateNickname(WristbandAuthRequiredMixin, View):
    """Update user nickname via Wristband API"""

    def post(self, request: HttpRequest) -> JsonResponse:
        try:
            # Auth middleware ensures this exists
            wristband_session = request.session.get('wristband', {})
            user_info = wristband_session.get('user_info', {})

            # Wristband Update User API - https://docs.wristband.dev/reference/patchuserv1
            response = requests.patch(
                f'https://<your-wristband-app-vanity-domain>/api/v1/users/{user_info.get('sub')}',
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {wristband_session.get('access_token')}'
                },
                json={'nickname': 'Satoshi Nakamoto'},
            )
            
            response.raise_for_status()
            
            return JsonResponse({'success': True}, status=200)
                
        except requests.exceptions.RequestException as e:
            return JsonResponse({'error': f'API request failed: {str(e)}'}, status=500)
        except Exception as e:
            return JsonResponse({'error': 'Internal server error'}, status=500)
```

<br>

### 8) Configure CSRF Protection

Cross Site Request Forgery (CSRF) is a security vulnerability where attackers trick authenticated users into unknowingly submitting malicious requests to your application. Django's CSRF protection follows the Synchronizer Token Pattern, which generates a unique tokens for a session, stores them in the session, and validates submitted requests by comparing the submitted token with the session-stored token. This provides robust protection against CSRF attacks.

Refer to the [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) for more information about this topic.

#### Register CSRF Middleware

Enable CsrfViewMiddleware in your Django settings, and <ins>ensure it comes after SessionMiddleware but before AuthMiddleware</ins>. This ensures CSRF tokens are properly validated and synchronized with user sessions during the authentication process.

> [!NOTE]
> If you use Safari browser When developing and testing on `localhost`, you may need to set `CSRF_COOKIE_SECURE = False`. Remember to set the value back to `True` for Production!

```python
# your_project/settings.py

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    
    'django.middleware.csrf.CsrfViewMiddleware',  # <-- CSRF middleware
    
    'your_app.middleware.AuthMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

CSRF_COOKIE_AGE = 3600  # 1 hour (ensure this is the same as SESSION_COOKIE_AGE)
CSRF_COOKIE_SECURE = True # Set to True in Production!
```

#### Generate CSRF Token in Callback Endpoint

Call `get_token()` in your Callback View to generate the CSRF token and set the CSRF cookie. This ensures authenticated users receive a valid CSRF token immediately after login, enabling secure form submissions and API calls throughout their session.

```python
# your_app/auth_views.py
from django.middleware.csrf import get_token

# ...

class Callback(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        # ... existing callback logic ...
        
        # This creates the csrftoken cookie and stores the token in the Django session.
        get_token(request) # <-- Add this!
        
        post_callback_url = callback_data.return_url or '/'
        return wristband_auth.create_callback_response(request, post_callback_url)
```

#### Refresh CSRF Token in Auth Middleware

Update your auth middleware to call `getToken()` to refresh the CSRF token on each request to keep it synchronized with the session: This maintains rolling expiration for both session and CSRF cookies, ensuring they expire together and preventing authentication issues when users remain active beyond the initial timeout period.

```python
# your_app/middleware.py
from django.middleware.csrf import get_token

class AuthMiddleware(MiddlewareMixin):
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        # ... existing auth logic ...
        
        # Update CSRF cookie expiration to match session
        get_token(request) # <-- Add this!
        
        return None
```

#### Clear CSRF Cookie on Logout

Remove the CSRF token cookie when users log out. This prevents stale CSRF tokens from persisting after logout.

```python
# your_app/auth_views.py

# ...

class Logout(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        # ... existing logout logic ...
        
        request.session.flush()
        
        # Clear CSRF token cookie
        response.delete_cookie('csrftoken') # <-- Add this!
        
        return response
```

#### Using CSRF Tokens in Templates

Django automatically includes CSRF tokens in forms:

```html
<form method="post">
    {% csrf_token %}  <!-- Django handles this automatically -->
    <button type="submit">Submit</button>
</form>
```

#### Basic AJAX CSRF Handling

For AJAX requests with authenticated endpoints, include the CSRF token in request headers:

```javascript
// Get CSRF token from cookie
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Include CSRF token in AJAX requests
fetch('/api/update/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken'), // <-
    },
    mode: 'same-origin',
    body: JSON.stringify({ data: 'your data' })
});
```

This setup ensures your Wristband-authenticated sessions are protected against CSRF attacks while integrating seamlessly with Django's security framework.

> [!NOTE]
> For complete CSRF configuration options, advanced AJAX patterns, edge cases, and troubleshooting, see Django's CSRF protection documentation.

<br/>

## Hybrid Authentication with Django's Built-in Auth System

> [!NOTE]
> **OPTIONAL:** This section is optional. The Wristband SDK works perfectly on its own without Django's built-in authentication system. Only implement this hybrid approach if your application needs Django User objects, groups, permissions, or admin interface integration.

Many Django applications benefit from combining Wristband's multi-tenant authentication with Django's built-in user management system. This hybrid approach lets you leverage Wristband for secure, scalable authentication while using Django's familiar User model, groups, permissions, and admin interface for application-specific user management.

This integration pattern is particularly valuable when you need to:

- Map Wristband roles to Django groups for permission-based access control
- Store additional user data beyond what Wristband provides
- Use Django's admin interface for user management
- Integrate with existing Django packages that expect Django User objects
- Maintain user data locally for performance or offline scenarios

The hybrid approach synchronizes Wristband user data with Django's User model during your Callback View, creating a seamless bridge between external identity management and internal application logic.

To implement hybrid authentication, you'll need to handle the following steps.

<br>

### Enable Django Authentication Components

Add Django's authentication system to your settings to enable User model, groups, permissions, and admin interface integration:

```python
# your_project/settings.py

INSTALLED_APPS = [
    "django.contrib.admin",  # <-- ADD: Enables Django admin interface for user management
    "django.contrib.auth",   # <-- ADD: Provides User model, groups, and permissions system
    "django.contrib.sessions",
    # ... other apps
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    "django.contrib.auth.middleware.AuthenticationMiddleware",  # <-- ADD: Links request.user to Django User objects
    'your_app.middleware.AuthMiddleware',
    # your other middlewares ...
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                # your other context processors...
                "django.contrib.auth.context_processors.auth",  # <-- ADD: Makes request.user available in templates
                'your_app.context_processors.wristband_auth', 
            ],
        },
    },
]
```

You'll need to **run database migrations** to create the necessary database tables for Django's User model, groups, and permissions system. For example:

```sh
python manage.py migrate
```

<br>

### Sync Wristband Users to Django User Model and Groups

Modify your Callback View to create and sync Django User objects with Wristband user data. This bridges Wristband authentication with Django's user management system, enabling you to use Django's permissions, groups, and admin interface.

```python
# your_app/auth_views.py
from django.contrib.auth import login
from django.contrib.auth.models import User, Group
from django.http import HttpRequest, HttpResponse
from django.views.decorators.http import require_GET
from wristband.django_auth import CallbackResultType, LogoutConfig
from .wristband import wristband_auth

# ...

@require_GET
def callback_view(request: HttpRequest) -> HttpResponse:
    callback_result = wristband_auth.callback(request)

    if callback_result.type == CallbackResultType.REDIRECT_REQUIRED:
        redirect_url = callback_result.redirect_url
        return wristband_auth.create_callback_response(request, redirect_url)

    callback_data = callback_result.callback_data
    request.session["wristband"] = {
        "user_info": callback_data.user_info,
        "access_token": callback_data.access_token,
        "refresh_token": callback_data.refresh_token,
        "expires_at": callback_data.expires_at,
        "tenant_domain_name": callback_data.tenant_domain_name,
        "tenant_custom_domain": callback_data.tenant_custom_domain,
    }

    # Sync Wristband user and log them in to Django's auth system
    _sync_and_login_django_user(request, callback_data.user_info)  # <-- ADD THIS

    get_token(request)
    post_callback_url = callback_data.return_url or "/"
    return wristband_auth.create_callback_response(request, post_callback_url)


def _sync_and_login_django_user(request: HttpRequest, user_info):
    """ Create or update Django User from Wristband user data and map roles to groups. """
    email = user_info.get('email')
    first_name = user_info.get('given_name') or 'First Name'
    last_name = user_info.get('family_name') or 'Last Name'
    user_id = user_info.get('sub')

    # Use Wristband user ID as username since emails can change
    user, created = User.objects.get_or_create(
        username=user_id,
        defaults={
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'is_active': True,
        }
    )
    
    # Always sync fields for existing users
    if not created:
        user.email = email
        user.first_name = first_name
        user.last_name = last_name

    # NOTE: The role names "Viewers" and "Owners" are examples. 
    # Customize these group names and role-matching logic based on your requirements.
    user.groups.clear()
    user.is_staff = False
    user.is_superuser = False
    viewer_group, _ = Group.objects.get_or_create(name='Viewers')
    user.groups.add(viewer_group)

    # Map Wristband roles to Django groups and permissions.
    roles = user_info.get('roles', [])
    if roles:
        role_names = [role['name'] for role in roles]
        has_owner_role = any(
            role_name.startswith('app:') and role_name.endswith(':owner')
            for role_name in role_names
        )

        # Upgrade owners to admin permissions and Owners group.
        if has_owner_role:
            user.groups.clear()
            user.is_staff = True
            user.is_superuser = True
            owner_group, _ = Group.objects.get_or_create(name='Owners')
            user.groups.add(owner_group)

    # Save user and log into Django auth system
    user.save()
    login(request, user)
    return user
```

Make sure you configure the required scopes for the SDK to ensure user profile and role data is available for synchronization:

```python
# your_app/wristband.py
from django.conf import settings
from wristband.django_auth import AuthConfig, WristbandAuth

def _create_wristband_auth() -> WristbandAuth:
    wristband_settings = settings.WRISTBAND_AUTH
    
    auth_config = AuthConfig(
        client_id=wristband_settings['client_id'],
        client_secret=wristband_settings['client_secret'],
        wristband_application_vanity_domain=wristband_settings['wristband_application_vanity_domain'],
        scopes=["openid", "offline_access", "email", "profile", "roles"],  # <-- Include profile and roles
    )
    return WristbandAuth(auth_config)
```

### Update Your Authentication Middleware

With Django's authentication system enabled, update your middleware to work seamlessly with Django's `request.user` object while maintaining Wristband session validation and token refresh:

```python
# your_app/auth_middleware.py
from typing import Optional
from django.contrib.auth import logout
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin
from wristband.django_auth import is_wristband_auth_required
from .wristband import wristband_auth


class AuthMiddleware(MiddlewareMixin):
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        if not is_wristband_auth_required(request):
            return None

        # vvv ADD: Validate both Wristband session and Django authentication vvv
        wristband_data = request.session.get("wristband")
        if not request.user.is_authenticated or not wristband_data:
            return self._auth_failure_response(request)

        try:
            refresh_token = wristband_data.get("refresh_token")
            expires_at = wristband_data.get("expires_at", 0)
            new_token_data = wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

            if new_token_data:
                wristband_data.update({
                    "access_token": new_token_data.access_token,
                    "refresh_token": new_token_data.refresh_token,
                    "id_token": new_token_data.id_token,
                    "expires_at": new_token_data.expires_at,
                })
                request.session["wristband"] = wristband_data

            get_token(request)

        except Exception as e:
            return self._auth_failure_response(request)

        return None

    def _auth_failure_response(self, request: HttpRequest) -> HttpResponse:
        request.session.flush()

        logout(request)  # <-- ADD: Log user out of Django auth system

        if request.path.startswith("/api/"):
            return JsonResponse({"error": "Authentication failed"}, status=401)

        return redirect("/auth/login")
```

<br>

### Access Django Admin Through Wristband Authentication

Instead of maintaining separate admin credentials, you can configure Django's admin interface to use Wristband authentication, allowing users with appropriate permissions to access admin functionality seamlessly.

This configuration provides:

- Unified authentication: Admin access uses the same Wristband login flow as your application
- Permission-based access: Only users with `is_staff=True` (owners in your role mapping) can access admin
- Seamless experience: Users with admin permissions are automatically redirected to admin after login
- No duplicate credentials: Eliminates the need to manage separate Django superuser accounts

```python
# your_app/admin.py
from django.contrib import admin
from django.contrib.auth.models import User, Group
from django.contrib.sessions.models import Session
from django.shortcuts import redirect
from urllib.parse import urlencode


class WristbandAdminSite(admin.AdminSite):
    """Custom admin site that uses Wristband authentication instead of Django's login form."""
    
    site_header = "Your App Admin"
    site_title = "Admin Portal"
    
    def login(self, request, extra_context=None):
        """Redirect to Wristband login instead of showing Django's admin login form."""
        # Build return URL to redirect back to admin after authentication
        return_url = request.build_absolute_uri('/admin/')
        login_url = f'/auth/login/?return_url={return_url}'
        return redirect(login_url)


# Create custom admin site instance
wristband_admin_site = WristbandAdminSite(name='wristband_admin')

# Register models with the custom admin site
wristband_admin_site.register(User)
wristband_admin_site.register(Group)
wristband_admin_site.register(Session)
```

After creating the custom admin site, make sure to update your URL configuration to use it:

```python
# your_project/urls.py
from django.urls import path, include
from your_app.admin import wristband_admin_site

urlpatterns = [
    # Replace default admin with Wristband-authenticated admin
    path('admin/', wristband_admin_site.urls),
    # Your other URLs
    path('', include('your_app.urls')),
]
```

<br>

### Log users out of Django

When users log out, ensure you clear both Wristband and Django authentication sessions to maintain security and prevent stale authentication states:

```python
# your_app/auth_views.py
from django.contrib.auth import logout
from django.http import HttpRequest, HttpResponse
from django.views.decorators.http import require_GET
from wristband.django_auth import LogoutConfig
from .wristband import wristband_auth

# ...

@require_GET
def logout_view(request: HttpRequest) -> HttpResponse:
    """ Log out the user and redirect to the Wristband Logout Endpoint. """
    wristband_session = request.session.get('wristband', {})
        
    response = wristband_auth.logout(
        request, 
        LogoutConfig(
            refresh_token=wristband_session.get('refresh_token'),
            tenant_domain_name=wristband_session.get('tenant_domain_name'),
            tenant_custom_domain=wristband_session.get('tenant_custom_domain'),
        )
    )

    logout(request)  # <-- ADD: Log user out of Django's auth system
        
    request.session.flush()
    response.delete_cookie("csrftoken")
    return response
```

<br>

## Wristband Auth Configuration Options

The `WristbandAuth()` constructor is used to instantiate the Wristband SDK. It takes an `AuthConfig` type as an argument.

```python
def __init__(self, auth_config: AuthConfig) -> None:
```

| AuthConfig Field | Type | Required | Auto-Configurable | Description |
| ---------------- | ---- | -------- | ----------------- | ----------- |
| auto_configure_enabled | bool | No | _N/A_ | Flag that tells the SDK to automatically set some of the SDK configuration values by calling to Wristband's SDK Auto-Configuration Endpoint. Any manually provided configurations will take precedence over the configs returned from the endpoint. Auto-configure is enabled by default. When disabled, if manual configurations are not provided, then an error will be thrown. |
| client_id | str | Yes | No | The ID of the Wristband client. |
| client_secret | str | Yes | No | The client's secret. |
| custom_application_login_page_url | Optional[str] | No | Yes | Custom Application-Level Login Page URL (i.e. Tenant Discovery Page URL). This value only needs to be provided if you are self-hosting the application login page. By default, the SDK will use your Wristband-hosted Application-Level Login page URL. If this value is provided, the SDK will redirect to this URL in certain cases where it cannot resolve a proper Tenant-Level Login URL. |
| dangerously_disable_secure_cookies | bool | No | No | USE WITH CAUTION: If set to `True`, the "Secure" attribute will not be included in any cookie settings. This should only be done when testing in local development environments that don't have HTTPS enabed.  If not provided, this value defaults to `False`. |
| is_application_custom_domain_active | Optional[bool] | No | Yes | Indicates whether your Wristband application is configured with an application-level custom domain that is active. This tells the SDK which URL format to use when constructing the Wristband Authorize Endpoint URL. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `default_tenant_custom_domain` config.  Defaults to `False`. |
| login_state_secret | Optional[str] | No | No | A 32 character (or longer) secret used for encryption and decryption of login state cookies. If not provided, it will default to using the client secret. For enhanced security, it is recommended to provide a value that is unique from the client secret. You can run `python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"` to create a secret from your CLI. |
| login_url | Optional[str] | Only when `auto_configure_enabled` is set to `False` | Yes | The URL of your application's login endpoint.  This is the endpoint within your application that redirects to Wristband to initialize the login flow. If you intend to use tenant subdomains in your Login Endpoint URL, then this value must contain the `{tenant_domain}` token. For example: `https://{tenant_domain}.yourapp.com/auth/login`. |
| parse_tenant_from_root_domain | Optional[str] | Only if using tenant subdomains in your application | Yes | The root domain for your application. This value only needs to be specified if you intend to use tenant subdomains in your Login and Callback Endpoint URLs.  The root domain should be set to the portion of the domain that comes after the tenant subdomain.  For example, if your application uses tenant subdomains such as `tenantA.yourapp.com` and `tenantB.yourapp.com`, then the root domain should be set to `yourapp.com`. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `default_tenant_custom_domain` config. When this configuration is enabled, the SDK extracts the tenant subdomain from the host and uses it to construct the Wristband Authorize URL. |
| redirect_uri | Optional[str] | Only when `auto_configure_enabled` is set to `False` | Yes | The URI that Wristband will redirect to after authenticating a user.  This should point to your application's callback endpoint. If you intend to use tenant subdomains in your Callback Endpoint URL, then this value must contain the `{tenant_domain}` token. For example: `https://{tenant_domain}.yourapp.com/auth/callback`. |
| scopes | List[str] | No | No | The scopes required for authentication. Specified scopes can alter which data is returned from the `callback()` method's `callback_data` return type.  Refer to the [Wristband Authorize API](https://docs.wristband.dev/reference/authorizev1) documentation for currently supported scopes. The default value is `["openid", "offline_access", "email"]`. |
| token_expiration_buffer | int | No | No | Buffer time (in seconds) to subtract from the access token’s expiration time. This causes the token to be treated as expired before its actual expiration, helping to avoid token expiration during API calls. Defaults to 60 seconds. |
| wristband_application_vanity_domain | str | Yes | No | The vanity domain of the Wristband application. |

<br>

### `WristbandAuth()`

```ts
wristband_auth: WristbandAuth = WristbandAuth(auth_config: AuthConfig)
```

This constructor creates an instance of `WristbandAuth` using lazy auto-configuration. Auto-configuration is enabled by default and will fetch any missing configuration values from the Wristband SDK Configuration Endpoint when any auth function is first called (i.e. `login`, `callback`, etc.). Set `auto_configure_enabled` to `False` disable to prevent the SDK from making an API request to the Wristband SDK Configuration Endpoint. In the event auto-configuration is disabled, you must manually configure all required values. Manual configuration values take precedence over auto-configured values.

**Minimal config with auto-configure (default behavior)**
```python
# your_project/settings.py

WRISTBAND_AUTH = {
    "client_id": "<your_client_id>",
    "client_secret": "<your_client_secret>",
    "wristband_application_vanity_domain": "<your_wristband_application_vanity_domain>",
}

# your_app/wristband.py
from django.conf import settings
from wristband.django_auth import AuthConfig, WristbandAuth

__all__ = ['wristband_auth']

# Configure Wristband authentication
def _create_wristband_auth() -> WristbandAuth:
    wristband_settings = settings.WRISTBAND_AUTH
    
    auth_config = AuthConfig(
        client_id=wristband_settings['client_id'],
        client_secret=wristband_settings['client_secret'],
        wristband_application_vanity_domain=wristband_settings['wristband_application_vanity_domain'],
    )
```

**Manual override with partial auto-configure for some fields**
```python
# your_project/settings.py

WRISTBAND_AUTH = {
    "client_id": "<your_client_id>",
    "client_secret": "<your_client_secret>",
    "wristband_application_vanity_domain": "<your_wristband_application_vanity_domain>",
    "login_url": "https://yourapp.io/auth/login",  # Manually override "login_url"
    # "redirect_uri" will be auto-configured
}

# your_app/wristband.py
from django.conf import settings
from wristband.django_auth import AuthConfig, WristbandAuth

__all__ = ['wristband_auth']

# Configure Wristband authentication
def _create_wristband_auth() -> WristbandAuth:
    wristband_settings = settings.WRISTBAND_AUTH
    
    auth_config = AuthConfig(
        client_id=wristband_settings['client_id'],
        client_secret=wristband_settings['client_secret'],
        wristband_application_vanity_domain=wristband_settings['wristband_application_vanity_domain'],
        login_url=wristband_settings['login_url'],
    )
```

**Auto-configure disabled**
```python
# your_project/settings.py

WRISTBAND_AUTH = {
    "auto_configure_enabled": False,
    "client_id": "<your_client_id>",
    "client_secret": "<your_client_secret>",
    "wristband_application_vanity_domain": "auth.custom.com",
    # Must manually configure non-auto-configurable fields
    "is_application_custom_domain_active": True,
    "login_url": "https://{tenant_domain}.custom.com/auth/login",
    "redirect_uri": "https://{tenant_domain}.custom.com/auth/callback",
    "parse_tenant_from_root_domain": "custom.com",
}

# your_app/wristband.py
from django.conf import settings
from wristband.django_auth import AuthConfig, WristbandAuth

__all__ = ['wristband_auth']

# Configure Wristband authentication
def _create_wristband_auth() -> WristbandAuth:
    wristband_settings = settings.WRISTBAND_AUTH
    
    auth_config = AuthConfig(
        client_id=wristband_settings['client_id'],
        client_secret=wristband_settings['client_secret'],
        wristband_application_vanity_domain=wristband_settings['wristband_application_vanity_domain'],
        is_application_custom_domain_active=wristband_settings['is_application_custom_domain_active'],
        login_url=wristband_settings['login_url'],
        redirect_uri=wristband_settings['redirect_uri'],
        parse_tenant_from_root_domain=wristband_settings['parse_tenant_from_root_domain'],
    )
```

<br>

### `WristbandAuth.discover()`

This method performs eager auto-configuration on an existing `WristbandAuth` instance. Unlike the default lazy auto-configuration behavior, this method immediately fetches and resolves all auto-configuration values from the Wristband SDK Configuration Endpoint during the call. This is useful when you want to fail fast if auto-configuration is unavailable, or when you need configuration values resolved before making any auth method calls. Manual configuration values take precedence over auto-configured values.

> [!WARNING]
> NOTE: This method can only be called when `auto_configure_enabled` is `True`. If auto-configuration is disabled, a `WristbandError` will be raised.

**Eager auto-configure with error handling**
```python
try:
    wristband_auth = WristbandAuth(AuthConfig(
        client_id="your-client-id",
        client_secret="your-client-secret",
        wristband_application_vanity_domain="auth.yourapp.io"
    ))
    
    # Eager-fetch the SDK configuration
    wristband_auth.discover()
    
    #
    # ...Configuration is now resolved and validated...
    #
except WristbandError as error:
    print(f'Auto-configuration failed: {error.error_description}')
```

<br>

## API

### `login(self, request: HttpRequest, config: Optional[LoginConfig]) -> HttpResponse:`

```python
response: HttpResponse = wristband_auth.login(request)
```

Wristband requires that your application specify a Tenant-Level domain when redirecting to the Wristband Authorize Endpoint when initiating an auth request. When your application redirects the user to your Django Login Endpoint, there are two ways to accomplish getting the `tenant_domain_name` information: passing a query parameter or using tenant subdomains.

The `login()` method can also take optional configuration if your application needs custom behavior:

| LoginConfig Field | Type | Required | Description |
| ----------------- | ---- | -------- | ----------- |
| custom_state | Optional[dict[str, Any]] | No | Additional state to be saved in the Login State Cookie. Upon successful completion of an auth request/login attempt, your Callback Endpoint will return this custom state (unmodified) as part of the return type. |
| default_tenant_domain_name | str | No | An optional default tenant domain name to use for the login request in the event the tenant domain cannot be found in either the subdomain or query parameters (depending on your subdomain configuration). |
| default_tenant_custom_domain | str | No | An optional default tenant custom domain to use for the login request in the event the tenant custom domain cannot be found in the query parameters. |
| return_url | string | No | The URL to return to after authentication is completed. If a value is provided, then it takes precedence over the `return_url` request query parameter. |

#### Which Domains Are Used in the Authorize URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Authorize URL, which your login endpoint will redirect users to during the login flow. The selection follows this precedence order:

1. `tenant_custom_domain` query parameter: If provided, this takes top priority.
2. Tenant subdomain in the URL: Used if `parse_tenant_from_root_domain` is specified and there is a subdomain present in the host.
3. `tenant_domain` query parameter: Evaluated if no tenant subdomain is found in the host.
4. `default_tenant_custom_domain` in LoginConfig: Used if none of the above are present.
5. `default_tenant_domain` in LoginConfig: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Tenant Domain Query Param

If your application does not wish to utilize subdomains for each tenant, you can pass the `tenant_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.ai/auth/login?tenant_domain=customer01
```

Your AuthConfig would look like the following when creating an SDK instance without any subdomains:

```python
# your_project/settings.py
WRISTBAND_AUTH = {
    "client_id": "dummyso5hzdvbnof3bwgccejxy",
    "client_secret": "dummy77124b13037d035be10d727806f",
    "login_state_secret": "dummy7fdbeccab7d413493072dfcc52f7475",
    "login_url": 'https://yourapp.ai/auth/login',
    "redirect_uri": 'https://yourapp.ai/auth/callback',
    "wristband_application_vanity_domain": "yourapp-yourcompany.us.wristband.dev",
}
```

#### Tenant Subdomains

If your application wishes to utilize tenant subdomains, then you do not need to pass a query param when redirecting to your Django Login Endpoint. The SDK will parse the tenant subdomain from the host in order to make the redirection to the Wristband Authorize Endpoint. You will also need to tell the SDK what your application's root domain is in order for it to correctly parse the subdomain.

```sh
GET https://customer01.yourapp.ai/auth/login
```

Your AuthConfig would look like the following when creating an SDK instance when using subdomains:

```python
# your_project/settings.py
WRISTBAND_AUTH = {
    "client_id": "dummyso5hzdvbnof3bwgccejxy",
    "client_secret": "dummy77124b13037d035be10d727806f",
    "login_state_secret": "dummy7fdbeccab7d413493072dfcc52f7475",
    "login_url": 'https://{tenant_domain}.yourapp.ai/auth/login',
    "redirect_uri": 'https://{tenant_domain}.yourapp.ai/auth/callback',
    "parse_tenant_from_root_domain": "yourapp.ai",
    "wristband_application_vanity_domain": "yourapp-yourcompany.us.wristband.dev",
}
```

#### Default Tenant Domain Name

For certain use cases, it may be useful to specify a default tenant domain in the event that the `login()` method cannot find a tenant domain in either the query parameters or in the URL subdomain. You can specify a fallback default tenant domain via a `LoginConfig` object:

```python
response = wristband_auth.login(
    request=request, 
    config=LoginConfig(default_tenant_domain_name="default")
)
```

#### Tenant Custom Domain Query Param

If your application wishes to utilize tenant custom domains, you can pass the `tenant_custom_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.ai/auth/login?tenant_custom_domain=mytenant.com
```

The tenant custom domain takes precedence over all other possible domains else when present.

#### Default Tenant Custom Domain

For certain use cases, it may be useful to specify a default tenant custom domain in the event that the `login()` method cannot find a tenant custom domain in the query parameters. You can specify a fallback default tenant custom domain via a `LoginConfig` object:

```python
response = wristband_auth.login(
    request=request, 
    config=LoginConfig(default_tenant_custom_domain="mytenant.com")
)
```

The default tenant custom domain takes precedence over all other possible domain configurations when present except for the case where the `tenant_custom_domain` query parameter exists in the request.

#### Custom State

Before your Login Endpoint redirects to Wristband, it will create a Login State Cookie to cache all necessary data required in the Callback Endpoint to complete any auth requests. You can inject additional state into that cookie via a `LoginConfig` object:

```python
response = wristband_auth.login(
    request=request, 
    config=LoginConfig(custom_state={"test": "abc"})
)
```

> [!WARNING]
> Injecting custom state is an advanced feature, and it is recommended to use `custom_state` sparingly. Most applications may not need it at all. The max cookie size is 4kB. From our own tests, passing a `custom_state` JSON of at most 1kB should be a safe ceiling.

#### Login Hints

Wristband will redirect to your Django Login Endpoint for workflows like Application-Level Login (Tenant Discovery) and can pass the `login_hint` query parameter as part of the redirect request:

```sh
GET https://customer01.yourapp.ai/auth/login?login_hint=user@wristband.dev
```

If Wristband passes this parameter, it will be appended as part of the redirect request to the Wristband Authorize Endpoint. Typically, the email form field on the Tenant-Level Login page is pre-filled when a user has previously entered their email on the Application-Level Login Page.

#### Return URLs

It is possible that users will try to access a location within your application that is not some default landing page. In those cases, they would expect to immediately land back at that desired location after logging in.  This is a better experience for the user, especially in cases where they have application URLs bookmarked for convenience.

Given that your frontend will redirect users to your Login Endpoint, you can either include it in your Login Config:

```python
response = wristband_auth.login(
    request=request, 
    config=LoginConfig(return_url="test")
)
```

...or you can pass a `return_url` query parameter when redirecting to your Login Endpoint:

```sh
GET https://customer01.yourapp.io/auth/login?return_url=https://customer01.yourapp.io/settings/profile
```

The return URL is stored in the Login State Cookie, and it is available to you in your Callback Endpoint after the SDK's `callback()` method is done executing. You can choose to send users to that return URL (if necessary). The Login Config takes precedence over the query parameter in the event a value is provided for both.

<br/>

### `callback(self, request: HttpRequest) -> CallbackResult:`

```python
callback_result: CallbackResult = wristband_auth.callback(request)
response: HttpResponse = wristband_auth.create_callback_response(request, "https://yourapp.ai/home")
```

After a user authenticates on the Tenant-Level Login Page, Wristband will redirect to your Django Callback Endpoint with an authorization code which can be used to exchange for an access token. It will also pass the state parameter that was generated during the Login Endpoint.

```sh
GET https://customer01.yourapp.ai/auth/callback?state=f983yr893hf89ewn0idjw8e9f&code=shcsh90jf9wc09j9w0jewc
```

The SDK will validate that the incoming state matches the Login State Cookie, and then it will call the Wristband Token Endpoint to exchange the authorizaiton code for JWTs. Lastly, it will call the Wristband Userinfo Endpoint to get any user data as specified by the `scopes` in your SDK configuration. The return type of the callback method is a CallbackResult type containing the result of what happened during callback execution as well as any accompanying data:

| CallbackResult Field | Type | Description |
| -------------------- | ---- | ----------- |
| callback_data | `CallbackData` | The callback data received after authentication (`COMPLETED` result only). |
| redirect_url | str | A URL that you need to redirect to (`REDIRECT_REQUIRED` result only). For some edge cases, the SDK will require a redirect to restart the login flow. |
| type | `CallbackResultType`  | Enum representing the type of the callback result. |

The following are the possible `CallbackResultType` enum values that can be returned from the callback execution:

| CallbackResultType  | Description |
| ------------------- | ----------- |
| `COMPLETED`  | Indicates that the callback is successfully completed and data is available for creating a session. |
| `REDIRECT_REQUIRED`  | Indicates that a redirect to the login endpoint is required. |

When the callback returns a `COMPLETED` result, all of the token and userinfo data also gets returned. This enables your application to create an application session for the user and then redirect them back into your application.

The `CallbackData` is defined as follows:

| CallbackData Field | Type | Description |
| ------------------ | ---- | ----------- |
| access_token | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| custom_state | Optional[dict[str, Any]] | If you injected custom state into the Login State Cookie during the Login Endpoint for the current auth request, then that same custom state will be returned in this field. |
| expires_at | int | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `token_expiration_buffer` SDK configuration is accounted for in this value. |
| expires_in | int | The durtaion from the current time until the access token is expired (in seconds). The `token_expiration_buffer` SDK configuration is accounted for in this value. |
| id_token | str | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refresh_token | Optional[str] | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |
| return_url | Optional[str] | The URL to return to after authentication is completed. |
| tenant_custom_domain | Optional[str] | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenant_domain_name | str | The domain name of the tenant the user belongs to. |
| user_info | dict[str, Any] | Data for the current user retrieved from the Wristband Userinfo Endpoint. The data returned in this object follows the format laid out in the [Wristband Userinfo Endpoint documentation](https://docs.wristband.dev/reference/userinfov1). The exact fields that get returned are based on the scopes you configured in the SDK. |


#### Handling Callback Results

Regardless of the result type, you should call `create_callback_response()` to produce the appropriate redirect response with all required headers set.

##### Type: REDIRECT_REQUIRED

In specific edge cases, the SDK returns a redirect URL with a result type of `REDIRECT_REQUIRED`. These cases include:

- The Login State Cookie is missing by the time Wristband redirects back to the Callback Endpoint.
- The `state` query parameter sent from Wristband to your Callback Endpoint does not match the Login State Cookie.
- Wristband sends an `error` query parameter to your Callback Endpoint, and it is an expected error type that the SDK knows how to resolve.

The location of the redirect depends on whether the SDK is able to determine which tenant the user is attempting to authenticate against. If the tenant domain can be determined, then the user will get redirected back to your Django Login Endpoint.

```python
if callback_result.type == CallbackResultType.REDIRECT_REQUIRED:
    return wristband_auth.create_callback_response(request, callback_result.redirect_url)
```

##### Type: COMPLETED

If the result type is `COMPLETED`, no redirect URL is provided. You're free to redirect the user to any destination your application needs.

```python
appUrl = callback_result.callback_data.returnUrl or 'https://yourapp.ai/home'
return wristband_auth.create_callback_response(request, appUrl)
```

#### Error Parameters

Certain edge cases are possible where Wristband encounters an error during the processing of an auth request. These are the following query parameters that are sent for those cases to your Callback Endpoint:

| Query Parameter | Description |
| --------------- | ----------- |
| error | Indicates an error that occurred during the Login Workflow. |
| error_description | A human-readable description or explanation of the error to help diagnose and resolve issues more effectively. |

```sh
GET https://customer01.yourapp.ai/auth/callback?state=f983yr893hf89ewn0idjw8e9f&error=login_required&error_description=User%20must%20re-authenticate%20because%20the%20specified%20max_age%20value%20has%20elapsed
```

The error types that get automatically resolved in the SDK are:

| Error | Description |
| ----- | ----------- |
| login_required | Indicates that the user needs to log in to continue. This error can occur in scenarios where the user's session has expired, the user is not currently authenticated, or Wristband requires the user to explicitly log in again for security reasons. |

For all other error types, the SDK will throw a `WristbandError` object (containing the error and description) that your application can catch and handle. Most errors come from SDK configuration issues during development that should be addressed before release to production.


### `logout(self, request: HttpRequest, config: Optional[LogoutConfig]) -> HttpResponse:`

```python
response: HttpResponse = wristband_auth.logout(
    request=request,
    config=LogoutConfig(refresh_token="98yht308hf902hc90wh09")
)
```

When users of your application are ready to log out or their application session expires, you should redirect the user to your Django Logout Endpoint.

```sh
GET https://customer01.yourapp.ai/auth/logout
```

If your application created a session, it should destroy it before invoking the `logout()` method.  This method can also take an optional `LogoutConfig` argument:

| LogoutConfig Field | Type | Required | Description |
| ------------------ | ---- | -------- | ----------- |
| redirect_url | Optional[str] | No | Optional URL that Wristband will redirect to after the logout operation has completed. This will also take precedence over the `custom_application_login_page_url` (if specified) in the SDK AuthConfig if the tenant domain cannot be determined when attempting to redirect to the Wristband Logout Endpoint. |
| refresh_token | Optional[str] | No | The refresh token to revoke. |
| state | Optional[str] | No | Optional value that will be appended as a query parameter to the resolved logout URL, if provided. Maximum length of 512 characters. |
| tenant_custom_domain | Optional[str] | No | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenant_domain_name | Optional[str] | No | The domain name of the tenant the user belongs to. |

#### Which Domains Are Used in the Logout URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Logout URL, which your login endpoint will redirect users to during the logout flow. The selection follows this precedence order:

1. `tenant_custom_domain` in LogoutConfig: If provided, this takes top priority.
2. `tenant_domain_name` in LogoutConfig: This takes the next priority if `tenant_custom_domain` is not present.
3. `tenant_custom_domain` query parameter: Evaluated if present and there is also no LogoutConfig provided for either `tenant_custom_domain` or `tenant_domain_name`.
4. Tenant subdomain in the URL: Used if none of the above are present, and `parse_tenant_from_root_domain` is specified, and the subdomain is present in the host.
5. `tenant_domain` query parameter: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Revoking Refresh Tokens

If your application requested refresh tokens during the Login Workflow (via the `offline_access` scope), it is crucial to revoke the user's access to that refresh token when logging out. Otherwise, the refresh token would still be valid and able to refresh new access tokens.  You should pass the refresh token into the LogoutConfig when invoking the `logout()` method, and the SDK will call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) automatically.

#### Resolving Tenant Domain Names

Much like the Login Endpoint, Wristband requires your application specify a Tenant-Level domain when redirecting to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1). If your application does not utilize tenant subdomains, then you can either explicitly pass it into the LogoutConfig:

```python
response: HttpResponse = wristband_auth.logout(
    request=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_domain_name="customer01"
    )
)
```

...or you can alternatively pass the `tenant_domain` query parameter in your redirect request to Logout Endpoint:

```python
# Logout Request URL -> "https://yourapp.ai/auth/logout?client_id=123&tenant_domain=customer01"
response: HttpResponse = wristband_auth.logout(
    request=request,
    config=LogoutConfig(refresh_token="98yht308hf902hc90wh09")
)
```

If your application uses tenant subdomains, then passing the `tenant_domain_name` field to the LogoutConfig is not required since the SDK will automatically parse the subdomain from the URL as long as the `parse_tenant_from_root_domain` SDK config is set.

#### Tenant Custom Domains

If you have a tenant that relies on a tenant custom domain, then you can either explicitly pass it into the LogoutConfig:

```python
response: HttpResponse = wristband_auth.logout(
    request=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_custom_domain="customer01.com"
    )
)
```

...or you can alternatively pass the `tenant_custom_domain` query parameter in your redirect request to Logout Endpoint:

```python
# Logout Request URL -> "https://yourapp.ai/auth/logout?client_id=123&tenant_custom_domain=customer01.com"
response: HttpResponse = wristband_auth.logout(
    request=request,
    config=LogoutConfig(refresh_token="98yht308hf902hc90wh09")
)
```

If your application supports a mixture of tenants that use tenant subdomains and tenant custom domains, then you should consider passing both the tenant domain names and tenant custom domains (either via LogoutConfig or by query parameters) to ensure all use cases are handled by the SDK.

#### Preserving State After Logout

The `state` field in the `LogoutConfig` allows you to preserve application state through the logout flow.

```python
response: HttpResponse = wristband_auth.logout(
    request=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_domain_name="customer01",
        state="user_initiated_logout"
    )
)
```

The state value gets appended as a query parameter to the Wristband Logout Endpoint URL:

```sh
https://customer01.auth.yourapp.io/api/v1/logout?client_id=123&state=user_initiated_logout
```

After logout completes, Wristband will redirect to your configured redirect URL (either your Login Endpoint by default, or a custom logout redirect URL if configured) with the `state` parameter included:

```sh
https://yourapp.io/auth/login?tenant_domain=customer01&state=user_initiated_logout
```

This is useful for tracking logout context, displaying post-logout messages, or handling different logout scenarios. The state value is limited to 512 characters and will be URL-encoded automatically.

#### Custom Logout Redirect URL

Some applications might require the ability to land on a different page besides the Login Page after logging a user out. You can add the `redirect_url` field to the LogoutConfig, and doing so will tell Wristband to redirect to that location after it finishes processing the logout request.

```python
response: HttpResponse = wristband_auth.logout(
    request=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_domain_name="customer01",
        redirect_url="https://custom-logout.com"
    )
)
```

### `refresh_token_if_expired(self, refresh_token: Optional[str], expires_at: Optional[int]) -> Optional[TokenData]:`

```python
token_data: Optional[TokenData] = wristband_auth.refresh_token_if_expired(
    refresh_token="98yht308hf902hc90wh09",
    expires_at=1710707503788
)
```

If your application is using access tokens generated by Wristband either to make API calls to Wristband or to protect other backend APIs, then your applicaiton needs to ensure that access tokens don't expire until the user's session ends.  You can use the refresh token to generate new access tokens.

| Argument | Type | Required | Description |
| -------- | ---- | -------- | ----------- |
| expires_at | int | Yes | Unix timestamp in milliseconds at which the token expires. |
| refresh_token | str | Yes | The refresh token used to send to Wristband when access tokens expire in order to receive new tokens. |

If the `refresh_token_if_expired()` method finds that your token has not expired yet, it will return `None` as the value, which means your auth middleware can simply continue forward as usual.

The `TokenData` is defined as follows:

| TokenData Field | Type | Description |
| --------------- | ---- | ----------- |
| access_token | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| expires_at | int | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `token_expiration_buffer` SDK configuration is accounted for in this value. |
| expires_in | int | The durtaion from the current time until the access token is expired (in seconds). The `token_expiration_buffer` SDK configuration is accounted for in this value. |
| id_token | str | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refresh_token | Optional[str] | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |

<br>

## Wristband Multi-Tenant Django Demo App

You can check out the [Wristband Django demo app](https://github.com/wristband-dev/django-demo-app) to see this SDK in action. Refer to that GitHub repository for more information.

<br/>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.

<br/>
