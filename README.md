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

Enterprise-ready authentication for multi-tenant [Django applications](https://www.djangoproject.com/) using OAuth 2.1 and OpenID Connect standards. Optional support for [Django REST Framework](https://www.django-rest-framework.org/) (DRF) is included.

<br>

## Overview

This SDK provides complete authentication integration with Wristband, including:

- **Login flow** - Redirect to Wristband and handle OAuth callbacks
- **Session management** - Encrypted cookie-based sessions
- **Token handling** - Automatic access token refresh and validation
- **Logout flow** - Token revocation and session cleanup
- **Multi-tenancy** - Support for tenant subdomains and custom domains

Learn more about Wristband's authentication patterns:

- [Backend Server Integration Pattern](https://docs.wristband.dev/docs/backend-server-integration)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

> **💡 Learn by Example**
>
> Want to see the SDK in action? Check out our [Django demo application](#wristband-multi-tenant-django-demo-app). The demo showcases real-world authentication patterns and best practices.

<br>

---

<br>

## Table of Contents

- [Migrating From Older SDK Versions](#migrating-from-older-sdk-versions)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Basic Installation](#basic-installation)
  - [With Django REST Framework Support (Optional)](#with-django-rest-framework-support-optional)
- [Usage](#usage)
  - [1) Configure Wristband Settings](#1-configure-wristband-settings)
  - [2) Initialize the SDK](#2-initialize-the-sdk)
  - [3) Set Up Session Management](#3-set-up-session-management)
  - [4) Add Core Auth Views](#4-add-core-auth-views)
    - [URL Configuration](#url-configuration)
    - [Login View/Endpoint](#login-viewendpoint)
    - [Callback View/Endpoint](#callback-viewendpoint)
    - [Logout View/Endpoint](#logout-viewendpoint)
  - [5) Protect Your Django Views](#5-protect-your-django-views)
    - [Function-Based View Protection](#function-based-view-protection)
    - [Class-Based View Protection](#class-based-view-protection)
    - [Django REST Framework Protection (Optional)](#django-rest-framework-protection-optional)
  - [6) Add API Endpoints (API-First Apps Only)](#6-add-api-endpoints-api-first-apps-only)
    - [Session View/Endpoint](#session-viewendpoint)
    - [Token View/Endpoint (Optional)](#token-viewendpoint-optional)
  - [7) Add Template Context Processor](#7-add-template-context-processor)
  - [8) Pass Your Access Token to APIs](#8-pass-your-access-token-to-apis)
  - [9) Configure CSRF Protection](#9-configure-csrf-protection)
- [Integration with Django's Built-in Auth System](#integration-with-djangos-built-in-auth-system)
  - [Enable Django Authentication Components](#enable-django-authentication-components)
  - [Sync Wristband Users to Django User Model](#sync-wristband-users-to-django-user-model)
  - [How the Authentication Backend Works](#how-the-authentication-backend-works)
  - [Using Django's Built-in View Protection (Optional)](#using-djangos-built-in-view-protection-optional)
  - [Log Users Out of Django](#log-users-out-of-django)
  - [Access Django Admin Through Wristband Authentication](#access-django-admin-through-wristband-authentication)
- [Auth Configuration Options](#auth-configuration-options)
  - [WristbandAuth()](#wristbandauth)
  - [WristbandAuth.discover()](#wristbandauthdiscover)
- [Auth API](#auth-api)
  - [login()](#login)
  - [callback()](#callback)
  - [create_callback_response()](#create_callback_response)
  - [logout()](#logout)
  - [refresh_token_if_expired()](#refresh_token_if_expired)
- [Session Management](#session-management)
  - [Session Fields](#session-fields)
  - [Type Hints for Session Data](#type-hints-for-session-data)
  - [Session Access Patterns](#session-access-patterns)
  - [Session Helper Functions](#session-helper-functions)
- [Authentication Strategies](#authentication-strategies)
  - [Available Authentication Strategies](#available-authentication-strategies)
  - [Unauthenticated Request Behavior](#unauthenticated-request-behavior)
  - [create_auth_decorator()](#create_auth_decorator)
  - [create_auth_mixin()](#create_auth_mixin)
  - [create_drf_session_auth()](#create_drf_session_auth)
  - [create_drf_jwt_auth()](#create_drf_jwt_auth)
  - [Multi-Strategy Authentication with DRF](#multi-strategy-authentication-with-drf)
  - [JWT Authentication Details](#jwt-authentication-details)
  - [Choosing the Right Strategy](#choosing-the-right-strategy)
- [Debug Logging](#debug-logging)
- [Related Wristband SDKs](#related-wristband-sdks)
- [Wristband Multi-Tenant Django Demo App](#wristband-multi-tenant-django-demo-app)
- [Questions](#questions)

<br/>

---

<br>

## Migrating From Older SDK Versions

On an older version of our SDK? Check out our migration guide:

- [Instructions for migrating to Version 1.x (latest)](migration/v1/README.md)

<br>

## Prerequisites

> **⚡ Try Our Django Quickstart!**
>
> For the fastest way to get started with Django authentication, follow our [Quick Start Guide](https://docs.wristband.dev/docs/auth-quick-start). It walks you through setting up a working Django app with Wristband authentication in minutes. Refer back to this README for comprehensive documentation and advanced usage patterns.

Before installing, ensure you have:

- [Python](https://www.python.org) ≥ 3.10
- [Django](https://www.djangoproject.com) ≥ 4.2
- Your preferred package manager (pip, poetry, uv, etc.)

If you are using Django REST Framework, ensure you also have:

- [Django REST Framework](https://www.django-rest-framework.org/) ≥ 3.15.0

<br/>

## Installation

Install the `wristband-django-auth` package from PyPI.

### Basic Installation

```bash
# With pip
pip install wristband-django-auth

# Or if using poetry
poetry add wristband-django-auth

# Or if using pipenv
pipenv install wristband-django-auth
```

### With Django REST Framework Support (Optional)

If you're using [Django REST Framework](https://www.django-rest-framework.org/) (DRF) and want to use DRF authentication classes:

```bash
# With pip
pip install wristband-django-auth[drf]

# If using poetry, either:
poetry add wristband-django-auth[drf]
# or:
poetry add wristband-django-auth --extras drf

# If using pipenv:
pipenv install wristband-django-auth[drf]
```

> **Note:** The basic installation includes decorators that work with traditional Django views and DRF function-based views. The `[drf]` extra adds authentication classes for DRF class-based views (APIView, ViewSets, etc.).

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

# Initialize Wristband auth instance
wristband_auth = WristbandAuth(AuthConfig(**settings.WRISTBAND_AUTH))
```

<br>

### 3) Set Up Session Management

This Wristband authentication SDK is unopinionated about how you store and manage your application session data after the user has authenticated. The SDK includes a custom encrypted cookie-based session engine built to work with Django's built-in session framework.

The encrypted cookie-based session engine provides:
- **No backend infrastructure required** - Session data is encrypted and stored in cookies
- **Stateless sessions** - No database or cache lookups needed
- **Security** - Data is encrypted using AES-256-GCM before storage
- **Simplicity** - Works out of the box with no additional setup

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

Configure Django to use Wristband's encrypted cookie session engine and set up secure session cookies:

> [!NOTE]
> If you use Safari browser when developing and testing on `localhost`, you may need to set `SESSION_COOKIE_SECURE = False`. Remember to set the value back to `True` for Production!

```python
# your_project/settings.py (continued)

# ...

# Wristband encrypted cookie-based sessions (recommended)
SESSION_ENGINE = 'wristband.django_auth.sessions.backends.encrypted_cookies'
SESSION_COOKIE_AGE = 3600  # 1 hour of inactivity, adjust as needed
SESSION_COOKIE_SECURE = True  # IMPORTANT: Set to True in Production!!
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookie
SESSION_COOKIE_SAMESITE = 'Lax'  # Reasonably secure default option

# Session encryption secret (32+ characters recommended)
# IMPORTANT: In production, use a strong, randomly-generated secret!
WRISTBAND_SESSION_SECRET = 'your-secret-key-at-least-32-characters-long'
```

> [!TIP]
> **Alternative Session Backends**
>
> Django's session framework supports multiple storage options if encrypted cookies don't fit your needs:
>
> - **Database sessions** (default): `SESSION_ENGINE = 'django.contrib.sessions.backends.db'`
> - **Cache sessions**: `SESSION_ENGINE = 'django.contrib.sessions.backends.cache'`  
> - **File-based sessions**: `SESSION_ENGINE = 'django.contrib.sessions.backends.file'`
> - **Cached database sessions**: `SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'`
>
> For server-side session storage requirements, consider these alternatives or third-party packages like [django-redis](https://github.com/jazzband/django-redis).

<br>

### 4) Add Auth Views/Endpoints

There are **three core authentication views/endpoints** your Django application should expose to facilitate authentication workflows in Wristband. You'll need to add these to your Django URL configuration and create corresponding views:

- Login View/Endpoint
- Callback View/Endpoint  
- Logout View/Endpoint

> **💡 API-First Applications**
>
> If you're building an SPA, mobile app, or using Wristband frontend SDKs, you'll also need additional API endpoints covered in [Step 6](#6-add-api-endpoints-api-first-apps-only).

> [!NOTE]
> **Traditional Django apps** (server-rendered templates) only need the three core views. **API-first applications** (SPAs, mobile apps, or those using Wristband frontend SDKs) will also need the Session Endpoint. The Token Endpoint is only needed if your frontend makes direct API calls requiring the user's access token.

#### URL Configuration

Include your app's URLs in the main project URLs file, and add your authentication URLs to your Django app:

```python
# your_app/urls.py

from django.urls import path
from . import auth_views

app_name = 'your_app'

# Route paths can be whatever you prefer
urlpatterns = [
    # Your other app URLs...
    
    # Wristband Auth Endpoints (URL path values can be anything you want)
    path('auth/login/', auth_views.login_endpoint, name='login'),
    path('auth/callback/', auth_views.callback_endpoint, name='callback'),
    path('auth/logout/', auth_views.logout_endpoint, name='logout'),
]
```

**For API-first applications (SPAs, mobile apps, or using Wristband frontend SDKs)**, also add:

```python
# your_app/urls.py (continued)

# Route paths can be whatever you prefer
urlpatterns = [
    # ... core auth URLs above ...
    
    # Session Endpoint - required for Wristband frontend SDKs
    path('auth/session/', auth_views.session_endpoint, name='session'),
    
    # Token Endpoint - optional, only if frontend needs access tokens
    # path('auth/token/', auth_views.token_endpoint, name='token'),
]
```

<br/>

#### Login View/Endpoint

The goal of the Login View/Endpoint is to initiate an auth request by redirecting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. Your application should redirect to this endpoint when users need to log in to your application.

```python
# your_app/auth_views.py

from django.http import HttpRequest, HttpResponse
from django.views.decorators.http import require_GET
from wristband.django_auth import LogoutConfig, RedirectRequiredCallbackResult, session_from_callback

# Import your configured Wristband auth instance
from your_app.wristband import wristband_auth

@require_GET
def login_endpoint(request: HttpRequest) -> HttpResponse:
    """Initiate authentication by redirecting to Wristband"""
    return wristband_auth.login(request)

# ...
```

<br>

#### Callback View/Endpoint

The goal of the Callback View/Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

```python
# your_app/auth_views.py (continued)

# ...

@require_GET
def callback_endpoint(request: HttpRequest) -> HttpResponse:
    """Process OAuth callback and create session for authenticated user"""
    callback_result = wristband_auth.callback(request)

    # For certain edge cases, the SDK will require you to redirect back to login
    if isinstance(callback_result, RedirectRequiredCallbackResult):
        return wristband_auth.create_callback_response(request, callback_result.redirect_url)

    # The SDK provides a convenience method for storing callback data in your app's session
    session_from_callback(request, callback_result.callback_data)
        
    # Redirect to your app
    post_callback_url = callback_result.callback_data.return_url or '/'
    return wristband_auth.create_callback_response(request, post_callback_url)

# ...
```

<br/>

#### Logout View/Endpoint

The goal of the Logout View/Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).

```python
# your_app/auth_views.py (continued)

# ...

@require_GET
def logout_endpoint(request: HttpRequest) -> HttpResponse:
    """Log out user and redirect to Wristband logout endpoint"""
    # Get all the necessary session data needed to perform the logout operation.
    logout_config = LogoutConfig(
        refresh_token=request.session.get("refresh_token"),
        tenant_name=request.session.get("tenant_name"),
        tenant_custom_domain=request.session.get("tenant_custom_domain"),
    )

    # Clear the user's session in Django.
    request.session.flush()

    # Wristband SDK revokes the refresh token (if provided) and creates the proper redirect response.
    # Wristband Logout requires a tenant level domain. Custom domains take precedence (if present).
    return wristband_auth.logout(request, logout_config)
```

<br>

### 5) Protect Your Django Views

Once your core auth views are set up, you can protect routes that require authentication. This section covers **session-based authentication protection**, which is the most common approach for Django applications.

The SDK provides factory methods to create authentication protection that automatically:

- ✅ **Validates authentication** - Checks session validity (`request.session.is_authenticated`)
- ✅ **Refreshes expired tokens** - When both `request.session.refresh_token` and `request.session.expires_at` exist (with up to 3 retry attempts)
- ✅ **Extends session expiration** - Rolling session window on each authenticated request (regardless of `SESSION_SAVE_EVERY_REQUEST` setting)
- ✅ **Handles unauthenticated requests** - Redirects to login or returns 401 based on configuration

> **💡 Multiple Auth Strategies Available**
>
> This guide covers session-based authentication. For JWT bearer tokens or multi-strategy authentication (combining sessions + JWTs), see the [Authentication Strategies](#authentication-strategies) section.

#### Function-Based View Protection

For function-based views, you first need to create an authentication decorator instance in your Wristband file using the `create_auth_decorator()` factory method:

```python
# your_app/wristband.py

from django.conf import settings
from wristband.django_auth import (
  AuthConfig,
  AuthStrategy,
  UnauthenticatedBehavior,
  WristbandAuth,
)

wristband_auth = WristbandAuth(AuthConfig(**settings.WRISTBAND_AUTH))

# These decorator confifgs will enforce an authenticated session. If no session,
# then it will redirect to the loginUrl configured in your WristbandAuth instance.
require_session = wristband_auth.create_auth_decorator(
    strategies=[AuthStrategy.SESSION],
    on_unauthenticated=UnauthenticatedBehavior.REDIRECT,
)

__all__ = ['wristband_auth', 'require_session']
```

Then, apply the decorator to your views:

```python
# your_app/views.py

from django.shortcuts import render
from your_app.wristband import require_session

@require_session
def dashboard(request):
    return render(request, 'dashboard.html')
```

#### Class-Based View Protection

If using class-based views, you will need to create an authentication mixin instance in your Wristband file using the `create_auth_mixin()` factory method:

```python
# your_app/wristband.py

from django.conf import settings
from wristband.django_auth import (
  AuthConfig,
  AuthStrategy,
  UnauthenticatedBehavior,
  WristbandAuth,
)

wristband_auth = WristbandAuth(AuthConfig(**settings.WRISTBAND_AUTH))

# These mixin configs will enforce an authenticated session. If no session,
# then it will redirect to the loginUrl configured in your WristbandAuth instance.
SessionRequiredMixin = wristband_auth.create_auth_mixin(
    strategies=[AuthStrategy.SESSION],
    on_unauthenticated=UnauthenticatedBehavior.REDIRECT,
)

__all__ = ['wristband_auth', 'SessionRequiredMixin']
```

Apply the mixin to your views (must be leftmost in inheritance):

```python
# your_app/views.py

from django.views import View
from your_app.wristband import SessionRequiredMixin

class ProfileView(SessionRequiredMixin, View):
    def get(self, request):
        return render(request, 'profile.html')
```

#### Django REST Framework Protection (Optional)

If you're using Django REST Framework, you can create a DRF authentication class in your Wristband file instead by using the `create_drf_session_auth()` factory function:

```python
# your_app/wristband.py

from django.conf import settings
from wristband.django_auth import (
  AuthConfig,
  AuthStrategy,
  UnauthenticatedBehavior,
  WristbandAuth,
)

wristband_auth = WristbandAuth(AuthConfig(**settings.WRISTBAND_AUTH))

DrfSessionAuth = wristband_auth.create_drf_session_auth()

__all__ = ['wristband_auth', 'DrfSessionAuth']
```

Then, use the authentication class with DRF's `authentication_classes` and `IsAuthenticated` permission:

```python
# your_app/views.py

from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from your_app.wristband import DrfSessionAuth

class ProtectedAPIView(APIView):
    authentication_classes = [DrfSessionAuth]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({"message": "Hello!"})
```

> **Note:** DRF authentication classes require `djangorestframework>=3.15.0`. Install with `pip install wristband-django-auth[drf]`.

<br>

### 6) Add API Endpoints (API-First Apps Only)

API-first applications (SPAs, mobile apps, or apps using Wristband frontend SDKs) need additional endpoints to manage client-side authentication state.

#### Session View/Endpoint

> [!NOTE]
> This endpoint is required for Wristband frontend SDKs to function. For more details, see the [Wristband Session Management documentation](https://docs.wristband.dev/docs/session-management-backend-server).

Wristband frontend SDKs require a Session Endpoint in your backend to verify authentication status and retrieve session metadata. Use the `get_session_response()` helper to return session data in the format expected by Wristband's frontend SDKs. The response will always include `user_id` and `tenant_id`. You can include additional data for your frontend by customizing the `metadata` parameter (optional), which requires JSON-serializable values. **The response must not be cached**.

> **⚠️ Important:**
> Make sure to protect this endpoint with authentication! Use either the `require_session` decorator or `SessionRequiredMixin` class.

**Function-Based View:**
```python
# your_app/auth_views.py (continued)

from django.http import JsonResponse
from django.views.decorators.http import require_GET
from wristband.django_auth import get_session_response
from your_app.wristband import require_session

# ...

@require_session
@require_GET
def session_endpoint(request: HttpRequest) -> JsonResponse:
    """Session endpoint for Wristband frontend SDKs"""
    session_data = get_session_response(request, metadata={'foo': 'bar'})
    response = JsonResponse(session_data)
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'
    return response
```

**Class-Based View:**
```python
# your_app/auth_views.py (continued)

from django.http import JsonResponse
from django.views import View
from wristband.django_auth import get_session_response
from your_app.wristband import SessionRequiredMixin

# ...

class SessionEndpoint(SessionRequiredMixin, View):
    """Session endpoint for Wristband frontend SDKs"""
    
    def get(self, request: HttpRequest) -> JsonResponse:
        session_data = get_session_response(request, metadata={'foo': 'bar'})
        response = JsonResponse(session_data)
        response['Cache-Control'] = 'no-store'
        response['Pragma'] = 'no-cache'
        return response
```

The Session Endpoint returns JSON to your frontend:

```json
{
  "tenantId": "tenant_abc123",
  "userId": "user_xyz789",
  "metadata": {
    "foo": "bar"
  }
}
```

<br>

#### Token View/Endpoint (Optional)

> [!NOTE]
> This endpoint is required when your frontend needs to make authenticated API requests directly to Wristband or other protected services. For more details, see the [Wristband documentation on using access tokens from the frontend](https://docs.wristband.dev/docs/authenticating-api-requests-with-bearer-tokens#using-access-tokens-from-the-frontend).
>
> If your application doesn't need frontend access to tokens (e.g., all API calls go through your backend), you can skip this endpoint.

Some applications require the frontend to make direct API calls to Wristband or other protected services using the user's access token. The Token Endpoint provides a secure way for your frontend to retrieve the current access token and its expiration time without exposing it in the session cookie or browser storage.

Use the `get_token_response()` helper to return token data in the format expected by Wristband's frontend SDKs. **The response must not be cached**.

Create a protected token endpoint that returns the access token and expiration data. **The response must not be cached**.

> **⚠️ Important:**
> Make sure to protect this endpoint with authentication! Use the `require_session` decorator or `SessionRequiredMixin` class.

**Function-Based View:**
```python
# your_app/auth_views.py (continued)

from django.http import JsonResponse
from django.views.decorators.http import require_GET
from wristband.django_auth import get_token_response
from your_app.wristband import require_session

# ...

@require_session
@require_GET
def token_view(request: HttpRequest) -> JsonResponse:
    """Token endpoint for frontend access token retrieval"""
    token_data = get_token_response(request)
    response = JsonResponse(token_data)
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'
    return response
```

**Class-Based View:**
```python
# your_app/auth_views.py (continued)

from django.http import JsonResponse
from django.views import View
from wristband.django_auth import get_token_response
from your_app.wristband import SessionRequiredMixin

# ...

class TokenView(SessionRequiredMixin, View):
    """Token endpoint for frontend access token retrieval"""
    
    def get(self, request: HttpRequest) -> JsonResponse:
        token_data = get_token_response(request)
        response = JsonResponse(token_data)
        response['Cache-Control'] = 'no-store'
        response['Pragma'] = 'no-cache'
        return response
```

The Token Endpoint returns JSON to your frontend:
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresAt": 1735689600000
}
```

Your frontend can then use the `accessToken` in the Authorization header when making API requests:
```javascript
const tokenResponse = await fetch('/api/auth/token');
const { accessToken } = await tokenResponse.json();

// Use token to call Wristband API
const userResponse = await fetch('https://<your-wristband-app-vanity_domain>/api/v1/users/123', {
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});
```

<br>

### 7) Add Template Context Processor

Django context processors allow you to make data available across all templates without manually passing it from each view. This is perfect for authenticated session data that you want to access in your templates for things like showing user information, login/logout links, and conditional content.

#### Create the Context Processor

Create a context processor to make Wristband authentication data available in all your templates:

```python
# your_app/context_processors.py

from typing import Any, Dict
from django.http import HttpRequest

def wristband_auth(request: HttpRequest) -> Dict[str, Any]:
    """
    Add Wristband auth context to templates.
    
    Exposes session fields directly to templates for easy access.
    
    Returns:
        Context dictionary with auth data directly accessible in templates.
    """
    if not hasattr(request, 'session'):
        return {}
    
    # List of session fields to expose in templates
    session_fields = [
        'is_authenticated',
        'user_id',
        'tenant_id',
        'tenant_name',
        'tenant_custom_domain',
        'identity_provider_name',
        'email',
        'given_name',
        'family_name',
        # Add other fields as needed
    ]
    
    return {
        field: request.session.get(field) 
        for field in session_fields 
        if request.session.get(field) is not None
    }
```

> **⚠️ Security Note:**
> Never expose `refresh_token` or `access_token` in template context. These tokens should never be accessible in HTML templates or client-side JavaScript. If your frontend needs the access token for API calls, use the [Token View/Endpoint](#token-viewendpoint-optional) instead, which provides secure, on-demand access.

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
{% if is_authenticated %}
    <div class="user-info">
        <p>Welcome, {{ email }}!</p>
        <p>Tenant: {{ tenant_name }}</p>
        <a href="{% url 'your_app:logout' %}">Logout</a>
    </div>
{% else %}
    <a href="{% url 'your_app:login' %}">Login with Wristband</a>
{% endif %}

<!-- Access specific user data -->
{% if given_name %}
    <span>{{ given_name }} {{ family_name }}</span>
{% endif %}
```

<br/>

### 8) Pass Your Access Token to APIs

> [!NOTE]
> This section is only applicable if you need to call Wristband APIs or protect your own backend services with Wristband tokens.

If you intend to utilize Wristband APIs within your application or secure any backend APIs or downstream services using the access token provided by Wristband, you must include this token in the `Authorization` HTTP request header.

```bash
Authorization: Bearer <access_token_value>
```

The access token is available in different ways depending on your authentication strategy.

#### Session-Based Authentication

When using session-based authentication, the access token is stored in the session and accessible via `request.session`:

**Function-Based View:**
```python
# your_app/views.py

import requests
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from your_app.wristband import require_session

@require_session
@require_POST
def create_order(request):
    try:
        order_data = json.loads(request.body)
        db.save(order_data)
        
        requests.post(
            "https://api.example.com/email-receipt",
            json=order_data,
            headers={
                # Pass your access token to downstream API
                "Authorization": f"Bearer {request.session['access_token']}"
            }
        )
        
        return JsonResponse({"status": "created"})
    except Exception:
        return JsonResponse({"error": "Failed"}, status=500)
```

**Class-Based View:**
```python
# your_app/views.py
import json
import requests
from django.http import JsonResponse
from django.views import View
from your_app.wristband import SessionRequiredMixin

class CreateOrderView(SessionRequiredMixin, View):
    def post(self, request):
        try:
            order_data = json.loads(request.body)
            db.save(order_data)
            
            # Pass your access token to downstream API
            requests.post(
                "https://api.example.com/email-receipt",
                json=order_data,
                headers={
                    "Authorization": f"Bearer {request.session['access_token']}"
                }
            )
            
            return JsonResponse({"status": "created"})
        except Exception:
            return JsonResponse({"error": "Failed"}, status=500)
```

#### JWT Bearer Token Authentication

When using JWT authentication, both the raw JWT string and the decoded JWT payload are available via `request.auth`.

> **💡 JWT Authentication**
>
> For more on JWT authentication, see the [Authentication Strategies](#authentication-strategies) section.

**Function-Based View:**
```python
# your_app/views.py

import requests
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from your_app.wristband import require_jwt

@require_jwt
@require_POST
def create_order(request):
    try:
        order_data = json.loads(request.body)
        db.save(order_data)
        
        requests.post(
            "https://api.example.com/email-receipt",
            json=order_data,
            headers={
                # Pass your access token to downstream API
                "Authorization": f"Bearer {request.auth.jwt}"
            }
        )
        
        return JsonResponse({"status": "created"})
    except Exception:
        return JsonResponse({"error": "Failed"}, status=500)
```

**Class-Based View:**
```python
# your_app/views.py

import json
import requests
from django.http import JsonResponse
from django.views import View
from your_app.wristband import JwtRequiredMixin

class CreateOrderView(JwtRequiredMixin, View):
    def post(self, request):
        try:
            order_data = json.loads(request.body)
            db.save(order_data)
            
            requests.post(
                "https://api.example.com/email-receipt",
                json=order_data,
                headers={
                    # Pass your access token to downstream API
                    "Authorization": f"Bearer {request.auth.jwt}"
                }
            )
            
            return JsonResponse({"status": "created"})
        except Exception:
            return JsonResponse({"error": "Failed"}, status=500)
```

#### Using Access Tokens from the Frontend

For scenarios where your frontend needs to make direct API calls with the user's access token, use the [Token Endpoint](#token-viewendpoint-optional) to securely retrieve the current access token.

<br>

### 9) Configure CSRF Protection

Cross Site Request Forgery (CSRF) is a security vulnerability where attackers trick authenticated users into unknowingly submitting malicious requests to your application. Django's CSRF protection follows the Synchronizer Token Pattern, which generates a unique tokens for a session, stores them in the session, and validates submitted requests by comparing the submitted token with the session-stored token. This provides robust protection against CSRF attacks.

Refer to the [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) for more information about this topic.

#### Register CSRF Middleware

Enable CsrfViewMiddleware in your Django settings, and <ins>ensure it comes after SessionMiddleware but before AuthMiddleware</ins>. This ensures CSRF tokens are properly validated and synchronized with user sessions during the authentication process.

```python
# your_project/settings.py

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',  # <-- CSRF middleware
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

    ### ...your other middlewares...
]
```

Your CSRF configuration depends on whether your application uses traditional form submissions or AJAX/SPA interactions.

> [!NOTE]
> If you use Safari browser When developing and testing on `localhost`, you may need to set `CSRF_COOKIE_SECURE = False`. Remember to set the value back to `True` for Production!

**Template-Based Applications (Form Submissions):**
```python
# your_project/settings.py

# Store CSRF token in session (recommended for traditional form posts)
CSRF_USE_SESSIONS = True
CSRF_COOKIE_AGE = 3600  # 1 hour (match to SESSION_COOKIE_AGE)
CSRF_COOKIE_SECURE = True  # IMPORTANT: Set to True in Production!
```

**AJAX/SPA Applications**

If your application makes AJAX requests - whether from Django templates or a separate SPA frontend - you need to allow JavaScript to read the CSRF token from a cookie.

```python
# your_project/settings.py

# Use cookie-based CSRF tokens for AJAX/SPA apps
CSRF_USE_SESSIONS = False  # Token stored in cookie instead of session
CSRF_COOKIE_AGE = 3600  # 1 hour (match to SESSION_COOKIE_AGE)
CSRF_COOKIE_SECURE = True  # IMPORTANT: Set to True in Production!
```

This enables the **double-submit cookie pattern**: JavaScript reads the token from the cookie and sends it in the `X-CSRFToken` header. Django validates that the header matches the cookie value.

#### Generate CSRF Token in Callback Endpoint

Call Django's `get_token()` function in your Callback Endpoint to generate a CSRF token for your session and set the CSRF cookie. This ensures authenticated users receive a valid CSRF token immediately after login, enabling secure form submissions and API calls throughout their session.

```python
# your_app/auth_views.py

from django.middleware.csrf import get_token

# ...

@require_GET
def callback_endpoint(request: HttpRequest) -> HttpResponse:
    """Process OAuth callback and create session for authenticated user"""
    callback_result = wristband_auth.callback(request)

    if isinstance(callback_result, RedirectRequiredCallbackResult):
        return wristband_auth.create_callback_response(request, callback_result.redirect_url)

    session_from_callback(request, callback_result.callback_data)
    
    # Generate CSRF token and cookie
    get_token(request)  # <-- Add this!
    
    post_callback_url = callback_result.callback_data.return_url or '/'
    return wristband_auth.create_callback_response(request, post_callback_url)
```

#### Automatic CSRF Token Refresh

When you use the session-based authentication decorator (`require_session`) or mixin (`SessionRequiredMixin`) created in [Step 5](#5-protect-your-django-views), CSRF tokens are automatically refreshed on each authenticated request. This maintains rolling expiration for both session and CSRF cookies, ensuring they expire together.

No additional code is needed, as the decorator and mixin handle this automatically when Django's `CsrfViewMiddleware` is enabled.

#### Clear CSRF Cookie on Logout

Remove the CSRF token cookie when users log out. This prevents stale CSRF tokens from persisting after logout.

```python
# your_app/auth_views.py

@require_GET
def logout_endpoint(request: HttpRequest) -> HttpResponse:
    """Log out user and redirect to Wristband logout endpoint"""
    logout_config = LogoutConfig(
        refresh_token=request.session.get("refresh_token"),
        tenant_name=request.session.get("tenant_name"),
        tenant_custom_domain=request.session.get("tenant_custom_domain"),
    )

    request.session.flush()
    response = wristband_auth.logout(request, logout_config)
    
    # Clear CSRF token cookie
    response.delete_cookie('csrftoken')  # <-- Add this!
    
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
        'X-CSRFToken': getCookie('csrftoken'), // <-- Add CSRF token header
    },
    mode: 'same-origin',
    body: JSON.stringify({ data: 'your data' })
});
```

This setup ensures your Wristband-authenticated sessions are protected against CSRF attacks while integrating seamlessly with Django's security framework.

> [!NOTE]
> For complete CSRF configuration options, advanced AJAX patterns, edge cases, and troubleshooting, see Django's [CSRF documentation](https://docs.djangoproject.com/en/6.0/ref/csrf/).

<br/>

## Integration with Django's Built-in Auth System

> [!NOTE]
> **OPTIONAL:** This section is optional. The Wristband SDK works perfectly on its own without Django's built-in authentication system. Only implement this approach if your application needs Django User objects, groups, permissions, or admin interface integration.

Many Django applications benefit from combining Wristband's multi-tenant authentication with Django's built-in user management system. This lets you leverage Wristband for secure, scalable authentication while using Django's familiar User model, groups, permissions, and admin interface for application-specific user management.

This integration pattern is particularly valuable when you need to:

- Map Wristband roles to Django groups for permission-based access control
- Store additional user data beyond what Wristband provides
- Use Django's admin interface for user management
- Integrate with existing Django packages that expect Django User objects
- Maintain user data locally for performance or offline scenarios

This approach synchronizes Wristband user data with Django's User model during your Callback Endpoint, creating a seamless bridge between external identity management and internal application logic.

To do this, you'll need to handle the following steps.

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

# Configure Wristband as the authentication backend
AUTHENTICATION_BACKENDS = [
    'wristband.django_auth.WristbandAuthBackend',  # <-- ADD: Wristband authentication backend
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',

    # ADD: Populates request.user with Django User objects
    "django.contrib.auth.middleware.AuthenticationMiddleware",

    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

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

# Database configuration required for storing Django User objects
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}
```

You'll need to **run database migrations** to create the necessary database tables for Django's User model, groups, and permissions system. For example:

```sh
python manage.py migrate
```

<br>

### Sync Wristband Users to Django User Model

Modify your Callback Endpoint to authenticate and sync Django User objects with Wristband user data. The `WristbandAuthBackend` automatically creates or updates Django Users based on Wristband authentication data.

```python
# your_app/auth_views.py

from django.contrib.auth import authenticate, login
from django.http import HttpRequest, HttpResponse
from django.middleware.csrf import get_token
from django.views.decorators.http import require_GET
from wristband.django_auth import RedirectRequiredCallbackResult, session_from_callback
from .wristband import wristband_auth

# ...

@require_GET
def callback_endpoint(request: HttpRequest) -> HttpResponse:
    """Process OAuth callback and sync with Django User"""
    callback_result = wristband_auth.callback(request)

    if isinstance(callback_result, RedirectRequiredCallbackResult):
        return wristband_auth.create_callback_response(request, callback_result.redirect_url)

    session_from_callback(request, callback_result.callback_data)

    # ADD: Authenticate and sync Wristband user with Django User model
    user = authenticate(request=request, callback_data=callback_result.callback_data)
    login(request, user)

    get_token(request)
    post_callback_url = callback_result.callback_data.return_url or "/"
    return wristband_auth.create_callback_response(request, post_callback_url)
```

<br>

### How the Authentication Backend Works

The `WristbandAuthBackend` automatically synchronizes Wristband users with Django's User model during the login flow. When a user successfully authenticates through Wristband, the backend:

1. **Creates or retrieves** a Django User based on the Wristband user ID
2. **Populates User fields** (email, name, etc.) from Wristband data, if available
3. **Returns the User** for Django's login() to establish a session

The backend uses an **adapter pattern** to control how Wristband data maps to Django User fields. This separation allows you to customize user synchronization logic without modifying the authentication flow.

#### Default Adapter

By default, the backend uses `DefaultWristbandAuthBackendAdapter`, which performs basic field mapping based on the `callback_data` that Wristband returns to your Callback Endpoint:

```python
# Default behavior (no configuration needed)
user.username = callback_data.user_info.user_id       # Immutable Wristband user ID
user.email = callback_data.user_info.email            # Requires 'email' scope
user.first_name = callback_data.user_info.given_name  # Requires 'profile' scope
user.last_name = callback_data.user_info.family_name  # Requires 'profile' scope
```

#### Custom Adapter for Role Mapping

To map Wristband roles to Django groups and permissions, create a custom adapter that subclasses `DefaultWristbandAuthBackendAdapter`. For example:

```python
# your_app/adapters.py

from django.contrib.auth.models import Group
from wristband.django_auth import DefaultWristbandAuthBackendAdapter


class MyWristbandAdapter(DefaultWristbandAuthBackendAdapter):
    """Custom adapter with role mapping logic."""

    def populate_user(self, user, callback_data, **kwargs):
        # Populate basic fields from parent
        user = super().populate_user(user, callback_data, **kwargs)

        # Add custom role mapping (requires 'roles' scope)
        user_info = callback_data.user_info
        roles = user_info.roles

        if not roles:
            # No roles assigned - default to viewer permissions
            user.groups.clear()
            user.is_staff = False
            user.is_superuser = False
            viewer_group, _ = Group.objects.get_or_create(name="Viewers")
            user.groups.add(viewer_group)
        else:
            # Check for owner role
            role_names = [role.name for role in roles]
            has_owner_role = any(
                role_name.startswith("app:") and role_name.endswith(":owner")
                for role_name in role_names
            )

            if has_owner_role:
                user.groups.clear()
                user.is_staff = True
                user.is_superuser = True
                owner_group, _ = Group.objects.get_or_create(name="Owners")
                user.groups.add(owner_group)
            else:
                user.groups.clear()
                user.is_staff = False
                user.is_superuser = False
                viewer_group, _ = Group.objects.get_or_create(name="Viewers")
                user.groups.add(viewer_group)

        return user
```

> **Note:** Role mapping requires the `roles` scope. Make sure your Wristband configuration includes it:
>
> ```python
> WRISTBAND_AUTH = {
>    # ... other settings
>    "scopes": ["openid", "offline_access", "email", "profile", "roles"],
> }
> ```

To utilize your custom adapter, configure it in your Django settings:

```python
# your_project/settings.py

# Custom adapter for role mapping (optional)
WRISTBAND_AUTH_BACKEND_ADAPTER = 'your_app.adapters.MyWristbandAdapter'
```

#### Passing Custom Data to Adapters

You can pass additional data to your adapter from the callback view via `**kwargs`:

```python
# In your callback view:
user = authenticate(
    request=request,
    callback_data=callback_result.callback_data,
    subscription_tier='premium',
    external_flags={'beta_access': True}
)

# Your adapter receives it via **kwargs
class MyWristbandAdapter(DefaultWristbandAuthBackendAdapter):
    def populate_user(self, user, callback_data, **kwargs):
        user = super().populate_user(user, callback_data, **kwargs)
        
        # Access custom kwargs
        tier = kwargs.get('subscription_tier')
        if tier == 'premium':
            user.is_staff = True
        
        flags = kwargs.get('external_flags', {})
        if flags.get('beta_access'):
            # Grant beta permissions
            beta_group, _ = Group.objects.get_or_create(name='Beta Users')
            user.groups.add(beta_group)
        
        return user
```

<br>

### Using Django's Built-in View Protection (Optional)

Once Django User integration is enabled, you can optionally use Django's built-in `@login_required` decorator and `LoginRequiredMixin` for simple authentication checks in template-based views. However, **these should only be used for basic session validation** as they don't handle token refresh or validation.

> **⚠️ Recommendation**
>
> For most use cases, **prefer Wristband's authentication decorators and mixins** from [Step 5](#5-protect-your-django-views). They provide:
> - Automatic token refresh
> - Session expiration extension
> - Proper redirect handling
>
> Only use Django's built-in protection for simple template views where token management isn't required.

**Configure Login URL:**

Django's authentication decorators and mixins redirect unauthenticated users to `settings.LOGIN_URL`. Point this to your Login Endpoint:

```python
# your_project/settings.py

LOGIN_URL = '/auth/login/'  # Your Wristband login endpoint
```

**Function-Based Views:**
```python
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

@login_required
def simple_profile(request):
    """Basic profile view - no API calls, just templates"""
    return render(request, 'profile.html')
```

**Class-Based Views:**
```python
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

class SimpleProfileView(LoginRequiredMixin, TemplateView):
    """Basic profile view - no API calls, just templates"""
    template_name = 'profile.html'
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
def logout_endpoint(request: HttpRequest) -> HttpResponse:
    """Log out user and redirect to Wristband logout endpoint"""
    logout_config = LogoutConfig(
        refresh_token=request.session.get("refresh_token"),
        tenant_name=request.session.get("tenant_name"),
        tenant_custom_domain=request.session.get("tenant_custom_domain"),
    )
    request.session.flush()

    # Log user out of Django's auth system
    logout(request)  # <-- ADD THIS

    response = wristband_auth.logout(request, logout_config)
    response.delete_cookie('csrftoken')
    return response
```

<br>

### Access Django Admin Through Wristband Authentication

Instead of maintaining separate admin credentials, configure Django's admin interface to use Wristband authentication by redirecting admin login/logout to your Wristband endpoints.

Add these redirects to your URL configuration:

```python
# your_project/urls.py

from django.contrib import admin
from django.shortcuts import redirect
from django.urls import path, include

def admin_login_redirect(request):
    """Redirect admin login to Wristband"""
    return_url = request.build_absolute_uri('/admin/')
    return redirect(f'/auth/login') # <-- Your Wristband Login Endpoint

def admin_logout_redirect(request):
    """Redirect admin logout to Wristband"""
    return_url = request.build_absolute_uri('/admin/')
    return redirect('/auth/logout') # <-- Your Wristband Logout Endpoint

urlpatterns = [
    path('admin/login/', admin_login_redirect),   # <-- ADD: Redirect admin login
    path('admin/logout/', admin_logout_redirect), # <-- ADD: Redirect admin logout
    path('admin/', admin.site.urls),
    path('', include('your_app.urls')),
]
```

<br>

## Auth Configuration Options

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
| login_url | Optional[str] | Only when `auto_configure_enabled` is set to `False` | Yes | The URL of your application's login endpoint.  This is the endpoint within your application that redirects to Wristband to initialize the login flow. If you intend to use tenant subdomains in your Login Endpoint URL, then this value must contain the `{tenant_name}` token. For example: `https://{tenant_name}.yourapp.com/auth/login`. |
| parse_tenant_from_root_domain | Optional[str] | Only if using tenant subdomains in your application | Yes | The root domain for your application. This value only needs to be specified if you intend to use tenant subdomains in your Login and Callback Endpoint URLs.  The root domain should be set to the portion of the domain that comes after the tenant subdomain.  For example, if your application uses tenant subdomains such as `tenantA.yourapp.com` and `tenantB.yourapp.com`, then the root domain should be set to `yourapp.com`. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `default_tenant_custom_domain` config. When this configuration is enabled, the SDK extracts the tenant subdomain from the host and uses it to construct the Wristband Authorize URL. |
| redirect_uri | Optional[str] | Only when `auto_configure_enabled` is set to `False` | Yes | The URI that Wristband will redirect to after authenticating a user.  This should point to your application's callback endpoint. If you intend to use tenant subdomains in your Callback Endpoint URL, then this value must contain the `{tenant_name}` token. For example: `https://{tenant_name}.yourapp.com/auth/callback`. |
| scopes | List[str] | No | No | The scopes required for authentication. Specified scopes can alter which data is returned from the `callback()` method's `callback_data` return type.  Refer to the [Wristband Authorize API](https://docs.wristband.dev/reference/authorizev1) documentation for currently supported scopes. The default value is `["openid", "offline_access", "email"]`. |
| token_expiration_buffer | int | No | No | Buffer time (in seconds) to subtract from the access token’s expiration time. This causes the token to be treated as expired before its actual expiration, helping to avoid token expiration during API calls. Defaults to 60 seconds. |
| wristband_application_vanity_domain | str | Yes | No | The vanity domain of the Wristband application. |

<br>

### `WristbandAuth()`

```python
wristband_auth = WristbandAuth(auth_config: AuthConfig)
```

This constructor creates an instance of `WristbandAuth` using lazy auto-configuration. Auto-configuration is enabled by default and will fetch any missing configuration values from the Wristband SDK Configuration Endpoint when any auth function is first called (i.e. `login`, `callback`, etc.). Set `auto_configure_enabled` to `False` disable to prevent the SDK from making an API request to the Wristband SDK Configuration Endpoint. In the event auto-configuration is disabled, you must manually configure all required values. Manual configuration values take precedence over auto-configured values.

| Method | When Config is Fetched | Use When |
| ------ | ---------------------- | -------- |
| WristbandAuth() (default) | Lazily, on first auth method call (login, callback, etc.) | Standard usage - allows your app to start without waiting for config |
| WristbandAuth.discover() | Eagerly, immediately when called | You want to fail fast at startup if auto-config is unavailable |

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
    "login_url": "https://{tenant_name}.custom.com/auth/login",
    "redirect_uri": "https://{tenant_name}.custom.com/auth/callback",
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

## Auth API

### login()

```python
def login(self, request: HttpRequest, config: Optional[LoginConfig]) -> HttpResponse:
```

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | HttpRequest | Yes | The Django request object. |
| config | LoginConfig | No | Optional configuration if your application needs custom behavior. |

Wristband requires that your application specify a Tenant-Level domain when redirecting to the Wristband Authorize Endpoint when initiating an auth request. When your application redirects the user to your Django Login Endpoint, there are two ways to accomplish getting the `tenant_name` information: passing a query parameter or using tenant subdomains.

```python
response: HttpResponse = wristband_auth.login(request)
```

The `login()` method can also take optional configuration if your application needs custom behavior:

| LoginConfig Field | Type | Required | Description |
| ----------------- | ---- | -------- | ----------- |
| custom_state | Optional[dict[str, Any]] | No | Additional state to be saved in the Login State Cookie. Upon successful completion of an auth request/login attempt, your Callback Endpoint will return this custom state (unmodified) as part of the return type. |
| default_tenant_name | str | No | An optional default tenant name to use for the login request in the event the tenant name cannot be found in either the subdomain or query parameters (depending on your subdomain configuration). |
| default_tenant_custom_domain | str | No | An optional default tenant custom domain to use for the login request in the event the tenant custom domain cannot be found in the query parameters. |
| return_url | string | No | The URL to return to after authentication is completed. If a value is provided, then it takes precedence over the `return_url` request query parameter. |

#### Which Domains Are Used in the Authorize URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Authorize URL, which your login endpoint will redirect users to during the login flow. The selection follows this precedence order:

1. `tenant_custom_domain` query parameter: If provided, this takes top priority.
2. Tenant subdomain in the URL: Used if `parse_tenant_from_root_domain` is specified and there is a subdomain present in the host.
3. `tenant_name` query parameter: Evaluated if no tenant subdomain is found in the host.
4. `default_tenant_custom_domain` in LoginConfig: Used if none of the above are present.
5. `default_tenant_name` in LoginConfig: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Tenant Name Query Param

If your application does not wish to utilize subdomains for each tenant, you can pass the `tenant_name` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.ai/auth/login?tenant_name=customer01
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
    "login_url": 'https://{tenant_name}.yourapp.ai/auth/login',
    "redirect_uri": 'https://{tenant_name}.yourapp.ai/auth/callback',
    "parse_tenant_from_root_domain": "yourapp.ai",
    "wristband_application_vanity_domain": "yourapp-yourcompany.us.wristband.dev",
}
```

#### Default Tenant Name

For certain use cases, it may be useful to specify a default tenant name in the event that the `login()` method cannot find a tenant name in either the query parameters or in the URL subdomain. You can specify a fallback default tenant name via a `LoginConfig` object:

```python
response = wristband_auth.login(
    request=request, 
    config=LoginConfig(default_tenant_name="default")
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

### callback()

```python
def callback(self, request: HttpRequest) -> CallbackResult:
```

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | HttpRequest | Yes | The Django request object. |

After a user authenticates on the Tenant-Level Login Page, Wristband will redirect to your Django Callback Endpoint with an authorization code which can be used to exchange for an access token.

```python
callback_result: CallbackResult = wristband_auth.callback(request)
```

It will also pass the state parameter that was generated during the Login Endpoint.

```sh
GET https://customer01.yourapp.io/auth/callback?state=f983yr893hf89ewn0idjw8e9f&code=shcsh90jf9wc09j9w0jewc
```

The SDK will validate that the incoming state matches the Login State Cookie, and then it will call the Wristband Token Endpoint to exchange the authorizaiton code for JWTs. Lastly, it will call the Wristband Userinfo Endpoint to get any user data as specified by the `scopes` in your SDK configuration.

The callback method returns a discriminated union type `CallbackResult` that indicates whether the callback succeeded or requires a redirect:

**CallbackResult Variants:**

| Type | Description | Fields |
| ---- | ----------- | ------ |
| `CompletedCallbackResult` | Callback successfully completed with authentication data | <ul><li>`type` (always `CallbackResultType.COMPLETED`)</li><li>`callback_data`</li></ul> |
| `RedirectRequiredCallbackResult` | Redirect required to retry authentication | <ul><li>`type` (always `CallbackResultType.REDIRECT_REQUIRED`)</li><li>`redirect_url`</li><li>`reason`</li></ul> |

**All Possible CallbackResult Fields:**

| CallbackResult Field | Type | Description |
| -------------------- | ---- | ----------- |
| type | `CallbackResultType`  | Enum representing the type of the callback result. |
| callback_data | `CallbackData` | The callback data received after authentication (`COMPLETED` result only). |
| redirect_url | str | A URL that you need to redirect to (`REDIRECT_REQUIRED` result only). For some edge cases, the SDK will require a redirect to restart the login flow. |
| reason | `CallbackFailureReason` | Specific reason why the callback failed and requires redirect (`REDIRECT_REQUIRED` result only) |

<br>

**CallbackResultType Enum:**

| Value | Description |
| ----- | ----------- |
| `COMPLETED` | Indicates that the callback is successfully completed and data is available for creating a session. |
| `REDIRECT_REQUIRED` | Indicates that a redirect to the login endpoint is required. |

<br>

**CallbackFailureReason Enum:**

When a redirect is required, the `reason` field indicates why the callback failed:

| Value | Description |
| ------ | ----------- |
| `MISSING_LOGIN_STATE` | Login state cookie was not found (cookie expired or bookmarked callback URL) |
| `INVALID_LOGIN_STATE` | Login state validation failed (possible CSRF attack or cookie tampering) |
| `LOGIN_REQUIRED` | Wristband returned a login_required error (session expired or max_age elapsed) |
| `INVALID_GRANT` | Authorization code was invalid, expired, or already used |

<br>

**CallbackData:**

When the callback returns a `COMPLETED` result, all of the token and userinfo data also gets returned. This enables your application to create an application session for the user and then redirect them back into your application. The `CallbackData` is defined as follows:

| CallbackData Field | Type | Description |
| ------------------ | ---- | ----------- |
| access_token | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| custom_state | Optional[dict[str, Any]] | If you injected custom state into the Login State Cookie during the Login Endpoint for the current auth request, then that same custom state will be returned in this field. |
| expires_at | int | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `token_expiration_buffer` SDK configuration is accounted for in this value. |
| expires_in | int | The duration from the current time until the access token is expired (in seconds). The `token_expiration_buffer` SDK configuration is accounted for in this value. |
| id_token | str | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refresh_token | Optional[str] | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |
| return_url | Optional[str] | The URL to return to after authentication is completed. |
| tenant_custom_domain | Optional[str] | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenant_name | str | The name of the tenant the user belongs to. |
| user_info | `UserInfo` | User information that is retrieved from the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) and transformed to user-friendly field names that match the Wristband User entity naming convention. The exact fields that get returned are based on the scopes you configured in the SDK. |

<br>

**UserInfo:**

| UserInfo Field | Type | Always Returned | Description |
| -------------- | ---- | --------------- | ----------- |
| user_id | str | Yes | ID of the user. |
| tenant_id | str | Yes | ID of the tenant that the user belongs to. |
| application_id | str | Yes | ID of the application that the user belongs to. |
| identity_provider_name | str | Yes | Name of the identity provider. |
| full_name | Optional[str] | No | End-User's full name in displayable form (requires `profile` scope). |
| given_name | Optional[str] | No | Given name(s) or first name(s) of the End-User (requires `profile` scope). |
| family_name | Optional[str] | No | Surname(s) or last name(s) of the End-User (requires `profile` scope). |
| middle_name | Optional[str] | No | Middle name(s) of the End-User (requires `profile` scope). |
| nickname | Optional[str] | No | Casual name of the End-User (requires `profile` scope). |
| display_name | Optional[str] | No | Shorthand name by which the End-User wishes to be referred (requires `profile` scope). |
| picture_url | Optional[str] | No | URL of the End-User's profile picture (requires `profile` scope). |
| email | Optional[str] | No | End-User's preferred email address (requires `email` scope). |
| email_verified | Optional[bool] | No | True if the End-User's email address has been verified (requires `email` scope). |
| gender | Optional[str] | No | End-User's gender (requires `profile` scope). |
| birthdate | Optional[str] | No | End-User's birthday in YYYY-MM-DD format (requires `profile` scope). |
| time_zone | Optional[str] | No | End-User's time zone (requires `profile` scope). |
| locale | Optional[str] | No | End-User's locale as BCP47 language tag, e.g., "en-US" (requires `profile` scope). |
| phone_number | Optional[str] | No | End-User's telephone number in E.164 format (requires `phone` scope). |
| phone_number_verified | Optional[bool] | No | True if the End-User's phone number has been verified (requires `phone` scope). |
| updated_at | Optional[int] | No | Time the End-User's information was last updated as Unix timestamp (requires `profile` scope). |
| roles | Optional[List[`UserInfoRole`]] | No | The roles assigned to the user (requires `roles` scope). |
| custom_claims | Optional[dict[str, Any]] | No | Object containing any configured custom claims. |

<br>

**UserInfoRole:**

| UserInfoRole Field | Type | Description |
| ------------------ | ---- | ----------- |
| id | str | Globally unique ID of the role. |
| name | str | The role name (e.g., "app:app-name:admin"). |
| display_name | str | The human-readable display name for the role. |

<br>

#### Handling Callback Results

Regardless of the result type (`COMPLETED` and `REDIRECT_REQUIRED`), you should call `create_callback_response()` to produce the appropriate redirect response with all required headers set.

There are edge cases where a redirect URL is returned by the SDK. The following are edge cases where this occurs:

- The Login State Cookie is missing by the time Wristband redirects back to the Callback Endpoint.
- The `state` query parameter sent from Wristband to your Callback Endpoint does not match the Login State Cookie.
- Wristband sends an `error` query parameter to your Callback Endpoint, and it is an expected error type that the SDK knows how to resolve.

The location of where the user gets redirected to in these scenarios depends on if the application is using tenant subdomains and if the SDK is able to determine which tenant the user is currently attempting to log in to. The resolution happens in the following order:

1. If the tenant domain can be determined, then the user will get redirected back to your Django Login Endpoint.
2. Otherwise, the user will be sent to the Wristband-hosted Application-Level Login (Tenant Discovery) Page.

<br>

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

<br>

### create_callback_response()

```python
def create_callback_response(self, request: HttpRequest, redirect_url: str) -> HttpResponse:
```

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | HttpRequest | Yes | The Django request object. |
| redirect_url | str | Yes | The URL to redirect the user to after authentication completes. |

Your Callback Endpoint will call `create_callback_response()` after the `callback()` method is finished in order to complete the authentication flow. This will return a Django response object with the appropriate response headers and cookie handling set.

```python
callback_result: CallbackResult = wristband_auth.callback(request)

# Handle redirect required scenario
if isinstance(callback_result, RedirectRequiredCallbackResult):
    return wristband_auth.create_callback_response(request, callback_result.redirect_url)

# Create session before returning response
session.from_callback(callback_result.callback_data)
post_callback_url = callback_result.callback_data.return_url or "<your_app_home_url>"
return wristband_auth.create_callback_response(request, post_callback_url)
```

<br>

### logout()

```python
def logout(self, request: HttpRequest, config: Optional[LogoutConfig]) -> HttpResponse:
```

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | Request | Yes | The Django request object. |
| config | LogoutConfig | No | Optional configuration if your application needs custom behavior. |

When users of your application are ready to log out or their application session expires, your frontend should redirect the user to your Django Logout Endpoint. If your application created a session, it should destroy the session before invoking the `wristband_auth.logout()` method.

```sh
GET https://customer01.yourapp.ai/auth/logout
```

```python
logout_config = LogoutConfig(
    refresh_token=request.session.refresh_token,
    tenant_name=request.session.tenant_name,
)

request.session.flush()
return wristband_auth.logout(request, logout_config)
```

This method can also take an optional `LogoutConfig` argument:

| LogoutConfig Field | Type | Required | Description |
| ------------------ | ---- | -------- | ----------- |
| redirect_url | Optional[str] | No | Optional URL that Wristband will redirect to after the logout operation has completed. This will also take precedence over the `custom_application_login_page_url` (if specified) in the SDK AuthConfig if the tenant domain cannot be determined when attempting to redirect to the Wristband Logout Endpoint. |
| refresh_token | Optional[str] | No | The refresh token to revoke. |
| state | Optional[str] | No | Optional value that will be appended as a query parameter to the resolved logout URL, if provided. Maximum length of 512 characters. |
| tenant_custom_domain | Optional[str] | No | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenant_name | Optional[str] | No | The name of the tenant the user belongs to. |

#### Which Domains Are Used in the Logout URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Logout URL, which your login endpoint will redirect users to during the logout flow. The selection follows this precedence order:

1. `tenant_custom_domain` in LogoutConfig: If provided, this takes top priority.
2. `tenant_name` in LogoutConfig: This takes the next priority if `tenant_custom_domain` is not present.
3. `tenant_custom_domain` query parameter: Evaluated if present and there is also no LogoutConfig provided for either `tenant_custom_domain` or `tenant_name`.
4. Tenant subdomain in the URL: Used if none of the above are present, and `parse_tenant_from_root_domain` is specified, and the subdomain is present in the host.
5. `tenant_name` query parameter: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Revoking Refresh Tokens

If your application requested refresh tokens during the Login Workflow (via the `offline_access` scope), it is crucial to revoke the user's access to that refresh token when logging out. Otherwise, the refresh token would still be valid and able to refresh new access tokens.  You should pass the refresh token into the LogoutConfig when invoking the `logout()` method, and the SDK will call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) automatically.

#### Resolving Tenant Domains

Much like the Login Endpoint, Wristband requires your application specify a Tenant-Level domain when redirecting to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1). If your application does not utilize tenant subdomains, then you can either explicitly pass it into the LogoutConfig:

```python
response: HttpResponse = wristband_auth.logout(
    request=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_name="customer01"
    )
)
```

...or you can alternatively pass the `tenant_name` query parameter in your redirect request to Logout Endpoint:

```python
# Logout Request URL -> "https://yourapp.ai/auth/logout?client_id=123&tenant_name=customer01"
response: HttpResponse = wristband_auth.logout(
    request=request,
    config=LogoutConfig(refresh_token="98yht308hf902hc90wh09")
)
```

If your application uses tenant subdomains, then passing the `tenant_name` field to the LogoutConfig is not required since the SDK will automatically parse the subdomain from the URL as long as the `parse_tenant_from_root_domain` SDK config is set.

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

If your application supports a mixture of tenants that use tenant subdomains and tenant custom domains, then you should consider passing both the tenant names and tenant custom domains (either via LogoutConfig or by query parameters) to ensure all use cases are handled by the SDK.

#### Preserving State After Logout

The `state` field in the `LogoutConfig` allows you to preserve application state through the logout flow.

```python
response: HttpResponse = wristband_auth.logout(
    request=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_name="customer01",
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
https://yourapp.io/auth/login?tenant_name=customer01&state=user_initiated_logout
```

This is useful for tracking logout context, displaying post-logout messages, or handling different logout scenarios. The state value is limited to 512 characters and will be URL-encoded automatically.

#### Custom Logout Redirect URL

Some applications might require the ability to land on a different page besides the Login Page after logging a user out. You can add the `redirect_url` field to the LogoutConfig, and doing so will tell Wristband to redirect to that location after it finishes processing the logout request.

```python
response: HttpResponse = wristband_auth.logout(
    request=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_name="customer01",
        redirect_url="https://custom-logout.com"
    )
)
```

### refresh_token_if_expired()

```python
def refresh_token_if_expired(self, refresh_token: str, expires_at: int) -> Optional[TokenData]:
```

| Argument | Type | Required | Description |
| -------- | ---- | -------- | ----------- |
| expires_at | int | Yes | Unix timestamp in milliseconds at which the token expires. |
| refresh_token | str | Yes | The refresh token used to send to Wristband when access tokens expire in order to receive new tokens. |

If your application is using access tokens generated by Wristband either to make API calls to Wristband or to protect other backend APIs, then your applicaiton needs to ensure that access tokens don't expire until the user's session ends.  You can use the refresh token to generate new access tokens.

```python
token_data: Optional[TokenData] = wristband_auth.refresh_token_if_expired(
    refresh_token="98yht308hf902hc90wh09",
    expires_at=1710707503788
)
```

If the `refresh_token_if_expired()` method finds that your token has not expired yet, it will return `None` as the value, which means your auth middleware can simply continue forward as usual.

The `TokenData` is defined as follows:

| TokenData Field | Type | Description |
| --------------- | ---- | ----------- |
| access_token | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| expires_at | int | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `token_expiration_buffer` SDK configuration is accounted for in this value. |
| expires_in | int | The duration from the current time until the access token is expired (in seconds). The `token_expiration_buffer` SDK configuration is accounted for in this value. |
| id_token | str | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refresh_token | Optional[str] | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |

<br>

## Session Management

After successful authentication, Wristband user and token data is stored in Django's session. This section documents the session fields, type hints, and access patterns.

This SDK uses Django's built-in session framework. The [encrypted cookie session engine](#3-set-up-session-management) is recommended for getting started, but you can use any Django session backend. For more information on Django's session framework, see the [Django Sessions documentation](https://docs.djangoproject.com/en/stable/topics/http/sessions/).

<br>

### Session Fields

These fields are automatically populated when you call `session_from_callback()` after successful Wristband authentication:

| Session Field | Type | Always Present | Description |
| ------------- | ---- | -------------- | ----------- |
| `is_authenticated` | `bool` | Yes | Whether the user is authenticated (always `True` after `session_from_callback()`). |
| `access_token` | `str` | Yes | JWT access token for making authenticated API calls to Wristband and other services. |
| `expires_at` | `int` | Yes | Token expiration timestamp (milliseconds since Unix epoch). Accounts for `token_expiration_buffer` from SDK config. |
| `user_id` | `str` | Yes | Unique identifier for the authenticated user. |
| `tenant_id` | `str` | Yes | Unique identifier for the tenant that the user belongs to. |
| `tenant_name` | `str` | Yes | Name of the tenant that the user belongs to. |
| `identity_provider_name` | `str` | Yes | Name of the identity provider that the user belongs to. |
| `refresh_token` | `str` | No | Refresh token for obtaining new access tokens when they expire. Only present if `offline_access` scope was requested during authentication. |
| `tenant_custom_domain` | `str` | No | Custom domain for the tenant, if configured. Only present if a tenant custom domain was used during authentication. |

<br>

### Type Hints for Session Data

For better IDE autocomplete and type checking, you can use the `WristbandSessionData` TypedDict:

```python
from typing import cast
from wristband.django_auth import WristbandSessionData

def my_view(request):
    # Optional: Cast for IDE autocomplete
    session: WristbandSessionData = cast(WristbandSessionData, request.session)
    
    # IDE now knows these are strings
    user_id = session['user_id']
    tenant_id = session['tenant_id']
    
    # IDE knows this is Optional[str]
    refresh_token = session.get('refresh_token')
```

> **Note:** Using `WristbandSessionData` is entirely optional. It provides type hints for Wristband-specific fields but doesn't affect runtime behavior.

<br>

### Session Access Patterns

Django sessions work like dictionaries. You can access Wristband session data using standard Django session patterns:

```python
# Read session data (dict-style)
user_id = request.session['user_id']
tenant_id = request.session.get('tenant_id')
refresh_token = request.session.get('refresh_token')  # Returns None if not present

# Check if field exists
if 'refresh_token' in request.session:
    token = request.session['refresh_token']

# Update session data
request.session['last_activity'] = time.time()
request.session.modified = True  # Mark as modified to ensure Django saves it

# Clear session (logout)
request.session.flush()
```

<br>

### Session Helper Functions

The SDK provides helper functions for working with sessions:

#### session_from_callback()

```python
def session_from_callback(
    request: HttpRequest,
    callback_data: CallbackData,
    custom_fields: Optional[Dict[str, Any]] = None
) -> None:
```

Populate Django session from Wristband callback data. Automatically extracts core user and tenant info from callback data and stores it in the session. Optionally merges custom fields.

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | `HttpRequest` | Yes | Django HttpRequest with session middleware enabled. |
| callback_data | `CallbackData` | Yes | Callback data from `wristband_auth.callback()`. |
| custom_fields | `Optional[Dict[str, Any]]` | No | Additional fields to store in session (must be JSON-serializable). |

**Raises:**

| Exception | Condition |
| --------- | --------- |
| `RuntimeError` | If SessionMiddleware is not installed. |
| `ValueError` | If `request` or `callback_data` is `None`, or if `callback_data.user_info` is missing. |

**Example with default values:**

```python
from django.http import HttpRequest, HttpResponse
from django.views.decorators.http import require_GET
from wristband.django_auth import RedirectRequiredCallbackResult, session_from_callback
from your_app.wristband import wristband_auth

@require_GET
def callback_endpoint(request: HttpRequest) -> HttpResponse:
    callback_result = wristband_auth.callback(request)
    
    if isinstance(callback_result, RedirectRequiredCallbackResult):
        return wristband_auth.create_callback_response(request, callback_result.redirect_url)
    
    # Populate session from callback data
    session_from_callback(request, callback_result.callback_data)
    
    post_callback_url = callback_result.callback_data.return_url or '/'
    return wristband_auth.create_callback_response(request, post_callback_url)
```

**Example with custom fields included:**

```python
session_from_callback(
    request,
    callback_result.callback_data,
    custom_fields={'role': 'admin', 'last_login': time.time()}
)
```

**Fields stored in session:**

- `is_authenticated` (always `True`)
- `access_token`
- `expires_at`
- `user_id`
- `tenant_id`
- `tenant_name`
- `identity_provider_name`
- `refresh_token` (only if `offline_access` scope was requested)
- `tenant_custom_domain` (only if present in callback data)
- Any `custom_fields` provided

#### get_session_response()

```python
def get_session_response(
    request: HttpRequest,
    metadata: Optional[Dict[str, Any]] = None
) -> SessionResponse:
```

Create a session response for Wristband frontend SDKs. Extracts `tenant_id` and `user_id` from the session and returns them in the format expected by Wristband's frontend SDKs. Optionally includes custom metadata.

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | `HttpRequest` | Yes | Django HttpRequest with session middleware enabled. |
| metadata | `Optional[Dict[str, Any]]` | No | Custom metadata to include (must be JSON-serializable). Defaults to empty dict if not provided. |

**Returns:**

`SessionResponse` - Class type with the following fields:

| Field | Type | Description |
| ----- | ---- | ----------- |
| tenant_id | `str` | The ID of the tenant that the authenticated user belongs to. |
| user_id | `str` | The ID of the user who authenticated. |
| metadata | `Dict[str, Any]` | Any included custom session metadata. |

**Raises:**

| Exception | Condition |
| --------- | --------- |
| `RuntimeError` | If SessionMiddleware is not installed. |
| `ValueError` | If `request` is None, or if `tenant_id` or `user_id` are missing from session. |

**Example:**

```python
from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_GET
from wristband.django_auth import get_session_response
from your_app.wristband import wristband_auth

@require_session
@require_GET
def session_endpoint(request: HttpRequest) -> JsonResponse:
    """Session endpoint for Wristband frontend SDKs"""
    session_data = get_session_response(request, metadata={'foo': 'bar'})
    response = JsonResponse(session_data)
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'
    return response
```

**Response format:**

```json
{
  "tenantId": "tenant_abc123",
  "userId": "user_xyz789",
  "metadata": {
    "foo": "bar"
  }
}
```

#### get_token_response()

```python
def get_token_response(request: HttpRequest) -> TokenResponse:
```

Create a token response for Wristband frontend SDKs. Extracts `access_token` and `expires_at` from the session and returns them in the format expected by Wristband's frontend SDKs.

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | `HttpRequest` | Yes | Django HttpRequest with session middleware enabled. |

**Returns:**

`TokenResponse` - Class type with the following fields:

| Field | Type | Description |
| ----- | ---- | ----------- |
| access_token | `str` | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| expires_at | `int` | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `token_expiration_buffer` SDK configuration is accounted for in this value. |

**Raises:**

| Exception | Condition |
| --------- | --------- |
| `RuntimeError` | If SessionMiddleware is not installed. |
| `ValueError` | If `request` is None, or if `access_token` or `expires_at` are missing from session. |

**Example:**

```python
from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_GET
from wristband.django_auth import get_token_response
from your_app.wristband import wristband_auth

@require_session
@require_GET
def token_endpoint(request: HttpRequest) -> JsonResponse:
    """Token endpoint for frontend access token retrieval"""
    token_data = get_token_response(request)
    response = JsonResponse(token_data)
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'
    return response
```

**Response format:**

```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresAt": 1735689600000
}
```

<br>

## Authentication Strategies

The SDK provides factory methods to create authentication protection for your Django views. These methods support session-based authentication, JWT bearer token authentication, and multi-strategy authentication (combining both). Each factory method creates decorators for function-based views, mixins for class-based views, or DRF authentication classes.

<br>

### Available Authentication Strategies

The SDK supports two authentication strategies that can be used individually or combined:

| Strategy | Value | Description |
| -------- | ----- | ----------- |
| `AuthStrategy.SESSION` | `"session"` | Validates authentication using Django session data containing Wristband tokens. Automatically refreshes expired access tokens using the refresh token (only if `refresh_token` and `expires_at` exist in session). Refreshes CSRF cookie expiration time if Django's `CsrfViewMiddleware` is enabled (implements rolling sessions). |
| `AuthStrategy.JWT` | `"jwt"` | Validates authentication using a Wristband JWT bearer token from the Authorization header. Does not use sessions or refresh tokens. Verifies token signature using JWKS from Wristband and validates claims. |

Multiple strategies can be used together, tried in order until one succeeds (e.g., try `SESSION` first, then fall back to `JWT`).

<br>

### Unauthenticated Request Behavior

When authentication fails, the SDK can respond in two ways:

| Behavior | Value | Description |
| -------- | ----- | ----------- |
| `UnauthenticatedBehavior.REDIRECT` | `"redirect"` | Redirects unauthenticated users to the login URL (configured in your Wristband SDK settings). Appropriate for browser-based page views where users can be redirected to a login page to authenticate. |
| `UnauthenticatedBehavior.JSON` | `"json"` | Returns a 401 Unauthorized HTTP response. Appropriate for API endpoints where the client (e.g., AJAX, mobile app) expects HTTP status codes instead of HTML redirects. |

<br>

### create_auth_decorator()

```python
def create_auth_decorator(
    self,
    strategies: List[AuthStrategy],
    on_unauthenticated: UnauthenticatedBehavior = UnauthenticatedBehavior.JSON,
    jwt_config: Optional[JWTAuthConfig] = None
) -> Callable:
```

Creates a reusable decorator for protecting function-based views with authentication. Supports session-based authentication, JWT bearer token authentication, or both.

**Parameters:**

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| strategies | List[`AuthStrategy`] | Yes | N/A | Authentication strategies to try in order. Available: `AuthStrategy.SESSION`, `AuthStrategy.JWT` |
| on_unauthenticated | `UnauthenticatedBehavior` | No | `UnauthenticatedBehavior.JSON` | How to handle unauthenticated requests. `REDIRECT` redirects to login URL, `JSON` returns HTTP 401 response. |
| jwt_config | `JWTAuthConfig` | No | `None` | Configuration for JWT authentication. Only used when `AuthStrategy.JWT` is included. |

**JWTAuthConfig:**

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `jwks_cache_max_size` | `int` | `20` | Maximum number of JWKs to cache in memory. |
| `jwks_cache_ttl` | `int` | `None` (infinite) | Time-to-live for cached JWKs in seconds. |

**Authentication Flow:**

When applied to a view, the decorator tries each authentication strategy in order:

1. For `AuthStrategy.SESSION`:
   - Verifies the session exists and user is authenticated
   - Checks if access token expired and refreshes if necessary (only if `refresh_token` and `expires_at` are in the session)
   - Updates the session with new token data if a refresh occurs
   - Refreshes the CSRF token for rolling session behavior (only if Django's `CsrfViewMiddleware` is enabled)
   - Saves session to persist changes (implements rolling sessions)

2. For `AuthStrategy.JWT`:
   - Extracts JWT from `Authorization: Bearer <token>` header
   - Verifies signature using JWKS from Wristband
   - Validates claims (expiration, issuer, etc.)
   - Stores the raw JWT string on the request at `request.auth.jwt`
   - Stores decoded JWT payload on the request at `request.auth.payload`

3. If all strategies fail, redirects to the Login Endpoint or returns a 401 based on `on_unauthenticated`

**Session Authentication Example:**

```python
# your_app/wristband.py
from wristband.django_auth import (
    AuthConfig,
    AuthStrategy,
    UnauthenticatedBehavior,
    WristbandAuth,
)

wristband_auth = WristbandAuth(AuthConfig(**settings.WRISTBAND_AUTH))

require_session = wristband_auth.create_auth_decorator(
    strategies=[AuthStrategy.SESSION],
    on_unauthenticated=UnauthenticatedBehavior.REDIRECT,
)

__all__ = ['wristband_auth', 'require_session']
```

```python
# your_app/views.py
from django.shortcuts import render
from your_app.wristband import require_session

@require_session
def dashboard(request):
    return render(request, 'dashboard.html', {
        'user_id': request.session['user_id']
    })
```

**JWT Authentication Example:**

```python
# your_app/wristband.py
from wristband.django_auth import (
    AuthConfig,
    AuthStrategy,
    JWTAuthConfig,
    UnauthenticatedBehavior,
    WristbandAuth,
)

wristband_auth = WristbandAuth(AuthConfig(**settings.WRISTBAND_AUTH))

require_jwt = wristband_auth.create_auth_decorator(
    strategies=[AuthStrategy.JWT],
    on_unauthenticated=UnauthenticatedBehavior.JSON,
    jwt_config=JWTAuthConfig(jwks_cache_max_size=50, jwks_cache_ttl=3600)
)

__all__ = ['wristband_auth', 'require_jwt']
```

```python
# your_app/views.py
from django.http import JsonResponse
from your_app.wristband import require_jwt

@require_jwt
def api_endpoint(request):
    # JWT validated and available in request.auth
    user_id = request.auth.payload.sub
    access_token = request.auth.jwt
    
    return JsonResponse({'user_id': user_id})
```

**Multi-Strategy Authentication Example:**

```python
# your_app/wristband.py
from wristband.django_auth import (
    AuthConfig,    
    AuthStrategy,
    JWTAuthConfig,
    UnauthenticatedBehavior,
    WristbandAuth,
)

wristband_auth = WristbandAuth(AuthConfig(**settings.WRISTBAND_AUTH))

# Try session first, fall back to JWT
require_auth = wristband_auth.create_auth_decorator(
    strategies=[AuthStrategy.SESSION, AuthStrategy.JWT],
    on_unauthenticated=UnauthenticatedBehavior.JSON,
)

__all__ = ['wristband_auth', 'require_auth']
```

```python
from django.http import JsonResponse
from wristband.django_auth import AuthStrategy
from your_app.wristband import require_auth

@require_auth
def flexible_api(request):
    if hasattr(request, 'auth'):
        # JWT strategy succeeded
        user_id = request.auth.payload.sub
        auth_method = AuthStrategy.JWT
    else:
        # Session strategy succeeded
        user_id = request.session['user_id']
        auth_method = AuthStrategy.SESSION

    return JsonResponse({
        'user_id': user_id,
        'auth_method': auth_method
    })
```

<br>

### create_auth_mixin()

```python
def create_auth_mixin(
    self,
    strategies: List[AuthStrategy],
    on_unauthenticated: UnauthenticatedBehavior = UnauthenticatedBehavior.JSON,
    jwt_config: Optional[JWTAuthConfig] = None
) -> Type[WristbandAuthMixin]:
```

Creates a reusable mixin class for protecting class-based views with authentication. Takes the same parameters and performs the same authentication flow as `create_auth_decorator()`.

**Session Authentication Example:**

```python
# your_app/wristband.py
from wristband.django_auth import (
    AuthConfig,
    AuthStrategy,
    UnauthenticatedBehavior,
    WristbandAuth,
)

wristband_auth = WristbandAuth(AuthConfig(**settings.WRISTBAND_AUTH))

SessionRequiredMixin = wristband_auth.create_auth_mixin(
    strategies=[AuthStrategy.SESSION],
    on_unauthenticated=UnauthenticatedBehavior.REDIRECT,
)

__all__ = ['wristband_auth', 'SessionRequiredMixin']
```

```python
# your_app/views.py
from django.views import View
from django.shortcuts import render
from your_app.wristband import SessionRequiredMixin

class DashboardView(SessionRequiredMixin, View):
    def get(self, request):
        return render(request, 'dashboard.html', {
            'user_id': request.session['user_id']
        })
```

**JWT Authentication Example:**

```python
# your_app/wristband.py
from wristband.django_auth import (
    AuthConfig,
    AuthStrategy,
    JWTAuthConfig,
    UnauthenticatedBehavior,
    WristbandAuth,
)

wristband_auth = WristbandAuth(AuthConfig(**settings.WRISTBAND_AUTH))

JwtRequiredMixin = wristband_auth.create_auth_mixin(
    strategies=[AuthStrategy.JWT],
    on_unauthenticated=UnauthenticatedBehavior.JSON,
    jwt_config=JWTAuthConfig(jwks_cache_max_size=50, jwks_cache_ttl=3600)
)

__all__ = ['wristband_auth', 'JwtRequiredMixin']
```

```python
# your_app/views.py
from django.http import JsonResponse
from django.views import View
from your_app.wristband import JwtRequiredMixin

class ApiView(JwtRequiredMixin, View):
    def get(self, request):
        access_token = request.auth.jwt
        user_id = request.auth.payload.sub

        return JsonResponse({'user_id': user_id})
```

> **Note:** The mixin must be the leftmost class in the inheritance chain to ensure authentication is checked before any other view logic executes.

<br>

### create_drf_session_auth()

```python
def create_drf_session_auth(self) -> Type[BaseAuthentication]:
```

Creates a DRF authentication class for session-based authentication. Use this with Django REST Framework's `authentication_classes` and `IsAuthenticated` permission.

This DRF authentication class focuses solely on session auth and does not include strategy selection or custom unauthenticated behavior, since DRF supports multi-strategy handling and always returns JSON 401 responses for API-first applications.

> **Note:** Requires `djangorestframework>=3.15.0`. Install with `pip install wristband-django-auth[drf]`.

**Example:**

```python
# your_app/wristband.py
from wristband.django_auth import AuthConfig, WristbandAuth

wristband_auth = WristbandAuth(AuthConfig(**settings.WRISTBAND_AUTH))

DrfSessionAuth = wristband_auth.create_drf_session_auth()

__all__ = ['wristband_auth', 'DrfSessionAuth']
```

```python
# your_app/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from your_app.wristband import DrfSessionAuth

class ProfileAPIView(APIView):
    authentication_classes = [DrfSessionAuth]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({
            'user_id': request.session['user_id'],
            'email': request.session['email']
        })
```

<br>

### create_drf_jwt_auth()

```python
def create_drf_jwt_auth(
    self,
    jwt_config: Optional[JWTAuthConfig] = None
) -> Type[BaseAuthentication]:
```

Creates a DRF authentication class for JWT bearer token authentication. Use this with Django REST Framework's `authentication_classes` and `IsAuthenticated` permission.

This DRF authentication class focuses solely on JWT auth and does not include strategy selection or custom unauthenticated behavior, since DRF supports multi-strategy handling and always returns JSON 401 responses for API-first applications.

> **Note:** Requires `djangorestframework>=3.15.0`. Install with `pip install wristband-django-auth[drf]`.

**Parameters:**

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| jwt_config | `JWTAuthConfig` | No | `None` | Configuration for JWT authentication. |

**Example:**

```python
# your_app/wristband.py
from wristband.django_auth import AuthConfig, JWTAuthConfig, WristbandAuth

wristband_auth = WristbandAuth(AuthConfig(**settings.WRISTBAND_AUTH))

DrfJwtAuth = wristband_auth.create_drf_jwt_auth(
    jwt_config=JWTAuthConfig(jwks_cache_max_size=50, jwks_cache_ttl=3600)
)

__all__ = ['wristband_auth', 'DrfJwtAuth']
```

```python
# your_app/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from your_app.wristband import DrfJwtAuth

class ApiEndpoint(APIView):
    authentication_classes = [DrfJwtAuth]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        access_token = request.auth.jwt
        user_id = request.auth.payload.sub
        return Response({'user_id': user_id})
```

<br>

### Multi-Strategy Authentication with DRF

Unlike Django's traditional decorators and mixins, Django REST Framework natively supports multiple authentication strategies through its `authentication_classes` list. To combine session and JWT authentication, simply include both authentication classes:

```python
# your_app/wristband.py
from wristband.django_auth import AuthConfig, WristbandAuth

wristband_auth = WristbandAuth(AuthConfig(**settings.WRISTBAND_AUTH))

DrfSessionAuth = wristband_auth.create_drf_session_auth()
DrfJwtAuth = wristband_auth.create_drf_jwt_auth()

__all__ = ['wristband_auth', 'DrfSessionAuth', 'DrfJwtAuth']
```

```python
# your_app/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from your_app.wristband import DrfSessionAuth, DrfJwtAuth

class FlexibleAPIView(APIView):
    # DRF tries session auth first, then JWT - first success wins
    authentication_classes = [DrfSessionAuth, DrfJwtAuth]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Check which strategy succeeded
        if hasattr(request, 'auth'):
            # JWT authentication succeeded
            user_id = request.auth.payload.sub
        else:
            # Session authentication succeeded
            user_id = request.session['user_id']
        
        return Response({'user_id': user_id})
```

<br>

### JWT Authentication Details

When using JWT authentication (via `AuthStrategy.JWT`), the decoded JWT data is stored in `request.auth` as a `JWTAuthResult` object:

**JWTAuthResult:**

| Field | Type | Description |
| ----- | ---- | ----------- |
| `jwt` | `str` | The raw JWT token string from the Authorization header. |
| `payload` | `JWTPayload` | The decoded and validated JWT payload containing claims. |

**JWTPayload:**

The JWT payload follows [OpenID Connect standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims). Common claims include:

| Field | Type | Description |
| ----- | ---- | ----------- |
| `sub` | `Optional[str]` | Subject - unique identifier for the user. |
| `iss` | `Optional[str]` | Issuer - URL of the identity provider. |
| `aud` | `Optional[str]` or `Optional[List[str]]` | Audience - intended recipient(s) of the token. |
| `exp` | `Optional[int]` | Expiration time - time after which JWT must not be accepted (Unix timestamp). |
| `nbf` | `Optional[int]` | Not before - time before which JWT must not be accepted (Unix timestamp). |
| `iat` | `Optional[int]` | Issued at - time when the JWT was issued (Unix timestamp). |
| `jti` | `Optional[str]` | JWT ID - unique identifier for the JWT. |
| `email` | `Optional[str]` | User's email address (if `email` scope requested). |
| `email_verified` | `Optional[bool]` | Whether email is verified (if `email` scope requested). |

> **Note:** All standard JWT claims are optional. Additional custom claims may be present based on requested scopes and Wristband configuration. Access any claim using `payload.get('claim_name')` or dict-like syntax `payload['claim_name']`.

**Accessing JWT Data:**

```python
# Function-based view
@require_jwt
def api_view(request):
    # Raw token for downstream API calls
    token = request.auth.jwt
    
    # Decoded claims
    user_id = request.auth.payload.sub
    email = request.auth.payload.email
    exp_time = request.auth.payload.exp
    
    return JsonResponse({
        'user_id': user_id,
        'email': email
    })
```

```python
# Class-based view
class ApiView(JwtRequiredMixin, View):
    def get(self, request):
        user_id = request.auth.payload.sub
        return JsonResponse({'user_id': user_id})
```

```python
# DRF view
class DRFApiView(APIView):
    authentication_classes = [DrfJwtAuth]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user_id = request.auth.payload.sub
        return Response({'user_id': user_id})
```

<br>

### Choosing the Right Strategy

**Use Session Authentication When:**
- Building traditional Django web applications with server-rendered templates
- Users log in through your application's UI
- You want automatic CSRF protection
- You need rolling session expiration

**Use JWT Authentication When:**
- Building API-first applications
- Developing mobile apps or SPAs that store tokens client-side
- Microservices need to validate tokens independently
- You want stateless authentication

**Use Multi-Strategy Authentication When:**
- Supporting both web and API clients in the same application
- Gradually migrating from session to JWT authentication
- Building a hybrid application with both traditional and modern frontends

<br>

## Debug Logging

The SDK includes some debug-level logging for troubleshooting authentication issues. To enable debug logs in your Django application, configure the logger for the Wristband SDK in your Django settings.

> **⚠️ Production Warning**
>
> Debug logging can potentially expose sensitive information in logs. Always set the Wristband logger level to `INFO` or `WARNING` in production environments.

```python
# your_project/settings.py

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        # Set Wristband to DEBUG level.
        'wristband': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
```

<br>

## Related Wristband SDKs

This SDK builds upon and integrates with other Wristband SDKs to provide a complete authentication solution:

**[@wristband/python-jwt](https://github.com/wristband-dev/python-jwt)**

This SDK leverages the Wristband Python JWT SDK for JWT validation when using JWT authentication strategies. It handles JWT signature verification, token parsing, and JWKS key management. The JWT SDK functions are also re-exported from this package, allowing you to use them directly for custom JWT validation scenarios beyond the built-in authentication dependencies. Refer to that GitHub repository for more information on JWT validation configuration and options.

<br>

## Wristband Multi-Tenant Django Demo App

You can check out the [Wristband Django demo app](https://github.com/wristband-dev/django-demo-app) to see this SDK in action. Refer to that GitHub repository for more information.

<br/>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.

<br/>
