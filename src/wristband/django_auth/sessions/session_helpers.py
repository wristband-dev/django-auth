"""
Session helper functions for Wristband authentication.

Provides utilities for working with Django sessions after Wristband authentication,
including helpers for populating session data from callback results and creating
response formats expected by Wristband frontend SDKs.
"""

from typing import Any, Dict, Optional, TypedDict

from django.contrib.sessions.backends.base import SessionBase
from django.http import HttpRequest

from ..models import CallbackData, SessionResponse, TokenResponse


class WristbandSessionData(TypedDict, total=False):
    """
    Type hints for Wristband session fields.

    These fields are automatically populated when using session_from_callback().
    This TypedDict is optional - use it for better IDE autocomplete and type checking.

    Usage:
        from typing import cast
        from wristband.django_auth import WristbandSessionData

        # Optional: Cast for IDE autocomplete
        session: WristbandSessionData = cast(WristbandSessionData, request.session)
        user_id = session['user_id']  # IDE knows this is a string
    """

    is_authenticated: bool
    access_token: str
    expires_at: int
    user_id: str
    tenant_id: str
    tenant_name: str
    identity_provider_name: str
    refresh_token: Optional[str]
    tenant_custom_domain: Optional[str]


def session_from_callback(
    request: HttpRequest, callback_data: CallbackData, custom_fields: Optional[Dict[str, Any]] = None
) -> None:
    """
    Populate Django session from Wristband callback data.

    Automatically extracts core user and tenant info from callback data and
    stores it in the session. Optionally merges custom fields.

    Args:
        request: Django HttpRequest with session middleware enabled.
        callback_data: Callback data from wristband_auth.callback()
        custom_fields: Optional dict of additional fields to store (must be JSON-serializable)

    Raises:
        RuntimeError: If SessionMiddleware is not installed.
        ValueError: If request or callback_data is None, or if user_info is missing

    Example:
        from wristband.django_auth import session_from_callback

        callback_result = wristband_auth.callback(request)
        session_from_callback(request.session, callback_result.callback_data)

        # With custom fields
        session_from_callback(
            request.session,
            callback_result.callback_data,
            custom_fields={'role': 'admin', 'preferences': {'theme': 'dark'}}
        )

    Fields stored in session:
        - is_authenticated (always True)
        - access_token
        - expires_at
        - user_id
        - tenant_id
        - tenant_name
        - identity_provider_name
        - refresh_token (only if offline_access scope was requested)
        - tenant_custom_domain (only if present in callback data)
        - Any custom_fields provided
    """

    # Ensure SessionMiddleware has attached a session to the request
    if request is None:
        raise ValueError("request is required")
    if not hasattr(request, "session"):
        raise RuntimeError("Session not found. Ensure SessionMiddleware is registered in your app.")

    if callback_data is None:
        raise ValueError("callback_data is required")
    if not callback_data.user_info:
        raise ValueError("callback_data.user_info is required")

    # Build base session data from callback
    session: SessionBase = request.session
    session["is_authenticated"] = True
    session["access_token"] = callback_data.access_token
    session["expires_at"] = callback_data.expires_at
    session["user_id"] = callback_data.user_info.user_id
    session["tenant_id"] = callback_data.user_info.tenant_id
    session["tenant_name"] = callback_data.tenant_name
    session["identity_provider_name"] = callback_data.user_info.identity_provider_name

    # Only include optional fields if they have values
    if callback_data.refresh_token:
        session["refresh_token"] = callback_data.refresh_token
    if callback_data.tenant_custom_domain:
        session["tenant_custom_domain"] = callback_data.tenant_custom_domain

    # Merge custom fields if provided
    if custom_fields:
        session.update(custom_fields)

    # Mark session as modified to ensure Django saves it
    session.modified = True


def get_session_response(request: HttpRequest, metadata: Optional[Dict[str, Any]] = None) -> SessionResponse:
    """
    Create a session response for Wristband frontend SDKs.

    Extracts tenant_id and user_id from the session and returns them in the
    format expected by Wristband's frontend SDKs. Optionally includes custom metadata.

    Args:
        request: Django HttpRequest with session middleware enabled.
        metadata: Optional custom metadata to include (must be JSON-serializable).
                 Defaults to empty dict if not provided.

    Returns:
        SessionResponse instance with tenantId, userId, and metadata

    Raises:
        RuntimeError: If SessionMiddleware is not installed.
        ValueError: If request is None, or if tenant_id or user_id are missing from session

    Example:
        from wristband.django_auth import get_session_response
        from django.http import JsonResponse

        @require_auth
        def session_endpoint(request):
            response_data = get_session_response(request.session, metadata={'foo': 'bar'})
            response = JsonResponse(response_data)
            response['Cache-Control'] = 'no-store'
            response['Pragma'] = 'no-cache'
            return response

    Response format:
        {
            "tenantId": "tenant_abc123",
            "userId": "user_xyz789",
            "metadata": {"foo": "bar"}
        }
    """
    # Ensure SessionMiddleware has attached a session to the request
    if request is None:
        raise ValueError("request is required")
    if not hasattr(request, "session"):
        raise RuntimeError("Session not found. Ensure SessionMiddleware is registered in your app.")

    session: SessionBase = request.session
    tenant_id = session.get("tenant_id")
    user_id = session.get("user_id")

    if not tenant_id or not user_id:
        raise ValueError("Session must contain tenant_id and user_id")

    session_metadata = metadata if metadata is not None else {}

    return SessionResponse(tenant_id=tenant_id, user_id=user_id, metadata=session_metadata)


def get_token_response(request: HttpRequest) -> TokenResponse:
    """
    Create a token response for Wristband frontend SDKs.

    Extracts access_token and expires_at from the session and returns them in the
    format expected by Wristband's frontend SDKs.

    Args:
        request: Django HttpRequest with session middleware enabled.

    Returns:
        TokenResponse instance with accessToken and expiresAt

    Raises:
        RuntimeError: If SessionMiddleware is not installed.
        ValueError: If request is None, or if access_token or expires_at are missing from session

    Example:
        from wristband.django_auth import get_token_response
        from django.http import JsonResponse

        @require_auth
        def token_endpoint(request):
            response_data = get_token_response(request.session)
            response = JsonResponse(response_data)
            response['Cache-Control'] = 'no-store'
            response['Pragma'] = 'no-cache'
            return response

    Response format:
        {
            "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            "expiresAt": 1735689600000
        }
    """
    # Ensure SessionMiddleware has attached a session to the request
    if request is None:
        raise ValueError("request is required")
    if not hasattr(request, "session"):
        raise RuntimeError("Session not found. Ensure SessionMiddleware is registered in your app.")

    session: SessionBase = request.session
    access_token = session.get("access_token")
    expires_at = session.get("expires_at")

    if not access_token or not expires_at:
        raise ValueError("Session must contain access_token and expires_at")

    return TokenResponse(access_token=access_token, expires_at=expires_at)
