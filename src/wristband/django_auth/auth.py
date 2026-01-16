import base64
import hashlib
import logging
import re
import secrets
import time
from datetime import datetime
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable, List, Literal, Optional, Tuple, Type, Union, cast
from urllib.parse import quote, urlencode

import httpx
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect

from .client import WristbandApiClient
from .config_resolver import ConfigResolver
from .data_encryptor import DataEncryptor
from .exceptions import InvalidGrantError, WristbandError
from .models import (
    AuthConfig,
    AuthStrategy,
    CallbackData,
    CallbackFailureReason,
    CallbackResult,
    CompletedCallbackResult,
    JWTAuthConfig,
    JWTAuthResult,
    LoginConfig,
    LoginState,
    LogoutConfig,
    OAuthAuthorizeUrlConfig,
    RedirectRequiredCallbackResult,
    TokenData,
    UnauthenticatedBehavior,
    UserInfo,
    WristbandAuthMixin,
    WristbandTokenResponse,
)

if TYPE_CHECKING:
    from rest_framework.authentication import BaseAuthentication

_logger = logging.getLogger(__name__)


class WristbandAuth:
    """
    WristbandAuth provides methods for seamless interaction with Wristband for authenticating application users.
    It can handle the following:
    - Initiate a login request by redirecting to Wristband.
    - Receive callback requests from Wristband to complete a login request.
    - Retrive all necessary JWT tokens and userinfo to start an application session.
    - Logout a user from the application by revoking refresh tokens and redirecting to Wristband.
    - Checking for expired access tokens and refreshing them automatically, if necessary.
    """

    _login_state_cookie_prefix: str = "login#"
    _login_state_cookie_separator: str = "#"
    _return_url_char_max_len = 450
    _tenant_placeholder_pattern = re.compile(r"\{tenant_(?:domain|name)\}")
    _token_refresh_retries = 2
    _token_refresh_retry_timeout = 0.1  # 100ms

    def __init__(self, auth_config: AuthConfig) -> None:
        self._config_resolver = ConfigResolver(auth_config)
        self._wristband_api = WristbandApiClient(
            wristband_application_vanity_domain=self._config_resolver.get_wristband_application_vanity_domain(),
            client_id=self._config_resolver.get_client_id(),
            client_secret=self._config_resolver.get_client_secret(),
        )
        self._login_state_encryptor = DataEncryptor(secret_key=self._config_resolver.get_login_state_secret())

    #################################
    #  DISCOVER
    #################################

    def discover(self) -> None:
        """
        Immediately fetch and resolve all auto-configuration values from the Wristband SDK Configuration Endpoint.
        This is useful when you want to fail fast if auto-configuration is unavailable, or when you need configuration
        values resolved before making any auth method calls. Manual configuration values take precedence over
        auto-configured values.
        """
        if not self._config_resolver.get_auto_configure_enabled():
            raise WristbandError(
                "Cannot preload configs when auto_configure_enabled is false. " "Use create_wristband_auth() instead."
            )

        self._config_resolver.preload_sdk_config()

    #################################
    #  LOGIN
    #################################

    def login(self, request: HttpRequest, config: LoginConfig = LoginConfig()) -> HttpResponse:
        """
        Initiates a login request by redirecting to Wristband. Constructs an OAuth2 Authorization
        Request to begin the Authorization Code flow.

        The incoming HTTP request can include Wristband-specific query parameters:
        - login_hint: A hint about the user's preferred login identifier. This is passed as a query
          parameter in the redirect to the Authorize URL.
        - return_url: The URL to redirect the user to after authentication.
        - tenant_custom_domain: The tenant-specific custom domain, if applicable. Used as the domain
          for the Authorize URL when present.
        - tenant_name: The tenant's name. Used as a subdomain or vanity domain in the
          Authorize URL if not using tenant custom domains.

        Args:
            req (Request): The HTTP request object.
            config (LoginConfig, optional): Additional configuration for the login request,
                including default tenant name and custom state.

        Returns:
            Response: An HTTP Response object that redirects the user to the Wristband
            Authorize endpoint.
        """

        # Fetch our SDK configs
        client_id = self._config_resolver.get_client_id()
        custom_application_login_page_url = self._config_resolver.get_custom_application_login_page_url()
        dangerously_disable_secure_cookies = self._config_resolver.get_dangerously_disable_secure_cookies()
        is_application_custom_domain_active = self._config_resolver.get_is_application_custom_domain_active()
        parse_tenant_from_root_domain = self._config_resolver.get_parse_tenant_from_root_domain()
        redirect_uri = self._config_resolver.get_redirect_uri()
        scopes = self._config_resolver.get_scopes()
        wristband_application_vanity_domain = self._config_resolver.get_wristband_application_vanity_domain()

        # Determine tenant domain
        tenant_name = self._resolve_tenant_name(request, parse_tenant_from_root_domain)
        tenant_custom_domain = self._resolve_tenant_custom_domain_param(request)
        default_tenant_custom_domain: Optional[str] = config.default_tenant_custom_domain
        default_tenant_name: Optional[str] = config.default_tenant_name

        resovled_return_url: Optional[str] = self._resolve_return_url(request, config.return_url)

        # In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
        if not any([tenant_custom_domain, tenant_name, default_tenant_custom_domain, default_tenant_name]):
            app_login_url = custom_application_login_page_url or f"https://{wristband_application_vanity_domain}/login"
            state_param = f"&state={quote(resovled_return_url)}" if resovled_return_url else ""
            response = redirect(f"{app_login_url}?client_id={client_id}{state_param}")
            response["Cache-Control"] = "no-store"
            response["Pragma"] = "no-cache"
            return response

        # Create login state
        login_state = self._create_login_state(request, redirect_uri, config.custom_state, resovled_return_url)

        # Generate authorization URL
        authorize_url = self._get_oauth_authorize_url(
            request,
            config=OAuthAuthorizeUrlConfig(
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_verifier=login_state.code_verifier,
                scopes=scopes,
                state=login_state.state,
                default_tenant_custom_domain=default_tenant_custom_domain,
                default_tenant_name=default_tenant_name,
                tenant_custom_domain=tenant_custom_domain,
                tenant_name=tenant_name,
                is_application_custom_domain_active=is_application_custom_domain_active,
                wristband_application_vanity_domain=wristband_application_vanity_domain,
            ),
        )

        # Create redirect response
        response = redirect(authorize_url)
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"

        # Clear old cookies and create new login state cookie
        self._clear_oldest_login_state_cookie(request, response, dangerously_disable_secure_cookies)
        encrypted_login_state = self._encrypt_login_state(login_state)
        self._create_login_state_cookie(
            response, login_state.state, encrypted_login_state, dangerously_disable_secure_cookies
        )

        return response

    #################################
    #  CALLBACK
    #################################

    def callback(self, request: HttpRequest) -> CallbackResult:
        """
        Handles the OAuth2 callback from Wristband. Exchanges the authorization code for tokens
        and retrieves user information for the authenticated user.

        The incoming HTTP request can include Wristband-specific query parameters:
        - code: The authorization code returned from Wristband after a successful login.
        - error: An error identifier indicating a problem occurred during login.
        - error_description: A human-readable explanation of the error that occurred.
        - state: The original state value sent during the authorization request, used to validate the response.
        - tenant_custom_domain: The tenant's custom domain, if defined. If a redirect to the Login Endpoint
          is needed, this value should be passed along in the redirect.
        - tenant_name: The tenant's name. Used when redirecting to the Login Endpoint in setups
          that don't rely on tenant subdomains or custom domains.

        Args:
            request (Request): The HTTP request object containing the callback query parameters.

        Returns:
            CallbackResult: A union type representing the outcome of the callback process:
                - CompletedCallbackResult: Contains callback_data for creating an authenticated session.
                - RedirectRequiredCallbackResult: Contains redirect_url and reason when callback fails
                  and requires redirecting to login to retry authentication.

            Use isinstance() to determine which result type was returned:
                if isinstance(result, CompletedCallbackResult):
                    # Success - use result.callback_data
                elif isinstance(result, RedirectRequiredCallbackResult):
                    # Failure - redirect to result.redirect_url
        """

        # Fetch our SDK configs
        login_url = self._config_resolver.get_login_url()
        parse_tenant_from_root_domain = self._config_resolver.get_parse_tenant_from_root_domain()
        token_expiration_buffer = self._config_resolver.get_token_expiration_buffer()

        # Extract and validate callback parameters
        code = self._assert_single_param(request, "code")
        param_state = self._assert_single_param(request, "state")
        error = self._assert_single_param(request, "error")
        error_description = self._assert_single_param(request, "error_description")
        tenant_custom_domain_param = self._assert_single_param(request, "tenant_custom_domain")

        if not param_state:
            raise TypeError("Invalid query parameter [state] passed from Wristband during callback")

        # Resolve and validate tenant name
        resolved_tenant_name = self._resolve_tenant_name(request, parse_tenant_from_root_domain)
        if not resolved_tenant_name:
            if parse_tenant_from_root_domain:
                raise WristbandError("missing_tenant_subdomain", "Callback request URL is missing a tenant subdomain")
            else:
                raise WristbandError("missing_tenant_name", "Callback request is missing the [tenant_name] param")

        # Build the tenant login URL in case we need to redirect
        tenant_login_url = self._build_tenant_login_url(
            login_url=login_url,
            tenant_name=resolved_tenant_name,
            tenant_custom_domain=tenant_custom_domain_param,
            parse_tenant_from_root_domain=parse_tenant_from_root_domain,
        )

        # Check if Wristband gave an error
        if error:
            # If we specifically got a 'login_required' error, go back to the login
            if error.lower() == "login_required":
                return RedirectRequiredCallbackResult(
                    redirect_url=tenant_login_url,
                    reason=CallbackFailureReason.LOGIN_REQUIRED,
                )
            raise WristbandError(error, error_description or "")

        # Retrieve and decrypt the login state cookie
        _, login_state_cookie_val = self._get_login_state_cookie(request)

        # No valid cookie, we cannot verify the request
        if not login_state_cookie_val:
            return RedirectRequiredCallbackResult(
                redirect_url=tenant_login_url,
                reason=CallbackFailureReason.MISSING_LOGIN_STATE,
            )

        login_state = self._decrypt_login_state(login_state_cookie_val)

        # Validate the state from the cookie matches the incoming state param
        if param_state != login_state.state:
            return RedirectRequiredCallbackResult(
                redirect_url=tenant_login_url,
                reason=CallbackFailureReason.INVALID_LOGIN_STATE,
            )

        # Safety check (should never happen)
        if not code:
            raise ValueError("Invalid query parameter [code] passed from Wristband during callback")

        try:
            # Exchange code for tokens
            token_response: WristbandTokenResponse = self._wristband_api.get_tokens(
                code=code,
                redirect_uri=login_state.redirect_uri,
                code_verifier=login_state.code_verifier,
            )

            # Get user info
            userinfo: UserInfo = self._wristband_api.get_userinfo(token_response.access_token)

            # Calculate token expiry buffer
            expires_in = token_response.expires_in - (token_expiration_buffer or 0)
            expires_at = int((time.time() + expires_in) * 1000)

            return CompletedCallbackResult(
                callback_data=CallbackData(
                    access_token=token_response.access_token,
                    id_token=token_response.id_token,
                    expires_in=expires_in,
                    expires_at=expires_at,
                    tenant_name=resolved_tenant_name,
                    user_info=userinfo,
                    custom_state=login_state.custom_state,
                    refresh_token=token_response.refresh_token,
                    return_url=login_state.return_url,
                    tenant_custom_domain=tenant_custom_domain_param,
                )
            )
        except InvalidGrantError:
            return RedirectRequiredCallbackResult(
                redirect_url=tenant_login_url,
                reason=CallbackFailureReason.INVALID_GRANT,
            )
        except Exception as ex:
            raise ex

    #################################
    #  CREATE CALLBACK RESPONSE
    #################################

    def create_callback_response(self, request: HttpRequest, redirect_url: str) -> HttpResponse:
        """
        Constructs the redirect response to your application and cleans up the login state.

        Args:
            req (Request): The HTTP request object.
            redirect_url (str): The location for your application that you want to send users to.

        Returns:
            Response: The HTTP Response that is performing the URL redirect to your desired application URL.
        """

        # Fetch our SDK configs
        dangerously_disable_secure_cookies = self._config_resolver.get_dangerously_disable_secure_cookies()

        if not redirect_url or not redirect_url.strip():
            raise TypeError("redirect_url cannot be null or empty")

        response = redirect(redirect_url)
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"

        # Clear login state cookie
        login_state_cookie_name, _ = self._get_login_state_cookie(request)
        if login_state_cookie_name:
            self._clear_login_state_cookie(response, login_state_cookie_name, dangerously_disable_secure_cookies)

        return response

    #################################
    #  LOGOUT
    #################################

    def logout(self, request: HttpRequest, config: LogoutConfig = LogoutConfig()) -> HttpResponse:
        """
        Logs the user out by revoking their refresh token (if provided) and constructing a redirect
        URL to Wristband's Logout Endpoint.

        Args:
            request (HttpRequest): The HTTP request object containing user session or token data.
            config (LogoutConfig, optional): Optional configuration parameters for the logout process,
            such as a custom return URL or tenant name.

        Returns:
            Response: An HTTP redirect response to Wristband's Logout Endpoint.
        """

        # Fetch our SDK configs
        client_id = self._config_resolver.get_client_id()
        custom_application_login_page_url = self._config_resolver.get_custom_application_login_page_url()
        is_application_custom_domain_active = self._config_resolver.get_is_application_custom_domain_active()
        parse_tenant_from_root_domain = self._config_resolver.get_parse_tenant_from_root_domain()
        wristband_application_vanity_domain = self._config_resolver.get_wristband_application_vanity_domain()

        # Revoke refresh token if provided
        if config.refresh_token:
            try:
                self._wristband_api.revoke_refresh_token(config.refresh_token)
            except Exception as e:
                # No need to block logout execution if revoking fails
                _logger.debug(f"Revoking refresh token failed during logout: {e}")

        if config.state and len(config.state) > 512:
            raise ValueError("The [state] logout config cannot exceed 512 characters.")

        # Get host and determine tenant domain
        tenant_name = self._resolve_tenant_name(request, parse_tenant_from_root_domain)
        tenant_custom_domain = self._resolve_tenant_custom_domain_param(request)

        # Build logout URL components
        separator = "." if is_application_custom_domain_active else "-"
        redirect_url = f"&redirect_url={config.redirect_url}" if config.redirect_url else ""
        state = f"&state={config.state}" if config.state else ""
        logout_path = f"/api/v1/logout?client_id={client_id}{redirect_url}{state}"

        # Create response
        response = redirect(request.build_absolute_uri())  # Temporary URL, will be overridden
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"

        # Domain priority order resolution
        # 1) If the LogoutConfig has a tenant custom domain explicitly defined, use that.
        if config.tenant_custom_domain and config.tenant_custom_domain.strip():
            response["Location"] = f"https://{config.tenant_custom_domain}{logout_path}"
            return response

        # 2) If the LogoutConfig has a tenant name defined, then use that.
        if config.tenant_name and config.tenant_name.strip():
            response["Location"] = (
                f"https://{config.tenant_name}{separator}" f"{wristband_application_vanity_domain}{logout_path}"
            )
            return response

        # 3) If the tenant_custom_domain query param exists, then use that.
        if tenant_custom_domain and tenant_custom_domain.strip():
            response["Location"] = f"https://{tenant_custom_domain}{logout_path}"
            return response

        # 4a) If tenant subdomains are enabled, get the tenant name from the host.
        # 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_name query param.
        if tenant_name and tenant_name.strip():
            response["Location"] = (
                f"https://{tenant_name}{separator}" f"{wristband_application_vanity_domain}{logout_path}"
            )
            return response

        # Otherwise, fallback to app login URL (or custom logout redirect URL) if tenant cannot be determined.
        app_login_url = custom_application_login_page_url or f"https://{wristband_application_vanity_domain}/login"
        response["Location"] = config.redirect_url or f"{app_login_url}?client_id={client_id}"
        return response

    #################################
    #  REFRESH TOKEN IF EXPIRED
    #################################

    def refresh_token_if_expired(self, refresh_token: str, expires_at: int) -> Optional[TokenData]:
        """
        Checks if the user's access token has expired and refreshes the token, if necessary.

        Args:
          refresh_token (str): The refresh token used to obtain a new access token.
          expires_at (int): Unix timestamp in milliseconds indicating when the current access token expires.

        Returns:
            TokenData | None: The refreshed token data if a new token was obtained, otherwise None.
        """

        # Fetch our SDK configs
        token_expiration_buffer = self._config_resolver.get_token_expiration_buffer()

        if not refresh_token or not refresh_token.strip():
            raise TypeError("Refresh token must be a valid string")
        if not expires_at or expires_at < 0:
            raise TypeError("The expiresAt field must be an integer greater than 0")

        # Nothing to do here if the access token is still valid
        if expires_at > int(datetime.now().timestamp() * 1000):
            return None

        # Try up to 3 times to perform a token refresh
        for attempt in range(self._token_refresh_retries + 1):
            try:
                token_response: WristbandTokenResponse = self._wristband_api.refresh_token(refresh_token)

                # Calculate token expiry buffer
                expires_in = token_response.expires_in - (token_expiration_buffer or 0)
                expires_at = int((time.time() + expires_in) * 1000)

                return TokenData(
                    access_token=token_response.access_token,
                    id_token=token_response.id_token,
                    expires_in=expires_in,
                    expires_at=expires_at,
                    refresh_token=token_response.refresh_token,
                )
            except InvalidGrantError as e:
                # Do not retry, bail immediately
                raise e
            except httpx.HTTPStatusError as e:
                # Only 4xx errors should short-circuit the retry loop early.
                if e.response is not None and 400 <= e.response.status_code < 500:
                    try:
                        error_description = e.response.json().get("error_description", "Invalid Refresh Token")
                    except Exception:
                        error_description = "Invalid Refresh Token"
                    raise WristbandError("invalid_refresh_token", error_description)

                # On last attempt, raise the error.
                if attempt == self._token_refresh_retries:
                    raise WristbandError("unexpected_error", "Unexpected Error")

                # Wait before retrying.
                time.sleep(self._token_refresh_retry_timeout)
            except Exception:
                # Handle all other exceptions with retry logic. On last attempt, raise the error.
                if attempt == self._token_refresh_retries:
                    raise WristbandError("unexpected_error", "Unexpected Error")

                # Wait before retrying.
                time.sleep(self._token_refresh_retry_timeout)

        # Safety check that should never happen
        raise WristbandError("unexpected_error", "Unexpected Error")

    #####################################################
    #  CREATE AUTH DECORATOR
    #####################################################

    def create_auth_decorator(
        self,
        strategies: List[AuthStrategy],
        on_unauthenticated: UnauthenticatedBehavior = UnauthenticatedBehavior.JSON,
        jwt_config: Optional[JWTAuthConfig] = None,
    ) -> Callable[[Callable[..., HttpResponse]], Callable[..., HttpResponse]]:
        """
        Create a decorator that enforces authentication with specified strategies.

        This factory method creates a reusable decorator configured with your app's
        default authentication behavior. The decorator tries each strategy in order
        until one succeeds. Configuration is frozen at creation time. For different
        auth requirements, call this factory multiple times.

        Args:
            strategies: List of auth strategies to try in order.
            on_unauthenticated: What to do when user is not authenticated.
            jwt_config: Optional JWT configuration (only used if AuthStrategy.JWT in strategies)

        Returns:
            A decorator function that can be applied to Django views

        Example:
            # Create multiple decorators with different configs
            require_session = wristband_auth.create_auth_decorator(
                strategies=[AuthStrategy.SESSION],
                on_unauthenticated=UnauthenticatedBehavior.REDIRECT
            )

            require_jwt = wristband_auth.create_auth_decorator(
                strategies=[AuthStrategy.JWT],
                on_unauthenticated=UnauthenticatedBehavior.JSON
            )

            require_either = wristband_auth.create_auth_decorator(
                strategies=[AuthStrategy.SESSION, AuthStrategy.JWT]
            )

            # Use them
            @require_session
            def dashboard(request):
                return render(request, 'dashboard.html')

            @csrf_exempt
            @require_jwt
            @require_POST
            def api_endpoint(request):
                return JsonResponse({'data': '...'})
        """
        if not strategies:
            raise ValueError("At least one authentication strategy must be provided")

        self._validate_auth_decorator_config(strategies, on_unauthenticated)

        # Create validator once at decorator creation time if JWT strategy is used
        jwt_validator = None
        if AuthStrategy.JWT in strategies:
            jwt_validator = self._create_jwt_validator(jwt_config)

        def decorator(view_func: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
            return self._create_auth_wrapper(view_func, strategies, on_unauthenticated, jwt_validator)

        return decorator

    #####################################################
    #  CBV AUTHENTICATION MIXIN FACTORY METHOD
    #####################################################

    def create_auth_mixin(
        self,
        strategies: List[AuthStrategy],
        on_unauthenticated: UnauthenticatedBehavior = UnauthenticatedBehavior.REDIRECT,
        jwt_config: Optional[JWTAuthConfig] = None,
    ) -> Type[WristbandAuthMixin]:
        """
        Create a mixin for Django class-based views that enforces Wristband authentication.

        This factory method returns a mixin class that can be used with any Django CBV.
        Configuration is frozen at creation time. For different auth requirements,
        call this factory multiple times to create different mixins.

        Args:
            strategies: List of auth strategies to try in order.
            on_unauthenticated: What to do when user is not authenticated.
            jwt_config: Optional JWT configuration (only used if AuthStrategy.JWT in strategies)

        Returns:
            Mixin class for Django CBVs

        Example:
            # In your app's wristband.py configuration
            SessionAuthMixin: Type[WristbandAuthMixin] = wristband_auth.create_auth_mixin(
                strategies=[AuthStrategy.SESSION],
                on_unauthenticated=UnauthenticatedBehavior.REDIRECT
            )

            JWTAuthMixin: Type[WristbandAuthMixin] = wristband_auth.create_auth_mixin(
                strategies=[AuthStrategy.JWT],
                on_unauthenticated=UnauthenticatedBehavior.JSON
            )

            # Then import and use in your views
            from myapp.wristband import SessionAuthMixin

            class DashboardView(SessionAuthMixin, TemplateView):
                template_name = 'dashboard.html'

            class APIView(JWTAuthMixin, View):
                def get(self, request):
                    return JsonResponse({'status': 'ok'})

        Note:
            The mixin must be the leftmost class in the inheritance chain:
            CORRECT:   class MyView(SessionAuthMixin, TemplateView)
            INCORRECT: class MyView(TemplateView, SessionAuthMixin)
        """
        if not strategies:
            raise ValueError("At least one authentication strategy must be provided")

        self._validate_auth_decorator_config(strategies, on_unauthenticated)

        wristband_auth = self
        frozen_strategies = strategies
        frozen_on_unauthenticated = on_unauthenticated

        # Create validator once at mixin creation time if JWT strategy is used
        jwt_validator = None
        if AuthStrategy.JWT in frozen_strategies:
            jwt_validator = wristband_auth._create_jwt_validator(jwt_config)

        class WristbandAuthMixinImpl(WristbandAuthMixin):
            """
            Mixin for Django class-based views that enforces Wristband authentication.

            Configuration is frozen at mixin creation time.
            """

            def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
                """
                Override dispatch to check authentication before processing request.

                Tries each authentication strategy in order. If any succeeds,
                the request proceeds to the view. If all fail, handles based
                on on_unauthenticated setting.
                """
                # Ensure SessionMiddleware has attached a session to the request
                if AuthStrategy.SESSION in strategies and not hasattr(request, "session"):
                    raise RuntimeError("Session not found. Ensure SessionMiddleware is registered in your app.")

                # Try each strategy in order
                for strategy in frozen_strategies:
                    try:
                        if strategy == AuthStrategy.SESSION:
                            if wristband_auth._try_session_auth(request):
                                return super().dispatch(request, *args, **kwargs)

                        elif strategy == AuthStrategy.JWT:
                            if wristband_auth._try_jwt_auth(request, jwt_validator):
                                return super().dispatch(request, *args, **kwargs)

                    except Exception as e:
                        _logger.debug(f"{strategy.value} authentication failed: {e}")
                        continue

                # All strategies failed - handle based on on_unauthenticated
                if frozen_on_unauthenticated == UnauthenticatedBehavior.REDIRECT:
                    login_url = wristband_auth._config_resolver.get_login_url()
                    return redirect(login_url)
                else:  # JSON
                    return JsonResponse({"error": "Unauthorized"}, status=401)

        return WristbandAuthMixinImpl

    #####################################################
    #  DRF AUTHENTICATION FACTORY METHODS
    #####################################################

    def create_drf_session_auth(self) -> "type[BaseAuthentication]":
        """
        Create a DRF authentication class for session-based authentication.

        This factory method returns a DRF BaseAuthentication class configured to:
        - Validate Wristband sessions on every request
        - Automatically refresh expired access tokens
        - Preserve Django User if auth backend is enabled
        - Set request.user for IsAuthenticated permission

        Requires: pip install wristband-django[drf]

        Returns:
            DRF authentication class for session auth

        Raises:
            ImportError: If Django REST Framework is not installed

        Example:
            # In your app's wristband.py configuration
            from typing import Type
            from wristband.django_auth import WristbandDrfSessionAuth

            WristbandSessionAuth: Type[WristbandDrfSessionAuth] = wristband_auth.create_drf_session_auth()

            # Then import and use in your DRF views
            from myapp.wristband import WristbandSessionAuth
            from rest_framework.views import APIView
            from rest_framework.permissions import IsAuthenticated
            from rest_framework.response import Response

            class UserProfileView(APIView):
                authentication_classes = [WristbandSessionAuth]
                permission_classes = [IsAuthenticated]

                def get(self, request):
                    # Access session data
                    user_id = request.session['user_id']
                    tenant_name = request.session['tenant_name']

                    return Response({
                        'user_id': user_id,
                        'tenant': tenant_name
                    })
        """
        # Import DRF dependencies (raises ImportError if not installed)
        try:
            from rest_framework.authentication import BaseAuthentication
        except ImportError:
            raise ImportError(
                "Django REST Framework is required to use DRF authentication classes. "
                "Install it with: pip install wristband-django[drf]"
            )

        wristband_auth = self

        # Try to import Django auth at creation time
        try:
            from django.contrib.auth import get_user, get_user_model

            django_user_model = get_user_model()
        except (ImportError, Exception):
            django_user_model = None

        class WristbandDrfSessionAuth(BaseAuthentication):
            """
            Authenticate requests using Wristband session cookies.

            This authentication class:
            - Validates Wristband session on every request
            - Automatically refreshes expired access tokens
            - Refreshes CSRF tokens (if CSRF middleware active)
            - Preserves Django User if auth backend enabled
            - Sets lightweight user for IsAuthenticated if no Django User

            Data access:
                request.session['user_id']
                request.session['tenant_id']
                request.session['tenant_name']
                request.session['access_token']

            Permission class:
                permission_classes = [IsAuthenticated]
            """

            def authenticate(self, request: HttpRequest) -> Optional[Tuple[Any, None]]:
                """
                Authenticate the request using Wristband session.

                Returns:
                    tuple: (user, None) if authenticated, None if not
                """
                # ALWAYS revalidate Wristband session (includes token refresh)
                if not wristband_auth._try_session_auth(request):
                    return None  # Invalid or missing session

                # Valid session - preserve Django User if it exists
                if django_user_model is not None:
                    user = get_user(request)
                    if user and isinstance(user, django_user_model):
                        return (user, None)

                # No Django user - return lightweight authenticated user
                class WristbandUser:
                    is_authenticated = True

                return (WristbandUser(), None)

            def authenticate_header(self, request: HttpRequest) -> str:
                """
                Return WWW-Authenticate header value for 401 responses.

                Returns:
                    str: Authentication scheme name
                """
                return "Session"

        return WristbandDrfSessionAuth

    def create_drf_jwt_auth(self, jwt_config: Optional[JWTAuthConfig] = None) -> "type[BaseAuthentication]":
        """
        Create a DRF authentication class for JWT bearer token authentication.

        This factory method returns a DRF BaseAuthentication class configured to:
        - Validate Wristband JWTs from Authorization header
        - Preserve Django User only if JWT subject matches User ID
        - Set request.user for IsAuthenticated permission
        - Set request.auth with JWT payload

        Requires: pip install wristband-django[drf]

        Args:
            jwt_config: Optional JWT validation configuration

        Returns:
            DRF authentication class for JWT auth

        Raises:
            ImportError: If Django REST Framework is not installed

        Example:
            # In your app's wristband.py configuration
            from typing import Type
            from wristband.django_auth import WristbandDrfJwtAuth

            WristbandJwtAuth: Type[WristbandDrfJwtAuth] = wristband_auth.create_drf_jwt_auth()

            # Then import and use in your DRF views
            from myapp.wristband import WristbandJwtAuth
            from rest_framework.views import APIView
            from rest_framework.permissions import IsAuthenticated
            from rest_framework.response import Response

            class APIEndpoint(APIView):
                authentication_classes = [WristbandJwtAuth]
                permission_classes = [IsAuthenticated]

                def get(self, request):
                    # Access JWT claims via request.auth
                    user_id = request.auth.payload['sub']
                    tenant_id = request.auth.payload['tnt_id']

                    return Response({
                        'user_id': user_id,
                        'tenant_id': tenant_id
                    })
        """
        # Import DRF dependencies (raises ImportError if not installed)
        try:
            from rest_framework.authentication import BaseAuthentication
        except ImportError:
            raise ImportError(
                "Django REST Framework is required to use DRF authentication classes. "
                "Install it with: pip install wristband-django[drf]"
            )

        wristband_auth = self
        jwt_validator = self._create_jwt_validator(jwt_config)

        # EAFP: Try to import Django auth at creation time
        try:
            from django.contrib.auth import get_user, get_user_model

            django_user_model = get_user_model()
        except (ImportError, Exception):
            django_user_model = None

        class _WristbandDrfJwtAuthImpl(BaseAuthentication):
            """
            Authenticate requests using Wristband JWT bearer tokens.

            This authentication class:
            - Validates JWT from Authorization: Bearer <token> header
            - Checks JWT signature and expiration
            - Preserves Django User only if JWT sub matches User ID
            - Sets lightweight user for IsAuthenticated if no match
            - Sets request.auth with decoded JWT payload

            Data access:
                request.auth.payload['sub']
                request.auth.payload['tnt_id']
                request.auth.payload['app_id']
                request.auth.jwt  # Raw token string

            Permission class:
                permission_classes = [IsAuthenticated]
            """

            def authenticate(self, request: HttpRequest) -> Optional[Tuple[Any, JWTAuthResult]]:
                """
                Authenticate the request using Wristband JWT.

                Returns:
                    tuple: (user, auth) if authenticated, None if not
                """
                # Validate JWT and set request.auth
                if not wristband_auth._try_jwt_auth(request, jwt_validator):
                    return None  # No token or invalid

                # JWT valid - request.auth is now set with JWTAuthResult
                wb_user_id = request.auth.payload.get("sub")  # type: ignore[attr-defined]

                # Try to preserve Django User if username matches JWT sub
                if django_user_model is not None:
                    user = get_user(request)
                    if user and isinstance(user, django_user_model):
                        # Check if username matches (works with WristbandAuthBackend)
                        if getattr(user, "username", None) == wb_user_id:
                            return (user, request.auth)  # type: ignore[attr-defined]

                # Otherwise - return JWT-backed user
                class WristbandUser:
                    is_authenticated = True

                    def __init__(self, claims: dict[str, Any]) -> None:
                        self.claims = claims
                        self.id = claims.get("sub")

                return (WristbandUser(request.auth.payload), request.auth)  # type: ignore[attr-defined]

            def authenticate_header(self, request: HttpRequest) -> str:
                """
                Return WWW-Authenticate header value for 401 responses.

                Returns:
                    str: Authentication scheme with realm
                """
                return 'Bearer realm="api"'

        return _WristbandDrfJwtAuthImpl

    #################################
    #  HELPER METHODS
    #################################

    def _create_auth_wrapper(
        self,
        view_func: Callable[..., HttpResponse],
        strategies: List[AuthStrategy],
        on_unauthenticated: UnauthenticatedBehavior,
        jwt_validator: Any,
    ) -> Callable[..., HttpResponse]:
        """
        Create the actual wrapper function that performs authentication.

        This is separated from the decorator factory to handle both @decorator
        and @decorator(...) syntax cleanly.
        """

        @wraps(view_func)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            # Ensure SessionMiddleware has attached a session to the request
            if AuthStrategy.SESSION in strategies and not hasattr(request, "session"):
                raise RuntimeError("Session not found. Ensure SessionMiddleware is registered in your app.")

            # Try each strategy in order
            for strategy in strategies:
                try:
                    if strategy == AuthStrategy.SESSION:
                        if self._try_session_auth(request):
                            return view_func(request, *args, **kwargs)

                    elif strategy == AuthStrategy.JWT:
                        if self._try_jwt_auth(request, jwt_validator):
                            return view_func(request, *args, **kwargs)

                except Exception as e:
                    # Log but continue to next strategy
                    _logger.debug(f"{strategy.value} authentication failed: {e}")
                    continue

            # All strategies failed - handle based on on_unauthenticated
            if on_unauthenticated == UnauthenticatedBehavior.REDIRECT:
                login_url = self._config_resolver.get_login_url()
                return redirect(login_url)
            else:  # JSON
                return JsonResponse({"error": "Unauthorized"}, status=401)

        return wrapper

    def _try_session_auth(self, request: HttpRequest) -> bool:
        """
        Attempt session-based authentication.

        Returns True if a valid authenticated session is present; False otherwise.
        """
        from django.middleware.csrf import get_token

        # Check if user is authenticated
        if not request.session.get("is_authenticated", False):
            return False

        # Try to refresh tokens if possible (optional)
        refresh_token = request.session.get("refresh_token")
        expires_at = request.session.get("expires_at")
        if refresh_token is not None and expires_at is not None:
            try:
                # Update session with fresh tokens if a refresh occurred
                new_token_data: Optional[TokenData] = self.refresh_token_if_expired(refresh_token, expires_at)
                if new_token_data:
                    _logger.debug("Token refresh succeeded during session auth")
                    request.session["access_token"] = new_token_data.access_token
                    request.session["refresh_token"] = new_token_data.refresh_token
                    request.session["expires_at"] = new_token_data.expires_at

            except Exception as e:
                _logger.debug(f"Token refresh failed during session auth: {str(e)}")
                return False

        # Touch the session to update expiry (rolling session)
        request.session.modified = True

        # Refresh CSRF token if CsrfViewMiddleware is active (rolling session sync)
        middleware = getattr(settings, "MIDDLEWARE", [])
        if "django.middleware.csrf.CsrfViewMiddleware" in middleware:
            get_token(request)

        return True

    def _try_jwt_auth(self, request: HttpRequest, jwt_validator: Any) -> bool:
        """
        Attempt JWT bearer token authentication.

        Returns True if JWT is valid. Sets request.jwt_auth with both token and decoded JWT payload.
        """
        from wristband.python_jwt import JWTPayload, JwtValidationResult

        if not jwt_validator:
            raise RuntimeError("JWT Validator instance must be created for JWT auth strategy.")

        # Extract Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header:
            _logger.debug("JWT auth failed: Missing Authorization header")
            return False

        # Extract the Bearer token from the header
        token = jwt_validator.extract_bearer_token(auth_header)
        if not token:
            _logger.debug("JWT auth failed: Invalid Authorization header format. Expected 'Bearer <token>'")
            return False

        try:
            # Validate the JWT token
            result: JwtValidationResult = jwt_validator.validate(token)
            if not result.is_valid:
                _logger.debug("JWT auth failed: Invalid or expired token")
                return False

            # Cast payload to JWTPayload and attach to request
            payload = cast(JWTPayload, result.payload)
            setattr(request, "auth", JWTAuthResult(jwt=token, payload=payload))
            return True
        except Exception as e:
            _logger.debug(f"JWT validation failed: {e}")
            return False

    def _validate_auth_decorator_config(
        self, strategies: List[AuthStrategy], on_unauthenticated: UnauthenticatedBehavior
    ) -> None:
        """
        Validate decorator configuration parameters.

        Args:
            strategies: List of auth strategies to validate
            on_unauthenticated: Behavior to validate
        """

        if len(strategies) != len(set(strategies)):
            raise ValueError("Duplicate authentication strategies are not allowed")

        for strategy in strategies:
            if not isinstance(strategy, AuthStrategy):
                raise ValueError(f"Invalid authentication strategy: {strategy}")

        if not isinstance(on_unauthenticated, UnauthenticatedBehavior):
            raise ValueError(f"Invalid on_unauthenticated value: {on_unauthenticated}")

    def _create_jwt_validator(self, jwt_config: Optional[JWTAuthConfig]) -> Any:
        """
        Create a JWT validator with the given config.

        The validator is created once on first use and reused for all subsequent requests.
        """
        from wristband.python_jwt import WristbandJwtValidatorConfig, create_wristband_jwt_validator

        config = WristbandJwtValidatorConfig(
            wristband_application_vanity_domain=self._config_resolver.get_wristband_application_vanity_domain(),
            jwks_cache_max_size=jwt_config.jwks_cache_max_size if jwt_config else 20,
            jwks_cache_ttl=jwt_config.jwks_cache_ttl if jwt_config else None,
        )
        return create_wristband_jwt_validator(config)

    def _resolve_tenant_name(self, request: HttpRequest, parse_tenant_from_root_domain: Optional[str]) -> Optional[str]:
        """Resolve tenant name from request"""
        if parse_tenant_from_root_domain and parse_tenant_from_root_domain.strip():
            host = request.get_host()

            # Strip off the port if it exists
            hostname = host.split(":")[0]

            # Extract everything after the first dot
            if "." not in hostname:
                return None

            root_domain = hostname[hostname.index(".") + 1 :]

            # Check if the root domain matches
            if root_domain != parse_tenant_from_root_domain:
                return None

            # Extract subdomain (everything before the first dot)
            subdomain = hostname[: hostname.index(".")]
            return subdomain if subdomain else None

        return self._assert_single_param(request, "tenant_name")

    def _resolve_tenant_custom_domain_param(self, request: HttpRequest) -> Optional[str]:
        """Resolve tenant custom domain from request"""
        return self._assert_single_param(request, "tenant_custom_domain")

    def _assert_single_param(self, request: HttpRequest, param: str) -> Optional[str]:
        """Assert single query parameter"""
        values = request.GET.getlist(param)
        if len(values) > 1:
            raise TypeError(f"More than one instance of the query parameter [{param}] was present in the request")
        return values[0] if values else None

    def _resolve_return_url(self, request: HttpRequest, return_url: Optional[str] = None) -> Optional[str]:
        """Resolve return URL source (if any) and validate length"""
        return_url_list = request.GET.getlist("return_url")
        if len(return_url_list) > 1:
            raise TypeError("More than one [return_url] query parameter was encountered")

        # LoginConfig takes precedence over the request query param for return URLs.
        resolved_return_url = return_url or (return_url_list[0] if return_url_list else None)

        if resolved_return_url and len(resolved_return_url) > self._return_url_char_max_len:
            _logger.debug(f"Return URL exceeds {self._return_url_char_max_len} characters: {resolved_return_url}")
            return None

        return resolved_return_url

    def _create_login_state(
        self,
        request: HttpRequest,
        redirect_uri: str,
        custom_state: Optional[dict[str, Any]],
        return_url: Optional[str] = None,
    ) -> LoginState:
        """Create login state for OAuth flow"""
        return_url_list = request.GET.getlist("return_url")
        if len(return_url_list) > 1:
            raise TypeError("More than one [return_url] query parameter was encountered")

        # LoginConfig takes precedence over the request query param for return URLs.
        resolved_return_url = return_url or (return_url_list[0] if return_url_list else None)

        return LoginState(
            state=self._generate_random_string(),
            code_verifier=self._generate_random_string(64),
            redirect_uri=redirect_uri,
            return_url=resolved_return_url,
            custom_state=custom_state,
        )

    def _generate_random_string(self, length: int = 32) -> str:
        """Generate random string"""
        random_bytes = secrets.token_bytes(length)
        random_string = base64.urlsafe_b64encode(random_bytes).decode("utf-8")
        return random_string.rstrip("=")[:length]

    def _encrypt_login_state(self, login_state: LoginState) -> str:
        """Encrypt login state"""
        encrypted_str = self._login_state_encryptor.encrypt(login_state.to_dict())
        if len(encrypted_str.encode("utf-8")) > 4096:
            raise TypeError("Login state cookie exceeds 4kB in size.")
        return encrypted_str

    def _decrypt_login_state(self, login_state_cookie: str) -> LoginState:
        """Decrypt login state"""
        login_state_dict = self._login_state_encryptor.decrypt(login_state_cookie)
        return LoginState(**login_state_dict)

    def _generate_code_challenge(self, code_verifier: str) -> str:
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    def _get_oauth_authorize_url(self, request: HttpRequest, config: OAuthAuthorizeUrlConfig) -> str:
        """Build OAuth authorization URL"""
        login_hint_list = request.GET.getlist("login_hint")
        if len(login_hint_list) > 1:
            raise TypeError("More than one [login_hint] query parameter was encountered")

        # Assemble necessary query params for authorization request
        query_params = {
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "response_type": "code",
            "state": config.state,
            "scope": " ".join(config.scopes),
            "code_challenge": self._generate_code_challenge(config.code_verifier),
            "code_challenge_method": "S256",
            "nonce": self._generate_random_string(),
        }
        if login_hint_list:
            query_params["login_hint"] = login_hint_list[0]

        # Separator changes to a period if using an app-level custom domain with tenant subdomains
        separator: Union[Literal["."], Literal["-"]] = "." if config.is_application_custom_domain_active else "-"
        path_and_query: str = f"/api/v1/oauth2/authorize?{urlencode(query_params)}"

        # Domain priority order resolution:
        # 1)  tenant_custom_domain query param
        # 2a) tenant subdomain
        # 2b) tenant_name query param
        # 3)  defaultTenantCustomDomain login config
        # 4)  defaultTenantDomainName login config
        if config.tenant_custom_domain:
            return f"https://{config.tenant_custom_domain}{path_and_query}"
        if config.tenant_name:
            return (
                f"https://{config.tenant_name}"
                f"{separator}{config.wristband_application_vanity_domain}"
                f"{path_and_query}"
            )
        if config.default_tenant_custom_domain:
            return f"https://{config.default_tenant_custom_domain}{path_and_query}"

        # By this point, we know the tenant name has already resolved properly, so just return the default.
        return (
            f"https://{config.default_tenant_name}"
            f"{separator}{config.wristband_application_vanity_domain}"
            f"{path_and_query}"
        )

    def _create_login_state_cookie(
        self, response: HttpResponse, state: str, encrypted_data: str, dangerously_disable_secure_cookies: bool
    ) -> None:
        """Create login state cookie"""
        cookie_name = (
            f"{self._login_state_cookie_prefix}{state}" f"{self._login_state_cookie_separator}{int(time.time() * 1000)}"
        )
        response.set_cookie(
            key=cookie_name,
            value=encrypted_data,
            max_age=3600,
            path="/",
            secure=not dangerously_disable_secure_cookies,
            httponly=True,
            samesite="Lax",
        )

    def _get_login_state_cookie(self, request: HttpRequest) -> tuple[Optional[str], Optional[str]]:
        """Get login state cookie - returns (cookie_name, cookie_value)"""
        param_state = request.GET.get("state", "")
        cookie_prefix = f"{self._login_state_cookie_prefix}{param_state}{self._login_state_cookie_separator}"

        for cookie_name, cookie_value in request.COOKIES.items():
            if cookie_name.startswith(cookie_prefix):
                return cookie_name, cookie_value

        return None, None

    def _clear_login_state_cookie(
        self, response: HttpResponse, cookie_name: str, dangerously_disable_secure_cookies: bool
    ) -> None:
        """Clear login state cookie"""
        response.set_cookie(
            key=cookie_name,
            value="",
            max_age=0,
            path="/",
            secure=not dangerously_disable_secure_cookies,
            httponly=True,
        )

    def _clear_oldest_login_state_cookie(
        self, request: HttpRequest, response: HttpResponse, dangerously_disable_secure_cookies: bool
    ) -> None:
        """Clear oldest login state cookies if too many exist"""
        cookies = request.COOKIES
        login_cookie_names = [name for name in cookies if name.startswith(self._login_state_cookie_prefix)]

        if len(login_cookie_names) >= 3:
            timestamps = []
            for name in login_cookie_names:
                parts = name.split(self._login_state_cookie_separator)
                if len(parts) > 2:
                    timestamps.append(parts[2])

            # Keep the 2 newest timestamps
            newest_timestamps = sorted(timestamps, reverse=True)[:2]

            # Clear cookies that aren't in the newest 2
            for cookie_name in login_cookie_names:
                parts = cookie_name.split(self._login_state_cookie_separator)
                if len(parts) > 2 and parts[2] not in newest_timestamps:
                    response.set_cookie(
                        key=cookie_name,
                        value="",
                        max_age=0,
                        path="/",
                        secure=not dangerously_disable_secure_cookies,
                        httponly=True,
                    )

    def _build_tenant_login_url(
        self,
        login_url: str,
        tenant_name: str,
        tenant_custom_domain: Optional[str] = None,
        parse_tenant_from_root_domain: Optional[str] = None,
    ) -> str:
        """Build tenant login URL"""
        if parse_tenant_from_root_domain and parse_tenant_from_root_domain.strip():
            tenant_login_url = self._tenant_placeholder_pattern.sub(tenant_name, login_url)
        else:
            tenant_login_url = f"{login_url}?tenant_name={tenant_name}"

        # If the tenant_custom_domain is set, add that query param
        if tenant_custom_domain:
            # If we already used "?" above, use "&"" instead
            connector = "&" if "?" in tenant_login_url else "?"
            tenant_login_url = f"{tenant_login_url}{connector}tenant_custom_domain={tenant_custom_domain}"

        return tenant_login_url
