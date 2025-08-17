import base64
import hashlib
import logging
import secrets
import time
from datetime import datetime
from typing import Any, Literal, Optional, Union
from urllib.parse import urlencode

import httpx
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect

from .client import WristbandApiClient
from .exceptions import InvalidGrantError, WristbandError
from .models import (
    AuthConfig,
    CallbackData,
    CallbackResult,
    CallbackResultType,
    LoginConfig,
    LoginState,
    LogoutConfig,
    OAuthAuthorizeUrlConfig,
    TokenData,
    TokenResponse,
    UserInfo,
)
from .utils import SessionEncryptor

logger = logging.getLogger(__name__)


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
    _tenant_domain_token: str = "{tenant_domain}"
    _token_refresh_retries = 2
    _token_refresh_retry_timeout = 0.1  # 100ms

    def __init__(self, auth_config: AuthConfig) -> None:
        if not auth_config.client_id or not auth_config.client_id.strip():
            raise ValueError("The [client_id] config must have a value.")
        if not auth_config.client_secret or not auth_config.client_secret.strip():
            raise ValueError("The [client_secret] config must have a value.")
        if not (
            auth_config.wristband_application_vanity_domain
            or not auth_config.wristband_application_vanity_domain.strip()
        ):
            raise ValueError("The [wristband_application_vanity_domain] config must have a value.")
        if (
            not auth_config.login_state_secret
            or not auth_config.login_state_secret.strip()
            or len(auth_config.login_state_secret) < 32
        ):
            raise ValueError("The [login_state_secret] config must have a value of at least 32 characters.")
        if auth_config.token_expiration_buffer is not None and auth_config.token_expiration_buffer < 0:
            raise ValueError("The [token_expiration_buffer] config must be greater than or equal to 0.")
        if auth_config.parse_tenant_from_root_domain and auth_config.parse_tenant_from_root_domain.strip():
            if self._tenant_domain_token not in auth_config.login_url:
                raise ValueError(
                    "The [login_url] must contain the '{tenant_domain}' token when using "
                    "[parse_tenant_from_root_domain]."
                )
            if self._tenant_domain_token not in auth_config.redirect_uri:
                raise ValueError(
                    "The [redirect_uri] must contain the '{tenant_domain}' token when using "
                    "[parse_tenant_from_root_domain]."
                )
        else:
            if self._tenant_domain_token in auth_config.login_url:
                raise ValueError(
                    "The [login_url] cannot contain the '{tenant_domain}' token when "
                    "[parse_tenant_from_root_domain] is not set."
                )
            if self._tenant_domain_token in auth_config.redirect_uri:
                raise ValueError(
                    "The [redirect_uri] cannot contain the '{tenant_domain}' token when "
                    "[parse_tenant_from_root_domain] is not set."
                )

        self.config = auth_config
        self.wristband_api = WristbandApiClient(
            wristband_application_vanity_domain=auth_config.wristband_application_vanity_domain,
            client_id=auth_config.client_id,
            client_secret=auth_config.client_secret,
        )
        self._login_state_encryptor = SessionEncryptor(secret_key=auth_config.login_state_secret)

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
        - tenant_domain: The tenant's domain name. Used as a subdomain or vanity domain in the
          Authorize URL if not using tenant custom domains.

        Args:
            req (Request): The HTTP request object.
            config (LoginConfig, optional): Additional configuration for the login request,
                including default tenant domain and custom state.

        Returns:
            Response: An HTTP Response object that redirects the user to the Wristband
            Authorize endpoint.
        """
        # Determine tenant domain
        tenant_domain_name = self._resolve_tenant_domain_name(request)
        tenant_custom_domain = self._resolve_tenant_custom_domain_param(request)
        default_tenant_custom_domain: Optional[str] = config.default_tenant_custom_domain
        default_tenant_domain_name: Optional[str] = config.default_tenant_domain

        # In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
        if not any(
            [
                tenant_custom_domain,
                tenant_domain_name,
                default_tenant_custom_domain,
                default_tenant_domain_name,
            ]
        ):
            app_login_url = (
                self.config.custom_application_login_page_url
                or f"https://{self.config.wristband_application_vanity_domain}/login"
            )
            response = redirect(f"{app_login_url}?client_id={self.config.client_id}")
            response["Cache-Control"] = "no-store"
            response["Pragma"] = "no-cache"
            return response

        # Create login state
        login_state = self._create_login_state(request, config.custom_state)

        # Generate authorization URL
        authorize_url = self._get_oauth_authorize_url(
            request,
            oauthConfig=OAuthAuthorizeUrlConfig(
                login_state=login_state,
                default_tenant_custom_domain=default_tenant_custom_domain,
                default_tenant_domain_name=default_tenant_domain_name,
                tenant_custom_domain=tenant_custom_domain,
                tenant_domain_name=tenant_domain_name,
            ),
        )

        # Create redirect response
        response = redirect(authorize_url)
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"

        # Clear old cookies and create new login state cookie
        self._clear_oldest_login_state_cookie(request, response)
        encrypted_login_state = self._encrypt_login_state(login_state)
        self._create_login_state_cookie(response, login_state.state, encrypted_login_state)

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
        - tenant_domain: The tenant's domain name. Used when redirecting to the Login Endpoint in setups
          that don't rely on tenant subdomains or custom domains.

        Args:
            req (Request): The HTTP request object containing the callback query parameters.

        Returns:
            CallbackResult: An object representing the outcome of the callback process,
            including login state, user info, or redirect behavior.
        """
        # Extract and validate callback parameters
        code = self._assert_single_param(request, "code")
        param_state = self._assert_single_param(request, "state")
        error = self._assert_single_param(request, "error")
        error_description = self._assert_single_param(request, "error_description")
        tenant_custom_domain_param = self._assert_single_param(request, "tenant_custom_domain")

        if not param_state:
            raise TypeError("Invalid query parameter [state] passed from Wristband during callback")

        # Resolve and validate tenant domain name
        resolved_tenant_domain_name = self._resolve_tenant_domain_name(request)
        if not resolved_tenant_domain_name:
            if self.config.parse_tenant_from_root_domain:
                raise WristbandError("missing_tenant_subdomain", "Callback request URL is missing a tenant subdomain")
            else:
                raise WristbandError("missing_tenant_domain", "Callback request is missing the [tenant_domain] param")

        # Build the tenant login URL in case we need to redirect
        tenant_login_url = self._build_tenant_login_url(resolved_tenant_domain_name, tenant_custom_domain_param)
        redirect_required_result = CallbackResult(
            type=CallbackResultType.REDIRECT_REQUIRED,
            callback_data=None,
            redirect_url=tenant_login_url,
        )

        # Check if Wristband gave an error
        if error:
            # If we specifically got a 'login_required' error, go back to the login
            if error.lower() == "login_required":
                return redirect_required_result
            raise WristbandError(error, error_description or "")

        # Retrieve and decrypt the login state cookie
        _, login_state_cookie_val = self._get_login_state_cookie(request)

        # No valid cookie, we cannot verify the request
        if not login_state_cookie_val:
            return redirect_required_result

        login_state = self._decrypt_login_state(login_state_cookie_val)

        # Validate the state from the cookie matches the incoming state param
        if param_state != login_state.state:
            return redirect_required_result

        # Safety check (should never happen)
        if not code:
            raise ValueError("Invalid query parameter [code] passed from Wristband during callback")

        try:
            # Exchange code for tokens
            token_response: TokenResponse = self.wristband_api.get_tokens(
                code=code,
                redirect_uri=login_state.redirect_uri,
                code_verifier=login_state.code_verifier,
            )

            # Get user info
            userinfo: UserInfo = self.wristband_api.get_userinfo(token_response.access_token)

            # Calculate token expiry buffer
            expires_in = token_response.expires_in - (self.config.token_expiration_buffer or 0)
            expires_at = int((time.time() + expires_in) * 1000)

            return CallbackResult(
                type=CallbackResultType.COMPLETED,
                redirect_url=None,
                callback_data=CallbackData(
                    access_token=token_response.access_token,
                    id_token=token_response.id_token,
                    expires_in=expires_in,
                    expires_at=expires_at,
                    tenant_domain_name=resolved_tenant_domain_name,
                    user_info=userinfo,
                    custom_state=login_state.custom_state,
                    refresh_token=token_response.refresh_token,
                    return_url=login_state.return_url,
                    tenant_custom_domain=tenant_custom_domain_param,
                ),
            )
        except InvalidGrantError:
            return redirect_required_result
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
        if not redirect_url or not redirect_url.strip():
            raise TypeError("redirect_url cannot be null or empty")

        response = redirect(redirect_url)
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"

        # Clear login state cookie
        login_state_cookie_name, _ = self._get_login_state_cookie(request)
        if login_state_cookie_name:
            self._clear_login_state_cookie(response, login_state_cookie_name)

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
            such as a custom return URL or tenant domain.

        Returns:
            Response: An HTTP redirect response to Wristband's Logout Endpoint.
        """
        # Revoke refresh token if provided
        if config.refresh_token:
            try:
                self.wristband_api.revoke_refresh_token(config.refresh_token)
            except Exception as e:
                # No need to block logout execution if revoking fails
                logger.warning(f"Revoking refresh token failed during logout: {e}")

        # Get host and determine tenant domain
        tenant_domain_name = self._resolve_tenant_domain_name(request)
        tenant_custom_domain = self._resolve_tenant_custom_domain_param(request)

        # Build logout URL components
        separator = "." if self.config.is_application_custom_domain_active else "-"
        redirect_url = f"&redirect_url={config.redirect_url}" if config.redirect_url else ""
        logout_path = f"/api/v1/logout?client_id={self.config.client_id}{redirect_url}"

        # Create response
        response = redirect(request.build_absolute_uri())  # Temporary URL, will be overridden
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"

        # Domain priority order resolution
        # 1) If the LogoutConfig has a tenant custom domain explicitly defined, use that.
        if config.tenant_custom_domain and config.tenant_custom_domain.strip():
            response["Location"] = f"https://{config.tenant_custom_domain}{logout_path}"
            return response

        # 2) If the LogoutConfig has a tenant domain defined, then use that.
        if config.tenant_domain_name and config.tenant_domain_name.strip():
            response["Location"] = (
                f"https://{config.tenant_domain_name}{separator}"
                f"{self.config.wristband_application_vanity_domain}{logout_path}"
            )
            return response

        # 3) If the tenant_custom_domain query param exists, then use that.
        if tenant_custom_domain and tenant_custom_domain.strip():
            response["Location"] = f"https://{tenant_custom_domain}{logout_path}"
            return response

        # 4a) If tenant subdomains are enabled, get the tenant domain from the host.
        # 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_domain query param.
        if tenant_domain_name and tenant_domain_name.strip():
            response["Location"] = (
                f"https://{tenant_domain_name}{separator}"
                f"{self.config.wristband_application_vanity_domain}{logout_path}"
            )
            return response

        # Otherwise, fallback to app login URL (or custom logout redirect URL) if tenant cannot be determined.
        app_login_url = (
            self.config.custom_application_login_page_url
            or f"https://{self.config.wristband_application_vanity_domain}/login"
        )
        response["Location"] = config.redirect_url or f"{app_login_url}?client_id={self.config.client_id}"
        return response

    #################################
    #  REFRESH TOKEN IF EXPIRED
    #################################

    def refresh_token_if_expired(self, refresh_token: Optional[str], expires_at: Optional[int]) -> Optional[TokenData]:
        """
        Checks if the user's access token has expired and refreshes the token, if necessary.

        Args:
          refresh_token (Optional[str]): The refresh token used to obtain a new access token.
          expires_at (Optional[int]): Unix timestamp in milliseconds indicating when the current access token expires.

        Returns:
            TokenData | None: The refreshed token data if a new token was obtained, otherwise None.
        """
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
                token_response: TokenResponse = self.wristband_api.refresh_token(refresh_token)

                # Calculate token expiry buffer
                expires_in = token_response.expires_in - (self.config.token_expiration_buffer or 0)
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

    #################################
    #  HELPER METHODS
    #################################

    def _resolve_tenant_domain_name(self, request: HttpRequest) -> Optional[str]:
        """Resolve tenant domain from request"""
        if self.config.parse_tenant_from_root_domain and self.config.parse_tenant_from_root_domain.strip():
            host = request.get_host()

            if not host.endswith(self.config.parse_tenant_from_root_domain):
                return None

            subdomain = host[: -len(self.config.parse_tenant_from_root_domain)].rstrip(".")
            return subdomain if subdomain else None

        return self._assert_single_param(request, "tenant_domain")

    def _resolve_tenant_custom_domain_param(self, request: HttpRequest) -> Optional[str]:
        """Resolve tenant custom domain from request"""
        return self._assert_single_param(request, "tenant_custom_domain")

    def _assert_single_param(self, request: HttpRequest, param: str) -> Optional[str]:
        """Assert single query parameter"""
        values = request.GET.getlist(param)
        if len(values) > 1:
            raise TypeError(f"Duplicate query parameter [{param}] passed from Wristband during callback")
        return values[0] if values else None

    def _create_login_state(self, request: HttpRequest, custom_state: Optional[dict[str, Any]]) -> LoginState:
        """Create login state for OAuth flow"""
        return_url_list = request.GET.getlist("return_url")
        if len(return_url_list) > 1:
            raise TypeError("More than one [return_url] query parameter was encountered")

        return LoginState(
            state=self._generate_random_string(),
            code_verifier=self._generate_random_string(64),
            redirect_uri=self.config.redirect_uri,
            return_url=return_url_list[0] if return_url_list else None,
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

    def _get_oauth_authorize_url(self, request: HttpRequest, oauthConfig: OAuthAuthorizeUrlConfig) -> str:
        """Build OAuth authorization URL"""
        login_hint_list = request.GET.getlist("login_hint")
        if len(login_hint_list) > 1:
            raise TypeError("More than one [login_hint] query parameter was encountered")

        # Assemble necessary query params for authorization request
        query_params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "response_type": "code",
            "state": oauthConfig.login_state.state,
            "scope": " ".join(self.config.scopes),
            "code_challenge": self._generate_code_challenge(oauthConfig.login_state.code_verifier),
            "code_challenge_method": "S256",
            "nonce": self._generate_random_string(),
        }
        if login_hint_list:
            query_params["login_hint"] = login_hint_list[0]

        # Separator changes to a period if using an app-level custom domain with tenant subdomains
        separator: Union[Literal["."], Literal["-"]] = "." if self.config.is_application_custom_domain_active else "-"
        path_and_query: str = f"/api/v1/oauth2/authorize?{urlencode(query_params)}"

        # Domain priority order resolution:
        # 1)  tenant_custom_domain query param
        # 2a) tenant subdomain
        # 2b) tenant_domain query param
        # 3)  defaultTenantCustomDomain login config
        # 4)  defaultTenantDomainName login config
        if oauthConfig.tenant_custom_domain:
            return f"https://{oauthConfig.tenant_custom_domain}{path_and_query}"
        if oauthConfig.tenant_domain_name:
            return (
                f"https://{oauthConfig.tenant_domain_name}"
                f"{separator}{self.config.wristband_application_vanity_domain}"
                f"{path_and_query}"
            )
        if oauthConfig.default_tenant_custom_domain:
            return f"https://{oauthConfig.default_tenant_custom_domain}{path_and_query}"

        # By this point, we know the tenant domain name has already resolved properly, so just return the default.
        return (
            f"https://{oauthConfig.default_tenant_domain_name}"
            f"{separator}{self.config.wristband_application_vanity_domain}"
            f"{path_and_query}"
        )

    def _create_login_state_cookie(self, response: HttpResponse, state: str, encrypted_data: str) -> None:
        """Create login state cookie"""
        cookie_name = (
            f"{self._login_state_cookie_prefix}{state}" f"{self._login_state_cookie_separator}{int(time.time() * 1000)}"
        )
        response.set_cookie(
            key=cookie_name,
            value=encrypted_data,
            max_age=3600,
            path="/",
            secure=not self.config.dangerously_disable_secure_cookies,
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

    def _clear_login_state_cookie(self, response: HttpResponse, cookie_name: str) -> None:
        """Clear login state cookie"""
        response.set_cookie(
            key=cookie_name,
            value="",
            max_age=0,
            path="/",
            secure=not self.config.dangerously_disable_secure_cookies,
            httponly=True,
        )

    def _clear_oldest_login_state_cookie(self, request: HttpRequest, response: HttpResponse) -> None:
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
                        secure=not self.config.dangerously_disable_secure_cookies,
                        httponly=True,
                    )

    def _build_tenant_login_url(self, tenant_domain: str, tenant_custom_domain: Optional[str] = None) -> str:
        """Build tenant login URL"""
        if self.config.parse_tenant_from_root_domain and self.config.parse_tenant_from_root_domain.strip():
            tenant_login_url = self.config.login_url.replace("{tenant_domain}", tenant_domain)
        else:
            tenant_login_url = f"{self.config.login_url}?tenant_domain={tenant_domain}"

        # If the tenant_custom_domain is set, add that query param
        if tenant_custom_domain:
            # If we already used "?" above, use "&"" instead
            connector = "&" if "?" in tenant_login_url else "?"
            tenant_login_url = f"{tenant_login_url}{connector}tenant_custom_domain={tenant_custom_domain}"

        return tenant_login_url
