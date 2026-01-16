from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from django.http import HttpRequest, HttpResponse

if TYPE_CHECKING:
    from wristband.python_jwt import JWTPayload

########################################
# AUTH CONFIG MODELS
########################################


@dataclass
class AuthConfig:
    """
    Represents the configuration for Wristband authentication.

    Attributes:
        auto_configure_enabled: Flag that tells the SDK to automatically set some of the SDK configuration values by
            calling to Wristband's SDK Auto-Configuration Endpoint. Any manually provided configurations will take
            precedence over the configs returned from the endpoint. Auto-configure is enabled by default. When disabled,
            if manual configurations are not provided, then an error will be thrown.
        client_id: The client ID for the application.
        client_secret: The client secret for the application.
        login_state_secret: A secret (32 or more characters in length) used for encryption and decryption of login state
            cookies. If not provided, it will default to using the client secret. For enhanced security, it is
            recommended to provide a value that is unique from the client secret.
        login_url: The URL for initiating the login request.
        redirect_uri: The redirect URI for callback after authentication.
        wristband_application_vanity_domain: The vanity domain of the Wristband application.
        custom_application_login_page_url: Custom application login (tenant discovery) page URL
            if you are self-hosting the application login/tenant discovery UI.
        dangerously_disable_secure_cookies: If set to True, the "Secure" attribute will not be
            included in any cookie settings. This should only be done when testing in local
            development (if necessary).
        is_application_custom_domain_active: Indicates whether an application-level custom domain
            is active in your Wristband application.
        parse_tenant_from_root_domain: The root domain for your application from which to parse
            out the tenant name. Indicates whether tenant subdomains are used for authentication.
        scopes: The scopes required for authentication.
        token_expiration_buffer: Buffer time (in seconds) to subtract from the access token’s expiration time.
            This causes the token to be treated as expired before its actual expiration, helping to avoid token
            expiration during API calls.
    """

    client_id: str
    client_secret: str
    wristband_application_vanity_domain: str
    auto_configure_enabled: bool = True
    custom_application_login_page_url: Optional[str] = None
    dangerously_disable_secure_cookies: bool = False
    is_application_custom_domain_active: Optional[bool] = None
    login_state_secret: Optional[str] = None
    login_url: Optional[str] = None
    parse_tenant_from_root_domain: Optional[str] = None
    redirect_uri: Optional[str] = None
    scopes: List[str] = field(default_factory=lambda: ["openid", "offline_access", "email"])
    token_expiration_buffer: int = 60


@dataclass
class SdkConfiguration:
    """
    Represents the SDK configuration returned from Wristband's SDK Auto-Configuration Endpoint.

    Attributes:
        custom_application_login_page_url: Custom application login (tenant discovery) page URL if you are
            self-hosting the application login/tenant discovery UI.
        is_application_custom_domain_active: Indicates whether an application-level custom domain
            is active in your Wristband application.
        login_url: The URL for initiating the login request.
        login_url_tenant_domain_suffix: The tenant domain suffix for the login URL when using tenant subdomains.
        redirect_uri: The redirect URI for callback after authentication.
    """

    login_url: str
    redirect_uri: str
    is_application_custom_domain_active: bool
    custom_application_login_page_url: Optional[str] = None
    login_url_tenant_domain_suffix: Optional[str] = None

    @staticmethod
    def from_api_response(response: dict[str, Any]) -> "SdkConfiguration":
        """
        Creates an SdkConfiguration instance from an API response dictionary.

        Args:
            response: The raw API response containing SDK configuration data.

        Returns:
            An SdkConfiguration instance with the parsed configuration data.
        """
        return SdkConfiguration(
            login_url=response["loginUrl"],
            redirect_uri=response["redirectUri"],
            is_application_custom_domain_active=response.get("isApplicationCustomDomainActive", False),
            custom_application_login_page_url=response.get("customApplicationLoginPageUrl"),
            login_url_tenant_domain_suffix=response.get("loginUrlTenantDomainSuffix"),
        )


########################################
# LOGIN MODELS
########################################


@dataclass
class LoginState:
    """
    Represents all possible state for the current login request, which is stored in the login state cookie.

    Attributes:
        state: The state of the login process.
        code_verifier: The code verifier for PKCE.
        redirect_uri: The redirect URI for callback after authentication.
        return_url: The URL to return to after authentication.
        custom_state: Custom state data for the login state.
    """

    state: str
    code_verifier: str
    redirect_uri: str
    return_url: Optional[str]
    custom_state: Optional[dict[str, Any]]

    def to_dict(self) -> Dict[str, Union[str, Dict[str, str]]]:
        """
        Converts the LoginState instance to a dictionary representation.
        """
        return asdict(self)


@dataclass
class LoginConfig:
    """
    Represents the configuration for login.

    Attributes:
        custom_state: Custom state data for the login request.
        default_tenant_custom_domain: An optional default tenant custom domain to use for the
            login request in the event the tenant custom domain cannot be found in the
            "tenant_custom_domain" request query parameter.
        default_tenant_name: An optional default tenant name to use for the login
            request in the event the tenant name cannot be found in either the subdomain or
            the "tenant_name" request query parameter (depending on your subdomain configuration).
        return_url: The URL to return to after authentication is completed. If a value is provided,
            then it takes precence over the `return_url` request query parameter.
    """

    custom_state: Optional[dict[str, Any]] = None
    default_tenant_custom_domain: Optional[str] = None
    default_tenant_name: Optional[str] = None
    return_url: Optional[str] = None


@dataclass
class OAuthAuthorizeUrlConfig:
    """
    Represents the configuration for building OAuth authorization URLs.

    Attributes:
        client_id: The client ID for the application.
        code_verifier: The code verifier for PKCE (Proof Key for Code Exchange).
        redirect_uri: The redirect URI for callback after authentication.
        scopes: The scopes required for authentication.
        state: The state parameter for OAuth security.
        wristband_application_vanity_domain: The vanity domain of the Wristband application.
        default_tenant_custom_domain: An optional default tenant custom domain to use for the
            login request in the event the tenant custom domain cannot be found in the
            "tenant_custom_domain" request query parameter.
        default_tenant_name: An optional default tenant name to use for the
            login request in the event the tenant name cannot be found in either the subdomain
            or the "tenant_name" request query parameter (depending on your subdomain configuration).
        tenant_custom_domain: The tenant custom domain for the current login request.
        tenant_name: The domain name of the tenant for the current login request.
        is_application_custom_domain_active: Indicates whether an application-level custom domain
            is active in your Wristband application.
    """

    client_id: str
    code_verifier: str
    redirect_uri: str
    scopes: List[str]
    state: str
    wristband_application_vanity_domain: str
    default_tenant_custom_domain: Optional[str] = None
    default_tenant_name: Optional[str] = None
    tenant_custom_domain: Optional[str] = None
    tenant_name: Optional[str] = None
    is_application_custom_domain_active: Optional[bool] = False


########################################
# CALLBACK MODELS
########################################


class CallbackResultType(str, Enum):
    """
    Enum representing different possible results from the execution of the callback handler.

    Values:
        COMPLETED: Indicates that the callback is successfully completed and data is available
            for creating a session.
        REDIRECT_REQUIRED: Indicates that a redirect is required, generally to a login route or page.
    """

    COMPLETED = "completed"
    REDIRECT_REQUIRED = "redirect_required"


class CallbackFailureReason(str, Enum):
    """
    Reason why callback processing failed and requires a redirect to retry authentication.

    Attributes:
        MISSING_LOGIN_STATE: Login state cookie was not found (cookie expired or bookmarked callback URL)
        INVALID_LOGIN_STATE: Login state validation failed (possible CSRF attack or cookie tampering)
        LOGIN_REQUIRED: Wristband returned a login_required error (session expired or max_age elapsed)
        INVALID_GRANT: Authorization code was invalid, expired, or already used
    """

    MISSING_LOGIN_STATE = "missing_login_state"
    INVALID_LOGIN_STATE = "invalid_login_state"
    LOGIN_REQUIRED = "login_required"
    INVALID_GRANT = "invalid_grant"


@dataclass
class UserInfoRole:
    """
    User Info Role model.

    Represents a role assigned to a user in Wristband. This is a subset of the
    fields from the Role entity in Wristband's Resource Management API.

    Attributes:
        id (str): Globally unique ID of the role.
        name (str): The role name (e.g., "app:app-name:admin").
        display_name (str): The human-readable display name for the role.

    Serializes to:
        {
            "id": "x25rpgafgvgedcvjw52ooul3xm",
            "name": "app:app-name:admin",
            "displayName": "Admin Role"
        }
    """

    id: str
    name: str
    display_name: str

    @staticmethod
    def from_api_response(response: Dict[str, Any]) -> "UserInfoRole":
        """
        Creates a UserInfoRole instance from an API response dictionary.
        Handles the displayName -> display_name conversion.

        Args:
            response: The raw API response containing role data.

        Returns:
            A UserInfoRole instance with the parsed role data.
        """
        return UserInfoRole(
            id=response["id"],
            name=response["name"],
            display_name=response.get("displayName", response.get("display_name", "")),
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts the UserInfoRole instance to a dictionary with camelCase keys.

        Returns:
            A dictionary with displayName instead of display_name.
        """
        return {
            "id": self.id,
            "name": self.name,
            "displayName": self.display_name,
        }


@dataclass
class RawUserInfo:
    """
    Raw User Info model with original OIDC claim names.

    This internal model represents user information returned directly from
    Wristband's OIDC-compliant UserInfo endpoint using the original OIDC
    claim names. Use this model for internal SDK operations when working
    with the raw API response.

    For external/public use, use the UserInfo model which maps claim names
    to match Wristband's User entity field names.

    Attributes:
        sub (str): Subject identifier - ID of the user.
        tnt_id (str): Tenant ID.
        app_id (str): Application ID.
        idp_name (str): Identity provider name.
        name (Optional[str]): Full name.
        given_name (Optional[str]): Given/first name.
        family_name (Optional[str]): Family/last name.
        middle_name (Optional[str]): Middle name.
        nickname (Optional[str]): Nickname.
        preferred_username (Optional[str]): Preferred username.
        picture (Optional[str]): Profile picture URL.
        email (Optional[str]): Email address.
        email_verified (Optional[bool]): Email verification status.
        gender (Optional[str]): Gender.
        birthdate (Optional[str]): Birthdate in YYYY-MM-DD format.
        zoneinfo (Optional[str]): Time zone.
        locale (Optional[str]): Locale.
        phone_number (Optional[str]): Phone number.
        phone_number_verified (Optional[bool]): Phone verification status.
        updated_at (Optional[int]): Last update timestamp.
        roles (Optional[list[UserInfoRole]]): User roles.
        custom_claims (Optional[dict[str, Any]]): Custom claims.
    """

    # Always returned
    sub: str
    tnt_id: str
    app_id: str
    idp_name: str

    # Profile scope
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    middle_name: Optional[str] = None
    nickname: Optional[str] = None
    preferred_username: Optional[str] = None
    picture: Optional[str] = None
    gender: Optional[str] = None
    birthdate: Optional[str] = None
    zoneinfo: Optional[str] = None
    locale: Optional[str] = None
    updated_at: Optional[int] = None

    # Email scope
    email: Optional[str] = None
    email_verified: Optional[bool] = None

    # Phone scope
    phone_number: Optional[str] = None
    phone_number_verified: Optional[bool] = None

    # Roles scope
    roles: Optional[List[UserInfoRole]] = None

    # Custom claims
    custom_claims: Optional[Dict[str, Any]] = None

    @staticmethod
    def from_api_response(response: Dict[str, Any]) -> "RawUserInfo":
        """
        Creates a RawUserInfo instance from an API response dictionary.

        Args:
            response: The raw API response containing user info data.

        Returns:
            A RawUserInfo instance with the parsed user data.
        """
        # Parse roles if present
        roles = None
        if "roles" in response and response["roles"]:
            roles = [UserInfoRole.from_api_response(role) for role in response["roles"]]

        return RawUserInfo(
            sub=response["sub"],
            tnt_id=response["tnt_id"],
            app_id=response["app_id"],
            idp_name=response["idp_name"],
            name=response.get("name"),
            given_name=response.get("given_name"),
            family_name=response.get("family_name"),
            middle_name=response.get("middle_name"),
            nickname=response.get("nickname"),
            preferred_username=response.get("preferred_username"),
            picture=response.get("picture"),
            gender=response.get("gender"),
            birthdate=response.get("birthdate"),
            zoneinfo=response.get("zoneinfo"),
            locale=response.get("locale"),
            updated_at=response.get("updated_at"),
            email=response.get("email"),
            email_verified=response.get("email_verified"),
            phone_number=response.get("phone_number"),
            phone_number_verified=response.get("phone_number_verified"),
            roles=roles,
            custom_claims=response.get("custom_claims"),
        )


@dataclass
class UserInfo:
    """
    User Info model representing claims from the Wristband UserInfo endpoint.

    This model represents user information returned from Wristband's OIDC-compliant
    UserInfo endpoint, with field names mapped to match the User entity field names
    in Wristband's Resource Management API. The claims returned depend on the scopes
    requested during authorization.

    Always returned claims: user_id, tenant_id, application_id, identity_provider_name

    Scope-dependent claims:
    - profile: full_name, given_name, family_name, middle_name, nickname, display_name,
               picture_url, gender, birthdate, time_zone, locale, updated_at
    - email: email, email_verified
    - phone: phone_number, phone_number_verified
    - roles: roles

    Attributes:
        user_id (str): ID of the user (mapped from "sub" claim).
        tenant_id (str): ID of the tenant that the user belongs to (mapped from "tnt_id").
        application_id (str): ID of the application that the user belongs to (mapped from "app_id").
        identity_provider_name (str): Name of the identity provider (mapped from "idp_name").
        full_name (Optional[str]): End-User's full name in displayable form (mapped from "name").
        given_name (Optional[str]): Given name(s) or first name(s) of the End-User.
        family_name (Optional[str]): Surname(s) or last name(s) of the End-User.
        middle_name (Optional[str]): Middle name(s) of the End-User.
        nickname (Optional[str]): Casual name of the End-User.
        display_name (Optional[str]): Shorthand name by which the End-User wishes to be referred
                                      (mapped from "preferred_username").
        picture_url (Optional[str]): URL of the End-User's profile picture (mapped from "picture").
        email (Optional[str]): End-User's preferred email address.
        email_verified (Optional[bool]): True if the End-User's email address has been verified.
        gender (Optional[str]): End-User's gender.
        birthdate (Optional[str]): End-User's birthday in YYYY-MM-DD format.
        time_zone (Optional[str]): End-User's time zone (mapped from "zoneinfo").
        locale (Optional[str]): End-User's locale as BCP47 language tag (e.g., "en-US").
        phone_number (Optional[str]): End-User's telephone number in E.164 format.
        phone_number_verified (Optional[bool]): True if the End-User's phone number has been verified.
        updated_at (Optional[int]): Time the End-User's information was last updated (Unix timestamp).
        roles (Optional[list[UserInfoRole]]): The roles assigned to the user.
        custom_claims (Optional[dict[str, Any]]): Object containing any configured custom claims.

    Serializes to:
        {
            "userId": "x25rpgafgvgedcvjw52ooul3xm",
            "tenantId": "lu4a47jcm2ejayovsgbgbpkihb",
            "applicationId": "hblu4a47jcm2ejayovsgbgbpki",
            "identityProviderName": "Wristband",
            "fullName": "Bob Jay Smith",
            "givenName": "Bob",
            "familyName": "Smith",
            "email": "bob@example.com",
            "emailVerified": true,
            "roles": [
                {
                    "id": "x25rpgafgvgedcvjw52ooul3xm",
                    "name": "app:app-name:admin",
                    "displayName": "Admin Role"
                }
            ],
            "customClaims": {
                "fieldA": "a",
                "fieldB": "b"
            }
        }
    """

    # Always returned - mapped from OIDC standard claims
    user_id: str
    tenant_id: str
    application_id: str
    identity_provider_name: str

    # Profile scope - mapped to User entity field names
    full_name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    middle_name: Optional[str] = None
    nickname: Optional[str] = None
    display_name: Optional[str] = None
    picture_url: Optional[str] = None
    gender: Optional[str] = None
    birthdate: Optional[str] = None
    time_zone: Optional[str] = None
    locale: Optional[str] = None
    updated_at: Optional[int] = None

    # Email scope
    email: Optional[str] = None
    email_verified: Optional[bool] = None

    # Phone scope
    phone_number: Optional[str] = None
    phone_number_verified: Optional[bool] = None

    # Roles scope
    roles: Optional[List[UserInfoRole]] = None

    # Custom claims
    custom_claims: Optional[Dict[str, Any]] = None

    @staticmethod
    def from_raw_userinfo(raw: RawUserInfo) -> "UserInfo":
        """
        Creates a UserInfo instance from a RawUserInfo instance.
        Maps OIDC claim names to Wristband User entity field names.

        Args:
            raw: The RawUserInfo instance with OIDC claim names.

        Returns:
            A UserInfo instance with mapped field names.
        """
        return UserInfo(
            user_id=raw.sub,
            tenant_id=raw.tnt_id,
            application_id=raw.app_id,
            identity_provider_name=raw.idp_name,
            full_name=raw.name,
            given_name=raw.given_name,
            family_name=raw.family_name,
            middle_name=raw.middle_name,
            nickname=raw.nickname,
            display_name=raw.preferred_username,
            picture_url=raw.picture,
            gender=raw.gender,
            birthdate=raw.birthdate,
            time_zone=raw.zoneinfo,
            locale=raw.locale,
            updated_at=raw.updated_at,
            email=raw.email,
            email_verified=raw.email_verified,
            phone_number=raw.phone_number,
            phone_number_verified=raw.phone_number_verified,
            roles=raw.roles,
            custom_claims=raw.custom_claims,
        )

    @staticmethod
    def from_api_response(response: Dict[str, Any]) -> "UserInfo":
        """
        Creates a UserInfo instance from an API response dictionary.
        Accepts either camelCase (API format) or snake_case field names.

        Args:
            response: The raw API response containing user info data.

        Returns:
            A UserInfo instance with the parsed user data.
        """
        # Parse roles if present
        roles = None
        if "roles" in response and response["roles"]:
            roles = [UserInfoRole.from_api_response(role) for role in response["roles"]]

        return UserInfo(
            user_id=response.get("userId", response.get("user_id", "")),
            tenant_id=response.get("tenantId", response.get("tenant_id", "")),
            application_id=response.get("applicationId", response.get("application_id", "")),
            identity_provider_name=response.get("identityProviderName", response.get("identity_provider_name", "")),
            full_name=response.get("fullName", response.get("full_name")),
            given_name=response.get("givenName", response.get("given_name")),
            family_name=response.get("familyName", response.get("family_name")),
            middle_name=response.get("middleName", response.get("middle_name")),
            nickname=response.get("nickname"),
            display_name=response.get("displayName", response.get("display_name")),
            picture_url=response.get("pictureUrl", response.get("picture_url")),
            gender=response.get("gender"),
            birthdate=response.get("birthdate"),
            time_zone=response.get("timeZone", response.get("time_zone")),
            locale=response.get("locale"),
            updated_at=response.get("updatedAt", response.get("updated_at")),
            email=response.get("email"),
            email_verified=response.get("emailVerified", response.get("email_verified")),
            phone_number=response.get("phoneNumber", response.get("phone_number")),
            phone_number_verified=response.get("phoneNumberVerified", response.get("phone_number_verified")),
            roles=roles,
            custom_claims=response.get("customClaims", response.get("custom_claims")),
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts the UserInfo instance to a dictionary with camelCase keys.

        Returns:
            A dictionary in the API format with camelCase field names.
        """
        result: Dict[str, Any] = {
            "userId": self.user_id,
            "tenantId": self.tenant_id,
            "applicationId": self.application_id,
            "identityProviderName": self.identity_provider_name,
        }

        # Add optional fields only if they have values
        if self.full_name is not None:
            result["fullName"] = self.full_name
        if self.given_name is not None:
            result["givenName"] = self.given_name
        if self.family_name is not None:
            result["familyName"] = self.family_name
        if self.middle_name is not None:
            result["middleName"] = self.middle_name
        if self.nickname is not None:
            result["nickname"] = self.nickname
        if self.display_name is not None:
            result["displayName"] = self.display_name
        if self.picture_url is not None:
            result["pictureUrl"] = self.picture_url
        if self.gender is not None:
            result["gender"] = self.gender
        if self.birthdate is not None:
            result["birthdate"] = self.birthdate
        if self.time_zone is not None:
            result["timeZone"] = self.time_zone
        if self.locale is not None:
            result["locale"] = self.locale
        if self.updated_at is not None:
            result["updatedAt"] = self.updated_at
        if self.email is not None:
            result["email"] = self.email
        if self.email_verified is not None:
            result["emailVerified"] = self.email_verified
        if self.phone_number is not None:
            result["phoneNumber"] = self.phone_number
        if self.phone_number_verified is not None:
            result["phoneNumberVerified"] = self.phone_number_verified
        if self.roles is not None:
            result["roles"] = [role.to_dict() for role in self.roles]
        if self.custom_claims is not None:
            result["customClaims"] = self.custom_claims

        return result


@dataclass
class CallbackData:
    """
    Represents the callback data received after authentication.

    Attributes:
        access_token: The access token.
        id_token: The ID token.
        expires_in: The duration from the current time until the access token is expired (in seconds).
        expires_at: The absolute expiration time of the access token in milliseconds since Unix epoch
        tenant_name: The name of the tenant the user belongs to.
        user_info: User information received in the callback.
        custom_state: Custom state data received in the callback.
        refresh_token: The refresh token.
        return_url: The URL to return to after authentication.
        tenant_custom_domain: The tenant custom domain for the tenant that the user belongs to.
    """

    access_token: str
    id_token: str
    expires_at: int
    expires_in: int
    tenant_name: str
    user_info: UserInfo
    custom_state: Optional[dict[str, Any]] = None
    refresh_token: Optional[str] = None
    return_url: Optional[str] = None
    tenant_custom_domain: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """
        Converts the CallbackData instance to a dictionary representation.

        Returns:
            A dictionary containing all the callback data.
        """
        return asdict(self)


@dataclass
class TokenData:
    """
    Represents the token data received after authentication.

    Attributes:
        access_token: The access token.
        id_token: The ID token.
        expires_in: The duration from the current time until the access token is expired (in seconds).
        expires_at: The absolute expiration time of the access token in milliseconds since Unix epoch
        refresh_token: The refresh token.
    """

    access_token: str
    id_token: str
    expires_at: int
    expires_in: int
    refresh_token: str


@dataclass
class CompletedCallbackResult:
    """Callback successfully completed with data for creating a session."""

    type: CallbackResultType = field(default=CallbackResultType.COMPLETED, init=False)
    callback_data: CallbackData


@dataclass
class RedirectRequiredCallbackResult:
    """Redirect is required, generally to a login route or page."""

    type: CallbackResultType = field(default=CallbackResultType.REDIRECT_REQUIRED, init=False)
    redirect_url: str
    reason: CallbackFailureReason


# Union type for the result
CallbackResult = Union[CompletedCallbackResult, RedirectRequiredCallbackResult]
"""
Represents the result of the callback execution after authentication. It can include the set of
callback data necessary for creating an authenticated session in the event a redirect is not required.

Attributes:
    callback_data: The callback data received after authentication (COMPLETED only).
    type: Enum representing the end result of callback execution.
    redirect_url: The URL to redirect to (REDIRECT_REQUIRED only).
"""


@dataclass
class WristbandTokenResponse:
    """
    Represents the token response received from the Wristband token endpoint.

    Attributes:
        access_token: The access token.
        token_type: The type of token.
        expires_in: The expiration time of the access token (in seconds).
        refresh_token: The refresh token.
        id_token: The ID token.
        scope: The scope of the access token.
    """

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
    id_token: str
    scope: str

    @staticmethod
    def from_api_response(response: dict[str, Any]) -> "WristbandTokenResponse":
        """
        Creates a WristbandTokenResponse instance from an API response dictionary.
        """
        return WristbandTokenResponse(
            access_token=response["access_token"],
            token_type=response["token_type"],
            expires_in=response["expires_in"],
            refresh_token=response["refresh_token"],
            id_token=response["id_token"],
            scope=response["scope"],
        )


########################################
# LOGOUT MODELS
########################################


@dataclass
class LogoutConfig:
    """
    Represents the configuration for logout.

    Attributes:
        redirect_url: Optional URL that the logout endpoint will redirect to after completing
            the logout operation.
        refresh_token: The refresh token to revoke during logout.
        state: Optional value that will be appended as a query parameter to the resolved logout URL, if provided.
            This is used to preserve any desired state throughout the logout flow.
        tenant_custom_domain: The tenant custom domain for the tenant that the user belongs to
            (if applicable).
        tenant_name: The name of the tenant the user belongs to.
    """

    redirect_url: Optional[str] = None
    refresh_token: Optional[str] = None
    state: Optional[str] = None
    tenant_custom_domain: Optional[str] = None
    tenant_name: Optional[str] = None


########################################
# SESSION ENDPOINT MODELS
########################################


@dataclass
class SessionResponse:
    """
    Response model for session endpoints.

    This model is used to return session information including tenant ID, user ID,
    and any additional metadata associated with the session. The metadata field
    accepts a dictionary of JSON-serializable values. The response format
    matches what Wristband frontend SDKs expect for session endpoints.

    Serializes to:
        {
            "tenantId": "tenant_abc123",
            "userId": "user_xyz789",
            "metadata": {
                # your metadata JSON...
            }
        }

    Attributes:
        tenant_id (str): The tenant identifier for the authenticated user's organization.
        user_id (str): The unique identifier for the authenticated user.
        metadata (dict[str, Any]): Additional session data as key-value pairs. Values must be JSON-serializable.
    """

    tenant_id: str
    user_id: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict with camelCase keys for JSON response."""
        return {
            "tenantId": self.tenant_id,
            "userId": self.user_id,
            "metadata": self.metadata,
        }


########################################
# TOKEN ENDPOINT MODELS
########################################


@dataclass
class TokenResponse:
    """
    Token response model for the Token Endpoint.

    This model is used by applications to expose token data to Wristband frontend SDKs.

    Serializes to:
        {
            "accessToken": "eyJhbGc...",
            "expiresAt": 1234567890
        }

    Attributes:
        access_token: The JWT access token for authenticating API requests
        expires_at: Unix timestamp in milliseconds when the token expires
    """

    access_token: str
    expires_at: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict with camelCase keys for JSON response."""
        return {
            "accessToken": self.access_token,
            "expiresAt": self.expires_at,
        }


########################################
# AUTH MIDDLEWARE MODELS
########################################


class AuthStrategy(str, Enum):
    """
    Authentication strategies supported by the Wristband auth decorators and mixins.

    These strategies define how to validate user authentication:

    - SESSION: Validates authentication using Django session data containing Wristband tokens.
                Automatically refreshes expired access tokens using the refresh token (only if
                `refresh_token` and `expires_at` exists in session). This will also call Django's
                get_token() function if using Django's CSRF middleware in order to refresh the
                CSRF cookie expiration time (rolling sessions).

    - JWT: Validates authentication using a Wristband JWT bearer token from the Authorization
           header. This is does not use sessions or refresh tokens.

    Multiple strategies can be used together in a single decorator, tried in order
    until one succeeds (e.g., try SESSION first, then fallback to JWT).

    Example:
        # Using strings (accepted for convenience)
        @require_auth(strategies=['session'])
        @require_auth(strategies=['session', 'jwt'])

        # Using enums (provides type safety and autocomplete)
        @require_auth(strategies=[AuthStrategy.SESSION])
        @require_auth(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])
    """

    SESSION = "session"  # Validate via Django session with token refresh
    JWT = "jwt"  # Validate via JWT bearer token from Authorization header


class UnauthenticatedBehavior(str, Enum):
    """
    Defines how Wristband auth decorators and mixins respond when authentication fails.

    - REDIRECT: Redirects unauthenticated users to the login URL (configured in your Wristband
                SDK settings). Appropriate for browser-based page views where users can be
                redirected to a login page to authenticate.

    - JSON: Returns a 401 Unauthorized JSON response with an error message.
            Appropriate for API endpoints where the client (e.g., AJAX, mobile app)
            expects structured error responses instead of HTML redirects.

    Example:
        # Using strings (most common)
        @require_auth(on_unauthenticated='redirect')  # For page views
        @require_auth(on_unauthenticated='json')      # For APIs

        # Using enums (for type safety)
        @require_auth(on_unauthenticated=UnauthenticatedBehavior.REDIRECT)
        @require_auth(on_unauthenticated=UnauthenticatedBehavior.JSON)
    """

    REDIRECT = "redirect"  # Redirect to login URL
    JSON = "json"  # Return 401 JSON response


@dataclass
class JWTAuthConfig:
    """Configuration for JWT bearer token authentication."""

    jwks_cache_max_size: int = 20
    jwks_cache_ttl: Optional[int] = None  # None = infinite TTL


@dataclass
class JWTAuthResult:
    """
    JWT authentication data attached to request.wristband when JWT strategy succeeds.

    Attributes:
        jwt: Raw JWT token string from Authorization header
        payload: Decoded JWT payload with claims (sub, tnt_id, app_id, exp, etc.)
    """

    jwt: str
    payload: "JWTPayload"  # Forward reference (type checkers resolve it, runtime ignores it)


if TYPE_CHECKING:
    # For type checkers: WristbandAuthMixin is a class that can be subclassed
    class WristbandAuthMixin:
        """
        Nominal base class for Wristband auth mixin classes created by WristbandAuth.create_auth_mixin().

        Use this for type hints when storing mixin classes created by the factory method.
        The mixin intercepts dispatch() to enforce authentication before processing requests.
        """
        def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            """
            Intercept view dispatch to check authentication before processing request.
            """
            return super().dispatch(request, *args, **kwargs)  # type: ignore[misc,no-any-return]
else:
    # At runtime: just a marker for isinstance checks (optional)
    WristbandAuthMixin = object
