"""
Wristband API Client for token operations and user information retrieval.

This module provides a client for interacting with Wristband's endpoints, including
token exchange, user information retrieval, token refresh, and token revocation.
It handles authentication and error processing.
"""

import base64

import httpx

from .exceptions import InvalidGrantError, WristbandError
from .models import SdkConfiguration, TokenResponse, UserInfo


class WristbandApiClient:
    """
    HTTP client for interacting with Wristband APIs.

    This client handles all OAuth 2.0 operations including authorization code exchange,
    token refresh, user information retrieval, and token revocation. It automatically
    handles authentication using HTTP Basic Auth with client credentials and provides
    proper handling for error responses.

    The client is designed to work with Wristband's OAuth 2.0 implementation and
    follows RFC 6749 (OAuth 2.0) and RFC 7009 (Token Revocation) specifications.

    Attributes:
        base_url (str): The base URL for Wristband API endpoints.
        headers (dict[str, str]): Default headers including Authorization and Content-Type for API requests.
        client (httpx.Client): The httpx client instance for making requests.
    """

    def __init__(self, wristband_application_vanity_domain: str, client_id: str, client_secret: str) -> None:
        """
        Initialize the Wristband API client with client credentials.

        Creates an HTTP client configured for Wristband operations.
        The client uses HTTP Basic Authentication with the provided client credentials
        and sets up the base URL and default headers for API requests.

        Args:
            wristband_application_vanity_domain (str): The vanity domain for your
                Wristband application (e.g., "auth.yourdomain.com"). This should not
                include the protocol (https://) or path components.
            client_id (str): The OAuth 2.0 client identifier for your application.
                This is provided when you register your application with Wristband.
            client_secret (str): The OAuth 2.0 client secret for your application.
                This is a confidential credential and should be stored securely.

        Raises:
            ValueError: If any of the required parameters are None, empty, or whitespace-only.
        """
        if not wristband_application_vanity_domain or not wristband_application_vanity_domain.strip():
            raise ValueError("Wristband application vanity domain is required")
        if not client_id or not client_id.strip():
            raise ValueError("Client ID is required")
        if not client_secret or not client_secret.strip():
            raise ValueError("Client secret is required")

        credentials: str = f"{client_id}:{client_secret}"
        encoded_credentials: str = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

        self.client_id = client_id
        self.base_url: str = f"https://{wristband_application_vanity_domain}/api/v1"
        self.headers: dict[str, str] = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        # Initialize httpx client with default headers and timeout
        self.client = httpx.Client(headers=self.headers, timeout=15.0)

    def get_sdk_configuration(self) -> SdkConfiguration:
        """
        Retrieves the SDK configuration from Wristband's SDK Auto-Configuration Endpoint.

        Returns:
            SdkConfiguration: The SDK configuration containing auto-configurable values.

        Raises:
            WristbandError: If the request fails or returns an error response.
            httpx.HTTPStatusError: For HTTP errors during the request.
        """
        try:
            response = self.client.get(
                f"{self.base_url}/clients/{self.client_id}/sdk-configuration",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )

            response.raise_for_status()
            return SdkConfiguration.from_api_response(response.json())

        except Exception as e:
            raise WristbandError("unexpected_error", str(e))

    def get_tokens(self, code: str, redirect_uri: str, code_verifier: str) -> TokenResponse:
        """
        Exchange an authorization code for access, ID, and refresh tokens.

        Implements the authorization code grant flow (RFC 6749, Section 4.1) with
        PKCE support (RFC 7636). This method exchanges the authorization code received
        from the authorization server for an access token, refresh token, and ID token.

        This is called after the user has been redirected back from the
        Wristband with an authorization code in the callback URL.

        Args:
            code (str): The authorization code received from the authorization server.
                This code is extracted from the 'code' query parameter in
                the callback URL after the user authenticates.
            redirect_uri (str): The redirect URI that was used in the initial
                authorization request. This must exactly match the URI used in the
                authorization request for security purposes.
            code_verifier (str): The PKCE code verifier that corresponds to the
                code challenge sent in the initial authorization request. Used to
                prevent authorization code interception attacks.

        Returns:
            TokenResponse: An object containing the OAuth 2.0 tokens including:
                - access_token: Bearer token for API access
                - refresh_token: Token for refreshing the access token
                - id_token: JWT containing user identity information
                - expires_in: Token lifetime in seconds
                - token_type: Always "Bearer"
                - scope: Granted scopes

        Raises:
            ValueError: If any required parameter is None, empty, or whitespace-only.
            InvalidGrantError: If the authorization code is invalid, expired, already used,
                or doesn't match the redirect URI or client credentials.
            WristbandError: For all other errors

        See Also:
            RFC 6749 Section 4.1: https://tools.ietf.org/html/rfc6749#section-4.1
            RFC 7636 (PKCE): https://tools.ietf.org/html/rfc7636
        """
        if not code or not code.strip():
            raise ValueError("Authorization code is required")
        if not redirect_uri or not redirect_uri.strip():
            raise ValueError("Redirect URI is required")
        if not code_verifier or not code_verifier.strip():
            raise ValueError("Code verifier is required")

        response = self.client.post(
            self.base_url + "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
        )

        if response.status_code != 200:
            data = response.json()
            if data.get("error") == "invalid_grant":
                raise InvalidGrantError(data.get("error_description", "Invalid grant"))

            error = data.get("error") or "unknown_error"
            error_description = data.get("error_description") or "Unknown error"
            raise WristbandError(error, error_description)

        return TokenResponse.from_api_response(response.json())

    def get_userinfo(self, access_token: str) -> UserInfo:
        """
        Retrieve user information using a Wristband-issued access token.

        Calls the Wristband UserInfo endpoint to retrieve claims about the authenticated
        user. The returned information depends on the scopes that were granted during
        authorization (e.g., 'profile', 'email').

        This endpoint returns standardized claims as defined in OpenID Connect Core
        specification, along with any custom claims configured in your Wristband
        application.

        Args:
            access_token (str): A valid Wristband-issued access token with appropriate
                scopes for accessing user information. The token should have been
                obtained from get_tokens() or refresh_token().

        Returns:
            UserInfo: A dictionary containing user claims and information. Common
                claims include:
                - sub: Subject identifier (user ID)
                - email: User's email address (if 'email' scope granted)
                - name: User's full name (if 'profile' scope granted)
                - given_name: User's first name
                - family_name: User's last name
                - picture: URL to user's profile picture
                Additional custom claims may be present based on your configuration.

        Raises:
            httpx.HTTPStatusError: For any errors encountered during request.

        Note:
            The exact claims returned depend on:
            1. The scopes granted during authorization
            2. The user's profile completeness
            3. Your application's claim configuration in Wristband

        See Also:
            RFC 6749 Section 7: https://tools.ietf.org/html/rfc6749#section-7
            OpenID Connect UserInfo: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
        """
        response = self.client.get(
            self.base_url + "/oauth2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        return response.json()  # type: ignore[no-any-return]

    def refresh_token(self, refresh_token: str) -> TokenResponse:
        """
        Refresh an access token using a refresh token.

        Implements the refresh token grant flow (RFC 6749, Section 6) to obtain
        a new access token when the current one has expired. This allows maintaining
        user sessions without requiring re-authentication.

        The refresh operation may also return a new refresh token if refresh token rotation
        is enabled, in which case the old refresh token should be discarded.

        Args:
            refresh_token (str): A valid refresh token obtained from a previous
                token exchange or refresh operation. This token allows obtaining
                new access tokens without user interaction.

        Returns:
            TokenResponse: An object containing the new OAuth 2.0 tokens:
                - access_token: New bearer token for API access
                - refresh_token: New or existing refresh token
                - id_token: Updated JWT with current user information
                - expires_in: New token lifetime in seconds
                - token_type: Always "Bearer"
                - scope: Granted scopes

        Raises:
            InvalidGrantError: If the refresh token is invalid, expired, or revoked.
                Common scenarios include:
                - Refresh token has been revoked by the user
                - Refresh token has exceeded its maximum lifetime
                - Refresh token was issued to a different client
            httpx.HTTPStatusError: For all other errors during request.

        See Also:
            RFC 6749 Section 6: https://tools.ietf.org/html/rfc6749#section-6
        """
        response = self.client.post(
            self.base_url + "/oauth2/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        )

        if response.status_code != 200:
            data = response.json()
            if data.get("error") == "invalid_grant":
                raise InvalidGrantError(data.get("error_description", "Invalid grant"))

            # Raises for 4xx or 5xx
            response.raise_for_status()

        return TokenResponse.from_api_response(response.json())

    def revoke_refresh_token(self, refresh_token: str) -> None:
        """
        Revoke a refresh token to invalidate it and prevent further use.

        Implements OAuth 2.0 Token Revocation (RFC 7009) to immediately invalidate
        a refresh token. This is used during logout to ensure tokens cannot be reused,
        enhancing security by preventing token misuse if they are compromised.

        Revoking a refresh token will typically also invalidate any associated
        access tokens, effectively terminating the user's session across all
        applications using those tokens.

        Args:
            refresh_token (str): The refresh token to revoke. After successful
                revocation, this token will no longer be valid for refreshing
                access tokens.

        Returns:
            None: This method returns nothing on success. The refresh token is
                invalidated and should be removed from storage.

        Raises:
            httpx.HTTPStatusError: For any errors encountered during request.

        See Also:
            RFC 7009: https://tools.ietf.org/html/rfc7009
        """
        response = self.client.post(
            self.base_url + "/oauth2/revoke",
            data={"token": refresh_token},
        )
        response.raise_for_status()
