import base64
from unittest.mock import Mock, patch

import pytest
from requests.exceptions import HTTPError, RequestException

from wristband.django_auth.client import WristbandApiClient
from wristband.django_auth.exceptions import InvalidGrantError, WristbandError
from wristband.django_auth.models import TokenResponse


class TestWristbandApiClientInit:
    """Test cases for WristbandApiClient initialization."""

    def test_init_valid_parameters(self):
        """Test successful initialization with valid parameters."""
        domain = "auth.example.com"
        client_id = "test_client_id"
        client_secret = "test_client_secret"

        client = WristbandApiClient(domain, client_id, client_secret)

        assert client.base_url == f"https://{domain}/api/v1"

        # Verify Basic Auth header is correctly formatted
        expected_credentials = f"{client_id}:{client_secret}"
        expected_encoded = base64.b64encode(expected_credentials.encode("utf-8")).decode("utf-8")
        expected_auth_header = f"Basic {expected_encoded}"

        assert client.headers["Authorization"] == expected_auth_header
        assert client.headers["Content-Type"] == "application/x-www-form-urlencoded"

    def test_init_empty_domain_raises_valueerror(self):
        """Test that empty domain raises ValueError."""
        with pytest.raises(ValueError, match="Wristband application vanity domain is required"):
            WristbandApiClient("", "client_id", "client_secret")

    def test_init_whitespace_domain_raises_valueerror(self):
        """Test that whitespace-only domain raises ValueError."""
        with pytest.raises(ValueError, match="Wristband application vanity domain is required"):
            WristbandApiClient("   ", "client_id", "client_secret")

    def test_init_none_domain_raises_valueerror(self):
        """Test that None domain raises ValueError."""
        with pytest.raises(ValueError, match="Wristband application vanity domain is required"):
            WristbandApiClient(None, "client_id", "client_secret")

    def test_init_empty_client_id_raises_valueerror(self):
        """Test that empty client_id raises ValueError."""
        with pytest.raises(ValueError, match="Client ID is required"):
            WristbandApiClient("auth.example.com", "", "client_secret")

    def test_init_whitespace_client_id_raises_valueerror(self):
        """Test that whitespace-only client_id raises ValueError."""
        with pytest.raises(ValueError, match="Client ID is required"):
            WristbandApiClient("auth.example.com", "   ", "client_secret")

    def test_init_none_client_id_raises_valueerror(self):
        """Test that None client_id raises ValueError."""
        with pytest.raises(ValueError, match="Client ID is required"):
            WristbandApiClient("auth.example.com", None, "client_secret")

    def test_init_empty_client_secret_raises_valueerror(self):
        """Test that empty client_secret raises ValueError."""
        with pytest.raises(ValueError, match="Client secret is required"):
            WristbandApiClient("auth.example.com", "client_id", "")

    def test_init_whitespace_client_secret_raises_valueerror(self):
        """Test that whitespace-only client_secret raises ValueError."""
        with pytest.raises(ValueError, match="Client secret is required"):
            WristbandApiClient("auth.example.com", "client_id", "   ")

    def test_init_none_client_secret_raises_valueerror(self):
        """Test that None client_secret raises ValueError."""
        with pytest.raises(ValueError, match="Client secret is required"):
            WristbandApiClient("auth.example.com", "client_id", None)

    def test_init_base64_encoding(self):
        """Test that credentials are properly base64 encoded."""
        client_id = "test_id"
        client_secret = "test_secret"
        client = WristbandApiClient("auth.example.com", client_id, client_secret)

        # Manually encode to verify
        credentials = f"{client_id}:{client_secret}"
        expected_encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

        auth_header = client.headers["Authorization"]
        assert auth_header == f"Basic {expected_encoded}"

    def test_init_special_characters_in_credentials(self):
        """Test initialization with special characters in credentials."""
        client_id = "client@example.com"
        client_secret = "secret:with:colons&symbols!"

        client = WristbandApiClient("auth.example.com", client_id, client_secret)

        # Should not raise an exception and should encode properly
        assert "Authorization" in client.headers
        assert client.headers["Authorization"].startswith("Basic ")


class TestWristbandApiClientGetTokens:
    """Test cases for get_tokens method."""

    def setup_method(self):
        """Set up test client for each test."""
        self.client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

    @patch("wristband.django_auth.client.requests.post")
    def test_get_tokens_success(self, mock_post):
        """Test successful token exchange."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "access_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh_123",
            "id_token": "id_123",
            "scope": "openid email",
        }
        mock_post.return_value = mock_response

        result = self.client.get_tokens("auth_code", "https://app.com/callback", "code_verifier")

        # Verify the request was made correctly
        mock_post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/token",
            headers=self.client.headers,
            data={
                "grant_type": "authorization_code",
                "code": "auth_code",
                "redirect_uri": "https://app.com/callback",
                "code_verifier": "code_verifier",
            },
            timeout=15,
        )

        # Verify the result
        assert isinstance(result, TokenResponse)
        assert result.access_token == "access_123"
        assert result.refresh_token == "refresh_123"

    def test_get_tokens_empty_code_raises_valueerror(self):
        """Test that empty code raises ValueError."""
        with pytest.raises(ValueError, match="Authorization code is required"):
            self.client.get_tokens("", "https://app.com/callback", "code_verifier")

    def test_get_tokens_whitespace_code_raises_valueerror(self):
        """Test that whitespace-only code raises ValueError."""
        with pytest.raises(ValueError, match="Authorization code is required"):
            self.client.get_tokens("   ", "https://app.com/callback", "code_verifier")

    def test_get_tokens_none_code_raises_valueerror(self):
        """Test that None code raises ValueError."""
        with pytest.raises(ValueError, match="Authorization code is required"):
            self.client.get_tokens(None, "https://app.com/callback", "code_verifier")

    def test_get_tokens_empty_redirect_uri_raises_valueerror(self):
        """Test that empty redirect_uri raises ValueError."""
        with pytest.raises(ValueError, match="Redirect URI is required"):
            self.client.get_tokens("auth_code", "", "code_verifier")

    def test_get_tokens_whitespace_redirect_uri_raises_valueerror(self):
        """Test that whitespace-only redirect_uri raises ValueError."""
        with pytest.raises(ValueError, match="Redirect URI is required"):
            self.client.get_tokens("auth_code", "   ", "code_verifier")

    def test_get_tokens_none_redirect_uri_raises_valueerror(self):
        """Test that None redirect_uri raises ValueError."""
        with pytest.raises(ValueError, match="Redirect URI is required"):
            self.client.get_tokens("auth_code", None, "code_verifier")

    def test_get_tokens_empty_code_verifier_raises_valueerror(self):
        """Test that empty code_verifier raises ValueError."""
        with pytest.raises(ValueError, match="Code verifier is required"):
            self.client.get_tokens("auth_code", "https://app.com/callback", "")

    def test_get_tokens_whitespace_code_verifier_raises_valueerror(self):
        """Test that whitespace-only code_verifier raises ValueError."""
        with pytest.raises(ValueError, match="Code verifier is required"):
            self.client.get_tokens("auth_code", "https://app.com/callback", "   ")

    def test_get_tokens_none_code_verifier_raises_valueerror(self):
        """Test that None code_verifier raises ValueError."""
        with pytest.raises(ValueError, match="Code verifier is required"):
            self.client.get_tokens("auth_code", "https://app.com/callback", None)

    @patch("wristband.django_auth.client.requests.post")
    def test_get_tokens_invalid_grant_error(self, mock_post):
        """Test handling of invalid_grant error."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Authorization code has expired",
        }
        mock_post.return_value = mock_response

        with pytest.raises(InvalidGrantError) as exc_info:
            self.client.get_tokens("expired_code", "https://app.com/callback", "code_verifier")

        assert exc_info.value.get_error() == "invalid_grant"
        assert exc_info.value.get_error_description() == "Authorization code has expired"

    @patch("wristband.django_auth.client.requests.post")
    def test_get_tokens_invalid_grant_error_no_description(self, mock_post):
        """Test handling of invalid_grant error without description."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "invalid_grant"}
        mock_post.return_value = mock_response

        with pytest.raises(InvalidGrantError) as exc_info:
            self.client.get_tokens("expired_code", "https://app.com/callback", "code_verifier")

        assert exc_info.value.get_error() == "invalid_grant"
        assert exc_info.value.get_error_description() == "Invalid grant"

    @patch("wristband.django_auth.client.requests.post")
    def test_get_tokens_other_oauth_error(self, mock_post):
        """Test handling of other OAuth errors."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_client",
            "error_description": "Client authentication failed",
        }
        mock_post.return_value = mock_response

        with pytest.raises(WristbandError) as exc_info:
            self.client.get_tokens("auth_code", "https://app.com/callback", "code_verifier")

        assert exc_info.value.get_error() == "invalid_client"
        assert exc_info.value.get_error_description() == "Client authentication failed"

    @patch("wristband.django_auth.client.requests.post")
    def test_get_tokens_error_no_description(self, mock_post):
        """Test handling of OAuth error without description."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "invalid_request"}
        mock_post.return_value = mock_response

        with pytest.raises(WristbandError) as exc_info:
            self.client.get_tokens("auth_code", "https://app.com/callback", "code_verifier")

        assert exc_info.value.get_error() == "invalid_request"
        assert exc_info.value.get_error_description() == "Unknown error"

    @patch("wristband.django_auth.client.requests.post")
    def test_get_tokens_unknown_error_format(self, mock_post):
        """Test handling of unknown error format."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.json.return_value = {}
        mock_post.return_value = mock_response

        with pytest.raises(WristbandError) as exc_info:
            self.client.get_tokens("auth_code", "https://app.com/callback", "code_verifier")

        assert exc_info.value.get_error() == "unknown_error"
        assert exc_info.value.get_error_description() == "Unknown error"


class TestWristbandApiClientGetUserinfo:
    """Test cases for get_userinfo method."""

    def setup_method(self):
        """Set up test client for each test."""
        self.client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

    @patch("wristband.django_auth.client.requests.get")
    def test_get_userinfo_success(self, mock_get):
        """Test successful userinfo retrieval."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "sub": "user123",
            "email": "user@example.com",
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = self.client.get_userinfo("access_token_123")

        # Verify the request was made correctly
        mock_get.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/userinfo",
            headers={"Authorization": "Bearer access_token_123"},
            timeout=15,
        )
        mock_response.raise_for_status.assert_called_once()

        # Verify the result
        assert result["sub"] == "user123"
        assert result["email"] == "user@example.com"
        assert result["name"] == "Test User"

    @patch("wristband.django_auth.client.requests.get")
    def test_get_userinfo_http_error(self, mock_get):
        """Test handling of HTTP errors in userinfo."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = HTTPError("401 Client Error")
        mock_get.return_value = mock_response

        with pytest.raises(HTTPError):
            self.client.get_userinfo("invalid_token")

        mock_response.raise_for_status.assert_called_once()

    @patch("wristband.django_auth.client.requests.get")
    def test_get_userinfo_with_minimal_claims(self, mock_get):
        """Test userinfo with minimal claims."""
        mock_response = Mock()
        mock_response.json.return_value = {"sub": "user123"}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = self.client.get_userinfo("access_token_123")

        assert result["sub"] == "user123"
        assert len(result) == 1

    @patch("wristband.django_auth.client.requests.get")
    def test_get_userinfo_with_custom_claims(self, mock_get):
        """Test userinfo with custom claims."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "sub": "user123",
            "email": "user@example.com",
            "custom_role": "admin",
            "tenant_id": "tenant_456",
            "permissions": ["read", "write", "admin"],
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = self.client.get_userinfo("access_token_123")

        assert result["sub"] == "user123"
        assert result["custom_role"] == "admin"
        assert result["permissions"] == ["read", "write", "admin"]


class TestWristbandApiClientRefreshToken:
    """Test cases for refresh_token method."""

    def setup_method(self):
        """Set up test client for each test."""
        self.client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

    @patch("wristband.django_auth.client.requests.post")
    def test_refresh_token_success(self, mock_post):
        """Test successful token refresh."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new_refresh_123",
            "id_token": "new_id_123",
            "scope": "openid email",
        }
        mock_post.return_value = mock_response

        result = self.client.refresh_token("refresh_token_123")

        # Verify the request was made correctly
        mock_post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/token",
            headers=self.client.headers,
            data={"grant_type": "refresh_token", "refresh_token": "refresh_token_123"},
            timeout=15,
        )

        # Verify the result
        assert isinstance(result, TokenResponse)
        assert result.access_token == "new_access_123"
        assert result.refresh_token == "new_refresh_123"

    @patch("wristband.django_auth.client.requests.post")
    def test_refresh_token_invalid_grant_error(self, mock_post):
        """Test handling of invalid_grant error during refresh."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Refresh token is invalid or expired",
        }
        mock_post.return_value = mock_response

        with pytest.raises(InvalidGrantError) as exc_info:
            self.client.refresh_token("expired_refresh_token")

        assert exc_info.value.get_error() == "invalid_grant"
        assert exc_info.value.get_error_description() == "Refresh token is invalid or expired"

    @patch("wristband.django_auth.client.requests.post")
    def test_refresh_token_invalid_grant_no_description(self, mock_post):
        """Test handling of invalid_grant error without description."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "invalid_grant"}
        mock_post.return_value = mock_response

        with pytest.raises(InvalidGrantError) as exc_info:
            self.client.refresh_token("expired_refresh_token")

        assert exc_info.value.get_error_description() == "Invalid grant"

    @patch("wristband.django_auth.client.requests.post")
    def test_refresh_token_http_error_fallback(self, mock_post):
        """Test that HTTP errors are raised when not invalid_grant."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.json.return_value = {"error": "server_error", "error_description": "Internal server error"}
        mock_response.raise_for_status.side_effect = HTTPError("500 Server Error")
        mock_post.return_value = mock_response

        with pytest.raises(HTTPError):
            self.client.refresh_token("refresh_token_123")

        mock_response.raise_for_status.assert_called_once()

    @patch("wristband.django_auth.client.requests.post")
    def test_refresh_token_non_200_status_code(self, mock_post):
        """Test handling of non-200 status codes that aren't invalid_grant."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {
            "error": "invalid_client",
            "error_description": "Client authentication failed",
        }
        mock_response.raise_for_status.side_effect = HTTPError("401 Unauthorized")
        mock_post.return_value = mock_response

        with pytest.raises(HTTPError):
            self.client.refresh_token("refresh_token_123")


class TestWristbandApiClientRevokeRefreshToken:
    """Test cases for revoke_refresh_token method."""

    def setup_method(self):
        """Set up test client for each test."""
        self.client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

    @patch("wristband.django_auth.client.requests.post")
    def test_revoke_refresh_token_success(self, mock_post):
        """Test successful token revocation."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        # Should not raise any exception
        self.client.revoke_refresh_token("refresh_token_123")

        # Verify the request was made correctly
        mock_post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/revoke",
            headers=self.client.headers,
            data={"token": "refresh_token_123"},
            timeout=15,
        )
        mock_response.raise_for_status.assert_called_once()

    @patch("wristband.django_auth.client.requests.post")
    def test_revoke_refresh_token_http_error(self, mock_post):
        """Test handling of HTTP errors during revocation."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = HTTPError("400 Bad Request")
        mock_post.return_value = mock_response

        with pytest.raises(HTTPError):
            self.client.revoke_refresh_token("invalid_token")

        mock_response.raise_for_status.assert_called_once()

    @patch("wristband.django_auth.client.requests.post")
    def test_revoke_refresh_token_returns_none(self, mock_post):
        """Test that revoke_refresh_token returns None on success."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        result = self.client.revoke_refresh_token("refresh_token_123")

        assert result is None

    @patch("wristband.django_auth.client.requests.post")
    def test_revoke_refresh_token_with_empty_token(self, mock_post):
        """Test revocation with empty token (should still make request)."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        # Method doesn't validate token content, just passes it through
        self.client.revoke_refresh_token("")

        mock_post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/revoke",
            headers=self.client.headers, data={"token": ""},
            timeout=15,
        )


class TestWristbandApiClientIntegration:
    """Integration tests for WristbandApiClient methods working together."""

    def setup_method(self):
        """Set up test client for each test."""
        self.client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

    @patch("wristband.django_auth.client.requests.post")
    @patch("wristband.django_auth.client.requests.get")
    def test_full_oauth_flow_success(self, mock_get, mock_post):
        """Test complete OAuth flow: get tokens -> get userinfo -> refresh -> revoke."""
        # Setup mock responses
        token_response_data = {
            "access_token": "access_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh_123",
            "id_token": "id_123",
            "scope": "openid email",
        }

        userinfo_response_data = {"sub": "user123", "email": "user@example.com", "name": "Test User"}

        refresh_response_data = {
            "access_token": "new_access_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new_refresh_123",
            "id_token": "new_id_123",
            "scope": "openid email",
        }

        # Mock initial token exchange
        mock_token_response = Mock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = token_response_data

        # Mock userinfo request
        mock_userinfo_response = Mock()
        mock_userinfo_response.json.return_value = userinfo_response_data
        mock_userinfo_response.raise_for_status = Mock()

        # Mock token refresh
        mock_refresh_response = Mock()
        mock_refresh_response.status_code = 200
        mock_refresh_response.json.return_value = refresh_response_data

        # Mock token revocation
        mock_revoke_response = Mock()
        mock_revoke_response.raise_for_status = Mock()

        # Configure mocks based on call order
        mock_post.side_effect = [mock_token_response, mock_refresh_response, mock_revoke_response]
        mock_get.return_value = mock_userinfo_response

        # Execute the full flow
        # 1. Get initial tokens
        tokens = self.client.get_tokens("auth_code", "https://app.com/callback", "code_verifier")
        assert tokens.access_token == "access_123"
        assert tokens.refresh_token == "refresh_123"

        # 2. Get user info
        user_info = self.client.get_userinfo(tokens.access_token)
        assert user_info["sub"] == "user123"
        assert user_info["email"] == "user@example.com"

        # 3. Refresh tokens
        new_tokens = self.client.refresh_token(tokens.refresh_token)
        assert new_tokens.access_token == "new_access_123"
        assert new_tokens.refresh_token == "new_refresh_123"

        # 4. Revoke refresh token
        self.client.revoke_refresh_token(new_tokens.refresh_token)

        # Verify all calls were made
        assert mock_post.call_count == 3
        assert mock_get.call_count == 1

    def test_error_handling_consistency(self):
        """Test that error handling is consistent across methods."""
        # All methods should validate required parameters
        with pytest.raises(ValueError):
            self.client.get_tokens("", "uri", "verifier")

        with pytest.raises(ValueError):
            self.client.get_tokens("code", "", "verifier")

        with pytest.raises(ValueError):
            self.client.get_tokens("code", "uri", "")

    @patch("wristband.django_auth.client.requests.post")
    def test_base_url_construction(self, mock_post):
        """Test that base URL is constructed correctly for all endpoints."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh",
            "id_token": "id",
            "scope": "openid",
        }
        mock_post.return_value = mock_response

        # Test token endpoint
        self.client.get_tokens("code", "uri", "verifier")
        mock_post.assert_called_with(
            "https://auth.example.com/api/v1/oauth2/token",
            headers=self.client.headers,
            data={
                "grant_type": "authorization_code",
                "code": "code",
                "redirect_uri": "uri",
                "code_verifier": "verifier",
            },
            timeout=15,
        )

        # Test refresh endpoint (same URL)
        self.client.refresh_token("refresh_token")
        mock_post.assert_called_with(
            "https://auth.example.com/api/v1/oauth2/token",
            headers=self.client.headers,
            data={"grant_type": "refresh_token", "refresh_token": "refresh_token"},
            timeout=15,
        )

        # Test revoke endpoint
        mock_response.raise_for_status = Mock()
        self.client.revoke_refresh_token("refresh_token")
        mock_post.assert_called_with(
            "https://auth.example.com/api/v1/oauth2/revoke",
            headers=self.client.headers,
            data={"token": "refresh_token"},
            timeout=15,
        )

    @patch("wristband.django_auth.client.requests.get")
    def test_userinfo_endpoint_url(self, mock_get):
        """Test that userinfo endpoint URL is constructed correctly."""
        mock_response = Mock()
        mock_response.json.return_value = {"sub": "user123"}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        self.client.get_userinfo("access_token")

        mock_get.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/userinfo",
            headers={"Authorization": "Bearer access_token"},
            timeout=15,
        )

    def test_headers_consistency(self):
        """Test that headers are consistent across the client."""
        expected_auth_header = self.client.headers["Authorization"]
        expected_content_type = self.client.headers["Content-Type"]

        assert expected_auth_header.startswith("Basic ")
        assert expected_content_type == "application/x-www-form-urlencoded"

        # Headers should be the same instance used in requests
        assert len(self.client.headers) == 2


class TestWristbandApiClientEdgeCases:
    """Test edge cases and error conditions."""

    def setup_method(self):
        """Set up test client for each test."""
        self.client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

    @patch("wristband.django_auth.client.requests.post")
    def test_json_decode_error_handling(self, mock_post):
        """Test handling of invalid JSON responses."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_post.return_value = mock_response

        # Should raise the JSON decode error
        with pytest.raises(ValueError, match="Invalid JSON"):
            self.client.get_tokens("code", "uri", "verifier")

    @patch("wristband.django_auth.client.requests.post")
    def test_network_timeout_error(self, mock_post):
        """Test handling of network timeout errors."""
        mock_post.side_effect = RequestException("Connection timeout")

        with pytest.raises(RequestException, match="Connection timeout"):
            self.client.get_tokens("code", "uri", "verifier")

    @patch("wristband.django_auth.client.requests.post")
    def test_malformed_token_response(self, mock_post):
        """Test handling of malformed token response from TokenResponse.from_api_response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "token",
            # Missing required fields like token_type, expires_in, etc.
        }
        mock_post.return_value = mock_response

        # Should raise KeyError when TokenResponse.from_api_response tries to access missing fields
        with pytest.raises(KeyError):
            self.client.get_tokens("code", "uri", "verifier")

    @patch("wristband.django_auth.client.requests.get")
    def test_userinfo_json_decode_error(self, mock_get):
        """Test JSON decode error in userinfo endpoint."""
        mock_response = Mock()
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        with pytest.raises(ValueError, match="Invalid JSON"):
            self.client.get_userinfo("access_token")

    def test_client_immutability_of_headers(self):
        """Test that modifying returned headers doesn't affect the client."""
        original_headers = self.client.headers.copy()

        # Get a reference to headers and modify it
        headers_ref = self.client.headers
        headers_ref["X-Custom"] = "modified"

        # The client's headers should be modified (they're the same object)
        assert "X-Custom" in self.client.headers

        # But original expected headers should still be there
        assert self.client.headers["Authorization"] == original_headers["Authorization"]
        assert self.client.headers["Content-Type"] == original_headers["Content-Type"]

    @patch("wristband.django_auth.client.requests.post")
    def test_empty_error_response(self, mock_post):
        """Test handling of empty error response."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.json.return_value = {}
        mock_post.return_value = mock_response

        with pytest.raises(WristbandError) as exc_info:
            self.client.get_tokens("code", "uri", "verifier")

        assert exc_info.value.get_error() == "unknown_error"
        assert exc_info.value.get_error_description() == "Unknown error"

    @patch("wristband.django_auth.client.requests.post")
    def test_partial_error_response(self, mock_post):
        """Test handling of partial error response with only error field."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "invalid_request"}
        mock_post.return_value = mock_response

        with pytest.raises(WristbandError) as exc_info:
            self.client.get_tokens("code", "uri", "verifier")

        assert exc_info.value.get_error() == "invalid_request"
        assert exc_info.value.get_error_description() == "Unknown error"

    @patch("wristband.django_auth.client.requests.post")
    def test_error_response_with_null_values(self, mock_post):
        """Test handling of error response with null values."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": None, "error_description": None}
        mock_post.return_value = mock_response

        with pytest.raises(WristbandError) as exc_info:
            self.client.get_tokens("code", "uri", "verifier")

        assert exc_info.value.get_error() == "unknown_error"
        assert exc_info.value.get_error_description() == "Unknown error"

    def test_unicode_handling_in_credentials(self):
        """Test that unicode characters in credentials are handled properly."""
        client_id = "client_ñ_测试"
        client_secret = "secret_ñ_测试_🔑"

        client = WristbandApiClient("auth.example.com", client_id, client_secret)

        # Should encode without raising exceptions
        auth_header = client.headers["Authorization"]
        assert auth_header.startswith("Basic ")

        # Verify we can decode it back
        encoded_credentials = auth_header.replace("Basic ", "")
        decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
        assert decoded_credentials == f"{client_id}:{client_secret}"

    @patch("wristband.django_auth.client.requests.post")
    def test_refresh_token_with_unicode_token(self, mock_post):
        """Test refresh token with unicode characters."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "access_测试",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh_测试",
            "id_token": "id_测试",
            "scope": "openid",
        }
        mock_post.return_value = mock_response

        unicode_refresh_token = "refresh_token_测试_🔑"
        result = self.client.refresh_token(unicode_refresh_token)

        # Verify the unicode token was passed correctly
        mock_post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/token",
            headers=self.client.headers,
            data={"grant_type": "refresh_token", "refresh_token": unicode_refresh_token},
            timeout=15,
        )

        assert result.access_token == "access_测试"

    @patch("wristband.django_auth.client.requests.post")
    def test_very_long_token_handling(self, mock_post):
        """Test handling of very long tokens."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "a" * 2000,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "r" * 2000,
            "id_token": "i" * 2000,
            "scope": "openid",
        }
        mock_post.return_value = mock_response

        long_refresh_token = "x" * 1000
        result = self.client.refresh_token(long_refresh_token)

        assert len(result.access_token) == 2000
        assert len(result.refresh_token) == 2000

    @patch("wristband.django_auth.client.requests.get")
    def test_userinfo_with_complex_nested_data(self, mock_get):
        """Test userinfo with complex nested data structures."""
        complex_userinfo = {
            "sub": "user123",
            "email": "user@example.com",
            "address": {
                "street_address": "123 Main St",
                "locality": "Anytown",
                "region": "CA",
                "postal_code": "12345",
                "country": "US",
            },
            "groups": [
                {"id": "group1", "name": "Admins", "roles": ["admin", "user"]},
                {"id": "group2", "name": "Users", "roles": ["user"]},
            ],
            "custom_claims": {"tenant_id": "tenant123", "permissions": {"read": True, "write": True, "delete": False}},
        }

        mock_response = Mock()
        mock_response.json.return_value = complex_userinfo
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = self.client.get_userinfo("access_token")

        assert result["sub"] == "user123"
        assert result["address"]["street_address"] == "123 Main St"
        assert result["groups"][0]["roles"] == ["admin", "user"]
        assert result["custom_claims"]["permissions"]["read"] is True


class TestWristbandApiClientMockingBestPractices:
    """Test that demonstrates proper mocking patterns and edge cases."""

    def setup_method(self):
        """Set up test client for each test."""
        self.client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

    @patch("wristband.django_auth.client.requests")
    def test_requests_module_level_mocking(self, mock_requests):
        """Test mocking at the requests module level."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh",
            "id_token": "id",
            "scope": "openid",
        }
        mock_requests.post.return_value = mock_response

        result = self.client.get_tokens("code", "uri", "verifier")

        mock_requests.post.assert_called_once()
        assert result.access_token == "token"

    def test_client_state_isolation(self):
        """Test that multiple client instances don't interfere with each other."""
        client1 = WristbandApiClient("auth1.example.com", "client1", "secret1")
        client2 = WristbandApiClient("auth2.example.com", "client2", "secret2")

        assert client1.base_url != client2.base_url
        assert client1.headers["Authorization"] != client2.headers["Authorization"]

        # Modifying one shouldn't affect the other
        client1.headers["X-Custom"] = "test"
        assert "X-Custom" not in client2.headers

    @patch("wristband.django_auth.client.requests.post")
    def test_method_call_verification(self, mock_post):
        """Test comprehensive verification of method calls."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh",
            "id_token": "id",
            "scope": "openid",
        }
        mock_post.return_value = mock_response

        self.client.get_tokens("test_code", "https://test.com/callback", "test_verifier")

        # Verify exact call details
        args, kwargs = mock_post.call_args
        assert args[0] == "https://auth.example.com/api/v1/oauth2/token"
        assert kwargs["headers"] == self.client.headers
        assert kwargs["data"]["grant_type"] == "authorization_code"
        assert kwargs["data"]["code"] == "test_code"
        assert kwargs["data"]["redirect_uri"] == "https://test.com/callback"
        assert kwargs["data"]["code_verifier"] == "test_verifier"

    def test_comprehensive_parameter_validation(self):
        """Test all parameter validation scenarios comprehensively."""
        invalid_values = [None, "", "   ", "\t\n\r"]

        for invalid_value in invalid_values:
            with pytest.raises(ValueError, match="Authorization code is required"):
                self.client.get_tokens(invalid_value, "https://test.com", "verifier")

            with pytest.raises(ValueError, match="Redirect URI is required"):
                self.client.get_tokens("code", invalid_value, "verifier")

            with pytest.raises(ValueError, match="Code verifier is required"):
                self.client.get_tokens("code", "https://test.com", invalid_value)


class TestWristbandApiClientDocumentationExamples:
    """Test cases that match the examples in the documentation."""

    def setup_method(self):
        """Set up test client for each test."""
        self.client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

    @patch("wristband.django_auth.client.requests.post")
    @patch("wristband.django_auth.client.requests.get")
    def test_documentation_example_flow(self, mock_get, mock_post):
        """Test the exact flow shown in the class documentation."""
        # Setup responses as shown in documentation
        token_response = {
            "access_token": "access_token_from_docs",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh_token_from_docs",
            "id_token": "id_token_from_docs",
            "scope": "openid email",
        }

        userinfo_response = {"sub": "user123", "email": "user@example.com", "name": "Test User"}

        mock_token_resp = Mock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = token_response
        mock_post.return_value = mock_token_resp

        mock_userinfo_resp = Mock()
        mock_userinfo_resp.json.return_value = userinfo_response
        mock_userinfo_resp.raise_for_status = Mock()
        mock_get.return_value = mock_userinfo_resp

        # Execute the documented example flow
        tokens = self.client.get_tokens("auth_code", "redirect_uri", "code_verifier")
        user_info = self.client.get_userinfo(tokens.access_token)

        # Verify results match documentation
        assert tokens.access_token == "access_token_from_docs"
        assert user_info["sub"] == "user123"
        assert user_info["email"] == "user@example.com"

    @patch("wristband.django_auth.client.requests.post")
    def test_invalid_grant_documentation_example(self, mock_post):
        """Test the InvalidGrantError example from documentation."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Authorization code has expired",
        }
        mock_post.return_value = mock_response

        # This should match the documentation example
        with pytest.raises(InvalidGrantError) as exc_info:
            self.client.get_tokens("expired_code", "redirect_uri", "code_verifier")

        # Verify the error matches the documentation
        assert exc_info.value.get_error_description() == "Authorization code has expired"
