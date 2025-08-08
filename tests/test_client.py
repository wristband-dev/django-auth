import base64
from unittest.mock import Mock, patch

import httpx
import pytest

from wristband.django_auth.client import WristbandApiClient
from wristband.django_auth.exceptions import InvalidGrantError, WristbandError
from wristband.django_auth.models import TokenResponse


class TestWristbandApiClientInit:
    """Test cases for WristbandApiClient initialization."""

    @patch("wristband.django_auth.client.httpx.Client")
    def test_init_valid_parameters(self, mock_client_class):
        """Test successful initialization with valid parameters."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

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

        # Verify httpx.Client was called with correct parameters
        mock_client_class.assert_called_once_with(headers=client.headers, timeout=15.0)

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

    @patch("wristband.django_auth.client.httpx.Client")
    def test_init_base64_encoding(self, mock_client_class):
        """Test that credentials are properly base64 encoded."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client_id = "test_id"
        client_secret = "test_secret"
        client = WristbandApiClient("auth.example.com", client_id, client_secret)

        # Manually encode to verify
        credentials = f"{client_id}:{client_secret}"
        expected_encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

        auth_header = client.headers["Authorization"]
        assert auth_header == f"Basic {expected_encoded}"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_init_special_characters_in_credentials(self, mock_client_class):
        """Test initialization with special characters in credentials."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client_id = "client@example.com"
        client_secret = "secret:with:colons&symbols!"

        client = WristbandApiClient("auth.example.com", client_id, client_secret)

        # Should not raise an exception and should encode properly
        assert "Authorization" in client.headers
        assert client.headers["Authorization"].startswith("Basic ")


class TestWristbandApiClientGetTokens:
    """Test cases for get_tokens method."""

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_success(self, mock_client_class):
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

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")
        result = client.get_tokens("auth_code", "https://app.com/callback", "code_verifier")

        # Verify the request was made correctly
        mock_client_instance.post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": "auth_code",
                "redirect_uri": "https://app.com/callback",
                "code_verifier": "code_verifier",
            },
        )

        # Verify the result
        assert isinstance(result, TokenResponse)
        assert result.access_token == "access_123"
        assert result.refresh_token == "refresh_123"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_empty_code_raises_valueerror(self, mock_client_class):
        """Test that empty code raises ValueError."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(ValueError, match="Authorization code is required"):
            client.get_tokens("", "https://app.com/callback", "code_verifier")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_whitespace_code_raises_valueerror(self, mock_client_class):
        """Test that whitespace-only code raises ValueError."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(ValueError, match="Authorization code is required"):
            client.get_tokens("   ", "https://app.com/callback", "code_verifier")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_none_code_raises_valueerror(self, mock_client_class):
        """Test that None code raises ValueError."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(ValueError, match="Authorization code is required"):
            client.get_tokens(None, "https://app.com/callback", "code_verifier")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_empty_redirect_uri_raises_valueerror(self, mock_client_class):
        """Test that empty redirect_uri raises ValueError."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(ValueError, match="Redirect URI is required"):
            client.get_tokens("auth_code", "", "code_verifier")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_whitespace_redirect_uri_raises_valueerror(self, mock_client_class):
        """Test that whitespace-only redirect_uri raises ValueError."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(ValueError, match="Redirect URI is required"):
            client.get_tokens("auth_code", "   ", "code_verifier")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_none_redirect_uri_raises_valueerror(self, mock_client_class):
        """Test that None redirect_uri raises ValueError."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(ValueError, match="Redirect URI is required"):
            client.get_tokens("auth_code", None, "code_verifier")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_empty_code_verifier_raises_valueerror(self, mock_client_class):
        """Test that empty code_verifier raises ValueError."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(ValueError, match="Code verifier is required"):
            client.get_tokens("auth_code", "https://app.com/callback", "")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_whitespace_code_verifier_raises_valueerror(self, mock_client_class):
        """Test that whitespace-only code_verifier raises ValueError."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(ValueError, match="Code verifier is required"):
            client.get_tokens("auth_code", "https://app.com/callback", "   ")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_none_code_verifier_raises_valueerror(self, mock_client_class):
        """Test that None code_verifier raises ValueError."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(ValueError, match="Code verifier is required"):
            client.get_tokens("auth_code", "https://app.com/callback", None)

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_invalid_grant_error(self, mock_client_class):
        """Test handling of invalid_grant error."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Authorization code has expired",
        }

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(InvalidGrantError) as exc_info:
            client.get_tokens("expired_code", "https://app.com/callback", "code_verifier")

        assert exc_info.value.get_error() == "invalid_grant"
        assert exc_info.value.get_error_description() == "Authorization code has expired"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_invalid_grant_error_no_description(self, mock_client_class):
        """Test handling of invalid_grant error without description."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "invalid_grant"}

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(InvalidGrantError) as exc_info:
            client.get_tokens("expired_code", "https://app.com/callback", "code_verifier")

        assert exc_info.value.get_error() == "invalid_grant"
        assert exc_info.value.get_error_description() == "Invalid grant"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_other_oauth_error(self, mock_client_class):
        """Test handling of other OAuth errors."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_client",
            "error_description": "Client authentication failed",
        }

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(WristbandError) as exc_info:
            client.get_tokens("auth_code", "https://app.com/callback", "code_verifier")

        assert exc_info.value.get_error() == "invalid_client"
        assert exc_info.value.get_error_description() == "Client authentication failed"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_error_no_description(self, mock_client_class):
        """Test handling of OAuth error without description."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "invalid_request"}

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(WristbandError) as exc_info:
            client.get_tokens("auth_code", "https://app.com/callback", "code_verifier")

        assert exc_info.value.get_error() == "invalid_request"
        assert exc_info.value.get_error_description() == "Unknown error"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_tokens_unknown_error_format(self, mock_client_class):
        """Test handling of unknown error format."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.json.return_value = {}

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(WristbandError) as exc_info:
            client.get_tokens("auth_code", "https://app.com/callback", "code_verifier")

        assert exc_info.value.get_error() == "unknown_error"
        assert exc_info.value.get_error_description() == "Unknown error"


class TestWristbandApiClientGetUserinfo:
    """Test cases for get_userinfo method."""

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_userinfo_success(self, mock_client_class):
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

        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")
        result = client.get_userinfo("access_token_123")

        # Verify the request was made correctly
        mock_client_instance.get.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/userinfo",
            headers={"Authorization": "Bearer access_token_123"},
        )
        mock_response.raise_for_status.assert_called_once()

        # Verify the result
        assert result["sub"] == "user123"
        assert result["email"] == "user@example.com"
        assert result["name"] == "Test User"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_userinfo_http_error(self, mock_client_class):
        """Test handling of HTTP errors in userinfo."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401 Unauthorized", request=Mock(), response=mock_response
        )

        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(httpx.HTTPStatusError):
            client.get_userinfo("invalid_token")

        mock_response.raise_for_status.assert_called_once()

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_userinfo_with_minimal_claims(self, mock_client_class):
        """Test userinfo with minimal claims."""
        mock_response = Mock()
        mock_response.json.return_value = {"sub": "user123"}
        mock_response.raise_for_status = Mock()

        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")
        result = client.get_userinfo("access_token_123")

        assert result["sub"] == "user123"
        assert len(result) == 1

    @patch("wristband.django_auth.client.httpx.Client")
    def test_get_userinfo_with_custom_claims(self, mock_client_class):
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

        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")
        result = client.get_userinfo("access_token_123")

        assert result["sub"] == "user123"
        assert result["custom_role"] == "admin"
        assert result["permissions"] == ["read", "write", "admin"]


class TestWristbandApiClientRefreshToken:
    """Test cases for refresh_token method."""

    @patch("wristband.django_auth.client.httpx.Client")
    def test_refresh_token_success(self, mock_client_class):
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

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")
        result = client.refresh_token("refresh_token_123")

        # Verify the request was made correctly
        mock_client_instance.post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/token",
            data={"grant_type": "refresh_token", "refresh_token": "refresh_token_123"},
        )

        # Verify the result
        assert isinstance(result, TokenResponse)
        assert result.access_token == "new_access_123"
        assert result.refresh_token == "new_refresh_123"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_refresh_token_invalid_grant_error(self, mock_client_class):
        """Test handling of invalid_grant error during refresh."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Refresh token is invalid or expired",
        }

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(InvalidGrantError) as exc_info:
            client.refresh_token("expired_refresh_token")

        assert exc_info.value.get_error() == "invalid_grant"
        assert exc_info.value.get_error_description() == "Refresh token is invalid or expired"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_refresh_token_invalid_grant_no_description(self, mock_client_class):
        """Test handling of invalid_grant error without description."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "invalid_grant"}

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(InvalidGrantError) as exc_info:
            client.refresh_token("expired_refresh_token")

        assert exc_info.value.get_error_description() == "Invalid grant"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_refresh_token_http_error_fallback(self, mock_client_class):
        """Test that HTTP errors are raised when not invalid_grant."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.json.return_value = {"error": "server_error", "error_description": "Internal server error"}
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "500 Internal Server Error", request=Mock(), response=mock_response
        )

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(httpx.HTTPStatusError):
            client.refresh_token("refresh_token_123")

        mock_response.raise_for_status.assert_called_once()

    @patch("wristband.django_auth.client.httpx.Client")
    def test_refresh_token_non_200_status_code(self, mock_client_class):
        """Test handling of non-200 status codes that aren't invalid_grant."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {
            "error": "invalid_client",
            "error_description": "Client authentication failed",
        }
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401 Unauthorized", request=Mock(), response=mock_response
        )

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(httpx.HTTPStatusError):
            client.refresh_token("refresh_token_123")


class TestWristbandApiClientRevokeRefreshToken:
    """Test cases for revoke_refresh_token method."""

    @patch("wristband.django_auth.client.httpx.Client")
    def test_revoke_refresh_token_success(self, mock_client_class):
        """Test successful token revocation."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        # Should not raise any exception
        client.revoke_refresh_token("refresh_token_123")

        # Verify the request was made correctly
        mock_client_instance.post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/revoke",
            data={"token": "refresh_token_123"},
        )
        mock_response.raise_for_status.assert_called_once()

    @patch("wristband.django_auth.client.httpx.Client")
    def test_revoke_refresh_token_http_error(self, mock_client_class):
        """Test handling of HTTP errors during revocation."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "400 Bad Request", request=Mock(), response=mock_response
        )

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(httpx.HTTPStatusError):
            client.revoke_refresh_token("invalid_token")

        mock_response.raise_for_status.assert_called_once()

    @patch("wristband.django_auth.client.httpx.Client")
    def test_revoke_refresh_token_returns_none(self, mock_client_class):
        """Test that revoke_refresh_token returns None on success."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")
        result = client.revoke_refresh_token("refresh_token_123")

        assert result is None

    @patch("wristband.django_auth.client.httpx.Client")
    def test_revoke_refresh_token_with_empty_token(self, mock_client_class):
        """Test revocation with empty token (should still make request)."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        # Method doesn't validate token content, just passes it through
        client.revoke_refresh_token("")

        mock_client_instance.post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/revoke",
            data={"token": ""},
        )


class TestWristbandApiClientNetworkErrors:
    """Test cases for network and connection errors."""

    @patch("wristband.django_auth.client.httpx.Client")
    def test_network_timeout_error(self, mock_client_class):
        """Test handling of network timeout errors."""
        mock_client_instance = Mock()
        mock_client_instance.post.side_effect = httpx.RequestError("Connection timeout")
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(httpx.RequestError, match="Connection timeout"):
            client.get_tokens("code", "uri", "verifier")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_connection_error(self, mock_client_class):
        """Test handling of connection errors."""
        mock_client_instance = Mock()
        mock_client_instance.post.side_effect = httpx.ConnectError("Connection failed")
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(httpx.ConnectError, match="Connection failed"):
            client.get_tokens("code", "uri", "verifier")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_read_timeout_error(self, mock_client_class):
        """Test handling of read timeout errors."""
        mock_client_instance = Mock()
        mock_client_instance.get.side_effect = httpx.ReadTimeout("Read timeout")
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(httpx.ReadTimeout, match="Read timeout"):
            client.get_userinfo("access_token")


class TestWristbandApiClientEdgeCases:
    """Test edge cases and error conditions."""

    @patch("wristband.django_auth.client.httpx.Client")
    def test_json_decode_error_handling(self, mock_client_class):
        """Test handling of invalid JSON responses."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.side_effect = ValueError("Invalid JSON")

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        # Should raise the JSON decode error
        with pytest.raises(ValueError, match="Invalid JSON"):
            client.get_tokens("code", "uri", "verifier")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_malformed_token_response(self, mock_client_class):
        """Test handling of malformed token response from TokenResponse.from_api_response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "token",
            # Missing required fields like token_type, expires_in, etc.
        }

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        # Should raise KeyError when TokenResponse.from_api_response tries to access missing fields
        with pytest.raises(KeyError):
            client.get_tokens("code", "uri", "verifier")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_userinfo_json_decode_error(self, mock_client_class):
        """Test JSON decode error in userinfo endpoint."""
        mock_response = Mock()
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.raise_for_status = Mock()

        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(ValueError, match="Invalid JSON"):
            client.get_userinfo("access_token")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_unicode_handling_in_credentials(self, mock_client_class):
        """Test that unicode characters in credentials are handled properly."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

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

    @patch("wristband.django_auth.client.httpx.Client")
    def test_refresh_token_with_unicode_token(self, mock_client_class):
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

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")
        unicode_refresh_token = "refresh_token_测试_🔑"
        result = client.refresh_token(unicode_refresh_token)

        # Verify the unicode token was passed correctly
        mock_client_instance.post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/token",
            data={"grant_type": "refresh_token", "refresh_token": unicode_refresh_token},
        )

        assert result.access_token == "access_测试"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_very_long_token_handling(self, mock_client_class):
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

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")
        long_refresh_token = "x" * 1000
        result = client.refresh_token(long_refresh_token)

        assert len(result.access_token) == 2000
        assert len(result.refresh_token) == 2000

    @patch("wristband.django_auth.client.httpx.Client")
    def test_userinfo_with_complex_nested_data(self, mock_client_class):
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

        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")
        result = client.get_userinfo("access_token")

        assert result["sub"] == "user123"
        assert result["address"]["street_address"] == "123 Main St"
        assert result["groups"][0]["roles"] == ["admin", "user"]
        assert result["custom_claims"]["permissions"]["read"] is True

    @patch("wristband.django_auth.client.httpx.Client")
    def test_empty_error_response(self, mock_client_class):
        """Test handling of empty error response."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.json.return_value = {}

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(WristbandError) as exc_info:
            client.get_tokens("code", "uri", "verifier")

        assert exc_info.value.get_error() == "unknown_error"
        assert exc_info.value.get_error_description() == "Unknown error"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_partial_error_response(self, mock_client_class):
        """Test handling of partial error response with only error field."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "invalid_request"}

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(WristbandError) as exc_info:
            client.get_tokens("code", "uri", "verifier")

        assert exc_info.value.get_error() == "invalid_request"
        assert exc_info.value.get_error_description() == "Unknown error"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_error_response_with_null_values(self, mock_client_class):
        """Test handling of error response with null values."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": None, "error_description": None}

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        with pytest.raises(WristbandError) as exc_info:
            client.get_tokens("code", "uri", "verifier")

        assert exc_info.value.get_error() == "unknown_error"
        assert exc_info.value.get_error_description() == "Unknown error"


class TestWristbandApiClientIntegration:
    """Integration tests for WristbandApiClient methods working together."""

    @patch("wristband.django_auth.client.httpx.Client")
    def test_full_oauth_flow_success(self, mock_client_class):
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

        # Configure mock client to return different responses for different calls
        mock_client_instance = Mock()
        post_responses = [mock_token_response, mock_refresh_response, mock_revoke_response]
        mock_client_instance.post.side_effect = post_responses
        mock_client_instance.get.return_value = mock_userinfo_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        # Execute the full flow
        # 1. Get initial tokens
        tokens = client.get_tokens("auth_code", "https://app.com/callback", "code_verifier")
        assert tokens.access_token == "access_123"
        assert tokens.refresh_token == "refresh_123"

        # 2. Get user info
        user_info = client.get_userinfo(tokens.access_token)
        assert user_info["sub"] == "user123"
        assert user_info["email"] == "user@example.com"

        # 3. Refresh tokens
        new_tokens = client.refresh_token(tokens.refresh_token)
        assert new_tokens.access_token == "new_access_123"
        assert new_tokens.refresh_token == "new_refresh_123"

        # 4. Revoke refresh token
        client.revoke_refresh_token(new_tokens.refresh_token)

        # Verify all calls were made
        assert mock_client_instance.post.call_count == 3
        assert mock_client_instance.get.call_count == 1

    @patch("wristband.django_auth.client.httpx.Client")
    def test_error_handling_consistency(self, mock_client_class):
        """Test that error handling is consistent across methods."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        # All methods should validate required parameters
        with pytest.raises(ValueError):
            client.get_tokens("", "uri", "verifier")

        with pytest.raises(ValueError):
            client.get_tokens("code", "", "verifier")

        with pytest.raises(ValueError):
            client.get_tokens("code", "uri", "")

    @patch("wristband.django_auth.client.httpx.Client")
    def test_headers_consistency(self, mock_client_class):
        """Test that headers are consistent across the client."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        expected_auth_header = client.headers["Authorization"]
        expected_content_type = client.headers["Content-Type"]

        assert expected_auth_header.startswith("Basic ")
        assert expected_content_type == "application/x-www-form-urlencoded"

        # Headers should be the same instance used in requests
        assert len(client.headers) == 2

    @patch("wristband.django_auth.client.httpx.Client")
    def test_client_state_isolation(self, mock_client_class):
        """Test that multiple client instances don't interfere with each other."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client1 = WristbandApiClient("auth1.example.com", "client1", "secret1")
        client2 = WristbandApiClient("auth2.example.com", "client2", "secret2")

        assert client1.base_url != client2.base_url
        assert client1.headers["Authorization"] != client2.headers["Authorization"]

        # Modifying one shouldn't affect the other
        client1.headers["X-Custom"] = "test"
        assert "X-Custom" not in client2.headers

    @patch("wristband.django_auth.client.httpx.Client")
    def test_comprehensive_parameter_validation(self, mock_client_class):
        """Test all parameter validation scenarios comprehensively."""
        mock_client_instance = Mock()
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        invalid_values = [None, "", "   ", "\t\n\r"]

        for invalid_value in invalid_values:
            with pytest.raises(ValueError, match="Authorization code is required"):
                client.get_tokens(invalid_value, "https://test.com", "verifier")

            with pytest.raises(ValueError, match="Redirect URI is required"):
                client.get_tokens("code", invalid_value, "verifier")

            with pytest.raises(ValueError, match="Code verifier is required"):
                client.get_tokens("code", "https://test.com", invalid_value)


class TestWristbandApiClientDocumentationExamples:
    """Test cases that match the examples in the documentation."""

    @patch("wristband.django_auth.client.httpx.Client")
    def test_documentation_example_flow(self, mock_client_class):
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

        mock_userinfo_resp = Mock()
        mock_userinfo_resp.json.return_value = userinfo_response
        mock_userinfo_resp.raise_for_status = Mock()

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_token_resp
        mock_client_instance.get.return_value = mock_userinfo_resp
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        # Execute the documented example flow
        tokens = client.get_tokens("auth_code", "redirect_uri", "code_verifier")
        user_info = client.get_userinfo(tokens.access_token)

        # Verify results match documentation
        assert tokens.access_token == "access_token_from_docs"
        assert user_info["sub"] == "user123"
        assert user_info["email"] == "user@example.com"

    @patch("wristband.django_auth.client.httpx.Client")
    def test_invalid_grant_documentation_example(self, mock_client_class):
        """Test the InvalidGrantError example from documentation."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Authorization code has expired",
        }

        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        client = WristbandApiClient("auth.example.com", "client_id", "client_secret")

        # This should match the documentation example
        with pytest.raises(InvalidGrantError) as exc_info:
            client.get_tokens("expired_code", "redirect_uri", "code_verifier")

        # Verify the error matches the documentation
        assert exc_info.value.get_error_description() == "Authorization code has expired"
