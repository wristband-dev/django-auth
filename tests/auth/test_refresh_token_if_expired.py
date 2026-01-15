from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import httpx
import pytest

from wristband.django_auth.auth import WristbandAuth
from wristband.django_auth.exceptions import InvalidGrantError, WristbandError
from wristband.django_auth.models import AuthConfig, TokenData, WristbandTokenResponse


class TestWristbandAuthRefreshTokenIfExpired:
    """Test cases for refresh_token_if_expired method."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret="this_is_a_very_long_secret_key_for_testing_purposes_123456789",
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            token_expiration_buffer=60,  # 60 second buffer
        )
        self.wristband_auth = WristbandAuth(self.auth_config)

    def test_refresh_token_if_expired_invalid_refresh_token_none(self) -> None:
        """Test raises TypeError when refresh_token is None."""
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        with pytest.raises(TypeError, match="Refresh token must be a valid string"):
            self.wristband_auth.refresh_token_if_expired(None, expires_at)

    def test_refresh_token_if_expired_invalid_refresh_token_empty(self) -> None:
        """Test raises TypeError when refresh_token is empty string."""
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        with pytest.raises(TypeError, match="Refresh token must be a valid string"):
            self.wristband_auth.refresh_token_if_expired("", expires_at)

    def test_refresh_token_if_expired_invalid_refresh_token_whitespace(self) -> None:
        """Test raises TypeError when refresh_token is only whitespace."""
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        with pytest.raises(TypeError, match="Refresh token must be a valid string"):
            self.wristband_auth.refresh_token_if_expired("   ", expires_at)

    def test_refresh_token_if_expired_invalid_expires_at_none(self) -> None:
        """Test raises TypeError when expires_at is None."""
        with pytest.raises(TypeError, match="The expiresAt field must be an integer greater than 0"):
            self.wristband_auth.refresh_token_if_expired("valid_refresh_token", None)

    def test_refresh_token_if_expired_invalid_expires_at_zero(self) -> None:
        """Test raises TypeError when expires_at is 0."""
        with pytest.raises(TypeError, match="The expiresAt field must be an integer greater than 0"):
            self.wristband_auth.refresh_token_if_expired("valid_refresh_token", 0)

    def test_refresh_token_if_expired_invalid_expires_at_negative(self) -> None:
        """Test raises TypeError when expires_at is negative."""
        with pytest.raises(TypeError, match="The expiresAt field must be an integer greater than 0"):
            self.wristband_auth.refresh_token_if_expired("valid_refresh_token", -1)

    def test_refresh_token_if_expired_token_still_valid_returns_none(self) -> None:
        """Test returns None when access token is still valid."""
        refresh_token = "valid_refresh_token"
        # Set expires_at to 1 hour in the future
        expires_at = int((datetime.now() + timedelta(hours=1)).timestamp() * 1000)

        result = self.wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

        assert result is None

    @patch("wristband.django_auth.auth.time.time")
    def test_refresh_token_if_expired_successful_refresh(self, mock_time) -> None:
        """Test successful token refresh when token is expired."""
        mock_time.return_value = 1640995200.0  # Fixed timestamp

        refresh_token = "expired_refresh_token"
        # Set expires_at to 1 hour ago
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        # Mock the API response
        mock_token_response = WristbandTokenResponse(
            access_token="new_access_token",
            id_token="new_id_token",
            expires_in=3600,
            refresh_token="new_refresh_token",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        with patch.object(self.wristband_auth._wristband_api, "refresh_token", return_value=mock_token_response):
            result = self.wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

        assert result is not None
        assert isinstance(result, TokenData)
        assert result.access_token == "new_access_token"
        assert result.id_token == "new_id_token"
        assert result.expires_in == 3540  # 3600 - 60 (buffer)
        assert result.expires_at == int((1640995200.0 + 3540) * 1000)
        assert result.refresh_token == "new_refresh_token"

    @patch("wristband.django_auth.auth.time.time")
    def test_refresh_token_if_expired_with_default_token_expiration_buffer(self, mock_time) -> None:
        """Test token refresh with no expiry buffer configured."""
        mock_time.return_value = 1640995200.0

        # Create config without token_expiration_buffer
        config_no_buffer = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret="this_is_a_very_long_secret_key_for_testing_purposes_123456789",
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
        )
        wristband_auth = WristbandAuth(config_no_buffer)

        refresh_token = "expired_refresh_token"
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        mock_token_response = WristbandTokenResponse(
            access_token="new_access_token",
            id_token="new_id_token",
            expires_in=3600,
            refresh_token="new_refresh_token",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        with patch.object(wristband_auth._wristband_api, "refresh_token", return_value=mock_token_response):
            result = wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

        assert result is not None
        assert result.expires_in == 3540
        assert result.expires_at == int((1640995200.0 + 3540) * 1000)

    def test_refresh_token_if_expired_invalid_grant_error_no_retry(self) -> None:
        """Test InvalidGrantError is raised immediately without retry."""
        refresh_token = "invalid_refresh_token"
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        with patch.object(self.wristband_auth._wristband_api, "refresh_token") as mock_refresh:
            mock_refresh.side_effect = InvalidGrantError("Invalid grant")

            with pytest.raises(InvalidGrantError, match="Invalid grant"):
                self.wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

            # Should only be called once (no retries)
            assert mock_refresh.call_count == 1

    def test_refresh_token_if_expired_http_error_4xx_no_retry(self) -> None:
        """Test 4xx HTTP errors are raised immediately without retry."""
        refresh_token = "invalid_refresh_token"
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        # Create a mock 400 error response
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error_description": "Bad Request"}

        mock_http_error = httpx.HTTPStatusError("400 Bad Request", request=Mock(), response=mock_response)
        mock_http_error.response = mock_response

        with patch.object(self.wristband_auth._wristband_api, "refresh_token") as mock_refresh:
            mock_refresh.side_effect = mock_http_error

            with pytest.raises(WristbandError) as exc_info:
                self.wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

            # Check the error message contains both error code and description
            error_message = str(exc_info.value)
            assert "invalid_refresh_token" in error_message
            assert "Bad Request" in error_message
            # Should only be called once (no retries)
            assert mock_refresh.call_count == 1

    def test_refresh_token_if_expired_http_error_4xx_json_parse_error(self) -> None:
        """Test 4xx HTTP errors with JSON parse failure use default error message."""
        refresh_token = "invalid_refresh_token"
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        # Create a mock 401 error response with invalid JSON
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.side_effect = Exception("Invalid JSON")

        mock_http_error = httpx.HTTPStatusError("401 Unauthorized", request=Mock(), response=mock_response)
        mock_http_error.response = mock_response

        with patch.object(self.wristband_auth._wristband_api, "refresh_token") as mock_refresh:
            mock_refresh.side_effect = mock_http_error

            with pytest.raises(WristbandError) as exc_info:
                self.wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

            error_message = str(exc_info.value)
            assert "invalid_refresh_token" in error_message
            assert "Invalid Refresh Token" in error_message

    @patch("wristband.django_auth.auth.time.sleep")
    def test_refresh_token_if_expired_http_error_5xx_with_retries(self, mock_sleep) -> None:
        """Test 5xx HTTP errors are retried up to 3 times."""
        refresh_token = "valid_refresh_token"
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        # Create a mock 500 error response
        mock_response = Mock()
        mock_response.status_code = 500

        mock_http_error = httpx.HTTPStatusError("500 Internal Server Error", request=Mock(), response=mock_response)
        mock_http_error.response = mock_response

        with patch.object(self.wristband_auth._wristband_api, "refresh_token") as mock_refresh:
            mock_refresh.side_effect = mock_http_error

            with pytest.raises(WristbandError) as exc_info:
                self.wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

            error_message = str(exc_info.value)
            assert "unexpected_error" in error_message
            assert "Unexpected Error" in error_message
            # Should be called 3 times (initial + 2 retries)
            assert mock_refresh.call_count == 3
            # Should sleep twice (between retries)
            assert mock_sleep.call_count == 2
            mock_sleep.assert_called_with(0.1)  # _token_refresh_retry_timeout

    @patch("wristband.django_auth.auth.time.sleep")
    @patch("wristband.django_auth.auth.time.time")
    def test_refresh_token_if_expired_retry_then_success(self, mock_time, mock_sleep) -> None:
        """Test successful refresh after initial failure."""
        mock_time.return_value = 1640995200.0

        refresh_token = "valid_refresh_token"
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        # Create a mock 500 error for first attempt
        mock_response = Mock()
        mock_response.status_code = 500

        mock_http_error = httpx.HTTPStatusError("500 Internal Server Error", request=Mock(), response=mock_response)
        mock_http_error.response = mock_response

        # Success response for second attempt
        mock_token_response = WristbandTokenResponse(
            access_token="new_access_token",
            id_token="new_id_token",
            expires_in=3600,
            refresh_token="new_refresh_token",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        with patch.object(self.wristband_auth._wristband_api, "refresh_token") as mock_refresh:
            mock_refresh.side_effect = [mock_http_error, mock_token_response]

            result = self.wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

            assert result is not None
            assert result.access_token == "new_access_token"
            assert mock_refresh.call_count == 2
            assert mock_sleep.call_count == 1

    def test_refresh_token_if_expired_http_error_no_response(self) -> None:
        """Test HTTP error without response object is retried."""
        refresh_token = "valid_refresh_token"
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        mock_http_error = httpx.RequestError("Network error")

        with patch.object(self.wristband_auth._wristband_api, "refresh_token") as mock_refresh:
            with patch("wristband.django_auth.auth.time.sleep"):
                mock_refresh.side_effect = mock_http_error

                with pytest.raises(WristbandError) as exc_info:
                    self.wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

                error_message = str(exc_info.value)
                assert "unexpected_error" in error_message
                # Should be retried 3 times
                assert mock_refresh.call_count == 3

    def test_refresh_token_if_expired_non_http_exception_with_retries(self) -> None:
        """Test non-HTTP exceptions are retried."""
        refresh_token = "valid_refresh_token"
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        with patch.object(self.wristband_auth._wristband_api, "refresh_token") as mock_refresh:
            with patch("wristband.django_auth.auth.time.sleep"):
                # Use a generic Exception instead of ConnectionError
                mock_refresh.side_effect = Exception("Generic error")

                with pytest.raises(WristbandError) as exc_info:
                    self.wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

                error_message = str(exc_info.value)
                assert "unexpected_error" in error_message
                # Should be retried 3 times
                assert mock_refresh.call_count == 3

    def test_refresh_token_if_expired_token_expiration_buffer_calculation(self) -> None:
        """Test token expiry buffer is correctly applied to expires_in."""
        # Create config with custom buffer
        config_custom_buffer = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret="this_is_a_very_long_secret_key_for_testing_purposes_123456789",
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            token_expiration_buffer=120,  # 2 minute buffer
        )
        wristband_auth = WristbandAuth(config_custom_buffer)

        refresh_token = "valid_refresh_token"
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        mock_token_response = WristbandTokenResponse(
            access_token="new_access_token",
            id_token="new_id_token",
            expires_in=3600,
            refresh_token="new_refresh_token",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        with patch.object(wristband_auth._wristband_api, "refresh_token", return_value=mock_token_response):
            with patch("wristband.django_auth.auth.time.time", return_value=1640995200.0):
                result = wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

        assert result is not None
        assert result.expires_in == 3480  # 3600 - 120 (custom buffer)
        assert result.expires_at == int((1640995200.0 + 3480) * 1000)

    def test_refresh_token_if_expired_edge_case_exactly_expired(self) -> None:
        """Test behavior when token expires exactly now."""
        refresh_token = "valid_refresh_token"
        # Set expires_at to exactly now
        expires_at = int(datetime.now().timestamp() * 1000)

        mock_token_response = WristbandTokenResponse(
            access_token="new_access_token",
            id_token="new_id_token",
            expires_in=3600,
            refresh_token="new_refresh_token",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        with patch.object(self.wristband_auth._wristband_api, "refresh_token", return_value=mock_token_response):
            with patch("wristband.django_auth.auth.time.time", return_value=1640995200.0):
                # Since expires_at is exactly now, it should be considered expired and refresh
                result = self.wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

        assert result is not None
        assert result.access_token == "new_access_token"

    @patch("wristband.django_auth.auth.time.time")
    def test_refresh_token_if_expired_with_zero_token_expiration_buffer(self, mock_time) -> None:
        """Test token refresh with zero expiry buffer configured."""
        mock_time.return_value = 1640995200.0

        # Create config with zero token_expiration_buffer
        config_zero_buffer = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret="this_is_a_very_long_secret_key_for_testing_purposes_123456789",
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            token_expiration_buffer=0,  # Zero buffer
        )
        wristband_auth = WristbandAuth(config_zero_buffer)

        refresh_token = "expired_refresh_token"
        expires_at = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

        mock_token_response = WristbandTokenResponse(
            access_token="new_access_token",
            id_token="new_id_token",
            expires_in=3600,
            refresh_token="new_refresh_token",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        with patch.object(wristband_auth._wristband_api, "refresh_token", return_value=mock_token_response):
            result = wristband_auth.refresh_token_if_expired(refresh_token, expires_at)

        assert result is not None
        assert result.expires_in == 3600  # No buffer applied (3600 - 0)
        assert result.expires_at == int((1640995200.0 + 3600) * 1000)
