import re
import threading
import time
from unittest.mock import Mock, patch

import pytest

from wristband.django_auth.config_resolver import ConfigResolver
from wristband.django_auth.exceptions import WristbandError
from wristband.django_auth.models import AuthConfig, SdkConfiguration


class TestConfigResolverValidation:
    """Test cases for ConfigResolver validation logic."""

    def test_validate_client_id_empty(self):
        """Test validation fails with empty client_id."""
        config = AuthConfig(
            client_id="",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )

        with pytest.raises(TypeError, match="The \\[client_id\\] config must have a value."):
            ConfigResolver(config)

    def test_validate_client_id_whitespace(self):
        """Test validation fails with whitespace-only client_id."""
        config = AuthConfig(
            client_id="   ",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )

        with pytest.raises(TypeError, match="The \\[client_id\\] config must have a value."):
            ConfigResolver(config)

    def test_validate_client_secret_empty(self):
        """Test validation fails with empty client_secret."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="",
            wristband_application_vanity_domain="test.wristband.dev",
        )

        with pytest.raises(TypeError, match="The \\[client_secret\\] config must have a value."):
            ConfigResolver(config)

    def test_validate_client_secret_whitespace(self):
        """Test validation fails with whitespace-only client_secret."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="   ",
            wristband_application_vanity_domain="test.wristband.dev",
        )

        with pytest.raises(TypeError, match="The \\[client_secret\\] config must have a value."):
            ConfigResolver(config)

    def test_validate_login_state_secret_too_short(self):
        """Test validation fails with short login_state_secret."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_state_secret="short",
        )

        with pytest.raises(
            TypeError, match="The \\[login_state_secret\\] config must have a value of at least 32 characters."
        ):
            ConfigResolver(config)

    def test_validate_login_state_secret_none_allowed(self):
        """Test validation passes with None login_state_secret."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_state_secret=None,
        )

        # Should not raise
        ConfigResolver(config)

    def test_validate_vanity_domain_empty(self):
        """Test validation fails with empty vanity domain."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="",
        )

        with pytest.raises(TypeError, match="The \\[wristband_application_vanity_domain\\] config must have a value."):
            ConfigResolver(config)

    def test_validate_vanity_domain_whitespace(self):
        """Test validation fails with whitespace-only vanity domain."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="   ",
        )

        with pytest.raises(TypeError, match="The \\[wristband_application_vanity_domain\\] config must have a value."):
            ConfigResolver(config)

    def test_validate_token_expiration_buffer_negative(self):
        """Test validation fails with negative token_expiration_buffer."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            token_expiration_buffer=-1,
        )

        with pytest.raises(
            TypeError, match="The \\[token_expiration_buffer\\] config must be greater than or equal to 0."
        ):
            ConfigResolver(config)

    def test_validate_auto_configure_disabled_missing_login_url(self):
        """Test validation fails when auto-configure disabled and login_url missing."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
        )

        with pytest.raises(
            TypeError, match="The \\[login_url\\] config must have a value when auto-configure is disabled."
        ):
            ConfigResolver(config)

    def test_validate_auto_configure_disabled_missing_redirect_uri(self):
        """Test validation fails when auto-configure disabled and redirect_uri missing."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://test.com/login",
        )

        with pytest.raises(
            TypeError, match="The \\[redirect_uri\\] config must have a value when auto-configure is disabled."
        ):
            ConfigResolver(config)

    def test_valid_configuration_passes(self):
        """Test that valid configuration passes validation."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://{tenant_name}.test.com/login",
            redirect_uri="https://{tenant_name}.test.com/callback",
            login_state_secret="a" * 32,
        )

        # Should not raise
        resolver = ConfigResolver(config)
        assert resolver is not None


class TestConfigResolverStaticConfigurations:
    """Test cases for static configuration getters."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_state_secret="a" * 32,
            dangerously_disable_secure_cookies=True,
            scopes=["custom", "scopes"],
            token_expiration_buffer=120,
        )
        self.resolver = ConfigResolver(self.config)

    def test_get_client_id(self):
        """Test get_client_id returns correct value."""
        assert self.resolver.get_client_id() == "test_client"

    def test_get_client_secret(self):
        """Test get_client_secret returns correct value."""
        assert self.resolver.get_client_secret() == "test_secret"

    def test_get_login_state_secret_custom(self):
        """Test get_login_state_secret returns custom value when provided."""
        assert self.resolver.get_login_state_secret() == "a" * 32

    def test_get_login_state_secret_fallback(self):
        """Test get_login_state_secret falls back to client_secret."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        resolver = ConfigResolver(config)
        assert resolver.get_login_state_secret() == "test_secret"

    def test_get_wristband_application_vanity_domain(self):
        """Test get_wristband_application_vanity_domain returns correct value."""
        assert self.resolver.get_wristband_application_vanity_domain() == "test.wristband.dev"

    def test_get_dangerously_disable_secure_cookies_true(self):
        """Test get_dangerously_disable_secure_cookies when set to True."""
        assert self.resolver.get_dangerously_disable_secure_cookies() is True

    def test_get_dangerously_disable_secure_cookies_default(self):
        """Test get_dangerously_disable_secure_cookies default value."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        resolver = ConfigResolver(config)
        assert resolver.get_dangerously_disable_secure_cookies() is False

    def test_get_scopes_custom(self):
        """Test get_scopes returns custom scopes."""
        assert self.resolver.get_scopes() == ["custom", "scopes"]

    def test_get_scopes_default(self):
        """Test get_scopes returns default scopes."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        resolver = ConfigResolver(config)
        assert resolver.get_scopes() == ["openid", "offline_access", "email"]

    def test_get_scopes_empty_list_uses_default(self):
        """Test get_scopes uses defaults when empty list provided."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            scopes=[],
        )
        resolver = ConfigResolver(config)
        assert resolver.get_scopes() == ["openid", "offline_access", "email"]

    def test_get_auto_configure_enabled_default(self):
        """Test get_auto_configure_enabled returns default True."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        resolver = ConfigResolver(config)
        assert resolver.get_auto_configure_enabled() is True

    def test_get_auto_configure_enabled_false(self):
        """Test get_auto_configure_enabled when set to False."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://test.com/login",
            redirect_uri="https://test.com/callback",
        )
        resolver = ConfigResolver(config)
        assert resolver.get_auto_configure_enabled() is False

    def test_get_token_expiration_buffer_custom(self):
        """Test get_token_expiration_buffer returns custom value."""
        assert self.resolver.get_token_expiration_buffer() == 120

    def test_get_token_expiration_buffer_default(self):
        """Test get_token_expiration_buffer returns default value."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        resolver = ConfigResolver(config)
        assert resolver.get_token_expiration_buffer() == 60


class TestConfigResolverDynamicConfigurations:
    """Test cases for dynamic configuration getters."""

    def setup_method(self):
        """Set up test fixtures."""
        self.valid_sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            custom_application_login_page_url="https://sdk.example.com/custom-login",
            is_application_custom_domain_active=True,
            login_url_tenant_domain_suffix=None,
        )

    def test_manual_config_takes_precedence(self):
        """Test that manual configuration takes precedence over auto-config."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://{tenant_name}.manual.com/login",
            redirect_uri="https://{tenant_name}.manual.com/callback",
            custom_application_login_page_url="https://manual.com/custom",
            is_application_custom_domain_active=False,
        )

        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=self.valid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            assert resolver.get_login_url() == "https://{tenant_name}.manual.com/login"
            assert resolver.get_redirect_uri() == "https://{tenant_name}.manual.com/callback"
            assert resolver.get_custom_application_login_page_url() == "https://manual.com/custom"
            assert resolver.get_is_application_custom_domain_active() is False
            assert resolver.get_parse_tenant_from_root_domain() == "manual.com"

    def test_auto_config_fallback(self):
        """Test auto-configuration fallback when manual values not provided."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=True,
        )

        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=self.valid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            assert resolver.get_login_url() == "https://sdk.example.com/login"
            assert resolver.get_redirect_uri() == "https://sdk.example.com/callback"
            assert resolver.get_custom_application_login_page_url() == "https://sdk.example.com/custom-login"
            assert resolver.get_is_application_custom_domain_active() is True
            assert resolver.get_parse_tenant_from_root_domain() == ""

    def test_auto_config_disabled_fallbacks(self):
        """Test fallback values when auto-config is disabled."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://manual.com/login",
            redirect_uri="https://manual.com/callback",
        )
        resolver = ConfigResolver(config)

        assert resolver.get_custom_application_login_page_url() == ""
        assert resolver.get_is_application_custom_domain_active() is False
        assert resolver.get_parse_tenant_from_root_domain() == ""

    def test_auto_config_none_values(self):
        """Test handling of None values from auto-config."""
        sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            custom_application_login_page_url=None,
            is_application_custom_domain_active=False,
            login_url_tenant_domain_suffix=None,
        )

        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=True,
        )

        with patch.object(ConfigResolver, "_load_sdk_config") as mock_load:
            mock_load.return_value = sdk_config
            resolver = ConfigResolver(config)

            assert resolver.get_custom_application_login_page_url() == ""
            assert resolver.get_is_application_custom_domain_active() is False
            assert resolver.get_parse_tenant_from_root_domain() == ""


class TestConfigResolverSdkConfigFetching:
    """Test cases for SDK configuration fetching and caching."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        self.valid_sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=True,
        )

    def test_sdk_config_caching(self):
        """Test that SDK config is cached after first fetch."""
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=self.valid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            # First call should fetch
            result1 = resolver.get_login_url()
            assert result1 == "https://sdk.example.com/login"

            # Second call should use cache
            result2 = resolver.get_redirect_uri()
            assert result2 == "https://sdk.example.com/callback"

            # Should only have called the API once
            mock_client.get_sdk_configuration.assert_called_once()

    def test_sdk_config_fetch_success_passthrough(self):
        """Test that a successful fetch is returned as-is (no retry loop at this layer)."""
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=self.valid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            result = resolver.get_login_url()
            assert result == "https://sdk.example.com/login"
            # Retrying on transient failures is handled one layer down by WristbandApiClient
            # (see with_retry() in retry.py), so this layer only ever calls the API once.
            assert mock_client.get_sdk_configuration.call_count == 1

    def test_sdk_config_fetch_failure_does_not_retry_at_this_layer(self):
        """Test that a fetch failure surfaces immediately without retrying here."""
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(side_effect=Exception("Persistent network error"))
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            with pytest.raises(WristbandError) as exc_info:
                resolver.get_login_url()

            assert exc_info.value.error == "sdk_config_fetch_failed"
            assert "Failed to fetch SDK configuration: Persistent network error" == exc_info.value.error_description
            assert mock_client.get_sdk_configuration.call_count == 1

    def test_preload_sdk_config(self):
        """Test preload_sdk_config method."""
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=self.valid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            # Preload config
            resolver.preload_sdk_config()
            assert mock_client.get_sdk_configuration.call_count == 1

            # Subsequent calls should use cache
            result = resolver.get_login_url()
            assert result == "https://sdk.example.com/login"
            assert mock_client.get_sdk_configuration.call_count == 1

    def test_thread_safety_multiple_threads(self):
        """Test that multiple threads don't cause duplicate requests."""
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()

            # Add delay to simulate network request
            def delayed_response():
                time.sleep(0.1)
                return self.valid_sdk_config

            mock_client.get_sdk_configuration = Mock(side_effect=delayed_response)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)
            results = []
            exceptions = []

            def worker():
                try:
                    result = resolver.get_login_url()
                    results.append(result)
                except Exception as e:
                    exceptions.append(e)

            # Create multiple threads
            threads = [threading.Thread(target=worker) for _ in range(3)]

            # Start all threads
            for thread in threads:
                thread.start()

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

            # Should only have made one API call
            mock_client.get_sdk_configuration.assert_called_once()
            assert len(exceptions) == 0
            assert all(result == "https://sdk.example.com/login" for result in results)

    def test_error_allows_retry_after_failure(self):
        """Test that errors reset to allow retry."""
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(
                side_effect=[
                    Exception("First error"),
                    self.valid_sdk_config,  # Success on retry
                ]
            )
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            # First attempt should fail immediately (no retry loop at this layer)
            with pytest.raises(WristbandError):
                resolver.get_login_url()
            assert mock_client.get_sdk_configuration.call_count == 1

            # Second attempt should succeed
            result = resolver.get_redirect_uri()
            assert result == "https://sdk.example.com/callback"
            assert mock_client.get_sdk_configuration.call_count == 2

    def test_sdk_config_fetch_with_network_delay(self):
        """Test SDK config fetch with a realistic network delay."""
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()

            # Simulate a slow but successful network call
            def delayed_success():
                time.sleep(0.05)  # Small delay
                return SdkConfiguration(
                    login_url="https://sdk.example.com/login",
                    redirect_uri="https://sdk.example.com/callback",
                    is_application_custom_domain_active=False,
                )

            mock_client.get_sdk_configuration = Mock(side_effect=delayed_success)
            mock_client_class.return_value = mock_client

            config = AuthConfig(
                client_id="test_client",
                client_secret="test_secret",
                wristband_application_vanity_domain="test.wristband.dev",
            )
            resolver = ConfigResolver(config)

            start_time = time.time()
            result = resolver.get_login_url()
            end_time = time.time()

            assert result == "https://sdk.example.com/login"
            # Retrying transient failures is handled one layer down by WristbandApiClient
            # (see with_retry() in retry.py), so this layer only calls the API once.
            assert mock_client.get_sdk_configuration.call_count == 1
            assert end_time - start_time >= 0.05


class TestConfigResolverDynamicValidation:
    """Test cases for dynamic configuration validation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )

    def test_validate_missing_login_url_in_sdk_config(self):
        """Test validation fails when SDK config missing login_url."""
        invalid_sdk_config = SdkConfiguration(
            login_url="", redirect_uri="https://sdk.example.com/callback", is_application_custom_domain_active=False
        )

        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=invalid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            with pytest.raises(WristbandError) as exc_info:
                resolver.get_login_url()

            assert exc_info.value.error == "sdk_config_invalid"
            assert "missing required field: login_url" in exc_info.value.error_description

    def test_validate_missing_redirect_uri_in_sdk_config(self):
        """Test validation fails when SDK config missing redirect_uri."""
        invalid_sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login", redirect_uri="", is_application_custom_domain_active=False
        )

        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=invalid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            with pytest.raises(WristbandError) as exc_info:
                resolver.get_redirect_uri()

            assert exc_info.value.error == "sdk_config_invalid"
            assert (
                "The [redirect_uri] could not be resolved. Provide it explicitly in your SDK config "
                "or ensure your Wristband OAuth2 Client has a single redirect URI configured."
                in exc_info.value.error_description
            )

    def test_validate_null_redirect_uri_in_sdk_config_without_manual_override(self):
        """Test validation fails when SDK config returns null redirect_uri and no manual override provided."""
        null_redirect_sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri=None,
            is_application_custom_domain_active=False,
        )

        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=null_redirect_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            with pytest.raises(WristbandError) as exc_info:
                resolver.get_redirect_uri()

            assert exc_info.value.error == "sdk_config_invalid"
            assert "The [redirect_uri] could not be resolved" in exc_info.value.error_description

    def test_manual_redirect_uri_overrides_null_sdk_redirect_uri(self):
        """Test that manual redirect_uri succeeds when SDK config returns null (multiple redirect URIs registered)."""
        null_redirect_sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri=None,
            is_application_custom_domain_active=False,
        )

        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            redirect_uri="https://manual.example.com/callback",
        )

        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=null_redirect_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)
            result = resolver.get_redirect_uri()
            assert result == "https://manual.example.com/callback"


class TestConfigResolverEdgeCases:
    """Test cases for edge cases and integration scenarios."""

    def test_boolean_handling_for_custom_domain_active(self):
        """Test proper boolean handling for is_application_custom_domain_active."""
        # Test explicit False
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            is_application_custom_domain_active=False,
        )
        resolver = ConfigResolver(config)
        assert resolver.get_is_application_custom_domain_active() is False

        # Test explicit True
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            is_application_custom_domain_active=True,
        )
        resolver = ConfigResolver(config)
        assert resolver.get_is_application_custom_domain_active() is True

        # Test None with auto-config
        sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)
            assert resolver.get_is_application_custom_domain_active() is False

    def test_empty_string_values(self):
        """Test handling of empty string values."""
        sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            custom_application_login_page_url=None,
            is_application_custom_domain_active=True,
        )

        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            custom_application_login_page_url="",
        )

        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)
            assert resolver.get_custom_application_login_page_url() == ""
            assert resolver.get_parse_tenant_from_root_domain() == ""

    def test_mixed_manual_and_auto_config(self):
        """Test mixed manual and auto-configuration."""
        sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            custom_application_login_page_url=None,
            is_application_custom_domain_active=False,
            login_url_tenant_domain_suffix=None,
        )

        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://manual.example.com/login",  # Manual override
            # redirect_uri will come from auto-config
        )

        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            assert resolver.get_login_url() == "https://manual.example.com/login"  # Manual
            assert resolver.get_redirect_uri() == "https://sdk.example.com/callback"  # Auto-config
            assert resolver.get_custom_application_login_page_url() == ""  # Auto-config empty
            assert resolver.get_parse_tenant_from_root_domain() == ""  # Auto-config empty

    def test_error_preserves_original_message(self):
        """Test that error messages preserve original exception details."""
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            original_error = Exception("Network connection failed")
            mock_client.get_sdk_configuration = Mock(side_effect=original_error)
            mock_client_class.return_value = mock_client

            config = AuthConfig(
                client_id="test_client",
                client_secret="test_secret",
                wristband_application_vanity_domain="test.wristband.dev",
            )
            resolver = ConfigResolver(config)

            with pytest.raises(WristbandError) as exc_info:
                resolver.get_login_url()

            assert "Network connection failed" in str(exc_info.value.error_description)

    def test_validate_resolved_config_precedence(self):
        """Test that manual config values take precedence in validation."""
        # Manual config has correct tenant name placeholder
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://{tenant_name}.manual.com/login",
        )

        # SDK config would fail validation if used
        sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",  # No tenant placeholder
            redirect_uri="https://{tenant_name}.sdk.com/callback",
            is_application_custom_domain_active=True,
        )

        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            # Should not raise validation error because manual login_url is used
            result = resolver.get_login_url()
            assert result == "https://{tenant_name}.manual.com/login"

    def test_wristband_api_client_initialization(self):
        """Test that WristbandApiClient is initialized correctly."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )

        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            ConfigResolver(config)
            mock_client_class.assert_called_once_with("test.wristband.dev", "test_client", "test_secret")

    def test_concurrent_thread_access(self):
        """Test concurrent access from multiple threads."""
        sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )

        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()

            # Add delay to simulate network request
            def delayed_response():
                time.sleep(0.1)
                return sdk_config

            mock_client.get_sdk_configuration = Mock(side_effect=delayed_response)
            mock_client_class.return_value = mock_client

            config = AuthConfig(
                client_id="test_client",
                client_secret="test_secret",
                wristband_application_vanity_domain="test.wristband.dev",
            )
            resolver = ConfigResolver(config)

            results = []
            exceptions = []

            def worker(getter_method):
                try:
                    result = getattr(resolver, getter_method)()
                    results.append(result)
                except Exception as e:
                    exceptions.append(e)

            # Start multiple threads with different getters
            threads = [
                threading.Thread(target=worker, args=("get_login_url",)),
                threading.Thread(target=worker, args=("get_redirect_uri",)),
                threading.Thread(target=worker, args=("get_is_application_custom_domain_active",)),
            ]

            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join()

            # Should only make one API call
            mock_client.get_sdk_configuration.assert_called_once()
            assert len(exceptions) == 0
            assert len(results) == 3

    def test_tenant_name_placeholder_in_redirect_uri_without_parsing(self):
        """Test redirect_uri validation without parsing."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://test.com/login",
            redirect_uri="https://{tenant_name}.test.com/callback",
        )

        with pytest.raises(TypeError, match='cannot contain the "\\{tenant_name\\}" placeholder'):
            ConfigResolver(config)

    def test_cache_thread_safety_with_error_recovery(self):
        """Test cache thread safety when errors occur and recovery happens."""
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()

            # Track total call count across all attempts
            total_call_count = 0

            def error_then_success():
                nonlocal total_call_count
                total_call_count += 1
                if total_call_count <= 1:  # First call fails
                    raise Exception(f"Error {total_call_count}")
                return SdkConfiguration(
                    login_url="https://sdk.example.com/login",
                    redirect_uri="https://sdk.example.com/callback",
                    is_application_custom_domain_active=True,
                )

            mock_client.get_sdk_configuration = Mock(side_effect=error_then_success)
            mock_client_class.return_value = mock_client

            config = AuthConfig(
                client_id="test_client",
                client_secret="test_secret",
                wristband_application_vanity_domain="test.wristband.dev",
            )
            resolver = ConfigResolver(config)

            # First call should fail immediately (retries live one layer down in the client)
            with pytest.raises(WristbandError):
                resolver.get_login_url()

            # Verify we made a single attempt at this layer
            assert total_call_count == 1

            # Second call should succeed (this will be the 2nd total call)
            result = resolver.get_redirect_uri()
            assert result == "https://sdk.example.com/callback"
            assert total_call_count == 2  # One more call that succeeded

    def test_sdk_config_fetch_with_network_delay(self):
        """Test SDK config fetch with a realistic network delay."""
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()

            # Simulate a slow but successful network call
            def delayed_success():
                time.sleep(0.05)  # Small delay
                return SdkConfiguration(
                    login_url="https://sdk.example.com/login",
                    redirect_uri="https://sdk.example.com/callback",
                    is_application_custom_domain_active=False,
                )

            mock_client.get_sdk_configuration = Mock(side_effect=delayed_success)
            mock_client_class.return_value = mock_client

            config = AuthConfig(
                client_id="test_client",
                client_secret="test_secret",
                wristband_application_vanity_domain="test.wristband.dev",
            )
            resolver = ConfigResolver(config)

            start_time = time.time()
            result = resolver.get_login_url()
            end_time = time.time()

            assert result == "https://sdk.example.com/login"
            # Retrying transient failures is handled one layer down by WristbandApiClient
            # (see with_retry() in retry.py), so this layer only calls the API once.
            assert mock_client.get_sdk_configuration.call_count == 1
            assert end_time - start_time >= 0.05

    def test_concurrent_preload_and_get_requests(self):
        """Test concurrent preload and getter requests with threading."""
        sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )

        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()

            # Add delay to simulate network request
            def delayed_response():
                time.sleep(0.1)
                return sdk_config

            mock_client.get_sdk_configuration = Mock(side_effect=delayed_response)
            mock_client_class.return_value = mock_client

            config = AuthConfig(
                client_id="test_client",
                client_secret="test_secret",
                wristband_application_vanity_domain="test.wristband.dev",
            )
            resolver = ConfigResolver(config)

            results = []
            exceptions = []

            def preload_worker():
                try:
                    resolver.preload_sdk_config()  # Returns None
                    results.append(None)
                except Exception as e:
                    exceptions.append(e)

            def getter_worker(method_name):
                try:
                    result = getattr(resolver, method_name)()
                    results.append(result)
                except Exception as e:
                    exceptions.append(e)

            # Start preload and getters concurrently
            threads = [
                threading.Thread(target=preload_worker),
                threading.Thread(target=getter_worker, args=("get_login_url",)),
                threading.Thread(target=getter_worker, args=("get_redirect_uri",)),
            ]

            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join()

            # Should only make one API call
            mock_client.get_sdk_configuration.assert_called_once()
            assert len(exceptions) == 0
            assert len(results) == 3
            # Preload returns None, getters return values
            assert None in results
            assert "https://sdk.example.com/login" in results
            assert "https://sdk.example.com/callback" in results


def _strict_config(login_url: str, redirect_uri: str) -> AuthConfig:
    return AuthConfig(
        client_id="test_client",
        client_secret="test_secret",
        wristband_application_vanity_domain="test.wristband.dev",
        auto_configure_enabled=False,
        login_url=login_url,
        redirect_uri=redirect_uri,
    )


def _mock_sdk_config_client(mock_client_class: Mock, sdk_config: SdkConfiguration) -> None:
    mock_client = Mock()
    mock_client.get_sdk_configuration = Mock(return_value=sdk_config)
    mock_client_class.return_value = mock_client


class TestConfigResolverTenantPlaceholderValidation:
    """Test cases for {tenant_name} placeholder validation in login_url and redirect_uri."""

    def test_redirect_uri_must_contain_placeholder_when_login_url_does(self):
        with pytest.raises(
            TypeError,
            match=re.escape(
                'The [redirect_uri] must contain the "{tenant_name}" placeholder when the [login_url] contains it.'
            ),
        ):
            ConfigResolver(_strict_config("https://{tenant_name}.test.com/login", "https://test.com/callback"))

    def test_redirect_uri_cannot_contain_placeholder_when_login_url_does_not(self):
        with pytest.raises(
            TypeError,
            match=re.escape(
                'The [redirect_uri] cannot contain the "{tenant_name}" placeholder when the [login_url] '
                "does not contain it."
            ),
        ):
            ConfigResolver(_strict_config("https://test.com/login", "https://{tenant_name}.test.com/callback"))

    @pytest.mark.parametrize(
        "login_url",
        [
            "https://app.{tenant_name}.test.com/login",
            "https://test.com/{tenant_name}/login",
            "https://{tenant_name}/login",
            "https://{tenant_name}.test.com/{tenant_name}/login",
        ],
    )
    def test_login_url_placeholder_must_be_leftmost_part_of_hostname_once(self, login_url):
        with pytest.raises(
            TypeError,
            match=re.escape(
                'The [login_url] can only contain the "{tenant_name}" placeholder once, '
                "as the leftmost part of its hostname."
            ),
        ):
            ConfigResolver(_strict_config(login_url, "https://{tenant_name}.test.com/callback"))

    def test_redirect_uri_placeholder_must_be_leftmost_part_of_hostname(self):
        with pytest.raises(TypeError, match=re.escape("The [redirect_uri] can only contain")):
            ConfigResolver(
                _strict_config("https://{tenant_name}.test.com/login", "https://test.com/{tenant_name}/callback")
            )

    def test_both_urls_with_placeholder_pass(self):
        resolver = ConfigResolver(
            _strict_config("http://{tenant_name}.localhost:6001/login", "http://{tenant_name}.localhost:6001/callback")
        )
        assert resolver is not None

    def test_partial_validation_checks_placeholder_position(self):
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://app.{tenant_name}.test.com/login",
        )
        with pytest.raises(TypeError, match=re.escape("The [login_url] can only contain")):
            ConfigResolver(config)

    def test_partial_validation_compares_both_urls_when_provided(self):
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://{tenant_name}.test.com/login",
            redirect_uri="https://test.com/callback",
        )
        with pytest.raises(TypeError, match=re.escape("The [redirect_uri] must contain")):
            ConfigResolver(config)

    def test_partial_validation_allows_only_one_url(self):
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://{tenant_name}.test.com/login",
        )
        assert ConfigResolver(config) is not None

    def test_tenant_domain_placeholder_is_no_longer_treated_as_a_placeholder(self):
        # {tenant_domain} is no longer a placeholder, so the redirect_uri {tenant_name} placeholder has no match.
        with pytest.raises(TypeError, match=re.escape("The [redirect_uri] cannot contain")):
            ConfigResolver(
                _strict_config("https://{tenant_domain}.test.com/login", "https://{tenant_name}.test.com/callback")
            )

    def test_resolved_redirect_uri_must_contain_placeholder_when_manual_login_url_does(self):
        sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://{tenant_name}.test.com/login",
        )
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            _mock_sdk_config_client(mock_client_class, sdk_config)
            resolver = ConfigResolver(config)
            with pytest.raises(WristbandError) as exc_info:
                resolver.get_redirect_uri()
        assert exc_info.value.error == "config_validation_error"
        assert "The resolved [redirect_uri] must contain the" in exc_info.value.error_description

    def test_resolved_redirect_uri_cannot_contain_placeholder_when_manual_login_url_does_not(self):
        sdk_config = SdkConfiguration(
            login_url="https://{tenant_name}.sdk.example.com/login",
            redirect_uri="https://{tenant_name}.sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://test.com/login",
        )
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            _mock_sdk_config_client(mock_client_class, sdk_config)
            resolver = ConfigResolver(config)
            with pytest.raises(WristbandError) as exc_info:
                resolver.get_redirect_uri()
        assert "The resolved [redirect_uri] cannot contain the" in exc_info.value.error_description

    def test_sdk_config_urls_are_trusted_as_is(self):
        sdk_config = SdkConfiguration(
            login_url="https://{tenant_name}.sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            _mock_sdk_config_client(mock_client_class, sdk_config)
            resolver = ConfigResolver(config)
            assert resolver.get_login_url() == "https://{tenant_name}.sdk.example.com/login"


class TestConfigResolverDerivedAndAppLevelConfigs:
    """Test cases for configs derived from login_url and application-level authorization requests."""

    @pytest.mark.parametrize(
        "login_url,expected_root_domain,expected_fallback_login_url",
        [
            ("https://{tenant_name}.myapp.com/auth/login", "myapp.com", "https://myapp.com/auth/login"),
            ("http://{tenant_name}.localhost:6001/auth/login", "localhost", "http://localhost:6001/auth/login"),
            ("https://myapp.com/auth/login", "", ""),
        ],
    )
    def test_root_domain_and_fallback_login_url_are_derived_from_manual_login_url(
        self, login_url, expected_root_domain, expected_fallback_login_url
    ):
        redirect_uri = login_url.replace("/auth/login", "/auth/callback")
        resolver = ConfigResolver(_strict_config(login_url, redirect_uri))
        assert resolver.get_parse_tenant_from_root_domain() == expected_root_domain
        assert resolver.get_fallback_login_url() == expected_fallback_login_url

    def test_root_domain_and_fallback_login_url_come_from_sdk_config_when_login_url_not_manual(self):
        sdk_config = SdkConfiguration(
            login_url="https://{tenant_name}.sdk.example.com/login",
            redirect_uri="https://{tenant_name}.sdk.example.com/callback",
            is_application_custom_domain_active=False,
            login_url_tenant_domain_suffix="sdk.example.com",
            fallback_login_url="https://sdk.example.com/login",
        )
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            _mock_sdk_config_client(mock_client_class, sdk_config)
            resolver = ConfigResolver(config)
            assert resolver.get_parse_tenant_from_root_domain() == "sdk.example.com"
            assert resolver.get_fallback_login_url() == "https://sdk.example.com/login"

    def test_application_authorization_requests_enabled_defaults_to_true_without_auto_configure(self):
        resolver = ConfigResolver(_strict_config("https://test.com/login", "https://test.com/callback"))
        assert resolver.get_application_authorization_requests_enabled() is True

    def test_application_authorization_requests_enabled_manual_value_takes_precedence(self):
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            application_authorization_requests_enabled=False,
        )
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = Mock()
            mock_client_class.return_value = mock_client
            resolver = ConfigResolver(config)
            assert resolver.get_application_authorization_requests_enabled() is False
            mock_client.get_sdk_configuration.assert_not_called()

    @pytest.mark.parametrize("sdk_value", [True, False])
    def test_application_authorization_requests_enabled_from_sdk_config(self, sdk_value):
        sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
            application_authorization_requests_enabled=sdk_value,
        )
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        with patch("wristband.django_auth.config_resolver.WristbandApiClient") as mock_client_class:
            _mock_sdk_config_client(mock_client_class, sdk_config)
            resolver = ConfigResolver(config)
            assert resolver.get_application_authorization_requests_enabled() is sdk_value

    def test_sdk_configuration_from_api_response_defaults_app_level_to_true(self):
        sdk_config = SdkConfiguration.from_api_response({"loginUrl": "https://sdk.example.com/login"})
        assert sdk_config.application_authorization_requests_enabled is True
        assert sdk_config.fallback_login_url is None

    def test_sdk_configuration_from_api_response_reads_app_level_fields(self):
        sdk_config = SdkConfiguration.from_api_response(
            {
                "loginUrl": "https://{tenant_name}.sdk.example.com/login",
                "applicationAuthorizationRequestsEnabled": False,
                "fallbackLoginUrl": "https://sdk.example.com/login",
            }
        )
        assert sdk_config.application_authorization_requests_enabled is False
        assert sdk_config.fallback_login_url == "https://sdk.example.com/login"
