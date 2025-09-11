from unittest.mock import Mock

import pytest

from wristband.django_auth.auth import WristbandAuth
from wristband.django_auth.exceptions import WristbandError
from wristband.django_auth.models import AuthConfig


@pytest.fixture
def mock_auth_config():
    return AuthConfig(
        client_id="test-client",
        client_secret="test-secret",
        login_state_secret="a" * 32,
        login_url="https://example.com/login",
        redirect_uri="https://example.com/callback",
        wristband_application_vanity_domain="example.wristband.dev",
        auto_configure_enabled=True,
    )


def test_discover_raises_if_auto_configure_disabled(mock_auth_config):
    mock_auth_config.auto_configure_enabled = False
    auth = WristbandAuth(mock_auth_config)

    with pytest.raises(WristbandError) as exc:
        auth.discover()

    assert "auto_configure_enabled is false" in str(exc.value)


def test_discover_calls_preload_sdk_config(mock_auth_config):
    auth = WristbandAuth(mock_auth_config)

    # Patch resolver to spy on preload_sdk_config
    mock_preload = Mock()
    auth._config_resolver.preload_sdk_config = mock_preload

    auth.discover()

    mock_preload.assert_called_once()
