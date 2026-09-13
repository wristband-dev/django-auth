import time
from unittest.mock import Mock

import httpx
import pytest

from wristband.django_auth.exceptions import WristbandError
from wristband.django_auth.retry import (
    API_RETRY_DELAY_MULTIPLIER,
    API_RETRY_DELAY_SECONDS,
    MAX_API_RETRY_ATTEMPTS,
    with_retry,
)


def _http_status_error(status_code: int) -> httpx.HTTPStatusError:
    response = httpx.Response(status_code, request=httpx.Request("GET", "https://example.com"))
    return httpx.HTTPStatusError(f"{status_code} error", request=response.request, response=response)


class TestWithRetry:
    """Test cases for the with_retry helper."""

    def test_returns_on_first_attempt_without_retrying(self):
        fn = Mock(return_value="result")

        result = with_retry(fn)

        assert result == "result"
        assert fn.call_count == 1

    def test_retries_on_a_5xx_http_status_error_and_eventually_succeeds(self):
        fn = Mock(side_effect=[_http_status_error(500), _http_status_error(503), "result"])

        result = with_retry(fn)

        assert result == "result"
        assert fn.call_count == 3

    def test_retries_on_a_network_error_and_eventually_succeeds(self):
        fn = Mock(side_effect=[httpx.ConnectError("Network failure"), "result"])

        result = with_retry(fn)

        assert result == "result"
        assert fn.call_count == 2

    def test_retries_on_a_wristband_error_with_a_5xx_status_code(self):
        fn = Mock(side_effect=[WristbandError("unexpected_error", "boom", status_code=502), "result"])

        result = with_retry(fn)

        assert result == "result"
        assert fn.call_count == 2

    def test_does_not_retry_on_a_4xx_http_status_error(self):
        fn = Mock(side_effect=_http_status_error(400))

        with pytest.raises(httpx.HTTPStatusError):
            with_retry(fn)

        assert fn.call_count == 1

    def test_does_not_retry_on_a_404_http_status_error(self):
        fn = Mock(side_effect=_http_status_error(404))

        with pytest.raises(httpx.HTTPStatusError):
            with_retry(fn)

        assert fn.call_count == 1

    def test_does_not_retry_on_a_wristband_error_with_a_4xx_status_code(self):
        fn = Mock(side_effect=WristbandError("invalid_request", "bad request", status_code=400))

        with pytest.raises(WristbandError):
            with_retry(fn)

        assert fn.call_count == 1

    def test_exhausts_retries_and_raises_the_last_error_on_persistent_5xx_failures(self):
        fn = Mock(side_effect=_http_status_error(500))

        with pytest.raises(httpx.HTTPStatusError):
            with_retry(fn)

        assert fn.call_count == MAX_API_RETRY_ATTEMPTS

    def test_exhausts_retries_and_raises_the_last_error_on_persistent_network_failures(self):
        fn = Mock(side_effect=httpx.ConnectError("Persistent network failure"))

        with pytest.raises(httpx.ConnectError):
            with_retry(fn)

        assert fn.call_count == MAX_API_RETRY_ATTEMPTS

    def test_waits_between_retry_attempts(self):
        fn = Mock(side_effect=[_http_status_error(500), "result"])

        start_time = time.monotonic()
        with_retry(fn)
        elapsed = time.monotonic() - start_time

        assert elapsed >= API_RETRY_DELAY_SECONDS - 0.01

    def test_does_not_wait_after_a_non_retryable_error(self):
        fn = Mock(side_effect=_http_status_error(400))

        start_time = time.monotonic()
        with pytest.raises(httpx.HTTPStatusError):
            with_retry(fn)
        elapsed = time.monotonic() - start_time

        assert elapsed < API_RETRY_DELAY_SECONDS

    def test_applies_exponential_backoff_multiplying_the_delay_after_each_retry(self):
        fn = Mock(side_effect=[_http_status_error(500), _http_status_error(500), "result"])

        expected_min_elapsed = API_RETRY_DELAY_SECONDS + API_RETRY_DELAY_SECONDS * API_RETRY_DELAY_MULTIPLIER

        start_time = time.monotonic()
        with_retry(fn)
        elapsed = time.monotonic() - start_time

        assert elapsed >= expected_min_elapsed - 0.01
