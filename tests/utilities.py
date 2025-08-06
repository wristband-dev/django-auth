from datetime import datetime, timezone
from typing import Dict, List, Tuple
from urllib.parse import ParseResult, parse_qs, urlparse

from django.http import HttpResponse

from wristband.django_auth.models import LoginState
from wristband.django_auth.utils import SessionEncryptor

# Shared test secret
test_login_state_secret = "this_is_a_very_long_secret_key_for_testing_purposes_123456789"

# Singleton encryptor instance (use a real secret from your settings or env)
_login_state_encryptor = SessionEncryptor(test_login_state_secret)


def assert_redirect_no_cache(
    response: HttpResponse,
    expected_url: str,
) -> Tuple[ParseResult, Dict[str, List[str]]]:
    assert response.status_code == 302, f"Expected status 302 but got {response.status_code}"
    assert (
        response["Cache-Control"] == "no-store"
    ), f"Expected Cache-Control no-store but got {response['Cache-Control']}"
    assert response["Pragma"] == "no-cache", f"Expected Pragma no-cache but got {response['Pragma']}"

    # URL comparison
    parsed_url = urlparse(response["Location"])
    expected = urlparse(expected_url)
    assert parsed_url.scheme == expected.scheme, f"Expected scheme {expected.scheme}, got {parsed_url.scheme}"
    assert parsed_url.netloc == expected.netloc, f"Expected netloc {expected.netloc}, got {parsed_url.netloc}"
    assert parsed_url.path == expected.path, f"Expected path {expected.path}, got {parsed_url.path}"

    # Query params
    query_params = parse_qs(parsed_url.query)

    return parsed_url, query_params


def assert_single_login_cookie_valid(response: HttpResponse) -> Tuple[str, str]:
    login_cookies = [(key, response.cookies[key]) for key in response.cookies.keys() if key.startswith("login#")]

    assert len(login_cookies) == 1, f"Expected 1 login cookie, found {len(login_cookies)}"

    cookie_name, morsel = login_cookies[0]

    parts = cookie_name.split("#")
    assert len(parts) == 3, f"Cookie name structure invalid: {cookie_name}"
    _, _, timestamp_str = parts
    timestamp = int(timestamp_str)
    assert timestamp > 0

    # Assert cookie has a value
    assert morsel.value, "Cookie value is missing or empty"

    # Assert expiry
    expires_raw = morsel["expires"]
    expires_dt = datetime.strptime(expires_raw, "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    # Other attributes
    assert expires_dt > now, f"Cookie expiration {expires_dt} is not in the future"
    assert morsel["httponly"] is True
    assert morsel["max-age"] == 3600
    assert morsel["path"] == "/"
    assert morsel["samesite"].lower() == "lax"
    assert morsel["secure"] is True

    return cookie_name, morsel.value


def assert_authorize_query_params(
    query_params: dict, client_id: str, redirect_uri: str, scopes: str = "openid offline_access email"
):
    assert query_params["client_id"] == [
        client_id
    ], f"Expected client_id to be [{client_id}], but got {query_params['client_id']}"
    assert query_params["redirect_uri"] == [
        redirect_uri
    ], f"Expected redirect_uri to be [{redirect_uri}], but got {query_params['redirect_uri']}"
    assert query_params["scope"] == [scopes], f"Expected scope to be [{scopes}], but got {query_params["scope"]}"

    assert query_params["response_type"] == ["code"]
    assert query_params["code_challenge_method"] == ["S256"]

    assert "state" in query_params and len(query_params["state"][0]) > 0, "Missing or empty 'state'"
    assert "nonce" in query_params and len(query_params["nonce"][0]) > 0, "Missing or empty 'nonce'"
    assert (
        "code_challenge" in query_params and len(query_params["code_challenge"][0]) > 0
    ), "Missing or empty 'code_challenge'"


def encrypt_login_state(login_state: LoginState) -> str:
    return _login_state_encryptor.encrypt(login_state.to_dict())


def decrypt_login_state(login_state_cookie: str) -> LoginState:
    login_state_dict = _login_state_encryptor.decrypt(login_state_cookie)
    return LoginState(**login_state_dict)
