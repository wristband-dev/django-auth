import time
from typing import Optional
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory

from tests.utilities import test_login_state_secret
from wristband.django_auth.auth import WristbandAuth
from wristband.django_auth.models import (
    AuthConfig,
    CallbackFailureReason,
    CallbackResultType,
    CompletedCallbackResult,
    LoginConfig,
    LoginState,
    LogoutConfig,
    RedirectRequiredCallbackResult,
    UserInfo,
    WristbandTokenResponse,
)

VANITY_DOMAIN = "auth.example.com"
ROOT_DOMAIN = "business.invotastic.com"

factory = RequestFactory()


def create_auth(
    use_tenant_subdomains: bool = True,
    application_authorization_requests_enabled: Optional[bool] = True,
    custom_application_login_page_url: Optional[str] = None,
    login_state_secret: str = test_login_state_secret,
) -> WristbandAuth:
    host = f"{{tenant_name}}.{ROOT_DOMAIN}" if use_tenant_subdomains else ROOT_DOMAIN
    return WristbandAuth(
        AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=login_state_secret,
            login_url=f"https://{host}/api/auth/login",
            redirect_uri=f"https://{host}/api/auth/callback",
            wristband_application_vanity_domain=VANITY_DOMAIN,
            application_authorization_requests_enabled=application_authorization_requests_enabled,
            custom_application_login_page_url=custom_application_login_page_url,
            auto_configure_enabled=False,
        )
    )


def make_request(host: str, path: str, query: Optional[dict] = None, secure: bool = True) -> HttpRequest:
    return factory.get(path, data=query or {}, HTTP_HOST=host, secure=secure)


def login_cookies(response: HttpResponse) -> dict:
    return {key: cookie for key, cookie in response.cookies.items() if key.startswith("login#")}


def encrypted_login_state_cookie(auth: WristbandAuth, return_url: Optional[str] = None) -> dict:
    login_state = LoginState(
        state="test_state",
        code_verifier="test_verifier",
        redirect_uri=f"https://devs4you.{ROOT_DOMAIN}/api/auth/callback",
        return_url=return_url,
        custom_state=None,
    )
    return {"login#test_state#1640995200000": auth._encrypt_login_state(login_state)}


MOCK_TOKENS = WristbandTokenResponse(
    access_token="access_token",
    id_token="id_token",
    expires_in=3600,
    refresh_token="refresh_token",
    token_type="Bearer",
    scope="openid offline_access email",
)
MOCK_USERINFO = UserInfo(user_id="user", tenant_id="tenant", application_id="app", identity_provider_name="Wristband")


class TestLoginApplicationLevelAuthorizationRequests:
    def test_unresolved_tenant_redirects_to_app_level_authorize_endpoint(self) -> None:
        auth = create_auth()
        request = make_request(ROOT_DOMAIN, "/api/auth/login", {"return_url": "/settings", "login_hint": "a@b.com"})

        response = auth.login(request, LoginConfig(custom_state={"flow": "signup"}))

        location = urlparse(response["Location"])
        query = parse_qs(location.query)
        assert f"{location.scheme}://{location.netloc}{location.path}" == (
            f"https://{VANITY_DOMAIN}/api/v1/oauth2/authorize"
        )
        assert query["client_id"] == ["test_client_id"]
        assert query["redirect_uri"] == [f"https://{{tenant_name}}.{ROOT_DOMAIN}/api/auth/callback"]
        assert query["login_hint"] == ["a@b.com"]

        # The login state cookie is set on the root domain so the tenant subdomain callback can read it.
        cookies = login_cookies(response)
        assert len(cookies) == 1
        cookie_name, cookie = next(iter(cookies.items()))
        assert cookie["domain"] == f".{ROOT_DOMAIN}"
        assert cookie_name.startswith(f"login#{query['state'][0]}#")

        # The return URL and custom state are preserved in the login state cookie.
        login_state = auth._decrypt_login_state(cookie.value)
        assert login_state is not None
        assert login_state.return_url == "/settings"
        assert login_state.custom_state == {"flow": "signup"}

    def test_unresolved_tenant_without_tenant_subdomains_sets_host_only_cookie(self) -> None:
        auth = create_auth(use_tenant_subdomains=False)

        response = auth.login(make_request(ROOT_DOMAIN, "/api/auth/login"))

        assert response["Location"].startswith(f"https://{VANITY_DOMAIN}/api/v1/oauth2/authorize?")
        cookies = login_cookies(response)
        assert len(cookies) == 1
        assert not next(iter(cookies.values()))["domain"]

    def test_custom_application_login_page_url_has_no_effect_when_enabled(self) -> None:
        auth = create_auth(custom_application_login_page_url="https://custom.example.com/login")

        response = auth.login(make_request(ROOT_DOMAIN, "/api/auth/login"))

        assert response["Location"].startswith(f"https://{VANITY_DOMAIN}/api/v1/oauth2/authorize?")

    def test_resolved_tenant_uses_tenant_level_flow_with_root_domain_cookie(self) -> None:
        auth = create_auth()

        response = auth.login(make_request(f"devs4you.{ROOT_DOMAIN}", "/api/auth/login"))

        assert response["Location"].startswith(f"https://devs4you-{VANITY_DOMAIN}/api/v1/oauth2/authorize?")
        cookies = login_cookies(response)
        assert len(cookies) == 1
        assert next(iter(cookies.values()))["domain"] == f".{ROOT_DOMAIN}"

    def test_resolved_tenant_sets_host_only_cookie_when_disabled(self) -> None:
        auth = create_auth(application_authorization_requests_enabled=False)

        response = auth.login(make_request(f"devs4you.{ROOT_DOMAIN}", "/api/auth/login"))

        cookies = login_cookies(response)
        assert len(cookies) == 1
        assert not next(iter(cookies.values()))["domain"]

    def test_stale_login_state_cookies_are_cleared_on_the_root_domain(self) -> None:
        auth = create_auth()
        request = make_request(ROOT_DOMAIN, "/api/auth/login")
        request.COOKIES = {"login#a#1000": "x", "login#b#2000": "y", "login#c#3000": "z"}

        response = auth.login(request)

        cleared = response.cookies["login#a#1000"]
        assert cleared["domain"] == f".{ROOT_DOMAIN}"
        assert cleared["max-age"] == 0

    def test_unresolved_tenant_redirects_to_app_login_page_with_return_url_when_disabled(self) -> None:
        auth = create_auth(application_authorization_requests_enabled=False)

        response = auth.login(make_request(ROOT_DOMAIN, "/api/auth/login", {"return_url": "/a?b=c"}))

        assert response["Location"] == f"https://{VANITY_DOMAIN}/login?client_id=test_client_id&state=/a%3Fb%3Dc"
        assert login_cookies(response) == {}


class TestCallbackApplicationLevelAuthorizationRequests:
    def _run_callback(self, auth: WristbandAuth, return_url: Optional[str], host: str, secure: bool = True):
        request = make_request(host, "/api/auth/callback", {"code": "code", "state": "test_state"}, secure=secure)
        request.COOKIES = encrypted_login_state_cookie(auth, return_url)
        with (
            patch.object(auth._wristband_api, "get_tokens", return_value=MOCK_TOKENS),
            patch.object(auth._wristband_api, "get_userinfo", return_value=MOCK_USERINFO),
        ):
            return auth.callback(request)

    def test_root_domain_return_url_is_rewritten_to_tenant_subdomain(self) -> None:
        auth = create_auth()
        result = self._run_callback(auth, f"https://{ROOT_DOMAIN}/dashboard?tab=1", f"devs4you.{ROOT_DOMAIN}")
        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.return_url == f"https://devs4you.{ROOT_DOMAIN}/dashboard?tab=1"

    def test_root_domain_return_url_is_not_rewritten_when_disabled(self) -> None:
        auth = create_auth(application_authorization_requests_enabled=False)
        result = self._run_callback(auth, f"https://{ROOT_DOMAIN}/dashboard", f"devs4you.{ROOT_DOMAIN}")
        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.return_url == f"https://{ROOT_DOMAIN}/dashboard"

    @pytest.mark.parametrize(
        "return_url,expected",
        [
            ("/settings?tab=billing", "/settings?tab=billing"),
            (f"https://devs4you.{ROOT_DOMAIN}/dashboard", f"https://devs4you.{ROOT_DOMAIN}/dashboard"),
            ("https://evil.com/phish", None),
            ("//evil.com/phish", None),
            (f"https://other.{ROOT_DOMAIN}/dashboard", None),
            (f"http://devs4you.{ROOT_DOMAIN}/dashboard", None),
        ],
    )
    def test_return_url_validation(self, return_url, expected) -> None:
        auth = create_auth()
        result = self._run_callback(auth, return_url, f"devs4you.{ROOT_DOMAIN}")
        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.return_url == expected

    def test_relative_return_url_is_allowed_on_http_request(self) -> None:
        auth = create_auth()
        result = self._run_callback(auth, "/home", f"devs4you.{ROOT_DOMAIN}", secure=False)
        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.return_url == "/home"

    def test_undecryptable_cookie_returns_invalid_login_state(self) -> None:
        auth = create_auth()
        other_auth = create_auth(login_state_secret="z" * 32)
        request = make_request(f"devs4you.{ROOT_DOMAIN}", "/api/auth/callback", {"code": "code", "state": "test_state"})
        request.COOKIES = encrypted_login_state_cookie(other_auth)

        result = auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert result.reason == CallbackFailureReason.INVALID_LOGIN_STATE
        assert result.redirect_url == f"https://devs4you.{ROOT_DOMAIN}/api/auth/login"

    def test_expired_cookie_returns_invalid_login_state(self) -> None:
        auth = create_auth()
        request = make_request(f"devs4you.{ROOT_DOMAIN}", "/api/auth/callback", {"code": "code", "state": "test_state"})
        request.COOKIES = encrypted_login_state_cookie(auth)

        with patch("cryptography.fernet.time.time", return_value=time.time() + 3600 + 61):
            result = auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.reason == CallbackFailureReason.INVALID_LOGIN_STATE

    def test_create_callback_response_clears_cookie_on_root_domain(self) -> None:
        auth = create_auth()
        request = make_request(f"devs4you.{ROOT_DOMAIN}", "/api/auth/callback", {"state": "test_state"})
        request.COOKIES = {"login#test_state#1640995200000": "value"}

        response = auth.create_callback_response(request, "/home")

        cleared = response.cookies["login#test_state#1640995200000"]
        assert cleared["domain"] == f".{ROOT_DOMAIN}"
        assert cleared["max-age"] == 0


class TestLogoutApplicationLevelAuthorizationRequests:
    def test_unresolved_tenant_redirects_to_login_url_without_tenant_subdomain(self) -> None:
        response = create_auth().logout(make_request(ROOT_DOMAIN, "/api/auth/logout"))
        assert response["Location"] == f"https://{ROOT_DOMAIN}/api/auth/login"

    def test_unresolved_tenant_redirects_to_login_url_without_tenant_subdomains(self) -> None:
        response = create_auth(use_tenant_subdomains=False).logout(make_request(ROOT_DOMAIN, "/api/auth/logout"))
        assert response["Location"] == f"https://{ROOT_DOMAIN}/api/auth/login"

    def test_redirect_url_takes_precedence_over_app_level_fallback(self) -> None:
        response = create_auth().logout(
            make_request(ROOT_DOMAIN, "/api/auth/logout"), LogoutConfig(redirect_url="https://redirect.example.com")
        )
        assert response["Location"] == "https://redirect.example.com"

    def test_custom_application_login_page_url_has_no_effect_when_enabled(self) -> None:
        auth = create_auth(custom_application_login_page_url="https://custom.example.com/login")
        response = auth.logout(make_request(ROOT_DOMAIN, "/api/auth/logout"))
        assert response["Location"] == f"https://{ROOT_DOMAIN}/api/auth/login"

    def test_unresolved_tenant_redirects_to_app_login_page_when_disabled(self) -> None:
        auth = create_auth(application_authorization_requests_enabled=False)
        response = auth.logout(make_request(ROOT_DOMAIN, "/api/auth/logout"))
        assert response["Location"] == f"https://{VANITY_DOMAIN}/login?client_id=test_client_id"
