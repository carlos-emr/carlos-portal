"""A browser must clear the same path-scoped session cookie that the portal issued."""

from email.message import Message
from http.cookiejar import CookieJar
from types import SimpleNamespace
from urllib.request import Request

import pytest
from starlette.responses import Response

from carlos_patient_portal.web_support import (
    PORTAL_SESSION_COOKIE_NAME,
    clear_portal_session_cookie,
    set_portal_session_cookie,
)
from tests.support import development_settings, staging_settings


def accept_cookies(jar, response, url):
    headers = Message()
    for value in response.headers.getlist("set-cookie"):
        headers.add_header("Set-Cookie", value)
    # CookieJar consumes response metadata only; no URL is fetched.
    request = Request(url)  # noqa: S310 - metadata for CookieJar; no URL is opened
    jar.extract_cookies(SimpleNamespace(info=lambda: headers), request)


def cookies_for(jar, url):
    request = Request(url)  # noqa: S310 - metadata for CookieJar; no URL is opened
    jar.add_cookie_header(request)
    return request.get_header("Cookie")


@pytest.mark.parametrize(
    ("settings_factory", "prefix"),
    [
        (development_settings, ""),
        (development_settings, "/patient"),
        (staging_settings, "/clinic/patient"),
    ],
)
def test_session_cookie_scope_and_deletion_match_the_deployment_path(settings_factory, prefix):
    origin = "https://portal.example.test"
    settings = settings_factory(public_base_url=origin + prefix)
    jar = CookieJar()
    issued = Response()
    set_portal_session_cookie(issued, "FAKE_test_session_value", settings=settings)
    accept_cookies(jar, issued, origin + prefix + "/auth/mfa/verify")

    assert cookies_for(jar, origin + prefix + "/portal/account") == (
        f"{PORTAL_SESSION_COOKIE_NAME}=FAKE_test_session_value"
    )
    # Cookie paths are route boundaries, not arbitrary matching text prefixes.
    assert cookies_for(jar, origin + prefix + "/portal-unrelated") is None
    assert cookies_for(jar, origin + prefix + "/auth/login") is None
    if not settings.is_development:
        assert cookies_for(jar, "http://portal.example.test" + prefix + "/portal/account") is None

    cleared = Response()
    clear_portal_session_cookie(cleared, settings=settings)
    accept_cookies(jar, cleared, origin + prefix + "/portal/logout")

    assert cookies_for(jar, origin + prefix + "/portal/account") is None
    assert list(jar) == []
