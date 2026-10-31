from http.cookies import SimpleCookie

import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal.web_support import CSRF_COOKIE_NAME, CSRF_COOKIE_PATH
from tests.support import (
    RecordingPortalEmailSender,
    csrf_token_from_response,
    migrated_development_app,
)
from tests.test_public_device_path import SplitProxy


@pytest.mark.parametrize(
    ("configured_prefix", "wire_prefix"),
    [
        pytest.param("/患者", "/%E6%82%A3%E8%80%85", id="unicode"),
        pytest.param("/%E6%82%A3%E8%80%85", "/%E6%82%A3%E8%80%85", id="escaped"),
        pytest.param("/patients:archive@main", "/patients:archive@main", id="ascii_reserved"),
    ],
)
def test_unicode_deployment_prefix_can_set_and_receive_the_browser_csrf_cookie(
    configured_prefix, wire_prefix
) -> None:
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(
        public_base_url="https://portal.example.test" + configured_prefix,
        email_sender=sender,
    )
    assert app.root_path == configured_prefix
    proxy = SplitProxy(app, configured_prefix, wire_prefix)
    with TestClient(
        proxy, base_url="https://portal.example.test", raise_server_exceptions=False
    ) as client:
        landing = client.get(wire_prefix + "/")
        assert landing.status_code == 200
        cookies = SimpleCookie()
        for header in landing.headers.get_list("set-cookie"):
            cookies.load(header)
            assert header.isascii()
        assert cookies[CSRF_COOKIE_NAME]["path"] == wire_prefix + CSRF_COOKIE_PATH

        submitted = client.post(
            wire_prefix + "/auth/password-reset/request",
            data={
                "csrf_token": csrf_token_from_response(landing),
                "username": "FAKE.unknown.patient",
                "email": "FAKE-unknown@example.test",
            },
            follow_redirects=False,
        )
        assert submitted.status_code == 202
        incoming_headers = dict(proxy.observed[-1][1]["headers"])
        assert (CSRF_COOKIE_NAME + "=").encode() in incoming_headers[b"cookie"]
        assert sender.messages == []
