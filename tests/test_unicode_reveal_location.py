import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal.web_support import CSRF_COOKIE_NAME, PORTAL_SESSION_COOKIE_NAME
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
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
def test_stale_browser_reveal_returns_a_usable_ascii_sign_in_location(
    configured_prefix, wire_prefix
) -> None:
    app = migrated_development_app(
        public_base_url="https://portal.example.test" + configured_prefix,
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    proxy = SplitProxy(app, configured_prefix, wire_prefix)
    with TestClient(
        proxy, base_url="https://portal.example.test", raise_server_exceptions=False
    ) as client:
        landing = client.get(wire_prefix + "/")
        assert landing.status_code == 200
        csrf_token = csrf_token_from_response(landing)
        # Model a cached signed-in form's valid CSRF cookie with a now-invalid session.
        # These are private fixture cookies; no account or real patient is needed.
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token, path=wire_prefix + "/portal")
        client.cookies.set(
            PORTAL_SESSION_COOKIE_NAME,
            "FAKE-stale-browser-credential",
            path=wire_prefix + "/portal",
        )

        refused = client.post(
            wire_prefix + "/portal/email-passwords/1/reveal",
            data={"csrf_token": csrf_token, "current_password": "FAKE-current-password"},
            follow_redirects=False,
        )

        assert refused.status_code == 401
        assert refused.json() == {"detail": "authentication required"}
        assert refused.headers["location"] == wire_prefix + "/"
        assert refused.headers["location"].isascii()
        assert "passphrase" not in refused.json()
        assert client.get(refused.headers["location"]).status_code == 200
