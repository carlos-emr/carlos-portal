import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal.i18n import LOCALE_COOKIE_NAME, portal_text
from carlos_patient_portal.web_support import SECURITY_HEADERS
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    migrated_development_app,
)
from tests.test_link_lifecycle_routes import PREFIX, StrippingProxy


def test_login_alias_routed_under_root_path_cannot_escape_the_same_authentication_budget():
    app = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        public_base_url="https://portal.example.test" + PREFIX,
        auth_rate_limit_max_requests=1,
        global_rate_limit_max_requests=100,
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    proxy = StrippingProxy(app)
    body = {"username": "fake.missing.user", "password": "FAKE missing account password 84"}
    path = PREFIX + "/auth/login"
    alias = PREFIX + path
    with TestClient(proxy, base_url="https://portal.example.test") as client:
        first = client.post(path, json=body)
        assert first.status_code == 401
        spent = client.post(path, json=body)
        assert spent.status_code == 429
        assert int(spent.headers["retry-after"]) > 0

        # The real proxy strips exactly one prefix. Routing may accept the remaining
        # prefix as root_path, so its security classification must use the same path.
        repeated_prefix = client.post(alias, json=body)

        assert proxy.observed_paths == [path.encode(), path.encode(), alias.encode()]
        assert repeated_prefix.status_code == 429
        assert int(repeated_prefix.headers["retry-after"]) > 0
        assert repeated_prefix.headers["cache-control"] == "no-store"


def test_static_child_path_named_fhir_keeps_its_browser_404_after_mount_dispatch():
    app = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        public_base_url="https://portal.example.test",
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    with TestClient(app, base_url="https://portal.example.test") as client:
        asset = client.get("/static/styles.css")
        assert asset.status_code == 200
        assert asset.headers["content-type"].startswith("text/css")
        missing = client.get("/static/fhir/FAKE-missing-boundary")

        assert missing.status_code == 404
        assert missing.headers["content-type"].startswith("text/html")
        assert "OperationOutcome" not in missing.text


def test_fhir_method_error_uses_the_captured_portal_path_after_alias_dispatch():
    app = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        public_base_url="https://portal.example.test" + PREFIX,
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    with TestClient(StrippingProxy(app), base_url="https://portal.example.test") as client:
        path = PREFIX + "/fhir/metadata"
        canonical = client.post(path, json={})
        assert canonical.status_code == 405
        assert canonical.json()["resourceType"] == "OperationOutcome"

        alias = client.post(PREFIX + path, json={})

        assert alias.status_code == 405
        assert alias.json() == canonical.json()
        assert alias.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    ("method", "application_path", "headers", "expected_type"),
    [
        ("GET", "/FAKE/error-boundary", {"Accept": "text/html"}, "text/html"),
        ("GET", "/FAKE/error-boundary", {"Accept": "application/json"}, "application/json"),
        (
            "GET",
            "/FAKE/error-boundary",
            {"Authorization": "Bearer FAKE-not-a-session"},
            "application/json",
        ),
        ("HEAD", "/FAKE/error-boundary", {"Accept": "text/html"}, "application/json"),
        ("GET", "/fhir/FAKE/error-boundary", {"Accept": "text/html"}, "application/fhir+json"),
    ],
    ids=["browser", "json", "bearer", "head", "fhir"],
)
def test_prefixed_unhandled_errors_keep_response_contract_and_privacy(
    method, application_path, headers, expected_type
):
    app = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        public_base_url="https://portal.example.test" + PREFIX,
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    private_marker = "FAKE-private-error-value-8e5d"

    def fail():
        raise RuntimeError(private_marker)

    app.add_api_route(application_path, fail, methods=["GET", "HEAD"])
    with TestClient(
        StrippingProxy(app),
        base_url="https://portal.example.test",
        raise_server_exceptions=False,
    ) as client:
        client.cookies.set(LOCALE_COOKIE_NAME, "pl")
        response = client.request(
            method,
            PREFIX + application_path,
            headers=headers,
        )

    assert response.status_code == 500
    assert response.headers["content-type"].startswith(expected_type)
    assert response.headers["cache-control"] == "no-store"
    assert "content-security-policy" in response.headers
    for header, value in SECURITY_HEADERS.items():
        assert response.headers[header] == value
    assert private_marker not in response.text
    if method == "HEAD":
        assert response.content == b""
    elif expected_type == "text/html":
        assert '<html lang="pl">' in response.text
        assert portal_text("pl")["service_unavailable_heading"] in response.text
        assert f'href="{PREFIX}/"' in response.text
    elif expected_type == "application/fhir+json":
        assert response.json()["resourceType"] == "OperationOutcome"
        assert response.json()["issue"][0]["code"] == "exception"
    else:
        assert response.json() == {"detail": "the request could not be completed"}
