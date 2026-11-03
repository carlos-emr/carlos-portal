from fastapi.testclient import TestClient

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
