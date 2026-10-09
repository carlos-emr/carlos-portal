from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal.config import Settings
from carlos_patient_portal.footer_audit import FooterAuditStore
from carlos_patient_portal.footer_audit_routes import PERMISSION_EMAIL_AUDIT_READ
from carlos_patient_portal.main import create_app
from carlos_patient_portal.staff_identity import staff_request_hash
from tests.footer_support import fake_footer
from tests.support import (
    INTERNAL_API_TOKEN,
    TEST_STAFF_ASSERTION_PUBLIC_KEYRING,
    carlos_staff_headers,
    upgrade_to_head,
)

ROUTE = "/internal/carlos/email-footer-attempts"


def headers(
    path=ROUTE,
    *,
    permission=PERMISSION_EMAIL_AUDIT_READ,
    clinic_id="clinic-a",
    token=INTERNAL_API_TOKEN,
):
    parsed = urlsplit(path)
    digest = staff_request_hash("GET", parsed.path.encode(), parsed.query.encode(), b"")
    return carlos_staff_headers(permission, clinic_id=clinic_id, token=token, request_hash=digest)


@pytest.fixture
def audit_app(tmp_path):
    tmp_path.chmod(0o700)
    settings = Settings(
        environment="development",
        clinic_id="clinic-a",
        database_url="sqlite+pysqlite:///:memory:",
        internal_api_token=INTERNAL_API_TOKEN,
        internal_staff_assertion_public_keyring=TEST_STAFF_ASSERTION_PUBLIC_KEYRING,
        email_footer_audit_directory=str(tmp_path),
    )
    app = create_app(settings)
    upgrade_to_head(app.state.database_engine)
    store = FooterAuditStore(str(tmp_path), settings.clinic_id)
    return app, store


def test_authorized_administrator_reads_saved_footer_metadata_without_html_or_logo_body(audit_app):
    app, store = audit_app
    attempt = store.prepare(fake_footer("clinic-a", text="FAKE Clinic A"), "password_reset")
    store.record_outcome(attempt, "accepted")
    with TestClient(app) as client:
        response = client.get(ROUTE, headers=headers())
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["date"] == attempt.date
    item = response.json()["attempts"][0]
    assert item["status"] == "accepted"
    assert item["footer_text"] == "FAKE Clinic A"
    assert set(item) == {
        "attempt_id",
        "kind",
        "prepared_at",
        "status",
        "status_at",
        "clinic_id",
        "revision",
        "footer_text",
        "logo_sha256",
    }
    assert "footer_html" not in response.text
    assert "bytes_base64" not in response.text


def test_audit_reads_old_snapshot_after_provider_configuration_changes(audit_app):
    app, store = audit_app
    original = store.prepare(fake_footer("clinic-a", text="FAKE Original Clinic"), "mfa")
    store.prepare(fake_footer("clinic-a", text="FAKE Changed Clinic"), "mfa")
    with TestClient(app) as client:
        response = client.get(ROUTE, headers=headers())
    assert response.status_code == 200
    by_id = {item["attempt_id"]: item for item in response.json()["attempts"]}
    assert by_id[original.attempt_id]["footer_text"] == "FAKE Original Clinic"
    assert by_id[original.attempt_id]["status"] == "prepared"


def test_missing_permission_denies_before_storage_and_validation(audit_app, tmp_path):
    app, _ = audit_app
    tmp_path.chmod(0o755)
    path = ROUTE + "?limit=999"
    with TestClient(app) as client:
        response = client.get(path, headers=headers(path, permission="portal.invite.manage"))
    assert response.status_code == 403
    assert "footer" not in response.text


def test_root_bearer_without_signed_staff_assertion_and_derived_read_token_cannot_read_audit(
    audit_app,
):
    app, _ = audit_app
    with TestClient(app) as client:
        no_assertion = client.get(ROUTE, headers={"Authorization": "Bearer " + INTERNAL_API_TOKEN})
        narrow = client.get(ROUTE, headers=headers(token="d" * 64))
    assert no_assertion.status_code == 404
    assert narrow.status_code == 404


def test_single_use_assertion_replay_refused(audit_app):
    app, _ = audit_app
    authentication = headers()
    with TestClient(app) as client:
        assert client.get(ROUTE, headers=authentication).status_code == 200
        assert client.get(ROUTE, headers=authentication).status_code == 404


def test_assertion_bound_to_exact_query_and_clinic(audit_app):
    app, _ = audit_app
    with TestClient(app) as client:
        wrong_query = client.get(ROUTE + "?limit=1", headers=headers())
        wrong_clinic = client.get(ROUTE, headers=headers(clinic_id="clinic-b"))
    assert wrong_query.status_code == 404
    assert wrong_clinic.status_code == 404


def test_authenticated_cursor_and_date_constraints(audit_app):
    app, store = audit_app
    attempts = [store.prepare(fake_footer("clinic-a"), "mfa") for _ in range(3)]
    path = ROUTE + "?date=" + attempts[0].date + "&limit=2"
    with TestClient(app) as client:
        first = client.get(path, headers=headers(path))
        assert first.status_code == 200
        cursor = first.json()["next_before"]
        next_path = path + "&before=" + cursor
        second = client.get(next_path, headers=headers(next_path))
        assert second.status_code == 200
        assert len(first.json()["attempts"]) == 2
        assert len(second.json()["attempts"]) == 1
        invalid = ROUTE + "?before=..%2Foutside"
        assert client.get(invalid, headers=headers(invalid)).status_code == 422
        impossible = ROUTE + "?date=2026-02-30"
        assert client.get(impossible, headers=headers(impossible)).status_code == 422


def test_missing_private_storage_not_reported_as_empty_history(audit_app, tmp_path):
    app, _ = audit_app
    tmp_path.chmod(0o755)
    with TestClient(app) as client:
        response = client.get(ROUTE, headers=headers())
    assert response.status_code == 503
    assert response.json() == {"detail": "clinic footer audit is unavailable"}


def test_mixed_clinic_corrupt_evidence_yields_no_partial_disclosure(audit_app, tmp_path):
    app, store = audit_app
    # Older foreign record is reached only AFTER a valid newer record was buffered.
    foreign = FooterAuditStore(str(tmp_path), "clinic-b")
    foreign.prepare(fake_footer("clinic-b", text="FAKE Foreign Clinic"), "mfa")
    store.prepare(fake_footer("clinic-a", text="FAKE Own Clinic"), "mfa")
    with TestClient(app) as client:
        response = client.get(ROUTE, headers=headers())
    assert response.status_code == 503
    assert "FAKE Foreign Clinic" not in response.text
    assert "FAKE Own Clinic" not in response.text
