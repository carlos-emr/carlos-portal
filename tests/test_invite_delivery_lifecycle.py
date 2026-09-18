from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.maintenance import cleanup_transient_auth_rows
from carlos_patient_portal.models import (
    AUDIT_EVENT_INVITE_REVOKE,
    PatientPortalAuditEvent,
    PatientPortalInvite,
    utc_now,
)
from tests.support import DEV_ADMIN_TOKEN, activation_request, dev_admin_headers
from tests.test_internal_api import carlos_headers, internal_app, invite_request


@pytest.mark.parametrize("endpoint", ["internal", "development"])
def test_legacy_resend_rejects_prepared_invite_without_changing_it(endpoint) -> None:
    app = internal_app(enable_dev_admin=True, dev_admin_token=DEV_ADMIN_TOKEN)
    client = TestClient(app, raise_server_exceptions=False)
    prepared = client.post(
        "/internal/carlos/patients/1234/invites/prepare",
        headers=carlos_headers("portal.invite.manage"),
        json={**invite_request(), "delivery_operation_id": "legacy-resend-preparation"},
    )
    assert prepared.status_code == 201
    invite_id = prepared.json()["id"]
    prefix = "/internal/carlos" if endpoint == "internal" else "/dev/admin"
    headers = (
        carlos_headers("portal.invite.manage") if endpoint == "internal" else dev_admin_headers()
    )
    response = client.post(f"{prefix}/invites/{invite_id}/resend", headers=headers)

    assert response.status_code == 409
    assert response.json()["detail"] == "invite delivery is not committed"
    with app.state.session_factory() as session:
        invites = list(session.scalars(select(PatientPortalInvite)))
        assert len(invites) == 1
        assert invites[0].status == "prepared"
        assert invites[0].encrypted_invite_token is not None
        assert invites[0].invite_token_nonce is not None


@pytest.mark.parametrize("original_state", ["pending", "revoked", "superseded", "accepted"])
def test_prepare_resend_retry_rechecks_original_invite(original_state) -> None:
    app = internal_app()
    client = TestClient(app)
    headers = carlos_headers("portal.invite.manage")
    original = client.post(
        "/internal/carlos/patients/1234/invites", headers=headers, json=invite_request()
    )
    assert original.status_code == 201
    original_id = original.json()["id"]
    path = f"/internal/carlos/invites/{original_id}/resend/prepare"
    request = {"delivery_operation_id": "resend-retry-original-status"}
    prepared = client.post(path, headers=headers, json=request)
    assert prepared.status_code == 201
    if original_state in ("revoked", "superseded"):
        action = "revoke" if original_state == "revoked" else "resend"
        changed = client.post(f"/internal/carlos/invites/{original_id}/{action}", headers=headers)
        assert changed.status_code == 200
    elif original_state == "accepted":
        activated = client.post(
            "/auth/activate", json=activation_request(original.json()["invite_token"])
        )
        assert activated.status_code == 201

    repeated = client.post(path, headers=headers, json=request)
    committed = client.post(
        f"/internal/carlos/invites/{prepared.json()['id']}/commit-delivery",
        headers=headers,
        json={**request, "delivery_reference": "email:resend-retry-original-status"},
    )
    if original_state == "pending":
        assert repeated.status_code == 201
        assert repeated.json()["invite_token"] == prepared.json()["invite_token"]
        assert committed.status_code == 200
    else:
        assert repeated.status_code == 409
        assert "invite_token" not in repeated.json()
        assert prepared.json()["invite_token"] not in repeated.text
        assert committed.status_code == 409


def test_cleanup_preserves_revoked_original_until_prepared_resend_is_removed() -> None:
    app = internal_app()
    client = TestClient(app)
    headers = carlos_headers("portal.invite.manage")
    original = client.post(
        "/internal/carlos/patients/1234/invites", headers=headers, json=invite_request()
    )
    assert original.status_code == 201
    original_id = original.json()["id"]
    with app.state.session_factory.begin() as session:
        invite = session.get(PatientPortalInvite, original_id)
        invite.created_at = utc_now() - timedelta(days=70)
        invite.expires_at = utc_now() - timedelta(days=60)
    request = {"delivery_operation_id": "cleanup-preserved-resend"}
    prepared = client.post(
        f"/internal/carlos/invites/{original_id}/resend/prepare", headers=headers, json=request
    )
    assert prepared.status_code == 201
    prepared_id = prepared.json()["id"]
    revoked = client.post(f"/internal/carlos/invites/{original_id}/revoke", headers=headers)
    assert revoked.status_code == 200
    commit_path = f"/internal/carlos/invites/{prepared_id}/commit-delivery"
    commit_body = {**request, "delivery_reference": "email:cleanup-preserved-resend"}
    assert client.post(commit_path, headers=headers, json=commit_body).status_code == 409
    cutoff = utc_now() - timedelta(days=30)
    for dry_run in (True, False):
        with app.state.session_factory.begin() as session:
            result = cleanup_transient_auth_rows(session, before=cutoff, dry_run=dry_run)
            assert result.invites == 0
    with app.state.session_factory() as session:
        assert session.get(PatientPortalInvite, original_id).status == "revoked"
        assert session.get(PatientPortalInvite, prepared_id).supersedes_invite_id == original_id
    assert client.post(commit_path, headers=headers, json=commit_body).status_code == 409

    # Even if both are eligible, remove the child first. A later bounded pass can then
    # remove the parent without orphaning a live prepared resend.
    with app.state.session_factory.begin() as session:
        invite = session.get(PatientPortalInvite, prepared_id)
        invite.created_at = utc_now() - timedelta(days=50)
        invite.expires_at = utc_now() - timedelta(days=40)
    for expected_remaining in ([original_id], []):
        with app.state.session_factory.begin() as session:
            result = cleanup_transient_auth_rows(session, before=cutoff, batch_size=1)
            assert result.invites == 1
        with app.state.session_factory() as session:
            assert list(session.scalars(select(PatientPortalInvite.id))) == expected_remaining


IN_PROGRESS_DETAIL = "another invite delivery is being prepared"


def _expire(app, invite_id: int) -> None:
    with app.state.session_factory.begin() as session:
        invite = session.get(PatientPortalInvite, invite_id)
        invite.created_at = utc_now() - timedelta(days=8)
        invite.expires_at = utc_now() - timedelta(seconds=1)


@pytest.mark.parametrize(
    "abandonment", ["expired_first", "expired_resend", "original_resent", "original_revoked"]
)
def test_new_preparation_retires_abandoned_preparation(abandonment) -> None:
    app = internal_app()
    client = TestClient(app)
    headers = carlos_headers("portal.invite.manage")
    first_path = "/internal/carlos/patients/1234/invites/prepare"
    if abandonment == "expired_first":
        abandoned = client.post(
            first_path,
            headers=headers,
            json={**invite_request(), "delivery_operation_id": "abandoned-operation"},
        )
        next_path = first_path
        next_request = {**invite_request(), "delivery_operation_id": "next-operation"}
    else:
        original = client.post(
            "/internal/carlos/patients/1234/invites", headers=headers, json=invite_request()
        )
        current_id = original.json()["id"]
        abandoned = client.post(
            f"/internal/carlos/invites/{current_id}/resend/prepare",
            headers=headers,
            json={"delivery_operation_id": "abandoned-operation"},
        )
        if abandonment == "original_resent":
            resent = client.post(f"/internal/carlos/invites/{current_id}/resend", headers=headers)
            assert resent.status_code == 200
            current_id = resent.json()["id"]
        elif abandonment == "original_revoked":
            revoked = client.post(f"/internal/carlos/invites/{current_id}/revoke", headers=headers)
            assert revoked.status_code == 200
        next_path = f"/internal/carlos/invites/{current_id}/resend/prepare"
        next_request = {"delivery_operation_id": "next-operation"}
        if abandonment == "original_revoked":
            # The revoked original cannot be resent; staff start over with a first invite.
            next_path = first_path
            next_request = {**invite_request(), **next_request}
    assert abandoned.status_code == 201
    abandoned_id = abandoned.json()["id"]
    if abandonment.startswith("expired"):
        _expire(app, abandoned_id)

    prepared = client.post(next_path, headers=headers, json=next_request)

    assert prepared.status_code == 201
    assert prepared.json()["invite_token"] != abandoned.json()["invite_token"]
    with app.state.session_factory() as session:
        retired = session.get(PatientPortalInvite, abandoned_id)
        assert retired.status == "revoked"
        assert retired.encrypted_invite_token is None
        assert retired.invite_token_nonce is None
        events = list(
            session.scalars(
                select(PatientPortalAuditEvent).where(
                    PatientPortalAuditEvent.invite_id == abandoned_id,
                    PatientPortalAuditEvent.event_type == AUDIT_EVENT_INVITE_REVOKE,
                )
            )
        )
        assert [event.reason for event in events] == ["preparation_abandoned"]
    committed = client.post(
        f"/internal/carlos/invites/{prepared.json()['id']}/commit-delivery",
        headers=headers,
        json={
            "delivery_operation_id": "next-operation",
            "delivery_reference": "email:next-operation",
        },
    )
    assert committed.status_code == 200
    assert committed.json()["status"] == "pending"


@pytest.mark.parametrize("resend", [False, True])
def test_live_preparation_is_not_displaced_by_another_operation(resend) -> None:
    app = internal_app()
    client = TestClient(app)
    headers = carlos_headers("portal.invite.manage")
    if resend:
        original = client.post(
            "/internal/carlos/patients/1234/invites", headers=headers, json=invite_request()
        )
        path = f"/internal/carlos/invites/{original.json()['id']}/resend/prepare"
        request = {}
    else:
        path = "/internal/carlos/patients/1234/invites/prepare"
        request = invite_request()
    live = client.post(path, headers=headers, json={**request, "delivery_operation_id": "live"})
    assert live.status_code == 201

    other = client.post(path, headers=headers, json={**request, "delivery_operation_id": "other"})

    assert other.status_code == 409
    assert other.json() == {"detail": IN_PROGRESS_DETAIL}
    assert live.json()["invite_token"] not in other.text
    with app.state.session_factory() as session:
        assert session.get(PatientPortalInvite, live.json()["id"]).status == "prepared"
    committed = client.post(
        f"/internal/carlos/invites/{live.json()['id']}/commit-delivery",
        headers=headers,
        json={"delivery_operation_id": "live", "delivery_reference": "email:live"},
    )
    assert committed.status_code == 200


@pytest.mark.parametrize("endpoint", ["internal", "development"])
@pytest.mark.parametrize("expired", [False, True])
def test_legacy_create_reports_live_first_preparation_and_retires_expired_one(
    endpoint, expired
) -> None:
    app = internal_app(enable_dev_admin=True, dev_admin_token=DEV_ADMIN_TOKEN)
    client = TestClient(app)
    prepared = client.post(
        "/internal/carlos/patients/1234/invites/prepare",
        headers=carlos_headers("portal.invite.manage"),
        json={**invite_request(), "delivery_operation_id": "first-preparation"},
    )
    assert prepared.status_code == 201
    if expired:
        _expire(app, prepared.json()["id"])
    if endpoint == "internal":
        path = "/internal/carlos/patients/1234/invites"
        headers = carlos_headers("portal.invite.manage")
    else:
        path = "/dev/admin/invites"
        headers = dev_admin_headers()

    created = client.post(path, headers=headers, json=invite_request())

    with app.state.session_factory() as session:
        preparation = session.get(PatientPortalInvite, prepared.json()["id"])
        if expired:
            assert created.status_code == 201
            assert preparation.status == "revoked"
            assert preparation.encrypted_invite_token is None
        else:
            assert created.status_code == 409
            assert created.json() == {"detail": IN_PROGRESS_DETAIL}
            assert preparation.status == "prepared"
