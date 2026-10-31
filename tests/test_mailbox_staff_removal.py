import pytest
from sqlalchemy import func, select

from carlos_patient_portal import main
from carlos_patient_portal.mailbox_models import (
    MailboxAccount,
    MailboxBlob,
    MailboxClinic,
    MailboxCopy,
    MailboxDevice,
    MailboxEvent,
)
from carlos_patient_portal.models import PatientPortalMyCarlosDevice
from carlos_patient_portal.staff_identity import staff_request_hash
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    carlos_staff_headers,
)
from tests.test_mycarlos_mailbox_http import (
    BODY,
    COPY_PATH,
    DEVICE,
    OUTER,
    UPLOAD_PATH,
    device_headers,
    http_mailbox,  # noqa: F401 -- owned private fixture, requested after provider injection
    job_headers,
)


def test_staff_removal_route_with_mailbox_enabled_releases_waiting_ciphertext_and_quotas(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Install explicit offline providers before the imported app fixture is constructed.
    monkeypatch.setattr(
        main, "build_portal_email_sender", lambda settings: RecordingPortalEmailSender()
    )
    monkeypatch.setattr(
        main, "build_portal_sms_sender", lambda settings: RecordingPortalSmsSender()
    )
    app, client, _proxy = request.getfixturevalue("http_mailbox")
    engine = app.state.database_engine
    quota_models = (MailboxClinic, MailboxAccount, MailboxDevice)
    try:
        assert client.post(UPLOAD_PATH, content=BODY, headers=job_headers()).status_code == 201
        downloaded = client.get(COPY_PATH, headers=device_headers(COPY_PATH))
        assert downloaded.status_code == 200
        assert downloaded.content
        with app.state.session_factory() as session:
            assert session.scalar(select(func.count()).select_from(MailboxBlob)) == 1
            copy = session.scalar(select(MailboxCopy))
            assert copy.status == "waiting"
            copy_identity = (copy.id, copy.delivery_id, copy.body_sha256, copy.ciphertext_sha256)
            for model in quota_models:
                quota = session.scalar(select(model))
                assert quota.waiting_count == 1
                assert quota.waiting_bytes > 0

        # Internal staff ingress remains root, independently of the device's public prefix.
        path = f"/internal/carlos/patients/6001/mycarlos/devices/{DEVICE.device_key_id}/remove"
        headers = carlos_staff_headers(
            "portal.mycarlos.device.manage",
            clinic_id="clinic-a",
            key_id="legacy",  # The imported development fixture names its single key this way.
            request_hash=staff_request_hash("POST", path.encode(), b"", b""),
        )
        removed = client.post(path, headers=headers)

        assert removed.status_code == 200
        assert removed.json()["status"] == "removed"
        assert removed.json()["removed_by"] == "staff"
        with app.state.session_factory() as session:
            device = session.scalar(select(PatientPortalMyCarlosDevice))
            assert device.status == "removed"
            assert device.removed_by == "staff"
            assert session.scalar(select(func.count()).select_from(MailboxBlob)) == 0
            copy = session.scalar(select(MailboxCopy))
            assert (
                copy.id,
                copy.delivery_id,
                copy.body_sha256,
                copy.ciphertext_sha256,
            ) == copy_identity
            assert copy.status == "removed"
            assert copy.terminal_at is not None
            for model in quota_models:
                quota = session.scalar(select(model))
                assert quota.waiting_count == quota.waiting_bytes == 0
            assert list(
                session.execute(
                    select(MailboxEvent.kind, MailboxEvent.delivery_id).order_by(
                        MailboxEvent.sequence
                    )
                )
            ) == [
                ("device_removed", None),
                ("removed", OUTER["delivery_id"]),
            ]

        denied = client.get(COPY_PATH, headers=device_headers(COPY_PATH))
        assert denied.status_code == 403
        assert denied.json() == {"code": "device_removed"}
        assert denied.content != downloaded.content
    finally:
        client.close()
        engine.dispose()
