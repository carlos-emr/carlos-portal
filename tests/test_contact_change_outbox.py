"""Public contact confirmation dispatches committed security notices outside development."""

from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.models import (
    CONTACT_REVIEW_STATUS_PENDING,
    EMAIL_CHANGE_STATUS_CONFIRMED,
    OUTBOX_KIND_CONTACT_CHANGE,
    OUTBOX_STATUS_DELIVERED,
    SESSION_REVOKED_REASON_CONTACT_CHANGE,
    PatientPortalAccount,
    PatientPortalContactReviewRequest,
    PatientPortalEmailChangeRequest,
    PatientPortalOutboundDelivery,
    PatientPortalSession,
)
from tests.support import (
    MFA_CHALLENGE_TOKEN_PATTERN,
    OUTBOX_ENCRYPTION_SECRET,
    SEEDED_INVITE_EMAIL,
    STRONG_PASSWORD,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    activation_request,
    confirm_seeded_email_change,
    csrf_token_from_response,
    migrated_staging_app,
    submit_contact_change,
)
from tests.test_delivery_outbox import create_staging_invite


def test_public_email_confirmation_commits_both_durable_notices_before_dispatch(tmp_path):
    new_email, old_phone = "fake-durable-contact@example.test", "+16135550199"
    observations = []

    class ObservingEmailSender(RecordingPortalEmailSender):
        def send_contact_change_notice(self, *, recipient, message_id=None):
            # The actual background worker calls this fake provider after decrypting a row.
            # A separate SQL session must see the whole change before either address is told.
            with self.app.state.session_factory() as session:
                account = session.scalars(select(PatientPortalAccount)).one()
                proof = session.scalars(select(PatientPortalEmailChangeRequest)).one()
                review = session.scalars(select(PatientPortalContactReviewRequest)).one()
                old_session = session.scalars(select(PatientPortalSession)).one()
                notices = session.scalars(
                    select(PatientPortalOutboundDelivery).order_by(PatientPortalOutboundDelivery.id)
                ).all()
                assert (account.email, account.phone_number) == (new_email, old_phone)
                assert proof.status == EMAIL_CHANGE_STATUS_CONFIRMED
                assert review.status == CONTACT_REVIEW_STATUS_PENDING
                assert (review.email_before, review.email_after) == (SEEDED_INVITE_EMAIL, new_email)
                assert old_session.revoked_at is not None
                assert old_session.revoked_reason == SESSION_REVOKED_REASON_CONTACT_CHANGE
                assert len(notices) == 2
                assert all(row.kind == OUTBOX_KIND_CONTACT_CHANGE for row in notices)
                assert all(row.account_id == account.id for row in notices)
                assert all(row.encrypted_payload and row.encryption_nonce for row in notices)
                observations.append((recipient, tuple(row.id for row in notices), message_id))
            super().send_contact_change_notice(recipient=recipient, message_id=message_id)

    sender, sms_sender = ObservingEmailSender(), RecordingPortalSmsSender()
    app = migrated_staging_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'private-contact-outbox.sqlite'}",
        email_sender=sender,
        sms_sender=sms_sender,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    sender.app = app
    patient = TestClient(app, base_url="https://portal.example.test")
    mailbox = TestClient(app, base_url="https://portal.example.test")
    try:
        invite = create_staging_invite(patient)
        assert invite.status_code == 201
        activated = patient.post(
            "/auth/activate",
            json=activation_request(
                invite.json()["invite_token"],
                mfa_delivery_method="sms",
                phone_number=old_phone,
            ),
        )
        assert activated.status_code == 201
        sign_in = patient.post(
            "/auth/login",
            data={
                "csrf_token": csrf_token_from_response(patient.get("/")),
                "username": "patient.user",
                "password": STRONG_PASSWORD,
            },
        )
        assert sign_in.status_code == 200
        challenge = MFA_CHALLENGE_TOKEN_PATTERN.search(sign_in.text)
        assert challenge is not None
        verified = patient.post(
            "/auth/mfa/verify",
            data={
                "csrf_token": csrf_token_from_response(sign_in),
                "mfa_challenge_token": challenge.group(1),
                "code": sms_sender.messages[-1]["code"],
            },
            follow_redirects=False,
        )
        assert verified.status_code == 303
        requested = submit_contact_change(app, patient, email=new_email, phone_number=old_phone)
        assert requested.status_code == 303
        assert requested.headers["location"] == (
            "/portal/account?status=email-confirmation-required"
        )
        confirmation_mail = next(
            message
            for message in sender.messages
            if message.get("type") == "email_change_confirmation"
        )
        assert confirmation_mail["recipient"] == new_email
        token = parse_qs(urlsplit(str(confirmation_mail["confirmation_url"])).fragment)["token"][0]
        assert observations == []
        with app.state.session_factory() as session:
            assert session.scalar(select(PatientPortalOutboundDelivery)) is None

        completed = confirm_seeded_email_change(mailbox, token)
        assert completed.status_code == 200
        with app.state.session_factory() as session:
            notices = session.scalars(
                select(PatientPortalOutboundDelivery).order_by(PatientPortalOutboundDelivery.id)
            ).all()
            assert len(notices) == 2
            assert all(row.status == OUTBOX_STATUS_DELIVERED for row in notices)
            assert all(row.attempt_count == 1 and row.last_failure_code is None for row in notices)
            assert all(
                row.encryption_key_id == app.state.settings.outbox_active_key_id for row in notices
            )
            notice_ids = tuple(row.id for row in notices)
            assert observations == [
                (SEEDED_INVITE_EMAIL, notice_ids, notices[0].message_id),
                (new_email, notice_ids, notices[1].message_id),
            ]
        assert [
            message for message in sender.messages if message.get("type") == "contact_change_notice"
        ] == [
            {"recipient": recipient, "type": "contact_change_notice", "message_id": message_id}
            for recipient, _, message_id in observations
        ]
        signed_out = patient.get("/portal/account", follow_redirects=False)
        assert signed_out.status_code == 303
        assert signed_out.headers["location"] == "/"
    finally:
        mailbox.close()
        patient.close()
        app.state.database_engine.dispose()
