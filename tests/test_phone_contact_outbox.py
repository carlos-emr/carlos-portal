"""A confirmed replacement phone finishes through the authenticated durable-notice path."""

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
from carlos_patient_portal.web_support import PORTAL_SESSION_COOKIE_NAME
from tests.support import (
    MFA_CHALLENGE_TOKEN_PATTERN,
    OUTBOX_ENCRYPTION_SECRET,
    SEEDED_INVITE_EMAIL,
    STRONG_PASSWORD,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    activation_request,
    csrf_token_from_response,
    migrated_staging_app,
    submit_contact_change,
)
from tests.test_delivery_outbox import create_staging_invite


def test_authenticated_phone_confirmation_commits_notice_and_clears_its_session_cookie(tmp_path):
    old_phone, new_phone = "+16135550199", "+16135550198"
    observations = []

    class ObservingEmailSender(RecordingPortalEmailSender):
        def send_contact_change_notice(self, *, recipient, message_id=None):
            # The real worker must find a committed change and notice before calling its provider.
            # The browser has not received the response yet, so inspect SQL rather than its jar.
            with self.app.state.session_factory() as session:
                account = session.scalars(select(PatientPortalAccount)).one()
                proof = session.scalars(select(PatientPortalEmailChangeRequest)).one()
                review = session.scalars(select(PatientPortalContactReviewRequest)).one()
                authorizing_session = session.get(PatientPortalSession, authorizing_session_id)
                notice = session.scalars(select(PatientPortalOutboundDelivery)).one()
                assert (account.email, account.phone_number) == (SEEDED_INVITE_EMAIL, new_phone)
                assert proof.status == EMAIL_CHANGE_STATUS_CONFIRMED
                assert proof.phone_confirmed_at is not None
                assert review.status == CONTACT_REVIEW_STATUS_PENDING
                assert (review.email_before, review.email_after) == (
                    SEEDED_INVITE_EMAIL,
                    SEEDED_INVITE_EMAIL,
                )
                assert (review.phone_number_before, review.phone_number_after) == (
                    old_phone,
                    new_phone,
                )
                assert authorizing_session.revoked_at is not None
                assert authorizing_session.revoked_reason == SESSION_REVOKED_REASON_CONTACT_CHANGE
                assert notice.kind == OUTBOX_KIND_CONTACT_CHANGE
                assert notice.account_id == account.id
                assert notice.encrypted_payload and notice.encryption_nonce
                observations.append((notice.id, recipient, message_id))
            super().send_contact_change_notice(recipient=recipient, message_id=message_id)

    sender, sms_sender = ObservingEmailSender(), RecordingPortalSmsSender()
    app = migrated_staging_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'private-phone-final.sqlite'}",
        email_sender=sender,
        sms_sender=sms_sender,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    sender.app = app
    patient = TestClient(app, base_url="https://portal.example.test")
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
        assert sms_sender.messages[-1]["recipient"] == old_phone
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
        assert patient.cookies.get(PORTAL_SESSION_COOKIE_NAME)
        with app.state.session_factory() as session:
            authorizing_session_id = session.scalars(select(PatientPortalSession.id)).one()

        requested = submit_contact_change(
            app, patient, email=SEEDED_INVITE_EMAIL, phone_number=new_phone
        )
        assert requested.status_code == 303
        assert requested.headers["location"] == (
            "/portal/account?status=phone-confirmation-required"
        )
        assert sms_sender.messages[-1]["recipient"] == new_phone
        assert observations == []
        with app.state.session_factory() as session:
            assert session.scalar(select(PatientPortalOutboundDelivery)) is None

        account_page = patient.get("/portal/account")
        assert account_page.status_code == 200
        completed = patient.post(
            "/portal/account/contact/confirm-phone",
            data={
                "csrf_token": csrf_token_from_response(account_page),
                "phone_confirmation_code": sms_sender.messages[-1]["code"],
            },
            follow_redirects=False,
        )
        assert completed.status_code == 200
        assert "Contact information updated" in completed.text
        assert "you have been signed out" in completed.text
        cleared_cookie = next(
            header
            for header in completed.headers.get_list("set-cookie")
            if header.startswith(f"{PORTAL_SESSION_COOKIE_NAME}=")
        )
        assert "Max-Age=0" in cleared_cookie
        assert patient.cookies.get(PORTAL_SESSION_COOKIE_NAME) is None
        with app.state.session_factory() as session:
            notice = session.scalars(select(PatientPortalOutboundDelivery)).one()
            assert notice.status == OUTBOX_STATUS_DELIVERED
            assert notice.attempt_count == 1
            assert notice.last_failure_code is None
            assert observations == [(notice.id, SEEDED_INVITE_EMAIL, notice.message_id)]
        assert [
            message for message in sender.messages if message.get("type") == "contact_change_notice"
        ] == [
            {
                "recipient": SEEDED_INVITE_EMAIL,
                "type": "contact_change_notice",
                "message_id": observations[0][2],
            }
        ]
    finally:
        patient.close()
        app.state.database_engine.dispose()
