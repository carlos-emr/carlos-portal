"""A joint contact change can finish from the new mailbox on another device."""

from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.models import (
    CONTACT_REVIEW_STATUS_PENDING,
    EMAIL_CHANGE_STATUS_CONFIRMED,
    EMAIL_CHANGE_STATUS_PENDING,
    SESSION_REVOKED_REASON_CONTACT_CHANGE,
    PatientPortalAccount,
    PatientPortalContactReviewRequest,
    PatientPortalEmailChangeRequest,
    PatientPortalSession,
)
from carlos_patient_portal.web_support import PORTAL_SESSION_COOKIE_NAME
from tests.support import (
    SEEDED_INVITE_EMAIL,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    browser_sign_in_seeded_patient,
    confirm_seeded_email_change,
    csrf_token_from_response,
    migrated_development_app,
    submit_contact_change,
)


def test_phone_first_joint_contact_change_finishes_in_a_separate_public_email_client(tmp_path):
    email_sender, sms_sender = RecordingPortalEmailSender(), RecordingPortalSmsSender()
    app = migrated_development_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'private-contact-journey.sqlite'}",
        email_sender=email_sender,
        sms_sender=sms_sender,
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    # Independent cookie jars model the signed-in portal and the device opening the email.
    patient, mailbox = TestClient(app), TestClient(app)
    new_email, new_phone = "fake-joint-contact@example.test", "+16135550198"
    try:
        account_id = browser_sign_in_seeded_patient(app, patient)
        original_cookie = patient.cookies.get(PORTAL_SESSION_COOKIE_NAME)
        assert original_cookie
        with app.state.session_factory() as session:
            original_session_id = session.scalars(
                select(PatientPortalSession.id).where(PatientPortalSession.account_id == account_id)
            ).one()

        requested = submit_contact_change(app, patient, email=new_email, phone_number=new_phone)
        assert requested.status_code == 303
        assert requested.headers["location"] == (
            "/portal/account?status=contact-confirmation-required"
        )
        confirmation_mail = next(
            message
            for message in email_sender.messages
            if message.get("type") == "email_change_confirmation"
        )
        assert confirmation_mail["recipient"] == new_email
        token = parse_qs(urlsplit(str(confirmation_mail["confirmation_url"])).fragment)["token"][0]
        assert len(sms_sender.messages) == 1
        assert sms_sender.messages[0]["recipient"] == new_phone
        provider_counts = (len(email_sender.messages), len(sms_sender.messages))
        assert not any(
            message.get("type") == "contact_change_notice" for message in email_sender.messages
        )

        phone_page = patient.get("/portal/account")
        assert phone_page.status_code == 200
        phone_confirmed = patient.post(
            "/portal/account/contact/confirm-phone",
            data={
                "csrf_token": csrf_token_from_response(phone_page),
                "phone_confirmation_code": sms_sender.messages[0]["code"],
            },
            follow_redirects=False,
        )
        assert phone_confirmed.status_code == 303
        assert phone_confirmed.headers["location"] == (
            "/portal/account?status=email-confirmation-required"
        )
        with app.state.session_factory() as session:
            account = session.get(PatientPortalAccount, account_id)
            proof = session.scalars(select(PatientPortalEmailChangeRequest)).one()
            assert (account.email, account.phone_number) == (SEEDED_INVITE_EMAIL, None)
            assert proof.status == EMAIL_CHANGE_STATUS_PENDING
            assert proof.phone_confirmed_at is not None
            assert proof.email_confirmed_at is None
            assert proof.confirmed_at is None
            assert session.scalar(select(PatientPortalContactReviewRequest)) is None
            assert session.get(PatientPortalSession, original_session_id).revoked_at is None
        assert patient.cookies.get(PORTAL_SESSION_COOKIE_NAME) == original_cookie
        assert patient.get("/portal/account").status_code == 200
        assert (len(email_sender.messages), len(sms_sender.messages)) == provider_counts

        assert mailbox.cookies.get(PORTAL_SESSION_COOKIE_NAME) is None
        completed = confirm_seeded_email_change(mailbox, token)
        assert completed.status_code == 200
        assert mailbox.cookies.get(PORTAL_SESSION_COOKIE_NAME) is None
        # Inspect committed state before the old client makes another request.
        with app.state.session_factory() as session:
            account = session.get(PatientPortalAccount, account_id)
            proof = session.scalars(select(PatientPortalEmailChangeRequest)).one()
            review = session.scalars(select(PatientPortalContactReviewRequest)).one()
            original_session = session.get(PatientPortalSession, original_session_id)
            assert (account.email, account.phone_number) == (new_email, new_phone)
            assert proof.status == EMAIL_CHANGE_STATUS_CONFIRMED
            assert proof.phone_confirmed_at is not None
            assert proof.email_confirmed_at is not None
            assert proof.confirmed_at is not None
            assert review.status == CONTACT_REVIEW_STATUS_PENDING
            assert review.account_id == account_id
            assert (review.email_before, review.email_after) == (SEEDED_INVITE_EMAIL, new_email)
            assert (review.phone_number_before, review.phone_number_after) == (None, new_phone)
            assert original_session.revoked_at is not None
            assert original_session.revoked_reason == SESSION_REVOKED_REASON_CONTACT_CHANGE
        assert email_sender.messages[provider_counts[0] :] == [
            {"recipient": SEEDED_INVITE_EMAIL, "type": "contact_change_notice"},
            {"recipient": new_email, "type": "contact_change_notice"},
        ]
        assert len(sms_sender.messages) == provider_counts[1]
        signed_out = patient.get("/portal/account", follow_redirects=False)
        assert signed_out.status_code == 303
        assert signed_out.headers["location"] == "/"
        assert patient.cookies.get(PORTAL_SESSION_COOKIE_NAME) is None
    finally:
        mailbox.close()
        patient.close()
        app.state.database_engine.dispose()
