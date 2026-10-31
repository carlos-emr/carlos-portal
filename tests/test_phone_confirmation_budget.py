"""Phone confirmation failures persist across browser requests."""

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from carlos_patient_portal.models import (
    EMAIL_CHANGE_STATUS_PENDING,
    EMAIL_CHANGE_STATUS_REVOKED,
    PatientPortalAccount,
    PatientPortalContactReviewRequest,
    PatientPortalEmailChangeRequest,
    PatientPortalSession,
)
from carlos_patient_portal.web_support import PORTAL_SESSION_COOKIE_NAME
from tests.support import (
    SEEDED_INVITE_EMAIL,
    STRONG_PASSWORD,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    browser_sign_in_seeded_patient,
    csrf_token_from_response,
    migrated_development_app,
)


def test_browser_phone_proof_budget_persists_and_rejects_the_correct_code_after_exhaustion(
    tmp_path,
):
    email_sender, sms_sender = RecordingPortalEmailSender(), RecordingPortalSmsSender()
    app = migrated_development_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'phone-budget.db'}",
        email_sender=email_sender,
        sms_sender=sms_sender,
        phone_change_max_failed_attempts=2,
    )
    client = TestClient(app)
    try:
        account_id = browser_sign_in_seeded_patient(app, client)
        session_cookie = client.cookies.get(PORTAL_SESSION_COOKIE_NAME)
        assert session_cookie
        with app.state.session_factory() as session:
            account = session.get(PatientPortalAccount, account_id)
            original_contact = (account.email, account.phone_number)
            session_id = session.scalar(
                select(PatientPortalSession.id).where(
                    PatientPortalSession.account_id == account_id,
                    PatientPortalSession.revoked_at.is_(None),
                )
            )
        assert session_id is not None
        account_page = client.get("/portal/account")
        assert account_page.status_code == 200
        requested = client.post(
            "/portal/account/contact",
            data={
                "csrf_token": csrf_token_from_response(account_page),
                "current_password": STRONG_PASSWORD,
                "email": SEEDED_INVITE_EMAIL,
                "phone_number": "+16135550199",
            },
            follow_redirects=False,
        )
        assert requested.status_code == 303
        assert requested.headers["location"] == (
            "/portal/account?status=phone-confirmation-required"
        )
        assert len(sms_sender.messages) == 1
        correct_code = sms_sender.messages[0]["code"]
        assert isinstance(correct_code, str)
        wrong_code = "000000" if correct_code != "000000" else "999999"
        # The initial request legitimately notifies the current email address.
        provider_counts = (len(email_sender.messages), len(sms_sender.messages))

        submissions = [
            (wrong_code, 1, EMAIL_CHANGE_STATUS_PENDING),
            (wrong_code, 2, EMAIL_CHANGE_STATUS_REVOKED),
            (correct_code, 2, EMAIL_CHANGE_STATUS_REVOKED),
        ]
        for code, expected_attempts, expected_status in submissions:
            account_page = client.get("/portal/account")
            assert account_page.status_code == 200
            refused = client.post(
                "/portal/account/contact/confirm-phone",
                data={
                    "csrf_token": csrf_token_from_response(account_page),
                    "phone_confirmation_code": code,
                },
                follow_redirects=False,
            )
            assert refused.status_code == 303
            assert refused.headers["location"] == (
                "/portal/account?status=phone-confirmation-invalid"
            )
            # Reopen a real session after every response to observe committed state.
            with app.state.session_factory() as session:
                proof = session.scalar(
                    select(PatientPortalEmailChangeRequest).where(
                        PatientPortalEmailChangeRequest.account_id == account_id
                    )
                )
                assert proof is not None
                assert proof.phone_failed_attempts == expected_attempts
                assert proof.status == expected_status
                assert proof.phone_confirmed_at is None
                account = session.get(PatientPortalAccount, account_id)
                assert (account.email, account.phone_number) == original_contact
                assert (
                    session.scalar(
                        select(func.count())
                        .select_from(PatientPortalContactReviewRequest)
                        .where(PatientPortalContactReviewRequest.account_id == account_id)
                    )
                    == 0
                )
                original_session = session.get(PatientPortalSession, session_id)
                assert original_session is not None
                assert original_session.revoked_at is None
            assert client.cookies.get(PORTAL_SESSION_COOKIE_NAME) == session_cookie
            assert (len(email_sender.messages), len(sms_sender.messages)) == provider_counts
        assert client.get("/portal/account").status_code == 200
    finally:
        client.close()
        app.state.database_engine.dispose()
