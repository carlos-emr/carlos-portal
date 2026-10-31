from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.models import (
    AUDIT_EVENT_ACCOUNT_PASSWORD_CHANGE,
    AUDIT_OUTCOME_FAILURE,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalSession,
)
from carlos_patient_portal.web_support import PORTAL_SESSION_COOKIE_NAME
from tests.support import (
    STRONG_PASSWORD,
    STRONG_RESET_PASSWORD,
    RecordingPortalEmailSender,
    browser_sign_in_seeded_patient,
    csrf_token_from_response,
    migrated_development_app,
)


def test_unusable_step_up_hash_preserves_budget_session_and_durable_fault_audit(tmp_path) -> None:
    app = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        database_url=f"sqlite+pysqlite:///{tmp_path / 'private-step-up.sqlite'}",
        auth_max_failed_password_attempts=3,
    )
    with TestClient(app) as client:
        account_id = browser_sign_in_seeded_patient(app, client)
        csrf_token = csrf_token_from_response(client.get("/portal/account"))
        original_cookie = client.cookies.get(PORTAL_SESSION_COOKIE_NAME)
        assert original_cookie
        corrupt_hash = "FAKE-unusable-password-hash"
        with app.state.session_factory() as session, session.begin():
            account = session.get(PatientPortalAccount, account_id)
            account.password_hash = corrupt_hash
            account.failed_login_count = 2
            password_updated_at = account.password_updated_at
            portal_session = session.scalar(select(PatientPortalSession))
            session_id = portal_session.id
            token_hash = portal_session.token_hash
            assert portal_session.revoked_at is None

        failed = client.post(
            "/portal/account/password",
            data={
                "csrf_token": csrf_token,
                "current_password": STRONG_PASSWORD,
                "new_password": STRONG_RESET_PASSWORD,
                "new_password_confirmation": STRONG_RESET_PASSWORD,
            },
            follow_redirects=False,
        )
        assert failed.status_code == 503
        assert failed.headers["retry-after"] == "1"
        assert "session_token" not in failed.text
        for private_value in (
            corrupt_hash,
            STRONG_PASSWORD,
            STRONG_RESET_PASSWORD,
            original_cookie,
        ):
            assert private_value not in failed.text
        assert client.cookies.get(PORTAL_SESSION_COOKIE_NAME) == original_cookie

        # The exception rolls back request teardown; its committed audit must survive.
        with app.state.session_factory() as session:
            account = session.get(PatientPortalAccount, account_id)
            assert account.password_hash == corrupt_hash
            assert account.password_updated_at == password_updated_at
            assert account.failed_login_count == 2
            assert account.locked_at is None
            assert account.force_password_reset is False
            sessions = list(session.scalars(select(PatientPortalSession)))
            assert len(sessions) == 1
            assert sessions[0].id == session_id
            assert sessions[0].token_hash == token_hash
            assert sessions[0].revoked_at is None
            assert sessions[0].revoked_reason is None
            events = list(
                session.scalars(
                    select(PatientPortalAuditEvent).where(
                        PatientPortalAuditEvent.account_id == account_id,
                        PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACCOUNT_PASSWORD_CHANGE,
                    )
                )
            )
            assert [(event.outcome, event.reason) for event in events] == [
                (AUDIT_OUTCOME_FAILURE, "password_hash_unusable")
            ]
        assert client.get("/portal/account", follow_redirects=False).status_code == 200
