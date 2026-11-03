from datetime import UTC, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal import account_settings, auth, web_support
from carlos_patient_portal.models import PatientPortalAccount, PatientPortalSession, utc_now
from tests.support import (
    STRONG_RESET_PASSWORD,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    browser_sign_in_seeded_patient,
    csrf_token_from_response,
    migrated_development_app,
)


def test_password_error_render_does_not_expire_a_session_renewed_earlier_in_the_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = migrated_development_app(
        session_idle_timeout_seconds=600,
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    with TestClient(app) as client:
        account_id = browser_sign_in_seeded_patient(app, client)
        account_page = client.get("/portal/account")
        assert account_page.status_code == 200
        csrf_token = csrf_token_from_response(account_page)
        cookie = client.cookies.get(web_support.PORTAL_SESSION_COOKIE_NAME)
        assert cookie
        started_at = utc_now()
        clock = [started_at]
        with app.state.session_factory() as session, session.begin():
            portal_session = session.scalar(select(PatientPortalSession))
            assert portal_session.revoked_at is None
            assert portal_session.expires_at.replace(tzinfo=UTC) > started_at + timedelta(seconds=2)
            session_id = portal_session.id
            portal_session.last_seen_at = started_at - timedelta(seconds=599)
            password_hash = session.get(PatientPortalAccount, account_id).password_hash

        real_password_matches = account_settings.password_matches
        verifications = []

        def observe_password_check(*args, **kwargs):
            matched = real_password_matches(*args, **kwargs)
            assert matched is False
            verifications.append(matched)
            # Simulate elapsed request work AFTER the real wrong-password verification.
            # No sleep or call-count assumption drives the two authentication phases.
            clock[0] = started_at + timedelta(seconds=2)
            return matched

        monkeypatch.setattr(auth, "utc_now", lambda: clock[0])
        monkeypatch.setattr(account_settings, "password_matches", observe_password_check)
        rejected = client.post(
            "/portal/account/password",
            data={
                "csrf_token": csrf_token,
                "current_password": "FAKE-Wrong-password-9274",
                "new_password": STRONG_RESET_PASSWORD,
                "new_password_confirmation": STRONG_RESET_PASSWORD,
            },
            follow_redirects=False,
        )

        assert verifications
        with app.state.session_factory() as session:
            stored = session.get(PatientPortalSession, session_id)
            account = session.get(PatientPortalAccount, account_id)
            assert stored.last_seen_at.replace(tzinfo=UTC) == started_at
            assert account.failed_login_count == 1
            assert account.locked_at is None
            assert account.password_hash == password_hash
            facts = {
                "http_status": rejected.status_code,
                "last_seen_at": stored.last_seen_at,
                "revoked_at": stored.revoked_at,
                "revoked_reason": stored.revoked_reason,
            }
            assert rejected.status_code == 403, facts
            assert stored.revoked_at is None, facts
        assert client.cookies.get(web_support.PORTAL_SESSION_COOKIE_NAME) == cookie
        assert client.get("/portal/account").status_code == 200
