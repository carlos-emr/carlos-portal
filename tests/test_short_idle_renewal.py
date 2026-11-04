from datetime import UTC, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal import auth, web_support
from carlos_patient_portal.models import PatientPortalSession, utc_now
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    browser_sign_in_seeded_patient,
    migrated_development_app,
)


@pytest.mark.parametrize(
    ("idle_seconds", "activity_offsets", "quiet_at"),
    [
        pytest.param(60, (20, 40, 60, 80, 100), 160, id="short"),
        pytest.param(600, (120, 240, 360, 480, 600), 1200, id="default-cadence"),
    ],
)
def test_browser_activity_renews_idle_timeout_then_quiet_time_expires_it(
    idle_seconds,
    activity_offsets,
    quiet_at,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = migrated_development_app(
        session_idle_timeout_seconds=idle_seconds,
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    with TestClient(app) as client:
        browser_sign_in_seeded_patient(app, client)
        cookie = client.cookies.get(web_support.PORTAL_SESSION_COOKIE_NAME)
        assert cookie
        started_at = utc_now()
        clock = [started_at]
        with app.state.session_factory() as session, session.begin():
            portal_session = session.scalar(select(PatientPortalSession))
            assert portal_session.revoked_at is None
            assert portal_session.expires_at.replace(tzinfo=UTC) > started_at + timedelta(
                seconds=quiet_at
            )
            session_id = portal_session.id
            portal_session.last_seen_at = started_at
        monkeypatch.setattr(auth, "utc_now", lambda: clock[0])

        # Each independent real request is activity within the configured idle window.
        # The fixed clock advances between requests; there are no sleeps or speed assertions.
        for elapsed in activity_offsets:
            clock[0] = started_at + timedelta(seconds=elapsed)
            response = client.get("/portal/account", follow_redirects=False)
            with app.state.session_factory() as session:
                stored = session.get(PatientPortalSession, session_id)
                facts = {
                    "elapsed": elapsed,
                    "last_seen_at": stored.last_seen_at,
                    "revoked_at": stored.revoked_at,
                    "revoked_reason": stored.revoked_reason,
                }
                assert response.status_code == 200, facts
                assert stored.revoked_at is None
                if idle_seconds == 600:
                    # Preserve the existing default write cadence, including skipped writes.
                    expected_offset = 360 if elapsed >= 360 else 0
                    assert stored.last_seen_at.replace(tzinfo=UTC) == started_at + timedelta(
                        seconds=expected_offset
                    )
        with app.state.session_factory() as session:
            stored = session.get(PatientPortalSession, session_id)
            assert stored.last_seen_at.replace(tzinfo=UTC) > started_at
        assert client.cookies.get(web_support.PORTAL_SESSION_COOKIE_NAME) == cookie

        # A full quiet interval still revokes durably; activity must not disable expiry.
        clock[0] = started_at + timedelta(seconds=quiet_at)
        expired = client.get("/portal/account", follow_redirects=False)
        assert expired.status_code == 303
        assert expired.headers["location"] == "/"
        assert client.cookies.get(web_support.PORTAL_SESSION_COOKIE_NAME) is None
        with app.state.session_factory() as session:
            stored = session.get(PatientPortalSession, session_id)
            assert stored.revoked_at.replace(tzinfo=UTC) == clock[0]
            assert stored.revoked_reason == "idle_timeout"
