"""A late provider result no longer owns the code or cooldown replaced by a newer resend."""

from concurrent.futures import Future
from datetime import timedelta
from threading import Event, Thread

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal import auth
from carlos_patient_portal.email_delivery import PortalEmailDeliveryError
from carlos_patient_portal.models import (
    AUDIT_EVENT_MFA_DELIVERY,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_SUCCESS,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalMfaChallenge,
)
from tests.support import (
    STRONG_PASSWORD,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    activate_seeded_patient_account,
    migrated_development_app,
)


@pytest.mark.parametrize(
    ("old_send_fails", "code_values", "new_method"),
    [
        pytest.param(False, ["111111", "222222", "333333"], "email", id="stale_success"),
        pytest.param(True, ["111111", "222222", "333333"], "email", id="stale_failure"),
        pytest.param(True, ["111111", "222222", "222222"], "email", id="same_code_failure"),
        pytest.param(
            True, ["111111", "222222", "222222"], "sms", id="same_code_expiry_new_channel"
        ),
    ],
)
def test_late_resend_delivery_cannot_replace_the_newer_code_or_its_cooldown(
    tmp_path, monkeypatch, old_send_fails, code_values, new_method
):
    entered, release = Event(), Event()
    worker = None

    class DelayedSender(RecordingPortalEmailSender):
        hold_next = False

        def send_code(self, **message):
            super().send_code(**message)
            if self.hold_next:
                self.hold_next = False
                entered.set()
                assert release.wait(timeout=15), "provider gate was not released"
                if old_send_fails:
                    raise PortalEmailDeliveryError("FAKE late provider failure")

    sender = DelayedSender()
    sms_sender = RecordingPortalSmsSender()
    app = migrated_development_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'mfa-race.db'}",
        email_sender=sender,
        sms_sender=sms_sender,
        mfa_email_resend_cooldown_seconds=60,
    )
    client, old_client = TestClient(app), TestClient(app)
    try:
        account_id = activate_seeded_patient_account(app, client)
        if new_method == "sms":
            with app.state.session_factory() as session, session.begin():
                account = session.get(PatientPortalAccount, account_id)
                account.phone_number = "+16135550199"
        clock = [auth.utc_now()]
        monkeypatch.setattr(auth, "utc_now", lambda: clock[0])
        # Deterministic codes include a legitimate RNG repeat in the ABA case.
        # Token hashes and verification are not mocked.
        codes = iter(code_values)
        monkeypatch.setattr(auth, "create_mfa_code", lambda: next(codes))
        login = client.post(
            "/auth/login",
            json={"username": "patient.user", "password": STRONG_PASSWORD},
        )
        assert login.status_code == 200
        token = login.json()["mfa_challenge_token"]
        resend = {"mfa_challenge_token": token, "mfa_delivery_method": "email"}
        clock[0] += timedelta(seconds=61)
        sender.hold_next = True
        older = Future()

        def old_resend():
            try:
                older.set_result(old_client.post("/auth/mfa/resend", json=resend))
            except Exception as error:
                older.set_exception(error)

        worker = Thread(target=old_resend, daemon=True)
        worker.start()
        assert entered.wait(timeout=5)
        old_code = sender.messages[-1]["code"]
        with app.state.session_factory() as session:
            old_expiry = session.scalar(select(PatientPortalMfaChallenge.expires_at))
        if new_method == "email":
            # A provider slower than the cooldown can overlap another legitimate resend.
            clock[0] += timedelta(seconds=61)
        # An independent SMS cooldown permits a same-instant channel switch. This
        # deliberately keeps both the numeric code and expiry identical across A/B.
        newer = client.post("/auth/mfa/resend", json={**resend, "mfa_delivery_method": new_method})
        assert newer.status_code == 200
        new_code = newer.json()["development_mfa_code"]
        assert old_code == code_values[1]
        assert new_code == code_values[2]

        def stored_state():
            with app.state.session_factory() as session:
                challenge = session.scalar(
                    select(PatientPortalMfaChallenge).where(
                        PatientPortalMfaChallenge.account_id == account_id
                    )
                )
                account = session.get(PatientPortalAccount, account_id)
                return (
                    challenge.code_hash,
                    challenge.delivery_method,
                    challenge.expires_at,
                    challenge.last_email_sent_at,
                    account.last_mfa_email_sent_at,
                    challenge.last_sms_sent_at,
                    account.last_mfa_sms_sent_at,
                )

        latest = stored_state()
        assert latest[1] == new_method
        if new_method == "sms":
            assert latest[2] == old_expiry
        clock[0] += timedelta(seconds=61)
        release.set()
        old_response = older.result(timeout=10)
        assert old_response.status_code == (503 if old_send_fails else 200)
        assert stored_state() == latest
        with app.state.session_factory() as session:
            superseded = list(
                session.scalars(
                    select(PatientPortalAuditEvent).where(
                        PatientPortalAuditEvent.event_type == AUDIT_EVENT_MFA_DELIVERY,
                        PatientPortalAuditEvent.account_id == account_id,
                        PatientPortalAuditEvent.reason == "email:superseded",
                    )
                )
            )
            assert len(superseded) == 1
            assert superseded[0].outcome == (
                AUDIT_OUTCOME_FAILURE if old_send_fails else AUDIT_OUTCOME_SUCCESS
            )
        # A repeated value belongs to the latest generation too; the initial code
        # remains distinct and must no longer authenticate in that case.
        obsolete_code = old_code if old_code != new_code else code_values[0]
        rejected = client.post(
            "/auth/mfa/verify", json={"mfa_challenge_token": token, "code": obsolete_code}
        )
        assert rejected.status_code == 401
        accepted = client.post(
            "/auth/mfa/verify", json={"mfa_challenge_token": token, "code": new_code}
        )
        assert accepted.status_code == 200
        assert accepted.json()["status"] == "signed_in"
        assert len(sender.messages) + len(sms_sender.messages) == 3
    finally:
        release.set()
        try:
            if worker is not None:
                worker.join(timeout=15)
                assert not worker.is_alive()
        finally:
            old_client.close()
            client.close()
            app.state.database_engine.dispose()
