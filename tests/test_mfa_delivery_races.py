"""A late provider result no longer owns the code or cooldown replaced by a newer resend."""

from concurrent.futures import Future
from datetime import UTC, timedelta
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
    MFA_CHALLENGE_STATUS_CANCELLED,
    MFA_CHALLENGE_STATUS_VERIFIED,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalMfaChallenge,
    PatientPortalSession,
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


def test_verified_current_challenge_still_records_its_own_provider_success(tmp_path, monkeypatch):
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

    sender = DelayedSender()
    app = migrated_development_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'verified-current.db'}",
        email_sender=sender,
        mfa_email_resend_cooldown_seconds=60,
    )
    client, sending_client = TestClient(app), TestClient(app)
    try:
        account_id = activate_seeded_patient_account(app, client)
        clock = [auth.utc_now()]
        monkeypatch.setattr(auth, "utc_now", lambda: clock[0])
        login = client.post(
            "/auth/login", json={"username": "patient.user", "password": STRONG_PASSWORD}
        )
        assert login.status_code == 200
        token = login.json()["mfa_challenge_token"]
        clock[0] += timedelta(seconds=61)
        sender.hold_next = True
        sending = Future()

        def resend():
            try:
                sending.set_result(
                    sending_client.post(
                        "/auth/mfa/resend",
                        json={"mfa_challenge_token": token, "mfa_delivery_method": "email"},
                    )
                )
            except Exception as error:
                sending.set_exception(error)

        worker = Thread(target=resend, daemon=True)
        worker.start()
        assert entered.wait(timeout=5)
        # The patient can receive the code before the provider call acknowledges it.
        verified = client.post(
            "/auth/mfa/verify",
            json={"mfa_challenge_token": token, "code": sender.messages[-1]["code"]},
        )
        assert verified.status_code == 200
        session_token = verified.json()["session_token"]
        assert session_token

        def current_identity_and_reservation():
            with app.state.session_factory() as session:
                challenge = session.scalar(select(PatientPortalMfaChallenge))
                account = session.get(PatientPortalAccount, account_id)
                assert challenge.status == MFA_CHALLENGE_STATUS_VERIFIED
                return (
                    (
                        challenge.id,
                        challenge.code_hash,
                        challenge.expires_at,
                        challenge.delivery_method,
                    ),
                    challenge.last_email_sent_at,
                    account.last_mfa_email_sent_at,
                )

        identity, _, before_reservation = current_identity_and_reservation()
        assert before_reservation.replace(tzinfo=UTC) == clock[0]
        clock[0] += timedelta(seconds=1)
        release.set()
        assert sending.result(timeout=10).status_code == 200
        after_identity, delivered_at, reservation = current_identity_and_reservation()
        assert after_identity == identity
        assert delivered_at == reservation
        assert reservation.replace(tzinfo=UTC) == clock[0]
        assert reservation - before_reservation == timedelta(seconds=1)
        with app.state.session_factory() as session:
            events = list(
                session.scalars(
                    select(PatientPortalAuditEvent).where(
                        PatientPortalAuditEvent.event_type == AUDIT_EVENT_MFA_DELIVERY,
                        PatientPortalAuditEvent.account_id == account_id,
                    )
                )
            )
            assert len(events) == 2
            assert all(event.reason == "email" for event in events)
            assert all(event.outcome == AUDIT_OUTCOME_SUCCESS for event in events)
            sessions = list(session.scalars(select(PatientPortalSession)))
            assert len(sessions) == 1
            assert sessions[0].revoked_at is None
        authenticated = client.get(
            "/auth/session", headers={"Authorization": f"Bearer {session_token}"}
        )
        assert authenticated.status_code == 200
        assert authenticated.json()["status"] == "authenticated"
        assert len(sender.messages) == 2
    finally:
        release.set()
        try:
            if worker is not None:
                worker.join(timeout=15)
                assert not worker.is_alive()
        finally:
            sending_client.close()
            client.close()
            app.state.database_engine.dispose()


@pytest.mark.parametrize("old_send_fails", [True, False], ids=["failure", "success"])
def test_cancelled_login_delivery_cannot_change_the_newer_login_cooldown(
    tmp_path, monkeypatch, old_send_fails
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
                    raise PortalEmailDeliveryError("FAKE cancelled login delivery failure")

    sender = DelayedSender()
    app = migrated_development_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'cancelled-login.db'}",
        email_sender=sender,
        mfa_email_resend_cooldown_seconds=60,
    )
    client, old_client = TestClient(app), TestClient(app)
    try:
        account_id = activate_seeded_patient_account(app, client)
        clock = [auth.utc_now()]
        monkeypatch.setattr(auth, "utc_now", lambda: clock[0])
        login = {"username": "patient.user", "password": STRONG_PASSWORD}
        sender.hold_next = True
        older = Future()

        def old_login():
            try:
                older.set_result(old_client.post("/auth/login", json=login))
            except Exception as error:
                older.set_exception(error)

        worker = Thread(target=old_login, daemon=True)
        worker.start()
        assert entered.wait(timeout=5)
        with app.state.session_factory() as session:
            old_id = session.scalar(select(PatientPortalMfaChallenge.id))
        assert old_id is not None
        clock[0] += timedelta(seconds=61)
        newer = client.post("/auth/login", json=login)
        assert newer.status_code == 200
        new_token = newer.json()["mfa_challenge_token"]
        new_code = newer.json()["development_mfa_code"]

        def stored_state():
            with app.state.session_factory() as session:
                old = session.get(PatientPortalMfaChallenge, old_id)
                current = session.scalar(
                    select(PatientPortalMfaChallenge).where(
                        PatientPortalMfaChallenge.account_id == account_id,
                        PatientPortalMfaChallenge.id != old_id,
                    )
                )
                account = session.get(PatientPortalAccount, account_id)
                assert old.status == MFA_CHALLENGE_STATUS_CANCELLED
                return (
                    current.id,
                    current.status,
                    current.code_hash,
                    current.delivery_method,
                    current.expires_at,
                    current.last_email_sent_at,
                    account.last_mfa_email_sent_at,
                )

        latest = stored_state()
        # Releasing just after B succeeds exposes a stale failure rewinding B's
        # cooldown, as well as a stale success extending it.
        clock[0] += timedelta(seconds=1)
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
        accepted = client.post(
            "/auth/mfa/verify", json={"mfa_challenge_token": new_token, "code": new_code}
        )
        assert accepted.status_code == 200
        assert accepted.json()["status"] == "signed_in"
        assert len(sender.messages) == 2
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
