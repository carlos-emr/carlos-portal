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
from carlos_patient_portal.routes import auth as auth_routes
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


@pytest.mark.parametrize("new_login_before_ack", [False, True], ids=["own_ack", "new_login"])
def test_verified_challenge_provider_outcome_follows_account_reservation(
    tmp_path, monkeypatch, new_login_before_ack
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
                if new_login_before_ack:
                    raise PortalEmailDeliveryError("FAKE older verified delivery failure")

    sender = DelayedSender()
    app = migrated_development_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'verified-current.db'}",
        email_sender=sender,
        mfa_email_resend_cooldown_seconds=60,
    )
    client, sending_client = TestClient(app), TestClient(app)
    try:
        account_id = activate_seeded_patient_account(app, client)
        real_resend = auth_routes.resend_mfa_challenge

        def resend_retaining_account(session, **kwargs):
            delivery = real_resend(session, **kwargs)
            # A real ORM identity retained across the provider wait must be refreshed
            # before its account reservation can decide callback ownership.
            session.info["held_mfa_account"] = session.get(PatientPortalAccount, account_id)
            return delivery

        monkeypatch.setattr(auth_routes, "resend_mfa_challenge", resend_retaining_account)
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
        with app.state.session_factory() as session:
            old_id = session.scalar(select(PatientPortalMfaChallenge.id))
        assert old_id is not None

        def current_identity_and_reservation():
            with app.state.session_factory() as session:
                challenge = session.get(PatientPortalMfaChallenge, old_id)
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
        if new_login_before_ack:
            clock[0] += timedelta(seconds=61)
            newer = client.post(
                "/auth/login", json={"username": "patient.user", "password": STRONG_PASSWORD}
            )
            assert newer.status_code == 200
            new_token = newer.json()["mfa_challenge_token"]
            new_code = newer.json()["development_mfa_code"]

            def newer_state():
                with app.state.session_factory() as session:
                    challenge = session.scalar(
                        select(PatientPortalMfaChallenge).where(
                            PatientPortalMfaChallenge.account_id == account_id,
                            PatientPortalMfaChallenge.id != identity[0],
                        )
                    )
                    account = session.get(PatientPortalAccount, account_id)
                    return (
                        challenge.id,
                        challenge.status,
                        challenge.code_hash,
                        challenge.expires_at,
                        challenge.delivery_method,
                        challenge.last_email_sent_at,
                        account.last_mfa_email_sent_at,
                    )

            latest = newer_state()
        clock[0] += timedelta(seconds=1)
        release.set()
        assert sending.result(timeout=10).status_code == (503 if new_login_before_ack else 200)
        if new_login_before_ack:
            assert newer_state() == latest
        after_identity, delivered_at, reservation = current_identity_and_reservation()
        assert after_identity == identity
        if new_login_before_ack:
            assert reservation == latest[-1]
        else:
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
            if new_login_before_ack:
                assert len(events) == 3
                superseded = [event for event in events if event.reason == "email:superseded"]
                assert len(superseded) == 1
                assert superseded[0].outcome == AUDIT_OUTCOME_FAILURE
                ordinary = [event for event in events if event.reason == "email"]
                assert len(ordinary) == 2
                assert all(event.outcome == AUDIT_OUTCOME_SUCCESS for event in ordinary)
            else:
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
        if new_login_before_ack:
            accepted = client.post(
                "/auth/mfa/verify", json={"mfa_challenge_token": new_token, "code": new_code}
            )
            assert accepted.status_code == 200
            assert accepted.json()["status"] == "signed_in"
        assert len(sender.messages) == (3 if new_login_before_ack else 2)
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


@pytest.mark.parametrize(
    ("old_send_fails", "verify_before_ack"),
    [
        pytest.param(True, False, id="failure"),
        pytest.param(False, False, id="success"),
        pytest.param(False, True, id="verified_after_restore"),
    ],
)
def test_failed_newer_resend_restores_the_pending_older_deliveries_outcome(
    tmp_path, monkeypatch, old_send_fails, verify_before_ack
):
    entered, release = Event(), Event()
    worker = None

    class DelayedSender(RecordingPortalEmailSender):
        hold_next = False
        fail_next = False

        def send_code(self, **message):
            super().send_code(**message)
            if self.hold_next:
                self.hold_next = False
                entered.set()
                assert release.wait(timeout=15), "provider gate was not released"
                if old_send_fails:
                    raise PortalEmailDeliveryError("FAKE restored older delivery failure")
            elif self.fail_next:
                self.fail_next = False
                raise PortalEmailDeliveryError("FAKE newer resend failure")

    sender = DelayedSender()
    app = migrated_development_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'restored-pending.db'}",
        email_sender=sender,
        mfa_email_resend_cooldown_seconds=60,
    )
    client, old_client = TestClient(app), TestClient(app)
    try:
        account_id = activate_seeded_patient_account(app, client)
        clock = [auth.utc_now()]
        monkeypatch.setattr(auth, "utc_now", lambda: clock[0])
        codes = iter(["111111", "222222", "333333"])
        monkeypatch.setattr(auth, "create_mfa_code", lambda: next(codes))
        login = client.post(
            "/auth/login", json={"username": "patient.user", "password": STRONG_PASSWORD}
        )
        assert login.status_code == 200
        token = login.json()["mfa_challenge_token"]
        resend = {"mfa_challenge_token": token, "mfa_delivery_method": "email"}

        def stored_state():
            with app.state.session_factory() as session:
                challenge = session.scalar(select(PatientPortalMfaChallenge))
                account = session.get(PatientPortalAccount, account_id)
                return (
                    (challenge.code_hash, challenge.expires_at, challenge.delivery_method),
                    challenge.last_email_sent_at,
                    account.last_mfa_email_sent_at,
                )

        initial_identity, initial_sent_at, _ = stored_state()
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
        older_identity, _, older_reservation = stored_state()
        clock[0] += timedelta(seconds=61)
        sender.fail_next = True
        newer = client.post("/auth/mfa/resend", json=resend)
        assert newer.status_code == 503
        restored_identity, _, newer_failure_reservation = stored_state()
        assert restored_identity == older_identity
        assert newer_failure_reservation > older_reservation
        if verify_before_ack:
            verified = client.post(
                "/auth/mfa/verify", json={"mfa_challenge_token": token, "code": "222222"}
            )
            assert verified.status_code == 200
            session_token = verified.json()["session_token"]
            assert session_token
        clock[0] += timedelta(seconds=1)
        release.set()
        assert older.result(timeout=10).status_code == (503 if old_send_fails else 200)
        identity, sent_at, reservation = stored_state()
        if old_send_fails:
            assert identity == initial_identity
            assert sent_at == initial_sent_at
            assert reservation - newer_failure_reservation == timedelta(seconds=1)
            accepted_code, retry_seconds = "111111", 5
        else:
            assert identity == older_identity
            assert sent_at == reservation
            assert reservation.replace(tzinfo=UTC) == clock[0]
            accepted_code, retry_seconds = "222222", 60
        if verify_before_ack:
            throttled = client.post(
                "/auth/login", json={"username": "patient.user", "password": STRONG_PASSWORD}
            )
        else:
            throttled = client.post("/auth/mfa/resend", json=resend)
        assert throttled.status_code == 429
        assert int(throttled.headers["retry-after"]) == retry_seconds
        with app.state.session_factory() as session:
            events = list(
                session.scalars(
                    select(PatientPortalAuditEvent)
                    .where(
                        PatientPortalAuditEvent.event_type == AUDIT_EVENT_MFA_DELIVERY,
                        PatientPortalAuditEvent.account_id == account_id,
                    )
                    .order_by(PatientPortalAuditEvent.id)
                )
            )
            assert [(event.reason, event.outcome) for event in events] == [
                ("email", AUDIT_OUTCOME_SUCCESS),
                ("email", AUDIT_OUTCOME_FAILURE),
                ("email", AUDIT_OUTCOME_FAILURE if old_send_fails else AUDIT_OUTCOME_SUCCESS),
            ]
        if verify_before_ack:
            with app.state.session_factory() as session:
                challenge = session.scalar(select(PatientPortalMfaChallenge))
                assert challenge.status == MFA_CHALLENGE_STATUS_VERIFIED
            authenticated = client.get(
                "/auth/session", headers={"Authorization": f"Bearer {session_token}"}
            )
            assert authenticated.status_code == 200
            assert authenticated.json()["status"] == "authenticated"
        else:
            for code in sorted({"111111", "222222", "333333"} - {accepted_code}):
                rejected = client.post(
                    "/auth/mfa/verify", json={"mfa_challenge_token": token, "code": code}
                )
                assert rejected.status_code == 401
            accepted = client.post(
                "/auth/mfa/verify", json={"mfa_challenge_token": token, "code": accepted_code}
            )
            assert accepted.status_code == 200
            assert accepted.json()["status"] == "signed_in"
        assert len(sender.messages) == 3
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
