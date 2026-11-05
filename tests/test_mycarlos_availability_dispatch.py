# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The queueing hook and the outbox worker for myCarlos availability notices (P2), on SQLite.

The #80 provider adapters run behind their recording HTTP fakes (tests/notification_transports_
support.py): nothing leaves the process. Every id, handle, key and value is FAKE; the notice key
is derived at run time, never written down. PostgreSQL locking is in the _postgresql file.
"""

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import anyio
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal import mailbox_worker
from carlos_patient_portal import mycarlos_availability_dispatch as dispatch_module
from carlos_patient_portal.mailbox_models import MailboxBase, MailboxCopy
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalMyCarlosAvailabilityOutbox,
    PatientPortalMyCarlosAvailabilitySubscription,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosRecipient,
)
from carlos_patient_portal.mycarlos_availability import (
    HINT_TTL_SECONDS,
    MAX_ATTEMPTS,
    AvailabilityError,
    DispatchDecision,
    NoticeKeys,
    Owner,
    ProviderResult,
    PushPlatform,
    ReadyHint,
    notice_token,
)
from carlos_patient_portal.mycarlos_availability_dispatch import (
    AvailabilityDispatch,
    AvailabilityDispatcher,
    dispatcher_for,
    queue_documents_ready,
    revoke_invalid_destination,
    run_dispatch_worker,
    settle,
)
from carlos_patient_portal.mycarlos_availability_store import enroll, revoke
from carlos_patient_portal.notification_transports import ApnsConfig, FcmConfig
from carlos_patient_portal.routes import mycarlos_mailbox
from tests import delivery_contract_reference as ref
from tests.notification_transports_support import (
    FixedHandles,
    RecordingApnsTransport,
    RecordingFcmTransport,
)
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    migrated_development_app,
)
from tests.test_internal_api import internal_app
from tests.test_mycarlos_availability_store import NOW, add_owner, consent, migrated  # noqa: F401
from tests.test_mycarlos_mailbox_http import (
    BODY,
    DEVICE,
    JOB,
    JOB_KID,
    OUTER,
    PREFIX,
    UPLOAD_PATH,
    job_headers,
)
from tests.test_mycarlos_mailbox_http import NOW as HTTP_NOW

Outbox = PatientPortalMyCarlosAvailabilityOutbox
Subscriptions = PatientPortalMyCarlosAvailabilitySubscription

# Derived at run time: the tests hold no key material.
FAKE_KEYS = NoticeKeys(sha256(b"FAKE availability notice key for tests").digest())
FCM = FcmConfig("fake-project-id", Path("/nonexistent/fake-service-account.json"))
APNS = ApnsConfig("FAKETEAM01", "FAKEKEYID1", Path("/nonexistent/fake.p8"), "ca.example.fake")
FCM_HANDLE = "fake-fcm-registration-handle-0001"
APNS_HANDLE = "ab" * 32


class Clock:
    def __init__(self, now: int = NOW) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


@pytest.fixture
def db(migrated):  # noqa: F811
    engine, _config = migrated
    MailboxBase.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)


def add_copy(
    session: Session, owner: Owner, sequence: int, *, expires_at: int = NOW + 3600
) -> MailboxCopy:
    device = session.get(PatientPortalMyCarlosDevice, owner.device_id)
    copy = MailboxCopy(
        account_id=owner.account_id,
        device_id=owner.device_id,
        clinic_id="clinic-a",
        recipient_id="FAKE-recipient",
        device_key_id=device.device_key_id,
        delivery_id=f"00000000-0000-4000-8000-{sequence:012d}",
        sequence=sequence,
        size=49,
        ciphertext_sha256="c" * 64,
        body_sha256="b" * 64,
        created_at=NOW - 60,
        expires_at=expires_at,
        status="waiting",
    )
    session.add(copy)
    session.flush()
    return copy


def enrolled(factory, label: str, *, platform: str = "android_fcm") -> tuple[Owner, UUID, UUID]:
    with factory() as session, session.begin():
        owner = add_owner(session, label)
        row, _ = enroll(
            session, owner, consent(platform=platform), now=datetime.fromtimestamp(NOW, tz=UTC)
        )
        return owner, UUID(row.subscription_id), UUID(row.destination_id)


def new_copy(factory, owner: Owner, sequence: int, *, expires_at: int = NOW + 3600, now=NOW):
    with factory() as session, session.begin():
        copy = add_copy(session, owner, sequence, expires_at=expires_at)
        return queue_documents_ready(session, copy, now=now, server_enabled=True)


def fcm(destination: UUID, *responses: int | BaseException) -> RecordingFcmTransport:
    return RecordingFcmTransport(FCM, FixedHandles({destination: FCM_HANDLE}), *responses)


def worker(factory, clock: Clock, transports, *, server_enabled: bool = True):
    return AvailabilityDispatcher(
        factory,
        AvailabilityDispatch(transports, FAKE_KEYS),
        server_enabled=server_enabled,
        clock=clock,
    )


def outbox(factory) -> list[Outbox]:
    with factory() as session:
        return list(session.scalars(select(Outbox).order_by(Outbox.id)))


def subscription(factory, subscription_id: UUID) -> Subscriptions:
    with factory() as session:
        return session.scalars(
            select(Subscriptions).where(Subscriptions.subscription_id == str(subscription_id))
        ).one()


# --- the queueing hook -------------------------------------------------------------------------


def test_the_hook_queues_nothing_while_the_switch_is_off(db) -> None:
    owner, _sid, _dest = enrolled(db, "off")
    with db() as session, session.begin():
        copy = add_copy(session, owner, 1)
        assert queue_documents_ready(session, copy, now=NOW) == 0
        assert queue_documents_ready(session, copy, now=NOW, server_enabled=False) == 0
    assert outbox(db) == []


def test_the_hook_queues_one_capped_intent_per_permitted_subscription(db) -> None:
    owner, sid, _dest = enrolled(db, "hook")
    with db() as session, session.begin():
        # A second subscription with the remote switch off gets nothing.
        enroll(session, owner, consent(remote_enabled=False))
    assert new_copy(db, owner, 1) == 1
    [row] = outbox(db)
    assert (row.subscription_id, row.sequence, row.status) == (str(sid), 1, "pending")
    assert row.expires_at == NOW + HINT_TTL_SECONDS
    assert row.attempts == 0 and row.lease_token is None


def test_a_rollback_drops_the_copy_and_its_intent_together(db) -> None:
    owner, _sid, _dest = enrolled(db, "rollback")
    with pytest.raises(RuntimeError), db() as session, session.begin():
        copy = add_copy(session, owner, 1)
        assert queue_documents_ready(session, copy, now=NOW, server_enabled=True) == 1
        raise RuntimeError("FAKE failure after queueing")
    with db() as session:
        assert session.scalar(select(func.count()).select_from(MailboxCopy)) == 0
    assert outbox(db) == []


def http_app(monkeypatch: pytest.MonkeyPatch, *, availability: bool):
    """The real upload route, as the M4 HTTP tests build it, with one enrolled subscription."""
    monkeypatch.setattr(mycarlos_mailbox, "time", lambda: HTTP_NOW)
    app = internal_app(
        mycarlos_delivery_enabled=True,
        mycarlos_mailbox_enabled=True,
        mycarlos_availability_enabled=availability,
        public_base_url="https://portal.example.test" + PREFIX,
        internal_job_assertion_public_keyring=json.dumps(
            {"delivery-sync": {JOB_KID: ref.b64url(JOB.ed25519_public)}}
        ),
    )
    MailboxBase.metadata.create_all(app.state.database_engine)
    with app.state.session_factory() as session, session.begin():
        account = PatientPortalAccount(
            clinic_id="clinic-a",
            demographic_no=6001,
            username="fake.availability.http",
            email="fake.availability.http@example.test",
            password_hash="FAKE-unused",
            status="active",
        )
        session.add(account)
        session.flush()
        session.add(
            PatientPortalMyCarlosRecipient(
                account_id=account.id, recipient_id=OUTER["recipient_id"]
            )
        )
        device = PatientPortalMyCarlosDevice(
            account_id=account.id,
            device_key_id=DEVICE.device_key_id,
            ed25519_public_key=DEVICE.ed25519_public,
            x25519_public_key=DEVICE.x25519_public,
            device_name="FAKE availability HTTP device",
            status="active",
            linked_at=datetime.fromtimestamp(HTTP_NOW, tz=UTC),
        )
        session.add(device)
        session.flush()
        enroll(session, Owner(account.id, device.id), consent())
    return app, TestClient(app, base_url="https://portal.example.test")


@pytest.mark.parametrize("availability", [False, True])
def test_an_upload_queues_through_the_real_route_once(monkeypatch, availability: bool) -> None:
    app, client = http_app(monkeypatch, availability=availability)
    assert client.post(UPLOAD_PATH, content=BODY, headers=job_headers()).status_code == 201
    # The same delivery again is idempotent: 200, no second copy, no second intent.
    assert client.post(UPLOAD_PATH, content=BODY, headers=job_headers()).status_code == 200
    factory = app.state.session_factory
    rows = outbox(factory)
    if not availability:
        assert rows == []
        return
    with factory() as session:
        copy = session.scalars(select(MailboxCopy)).one()
    [row] = rows
    assert (row.sequence, row.status, row.attempts) == (copy.sequence, "pending", 0)
    assert row.expires_at == min(copy.expires_at, HTTP_NOW + HINT_TTL_SECONDS)


def test_a_failed_upload_transaction_leaves_neither_copy_nor_intent(monkeypatch) -> None:
    app, client = http_app(monkeypatch, availability=True)
    real = mycarlos_mailbox.admit_upload

    def admit_then_fail(*args, **kwargs):
        result = real(*args, **kwargs)
        assert result[1] == 201 and kwargs["availability_enabled"] is True
        raise RuntimeError("FAKE failure after the copy and its intent were added")

    monkeypatch.setattr(mycarlos_mailbox, "admit_upload", admit_then_fail)
    with pytest.raises(RuntimeError):
        client.post(UPLOAD_PATH, content=BODY, headers=job_headers())
    factory = app.state.session_factory
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(MailboxCopy)) == 0
    assert outbox(factory) == []


# --- the worker: sending and settling ---------------------------------------------------------


def test_an_accepted_send_carries_only_the_notice_token_and_closes_the_row(db) -> None:
    owner, sid, dest = enrolled(db, "accept")
    new_copy(db, owner, 1)
    transport = fcm(dest, 200)
    clock = Clock()
    assert worker(db, clock, {PushPlatform.ANDROID_FCM: transport}).process_one() == (
        "provider_accepted"
    )
    [row] = outbox(db)
    assert (row.status, row.attempts, row.last_decision) == ("done", 1, "provider_accepted")
    assert row.lease_token is None and row.lease_until is None
    [request] = transport.requests
    body = json.loads(request.body)
    expected = notice_token(FAKE_KEYS, ReadyHint(sid, UUID(row.epoch), 1))
    assert body["message"]["data"] == {"n": expected}
    assert body["message"]["token"] == FCM_HANDLE
    assert set(body["message"]) == {"token", "notification", "data", "android"}
    for private in (str(sid), row.epoch, str(dest)):
        assert private not in request.body.decode()
    assert worker(db, clock, {PushPlatform.ANDROID_FCM: transport}).process_one() is None


def test_the_claim_commits_a_fresh_lease_before_anything_is_sent(db) -> None:
    owner, _sid, _dest = enrolled(db, "lease")
    new_copy(db, owner, 1)
    seen = []

    class Inspecting:
        def send(self, **_kwargs: object) -> ProviderResult:
            with db() as session:
                row = session.scalars(select(Outbox)).one()
                seen.append((row.status, row.lease_token, row.lease_until, row.attempts))
            return ProviderResult.ACCEPTED

    clock = Clock()
    assert worker(db, clock, {PushPlatform.ANDROID_FCM: Inspecting()}).process_one() == (
        "provider_accepted"
    )
    [(status, token, lease_until, attempts)] = seen
    assert status == "leased" and UUID(token).version == 4
    assert lease_until == NOW + 60 and attempts == 1


def test_a_provider_outage_backs_off_then_runs_out_of_attempts(db) -> None:
    owner, _sid, dest = enrolled(db, "outage")
    new_copy(db, owner, 1)
    transport = fcm(dest, 503)
    clock = Clock()
    run = worker(db, clock, {PushPlatform.ANDROID_FCM: transport})
    waits = []
    for _attempt in range(1, MAX_ATTEMPTS):
        assert run.process_one() == "retry"
        [row] = outbox(db)
        assert row.status == "pending" and row.lease_token is None
        waits.append(row.next_attempt_at - clock.now)
        assert run.process_one() is None  # not due yet
        clock.now = row.next_attempt_at
    assert waits == [30, 60, 120, 240]
    assert run.process_one() == "attempts_exhausted"
    [row] = outbox(db)
    assert (row.status, row.attempts) == ("done", MAX_ATTEMPTS)
    assert len(transport.requests) == MAX_ATTEMPTS


def test_an_expired_intent_is_closed_without_a_send(db) -> None:
    owner, _sid, dest = enrolled(db, "expired")
    new_copy(db, owner, 1)
    transport = fcm(dest, 200)
    clock = Clock(NOW + HINT_TTL_SECONDS)
    assert worker(db, clock, {PushPlatform.ANDROID_FCM: transport}).process_one() == "expired"
    assert transport.requests == [] and outbox(db)[0].status == "done"


def test_a_retry_that_would_outlive_the_intent_expires_instead(db) -> None:
    owner, _sid, dest = enrolled(db, "retry-expiry")
    new_copy(db, owner, 1, expires_at=NOW + 50)
    clock = Clock()
    run = worker(db, clock, {PushPlatform.ANDROID_FCM: fcm(dest, 429)})
    assert run.process_one() == "retry"
    clock.now = outbox(db)[0].next_attempt_at
    assert run.process_one() == "expired"


@pytest.mark.parametrize("change", ["revoked", "device_removed", "account_disabled", "picked_up"])
def test_a_revoked_or_inactive_owner_or_a_collected_copy_gets_no_send(db, change: str) -> None:
    owner, sid, dest = enrolled(db, f"gone-{change}")
    new_copy(db, owner, 1)
    transport = fcm(dest, 200)
    run = worker(db, Clock(), {PushPlatform.ANDROID_FCM: transport})
    claim = run.claim()  # leased first: revocation cannot recall it, the fresh read must
    with db() as session, session.begin():
        if change == "revoked":
            revoke(session, owner, sid)
        elif change == "device_removed":
            device = session.get(PatientPortalMyCarlosDevice, owner.device_id)
            device.status = "removed"
            device.removed_at = datetime.fromtimestamp(NOW, tz=UTC)
            device.removed_by = "patient"
        elif change == "account_disabled":
            account = session.get(PatientPortalAccount, owner.account_id)
            account.status = "disabled"
            account.disabled_at = datetime.fromtimestamp(NOW, tz=UTC)
            account.disabled_by = "FAKE staff"
        else:
            copy = session.scalars(select(MailboxCopy)).one()
            copy.status, copy.terminal_at, copy.receipt_sha256 = "picked_up", NOW, "r" * 64
    assert run.complete(claim) == "suppressed"
    assert transport.requests == []
    assert outbox(db)[0].status == "done"


def test_an_unlinked_account_gets_no_send(db) -> None:
    owner, _sid, dest = enrolled(db, "unlinked")
    new_copy(db, owner, 1)
    with db() as session, session.begin():
        session.delete(
            session.scalars(
                select(PatientPortalMyCarlosRecipient).where(
                    PatientPortalMyCarlosRecipient.account_id == owner.account_id
                )
            ).one()
        )
    transport = fcm(dest, 200)
    assert worker(db, Clock(), {PushPlatform.ANDROID_FCM: transport}).process_one() == (
        "suppressed"
    )
    assert transport.requests == []


def test_the_server_switch_off_suppresses_every_send(db) -> None:
    owner, _sid, dest = enrolled(db, "server-off")
    new_copy(db, owner, 1)
    transport = fcm(dest, 200)
    run = worker(db, Clock(), {PushPlatform.ANDROID_FCM: transport}, server_enabled=False)
    assert run.process_one() == "suppressed" and transport.requests == []


def test_an_invalid_destination_revokes_its_subscription_and_pending_intents(db) -> None:
    owner, sid, dest = enrolled(db, "invalid")
    new_copy(db, owner, 1)
    run = worker(db, Clock(), {PushPlatform.ANDROID_FCM: fcm(dest, 404)})
    claim = run.claim()
    new_copy(db, owner, 2)  # queued beside the lease while it is out
    assert run.complete(claim) == "invalid_destination"
    revoked = subscription(db, sid)
    assert revoked.revoked_by == "provider" and revoked.revoked_at is not None
    assert revoked.remote_enabled is False
    assert [(r.sequence, r.status) for r in outbox(db)] == [(1, "done")]
    assert new_copy(db, owner, 3) == 0


def test_the_provider_revocation_is_fenced_on_epoch_and_destination(db) -> None:
    owner, sid, dest = enrolled(db, "fence-revoke")
    new_copy(db, owner, 1)
    claim = worker(db, Clock(), {PushPlatform.ANDROID_FCM: fcm(dest)}).claim()
    with db() as session, session.begin():
        row = session.scalars(
            select(Subscriptions).where(Subscriptions.subscription_id == str(sid))
        ).one()
        row.epoch = "00000000-0000-4000-8000-000000000e02"  # rotated meanwhile
    with db() as session, session.begin():
        assert revoke_invalid_destination(session, claim.lease.intent, now=NOW) is False
    assert subscription(db, sid).revoked_at is None


def test_a_stale_lease_holder_writes_nothing_after_a_reclaim(db) -> None:
    owner, _sid, dest = enrolled(db, "stale")
    new_copy(db, owner, 1)
    clock = Clock()
    first = worker(db, clock, {PushPlatform.ANDROID_FCM: fcm(dest)}).claim()
    clock.now += 61  # the first worker stalled past its lease
    second_transport = fcm(dest, 200)
    second = worker(db, clock, {PushPlatform.ANDROID_FCM: second_transport})
    reclaimed = second.claim()
    assert reclaimed.lease.lease_token != first.lease.lease_token
    assert reclaimed.lease.attempt == 2
    with db() as session, session.begin():
        assert (
            settle(
                session,
                first.row_id,
                first.lease,
                DispatchDecision("provider_accepted"),
                now=clock.now,
            )
            == "lease_lost"
        )
    [row] = outbox(db)
    assert row.status == "leased" and row.lease_token == str(reclaimed.lease.lease_token)
    assert second.complete(reclaimed) == "provider_accepted"


def test_an_expired_lease_is_not_settled_even_by_its_own_token(db) -> None:
    owner, _sid, dest = enrolled(db, "own-expired")
    new_copy(db, owner, 1)
    clock = Clock()
    run = worker(db, clock, {PushPlatform.ANDROID_FCM: fcm(dest, 200)})
    claim = run.claim()
    clock.now += 60
    assert run.complete(claim) == "lease_lost"
    assert outbox(db)[0].status == "leased"  # reclaimed on the next pass
    assert run.process_one() == "provider_accepted"


def test_a_retry_hands_its_budget_to_a_newer_pending_intent(db) -> None:
    owner, _sid, dest = enrolled(db, "superseded")
    new_copy(db, owner, 1)
    clock = Clock()
    run = worker(db, clock, {PushPlatform.ANDROID_FCM: fcm(dest, 503)})
    claim = run.claim()
    new_copy(db, owner, 2)
    assert run.complete(claim) == "retry_superseded"
    first, newer = outbox(db)
    assert (first.status, first.last_decision) == ("done", "retry_superseded")
    assert (newer.status, newer.sequence, newer.attempts) == ("pending", 2, 1)
    assert newer.next_attempt_at == NOW + 30


def test_a_retry_after_revocation_does_not_bring_the_intent_back(db) -> None:
    owner, sid, dest = enrolled(db, "retry-revoked")
    new_copy(db, owner, 1)
    run = worker(db, Clock(), {PushPlatform.ANDROID_FCM: fcm(dest, 503)})
    claim = run.claim()
    with db() as session, session.begin():
        decision = DispatchDecision("retry", retry_at=NOW + 30)
        revoke(session, owner, sid)
        assert settle(session, claim.row_id, claim.lease, decision, now=NOW) == "suppressed"
    assert [(r.status, r.last_decision) for r in outbox(db)] == [("done", "suppressed")]


def test_a_platform_without_credentials_is_a_fault_and_sends_nothing(db) -> None:
    owner, _sid, _dest = enrolled(db, "no-apns", platform="ios_apns")
    new_copy(db, owner, 1)
    transport = fcm(UUID(int=1), 200)
    assert worker(db, Clock(), {PushPlatform.ANDROID_FCM: transport}).process_one() == (
        "transport_error:PlatformNotConfigured"
    )
    assert transport.requests == [] and outbox(db)[0].status == "done"


def test_a_miswired_transport_is_a_fault_not_a_retry(db) -> None:
    owner, _sid, dest = enrolled(db, "miswired")
    new_copy(db, owner, 1)
    apns = RecordingApnsTransport(APNS, FixedHandles({dest: APNS_HANDLE}), 200)
    decision = worker(db, Clock(), {PushPlatform.ANDROID_FCM: apns}).process_one()
    assert decision == "transport_error:TypeError"
    assert apns.requests == [] and outbox(db)[0].status == "done"


def test_the_apns_adapter_sends_through_the_worker(db) -> None:
    owner, _sid, dest = enrolled(db, "apns", platform="ios_apns")
    new_copy(db, owner, 1)
    apns = RecordingApnsTransport(APNS, FixedHandles({dest: APNS_HANDLE}), 200, now=NOW)
    assert worker(db, Clock(), {PushPlatform.IOS_APNS: apns}).process_one() == ("provider_accepted")
    assert len(apns.requests) == 1


def test_a_row_that_cannot_form_an_intent_is_closed_not_retried(db) -> None:
    owner, sid, dest = enrolled(db, "poison")
    with db() as session, session.begin():
        session.add(
            Outbox(
                subscription_id=str(sid),
                epoch="not-a-uuid-but-thirty-six-characters",
                sequence=1,
                expires_at=NOW + 600,
                status="pending",
                attempts=0,
                created_at=NOW,
            )
        )
    new_copy(db, owner, 1)
    transport = fcm(dest, 200)
    run = worker(db, Clock(), {PushPlatform.ANDROID_FCM: transport})
    assert run.process_one() == "invalid_row"
    assert run.process_one() == "provider_accepted"
    assert [r.last_decision for r in outbox(db)] == ["invalid_row", "provider_accepted"]


def test_closed_rows_are_pruned_after_their_retention_and_open_ones_stay(db) -> None:
    owner, _sid, dest = enrolled(db, "prune")
    new_copy(db, owner, 1)
    clock = Clock()
    run = worker(db, clock, {PushPlatform.ANDROID_FCM: fcm(dest, 200)})
    assert run.process_one() == "provider_accepted"
    new_copy(db, owner, 2)
    assert run.prune() == 0
    clock.now = outbox(db)[0].expires_at + dispatch_module.DONE_RETENTION_SECONDS
    assert run.prune() == 1
    assert [(r.sequence, r.status) for r in outbox(db)] == [(2, "pending")]


# --- configuration and lifespan ---------------------------------------------------------------


def test_the_dispatch_config_needs_keys_transports_and_a_short_lease(db) -> None:
    transport = fcm(UUID(int=1))
    with pytest.raises(AvailabilityError, match="invalid_notice_key"):
        AvailabilityDispatch({PushPlatform.ANDROID_FCM: transport}, None)  # type: ignore[arg-type]
    with pytest.raises(AvailabilityError, match="invalid_transports"):
        AvailabilityDispatch({}, FAKE_KEYS)
    with pytest.raises(AvailabilityError, match="invalid_lease"):
        AvailabilityDispatch({PushPlatform.ANDROID_FCM: transport}, FAKE_KEYS, lease_seconds=121)
    config = AvailabilityDispatch({PushPlatform.ANDROID_FCM: transport}, FAKE_KEYS)
    assert repr(config) == "AvailabilityDispatch[REDACTED]"


SWITCHES = (
    "mycarlos_delivery_enabled",
    "mycarlos_mailbox_enabled",
    "mycarlos_availability_enabled",
)


@pytest.mark.parametrize("off", SWITCHES)
def test_the_worker_needs_every_switch_and_credentials(db, off: str) -> None:
    switches = dict.fromkeys(SWITCHES, True)
    config = AvailabilityDispatch({PushPlatform.ANDROID_FCM: fcm(UUID(int=1))}, FAKE_KEYS)

    def runtime(dispatch, **changes):
        return SimpleNamespace(
            settings=SimpleNamespace(**(switches | changes)),
            availability_dispatch=dispatch,
            session_factory=db,
        )

    assert dispatcher_for(runtime(None)) is None
    assert dispatcher_for(runtime(config, **{off: False})) is None
    ready = dispatcher_for(runtime(config))
    assert isinstance(ready, AvailabilityDispatcher) and ready.server_enabled is True


@pytest.mark.parametrize("configured", [False, True])
def test_the_lifespan_starts_the_dispatch_worker_only_with_credentials(
    tmp_path, monkeypatch: pytest.MonkeyPatch, configured: bool
) -> None:
    started = []

    async def idle_mailbox_worker(_runtime) -> None:
        await anyio.sleep_forever()

    async def recording_dispatch_worker(dispatcher, runtime) -> None:
        started.append((dispatcher, runtime))
        await anyio.sleep_forever()

    sentinel = object()
    monkeypatch.setattr(mailbox_worker, "run_worker", idle_mailbox_worker)
    monkeypatch.setattr(dispatch_module, "run_dispatch_worker", recording_dispatch_worker)
    if configured:
        monkeypatch.setattr(dispatch_module, "dispatcher_for", lambda _runtime: sentinel)
    app = migrated_development_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'availability-lifespan.db'}",
        mycarlos_delivery_enabled=True,
        mycarlos_mailbox_enabled=True,
        mycarlos_availability_enabled=True,
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
    )
    with TestClient(app):
        pass
    if configured:
        [(dispatcher, runtime)] = started
        assert dispatcher is sentinel and runtime.availability_dispatch is None
    else:
        assert started == []


def test_the_worker_loop_reports_a_fault_by_class_name_only(
    db, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    run = worker(db, Clock(), {PushPlatform.ANDROID_FCM: fcm(UUID(int=1))})

    def failing() -> None:
        raise RuntimeError("FAKE detail that must not be logged")

    monkeypatch.setattr(run, "process_one", failing)
    failures = []
    runtime = SimpleNamespace(operational_metrics=SimpleNamespace(record_failure=failures.append))

    async def briefly() -> None:
        with anyio.move_on_after(0.5):
            await run_dispatch_worker(run, runtime)

    anyio.run(briefly)
    assert "RuntimeError" in caplog.text and "FAKE detail" not in caplog.text
    assert failures == ["mycarlos_availability_dispatch"]


def test_the_worker_loop_drains_due_rows(db) -> None:
    owners = [enrolled(db, f"drain-{index}") for index in range(3)]
    transports = {}
    handles = {}
    for owner, _sid, dest in owners:
        new_copy(db, owner, 1)
        handles[dest] = FCM_HANDLE
    transports[PushPlatform.ANDROID_FCM] = RecordingFcmTransport(FCM, FixedHandles(handles), 200)
    run = worker(db, Clock(), transports)

    async def briefly() -> None:
        with anyio.move_on_after(0.5):
            await run_dispatch_worker(run)

    anyio.run(briefly)
    assert [r.last_decision for r in outbox(db)] == ["provider_accepted"] * 3
    assert len(transports[PushPlatform.ANDROID_FCM].requests) == 3
