# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The availability worker's locking on PostgreSQL (P2): SKIP LOCKED claims, and the retry and
provider-revocation paths waiting on the same rows queueing locks. FAKE data, owned schema."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from time import monotonic, sleep

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import sessionmaker

from carlos_patient_portal.mailbox_models import MailboxBase, MailboxCopy
from carlos_patient_portal.models import PatientPortalMyCarlosDevice
from carlos_patient_portal.mycarlos_availability import DispatchDecision, PushPlatform
from carlos_patient_portal.mycarlos_availability_dispatch import queue_documents_ready, settle
from tests.test_mycarlos_availability_dispatch import (
    NOW,
    Clock,
    Outbox,
    add_copy,
    enrolled,
    fcm,
    new_copy,
    outbox,
    subscription,
    worker,
)
from tests.test_mycarlos_postgresql import migrated_postgresql_engine  # noqa: F401
from tests.test_postgresql_integration import POSTGRES_URL

pytestmark = pytest.mark.skipif(POSTGRES_URL is None, reason="owned PostgreSQL URL required")


@pytest.fixture
def pg(request):
    engine = request.getfixturevalue("migrated_postgresql_engine")
    with engine.connect() as connection:
        assert connection.scalar(text("select current_schema()")).startswith("mycarlos_test_")
    MailboxBase.metadata.create_all(engine)
    return engine, sessionmaker(engine, expire_on_commit=False)


def observe_block(engine, holder_pid: int, request_pid: list[int], completed) -> None:
    deadline = monotonic() + 5
    while monotonic() < deadline:
        if request_pid:
            with engine.connect() as observer:
                blocked = observer.scalar(
                    text("select :holder = any(pg_blocking_pids(:request))"),
                    {"holder": holder_pid, "request": request_pid[0]},
                )
            if blocked:
                return
        assert not completed.done(), "the request finished without waiting on the holder"
        sleep(0.02)
    pytest.fail("the request never waited on the held transaction")


def test_an_accepted_send_round_trips_on_postgresql(pg) -> None:
    _engine, factory = pg
    owner, _sid, dest = enrolled(factory, "pg-accept")
    assert new_copy(factory, owner, 1) == 1
    transport = fcm(dest, 200)
    assert worker(factory, Clock(), {PushPlatform.ANDROID_FCM: transport}).process_one() == (
        "provider_accepted"
    )
    [row] = outbox(factory)
    assert (row.status, row.attempts, row.lease_token) == ("done", 1, None)
    assert len(transport.requests) == 1


def test_a_rollback_drops_the_copy_and_its_intent_on_postgresql(pg) -> None:
    _engine, factory = pg
    owner, _sid, _dest = enrolled(factory, "pg-rollback")
    with pytest.raises(RuntimeError), factory() as session, session.begin():
        copy = add_copy(session, owner, 1)
        assert queue_documents_ready(session, copy, now=NOW, server_enabled=True) == 1
        raise RuntimeError("FAKE failure after queueing")
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(MailboxCopy)) == 0
    assert outbox(factory) == []


def test_a_claim_skips_a_row_another_worker_holds(pg) -> None:
    _engine, factory = pg
    first, _s1, d1 = enrolled(factory, "pg-skip-1")
    second, _s2, d2 = enrolled(factory, "pg-skip-2")
    new_copy(factory, first, 1)
    new_copy(factory, second, 1)
    run = worker(factory, Clock(), {PushPlatform.ANDROID_FCM: fcm(d1)})
    with factory() as holder, holder.begin():
        held = holder.scalars(select(Outbox).order_by(Outbox.id).limit(1).with_for_update()).one()
        claimed = run.claim()
        assert claimed.row_id != held.id
    assert run.claim().row_id == held.id
    assert run.claim() is None


def test_a_retry_waits_for_a_concurrent_new_copy_and_hands_it_the_budget(pg) -> None:
    engine, factory = pg
    owner, _sid, dest = enrolled(factory, "pg-retry")
    new_copy(factory, owner, 1)
    claim = worker(factory, Clock(), {PushPlatform.ANDROID_FCM: fcm(dest)}).claim()
    connected = Event()
    request_pid: list[int] = []

    def settle_retry() -> str:
        with factory() as session, session.begin():
            request_pid.append(session.scalar(text("select pg_backend_pid()")))
            connected.set()
            decision = DispatchDecision("retry", retry_at=NOW + 30)
            return settle(session, claim.row_id, claim.lease, decision, now=NOW)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as holder, holder.begin():
            holder_pid = holder.scalar(text("select pg_backend_pid()"))
            copy = add_copy(holder, owner, 2)
            assert queue_documents_ready(holder, copy, now=NOW, server_enabled=True) == 1
            completed = pool.submit(settle_retry)
            assert connected.wait(5)
            observe_block(engine, holder_pid, request_pid, completed)
        # Without the subscription lock this was a unique-index failure on one side.
        assert completed.result(timeout=5) == "retry_superseded"
    first, newer = outbox(factory)
    assert (first.status, newer.status, newer.sequence) == ("done", "pending", 2)
    assert (newer.attempts, newer.next_attempt_at) == (1, NOW + 30)


def test_a_provider_revocation_waits_for_an_upload_holding_the_device(pg) -> None:
    engine, factory = pg
    owner, sid, dest = enrolled(factory, "pg-revoke")
    new_copy(factory, owner, 1)
    claim = worker(factory, Clock(), {PushPlatform.ANDROID_FCM: fcm(dest)}).claim()
    connected = Event()
    request_pid: list[int] = []

    def settle_invalid() -> str:
        with factory() as session, session.begin():
            request_pid.append(session.scalar(text("select pg_backend_pid()")))
            connected.set()
            decision = DispatchDecision("invalid_destination", revoke_destination=True)
            return settle(session, claim.row_id, claim.lease, decision, now=NOW)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as holder, holder.begin():
            holder_pid = holder.scalar(text("select pg_backend_pid()"))
            # As mailbox_lock does before a new copy: the device row first.
            holder.scalars(
                select(PatientPortalMyCarlosDevice)
                .where(PatientPortalMyCarlosDevice.id == owner.device_id)
                .with_for_update()
            ).one()
            copy = add_copy(holder, owner, 2)
            assert queue_documents_ready(holder, copy, now=NOW, server_enabled=True) == 1
            completed = pool.submit(settle_invalid)
            assert connected.wait(5)
            observe_block(engine, holder_pid, request_pid, completed)
        assert completed.result(timeout=5) == "invalid_destination"
    assert subscription(factory, sid).revoked_by == "provider"
    # The intent the upload committed while the revocation waited went with the subscription.
    assert [(r.sequence, r.status) for r in outbox(factory)] == [(1, "done")]
