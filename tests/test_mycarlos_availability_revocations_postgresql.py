# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The revocation acknowledgement's locking on PostgreSQL (P4): a revocation and an enrollment of
the same id serialize on the device row or the destination index, and a revocation waits for an
upload holding the device, then drops the intent that upload committed. FAKE data, owned schema.
"""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from carlos_patient_portal.models import (
    PatientPortalMyCarlosAvailabilitySubscription,
    PatientPortalMyCarlosDevice,
)
from carlos_patient_portal.mycarlos_availability import Owner
from carlos_patient_portal.mycarlos_availability_dispatch import queue_documents_ready
from carlos_patient_portal.mycarlos_availability_store import (
    EnrollmentRefusal,
    RevocationRequest,
    acknowledge_revocation,
    enroll,
)
from tests.test_mycarlos_availability_dispatch import NOW, add_copy, enrolled, new_copy, outbox
from tests.test_mycarlos_availability_dispatch_postgresql import (  # noqa: F401
    migrated_postgresql_engine,
    observe_block,
    pg,
)
from tests.test_mycarlos_availability_store import add_owner, consent
from tests.test_postgresql_integration import POSTGRES_URL

pytestmark = pytest.mark.skipif(POSTGRES_URL is None, reason="owned PostgreSQL URL required")
Subscriptions = PatientPortalMyCarlosAvailabilitySubscription


def owner_for(factory, label: str) -> Owner:  # noqa: ANN001
    with factory() as session, session.begin():
        return add_owner(session, label)


def stop(destination: str) -> RevocationRequest:
    return RevocationRequest("android_fcm", destination)


def outcome(work: Callable[[], object]) -> str:
    try:
        work()
    except EnrollmentRefusal as exc:
        return exc.code
    return "ok"


def waits_then(engine, factory, hold: Callable[[Session], None], request) -> str:  # noqa: ANN001
    """Runs `request(session)` while `hold` keeps its transaction open; proves it waited."""
    connected = Event()
    request_pid: list[int] = []

    def run() -> str:
        with factory() as session, session.begin():
            request_pid.append(session.scalar(text("select pg_backend_pid()")))
            connected.set()
            return outcome(lambda: request(session))

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as holder, holder.begin():
            holder_pid = holder.scalar(text("select pg_backend_pid()"))
            hold(holder)
            completed = pool.submit(run)
            assert connected.wait(5)
            observe_block(engine, holder_pid, request_pid, completed)
        return completed.result(timeout=5)


def by_destination(factory, destination: str) -> Subscriptions:  # noqa: ANN001
    with factory() as session:
        return session.scalars(
            select(Subscriptions).where(Subscriptions.destination_id == destination)
        ).one()


def test_a_revocation_round_trips_on_postgresql(pg) -> None:  # noqa: F811
    _engine, factory = pg
    owner, _sid, dest = enrolled(factory, "pg-ack")
    new_copy(factory, owner, 1)
    unknown = str(uuid4())
    with factory() as session, session.begin():
        acknowledge_revocation(session, owner, stop(str(dest)))
        acknowledge_revocation(session, owner, stop(unknown))
    assert by_destination(factory, str(dest)).revoked_by == "device"
    tombstone = by_destination(factory, unknown)
    assert (tombstone.revoked_by, tombstone.remote_enabled) == ("device", False)
    assert outbox(factory) == []


def test_an_enrollment_waits_for_a_revocation_of_the_same_new_id_and_is_refused(pg) -> None:  # noqa: F811
    engine, factory = pg
    owner = owner_for(factory, "pg-late")
    destination = str(uuid4())
    result = waits_then(
        engine,
        factory,
        lambda holder: acknowledge_revocation(holder, owner, stop(destination)),
        lambda session: enroll(session, owner, consent(destination_id=destination)),
    )
    # The device row serializes them: the late enrollment sees the committed tombstone.
    assert result == "destination_revoked"
    assert by_destination(factory, destination).revoked_by == "device"


def test_a_revocation_waits_for_an_upload_holding_the_device_and_drops_its_intent(pg) -> None:  # noqa: F811
    engine, factory = pg
    owner, _sid, dest = enrolled(factory, "pg-upload")

    def upload(holder: Session) -> None:
        # As mailbox_lock does before a new copy: the device row first.
        holder.scalars(
            select(PatientPortalMyCarlosDevice)
            .where(PatientPortalMyCarlosDevice.id == owner.device_id)
            .with_for_update()
        ).one()
        copy = add_copy(holder, owner, 1)
        assert queue_documents_ready(holder, copy, now=NOW, server_enabled=True) == 1

    result = waits_then(
        engine,
        factory,
        upload,
        lambda session: acknowledge_revocation(session, owner, stop(str(dest))),
    )
    assert result == "ok"
    # The intent the upload committed while the revocation waited went with the destination.
    assert outbox(factory) == []
    assert by_destination(factory, str(dest)).revoked_by == "device"


def test_another_devices_enrollment_of_a_new_id_being_revoked_is_refused(pg) -> None:  # noqa: F811
    engine, factory = pg
    first = owner_for(factory, "pg-race-a")
    second = owner_for(factory, "pg-race-b")
    destination = str(uuid4())
    # Different device rows: the destination index decides, and waits for the first to commit.
    result = waits_then(
        engine,
        factory,
        lambda holder: acknowledge_revocation(holder, first, stop(destination)),
        lambda session: enroll(session, second, consent(destination_id=destination)),
    )
    assert result == "destination_taken"
    row = by_destination(factory, destination)
    assert (row.device_id, row.revoked_by) == (first.device_id, "device")


def test_two_devices_revoking_one_new_id_are_both_answered(pg) -> None:  # noqa: F811
    engine, factory = pg
    first = owner_for(factory, "pg-both-a")
    second = owner_for(factory, "pg-both-b")
    destination = str(uuid4())
    # The second insert waits on the destination index; the winner's row is revoked, so the
    # second device is answered too rather than told the destination is taken.
    result = waits_then(
        engine,
        factory,
        lambda holder: acknowledge_revocation(holder, first, stop(destination)),
        lambda session: acknowledge_revocation(session, second, stop(destination)),
    )
    assert result == "ok"
    row = by_destination(factory, destination)
    assert (row.device_id, row.revoked_by) == (first.device_id, "device")


def test_a_revocation_of_another_devices_new_enrollment_is_refused(pg) -> None:  # noqa: F811
    engine, factory = pg
    first = owner_for(factory, "pg-race-c")
    second = owner_for(factory, "pg-race-d")
    destination = str(uuid4())
    result = waits_then(
        engine,
        factory,
        lambda holder: enroll(holder, second, consent(destination_id=destination)),
        lambda session: acknowledge_revocation(session, first, stop(destination)),
    )
    assert result == "destination_taken"
    row = by_destination(factory, destination)
    assert (row.device_id, row.revoked_at) == (second.device_id, None)
