# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""The waiting key on PostgreSQL (carlos-portal#87): the table's checks and partial unique index,
registration serialized on the device row, and two checks at once answering only one within
120 seconds. FAKE data, owned schema.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from carlos_patient_portal.models import (
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosWaitingKey,
)
from carlos_patient_portal.mycarlos_waiting import (
    ANSWER_NOTHING,
    ANSWER_WAITING,
    TooSoon,
    WaitingPrincipal,
    answer,
    register,
    waiting_key_id,
)
from tests import delivery_contract_reference as ref
from tests.test_mycarlos_availability_dispatch import NOW, add_copy
from tests.test_mycarlos_availability_dispatch_postgresql import (  # noqa: F401
    migrated_postgresql_engine,
    observe_block,
    pg,
)
from tests.test_mycarlos_availability_store import add_owner
from tests.test_postgresql_integration import POSTGRES_URL

pytestmark = pytest.mark.skipif(POSTGRES_URL is None, reason="owned PostgreSQL URL required")

AT = datetime.fromtimestamp(NOW, tz=UTC)


def public_key(label: str) -> bytes:
    private = Ed25519PrivateKey.from_private_bytes(
        ref.DeviceKeys(f"FAKE waiting pg {label}").ed25519_seed
    )
    return ref._raw(private.public_key())


def registered(factory, owner, label: str):  # noqa: ANN001, ANN201
    key = public_key(label)
    with factory() as session, session.begin():
        row, created = register(session, owner, waiting_key_id(key), key, now=AT)
        assert created
        return WaitingPrincipal(row.id, owner.device_id, row.key_id, "unused", NOW + 60)


def test_the_table_checks_its_ids_and_who_revoked(pg) -> None:  # noqa: F811
    _engine, factory = pg
    with factory() as session, session.begin():
        owner = add_owner(session, "pg-checks")
    key = public_key("checks")
    for bad in (
        {"key_id": "short"},
        {"public_key": b"\x01" * 31},
        {"revoked_by": "someone", "revoked_at": AT},
        {"revoked_by": "device"},
    ):
        with factory() as session, pytest.raises(IntegrityError), session.begin():
            session.add(
                PatientPortalMyCarlosWaitingKey(
                    **(
                        {
                            "key_id": waiting_key_id(key),
                            "public_key": key,
                            "account_id": owner.account_id,
                            "device_id": owner.device_id,
                            "created_at": AT,
                        }
                        | bad
                    )
                )
            )
    for allowed in ("device", "waiting_key", "device_removed", "staff", "unlink"):
        other = public_key(f"allowed-{allowed}")
        with factory() as session, session.begin():
            session.add(
                PatientPortalMyCarlosWaitingKey(
                    key_id=waiting_key_id(other),
                    public_key=other,
                    account_id=owner.account_id,
                    device_id=owner.device_id,
                    created_at=AT,
                    revoked_at=AT,
                    revoked_by=allowed,
                )
            )


def test_one_live_key_per_device_and_a_key_id_once(pg) -> None:  # noqa: F811
    _engine, factory = pg
    with factory() as session, session.begin():
        owner = add_owner(session, "pg-live")
    registered(factory, owner, "live-1")
    second = public_key("live-2")
    with factory() as session, pytest.raises(IntegrityError), session.begin():
        session.add(
            PatientPortalMyCarlosWaitingKey(
                key_id=waiting_key_id(second),
                public_key=second,
                account_id=owner.account_id,
                device_id=owner.device_id,
                created_at=AT,
            )
        )
    # Through the store a second key replaces the first, which stays revoked.
    with factory() as session, session.begin():
        register(session, owner, waiting_key_id(second), second, now=AT)
    with factory() as session:
        rows = list(
            session.scalars(
                select(PatientPortalMyCarlosWaitingKey)
                .where(PatientPortalMyCarlosWaitingKey.device_id == owner.device_id)
                .order_by(PatientPortalMyCarlosWaitingKey.id)
            )
        )
    assert [(row.revoked_by is None) for row in rows] == [False, True]


def test_registration_waits_for_whoever_holds_the_device(pg) -> None:  # noqa: F811
    engine, factory = pg
    with factory() as session, session.begin():
        owner = add_owner(session, "pg-serial")
    key = public_key("serial")
    holding, done = Event(), Event()
    request_pid: list[int] = []

    def hold() -> None:
        with factory() as session, session.begin():
            session.scalars(
                select(PatientPortalMyCarlosDevice)
                .where(PatientPortalMyCarlosDevice.id == owner.device_id)
                .with_for_update()
            ).one()
            holding.pid = session.scalar(text("select pg_backend_pid()"))  # type: ignore[attr-defined]
            holding.set()
            done.wait(5)

    def registering() -> bool:
        holding.wait(5)
        with factory() as session, session.begin():
            request_pid.append(session.scalar(text("select pg_backend_pid()")))
            _row, created = register(session, owner, waiting_key_id(key), key, now=AT)
            return created

    with ThreadPoolExecutor(2) as pool:
        held = pool.submit(hold)
        result = pool.submit(registering)
        holding.wait(5)
        observe_block(engine, holding.pid, request_pid, result)  # type: ignore[attr-defined]
        done.set()
        held.result(5)
        assert result.result(5) is True


def test_two_checks_at_once_get_one_answer_within_120_seconds(pg) -> None:  # noqa: F811
    engine, factory = pg
    with factory() as session, session.begin():
        owner = add_owner(session, "pg-spacing")
        add_copy(session, owner, 1)
    principal = registered(factory, owner, "spacing")
    first_answered, release = Event(), Event()
    request_pid: list[int] = []

    def first() -> bytes:
        with factory() as session, session.begin():
            content = answer(session, principal, now=AT)
            first_answered.pid = session.scalar(text("select pg_backend_pid()"))  # type: ignore[attr-defined]
            first_answered.set()
            release.wait(5)
            return content

    def second() -> str:
        first_answered.wait(5)
        with factory() as session, session.begin():
            request_pid.append(session.scalar(text("select pg_backend_pid()")))
            try:
                answer(session, principal, now=AT + timedelta(seconds=1))
            except TooSoon as exc:
                return f"too soon {exc.retry_after}"
            return "answered"

    with ThreadPoolExecutor(2) as pool:
        answered = pool.submit(first)
        later = pool.submit(second)
        first_answered.wait(5)
        observe_block(engine, first_answered.pid, request_pid, later)  # type: ignore[attr-defined]
        release.set()
        assert answered.result(5) == ANSWER_WAITING
        assert later.result(5) == "too soon 119"
    with factory() as session, session.begin():
        assert answer(session, principal, now=AT + timedelta(seconds=120)) == ANSWER_WAITING


def test_nothing_waits_once_the_copy_has_expired(pg) -> None:  # noqa: F811
    _engine, factory = pg
    with factory() as session, session.begin():
        owner = add_owner(session, "pg-expired")
        add_copy(session, owner, 1, expires_at=NOW - 1)
    principal = registered(factory, owner, "expired")
    with factory() as session, session.begin():
        assert answer(session, principal, now=AT) == ANSWER_NOTHING


def test_removing_a_device_tombstones_its_keys_and_subscriptions(pg) -> None:  # noqa: F811
    from carlos_patient_portal.models import PatientPortalMyCarlosAvailabilitySubscription
    from carlos_patient_portal.mycarlos_availability_store import enroll
    from carlos_patient_portal.mycarlos_devices import remove_device
    from tests.test_mycarlos_availability_store import consent

    _engine, factory = pg
    with factory() as session, session.begin():
        owner = add_owner(session, "pg-removed")
        enroll(session, owner, consent())
    registered(factory, owner, "removed")
    with factory() as session, session.begin():
        device_key_id = session.scalar(
            select(PatientPortalMyCarlosDevice.device_key_id).where(
                PatientPortalMyCarlosDevice.id == owner.device_id
            )
        )
        assert remove_device(
            session,
            account_id=owner.account_id,
            device_key_id=device_key_id,
            removed_by="patient",
            now=AT,
        )
    with factory() as session:
        keys = session.scalars(
            select(PatientPortalMyCarlosWaitingKey.revoked_by).where(
                PatientPortalMyCarlosWaitingKey.device_id == owner.device_id
            )
        ).all()
        subscriptions = session.scalars(
            select(PatientPortalMyCarlosAvailabilitySubscription.revoked_by).where(
                PatientPortalMyCarlosAvailabilitySubscription.device_id == owner.device_id
            )
        ).all()
    # 0024's CHECK takes the removal on PostgreSQL too.
    assert (keys, subscriptions) == (["device_removed"], ["device_removed"])
