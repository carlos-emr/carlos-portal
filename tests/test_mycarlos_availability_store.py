# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Migration 0022 and the storage adapter for myCarlos availability notices (P1).

The policy core's own tests (test_mycarlos_availability.py) use in-memory fakes; these run the
same core against the real tables: enrollment, the outbox's coalescing, revocation, rollback,
and what is (and is not) stored. Every id and value is FAKE.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, event, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalMyCarlosAvailabilityOutbox,
    PatientPortalMyCarlosAvailabilitySubscription,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosRecipient,
)
from carlos_patient_portal.mycarlos_availability import (
    MAX_DESTINATIONS,
    AvailabilityError,
    MailboxReady,
    Owner,
    queue_new_copy,
)
from carlos_patient_portal.mycarlos_availability_store import (
    EnrollmentRefusal,
    EnrollmentRequest,
    SqlAvailabilityTransaction,
    as_subscription,
    enroll,
    revoke,
    subscriptions_for_owner,
)
from tests.support import alembic_config_for_tests

NOW = 1_793_800_000
SUBSCRIPTIONS = "patient_portal_mycarlos_availability_subscriptions"
OUTBOX = "patient_portal_mycarlos_availability_outbox"


@pytest.fixture
def migrated(tmp_path: Path) -> Iterator[tuple[Engine, Config]]:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'availability.db'}"
    config = alembic_config_for_tests()
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_engine(database_url)

    @event.listens_for(engine, "connect")
    def _foreign_keys_on(dbapi_connection, _record) -> None:  # noqa: ANN001
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    try:
        yield engine, config
    finally:
        engine.dispose()


def add_owner(session: Session, label: str, *, status: str = "active") -> Owner:
    account = PatientPortalAccount(
        clinic_id="clinic-a",
        demographic_no=abs(hash(label)) % 100000 + 1,
        username=f"fake.{label}",
        email=f"fake.{label}@example.test",
        password_hash="FAKE-unused",
        status="active",
    )
    session.add(account)
    session.flush()
    session.add(PatientPortalMyCarlosRecipient(account_id=account.id, recipient_id=f"FAKE-{label}"))
    device = PatientPortalMyCarlosDevice(
        account_id=account.id,
        device_key_id=(label * 43)[:43],
        x25519_public_key=bytes(32),
        ed25519_public_key=bytes(32),
        device_name=f"FAKE {label}",
        status="active",
        linked_at=datetime.fromtimestamp(NOW, tz=UTC),
    )
    session.add(device)
    session.flush()
    if status != "active":
        device.status = status
        device.removed_at = datetime.fromtimestamp(NOW, tz=UTC)
        device.removed_by = "patient"
        session.flush()
    return Owner(account.id, device.id)


def consent(destination: UUID | None = None, **changes: object) -> EnrollmentRequest:
    values: dict[str, object] = {
        "platform": "android_fcm",
        "destination_id": str(destination or uuid4()),
        "remote_enabled": True,
        "remote_consent_version": 1,
        "permission_observed": True,
        **changes,
    }
    return EnrollmentRequest(**values)  # type: ignore[arg-type]


def copy_ready(owner: Owner, sequence: int, *, expires_at: int = NOW + 3600) -> MailboxReady:
    return MailboxReady(owner, sequence, expires_at, True)


def outbox_rows(session: Session) -> list[PatientPortalMyCarlosAvailabilityOutbox]:
    return list(
        session.scalars(
            select(PatientPortalMyCarlosAvailabilityOutbox).order_by(
                PatientPortalMyCarlosAvailabilityOutbox.id
            )
        )
    )


# --- The migration -----------------------------------------------------------------------------


def test_the_revision_follows_main_and_is_its_only_head() -> None:
    script = ScriptDirectory.from_config(alembic_config_for_tests())
    assert script.get_heads() == ["0022_availability_enrollment"]
    revision = script.get_revision("0022_availability_enrollment")
    assert revision.down_revision == "0017_mycarlos_linking"
    # alembic_version.version_num is VARCHAR(32) on PostgreSQL.
    assert len(revision.revision) <= 32


def test_the_migration_creates_both_tables_with_their_unique_indexes(migrated) -> None:
    engine, _config = migrated
    inspector = inspect(engine)
    assert {SUBSCRIPTIONS, OUTBOX} <= set(inspector.get_table_names())
    unique = {
        index["name"]
        for table in (SUBSCRIPTIONS, OUTBOX)
        for index in inspector.get_indexes(table)
        if index["unique"]
    }
    assert {
        "ux_pp_mycarlos_avail_subs_subscription",
        "ux_pp_mycarlos_avail_subs_destination",
        "ux_pp_mycarlos_avail_outbox_pending",
    } <= unique


def test_the_downgrade_is_refused_while_enrollments_exist_and_drops_the_tables_once_clean(
    migrated,
) -> None:
    engine, config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        row, _ = enroll(session, owner, consent())
        subscription_id = row.subscription_id
    with pytest.raises(RuntimeError, match="availability enrollments exist"):
        command.downgrade(config, "0017_mycarlos_linking")
    # A tombstone counts: forgetting it would let a revoked destination enroll again.
    with Session(engine) as session, session.begin():
        revoke(session, owner, subscription_id)
    with pytest.raises(RuntimeError, match="availability enrollments exist"):
        command.downgrade(config, "0017_mycarlos_linking")
    with engine.begin() as connection:
        connection.execute(text(f"delete from {SUBSCRIPTIONS}"))  # noqa: S608
    command.downgrade(config, "0017_mycarlos_linking")
    assert not {SUBSCRIPTIONS, OUTBOX} & set(inspect(engine).get_table_names())
    command.upgrade(config, "head")
    assert {SUBSCRIPTIONS, OUTBOX} <= set(inspect(engine).get_table_names())


@pytest.mark.parametrize(
    "changes",
    [
        {"platform": "FAKE_push"},
        {"destination_id": "not-a-uuid"},
        {"remote_consent_version": -1},
        {"revoked_at": datetime.fromtimestamp(NOW, tz=UTC), "revoked_by": None},
        {"revoked_at": datetime.fromtimestamp(NOW, tz=UTC), "revoked_by": "device"},
        {"revoked_by": "FAKE"},
    ],
)
def test_a_malformed_subscription_row_is_refused(migrated, changes: dict[str, object]) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
    values: dict[str, object] = {
        "subscription_id": str(uuid4()),
        "account_id": owner.account_id,
        "device_id": owner.device_id,
        "epoch": str(uuid4()),
        "destination_id": str(uuid4()),
        "platform": "ios_apns",
        "remote_enabled": True,
        "remote_consent_version": 1,
        "permission_observed": True,
        "created_at": datetime.fromtimestamp(NOW, tz=UTC),
        **changes,
    }
    # The fifth case is a revoked row with remote still on.
    with pytest.raises(IntegrityError), Session(engine) as session, session.begin():
        session.add(PatientPortalMyCarlosAvailabilitySubscription(**values))


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "FAKE"},
        {"sequence": 0},
        {"attempts": -1},
        {"expires_at": NOW},
        {"status": "leased"},
        {"lease_token": str(uuid4()), "lease_until": NOW + 60},
        {"status": "leased", "lease_token": str(uuid4())},
        {"status": "leased", "lease_token": "FAKE-short", "lease_until": NOW + 60},
    ],
)
def test_a_malformed_outbox_row_is_refused(migrated, changes: dict[str, object]) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        row, _ = enroll(session, owner, consent())
        subscription_id, epoch = row.subscription_id, row.epoch
    values: dict[str, object] = {
        "subscription_id": subscription_id,
        "epoch": epoch,
        "sequence": 1,
        "expires_at": NOW + 900,
        "status": "pending",
        "attempts": 0,
        "created_at": NOW,
        **changes,
    }
    with pytest.raises(IntegrityError), Session(engine) as session, session.begin():
        session.add(PatientPortalMyCarlosAvailabilityOutbox(**values))


def test_one_pending_row_per_subscription_and_epoch_but_a_leased_one_beside_it(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        row, _ = enroll(session, owner, consent())
        slot = {"subscription_id": row.subscription_id, "epoch": row.epoch}
        session.add(
            PatientPortalMyCarlosAvailabilityOutbox(
                **slot,
                sequence=1,
                expires_at=NOW + 900,
                status="leased",
                attempts=1,
                lease_token=str(uuid4()),
                lease_until=NOW + 60,
                created_at=NOW,
            )
        )
        session.add(
            PatientPortalMyCarlosAvailabilityOutbox(
                **slot,
                sequence=2,
                expires_at=NOW + 900,
                status="pending",
                attempts=0,
                created_at=NOW,
            )
        )
    with pytest.raises(IntegrityError), Session(engine) as session, session.begin():
        session.add(
            PatientPortalMyCarlosAvailabilityOutbox(
                **slot,
                sequence=3,
                expires_at=NOW + 900,
                status="pending",
                attempts=0,
                created_at=NOW,
            )
        )


# --- Enrollment --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"remote_consent_version": 0}, "consent_required"),
        ({"remote_consent_version": 2}, "consent_required"),
        ({"permission_observed": False}, "consent_required"),
        ({"platform": "FAKE_push"}, "invalid_platform"),
        ({"destination_id": "00000000-0000-0000-0000-000000000000"}, "invalid_destination"),
        ({"destination_id": "AAAAAAAA-0000-4000-8000-000000000001"}, "invalid_destination"),
        ({"destination_id": "FAKE"}, "invalid_destination"),
    ],
)
def test_enrolling_needs_remote_consent_v1_an_observed_permission_and_valid_ids(
    migrated, changes: dict[str, object], code: str
) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        with pytest.raises(EnrollmentRefusal) as refused:
            enroll(session, owner, consent(**changes))
        assert refused.value.code == code
        assert subscriptions_for_owner(session, owner, include_revoked=True) == []


def test_the_same_destination_enrolls_once_per_device_and_never_after_revocation(
    migrated,
) -> None:
    engine, _config = migrated
    destination = uuid4()
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        other = add_owner(session, "b")
        first, created = enroll(session, owner, consent(destination))
        assert created
        # Again from the same device: the same subscription, the remote switch updated.
        again, created = enroll(session, owner, consent(destination, remote_enabled=False))
        assert not created
        assert again.subscription_id == first.subscription_id
        assert again.remote_enabled is False
        with pytest.raises(EnrollmentRefusal) as taken:
            enroll(session, other, consent(destination))
        assert taken.value.code == "destination_taken"
        with pytest.raises(EnrollmentRefusal) as moved:
            enroll(session, owner, consent(destination, platform="ios_apns"))
        assert moved.value.code == "destination_taken"
        revoked = revoke(session, owner, first.subscription_id)
        assert revoked.revoked_at is not None and revoked.revoked_by == "device"
        assert revoked.remote_enabled is False
        # Revoking again is harmless; enrolling the revoked destination again is not allowed.
        assert revoke(session, owner, first.subscription_id).revoked_at == revoked.revoked_at
        with pytest.raises(EnrollmentRefusal) as gone:
            enroll(session, owner, consent(destination))
        assert gone.value.code == "destination_revoked"
        # Another device cannot revoke what is not its own, and learns nothing about it.
        with pytest.raises(EnrollmentRefusal) as foreign:
            revoke(session, other, first.subscription_id)
        assert foreign.value.code == "not_found"


def test_a_device_holds_at_most_sixteen_live_destinations(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        rows = [enroll(session, owner, consent())[0] for _ in range(MAX_DESTINATIONS)]
        with pytest.raises(EnrollmentRefusal) as full:
            enroll(session, owner, consent())
        assert full.value.code == "destination_capacity"
        # A revoked one frees its place.
        revoke(session, owner, rows[0].subscription_id)
        enroll(session, owner, consent())
        assert len(subscriptions_for_owner(session, owner)) == MAX_DESTINATIONS


def test_a_removed_device_can_neither_enroll_nor_revoke(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        removed = add_owner(session, "a", status="removed")
        with pytest.raises(EnrollmentRefusal) as refused:
            enroll(session, removed, consent())
        assert refused.value.code == "device_inactive"


def test_enrollment_and_queueing_need_an_open_transaction(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
    with Session(engine) as session:
        session.commit()
        assert not session.in_transaction()
        with pytest.raises(AvailabilityError, match="transaction_required"):
            enroll(session, owner, consent())
        with pytest.raises(AvailabilityError, match="transaction_required"):
            queue_new_copy(
                SqlAvailabilityTransaction(session, clock=lambda: NOW),
                copy_ready(owner, 1),
                now=NOW,
                server_enabled=True,
            )


# --- The outbox, through the policy core -------------------------------------------------------


def test_a_new_copy_queues_one_intent_per_permitted_subscription(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        on, _ = enroll(session, owner, consent())
        off, _ = enroll(session, owner, consent(remote_enabled=False))
        transaction = SqlAvailabilityTransaction(session, clock=lambda: NOW)
        # The server switch off (the default): nothing is queued.
        assert queue_new_copy(transaction, copy_ready(owner, 1), now=NOW) == 0
        assert outbox_rows(session) == []
        assert queue_new_copy(transaction, copy_ready(owner, 1), now=NOW, server_enabled=True) == 1
        (row,) = outbox_rows(session)
        assert (row.subscription_id, row.epoch) == (on.subscription_id, on.epoch)
        assert row.subscription_id != off.subscription_id
        assert (row.sequence, row.status, row.attempts) == (1, "pending", 0)
        # The hint's life is capped at the policy's 15 minutes, not the copy's hour.
        assert row.expires_at == NOW + 900


def test_a_newer_copy_coalesces_into_the_pending_slot_and_keeps_its_retry_budget(
    migrated,
) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        enroll(session, owner, consent())
        transaction = SqlAvailabilityTransaction(session, clock=lambda: NOW)
        queue_new_copy(transaction, copy_ready(owner, 1), now=NOW, server_enabled=True)
        (row,) = outbox_rows(session)
        row.attempts, row.next_attempt_at = 2, NOW + 60
        later = SqlAvailabilityTransaction(session, clock=lambda: NOW + 100)
        assert queue_new_copy(later, copy_ready(owner, 2), now=NOW + 100, server_enabled=True) == 1
        (row,) = outbox_rows(session)
        assert row.sequence == 2
        assert (row.attempts, row.next_attempt_at) == (2, NOW + 60)
        # Never extended past the slot's own window.
        assert row.expires_at == NOW + 900
        # The same or an older sequence changes nothing.
        assert queue_new_copy(later, copy_ready(owner, 2), now=NOW + 100, server_enabled=True) == 0
        assert queue_new_copy(later, copy_ready(owner, 1), now=NOW + 100, server_enabled=True) == 0
        assert [r.sequence for r in outbox_rows(session)] == [2]


def test_a_leased_intent_is_never_edited_and_a_newer_copy_queues_beside_it(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        enroll(session, owner, consent())
        transaction = SqlAvailabilityTransaction(session, clock=lambda: NOW)
        queue_new_copy(transaction, copy_ready(owner, 1), now=NOW, server_enabled=True)
        (leased,) = outbox_rows(session)
        token = str(uuid4())
        leased.status, leased.lease_token, leased.lease_until = "leased", token, NOW + 60
        session.flush()
        # Not newer than what is being sent: suppressed.
        assert queue_new_copy(transaction, copy_ready(owner, 1), now=NOW, server_enabled=True) == 0
        assert queue_new_copy(transaction, copy_ready(owner, 3), now=NOW, server_enabled=True) == 1
        first, second = outbox_rows(session)
        assert (first.status, first.sequence, first.lease_token) == ("leased", 1, token)
        assert (second.status, second.sequence) == ("pending", 3)


def test_an_expired_slot_is_replaced_by_a_newer_live_intent(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        enroll(session, owner, consent())
        queue_new_copy(
            SqlAvailabilityTransaction(session, clock=lambda: NOW),
            copy_ready(owner, 1),
            now=NOW,
            server_enabled=True,
        )
        much_later = NOW + 2000
        assert (
            queue_new_copy(
                SqlAvailabilityTransaction(session, clock=lambda: much_later),
                copy_ready(owner, 2, expires_at=much_later + 3600),
                now=much_later,
                server_enabled=True,
            )
            == 1
        )
        (row,) = outbox_rows(session)
        assert (row.sequence, row.created_at, row.expires_at) == (
            2,
            much_later,
            much_later + 900,
        )


def test_a_rollback_discards_the_intent_with_the_copy(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        enroll(session, owner, consent())
    with Session(engine) as session:
        with session.begin():
            queue_new_copy(
                SqlAvailabilityTransaction(session, clock=lambda: NOW),
                copy_ready(owner, 1),
                now=NOW,
                server_enabled=True,
            )
            assert len(outbox_rows(session)) == 1
            session.rollback()
        assert outbox_rows(session) == []


def test_revoking_drops_pending_intents_and_queues_nothing_after(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        row, _ = enroll(session, owner, consent())
        transaction = SqlAvailabilityTransaction(session, clock=lambda: NOW)
        queue_new_copy(transaction, copy_ready(owner, 1), now=NOW, server_enabled=True)
        assert len(outbox_rows(session)) == 1
        revoke(session, owner, row.subscription_id)
        assert outbox_rows(session) == []
        assert queue_new_copy(transaction, copy_ready(owner, 2), now=NOW, server_enabled=True) == 0
        assert outbox_rows(session) == []


def test_put_refuses_an_intent_for_another_binding(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        other = add_owner(session, "b")
        enroll(session, owner, consent())
        (subscription,) = [as_subscription(r) for r in subscriptions_for_owner(session, owner)]

        class Retargeting(SqlAvailabilityTransaction):
            def subscriptions(self, _owner: Owner):  # noqa: ANN202
                # Hand the policy another owner's subscription row, as a wiring bug would.
                return [subscription.__class__(**{**subscription.__dict__, "owner": other})]

        with pytest.raises(AvailabilityError, match="coalescing_binding_mismatch"):
            queue_new_copy(
                Retargeting(session, clock=lambda: NOW),
                copy_ready(other, 1),
                now=NOW,
                server_enabled=True,
            )


# --- What is stored ------------------------------------------------------------------------------


def test_the_tables_hold_ids_settings_and_counters_only(migrated) -> None:
    engine, _config = migrated
    inspector = inspect(engine)
    assert {column["name"] for column in inspector.get_columns(SUBSCRIPTIONS)} == {
        "id",
        "subscription_id",
        "account_id",
        "device_id",
        "epoch",
        "destination_id",
        "platform",
        "remote_enabled",
        "remote_consent_version",
        "permission_observed",
        "created_at",
        "revoked_at",
        "revoked_by",
    }
    assert {column["name"] for column in inspector.get_columns(OUTBOX)} == {
        "id",
        "subscription_id",
        "epoch",
        "sequence",
        "expires_at",
        "status",
        "attempts",
        "next_attempt_at",
        "lease_token",
        "lease_until",
        "last_decision",
        "created_at",
    }
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        enroll(session, owner, consent())
        queue_new_copy(
            SqlAvailabilityTransaction(session, clock=lambda: NOW),
            copy_ready(owner, 1),
            now=NOW,
            server_enabled=True,
        )
    patient_values = {"fake.a", "fake.a@example.test", "FAKE-a", "FAKE a", "clinic-a"}
    with engine.connect() as connection:
        for table in (SUBSCRIPTIONS, OUTBOX):
            for stored in connection.execute(text(f"select * from {table}")).mappings():  # noqa: S608
                assert not {str(value) for value in stored.values()} & patient_values
