# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Removing a device revokes its availability subscriptions (carlos-portal#87), and migration
0024, which lets them say so. FAKE data only."""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal.database import create_portal_engine
from carlos_patient_portal.models import (
    PatientPortalMyCarlosAvailabilitySubscription,
    PatientPortalMyCarlosDevice,
)
from carlos_patient_portal.mycarlos_availability import queue_new_copy
from carlos_patient_portal.mycarlos_availability_store import (
    EnrollmentRefusal,
    SqlAvailabilityTransaction,
    enroll,
    revoke,
)
from carlos_patient_portal.mycarlos_devices import remove_device
from tests.support import alembic_config_for_tests
from tests.test_mycarlos_availability_store import (  # noqa: F401
    NOW,
    SUBSCRIPTIONS,
    add_owner,
    consent,
    copy_ready,
    migrated,
    outbox_rows,
)

REVISION = "0024_avail_device_removed"
WAITING_KEYS = "0023_mycarlos_waiting_keys"
AT = datetime.fromtimestamp(NOW, tz=UTC)


def subscriptions(session: Session, device_id: int) -> list:  # noqa: ANN201 - rows
    return list(
        session.scalars(
            select(PatientPortalMyCarlosAvailabilitySubscription)
            .where(PatientPortalMyCarlosAvailabilitySubscription.device_id == device_id)
            .order_by(PatientPortalMyCarlosAvailabilitySubscription.id)
        )
    )


def removed(session: Session, owner, label: str, removed_by: str) -> None:  # noqa: ANN001
    device_key_id = session.scalar(
        select(PatientPortalMyCarlosDevice.device_key_id).where(
            PatientPortalMyCarlosDevice.id == owner.device_id
        )
    )
    assert device_key_id == (label * 43)[:43]
    assert remove_device(
        session,
        account_id=owner.account_id,
        device_key_id=device_key_id,
        removed_by=removed_by,
        now=AT,
    )


def test_the_revision_follows_the_waiting_keys_on_the_one_line_to_the_head() -> None:
    script = ScriptDirectory.from_config(alembic_config_for_tests())
    (head,) = script.get_heads()
    assert REVISION in {revision.revision for revision in script.iterate_revisions(head, "base")}
    assert script.get_revision(REVISION).down_revision == WAITING_KEYS
    assert len(REVISION) <= 32


@pytest.mark.parametrize(
    ("removed_by", "revoked_by"), [("patient", "device_removed"), ("staff", "staff")]
)
def test_removing_a_device_revokes_its_subscriptions_and_their_pending_notices(
    migrated,  # noqa: F811
    removed_by: str,
    revoked_by: str,
) -> None:
    engine, _config = migrated
    destination = uuid4()
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "gone")
        other = add_owner(session, "kept")
        live, _ = enroll(session, owner, consent(destination))
        given_up, _ = enroll(session, owner, consent())
        revoke(session, owner, given_up.subscription_id)
        theirs, _ = enroll(session, other, consent())
        transaction = SqlAvailabilityTransaction(session, clock=lambda: NOW)
        for each in (owner, other):
            queue_new_copy(transaction, copy_ready(each, 1), now=NOW, server_enabled=True)
        assert {row.subscription_id for row in outbox_rows(session)} == {
            live.subscription_id,
            theirs.subscription_id,
        }
        removed(session, owner, "gone", removed_by)
        rows = subscriptions(session, owner.device_id)
        # The live one is revoked by the removal; the one given up earlier keeps its own record.
        assert [(row.revoked_by, row.remote_enabled) for row in rows] == [
            (revoked_by, False),
            ("device", False),
        ]
        assert rows[0].revoked_at == AT
        # Its pending notice is gone; the other device's stays, with its subscription.
        assert [row.subscription_id for row in outbox_rows(session)] == [theirs.subscription_id]
        assert subscriptions(session, other.device_id)[0].revoked_at is None
    # The removed device's destination never enrolls again, here or on a new link.
    with Session(engine) as session, session.begin():
        relinked = add_owner(session, "relinked")
        with pytest.raises(EnrollmentRefusal) as refused:
            enroll(session, relinked, consent(destination))
        assert refused.value.code == "destination_revoked"


def test_removing_a_device_with_no_subscriptions_changes_nothing_else(
    migrated,  # noqa: F811
) -> None:
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "bare")
        removed(session, owner, "bare", "patient")
        assert subscriptions(session, owner.device_id) == []


@pytest.fixture
def at_waiting_keys(tmp_path: Path) -> Iterator[tuple[Engine, Config]]:
    """A SQLite database at 0023 on the portal's own engine: foreign keys on, and a real BEGIN
    for each transaction."""
    database_url = f"sqlite+pysqlite:///{tmp_path / 'removal.db'}"
    config = alembic_config_for_tests()
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, WAITING_KEYS)
    engine = create_portal_engine(database_url)
    try:
        yield engine, config
    finally:
        engine.dispose()


def migrate(engine: Engine, config: Config, step: str, revision: str) -> None:
    """Runs the step on one of the engine's own connections, foreign keys on."""
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        try:
            getattr(command, step)(config, revision)
        finally:
            config.attributes.pop("connection")


def test_the_sqlite_rebuild_keeps_rows_notices_and_autoincrement(at_waiting_keys) -> None:
    engine, config = at_waiting_keys
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "rebuilt")
        first, _ = enroll(session, owner, consent())
        second, _ = enroll(session, owner, consent())
        enrolled = [first.subscription_id, second.subscription_id]
        highest = second.id
        transaction = SqlAvailabilityTransaction(session, clock=lambda: NOW)
        queue_new_copy(transaction, copy_ready(owner, 1), now=NOW, server_enabled=True)
        assert len(outbox_rows(session)) == 2
        # Before 0024 the removal value is refused.
        with pytest.raises(IntegrityError), session.begin_nested():
            session.execute(
                text(
                    f"update {SUBSCRIPTIONS} set revoked_by = 'device_removed', "  # noqa: S608
                    "revoked_at = '2026-11-06 12:00:00', remote_enabled = 0 where id = :id"
                ),
                {"id": highest},
            )
    migrate(engine, config, "upgrade", "head")
    with engine.connect() as connection:
        table_sql = connection.scalar(
            text("select sql from sqlite_master where type = 'table' and name = :name"),
            {"name": SUBSCRIPTIONS},
        )
        assert "AUTOINCREMENT" in table_sql.upper()
        assert list(connection.execute(text("pragma foreign_key_check"))) == []
    with Session(engine) as session, session.begin():
        assert [row.subscription_id for row in subscriptions(session, owner.device_id)] == enrolled
        assert len(outbox_rows(session)) == 2
        removed(session, owner, "rebuilt", "patient")
        assert {row.revoked_by for row in subscriptions(session, owner.device_id)} == {
            "device_removed"
        }
        assert outbox_rows(session) == []
        # A row id is never used twice, even after the highest one is gone.
        later = add_owner(session, "later")
        newest, _ = enroll(session, later, consent())
        assert newest.id > highest


def test_the_downgrade_is_refused_while_a_removal_tombstone_exists(at_waiting_keys) -> None:
    engine, config = at_waiting_keys
    migrate(engine, config, "upgrade", "head")
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "tombstoned")
        enroll(session, owner, consent())
        removed(session, owner, "tombstoned", "patient")
    with pytest.raises(RuntimeError, match="revoked by a device removal exist"):
        migrate(engine, config, "downgrade", WAITING_KEYS)
    # Recorded another way, the older CHECK can hold it again.
    with engine.begin() as connection:
        connection.execute(
            text(f"update {SUBSCRIPTIONS} set revoked_by = 'staff'")  # noqa: S608
        )
    migrate(engine, config, "downgrade", WAITING_KEYS)
    with Session(engine) as session, session.begin():
        row = session.scalars(select(PatientPortalMyCarlosAvailabilitySubscription)).one()
        with pytest.raises(IntegrityError), session.begin_nested():
            row.revoked_by = "device_removed"
            session.flush()
