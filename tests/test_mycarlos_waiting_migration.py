"""Migration 0023 (carlos-portal#87): the waiting keys table, on the one line to the head."""

from datetime import UTC, datetime

from alembic import command
from alembic.script import ScriptDirectory
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from carlos_patient_portal.mycarlos_waiting import (
    WaitingPrincipal,
    register,
    revoke_self,
    waiting_key_id,
)
from tests import delivery_contract_reference as ref
from tests.support import alembic_config_for_tests
from tests.test_mycarlos_availability_dispatch import NOW
from tests.test_mycarlos_availability_store import (  # noqa: F401
    add_owner,
    migrated,
)

REVISION = "0023_mycarlos_waiting_keys"
ENROLLMENT = "0022_availability_enrollment"
KEYS = "patient_portal_mycarlos_waiting_keys"
AT = datetime.fromtimestamp(NOW, tz=UTC)


def public_key(label: str) -> bytes:
    private = Ed25519PrivateKey.from_private_bytes(
        ref.DeviceKeys(f"FAKE waiting migration {label}").ed25519_seed
    )
    return ref._raw(private.public_key())


def test_the_revision_follows_enrollment_on_the_one_line_to_the_head() -> None:
    script = ScriptDirectory.from_config(alembic_config_for_tests())
    (head,) = script.get_heads()
    assert REVISION in {revision.revision for revision in script.iterate_revisions(head, "base")}
    assert script.get_revision(REVISION).down_revision == ENROLLMENT
    # alembic_version.version_num is VARCHAR(32) on PostgreSQL.
    assert len(REVISION) <= 32


def test_the_downgrade_is_refused_while_keys_exist_even_revoked_ones(migrated) -> None:  # noqa: F811
    engine, config = migrated
    key = public_key("migration")
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "waiting-migration")
        row, _ = register(session, owner, waiting_key_id(key), key, now=AT)
        principal = WaitingPrincipal(row.id, owner.device_id, row.key_id, "unused", 0)
    assert KEYS in set(inspect(engine).get_table_names())
    try:
        command.downgrade(config, ENROLLMENT)
    except RuntimeError as exc:
        assert "waiting keys exist" in str(exc)
    else:
        raise AssertionError("the downgrade forgot a live waiting key")
    # A tombstone counts: forgetting it would let a revoked key come back.
    with Session(engine) as session, session.begin():
        revoke_self(session, principal, now=AT)
    try:
        command.downgrade(config, ENROLLMENT)
    except RuntimeError as exc:
        assert "waiting keys exist" in str(exc)
    else:
        raise AssertionError("the downgrade forgot a revoked waiting key")
    with engine.begin() as connection:
        connection.execute(text(f"delete from {KEYS}"))  # noqa: S608
    command.downgrade(config, ENROLLMENT)
    assert KEYS not in set(inspect(engine).get_table_names())
    command.upgrade(config, "head")
    assert KEYS in set(inspect(engine).get_table_names())
