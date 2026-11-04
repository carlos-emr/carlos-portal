# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Affero General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

"""The myCarlos linking tables (carlos-portal#41, M2-a): what the database itself refuses."""

from collections.abc import Callable, Iterator
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal.config import Settings
from carlos_patient_portal.models import (
    AUDIT_EVENT_MYCARLOS_CLINIC_KEYS_PUBLISH,
    AUDIT_EVENT_MYCARLOS_DEVICE_LIST,
    AUDIT_EVENT_MYCARLOS_DEVICE_REMOVE,
    AUDIT_EVENT_MYCARLOS_LINK,
    AUDIT_EVENT_MYCARLOS_LINK_CODE_CREATE,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalClinicKey,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosLinkCode,
    PatientPortalMyCarlosLinkFailure,
    PatientPortalMyCarlosRecipient,
    PatientPortalSession,
    utc_now,
)
from tests.support import alembic_config_for_tests

MYCARLOS_TABLES = {
    "patient_portal_clinic_keys",
    "patient_portal_mycarlos_devices",
    "patient_portal_mycarlos_link_codes",
    "patient_portal_mycarlos_link_failures",
    "patient_portal_mycarlos_recipients",
}
MYCARLOS_EVENT_TYPES = (
    AUDIT_EVENT_MYCARLOS_CLINIC_KEYS_PUBLISH,
    AUDIT_EVENT_MYCARLOS_DEVICE_LIST,
    AUDIT_EVENT_MYCARLOS_DEVICE_REMOVE,
    AUDIT_EVENT_MYCARLOS_LINK,
    AUDIT_EVENT_MYCARLOS_LINK_CODE_CREATE,
)


def fake_key_id(label: str) -> str:
    """A 43-character b64url-shaped ID derived from a FAKE label (no literal key material)."""
    return sha256(label.encode()).hexdigest()[:43]


def fake_key_bytes(label: str) -> bytes:
    return sha256(label.encode()).digest()


@pytest.fixture
def migrated(tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[tuple[Engine, Config]]:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'mycarlos.db'}"
    config = alembic_config_for_tests()
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, getattr(request, "param", "head"))
    engine = create_engine(database_url)

    @event.listens_for(engine, "connect")
    def _foreign_keys_on(dbapi_connection, _record) -> None:  # noqa: ANN001
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    try:
        yield engine, config
    finally:
        engine.dispose()


def add_account(session: Session, demographic_no: int) -> PatientPortalAccount:
    account = PatientPortalAccount(
        clinic_id="default",
        demographic_no=demographic_no,
        username=f"fake.patient{demographic_no}",
        email=f"fake{demographic_no}@example.test",
        password_hash="FAKE-not-a-real-hash",
        status="active",
    )
    session.add(account)
    session.flush()
    return account


def add_session(session: Session, account: PatientPortalAccount) -> PatientPortalSession:
    now = utc_now()
    portal_session = PatientPortalSession(
        account_id=account.id,
        token_hash=sha256(f"FAKE session {account.id} {now}".encode()).hexdigest(),
        created_at=now,
        expires_at=now + timedelta(hours=1),
    )
    session.add(portal_session)
    session.flush()
    return portal_session


def device(
    account: PatientPortalAccount, label: str, **changes: object
) -> PatientPortalMyCarlosDevice:
    values: dict[str, object] = {
        "account_id": account.id,
        "device_key_id": fake_key_id(label),
        "x25519_public_key": fake_key_bytes(f"{label} x25519"),
        "ed25519_public_key": fake_key_bytes(f"{label} ed25519"),
        "device_name": "myCarlos on Linux",
        "status": "active",
        "linked_at": utc_now(),
    }
    values.update(changes)
    return PatientPortalMyCarlosDevice(**values)


def link_code(
    account: PatientPortalAccount,
    portal_session: PatientPortalSession,
    link_id: str,
    **changes: object,
) -> PatientPortalMyCarlosLinkCode:
    now = utc_now()
    values: dict[str, object] = {
        "account_id": account.id,
        "session_id": portal_session.id,
        "link_id": link_id,
        "code_hash": sha256(f"FAKE code for {link_id}".encode()).hexdigest(),
        "status": "pending",
        "wrong_codes": 0,
        "created_at": now,
        "expires_at": now + timedelta(minutes=10),
    }
    values.update(changes)
    return PatientPortalMyCarlosLinkCode(**values)


def clinic_key(label: str, **changes: object) -> PatientPortalClinicKey:
    values: dict[str, object] = {
        "kid": fake_key_id(label),
        "clinic_id": "default",
        "spki": fake_key_bytes(label) * 3,
        "status": "active",
        "published_at": utc_now(),
    }
    values.update(changes)
    return PatientPortalClinicKey(**values)


def assert_refused(engine: Engine, build: Callable[[Session], object]) -> None:
    with Session(engine) as session:
        build(session)
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()


def test_the_migration_creates_the_tables_and_matches_the_models(migrated) -> None:
    engine, _config = migrated
    assert MYCARLOS_TABLES <= set(inspect(engine).get_table_names())
    # Ending a session deletes its links, so that lookup must not scan the whole table.
    link_code_indexes = {
        tuple(index["column_names"])
        for index in inspect(engine).get_indexes("patient_portal_mycarlos_link_codes")
    }
    assert ("session_id",) in link_code_indexes


def test_a_device_key_can_be_linked_only_once_across_all_accounts(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session:
        first = add_account(session, 1001)
        second = add_account(session, 1002)
        session.add(device(first, "FAKE device one"))
        session.commit()
        session.add(device(second, "FAKE device one", device_name="myCarlos on Windows"))
        with pytest.raises(IntegrityError):
            session.flush()


@pytest.mark.parametrize(
    "changes",
    [
        {"device_key_id": "too-short"},
        {"x25519_public_key": b"\x00" * 31},
        {"ed25519_public_key": b"\x00" * 33},
        {"device_name": ""},
        {"device_name": "n" * 65},
        {"status": "pending"},
        # A removed device names who removed it and when; an active one names neither.
        {"status": "removed"},
        {"status": "removed", "removed_at": utc_now()},
        {"removed_at": utc_now(), "removed_by": "patient"},
        {"status": "removed", "removed_at": utc_now(), "removed_by": "someone"},
        {"vault_head_link": "a" * 63, "vault_head_link_at": utc_now()},
        {"vault_head_link": "a" * 64},
    ],
)
def test_a_malformed_device_row_is_refused(migrated, changes: dict[str, object]) -> None:
    engine, _config = migrated
    with Session(engine) as session:
        account = add_account(session, 1101)
        session.commit()
        account_id = account.id

    def build(session: Session) -> None:
        owner = session.get(PatientPortalAccount, account_id)
        session.add(device(owner, "FAKE malformed device", **changes))

    assert_refused(engine, build)


def test_a_removed_device_with_who_and_when_is_stored(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session:
        account = add_account(session, 1201)
        session.add(
            device(
                account,
                "FAKE removed device",
                status="removed",
                removed_at=utc_now(),
                removed_by="staff",
                vault_head_link="b" * 64,
                vault_head_link_at=utc_now(),
            )
        )
        session.commit()


@pytest.mark.parametrize(
    "changes",
    [
        {"link_id": "SHORT"},
        {"code_hash": "0" * 63},
        {"status": "expired"},
        {"status": "ended"},
        {"wrong_codes": 6},
        {"wrong_codes": -1},
        # A used link names its device and when; no other link does.
        {"status": "used"},
        {"used_at": utc_now()},
    ],
)
def test_a_malformed_link_code_row_is_refused(migrated, changes: dict[str, object]) -> None:
    engine, _config = migrated
    with Session(engine) as session:
        account = add_account(session, 1301)
        portal_session = add_session(session, account)
        session.commit()
        ids = (account.id, portal_session.id)

    def build(session: Session) -> None:
        owner = session.get(PatientPortalAccount, ids[0])
        signed_in = session.get(PatientPortalSession, ids[1])
        fields = dict(changes)
        session.add(link_code(owner, signed_in, str(fields.pop("link_id", "FAKE1301")), **fields))

    assert_refused(engine, build)


def test_a_link_id_names_one_link_and_ending_the_session_deletes_its_links(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session:
        account = add_account(session, 1401)
        portal_session = add_session(session, account)
        linked = device(account, "FAKE linked device")
        session.add(linked)
        session.flush()
        session.add(
            link_code(
                account,
                portal_session,
                "FAKE1401",
                status="used",
                used_at=utc_now(),
                device_id=linked.id,
            )
        )
        session.add(link_code(account, portal_session, "FAKE1402", status="replaced"))
        session.commit()
        # Unique over every link, not just pending ones.
        session.add(link_code(account, portal_session, "FAKE1402"))
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()

        session.delete(session.get(PatientPortalSession, portal_session.id))
        session.commit()
    with engine.connect() as connection:
        remaining = connection.scalar(
            text("select count(*) from patient_portal_mycarlos_link_codes")
        )
    assert remaining == 0


def test_wrong_codes_outlive_their_link(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session:
        account = add_account(session, 1501)
        portal_session = add_session(session, account)
        session.add(link_code(account, portal_session, "FAKE1501", wrong_codes=1))
        session.add(
            PatientPortalMyCarlosLinkFailure(
                account_id=account.id,
                link_id="FAKE1501",
                failed_at=utc_now(),
            )
        )
        session.commit()
        session.delete(session.get(PatientPortalSession, portal_session.id))
        session.commit()
    with engine.connect() as connection:
        failures = connection.scalar(
            text("select count(*) from patient_portal_mycarlos_link_failures")
        )
    assert failures == 1


def test_recipient_ids_are_one_per_account_and_unique(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session:
        first = add_account(session, 1601)
        second = add_account(session, 1602)
        session.add(
            PatientPortalMyCarlosRecipient(account_id=first.id, recipient_id="rcp-FAKE1601")
        )
        session.commit()
        session.add(
            PatientPortalMyCarlosRecipient(account_id=second.id, recipient_id="rcp-FAKE1601")
        )
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()
        session.add(
            PatientPortalMyCarlosRecipient(account_id=first.id, recipient_id="rcp-FAKE1601-other")
        )
        with pytest.raises(IntegrityError):
            session.flush()


@pytest.mark.parametrize(
    "changes",
    [
        {"kid": "too-short"},
        {"spki": b""},
        {"spki": b"\x00" * 513},
        # myCarlos refuses every key that isn't active, so there is no third status.
        {"status": "retired"},
        {"status": "revoked"},
        {"revoked_at": utc_now()},
        {"replaces_kid": fake_key_id("FAKE old clinic key")},
        {"replacement_signature": b"\x01" * 64},
        {"replaces_kid": "short", "replacement_signature": b"\x01" * 64},
    ],
)
def test_a_malformed_clinic_key_row_is_refused(migrated, changes: dict[str, object]) -> None:
    engine, _config = migrated
    assert_refused(engine, lambda session: session.add(clinic_key("FAKE clinic key", **changes)))


def test_a_replacement_and_a_revoked_clinic_key_are_stored(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session:
        old = clinic_key("FAKE old clinic key", status="revoked", revoked_at=utc_now())
        session.add(old)
        session.add(
            clinic_key(
                "FAKE new clinic key",
                replaces_kid=old.kid,
                replacement_signature=b"\x01" * 64,
            )
        )
        session.commit()


def test_the_mycarlos_audit_types_are_accepted_and_others_are_not(migrated) -> None:
    engine, _config = migrated
    with Session(engine) as session:
        for event_type in MYCARLOS_EVENT_TYPES:
            session.add(
                PatientPortalAuditEvent(
                    event_type=event_type,
                    outcome="success",
                    actor_type="system",
                    created_at=utc_now(),
                )
            )
        session.commit()
    assert_refused(
        engine,
        lambda session: session.add(
            PatientPortalAuditEvent(
                event_type="mycarlos.made_up",
                outcome="success",
                actor_type="system",
                created_at=utc_now(),
            )
        ),
    )


@pytest.mark.parametrize("migrated", ["0017_mycarlos_linking"], indirect=True)
def test_the_downgrade_is_refused_while_mycarlos_rows_exist(migrated) -> None:
    engine, config = migrated
    with Session(engine) as session:
        session.add(
            PatientPortalAuditEvent(
                event_type=AUDIT_EVENT_MYCARLOS_LINK,
                outcome="failure",
                actor_type="patient",
                created_at=utc_now(),
            )
        )
        session.commit()
    with pytest.raises(RuntimeError, match="myCarlos audit events exist"):
        command.downgrade(config, "0016_job_assertion_audit")

    with engine.begin() as connection:
        connection.execute(text("delete from patient_portal_audit_events"))
    with Session(engine) as session:
        session.add(device(add_account(session, 1701), "FAKE device kept"))
        session.commit()
    with pytest.raises(RuntimeError, match="myCarlos devices are linked"):
        command.downgrade(config, "0016_job_assertion_audit")
    assert MYCARLOS_TABLES <= set(inspect(engine).get_table_names())


@pytest.mark.parametrize("migrated", ["0017_mycarlos_linking"], indirect=True)
def test_a_clean_downgrade_drops_the_tables_and_the_audit_types(migrated) -> None:
    engine, config = migrated
    command.downgrade(config, "0016_job_assertion_audit")
    assert not MYCARLOS_TABLES & set(inspect(engine).get_table_names())
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                text(
                    "insert into patient_portal_audit_events "
                    "(event_type, outcome, actor_type, created_at) "
                    "values ('mycarlos.link', 'success', 'system', :now)"
                ),
                {"now": utc_now()},
            )
    command.upgrade(config, "head")
    assert MYCARLOS_TABLES <= set(inspect(engine).get_table_names())


def test_the_delivery_switch_is_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PATIENT_PORTAL_MYCARLOS_DELIVERY_ENABLED", raising=False)
    assert Settings(environment="development").mycarlos_delivery_enabled is False
    monkeypatch.setenv("PATIENT_PORTAL_MYCARLOS_DELIVERY_ENABLED", "true")
    assert Settings(environment="development").mycarlos_delivery_enabled is True
