# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Linear signup upgrades and guarded rollback preserve canonical portal data."""

import os
import re
from base64 import urlsafe_b64decode
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from hashlib import sha256
from threading import Event
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.schema import CreateSchema

from carlos_patient_portal.approval_models import ApprovalBase, ApprovalClinic, ApprovalRequest
from carlos_patient_portal.mailbox import accept_receipt, admit_upload
from carlos_patient_portal.mailbox_codec import parse_upload
from carlos_patient_portal.mailbox_models import MailboxBase
from carlos_patient_portal.models import (
    Base,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosRecipient,
    PatientPortalSignupRequest,
    utc_now,
)
from carlos_patient_portal.preflight import EXPECTED_SEQUENCE_PRIVILEGES, EXPECTED_TABLE_PRIVILEGES
from carlos_patient_portal.self_signup import (
    SignupRequestDetails,
    decrypt_signup_request,
    encrypt_signup_details,
)
from tests import delivery_contract_reference as ref
from tests.support import alembic_config_for_tests
from tests.test_device_identity import STATE
from tests.test_mycarlos_mailbox import ASSERTION, LIMITS, NOW, RECEIPT, VALUE, target

SIGNUP = "0019_self_signup_requests"
JOB = "0016_job_assertion_audit"
LINK = "0017_mycarlos_linking"
APPROVAL = "0018_mycarlos_mailbox_approval"
SCRIPT = ScriptDirectory.from_config(alembic_config_for_tests())
EVENTS = frozenset(
    re.findall(
        r"'([a-z][a-z_.]*)'",
        str(
            next(
                constraint.sqltext
                for constraint in PatientPortalAuditEvent.__table__.constraints
                if constraint.name == "ck_patient_portal_audit_events_event_type"
            )
        ),
    )
)
MYCARLOS = {value for value in EVENTS if value.startswith("mycarlos.")}
DETAILS = SignupRequestDetails("FAKE123456", date(1970, 1, 2), "fake@example.test")
ENCRYPTION_KEY = "FAKE historical signup encryption " + "x" * 32


@pytest.fixture(params=["sqlite", "postgresql"])
def lineage_engine(request, tmp_path):
    if request.param == "sqlite":
        engine = sa.create_engine("sqlite+pysqlite:///" + str(tmp_path / "lineage.db"))

        @sa.event.listens_for(engine, "connect")
        def enforce_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")
    else:
        url = os.environ.get("SIGNUP_LINEAGE_PG_TEST_URL") or os.environ.get(
            "PORTAL_TEST_POSTGRES_URL"
        )
        if not url:
            pytest.skip("requires an explicitly owned PostgreSQL test connection")
        schema = "signup_lineage_" + uuid4().hex
        bootstrap = sa.create_engine(url)
        with bootstrap.begin() as connection:
            connection.execute(CreateSchema(schema))
        bootstrap.dispose()
        engine = sa.create_engine(
            url, connect_args={"options": "-csearch_path=" + schema + ",pg_catalog"}
        )
    yield engine
    # Keep every owned schema/file, including failures. Never DROP SCHEMA in teardown.
    engine.dispose()


def migrate(engine, target_revision, direction="upgrade"):
    with engine.begin() as connection:
        config = alembic_config_for_tests()
        config.attributes["connection"] = connection
        getattr(command, direction)(config, target_revision)


def seed(engine, *, signup=False, signup_audit=True, job=False, link=False, mailbox=False):
    with Session(engine) as session, session.begin():
        account = PatientPortalAccount(
            clinic_id="clinic-a",
            demographic_no=91234,
            username="fake.lineage",
            email="fake.lineage@example.test",
            password_hash="FAKE-not-a-password-hash",
            status="active",
        )
        session.add(account)
        session.flush()
        account_id = account.id
        if link:
            row = next(
                d for d in STATE["devices"] if d["device_key_id"] == VALUE.outer["device_key_id"]
            )
            device = PatientPortalMyCarlosDevice(
                account_id=account_id,
                device_key_id=row["device_key_id"],
                x25519_public_key=urlsafe_b64decode(row["x25519_public_key"] + "="),
                ed25519_public_key=urlsafe_b64decode(row["ed25519_public_key"] + "="),
                device_name="FAKE retained myCarlos device",
                status="active",
                linked_at=utc_now(),
            )
            session.add(
                PatientPortalMyCarlosRecipient(
                    account_id=account_id, recipient_id=VALUE.outer["recipient_id"]
                )
            )
            session.add(device)
            session.flush()
            if mailbox:
                session.add(
                    ApprovalClinic(
                        clinic_id="clinic-a",
                        request_sequence=1,
                        challenge_sequence=1,
                        approval_sequence=1,
                    )
                )
                session.add(
                    ApprovalRequest(
                        clinic_id="clinic-a",
                        request_id=str(uuid4()),
                        account_id=account_id,
                        device_id=device.id,
                        demographic_no=91234,
                        recipient_id=VALUE.outer["recipient_id"],
                        candidate_kid=device.device_key_id,
                        request_sequence=1,
                        intent="FAKE retained opaque intent",
                        intent_body_hash=sha256(b"FAKE intent").hexdigest(),
                        expires_at=NOW + 300,
                        status="accepted",
                        challenge_id="f" * 43,
                        challenge_sequence=1,
                        challenge="FAKE retained opaque challenge",
                        approval_sequence=1,
                        approval="FAKE retained opaque approval",
                        acceptance="FAKE retained opaque acceptance",
                    )
                )
    with engine.begin() as connection:
        audit = sa.Table("patient_portal_audit_events", sa.MetaData(), autoload_with=connection)
        kinds = (
            {"login"}
            | ({"signup.request"} if signup and signup_audit else set())
            | ({"job.auth_refused"} if job else set())
            | (MYCARLOS if link else set())
        )
        for kind in sorted(kinds):
            values = dict(
                event_type=kind, outcome="success", actor_type="patient", created_at=utc_now()
            )
            if job and kind == "job.auth_refused":
                values.update(assertion_key_id="FAKE-retained-job-key", assertion_id=str(uuid4()))
            connection.execute(audit.insert().values(**values))
        if signup:
            digest = sha256(b"FAKE health-card reference").hexdigest()
            encrypted, nonce = encrypt_signup_details(
                DETAILS,
                encryption_secret=ENCRYPTION_KEY,
                clinic_id="clinic-a",
                health_card_hash=digest,
            )
            table = sa.Table(
                "patient_portal_signup_requests", sa.MetaData(), autoload_with=connection
            )
            connection.execute(
                table.insert().values(
                    clinic_id="clinic-a",
                    health_card_hash=digest,
                    encrypted_payload=encrypted,
                    encryption_nonce=nonce,
                    encryption_key_id="FAKE-old-key",
                    created_at=utc_now(),
                    expires_at=utc_now() + timedelta(days=1),
                )
            )
    if mailbox:
        factory = sessionmaker(engine, expire_on_commit=False)
        with factory() as session, session.begin():
            admit_upload(session, target(session), VALUE, now=NOW, limits=LIMITS)
        with factory() as session, session.begin():
            accept_receipt(
                session,
                target(session),
                delivery_id=VALUE.outer["delivery_id"],
                compact=RECEIPT,
                request_assertion=ASSERTION,
                request_anchor=None,
                clock=lambda: NOW,
                limits=LIMITS,
            )
        # A second portal-valid opaque upload retains primary ciphertext alongside history.
        outer = dict(VALUE.outer, delivery_id=str(uuid4()))
        upload = parse_upload(ref.frame(ref.canonical_json(outer), VALUE.sealed))
        with factory() as session, session.begin():
            admit_upload(session, target(session), upload, now=NOW, limits=LIMITS)


def snapshot(engine, *, versions=False):
    result = {}
    with engine.connect() as connection:
        for name in sa.inspect(connection).get_table_names():
            if name == "alembic_version" and not versions:
                continue
            table = sa.Table(name, sa.MetaData(), autoload_with=connection)
            columns = list(table.c)
            rows = [tuple(row) for row in connection.execute(sa.select(*columns))]
            result[name] = (tuple(c.name for c in columns), sorted(rows, key=repr))
    return result


def assert_preserved(engine, before):
    with engine.connect() as connection:
        for name, (columns, rows) in before.items():
            table = sa.Table(name, sa.MetaData(), autoload_with=connection)
            actual = [
                tuple(row) for row in connection.execute(sa.select(*(table.c[n] for n in columns)))
            ]
            assert sorted(actual, key=repr) == rows


def assert_schema_and_sequences(engine):
    metadata = [Base.metadata, MailboxBase.metadata, ApprovalBase.metadata]
    expected = {name: table for m in metadata for name, table in m.tables.items()}
    inspector = sa.inspect(engine)
    assert (
        set(inspector.get_table_names())
        == set(EXPECTED_TABLE_PRIVILEGES)
        == set(expected) | {"alembic_version"}
    )
    for name, table in expected.items():
        assert {c["name"] for c in inspector.get_columns(name)} == set(table.c.keys())
        assert tuple(inspector.get_pk_constraint(name)["constrained_columns"]) == tuple(
            column.name for column in table.primary_key.columns
        )
        assert {tuple(c["column_names"]) for c in inspector.get_unique_constraints(name)} == {
            tuple(column.name for column in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, sa.UniqueConstraint)
        }

        def options(value):
            return (
                str(value.get("ondelete") or "NO ACTION").upper(),
                str(value.get("onupdate") or "NO ACTION").upper(),
                bool(value.get("deferrable")),
                str(value.get("initially") or "IMMEDIATE").upper(),
            )

        assert {
            (
                tuple(c["constrained_columns"]),
                c["referred_table"],
                tuple(c["referred_columns"]),
                options(c.get("options", {})),
            )
            for c in inspector.get_foreign_keys(name)
        } == {
            (
                tuple(column.name for column in constraint.columns),
                next(iter(constraint.elements)).column.table.name,
                tuple(element.column.name for element in constraint.elements),
                options(
                    dict(
                        ondelete=constraint.ondelete,
                        onupdate=constraint.onupdate,
                        deferrable=constraint.deferrable,
                        initially=constraint.initially,
                    )
                ),
            )
            for constraint in table.foreign_key_constraints
        }
        actual_indexes = [
            index for index in inspector.get_indexes(name) if not index.get("duplicates_constraint")
        ]
        assert {
            (i["name"], tuple(i["column_names"]), bool(i["unique"])) for i in actual_indexes
        } == {
            (i.name, tuple(column.name for column in i.columns), bool(i.unique))
            for i in table.indexes
        }
    check = next(
        c
        for c in inspector.get_check_constraints("patient_portal_audit_events")
        if c["name"] == "ck_patient_portal_audit_events_event_type"
    )
    assert frozenset(re.findall(r"'([a-z][a-z_.]*)'", check["sqltext"])) == EVENTS
    if engine.dialect.name == "postgresql":
        with engine.connect() as connection:
            schema = connection.scalar(sa.text("SELECT current_schema()"))
            actual = set()
            for name in expected:
                for column in inspector.get_columns(name):
                    sequence = connection.scalar(
                        sa.text("SELECT pg_get_serial_sequence(:t,:c)"),
                        {"t": schema + "." + name, "c": column["name"]},
                    )
                    if sequence:
                        assert column["name"] == "id"
                        actual.add(sequence.removeprefix(schema + "."))
            assert actual == set(EXPECTED_SEQUENCE_PRIVILEGES)


@pytest.mark.parametrize("state", ["clean", "0015", "job", "link", "approval"])
def test_should_preserve_canonical_data_when_signup_follows_approval(lineage_engine, state):
    engine = lineage_engine
    if state != "clean":
        revision = {
            "0015": "0015_booking_offered_slots",
            "job": JOB,
            "link": LINK,
            "approval": APPROVAL,
        }[state]
        migrate(engine, revision)
        seed(
            engine,
            job=state != "0015",
            link=state in {"link", "approval"},
            mailbox=state == "approval",
        )
    before = snapshot(engine)
    migrate(engine, "head")
    assert_preserved(engine, before)
    assert_schema_and_sequences(engine)
    with engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_heads() == (SIGNUP,)
    assert SCRIPT.get_heads() == [SIGNUP]
    assert SCRIPT.get_revision(SIGNUP).down_revision == APPROVAL
    assert SCRIPT.get_revision(APPROVAL).down_revision == LINK
    assert SCRIPT.get_revision(LINK).down_revision == JOB
    after = snapshot(engine, versions=True)
    migrate(engine, "head")
    assert snapshot(engine, versions=True) == after


def test_should_keep_encrypted_signup_bytes_when_head_is_repeated(lineage_engine):
    engine = lineage_engine
    migrate(engine, "head")
    seed(engine, signup=True, job=True, link=True, mailbox=True)
    before = snapshot(engine, versions=True)
    migrate(engine, "head")
    assert snapshot(engine, versions=True) == before
    with Session(engine) as session:
        rows = list(session.scalars(sa.select(PatientPortalSignupRequest)))
        assert len(rows) == 1
        assert (
            decrypt_signup_request(rows[0], encryption_keys={"FAKE-old-key": ENCRYPTION_KEY})
            == DETAILS
        )


def test_should_roundtrip_empty_database_through_base_and_head(lineage_engine):
    engine = lineage_engine
    migrate(engine, "head")
    migrate(engine, "base", "downgrade")
    assert set(sa.inspect(engine).get_table_names()) <= {"alembic_version"}
    with engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_heads() == ()
    migrate(engine, "head")
    assert_schema_and_sequences(engine)


def test_should_preserve_unrelated_retained_data_when_empty_signup_is_rolled_back(lineage_engine):
    engine = lineage_engine
    migrate(engine, "head")
    seed(engine, job=True, link=True, mailbox=True)
    before = snapshot(engine)
    assert before.pop("patient_portal_signup_requests")[1] == []
    migrate(engine, APPROVAL, "downgrade")
    assert "patient_portal_signup_requests" not in sa.inspect(engine).get_table_names()
    assert_preserved(engine, before)
    check = next(
        c
        for c in sa.inspect(engine).get_check_constraints("patient_portal_audit_events")
        if c["name"] == "ck_patient_portal_audit_events_event_type"
    )
    assert frozenset(re.findall(r"'([a-z][a-z_.]*)'", check["sqltext"])) == EVENTS - {
        "signup.request"
    }
    with engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_heads() == (APPROVAL,)
    migrate(engine, "head")
    assert_preserved(engine, before)
    assert_schema_and_sequences(engine)


@pytest.mark.parametrize("retained", ["audit", "request"])
def test_should_refuse_signup_rollback_before_writes_when_either_record_exists(
    lineage_engine, retained
):
    engine = lineage_engine
    migrate(engine, "head")
    if retained == "request":
        # Deliberately no signup audit: a missing companion must not permit data loss.
        seed(engine, signup=True, signup_audit=False)
    else:
        with engine.begin() as connection:
            table = sa.Table("patient_portal_audit_events", sa.MetaData(), autoload_with=connection)
            connection.execute(
                table.insert().values(
                    event_type="signup.request",
                    outcome="success",
                    actor_type="patient",
                    created_at=utc_now(),
                )
            )
    before = snapshot(engine, versions=True)
    writes = []

    def record_write(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().split()[0].upper() in {
            "ALTER",
            "CREATE",
            "DROP",
            "DELETE",
            "INSERT",
            "UPDATE",
        }:
            writes.append(statement)

    sa.event.listen(engine, "before_cursor_execute", record_write)
    try:
        with pytest.raises(
            RuntimeError, match="sign-up audit events exist|stored sign-up requests exist"
        ):
            migrate(engine, APPROVAL, "downgrade")
    finally:
        sa.event.remove(engine, "before_cursor_execute", record_write)
    assert writes == []
    assert snapshot(engine, versions=True) == before


@pytest.mark.parametrize("writer", ["audit", "request"])
def test_should_hold_retention_decision_against_concurrent_inserts(lineage_engine, writer):
    engine = lineage_engine
    migrate(engine, "head")
    locked = Event()
    release = Event()

    def pause_before_request_count(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.lower().strip() == "select count(*) from patient_portal_signup_requests":
            locked.set()
            assert release.wait(10), "test did not release the owned migration transaction"

    sa.event.listen(engine, "before_cursor_execute", pause_before_request_count)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(migrate, engine, APPROVAL, "downgrade")
            try:
                assert locked.wait(10), "migration never reached its locked retention check"
                with pytest.raises(sa.exc.OperationalError) as failure:
                    with engine.begin() as connection:
                        if engine.dialect.name == "postgresql":
                            connection.exec_driver_sql("SET LOCAL lock_timeout='200ms'")
                        else:
                            connection.exec_driver_sql("PRAGMA busy_timeout=200")
                        if writer == "audit":
                            connection.execute(
                                sa.text(
                                    "INSERT INTO patient_portal_audit_events "
                                    "(event_type,outcome,actor_type,created_at) "
                                    "VALUES ('signup.request','success','patient',:now)"
                                ),
                                {"now": utc_now()},
                            )
                        else:
                            connection.execute(
                                sa.text(
                                    "INSERT INTO patient_portal_signup_requests "
                                    "(clinic_id,health_card_hash,encrypted_payload,encryption_nonce,"
                                    "encryption_key_id,created_at,expires_at) "
                                    "VALUES ('FAKE',:digest,:payload,:nonce,'FAKE',:now,:expires)"
                                ),
                                {
                                    "digest": "a" * 64,
                                    "payload": b"FAKE",
                                    "nonce": b"x" * 12,
                                    "now": utc_now(),
                                    "expires": utc_now() + timedelta(hours=1),
                                },
                            )
                if engine.dialect.name == "postgresql":
                    assert failure.value.orig.sqlstate == "55P03"
                else:
                    assert "locked" in str(failure.value).lower()
            finally:
                release.set()
                result.result(timeout=10)
    finally:
        sa.event.remove(engine, "before_cursor_execute", pause_before_request_count)
    with engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_heads() == (APPROVAL,)
