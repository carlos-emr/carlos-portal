# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Populated historical branches converge without changing retained application data."""

import os
import re
from base64 import urlsafe_b64decode
from datetime import date, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.operations import Operations
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

SIGNUP = "0016_self_signup_requests"
JOB = "0016_job_assertion_audit"
LINK = "0017_mycarlos_linking"
APPROVAL = "0018_mycarlos_mailbox_approval"
MERGE = "0019_signup_history_merge"
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
COMMON = EVENTS - MYCARLOS - {"signup.request", "job.auth_refused"}
DETAILS = SignupRequestDetails("FAKE123456", date(1970, 1, 2), "fake@example.test")
ENCRYPTION_KEY = "FAKE historical signup encryption " + "x" * 32


@pytest.fixture(params=["sqlite", "postgresql"])
def lineage_engine(request, tmp_path):
    if request.param == "sqlite":
        engine = sa.create_engine("sqlite+pysqlite:///" + str(tmp_path / "lineage.db"))
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


def set_historical_policy(engine, values):
    """Reproduce the released CHECK; all other historical DDL is unchanged."""
    with engine.begin() as connection:
        operations = Operations(MigrationContext.configure(connection))
        with operations.batch_alter_table("patient_portal_audit_events") as batch:
            batch.drop_constraint("ck_patient_portal_audit_events_event_type", type_="check")
            batch.create_check_constraint(
                "ck_patient_portal_audit_events_event_type",
                "event_type in (" + ", ".join(repr(v) for v in sorted(values)) + ")",
            )


def seed(engine, *, signup=False, job=False, link=False, mailbox=False):
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
            | ({"signup.request"} if signup else set())
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
        assert {tuple(c["column_names"]) for c in inspector.get_unique_constraints(name)} == {
            tuple(column.name for column in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, sa.UniqueConstraint)
        }
        assert {tuple(c["constrained_columns"]) for c in inspector.get_foreign_keys(name)} == {
            tuple(column.name for column in constraint.columns)
            for constraint in table.foreign_key_constraints
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


def prepare(engine, state):
    if state == "clean":
        return
    if state == "0015":
        migrate(engine, "0015_booking_offered_slots")
        seed(engine)
    elif state == "signup":
        migrate(engine, SIGNUP)
        set_historical_policy(engine, COMMON | {"signup.request"})
        seed(engine, signup=True)
    elif state == "job":
        migrate(engine, JOB)
        set_historical_policy(engine, COMMON | {"job.auth_refused"})
        seed(engine, job=True)
    elif state in {"link", "approval"}:
        migrate(engine, LINK if state == "link" else APPROVAL)
        set_historical_policy(engine, EVENTS - {"signup.request"})
        seed(engine, job=True, link=True, mailbox=state == "approval")
    else:
        if state == "combined_signup_last":
            migrate(engine, APPROVAL)
            migrate(engine, SIGNUP)
            set_historical_policy(engine, COMMON | {"signup.request"})
            seed(engine, signup=True)
        else:
            migrate(engine, SIGNUP)
            migrate(engine, APPROVAL)
            set_historical_policy(
                engine, EVENTS - {"signup.request"} if state == "combined_link_last" else EVENTS
            )
            seed(engine, signup=state == "combined_union", job=True, link=True, mailbox=True)


@pytest.mark.parametrize(
    "state",
    [
        "clean",
        "0015",
        "signup",
        "job",
        "link",
        "approval",
        "combined_signup_last",
        "combined_link_last",
        "combined_union",
    ],
)
def test_should_preserve_all_historical_bytes_when_both_branches_converge(lineage_engine, state):
    engine = lineage_engine
    prepare(engine, state)
    before = snapshot(engine)
    migrate(engine, "head")
    assert_preserved(engine, before)
    assert_schema_and_sequences(engine)
    with engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_heads() == (MERGE,)
    with Session(engine) as session:
        for row in session.scalars(sa.select(PatientPortalSignupRequest)):
            assert (
                decrypt_signup_request(row, encryption_keys={"FAKE-old-key": ENCRYPTION_KEY})
                == DETAILS
            )
    after = snapshot(engine, versions=True)
    migrate(engine, "head")
    assert snapshot(engine, versions=True) == after
    assert SCRIPT.get_heads() == [MERGE]
    assert len(EVENTS) == 48
    assert set(SCRIPT.get_revision(MERGE).down_revision) == {APPROVAL, SIGNUP}
    assert SCRIPT.get_revision(SIGNUP).down_revision == "0015_booking_offered_slots"
    assert SCRIPT.get_revision(JOB).down_revision == "0015_booking_offered_slots"


@pytest.mark.parametrize("retained", [False, True])
def test_should_refuse_unmerge_before_writes_even_when_no_data_is_retained(
    lineage_engine, retained
):
    engine = lineage_engine
    migrate(engine, "head")
    if retained:
        seed(engine, signup=True, job=True, link=True, mailbox=True)
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
        with pytest.raises(RuntimeError, match="0019 is forward-only"):
            migrate(engine, APPROVAL, "downgrade")
    finally:
        sa.event.remove(engine, "before_cursor_execute", record_write)
    assert writes == []
    assert snapshot(engine, versions=True) == before


@pytest.mark.parametrize(
    "drift",
    [
        "missing_table",
        "missing_column",
        "column_type",
        "column_nullability",
        "missing_check",
        "unknown_event",
        "weakened_check",
    ],
)
def test_should_refuse_unknown_parent_schema_before_any_merge_write(lineage_engine, drift):
    engine = lineage_engine
    migrate(engine, APPROVAL)
    migrate(engine, SIGNUP)
    with engine.begin() as connection:
        if drift == "missing_table":
            connection.execute(
                sa.text(
                    "ALTER TABLE patient_portal_signup_requests RENAME TO fake_unexpected_signup"
                )
            )
        elif drift == "missing_column":
            connection.execute(
                sa.text(
                    "ALTER TABLE patient_portal_audit_events "
                    "RENAME COLUMN assertion_key_id TO fake_unknown_key"
                )
            )
        elif drift in {"column_type", "column_nullability", "missing_check"}:
            operations = Operations(MigrationContext.configure(connection))
            with operations.batch_alter_table("patient_portal_audit_events") as batch:
                if drift == "column_type":
                    batch.alter_column(
                        "assertion_key_id", existing_type=sa.String(64), type_=sa.String(65)
                    )
                elif drift == "column_nullability":
                    batch.alter_column(
                        "assertion_key_id", existing_type=sa.String(64), nullable=False
                    )
                else:
                    batch.drop_constraint(
                        "ck_patient_portal_audit_events_assertion_id_length", type_="check"
                    )
        else:
            operations = Operations(MigrationContext.configure(connection))
            with operations.batch_alter_table("patient_portal_audit_events") as batch:
                batch.drop_constraint("ck_patient_portal_audit_events_event_type", type_="check")
                values = EVENTS | {"fake.unexpected"} if drift == "unknown_event" else EVENTS
                sql = "event_type in (" + ", ".join(repr(v) for v in sorted(values)) + ")"
                batch.create_check_constraint(
                    "ck_patient_portal_audit_events_event_type",
                    sql + (" OR 1=1" if drift == "weakened_check" else ""),
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
        with pytest.raises(RuntimeError, match="0019 refuses"):
            migrate(engine, "head")
    finally:
        sa.event.remove(engine, "before_cursor_execute", record_write)
    assert writes == []
    assert snapshot(engine, versions=True) == before
