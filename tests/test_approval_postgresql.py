# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Real PostgreSQL migration/lock proof. Each fixture preserves its owned UUID schema."""

import os
import threading
import time
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import Session

from carlos_patient_portal.approval_models import ApprovalBase, ApprovalClinic
from carlos_patient_portal.mailbox_models import MailboxBase
from tests.support import alembic_config_for_tests


@pytest.fixture
def owned_approval_pg():
    url = os.environ.get("MYCARLOS_APPROVAL_PG_TEST_URL")
    if not url:
        pytest.skip("requires an explicitly owned PostgreSQL test connection")
    schema = "a3_approval_" + uuid4().hex
    bootstrap = create_engine(url)
    with bootstrap.begin() as connection:
        connection.execute(text('CREATE SCHEMA "' + schema + '"'))
    engine = create_engine(
        url, connect_args={"options": "-csearch_path=" + schema + ",pg_catalog"}, pool_size=5
    )
    with engine.begin() as connection:
        config = alembic_config_for_tests()
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    yield engine, schema
    # Never drop schemas. These empty/synthetic fixtures are retained for review.
    engine.dispose()
    bootstrap.dispose()


def migrate(connection, revision, direction):
    config = alembic_config_for_tests()
    config.attributes["connection"] = connection
    getattr(command, direction)(config, revision)


def test_actual_pg_empty_downgrade_reupgrade_and_retained_row_refusal(owned_approval_pg):
    engine, schema = owned_approval_pg
    names = set(ApprovalBase.metadata.tables) | set(MailboxBase.metadata.tables)
    assert names <= set(inspect(engine).get_table_names(schema=schema))
    expected_serial = {
        "patient_portal_mycarlos_mailbox_copies",
        "patient_portal_mycarlos_mailbox_anchors",
        "patient_portal_mycarlos_mailbox_events",
        "patient_portal_mycarlos_mailbox_proofs",
    }
    serial_tables = set()
    with engine.connect() as connection:
        for table in names:
            for column in inspect(engine).get_columns(table, schema=schema):
                sequence = connection.scalar(
                    text("SELECT pg_get_serial_sequence(:table,:column)"),
                    {"table": schema + "." + table, "column": column["name"]},
                )
                if sequence is not None:
                    assert column["name"] == "id"
                    assert sequence == schema + "." + table + "_id_seq"
                    serial_tables.add(table)
    assert serial_tables == expected_serial
    with engine.begin() as connection:
        migrate(connection, "0017_mycarlos_linking", "downgrade")
    assert not names.intersection(inspect(engine).get_table_names(schema=schema))
    with engine.begin() as connection:
        migrate(connection, "head", "upgrade")
    with Session(engine) as session, session.begin():
        session.add(ApprovalClinic(clinic_id="FAKE-PG-retained-proof"))
    with pytest.raises(RuntimeError, match="retained proof/history"):
        with engine.begin() as connection:
            migrate(connection, "0017_mycarlos_linking", "downgrade")
    assert names <= set(inspect(engine).get_table_names(schema=schema))
    with engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT clinic_id FROM patient_portal_mycarlos_approval_clinics")
            )
            == "FAKE-PG-retained-proof"
        )
        assert (
            connection.scalar(text("SELECT version_num FROM alembic_version"))
            == "0018_mycarlos_mailbox_approval"
        )


def test_actual_pg_empty_downgrade_fences_concurrent_new_proof_insertion(owned_approval_pg):
    engine, schema = owned_approval_pg
    locked = threading.Event()
    release = threading.Event()
    inserting = threading.Event()
    outcome = {}
    with engine.connect() as observer:

        def downgrade():
            try:
                with engine.begin() as connection:
                    outcome["migration_pid"] = connection.scalar(text("SELECT pg_backend_pid()"))

                    def after_lock(conn, cursor, statement, parameters, context, many):
                        if statement.startswith("LOCK TABLE "):
                            locked.set()
                            if not release.wait(10):
                                raise RuntimeError("owned test release timeout")

                    event.listen(connection, "after_cursor_execute", after_lock)
                    try:
                        migrate(connection, "0017_mycarlos_linking", "downgrade")
                    finally:
                        event.remove(connection, "after_cursor_execute", after_lock)
                outcome["downgraded"] = True
            except Exception as exc:
                outcome["migration_error"] = type(exc).__name__
                locked.set()

        def insert_proof():
            try:
                with engine.begin() as connection:
                    outcome["writer_pid"] = connection.scalar(text("SELECT pg_backend_pid()"))
                    inserting.set()
                    connection.execute(
                        text(
                            "INSERT INTO patient_portal_mycarlos_approval_clinics("
                            "clinic_id,request_sequence,approval_sequence,challenge_sequence) "
                            "VALUES('FAKE-concurrent-proof',0,0,0)"
                        )
                    )
                outcome["inserted"] = True
            except Exception as exc:
                outcome["writer_error"] = type(exc).__name__

        migration = threading.Thread(target=downgrade)
        writer = threading.Thread(target=insert_proof)
        migration.start()
        try:
            assert locked.wait(10)
            assert "migration_error" not in outcome, outcome
            writer.start()
            assert inserting.wait(5)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                blockers = observer.scalar(
                    text("SELECT pg_blocking_pids(:pid)"), {"pid": outcome["writer_pid"]}
                )
                if outcome["migration_pid"] in blockers:
                    outcome["observed_real_blocker"] = True
                    break
                time.sleep(0.02)
            assert outcome.get("observed_real_blocker") is True, outcome
        finally:
            release.set()
            migration.join(10)
            if writer.ident is not None:
                writer.join(10)
        assert not migration.is_alive() and not writer.is_alive()
    assert outcome.get("downgraded") is True, outcome
    assert outcome.get("writer_error") == "ProgrammingError", outcome
    assert "inserted" not in outcome
    assert "patient_portal_mycarlos_approval_clinics" not in inspect(engine).get_table_names(
        schema=schema
    )


@pytest.mark.parametrize("rollback_first", [False, True])
def test_actual_pg_m3_first_use_serializes_committed_request_cursor(
    owned_approval_pg, rollback_first
):
    import json
    from datetime import UTC, datetime
    from pathlib import Path

    from cryptography.hazmat.primitives import serialization

    from carlos_patient_portal.approvals import candidate_request
    from carlos_patient_portal.mailbox import mailbox_lock
    from carlos_patient_portal.models import (
        PatientPortalAccount,
        PatientPortalMyCarlosDevice,
        PatientPortalMyCarlosRecipient,
    )
    from carlos_patient_portal.mycarlos_devices import strict_b64url_decode
    from tests import delivery_contract_reference as ref

    engine, _ = owned_approval_pg
    fixture = json.loads(
        (Path(__file__).parent / "fixtures/device-approval-contract-v1.json").read_bytes()
    )
    targets = []
    for number, key_name in enumerate(["first", "candidate"], start=6001):
        key = fixture["keys"][key_name]
        recipient = "FAKE-pg-recipient-" + str(number)
        with Session(engine) as session, session.begin():
            account = PatientPortalAccount(
                clinic_id=fixture["clinic_id"],
                demographic_no=number,
                username="fake.pg." + str(number),
                email="fake.pg." + str(number) + "@example.invalid",
                password_hash="FAKE-unused",
                status="active",
            )
            session.add(account)
            session.flush()
            account_id = account.id
            session.add(
                PatientPortalMyCarlosRecipient(account_id=account_id, recipient_id=recipient)
            )
            session.add(
                PatientPortalMyCarlosDevice(
                    account_id=account_id,
                    device_key_id=key["device_key_id"],
                    ed25519_public_key=strict_b64url_decode(key["ed25519_public_key"]),
                    x25519_public_key=strict_b64url_decode(key["x25519_public_key"]),
                    device_name="FAKE-PG-concurrent-device",
                    status="active",
                    linked_at=datetime.fromtimestamp(fixture["now"], UTC),
                )
            )
        private = serialization.load_der_private_key(
            strict_b64url_decode(key["FAKE_ed25519_private_pkcs8_b64url"]), None
        )
        claims = dict(
            fixture["flows"]["first"]["intent"]["claims"],
            request_id=str(uuid4()),
            recipient_id=recipient,
            candidate_device_key_id=key["device_key_id"],
            candidate_x25519_public_key=key["x25519_public_key"],
            candidate_ed25519_public_key=key["ed25519_public_key"],
        )
        intent = ref.compact_ed25519(private, claims)
        raw = json.dumps({"intent": intent}, separators=(",", ":")).encode()
        targets.append((account_id, key["device_key_id"], intent, raw))
    first_ready = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()
    result = {}

    def writer(index):
        try:
            account, kid, intent, raw = targets[index]
            with Session(engine) as session, session.begin():
                result["pid" + str(index)] = session.scalar(text("SELECT pg_backend_pid()"))
                if index:
                    second_entered.set()
                m = mailbox_lock(
                    session, account_id=account, device_key_id=kid, clinic_id=fixture["clinic_id"]
                )
                candidate_request(
                    session,
                    m,
                    intent=intent,
                    body=raw,
                    public_base=fixture["public_portal_base_url"],
                    now=fixture["now"],
                )
                if index == 0:
                    first_ready.set()
                    if not release_first.wait(10):
                        raise RuntimeError("owned M3 release timeout")
                    if rollback_first:
                        raise RuntimeError("FAKE intentional first writer rollback")
            result["committed" + str(index)] = True
        except Exception as exc:
            result["error" + str(index)] = type(exc).__name__
            if index == 0:
                first_ready.set()

    first = threading.Thread(target=writer, args=(0,))
    second = threading.Thread(target=writer, args=(1,))
    first.start()
    try:
        assert first_ready.wait(10)
        assert "error0" not in result, result
        second.start()
        assert second_entered.wait(5)
        with engine.connect() as observer:
            deadline = time.monotonic() + 5
            blocked = False
            while time.monotonic() < deadline:
                if result["pid0"] in observer.scalar(
                    text("SELECT pg_blocking_pids(:pid)"), {"pid": result["pid1"]}
                ):
                    blocked = True
                    break
                time.sleep(0.02)
            assert blocked, result
            assert (
                observer.scalar(
                    text("SELECT COUNT(*) FROM patient_portal_mycarlos_approval_requests")
                )
                == 0
            )
    finally:
        release_first.set()
        first.join(10)
        if second.ident is not None:
            second.join(10)
    assert not first.is_alive() and not second.is_alive()
    assert result.get("committed1") is True, result
    assert result.get("error0") == ("RuntimeError" if rollback_first else None), result
    with engine.connect() as observer:
        sequences = list(
            observer.scalars(
                text(
                    "SELECT request_sequence FROM patient_portal_mycarlos_approval_requests "
                    "ORDER BY request_sequence"
                )
            )
        )
        assert sequences == ([1] if rollback_first else [1, 2])
        assert (
            observer.scalar(
                text("SELECT request_sequence FROM patient_portal_mycarlos_approval_clinics")
            )
            == sequences[-1]
        )
