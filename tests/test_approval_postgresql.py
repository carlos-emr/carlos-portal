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
