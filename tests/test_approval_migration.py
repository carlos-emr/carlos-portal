# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Actual migration lifecycle and retained-row refusal, using only disposable test data."""

import pytest
from alembic import command
from alembic.autogenerate import produce_migrations
from alembic.migration import MigrationContext
from alembic.operations.ops import DropTableOp
from sqlalchemy import inspect, select

from carlos_patient_portal.approval_models import ApprovalBase, ApprovalClinic
from carlos_patient_portal.mailbox_models import MailboxBase
from carlos_patient_portal.models import Base
from tests.support import alembic_config_for_tests
from tests.test_internal_api import internal_app


def test_empty_downgrade_reupgrade_and_autogeneration_keep_new_storage():
    app = internal_app()
    engine = app.state.database_engine
    tables = set(ApprovalBase.metadata.tables) | set(MailboxBase.metadata.tables)
    assert tables <= set(inspect(engine).get_table_names())
    with engine.begin() as connection:
        config = alembic_config_for_tests()
        config.attributes["connection"] = connection
        command.downgrade(config, "0017_mycarlos_linking")
    assert not tables.intersection(inspect(engine).get_table_names())
    with engine.begin() as connection:
        config = alembic_config_for_tests()
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        generated = produce_migrations(
            MigrationContext.configure(connection),
            [Base.metadata, MailboxBase.metadata, ApprovalBase.metadata],
        )
        assert not any(
            isinstance(op, DropTableOp) and op.table_name in tables
            for op in generated.upgrade_ops.ops
        )
    assert tables <= set(inspect(engine).get_table_names())


def test_any_retained_approval_row_refuses_downgrade_before_any_table_is_dropped():
    app = internal_app()
    engine = app.state.database_engine
    tables = set(ApprovalBase.metadata.tables) | set(MailboxBase.metadata.tables)
    with app.state.session_factory() as session, session.begin():
        session.add(ApprovalClinic(clinic_id="FAKE-retained-migration-proof"))
    with pytest.raises(RuntimeError, match="retained proof/history"):
        with engine.begin() as connection:
            config = alembic_config_for_tests()
            config.attributes["connection"] = connection
            command.downgrade(config, "0017_mycarlos_linking")
    assert tables <= set(inspect(engine).get_table_names())
    with app.state.session_factory() as session:
        assert session.scalar(select(ApprovalClinic.clinic_id)) == "FAKE-retained-migration-proof"
