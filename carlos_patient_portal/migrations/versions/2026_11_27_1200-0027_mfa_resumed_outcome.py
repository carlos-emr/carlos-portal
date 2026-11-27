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

"""The audit outcome "resumed": a sign-in that returned to a pending code page (#147).

A sign-in inside the code-send cooldown used to be refused. When the browser can name the code
challenge that is still pending and unexpired (a short-lived cookie), the code page is shown again
for it and the audit trail records that as its own outcome, "resumed", apart from a throttled
refusal. The audit outcome CHECK only knew success, failure and throttled, so it is rewritten with
the new value. No data is moved and no other table changes.

The downgrade refuses while any "resumed" event exists: audit events are append-only (as in 0019
and 0025), and the old constraint cannot hold those rows.

Revision ID: 0027_mfa_resumed_outcome
Revises: 0026_mycarlos_push_handles
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0027_mfa_resumed_outcome",
    "down_revision": "0026_mycarlos_push_handles",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_AUDIT_TABLE = "patient_portal_audit_events"
_OUTCOME_CHECK = "ck_patient_portal_audit_events_outcome"
_OLD_OUTCOMES = "'success', 'failure', 'throttled'"
_NEW_OUTCOMES = "'success', 'failure', 'throttled', 'resumed'"


def upgrade() -> None:
    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint(_OUTCOME_CHECK, type_="check")
        batch_op.create_check_constraint(_OUTCOME_CHECK, f"outcome in ({_NEW_OUTCOMES})")


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0027 downgrade requires an online connection to check retained audit events"
        )
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        # Keep the retained-event check valid through the CHECK replacement.
        connection.execute(
            sa.text("LOCK TABLE patient_portal_audit_events IN ACCESS EXCLUSIVE MODE")
        )
    elif connection.dialect.name == "sqlite":
        # sqlite3's legacy transaction mode leaves SELECT/DDL outside a transaction.
        # Reserve the writer before reading.
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
    else:
        raise RuntimeError("migration 0027 supports only SQLite and PostgreSQL")
    if connection.scalar(
        sa.text("select count(*) from patient_portal_audit_events where outcome = 'resumed'")
    ):
        raise RuntimeError("cannot downgrade migration 0027 while resumed audit events exist")

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint(_OUTCOME_CHECK, type_="check")
        batch_op.create_check_constraint(_OUTCOME_CHECK, f"outcome in ({_OLD_OUTCOMES})")
