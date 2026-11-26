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

"""Tie a self sign-up request to the one invite the sign-up job prepared for it.

The job-only invite route (carlos-portal#16's follow-up) prepares an invite for a request the job
holds a lease on, with the identity proof copied from the request, and records the invite's id on
the request. A match can then be reported only with that invite. The column is a plain integer, as
`invite_id` is: the route checks the invite exists when it makes it.

The table is altered in place on PostgreSQL (batch mode recreates it only on SQLite).
Downgrade is refused while a request holds a prepared invite, since the old schema cannot keep
what ties the invite to its request.

Revision ID: 0027_signup_prepared_invite
Revises: 0026_mycarlos_push_handles
Create Date: 2026-11-25 09:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0027_signup_prepared_invite",
    "down_revision": "0026_mycarlos_push_handles",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_SIGNUP_TABLE = "patient_portal_signup_requests"
_POSITIVE = "ck_pp_signup_requests_prepared_invite_positive"


def upgrade() -> None:
    with op.batch_alter_table(_SIGNUP_TABLE) as batch_op:
        batch_op.add_column(sa.Column("prepared_invite_id", sa.Integer(), nullable=True))
        batch_op.create_check_constraint(
            _POSITIVE,
            "prepared_invite_id is null or prepared_invite_id > 0",
        )


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0027 downgrade requires an online connection to check retained signup data"
        )
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text("LOCK TABLE patient_portal_signup_requests IN ACCESS EXCLUSIVE MODE")
        )
    elif connection.dialect.name == "sqlite":
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
    else:
        raise RuntimeError("migration 0027 supports only SQLite and PostgreSQL")
    if connection.scalar(
        sa.text(
            "select count(*) from patient_portal_signup_requests "
            "where prepared_invite_id is not null"
        )
    ):
        raise RuntimeError(
            "cannot downgrade migration 0027 while sign-up requests hold a prepared invite"
        )
    with op.batch_alter_table(_SIGNUP_TABLE) as batch_op:
        batch_op.drop_constraint(_POSITIVE, type_="check")
        batch_op.drop_column("prepared_invite_id")
