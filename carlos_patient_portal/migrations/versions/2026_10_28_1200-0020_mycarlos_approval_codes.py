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

"""Add clinic code v1 submissions for myCarlos device approval (mycarlos#141).

A device sends the 6-digit code_r the patient entered; CARLOS's approval job reads and
consumes it. The portal never compares codes. No backfill, no network work, and no existing
request changes state.

Revision ID: 0020_mycarlos_approval_codes
Revises: 0018_mycarlos_mailbox_approval

0019 is the self sign-up migration on another branch (carlos-portal #35). Whichever of the two
merges second re-points its down_revision to the other.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0020_mycarlos_approval_codes",
    "down_revision": "0018_mycarlos_mailbox_approval",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_CLINICS = "patient_portal_mycarlos_approval_clinics"
_CODES = "patient_portal_mycarlos_approval_codes"


def upgrade() -> None:
    with op.batch_alter_table(_CLINICS) as batch_op:
        batch_op.add_column(
            sa.Column("code_sequence", sa.BigInteger(), nullable=False, server_default="0")
        )
    op.create_table(
        _CODES,
        sa.Column("clinic_id", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.String(length=36), nullable=False),
        sa.Column("attempt", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("code_sequence", sa.BigInteger(), nullable=False),
        sa.Column("code_r", sa.String(length=6), nullable=True),
        sa.Column("submitted_at", sa.BigInteger(), nullable=False),
        sa.Column("consumed_at", sa.BigInteger(), nullable=True),
        sa.CheckConstraint("attempt between 1 and 5", name="ck_pp_approval_code_attempt"),
        sa.CheckConstraint(
            "code_r is null or length(code_r) = 6", name="ck_pp_approval_code_value"
        ),
        sa.ForeignKeyConstraint(
            ["clinic_id", "request_id"],
            [
                "patient_portal_mycarlos_approval_requests.clinic_id",
                "patient_portal_mycarlos_approval_requests.request_id",
            ],
            name="fk_pp_approval_code_request",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("clinic_id", "request_id", "attempt"),
        sa.UniqueConstraint("clinic_id", "code_sequence", name="uq_pp_approval_code_sequence"),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # Hold the empty-table decision through DROP, as 0018 does: a concurrent code submission
        # must not appear between the retention check and schema removal.
        bind.execute(sa.text(f"LOCK TABLE {_CODES}, {_CLINICS} IN ACCESS EXCLUSIVE MODE"))
    elif bind.dialect.name != "sqlite":
        raise RuntimeError("unsupported myCarlos storage downgrade dialect")
    if bind.scalar(sa.select(sa.func.count()).select_from(sa.table(_CODES))):
        raise RuntimeError("myCarlos retained proof/history rows prevent downgrade")
    op.drop_table(_CODES)
    with op.batch_alter_table(_CLINICS) as batch_op:
        batch_op.drop_column("code_sequence")
