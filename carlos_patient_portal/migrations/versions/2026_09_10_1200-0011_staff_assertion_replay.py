# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This software is published under the GPL GNU General Public License.

"""Persist consumed CARLOS staff assertion nonces across portal workers.

Revision ID: 0011_staff_assertion_replay
Revises: 0010_durable_reset_request_queue
Create Date: 2026-09-10 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0011_staff_assertion_replay",
    "down_revision": "0010_durable_reset_request_queue",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)


def upgrade() -> None:
    op.create_table(
        "patient_portal_staff_assertion_uses",
        sa.Column("assertion_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(assertion_id) = 36",
            name="ck_pp_staff_assertion_use_id_length",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_pp_staff_assertion_use_expiry_after_creation",
        ),
        sa.PrimaryKeyConstraint("assertion_id"),
    )
    op.create_index(
        "ix_pp_staff_assertion_use_expires",
        "patient_portal_staff_assertion_uses",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_pp_staff_assertion_use_expires",
        table_name="patient_portal_staff_assertion_uses",
    )
    op.drop_table("patient_portal_staff_assertion_uses")
