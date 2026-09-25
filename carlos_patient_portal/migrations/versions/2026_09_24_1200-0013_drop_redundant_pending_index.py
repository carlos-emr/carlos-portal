# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This software is published under the GPL GNU General Public License.
# You can redistribute it and/or modify it under the terms published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

"""Drop the one-pending-invite index that the first-delivery index now covers.

``ux_pp_invites_first_delivery_per_patient`` (migration 0012) is unique over pending invites and
first preparations together, so it already allows only one pending invite per patient. The older
index repeated that check on every invite write.

Revision ID: 0013_drop_redundant_pending_idx
Revises: 0012_atomic_invite_delivery
Create Date: 2026-09-24 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0013_drop_redundant_pending_idx",
    "down_revision": "0012_atomic_invite_delivery",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_PENDING_STATUS_SQL = "status = 'pending'"


def upgrade() -> None:
    op.drop_index(
        "ux_patient_portal_invites_one_pending_per_patient",
        table_name="patient_portal_invites",
    )


def downgrade() -> None:
    # Safe to recreate: the first-delivery index has kept pending invites unique meanwhile. On
    # PostgreSQL this is a plain CREATE UNIQUE INDEX, which blocks invite writes while it builds;
    # the table is small, so run the downgrade in the same maintenance window as the rollback.
    op.create_index(
        "ux_patient_portal_invites_one_pending_per_patient",
        "patient_portal_invites",
        ["clinic_id", "demographic_no"],
        unique=True,
        sqlite_where=sa.text(_PENDING_STATUS_SQL),
        postgresql_where=sa.text(_PENDING_STATUS_SQL),
    )
