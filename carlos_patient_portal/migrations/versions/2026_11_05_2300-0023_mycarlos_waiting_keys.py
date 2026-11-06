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

"""Add the waiting keys a locked myCarlos asks "anything waiting?" with (carlos-portal#87).

`patient_portal_mycarlos_waiting_keys`: one row per registered Ed25519 waiting key, bound to a
linked device (so to one link), at most one live key per device. Only the public key is stored.
A revoked key stays as a tombstone with who revoked it, so its id never comes back. The table
holds no document id, no text and no patient data. It stays unused while
`PATIENT_PORTAL_MYCARLOS_AVAILABILITY_ENABLED` is off.

Revision ID: 0023_mycarlos_waiting_keys
Revises: 0022_availability_enrollment
Create Date: 2026-11-05 23:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0023_mycarlos_waiting_keys",
    "down_revision": "0022_availability_enrollment",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_KEYS = "patient_portal_mycarlos_waiting_keys"
_REVOKED_BY = ("device", "notice_key", "device_removed", "staff", "unlink")


def upgrade() -> None:
    revoked_by = ", ".join(f"'{value}'" for value in _REVOKED_BY)
    op.create_table(
        _KEYS,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key_id", sa.String(43), nullable=False),
        sa.Column("public_key", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "account_id",
            sa.Integer(),
            sa.ForeignKey("patient_portal_accounts.id", name="fk_pp_mycarlos_waiting_keys_account"),
            nullable=False,
        ),
        sa.Column(
            "device_id",
            sa.Integer(),
            sa.ForeignKey(
                "patient_portal_mycarlos_devices.id", name="fk_pp_mycarlos_waiting_keys_device"
            ),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_answered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(16), nullable=True),
        sa.CheckConstraint("length(key_id) = 43", name="ck_pp_mycarlos_waiting_keys_kid"),
        sa.CheckConstraint("length(public_key) = 32", name="ck_pp_mycarlos_waiting_keys_key"),
        sa.CheckConstraint(
            f"revoked_by is null or revoked_by in ({revoked_by})",
            name="ck_pp_mycarlos_waiting_keys_revoked_by",
        ),
        sa.CheckConstraint(
            "(revoked_at is null) = (revoked_by is null)",
            name="ck_pp_mycarlos_waiting_keys_revoked_complete",
        ),
        sqlite_autoincrement=True,
    )
    op.create_index("ux_pp_mycarlos_waiting_keys_kid", _KEYS, ["key_id"], unique=True)
    op.create_index(
        "ux_pp_mycarlos_waiting_keys_live",
        _KEYS,
        ["device_id"],
        unique=True,
        sqlite_where=sa.text("revoked_at is null"),
        postgresql_where=sa.text("revoked_at is null"),
    )


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError("migration 0023 downgrade requires an online connection to check keys")
    registered = op.get_bind().scalar(
        sa.text("select count(*) from patient_portal_mycarlos_waiting_keys")
    )
    if registered:
        # Dropping the table would forget the keys devices still hold, and the tombstones that
        # keep a revoked key from coming back.
        raise RuntimeError("cannot downgrade migration 0023 while waiting keys exist")
    op.drop_index("ux_pp_mycarlos_waiting_keys_live", table_name=_KEYS)
    op.drop_index("ux_pp_mycarlos_waiting_keys_kid", table_name=_KEYS)
    op.drop_table(_KEYS)
