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

"""The push handle table: the encrypted APNs device token of a live destination.

A linked myCarlos on an iPhone binds its Apple device token to the destination id it enrolled
(carlos-portal, iPhone push piece 6). The token is encrypted at rest and kept in a table of its
own, apart from the policy tables, with the destination, platform and environment bound in as
associated data. One row per destination; a new token replaces the old, and the row is deleted
when the destination is revoked or when APNs answers 410.

No data is moved and no existing table changes. The downgrade refuses while any handle exists
(dropping the table would forget tokens the devices believe the portal holds), as 0023 does for
waiting keys.

Revision ID: 0026_mycarlos_push_handles
Revises: 0025_signup_claim
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0026_mycarlos_push_handles",
    "down_revision": "0025_signup_claim",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_HANDLES = "patient_portal_mycarlos_push_handles"


def upgrade() -> None:
    op.create_table(
        _HANDLES,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("destination_id", sa.String(36), nullable=False),
        sa.Column(
            "account_id",
            sa.Integer(),
            sa.ForeignKey("patient_portal_accounts.id", name="fk_pp_mycarlos_push_handles_account"),
            nullable=False,
        ),
        sa.Column(
            "device_id",
            sa.Integer(),
            sa.ForeignKey(
                "patient_portal_mycarlos_devices.id", name="fk_pp_mycarlos_push_handles_device"
            ),
            nullable=False,
        ),
        sa.Column("platform", sa.String(16), nullable=False),
        sa.Column("environment", sa.String(10), nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("nonce", sa.LargeBinary(12), nullable=False),
        # 200 hex characters (the route's token cap) + the 16-byte AES-GCM tag = 216 bytes <= 256.
        sa.Column("ciphertext", sa.LargeBinary(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "platform in ('ios_apns', 'macos_apns')",
            name="ck_pp_mycarlos_push_handles_platform",
        ),
        sa.CheckConstraint(
            "environment in ('sandbox', 'production')",
            name="ck_pp_mycarlos_push_handles_environment",
        ),
        sa.CheckConstraint(
            "length(destination_id) = 36", name="ck_pp_mycarlos_push_handles_destination"
        ),
        sa.CheckConstraint("length(nonce) = 12", name="ck_pp_mycarlos_push_handles_nonce"),
        sqlite_autoincrement=True,
    )
    op.create_index(
        "ux_pp_mycarlos_push_handles_destination", _HANDLES, ["destination_id"], unique=True
    )
    op.create_index("ix_pp_mycarlos_push_handles_device", _HANDLES, ["device_id"])


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0026 downgrade requires an online connection to check handles"
        )
    held = op.get_bind().scalar(
        sa.text("select count(*) from patient_portal_mycarlos_push_handles")
    )
    if held:
        raise RuntimeError("cannot downgrade migration 0026 while push handles exist")
    op.drop_index("ix_pp_mycarlos_push_handles_device", table_name=_HANDLES)
    op.drop_index("ux_pp_mycarlos_push_handles_destination", table_name=_HANDLES)
    op.drop_table(_HANDLES)
