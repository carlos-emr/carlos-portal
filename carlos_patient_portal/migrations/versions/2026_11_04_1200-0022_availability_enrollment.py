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

"""Add the enrollment and outbox tables for myCarlos availability notices (myCarlos#192, P1).

The policy core (`mycarlos_availability`, carlos-portal#78) decides what may be queued and
sent; this revision gives it durable storage, with no worker and no provider yet:
- `patient_portal_mycarlos_availability_subscriptions`: one enrolled push destination per row,
  owned by an account and a linked device, with the consent the device reported and a
  tombstone once revoked;
- `patient_portal_mycarlos_availability_outbox`: "documents ready" intents, at most one pending
  per subscription and epoch, leased by the dispatch worker that comes later.
Neither table holds a document id, any text, or a provider token. Both stay unused while
`PATIENT_PORTAL_MYCARLOS_AVAILABILITY_ENABLED` is off.

It follows 0019_self_signup_requests (carlos-portal#35), main's head, in one line from 0017:
0017 -> 0018 -> 0020 -> 0019 -> 0022. Written before that chain merged, it revised 0017 too,
which would have left two heads. It leaves the audit event-type CHECK alone (0019 owns it). Only
remote consent version 1 exists, so the column is checked to be 1; a later version rewrites that
check and keeps older rows as their history.

Revision ID: 0022_availability_enrollment
Revises: 0019_self_signup_requests
Create Date: 2026-11-04 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0022_availability_enrollment",
    "down_revision": "0019_self_signup_requests",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_SUBSCRIPTIONS = "patient_portal_mycarlos_availability_subscriptions"
_OUTBOX = "patient_portal_mycarlos_availability_outbox"


def upgrade() -> None:
    op.create_table(
        _SUBSCRIPTIONS,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("subscription_id", sa.String(36), nullable=False),
        sa.Column(
            "account_id",
            sa.Integer(),
            sa.ForeignKey("patient_portal_accounts.id", name="fk_pp_mycarlos_avail_subs_account"),
            nullable=False,
        ),
        sa.Column(
            "device_id",
            sa.Integer(),
            sa.ForeignKey(
                "patient_portal_mycarlos_devices.id", name="fk_pp_mycarlos_avail_subs_device"
            ),
            nullable=False,
        ),
        sa.Column("epoch", sa.String(36), nullable=False),
        sa.Column("destination_id", sa.String(36), nullable=False),
        sa.Column("platform", sa.String(16), nullable=False),
        sa.Column("remote_enabled", sa.Boolean(), nullable=False),
        sa.Column("remote_consent_version", sa.Integer(), nullable=False),
        sa.Column("permission_observed", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(16), nullable=True),
        sa.CheckConstraint(
            "platform in ('android_fcm', 'ios_apns', 'macos_apns', 'windows_wns')",
            name="ck_pp_mycarlos_avail_subs_platform",
        ),
        sa.CheckConstraint(
            "length(subscription_id) = 36 and length(epoch) = 36 and length(destination_id) = 36",
            name="ck_pp_mycarlos_avail_subs_ids",
        ),
        sa.CheckConstraint(
            "remote_consent_version = 1",
            name="ck_pp_mycarlos_avail_subs_consent",
        ),
        sa.CheckConstraint(
            "revoked_by is null or revoked_by in ('device', 'provider', 'staff')",
            name="ck_pp_mycarlos_avail_subs_revoked_by",
        ),
        sa.CheckConstraint(
            "(revoked_at is null) = (revoked_by is null)",
            name="ck_pp_mycarlos_avail_subs_revoked_complete",
        ),
        sa.CheckConstraint(
            "revoked_at is null or not remote_enabled",
            name="ck_pp_mycarlos_avail_subs_revoked_off",
        ),
        sqlite_autoincrement=True,
    )
    op.create_index(
        "ux_pp_mycarlos_avail_subs_subscription", _SUBSCRIPTIONS, ["subscription_id"], unique=True
    )
    op.create_index(
        "ux_pp_mycarlos_avail_subs_destination", _SUBSCRIPTIONS, ["destination_id"], unique=True
    )
    op.create_index("ix_pp_mycarlos_avail_subs_owner", _SUBSCRIPTIONS, ["account_id", "device_id"])

    op.create_table(
        _OUTBOX,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "subscription_id",
            sa.String(36),
            sa.ForeignKey(
                f"{_SUBSCRIPTIONS}.subscription_id",
                name="fk_pp_mycarlos_avail_outbox_subscription",
            ),
            nullable=False,
        ),
        sa.Column("epoch", sa.String(36), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.BigInteger(), nullable=True),
        sa.Column("lease_token", sa.String(36), nullable=True),
        sa.Column("lease_until", sa.BigInteger(), nullable=True),
        sa.Column("last_decision", sa.String(96), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "status in ('pending', 'leased', 'done')",
            name="ck_pp_mycarlos_avail_outbox_status",
        ),
        sa.CheckConstraint(
            "length(epoch) = 36 and sequence > 0 and attempts >= 0 and expires_at > created_at",
            name="ck_pp_mycarlos_avail_outbox_values",
        ),
        sa.CheckConstraint(
            "(lease_token is null) = (lease_until is null)",
            name="ck_pp_mycarlos_avail_outbox_lease_complete",
        ),
        sa.CheckConstraint(
            "(status = 'leased') = (lease_token is not null)",
            name="ck_pp_mycarlos_avail_outbox_leased",
        ),
        sa.CheckConstraint(
            "lease_token is null or length(lease_token) = 36",
            name="ck_pp_mycarlos_avail_outbox_lease_token",
        ),
        sqlite_autoincrement=True,
    )
    op.create_index(
        "ux_pp_mycarlos_avail_outbox_pending",
        _OUTBOX,
        ["subscription_id", "epoch"],
        unique=True,
        sqlite_where=sa.text("status = 'pending'"),
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index("ix_pp_mycarlos_avail_outbox_claim", _OUTBOX, ["status", "next_attempt_at"])


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0022 downgrade requires an online connection to check enrollments"
        )
    enrolled = op.get_bind().scalar(
        sa.text("select count(*) from patient_portal_mycarlos_availability_subscriptions")
    )
    if enrolled:
        # Dropping the table would forget the enrollments the devices still hold, and the
        # tombstones that keep a revoked destination from enrolling again.
        raise RuntimeError("cannot downgrade migration 0022 while availability enrollments exist")
    op.drop_index("ix_pp_mycarlos_avail_outbox_claim", table_name=_OUTBOX)
    op.drop_index("ux_pp_mycarlos_avail_outbox_pending", table_name=_OUTBOX)
    op.drop_table(_OUTBOX)
    op.drop_index("ix_pp_mycarlos_avail_subs_owner", table_name=_SUBSCRIPTIONS)
    op.drop_index("ux_pp_mycarlos_avail_subs_destination", table_name=_SUBSCRIPTIONS)
    op.drop_index("ux_pp_mycarlos_avail_subs_subscription", table_name=_SUBSCRIPTIONS)
    op.drop_table(_SUBSCRIPTIONS)
