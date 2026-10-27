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

"""Add isolated myCarlos mailbox and device-approval proof storage.

Ciphertext lives only in mailbox_blobs, with restrictive foreign keys and terminal
metadata/proofs in separate rows. No existing link is approved by this migration.
All runtime feature switches remain default off. No data backfill or network work.

Revision ID: 0018_mycarlos_mailbox_approval
Revises: 0017_mycarlos_linking
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0018_mycarlos_mailbox_approval",
    "down_revision": "0017_mycarlos_linking",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)


def upgrade() -> None:

    op.create_table(
        "patient_portal_mycarlos_mailbox_accounts",
        sa.Column("account_id", sa.Integer(), nullable=False),
        sa.Column("waiting_bytes", sa.BigInteger(), nullable=False),
        sa.Column("waiting_count", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "waiting_bytes>=0 and waiting_count>=0", name="ck_pp_mailbox_account_counters"
        ),
        sa.ForeignKeyConstraint(
            ["account_id"], ["patient_portal_accounts.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("account_id"),
    )
    op.create_table(
        "patient_portal_mycarlos_mailbox_clinics",
        sa.Column("clinic_id", sa.String(length=64), nullable=False),
        sa.Column("waiting_bytes", sa.BigInteger(), nullable=False),
        sa.Column("waiting_count", sa.Integer(), nullable=False),
        sa.Column("ordinary_event_bytes", sa.BigInteger(), nullable=False),
        sa.Column("reserved_terminal_bytes", sa.BigInteger(), nullable=False),
        sa.Column("terminal_event_bytes", sa.BigInteger(), nullable=False),
        sa.Column("event_sequence", sa.BigInteger(), nullable=False),
        sa.Column("acked_through", sa.BigInteger(), nullable=False),
        sa.Column("retained_floor", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "waiting_bytes>=0 and waiting_count>=0 and ordinary_event_bytes>=0 and te"
            "rminal_event_bytes>=0 and reserved_terminal_bytes>=0 and event_sequence>"
            "=acked_through and acked_through>=retained_floor and retained_floor>=0",
            name="ck_pp_mailbox_clinic_counters",
        ),
        sa.PrimaryKeyConstraint("clinic_id"),
    )
    op.create_table(
        "patient_portal_mycarlos_mailbox_copies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("account_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("clinic_id", sa.String(length=64), nullable=False),
        sa.Column("recipient_id", sa.String(length=64), nullable=False),
        sa.Column("device_key_id", sa.String(length=43), nullable=False),
        sa.Column("delivery_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(length=64), nullable=False),
        sa.Column("body_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("terminal_at", sa.BigInteger(), nullable=True),
        sa.Column("receipt_sha256", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "(status='waiting' and terminal_at is null and receipt_sha256 is null) or"
            " (status='picked_up' and terminal_at is not null and receipt_sha256 is n"
            "ot null) or (status in ('removed','expired') and terminal_at is not null"
            " and receipt_sha256 is null)",
            name="ck_pp_mailbox_copy_terminal",
        ),
        sa.CheckConstraint(
            "status in ('waiting','picked_up','expired','removed') and sequence>0 and"
            " size between 49 and 20971520 and expires_at>created_at and expires_at-c"
            "reated_at<=604800",
            name="ck_pp_mailbox_copy_state",
        ),
        sa.CheckConstraint(
            "created_at>=0 and length(recipient_id) between 1 and 64 and length(devic"
            "e_key_id)=43 and length(body_sha256)=64 and length(ciphertext_sha256)=64",
            name="ck_pp_mailbox_copy_bindings",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"], ["patient_portal_accounts.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["patient_portal_mycarlos_devices.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "clinic_id", "device_key_id", "delivery_id", name="uq_pp_mailbox_copy_identity"
        ),
        sa.UniqueConstraint("device_id", "sequence", name="uq_pp_mailbox_copy_sequence"),
    )
    op.create_index(
        op.f("ix_patient_portal_mycarlos_mailbox_copies_account_id"),
        "patient_portal_mycarlos_mailbox_copies",
        ["account_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_patient_portal_mycarlos_mailbox_copies_device_id"),
        "patient_portal_mycarlos_mailbox_copies",
        ["device_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_patient_portal_mycarlos_mailbox_copies_expires_at"),
        "patient_portal_mycarlos_mailbox_copies",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_patient_portal_mycarlos_mailbox_copies_status"),
        "patient_portal_mycarlos_mailbox_copies",
        ["status"],
        unique=False,
    )
    op.create_table(
        "patient_portal_mycarlos_mailbox_devices",
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("waiting_bytes", sa.BigInteger(), nullable=False),
        sa.Column("waiting_count", sa.Integer(), nullable=False),
        sa.Column("delivery_sequence", sa.BigInteger(), nullable=False),
        sa.Column("anchor_sequence", sa.BigInteger(), nullable=False),
        sa.Column("removal_event_recorded", sa.Boolean(), nullable=False),
        sa.CheckConstraint(
            "waiting_bytes>=0 and waiting_count>=0 and delivery_sequence>=0 and anchor_sequence>=0",
            name="ck_pp_mailbox_device_counters",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["patient_portal_mycarlos_devices.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("device_id"),
    )
    op.create_table(
        "patient_portal_mycarlos_mailbox_proofs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_key_id", sa.String(length=43), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("compact", sa.LargeBinary(length=4096), nullable=False),
        sa.Column("recorded_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "length(compact) between 1 and 4096 and length(sha256)=64 and length(devi"
            "ce_key_id)=43 and recorded_at>=0",
            name="ck_pp_mailbox_proof_size",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_key_id", "sha256", name="uq_pp_mailbox_proof_bytes"),
    )
    op.create_table(
        "patient_portal_mycarlos_mailbox_rates",
        sa.Column("clinic_id", sa.String(length=64), nullable=False),
        sa.Column("bucket", sa.String(length=128), nullable=False),
        sa.Column("minute", sa.BigInteger(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("bytes", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("clinic_id", "bucket"),
    )
    op.create_table(
        "patient_portal_mycarlos_mailbox_anchors",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("clinic_id", sa.String(length=64), nullable=False),
        sa.Column("recipient_id", sa.String(length=64), nullable=False),
        sa.Column("device_key_id", sa.String(length=43), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("vault_head_link", sa.String(length=64), nullable=False),
        sa.Column("recorded_at", sa.BigInteger(), nullable=False),
        sa.Column("proof_kind", sa.String(length=16), nullable=False),
        sa.Column("proof_id", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "proof_kind in ('request','receipt') and sequence>0 and length(vault_head"
            "_link)=64 and recorded_at>=0",
            name="ck_pp_mailbox_anchor_kind",
        ),
        sa.ForeignKeyConstraint(
            ["proof_id"], ["patient_portal_mycarlos_mailbox_proofs.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_key_id", "proof_id", name="uq_pp_mailbox_anchor_proof"),
        sa.UniqueConstraint("device_key_id", "sequence", name="uq_pp_mailbox_anchor_sequence"),
    )
    op.create_index(
        op.f("ix_patient_portal_mycarlos_mailbox_anchors_device_key_id"),
        "patient_portal_mycarlos_mailbox_anchors",
        ["device_key_id"],
        unique=False,
    )
    op.create_table(
        "patient_portal_mycarlos_mailbox_blobs",
        sa.Column("copy_id", sa.Integer(), nullable=False),
        sa.Column("sealed", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint(
            "length(sealed) between 49 and 20971520", name="ck_pp_mailbox_blob_size"
        ),
        sa.ForeignKeyConstraint(
            ["copy_id"], ["patient_portal_mycarlos_mailbox_copies.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("copy_id"),
    )
    op.create_table(
        "patient_portal_mycarlos_mailbox_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("clinic_id", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("recipient_id", sa.String(length=64), nullable=False),
        sa.Column("device_key_id", sa.String(length=43), nullable=False),
        sa.Column("delivery_id", sa.String(length=36), nullable=True),
        sa.Column("payload", sa.LargeBinary(length=16384), nullable=False),
        sa.Column("request_proof_id", sa.Integer(), nullable=True),
        sa.Column("receipt_proof_id", sa.Integer(), nullable=True),
        sa.Column("budget", sa.String(length=16), nullable=False),
        sa.Column("charged_bytes", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "(kind='picked_up' and delivery_id is not null and budget='terminal' and "
            "request_proof_id is not null and receipt_proof_id is not null) or (kind "
            "in ('expired','removed') and delivery_id is not null and budget='termina"
            "l' and request_proof_id is null and receipt_proof_id is null) or (kind='"
            "device_removed' and delivery_id is null and budget='control' and request"
            "_proof_id is null and receipt_proof_id is null) or (kind='anchor' and de"
            "livery_id is null and budget='ordinary' and request_proof_id is not null"
            " and receipt_proof_id is null)",
            name="ck_pp_mailbox_event_evidence",
        ),
        sa.CheckConstraint(
            "kind in ('picked_up','expired','removed','device_removed','anchor') and "
            "sequence>0 and charged_bytes between 1 and 16384 and length(payload)<=16"
            "384 and occurred_at>=0",
            name="ck_pp_mailbox_event_kind",
        ),
        sa.ForeignKeyConstraint(
            ["receipt_proof_id"], ["patient_portal_mycarlos_mailbox_proofs.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["request_proof_id"], ["patient_portal_mycarlos_mailbox_proofs.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("clinic_id", "sequence", name="uq_pp_mailbox_event_sequence"),
    )
    op.create_index(
        op.f("ix_patient_portal_mycarlos_mailbox_events_clinic_id"),
        "patient_portal_mycarlos_mailbox_events",
        ["clinic_id"],
        unique=False,
    )
    op.create_table(
        "patient_portal_mycarlos_approval_clinics",
        sa.Column("clinic_id", sa.String(length=64), nullable=False),
        sa.Column("request_sequence", sa.BigInteger(), nullable=False),
        sa.Column("approval_sequence", sa.BigInteger(), nullable=False),
        sa.Column("challenge_sequence", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("clinic_id"),
    )
    op.create_table(
        "patient_portal_mycarlos_approval_requests",
        sa.Column("clinic_id", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.String(length=36), nullable=False),
        sa.Column("account_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("demographic_no", sa.Integer(), nullable=False),
        sa.Column("recipient_id", sa.String(length=64), nullable=False),
        sa.Column("candidate_kid", sa.String(length=43), nullable=False),
        sa.Column("predecessor_kid", sa.String(length=43), nullable=True),
        sa.Column("request_sequence", sa.BigInteger(), nullable=False),
        sa.Column("intent", sa.Text(), nullable=False),
        sa.Column("intent_body_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("challenge_id", sa.String(length=43), nullable=True),
        sa.Column("challenge_sequence", sa.BigInteger(), nullable=True),
        sa.Column("challenge", sa.Text(), nullable=True),
        sa.Column("approval_sequence", sa.BigInteger(), nullable=True),
        sa.Column("approval", sa.Text(), nullable=True),
        sa.Column("acceptance", sa.Text(), nullable=True),
        sa.Column("reason", sa.String(length=40), nullable=True),
        sa.Column("decision_body_hash", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(
            ["account_id"], ["patient_portal_accounts.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["patient_portal_mycarlos_devices.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("clinic_id", "request_id"),
        sa.UniqueConstraint("clinic_id", "approval_sequence"),
        sa.UniqueConstraint("clinic_id", "challenge_id"),
        sa.UniqueConstraint("clinic_id", "challenge_sequence"),
        sa.UniqueConstraint("clinic_id", "request_sequence"),
    )


def downgrade() -> None:
    bind = op.get_bind()
    tables = (
        "patient_portal_mycarlos_approval_requests",
        "patient_portal_mycarlos_approval_clinics",
        "patient_portal_mycarlos_mailbox_events",
        "patient_portal_mycarlos_mailbox_blobs",
        "patient_portal_mycarlos_mailbox_anchors",
        "patient_portal_mycarlos_mailbox_rates",
        "patient_portal_mycarlos_mailbox_proofs",
        "patient_portal_mycarlos_mailbox_devices",
        "patient_portal_mycarlos_mailbox_copies",
        "patient_portal_mycarlos_mailbox_clinics",
        "patient_portal_mycarlos_mailbox_accounts",
    )
    if bind.dialect.name == "postgresql":
        # Hold every empty-table decision through DROP; a concurrent device write must not
        # appear between the retention check and schema removal.
        bind.execute(sa.text("LOCK TABLE " + ", ".join(tables) + " IN ACCESS EXCLUSIVE MODE"))
    elif bind.dialect.name != "sqlite":
        raise RuntimeError("unsupported myCarlos storage downgrade dialect")
    for table in tables:
        if bind.scalar(sa.select(sa.func.count()).select_from(sa.table(table))):
            raise RuntimeError("myCarlos retained proof/history rows prevent downgrade")
    for table in tables:
        op.drop_table(table)
