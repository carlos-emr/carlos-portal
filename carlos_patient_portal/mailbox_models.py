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

"""Private M4 ORM source. No migration is assigned or executed by this module.

Primary ciphertext is isolated from durable content-free tombstones and retained
signed proofs. Restrictive foreign keys keep account deletion from bypassing the
single quota/event transition. Human migration/audit-union holds still apply.
"""

from sqlalchemy import BigInteger, Boolean, CheckConstraint, ForeignKey, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from carlos_patient_portal.database import Base


class MailboxClinic(Base):
    __tablename__ = "patient_portal_mycarlos_mailbox_clinics"
    __table_args__ = (CheckConstraint("waiting_bytes>=0 and waiting_count>=0 and ordinary_event_bytes>=0 and terminal_event_bytes>=0 and reserved_terminal_bytes>=0 and event_sequence>=acked_through and acked_through>=retained_floor and retained_floor>=0", name="ck_pp_mailbox_clinic_counters"),)
    clinic_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    waiting_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    waiting_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ordinary_event_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    reserved_terminal_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    terminal_event_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    event_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    acked_through: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    retained_floor: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class MailboxAccount(Base):
    __tablename__ = "patient_portal_mycarlos_mailbox_accounts"
    __table_args__ = (CheckConstraint("waiting_bytes>=0 and waiting_count>=0", name="ck_pp_mailbox_account_counters"),)
    account_id: Mapped[int] = mapped_column(ForeignKey("patient_portal_accounts.id", ondelete="RESTRICT"), primary_key=True)
    waiting_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    waiting_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class MailboxDevice(Base):
    __tablename__ = "patient_portal_mycarlos_mailbox_devices"
    __table_args__ = (CheckConstraint("waiting_bytes>=0 and waiting_count>=0 and delivery_sequence>=0 and anchor_sequence>=0", name="ck_pp_mailbox_device_counters"),)
    device_id: Mapped[int] = mapped_column(ForeignKey("patient_portal_mycarlos_devices.id", ondelete="RESTRICT"), primary_key=True)
    waiting_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    waiting_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    delivery_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    anchor_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    removal_event_recorded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class MailboxCopy(Base):
    __tablename__ = "patient_portal_mycarlos_mailbox_copies"
    __table_args__ = (
        UniqueConstraint("clinic_id", "device_key_id", "delivery_id", name="uq_pp_mailbox_copy_identity"),
        UniqueConstraint("device_id", "sequence", name="uq_pp_mailbox_copy_sequence"),
        CheckConstraint("status in ('waiting','picked_up','expired','removed') and sequence>0 and size between 49 and 20971520 and expires_at>created_at and expires_at-created_at<=604800", name="ck_pp_mailbox_copy_state"),
        CheckConstraint("created_at>=0 and length(recipient_id) between 1 and 64 and length(device_key_id)=43 and length(body_sha256)=64 and length(ciphertext_sha256)=64", name="ck_pp_mailbox_copy_bindings"),
        CheckConstraint("(status='waiting' and terminal_at is null and receipt_sha256 is null) or (status='picked_up' and terminal_at is not null and receipt_sha256 is not null) or (status in ('removed','expired') and terminal_at is not null and receipt_sha256 is null)", name="ck_pp_mailbox_copy_terminal"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("patient_portal_accounts.id", ondelete="RESTRICT"), nullable=False, index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("patient_portal_mycarlos_devices.id", ondelete="RESTRICT"), nullable=False, index=True)
    clinic_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient_id: Mapped[str] = mapped_column(String(64), nullable=False)
    device_key_id: Mapped[str] = mapped_column(String(43), nullable=False)
    delivery_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    body_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    terminal_at: Mapped[int | None] = mapped_column(BigInteger)
    # Exact compact receipt HASH lasts for the entire configured tombstone horizon.
    receipt_sha256: Mapped[str | None] = mapped_column(String(64))


class MailboxBlob(Base):
    __tablename__ = "patient_portal_mycarlos_mailbox_blobs"
    __table_args__ = (CheckConstraint("length(sealed) between 49 and 20971520", name="ck_pp_mailbox_blob_size"),)
    copy_id: Mapped[int] = mapped_column(ForeignKey("patient_portal_mycarlos_mailbox_copies.id", ondelete="RESTRICT"), primary_key=True)
    sealed: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


class MailboxProof(Base):
    """One retained original compact; anchor and event rows refer to it without copying."""
    __tablename__ = "patient_portal_mycarlos_mailbox_proofs"
    __table_args__ = (UniqueConstraint("device_key_id", "sha256", name="uq_pp_mailbox_proof_bytes"), CheckConstraint("length(compact) between 1 and 4096 and length(sha256)=64 and length(device_key_id)=43 and recorded_at>=0", name="ck_pp_mailbox_proof_size"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_key_id: Mapped[str] = mapped_column(String(43), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    compact: Mapped[bytes] = mapped_column(LargeBinary(4096), nullable=False)
    recorded_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class MailboxAnchor(Base):
    __tablename__ = "patient_portal_mycarlos_mailbox_anchors"
    __table_args__ = (UniqueConstraint("device_key_id", "sequence", name="uq_pp_mailbox_anchor_sequence"), UniqueConstraint("device_key_id", "proof_id", name="uq_pp_mailbox_anchor_proof"), CheckConstraint("proof_kind in ('request','receipt') and sequence>0 and length(vault_head_link)=64 and recorded_at>=0", name="ck_pp_mailbox_anchor_kind"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    clinic_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient_id: Mapped[str] = mapped_column(String(64), nullable=False)
    device_key_id: Mapped[str] = mapped_column(String(43), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    vault_head_link: Mapped[str] = mapped_column(String(64), nullable=False)
    recorded_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    proof_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    proof_id: Mapped[int] = mapped_column(ForeignKey("patient_portal_mycarlos_mailbox_proofs.id", ondelete="RESTRICT"), nullable=False)


class MailboxEvent(Base):
    __tablename__ = "patient_portal_mycarlos_mailbox_events"
    __table_args__ = (
        UniqueConstraint("clinic_id", "sequence", name="uq_pp_mailbox_event_sequence"),
        CheckConstraint("kind in ('picked_up','expired','removed','device_removed','anchor') and sequence>0 and charged_bytes between 1 and 16384 and length(payload)<=16384 and occurred_at>=0", name="ck_pp_mailbox_event_kind"),
        CheckConstraint("(kind='picked_up' and delivery_id is not null and budget='terminal' and request_proof_id is not null and receipt_proof_id is not null) or (kind in ('expired','removed') and delivery_id is not null and budget='terminal' and request_proof_id is null and receipt_proof_id is null) or (kind='device_removed' and delivery_id is null and budget='control' and request_proof_id is null and receipt_proof_id is null) or (kind='anchor' and delivery_id is null and budget='ordinary' and request_proof_id is not null and receipt_proof_id is null)", name="ck_pp_mailbox_event_evidence"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    clinic_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    occurred_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    recipient_id: Mapped[str] = mapped_column(String(64), nullable=False)
    device_key_id: Mapped[str] = mapped_column(String(43), nullable=False)
    delivery_id: Mapped[str | None] = mapped_column(String(36))
    # Exact public payload fields except proof strings, resolved from retained proof rows.
    payload: Mapped[bytes] = mapped_column(LargeBinary(16384), nullable=False)
    request_proof_id: Mapped[int | None] = mapped_column(ForeignKey("patient_portal_mycarlos_mailbox_proofs.id", ondelete="RESTRICT"))
    receipt_proof_id: Mapped[int | None] = mapped_column(ForeignKey("patient_portal_mycarlos_mailbox_proofs.id", ondelete="RESTRICT"))
    budget: Mapped[str] = mapped_column(String(16), nullable=False)
    charged_bytes: Mapped[int] = mapped_column(Integer, nullable=False)


class MailboxRate(Base):
    __tablename__ = "patient_portal_mycarlos_mailbox_rates"
    # All updates under the owning clinic mutex; window is a fixed UTC minute.
    clinic_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    bucket: Mapped[str] = mapped_column(String(128), primary_key=True)
    minute: Mapped[int] = mapped_column(BigInteger, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
