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

"""M3 durable opaque proofs, isolated from primary document ciphertext.

Deployment migration/grants remain a reviewed proposal. Tests create only owned tables.
"""

from sqlalchemy import BigInteger, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from carlos_patient_portal.models import PatientPortalAccount, PatientPortalMyCarlosDevice


class ApprovalBase(DeclarativeBase):
    pass


class ApprovalClinic(ApprovalBase):
    __tablename__ = "patient_portal_mycarlos_approval_clinics"
    clinic_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_sequence: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    approval_sequence: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    challenge_sequence: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)


class ApprovalRequest(ApprovalBase):
    __tablename__ = "patient_portal_mycarlos_approval_requests"
    __table_args__ = (
        UniqueConstraint("clinic_id", "request_sequence"),
        UniqueConstraint("clinic_id", "challenge_id"),
        UniqueConstraint("clinic_id", "challenge_sequence"),
        UniqueConstraint("clinic_id", "approval_sequence"),
    )
    clinic_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_id: Mapped[int] = mapped_column(
        ForeignKey(PatientPortalAccount.__table__.c.id, ondelete="RESTRICT"), nullable=False
    )
    device_id: Mapped[int] = mapped_column(
        ForeignKey(PatientPortalMyCarlosDevice.__table__.c.id, ondelete="RESTRICT"), nullable=False
    )
    demographic_no: Mapped[int] = mapped_column(Integer, nullable=False)
    recipient_id: Mapped[str] = mapped_column(String(64), nullable=False)
    candidate_kid: Mapped[str] = mapped_column(String(43), nullable=False)
    predecessor_kid: Mapped[str | None] = mapped_column(String(43))
    request_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    intent: Mapped[str] = mapped_column(Text, nullable=False)
    intent_body_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    challenge_id: Mapped[str | None] = mapped_column(String(43))
    challenge_sequence: Mapped[int | None] = mapped_column(BigInteger)
    challenge: Mapped[str | None] = mapped_column(Text)
    approval_sequence: Mapped[int | None] = mapped_column(BigInteger)
    approval: Mapped[str | None] = mapped_column(Text)
    acceptance: Mapped[str | None] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(String(40))
    decision_body_hash: Mapped[str | None] = mapped_column(String(64))
