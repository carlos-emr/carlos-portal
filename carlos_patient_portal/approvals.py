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

"""Transactional M3 request/proof storage under the existing account/device/clinic order."""

from hashlib import sha256

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from carlos_patient_portal.approval_codec import (
    compact_hash,
    compact_parts,
    device_keys,
    invalid,
    verify_clinic,
    verify_intent,
)
from carlos_patient_portal.approval_models import ApprovalClinic, ApprovalRequest
from carlos_patient_portal.mailbox import LockedMailbox, locked, next_sequence
from carlos_patient_portal.mailbox_codec import MailboxRefusal
from carlos_patient_portal.models import PatientPortalClinicKey

REFUSALS = frozenset(
    {
        "invalid_proof",
        "candidate_changed",
        "binding_changed",
        "predecessor_not_accepted",
        "predecessor_removed",
        "stale_predecessor",
        "challenge_expired",
        "challenge_cancelled",
        "staff_required",
        "no_accepted_approver",
    }
)


def approval_clinic(session: Session, clinic: str) -> ApprovalClinic:
    # Caller already holds the stable M4 clinic mutex through commit, including first insertion.
    row = locked(session, select(ApprovalClinic).where(ApprovalClinic.clinic_id == clinic))
    if row is None:
        row = ApprovalClinic(clinic_id=clinic)
        session.add(row)
        session.flush()
    return row


def scope(m: LockedMailbox, public_base: str) -> dict[str, str]:
    return {"clinic": m.account.clinic_id, "recipient": m.recipient, "public_base": public_base}


def request_row(session: Session, m: LockedMailbox, request_id: str) -> ApprovalRequest:
    row = locked(
        session,
        select(ApprovalRequest).where(
            ApprovalRequest.clinic_id == m.account.clinic_id,
            ApprovalRequest.request_id == request_id,
        ),
    )
    if (
        row is None
        or row.account_id != m.account.id
        or row.recipient_id != m.recipient
        or row.demographic_no != m.account.demographic_no
    ):
        raise invalid("approval_not_found", 404)
    return row


def candidate_request(
    session: Session, m: LockedMailbox, *, intent: str, body: bytes, public_base: str, now: int
) -> tuple[dict, int]:
    value = verify_intent(intent, **scope(m, public_base))
    if device_keys(value) != (
        m.device.device_key_id,
        m.device.x25519_public_key,
        m.device.ed25519_public_key,
    ):
        raise invalid("approval_conflict", 409)
    prior = session.get(ApprovalRequest, (m.account.clinic_id, value["request_id"]))
    digest = sha256(body).hexdigest()
    if prior is not None:
        if (
            prior.device_id != m.device.id
            or prior.intent != intent
            or prior.intent_body_hash != digest
        ):
            raise invalid("approval_conflict", 409)
        return status_payload(prior), 200
    if value["iat"] > now + 30 or value["exp"] <= now:
        raise invalid("approval_expired", 410)
    count = session.scalar(
        select(func.count())
        .select_from(ApprovalRequest)
        .where(
            ApprovalRequest.account_id == m.account.id,
            ApprovalRequest.status.in_(("pending", "challenge_ready")),
            ApprovalRequest.expires_at > now,
        )
    )
    if count is None or count >= 50:
        raise invalid("approval_unavailable", 429)
    from carlos_patient_portal.mailbox import rate

    try:
        rate(session, m.clinic, "approval-candidate:" + m.device.device_key_id, now=now, maximum=5)
    except MailboxRefusal as exc:
        if exc.code == "mailbox_quota_exceeded":
            raise invalid("approval_unavailable", 429) from exc
        raise
    clinic = approval_clinic(session, m.account.clinic_id)
    row = ApprovalRequest(
        clinic_id=m.account.clinic_id,
        request_id=value["request_id"],
        account_id=m.account.id,
        device_id=m.device.id,
        demographic_no=m.account.demographic_no,
        recipient_id=m.recipient,
        candidate_kid=m.device.device_key_id,
        predecessor_kid=value["predecessor_device_key_id"],
        request_sequence=next_sequence(clinic, "request_sequence"),
        intent=intent,
        intent_body_hash=digest,
        expires_at=value["exp"],
        status="pending",
    )
    session.add(row)
    session.flush()
    return status_payload(row), 201


def status_payload(row: ApprovalRequest) -> dict:
    return {
        "request_id": row.request_id,
        "status": row.status,
        "challenge": row.challenge,
        "acceptance": row.acceptance,
        "reason": row.reason,
    }


def clinic_object(
    session: Session, m: LockedMailbox, kind: str, compact: str, public_base: str
) -> dict:
    value, _, _ = compact_parts(compact)
    from carlos_patient_portal.mailbox_codec import canonical_key

    if not canonical_key(value.get("kid")):
        raise invalid()
    key = session.scalar(
        select(PatientPortalClinicKey).where(
            PatientPortalClinicKey.clinic_id == m.account.clinic_id,
            PatientPortalClinicKey.kid == value.get("kid"),
            PatientPortalClinicKey.status == "active",
        )
    )
    if key is None:
        raise invalid()
    return verify_clinic(kind, compact, spki=key.spki, **scope(m, public_base))


def publish_challenge(
    session: Session,
    m: LockedMailbox,
    row: ApprovalRequest,
    *,
    intent: str,
    challenge: str,
    public_base: str,
    now: int,
) -> None:
    if row.device_id != m.device.id or intent != row.intent:
        raise invalid("approval_conflict", 409)
    if row.challenge is not None:
        if row.challenge != challenge:
            raise invalid("approval_conflict", 409)
        return
    value = clinic_object(session, m, "challenge", challenge, public_base)
    original = verify_intent(intent, **scope(m, public_base))
    for field in (
        "request_id",
        "candidate_device_key_id",
        "candidate_x25519_public_key",
        "candidate_ed25519_public_key",
        "predecessor_device_key_id",
    ):
        if value[field] != original[field]:
            raise invalid("approval_conflict", 409)
    if value["candidate_intent_sha256"] != compact_hash(intent) or value["expires_at"] != min(
        value["issued_at"] + 600, original["exp"]
    ):
        raise invalid("approval_conflict", 409)
    if row.status != "pending" or value["issued_at"] > now + 30 or value["expires_at"] <= now:
        raise invalid("approval_expired", 410)
    # A challenge ID names one request per clinic. The caller holds the clinic mutex, so this
    # check can't race; without it a reused ID reached the unique constraint as a 500.
    taken = session.scalar(
        select(ApprovalRequest.request_id).where(
            ApprovalRequest.clinic_id == m.account.clinic_id,
            ApprovalRequest.challenge_id == value["challenge_id"],
        )
    )
    if taken is not None:
        raise invalid("approval_conflict", 409)
    row.challenge_id, row.challenge = value["challenge_id"], challenge
    row.challenge_sequence = next_sequence(
        approval_clinic(session, m.account.clinic_id), "challenge_sequence"
    )
    row.status = "challenge_ready"
    row.expires_at = value["expires_at"]


def publish_decision(
    session: Session,
    m: LockedMailbox,
    row: ApprovalRequest,
    *,
    value: dict,
    body: bytes,
    public_base: str,
) -> None:
    if (
        row.device_id != m.device.id
        or value["challenge_id"] != row.challenge_id
        or row.challenge is None
    ):
        raise invalid("approval_conflict", 409)
    digest = sha256(body).hexdigest()
    if row.decision_body_hash is not None:
        if row.decision_body_hash != digest:
            raise invalid("approval_conflict", 409)
        return
    status, acceptance, reason = value["status"], value["acceptance"], value["reason"]
    if status == "accepted":
        if reason is not None or not isinstance(acceptance, str):
            raise invalid()
        receipt = clinic_object(session, m, "acceptance", acceptance, public_base)
        challenge = clinic_object(session, m, "challenge", row.challenge, public_base)
        for field in (
            "request_id",
            "challenge_id",
            "candidate_device_key_id",
            "candidate_x25519_public_key",
            "candidate_ed25519_public_key",
            "approval_kind",
            "predecessor_device_key_id",
        ):
            if receipt[field] != challenge[field]:
                raise invalid("approval_conflict", 409)
        if receipt["challenge_sha256"] != compact_hash(row.challenge) or (
            receipt["approval_sha256"]
            != (None if row.approval is None else compact_hash(row.approval))
        ):
            raise invalid("approval_conflict", 409)
    elif (
        not isinstance(status, str)
        or status not in {"refused", "expired", "cancelled"}
        or acceptance is not None
        or not isinstance(reason, str)
        or reason not in REFUSALS
    ):
        raise invalid()
    row.status, row.acceptance, row.reason, row.decision_body_hash = (
        status,
        acceptance,
        reason,
        digest,
    )
