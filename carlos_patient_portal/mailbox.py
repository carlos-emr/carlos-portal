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

"""M4 transactional opaque mailbox. Caller commits before replying or performing I/O.

Every transition follows Account -> Device -> stable clinic mutex -> account quota
-> copy. No network calls, document decryption, or clinical verification occurs here.
The ORM is private source pending the held migration and real PostgreSQL race tests.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from secrets import compare_digest
from time import time
from typing import TypeVar

from sqlalchemy import Select, delete, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal.mailbox_codec import (
    LONG_MAX,
    MailboxRefusal,
    Upload,
    json_bytes,
    receipt_claims,
    uuid_text,
)
from carlos_patient_portal.mailbox_models import (
    MailboxAccount,
    MailboxAnchor,
    MailboxBlob,
    MailboxClinic,
    MailboxCopy,
    MailboxDevice,
    MailboxEvent,
    MailboxProof,
    MailboxRate,
)
from carlos_patient_portal.models import PatientPortalAccount, PatientPortalMyCarlosDevice
from carlos_patient_portal.mycarlos_devices import recipient_id_for_account

TERMINAL_RESERVATION = 16384
_MailboxRow = TypeVar("_MailboxRow")


@dataclass(frozen=True)
class MailboxLimits:
    device_bytes: int = 268435456
    account_bytes: int = 1073741824
    clinic_bytes: int = 21474836480
    device_copies: int = 100
    account_copies: int = 500
    clinic_copies: int = 20000
    ordinary_event_bytes: int = 536870912
    clinic_uploads_per_minute: int = 60
    clinic_upload_bytes_per_minute: int = 268435456
    device_lists_per_minute: int = 60
    device_downloads_per_minute: int = 60
    device_receipts_per_minute: int = 120
    clinic_sync_pages_per_minute: int = 120


DEFAULT_MAILBOX_LIMITS = MailboxLimits()


@dataclass
class LockedMailbox:
    account: PatientPortalAccount
    device: PatientPortalMyCarlosDevice
    recipient: str
    clinic: MailboxClinic
    account_quota: MailboxAccount
    device_quota: MailboxDevice


def locked(session: Session, statement: Select[tuple[_MailboxRow]]) -> _MailboxRow | None:
    return session.scalar(statement.with_for_update().execution_options(populate_existing=True))


def clinic_lock(session: Session, clinic_id: str) -> MailboxClinic:
    # A stable xact advisory lock exists BEFORE the first quota/counter row exists.
    if session.get_bind().dialect.name == "postgresql":
        lock_id = int.from_bytes(
            sha256(b"mycarlos-mailbox-v1\0" + clinic_id.encode("utf-8")).digest()[:8],
            "big",
            signed=True,
        )
        session.execute(text("select pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id})
    row = locked(session, select(MailboxClinic).where(MailboxClinic.clinic_id == clinic_id))
    if row is None:
        row = MailboxClinic(clinic_id=clinic_id)
        session.add(row)
        session.flush()
    return row


def mailbox_lock(
    session: Session,
    *,
    account_id: int,
    device_key_id: str,
    clinic_id: str | None = None,
    allow_removed: bool = False,
    removed_status: int = 403,
) -> LockedMailbox:
    account = locked(
        session, select(PatientPortalAccount).where(PatientPortalAccount.id == account_id)
    )
    if account is None or (clinic_id is not None and account.clinic_id != clinic_id):
        raise MailboxRefusal("delivery_not_found", 404)
    device = locked(
        session,
        select(PatientPortalMyCarlosDevice).where(
            PatientPortalMyCarlosDevice.account_id == account.id,
            PatientPortalMyCarlosDevice.device_key_id == device_key_id,
        ),
    )
    recipient = recipient_id_for_account(session, account.id)
    if device is None or recipient is None:
        raise MailboxRefusal("delivery_not_found", 404)
    if not allow_removed and device.status != "active":
        raise MailboxRefusal("device_removed", removed_status)
    clinic = clinic_lock(session, account.clinic_id)
    account_quota = locked(
        session, select(MailboxAccount).where(MailboxAccount.account_id == account.id)
    )
    if account_quota is None:
        account_quota = MailboxAccount(account_id=account.id)
        session.add(account_quota)
        session.flush()
    device_quota = session.get(MailboxDevice, device.id, populate_existing=True)
    if device_quota is None:
        device_quota = MailboxDevice(device_id=device.id)
        session.add(device_quota)
        session.flush()
    return LockedMailbox(account, device, recipient, clinic, account_quota, device_quota)


def next_sequence(row: MailboxClinic | MailboxDevice, name: str) -> int:
    value = getattr(row, name)
    if value >= LONG_MAX:
        raise MailboxRefusal("mailbox_quota_exceeded", 429)
    setattr(row, name, value + 1)
    return value + 1


def admission_event_budget(clinic: MailboxClinic, limits: MailboxLimits, *, extra: int) -> None:
    """Finite queue envelope derived from ordinary cap + upload reservation pool.

    Completing a pre-reserved copy replaces its16KiB reservation with <=16KiB
    terminal evidence, so cannot increase this envelope. New uploads/ordinary
    anchors must wait for collection/pruning once terminal evidence fills it.
    One-per-existing-device removal controls remain the frozen explicit exception.
    """
    ceiling = limits.ordinary_event_bytes + limits.clinic_copies * TERMINAL_RESERVATION
    queued = (
        clinic.ordinary_event_bytes + clinic.terminal_event_bytes + clinic.reserved_terminal_bytes
    )
    if queued + extra > ceiling:
        raise MailboxRefusal("mailbox_quota_exceeded", 429)


def rate(
    session: Session,
    clinic: MailboxClinic,
    bucket: str,
    *,
    now: int,
    maximum: int,
    byte_count: int = 0,
    maximum_bytes: int = LONG_MAX,
) -> None:
    row = session.get(MailboxRate, (clinic.clinic_id, bucket), populate_existing=True)
    minute = now // 60
    if row is None:
        row = MailboxRate(
            clinic_id=clinic.clinic_id, bucket=bucket, minute=minute, count=0, bytes=0
        )
        session.add(row)
    if row.minute != minute:
        row.minute, row.count, row.bytes = minute, 0, 0
    if row.count >= maximum or row.bytes + byte_count > maximum_bytes:
        raise MailboxRefusal("mailbox_quota_exceeded", 429)
    row.count += 1
    row.bytes += byte_count


def outer_record(copy: MailboxCopy) -> dict:
    return {
        "v": 1,
        "suite": {"kem_id": 32, "kdf_id": 1, "aead_id": 3},
        **{
            key: getattr(copy, key)
            for key in (
                "delivery_id",
                "recipient_id",
                "device_key_id",
                "size",
                "ciphertext_sha256",
                "created_at",
                "expires_at",
            )
        },
    }


def copy_lock(session: Session, m: LockedMailbox, delivery_id: str) -> MailboxCopy | None:
    if not uuid_text(delivery_id, version4=True):
        raise MailboxRefusal("delivery_not_found", 404)
    return locked(
        session,
        select(MailboxCopy).where(
            MailboxCopy.clinic_id == m.account.clinic_id,
            MailboxCopy.device_key_id == m.device.device_key_id,
            MailboxCopy.delivery_id == delivery_id,
        ),
    )


def retain_proof(session: Session, m: LockedMailbox, compact: str, now: int) -> MailboxProof:
    raw = compact.encode("ascii")
    if not 1 <= len(raw) <= 4096:
        raise MailboxRefusal("invalid_assertion", 404)
    digest = sha256(raw).hexdigest()
    row = session.scalar(
        select(MailboxProof).where(
            MailboxProof.device_key_id == m.device.device_key_id, MailboxProof.sha256 == digest
        )
    )
    if row is None:
        row = MailboxProof(
            device_key_id=m.device.device_key_id, sha256=digest, compact=raw, recorded_at=now
        )
        session.add(row)
        session.flush()
    return row


def proof_anchor(
    session: Session, m: LockedMailbox, *, compact: str, anchor: str, kind: str, now: int
) -> MailboxProof:
    proof = retain_proof(session, m, compact, now)
    previous = session.scalar(
        select(MailboxAnchor.id).where(
            MailboxAnchor.device_key_id == m.device.device_key_id,
            MailboxAnchor.proof_id == proof.id,
        )
    )
    if previous is None:
        session.add(
            MailboxAnchor(
                clinic_id=m.account.clinic_id,
                recipient_id=m.recipient,
                device_key_id=m.device.device_key_id,
                sequence=next_sequence(m.device_quota, "anchor_sequence"),
                vault_head_link=anchor,
                recorded_at=now,
                proof_kind=kind,
                proof_id=proof.id,
            )
        )
    return proof


def event_payload(session: Session, event: MailboxEvent) -> dict:
    payload = json.loads(event.payload)
    for field, proof_id in (
        ("request_assertion", event.request_proof_id),
        ("receipt", event.receipt_proof_id),
    ):
        if proof_id is not None:
            proof = session.get(MailboxProof, proof_id)
            if proof is None:
                raise RuntimeError("Missing retained mailbox proof")
            payload[field] = proof.compact.decode("ascii")
    return {
        "sequence": str(event.sequence),
        "kind": event.kind,
        "occurred_at": event.occurred_at,
        "recipient_id": event.recipient_id,
        "device_key_id": event.device_key_id,
        "delivery_id": event.delivery_id,
        "payload": payload,
    }


def append_event(
    session: Session,
    m: LockedMailbox,
    *,
    kind: str,
    payload: dict,
    now: int,
    delivery_id: str | None = None,
    budget: str = "ordinary",
    request_proof: MailboxProof | None = None,
    receipt_proof: MailboxProof | None = None,
    limits: MailboxLimits = DEFAULT_MAILBOX_LIMITS,
) -> None:
    event = MailboxEvent(
        clinic_id=m.account.clinic_id,
        sequence=next_sequence(m.clinic, "event_sequence"),
        kind=kind,
        occurred_at=now,
        recipient_id=m.recipient,
        device_key_id=m.device.device_key_id,
        delivery_id=delivery_id,
        payload=json_bytes(payload),
        budget=budget,
        charged_bytes=1,
        request_proof_id=request_proof.id if request_proof else None,
        receipt_proof_id=receipt_proof.id if receipt_proof else None,
    )
    # Proofs stored once; anchor indices retain them independently from event collection.
    public_size = len(json_bytes(event_payload(session, event)))
    storage_cost = (
        len(event.payload)
        + 512
        + sum(len(p.compact) + 256 for p in (request_proof, receipt_proof) if p is not None)
    )
    if public_size > TERMINAL_RESERVATION or storage_cost > TERMINAL_RESERVATION:
        raise RuntimeError("Mailbox event exceeded reserved proof budget")
    event.charged_bytes = storage_cost
    if budget == "ordinary":
        if m.clinic.ordinary_event_bytes + storage_cost > limits.ordinary_event_bytes:
            raise MailboxRefusal("mailbox_quota_exceeded", 429)
        admission_event_budget(m.clinic, limits, extra=storage_cost)
        m.clinic.ordinary_event_bytes += storage_cost
    elif budget == "terminal":
        m.clinic.terminal_event_bytes += storage_cost
    # One control event per removed device is allowed beyond the ordinary soft cap.
    session.add(event)


def record_request_anchor(
    session: Session,
    m: LockedMailbox,
    *,
    compact: str,
    anchor: str | None,
    now: int,
    limits: MailboxLimits,
) -> bool:
    if anchor is None:
        return False
    proof = proof_anchor(session, m, compact=compact, anchor=anchor, kind="request", now=now)
    append_event(
        session,
        m,
        kind="anchor",
        payload={"vault_head_link": anchor},
        now=now,
        request_proof=proof,
        limits=limits,
    )
    return True


def admit_upload(
    session: Session, m: LockedMailbox, upload: Upload, *, now: int, limits: MailboxLimits
) -> tuple[dict, int]:
    value = upload.outer
    if value["recipient_id"] != m.recipient or value["device_key_id"] != m.device.device_key_id:
        raise MailboxRefusal("delivery_not_found", 404)
    previous = copy_lock(session, m, value["delivery_id"])
    if previous is not None:
        if not compare_digest(previous.body_sha256, upload.body_sha256):
            raise MailboxRefusal("delivery_conflict", 409)
        return {
            "delivery_id": previous.delivery_id,
            "device_key_id": previous.device_key_id,
            "status": previous.status,
        }, 200
    if value["created_at"] > now + 30 or value["expires_at"] <= now:
        raise MailboxRefusal("invalid_delivery")
    for row, max_bytes, max_copies in (
        (m.device_quota, limits.device_bytes, limits.device_copies),
        (m.account_quota, limits.account_bytes, limits.account_copies),
        (m.clinic, limits.clinic_bytes, limits.clinic_copies),
    ):
        if row.waiting_bytes + value["size"] > max_bytes or row.waiting_count >= max_copies:
            raise MailboxRefusal("mailbox_quota_exceeded", 429)
    rate(
        session,
        m.clinic,
        "uploads",
        now=now,
        maximum=limits.clinic_uploads_per_minute,
        byte_count=value["size"],
        maximum_bytes=limits.clinic_upload_bytes_per_minute,
    )
    if m.clinic.ordinary_event_bytes >= limits.ordinary_event_bytes:
        raise MailboxRefusal("mailbox_quota_exceeded", 429)
    admission_event_budget(m.clinic, limits, extra=TERMINAL_RESERVATION)
    row = MailboxCopy(
        account_id=m.account.id,
        device_id=m.device.id,
        clinic_id=m.account.clinic_id,
        sequence=next_sequence(m.device_quota, "delivery_sequence"),
        body_sha256=upload.body_sha256,
        status="waiting",
        **{
            key: value[key]
            for key in (
                "recipient_id",
                "device_key_id",
                "delivery_id",
                "size",
                "ciphertext_sha256",
                "created_at",
                "expires_at",
            )
        },
    )
    session.add(row)
    session.flush()
    session.add(MailboxBlob(copy_id=row.id, sealed=upload.sealed))
    for counter in (m.device_quota, m.account_quota, m.clinic):
        counter.waiting_bytes += row.size
        counter.waiting_count += 1
    m.clinic.reserved_terminal_bytes += TERMINAL_RESERVATION
    return {
        "delivery_id": row.delivery_id,
        "device_key_id": row.device_key_id,
        "status": "waiting",
    }, 201


def terminate(
    session: Session,
    m: LockedMailbox,
    copy: MailboxCopy,
    *,
    status: str,
    now: int,
    request_proof: MailboxProof | None = None,
    receipt_proof: MailboxProof | None = None,
) -> None:
    if copy.status != "waiting":
        return
    removed = session.execute(delete(MailboxBlob).where(MailboxBlob.copy_id == copy.id))
    if removed.rowcount != 1:
        raise RuntimeError("Waiting copy lacks its single primary blob")
    copy.status, copy.terminal_at = status, now
    if receipt_proof is not None:
        copy.receipt_sha256 = receipt_proof.sha256
    for counter in (m.device_quota, m.account_quota, m.clinic):
        counter.waiting_bytes -= copy.size
        counter.waiting_count -= 1
    m.clinic.reserved_terminal_bytes -= TERMINAL_RESERVATION
    append_event(
        session,
        m,
        kind=status,
        payload={
            key: getattr(copy, key)
            for key in ("ciphertext_sha256", "size", "created_at", "expires_at")
        },
        now=now,
        delivery_id=copy.delivery_id,
        budget="terminal",
        request_proof=request_proof,
        receipt_proof=receipt_proof,
    )


def accept_receipt(
    session: Session,
    m: LockedMailbox,
    *,
    delivery_id: str,
    compact: str,
    request_assertion: str,
    request_anchor: str | None,
    clock: Callable[[], int | float] = time,
    limits: MailboxLimits,
) -> dict:
    copy = copy_lock(session, m, delivery_id)
    # Sample only AFTER all transition locks, immediately before the decision/write.
    now = int(clock())
    if copy is None or copy.status != "waiting":
        if (
            copy is not None
            and copy.receipt_sha256 is not None
            and compare_digest(copy.receipt_sha256, sha256(compact.encode("ascii")).hexdigest())
        ):
            record_request_anchor(
                session, m, compact=request_assertion, anchor=request_anchor, now=now, limits=limits
            )
            return {"status": "picked_up"}
        raise MailboxRefusal("delivery_not_found", 404)
    if copy.expires_at <= now:
        # Refusal itself does not mutate; the bounded expiry worker owns that transition.
        raise MailboxRefusal("delivery_not_found", 404)
    claims = receipt_claims(
        compact, key=m.device.ed25519_public_key, kid=m.device.device_key_id, recipient=m.recipient
    )
    if (
        claims["delivery_id"] != delivery_id
        or claims["ciphertext_sha256"] != copy.ciphertext_sha256
    ):
        raise MailboxRefusal("receipt_mismatch", 409)
    now = int(clock())
    if copy.expires_at <= now:
        raise MailboxRefusal("delivery_not_found", 404)
    receipt = proof_anchor(
        session, m, compact=compact, anchor=claims["vault_head_link"], kind="receipt", now=now
    )
    request = retain_proof(session, m, request_assertion, now)
    if request_anchor is not None:
        proof_anchor(
            session, m, compact=request_assertion, anchor=request_anchor, kind="request", now=now
        )
    terminate(
        session, m, copy, status="picked_up", now=now, request_proof=request, receipt_proof=receipt
    )
    # Valid security transitions consume their reservation even at ordinary-event cap.
    return {"status": "picked_up"}


def remove_waiting(session: Session, m: LockedMailbox, *, now: int) -> None:
    if not m.device_quota.removal_event_recorded:
        append_event(session, m, kind="device_removed", payload={}, now=now, budget="control")
        m.device_quota.removal_event_recorded = True
    copies = list(
        session.scalars(
            select(MailboxCopy)
            .where(MailboxCopy.device_id == m.device.id, MailboxCopy.status == "waiting")
            .order_by(MailboxCopy.delivery_id)
            .with_for_update()
        )
    )
    for copy in copies:
        terminate(session, m, copy, status="removed", now=now)


def events_page(
    session: Session,
    clinic: MailboxClinic,
    *,
    after: int,
    limit: int,
    now: int,
    limits: MailboxLimits,
) -> dict:
    if after > clinic.event_sequence:
        raise MailboxRefusal("invalid_cursor")
    if after < clinic.retained_floor:
        raise MailboxRefusal("cursor_too_old", 409)
    rate(session, clinic, "events", now=now, maximum=limits.clinic_sync_pages_per_minute)
    rows = list(
        session.scalars(
            select(MailboxEvent)
            .where(MailboxEvent.clinic_id == clinic.clinic_id, MailboxEvent.sequence > after)
            .order_by(MailboxEvent.sequence)
            .limit(limit + 1)
        )
    )
    selected = rows[:limit]
    last = selected[-1].sequence if selected else after
    content = {
        "events": [event_payload(session, row) for row in selected],
        "last_sequence": str(last),
        "next_cursor": str(last) if len(rows) > limit else None,
    }
    if len(json_bytes(content)) > 1048576:
        raise RuntimeError("Bounded event page exceeded frozen byte limit")
    return content


def acknowledge_events(session: Session, clinic: MailboxClinic, *, through: int) -> dict:
    if through > clinic.event_sequence:
        raise MailboxRefusal("invalid_cursor")
    if through > clinic.acked_through:
        # Budget measures UNACKNOWLEDGED evidence, not physically retained audit
        # proof storage. Release exactly the newly collected prefix in this commit.
        # Clinic mutex excludes append/prune writers until all counters+ack commit.
        released = session.execute(
            select(MailboxEvent.budget, func.sum(MailboxEvent.charged_bytes))
            .where(
                MailboxEvent.clinic_id == clinic.clinic_id,
                MailboxEvent.sequence > clinic.acked_through,
                MailboxEvent.sequence <= through,
            )
            .group_by(MailboxEvent.budget)
        )
        for budget, byte_count in released:
            if budget == "ordinary":
                clinic.ordinary_event_bytes -= int(byte_count)
            elif budget == "terminal":
                clinic.terminal_event_bytes -= int(byte_count)
        clinic.acked_through = through
    # Collection does not delete proof/receipt/tombstone evidence. Pruning is separate.
    return {"acked_through": str(clinic.acked_through)}


def prune_collected_events(session: Session, clinic: MailboxClinic, *, limit: int = 100) -> int:
    """Bounded acknowledged-prefix pruning; independent proofs/anchors stay retained."""
    rows = list(
        session.scalars(
            select(MailboxEvent)
            .where(
                MailboxEvent.clinic_id == clinic.clinic_id,
                MailboxEvent.sequence <= clinic.acked_through,
            )
            .order_by(MailboxEvent.sequence)
            .limit(limit)
        )
    )
    for row in rows:
        # Acknowledgment already released this prefix. Never subtract it twice.
        clinic.retained_floor = row.sequence
        session.delete(row)
    return len(rows)


def expire_batch(
    session_factory: sessionmaker[Session],
    *,
    limit: int = 100,
    clock: Callable[[], int | float] = time,
) -> int:
    # Candidate SELECT takes NO delivery lock. Each owned transition gets full normal order.
    with session_factory() as session:
        candidates = list(
            session.execute(
                select(MailboxCopy.account_id, MailboxCopy.device_key_id, MailboxCopy.delivery_id)
                .where(MailboxCopy.status == "waiting", MailboxCopy.expires_at <= int(clock()))
                .order_by(MailboxCopy.expires_at, MailboxCopy.id)
                .limit(limit)
            )
        )
    expired = 0
    for account_id, kid, delivery_id in candidates:
        with session_factory() as session, session.begin():
            m = mailbox_lock(session, account_id=account_id, device_key_id=kid, allow_removed=True)
            copy = copy_lock(session, m, delivery_id)
            now = int(clock())
            if copy is not None and copy.status == "waiting":
                if m.device.status != "active":
                    remove_waiting(session, m, now=now)
                elif copy.expires_at <= now:
                    terminate(session, m, copy, status="expired", now=now)
                    expired += 1
    return expired
