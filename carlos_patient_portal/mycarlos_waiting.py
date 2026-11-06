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

"""The waiting key: "is anything waiting for this device?" for a locked myCarlos (carlos-portal#87).

myCarlos's tray mode locks the vault, and the device key is inside it, so a locked app cannot
sign a device request. It holds a second, separate Ed25519 key instead, registered by the
unlocked device (signed with its device key) and bound to that device row, so to one link. That
key can do exactly one thing: ask whether a not-expired mailbox copy is waiting for the device,
and get yes or no, at most once every 120 seconds. Its assertions name their own audience, so a
waiting assertion never passes as a device assertion, nor the reverse; its key id is hashed
under its own label, so it never names a device. The portal stores only public keys.

("Notice key" in the design note. The portal already uses that name, and the label
`mycarlos-notice-v1`, for its own HMAC notice secrets, so the code says "waiting key".)
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from hmac import compare_digest
from math import ceil

from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal.device_identity import (
    DEVICE_CLOCK_SKEW_SECONDS,
    REFUSAL_DEVICE_REMOVED,
    REFUSAL_EXPIRED,
    REFUSAL_INVALID_ASSERTION,
    REFUSAL_UNKNOWN_DEVICE,
    DeviceRefusal,
    _check_claims,
    _check_request_hash,
    _parse_compact,
    _strict_b64url,
    _verify_signature,
    b64url,
)
from carlos_patient_portal.mailbox_models import MailboxCopy
from carlos_patient_portal.models import (
    MYCARLOS_DEVICE_STATUS_ACTIVE,
    MYCARLOS_PUBLIC_KEY_LENGTH,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosWaitingKey,
)
from carlos_patient_portal.mycarlos_availability import AvailabilityError, Owner
from carlos_patient_portal.staff_identity import (
    AssertionExpiredError,
    AssertionReplayError,
    consume_assertion_id,
)

WAITING_KEYS_PATH = "/api/mycarlos/availability/waiting-keys"
WAITING_PATH = "/api/mycarlos/availability/waiting"
WAITING_ASSERTION_HEADER = "X-MyCarlos-Waiting-Assertion"
WAITING_AUDIENCE = "carlos-patient-portal-waiting-check"
WAITING_KEY_ID_LABEL = b"mycarlos-waiting-key-v1"
WAITING_ALGORITHM = "ed25519"
WAITING_CLAIMS = frozenset({"aud", "iss", "kid", "jti", "iat", "exp", "request_hash"})
MAX_WAITING_ASSERTION_LIFETIME_SECONDS = 60
ANSWER_SPACING_SECONDS = 120
REGISTRATION_FIELDS = frozenset({"key_id", "public_key", "alg"})
CHECK_FIELDS = frozenset({"key_id"})
# Both answers are exactly 17 bytes, so their size never tells them apart.
ANSWER_WAITING = b'{"waiting": true}'
ANSWER_NOTHING = b'{"waiting":false}'


class WaitingRefusal(AvailabilityError):
    """A refused waiting-key request; `code` is safe to return."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class TooSoon(Exception):
    """Less than 120 seconds since this key's last answer."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(retry_after)
        self.retry_after = retry_after


def waiting_key_id(public_key: bytes) -> str:
    """b64url(SHA-256("mycarlos-waiting-key-v1" || frame(Ed25519 key))), 43 chars.

    The same framing as `device_key_id`, under its own label: a waiting key id never names a
    device, and a device key id never names a waiting key.
    """
    digest = sha256(WAITING_KEY_ID_LABEL)
    digest.update(len(public_key).to_bytes(8, "big"))
    digest.update(public_key)
    return b64url(digest.digest())


def _json_object(body: bytes, fields: frozenset[str]) -> dict[str, object]:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise WaitingRefusal("invalid_waiting_key") from None
    if not isinstance(value, dict) or set(value) != fields:
        raise WaitingRefusal("invalid_waiting_key")
    return value


def parse_registration(body: bytes) -> tuple[str, bytes]:
    """The exact three fields: the key id, the 32-byte public key, and "ed25519"."""
    value = _json_object(body, REGISTRATION_FIELDS)
    key_id, encoded, algorithm = value["key_id"], value["public_key"], value["alg"]
    if type(key_id) is not str or type(encoded) is not str or algorithm != WAITING_ALGORITHM:
        raise WaitingRefusal("invalid_waiting_key")
    try:
        public_key = _strict_b64url(encoded, expected_length=MYCARLOS_PUBLIC_KEY_LENGTH)
    except DeviceRefusal:
        raise WaitingRefusal("invalid_waiting_key") from None
    if not compare_digest(key_id, waiting_key_id(public_key)):
        raise WaitingRefusal("invalid_waiting_key")
    return key_id, public_key


def parse_check(body: bytes) -> str:
    """The waiting check's body: exactly {"key_id": ...}."""
    value = _json_object(body, CHECK_FIELDS)
    if type(value["key_id"]) is not str:
        raise WaitingRefusal("invalid_waiting_key")
    return value["key_id"]


def _locked_active_device(session: Session, owner: Owner) -> PatientPortalMyCarlosDevice:
    device = session.scalars(
        select(PatientPortalMyCarlosDevice)
        .where(
            PatientPortalMyCarlosDevice.id == owner.device_id,
            PatientPortalMyCarlosDevice.account_id == owner.account_id,
        )
        .with_for_update()
    ).first()
    if device is None or device.status != MYCARLOS_DEVICE_STATUS_ACTIVE:
        raise WaitingRefusal("device_inactive")
    return device


def _live_key(session: Session, device_id: int) -> PatientPortalMyCarlosWaitingKey | None:
    return session.scalars(
        select(PatientPortalMyCarlosWaitingKey)
        .where(
            PatientPortalMyCarlosWaitingKey.device_id == device_id,
            PatientPortalMyCarlosWaitingKey.revoked_at.is_(None),
        )
        .with_for_update()
    ).first()


def _revoke(row: PatientPortalMyCarlosWaitingKey, by: str, now: datetime) -> None:
    if row.revoked_at is None:
        row.revoked_at = now
        row.revoked_by = by


def register(
    session: Session,
    owner: Owner,
    key_id: str,
    public_key: bytes,
    *,
    now: datetime | None = None,
) -> tuple[PatientPortalMyCarlosWaitingKey, bool]:
    """Registers this device's waiting key; the row and whether it is new.

    The same live key again is returned unchanged. A different key replaces the live one, which
    stays as a tombstone. A key id ever used before, by any device, or revoked, is refused: a
    revoked key never comes back. The device's own key is refused too.
    """
    if not session.in_transaction():
        raise AvailabilityError("transaction_required")
    current = now or datetime.now(UTC)
    device = _locked_active_device(session, owner)
    if compare_digest(public_key, device.ed25519_public_key):
        raise WaitingRefusal("invalid_waiting_key")
    live = _live_key(session, device.id)
    if live is not None and live.key_id == key_id:
        return live, False
    known = session.scalars(
        select(PatientPortalMyCarlosWaitingKey).where(
            PatientPortalMyCarlosWaitingKey.key_id == key_id
        )
    ).first()
    if known is not None:
        raise WaitingRefusal("waiting_key_taken")
    if live is not None:
        _revoke(live, "device", current)
        session.flush()
    row = PatientPortalMyCarlosWaitingKey(
        key_id=key_id,
        public_key=public_key,
        account_id=owner.account_id,
        device_id=device.id,
        created_at=current,
    )
    # Two devices registering one key id at once: the unique index decides.
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
    except IntegrityError:
        raise WaitingRefusal("waiting_key_taken") from None
    return row, True


def revoke_for_device(
    session: Session, owner: Owner, key_id: str, *, now: datetime | None = None
) -> PatientPortalMyCarlosWaitingKey:
    """The device gives up one of its waiting keys; again is harmless."""
    if not session.in_transaction():
        raise AvailabilityError("transaction_required")
    _locked_active_device(session, owner)
    row = session.scalars(
        select(PatientPortalMyCarlosWaitingKey)
        .where(
            PatientPortalMyCarlosWaitingKey.key_id == key_id,
            PatientPortalMyCarlosWaitingKey.account_id == owner.account_id,
            PatientPortalMyCarlosWaitingKey.device_id == owner.device_id,
        )
        .with_for_update()
    ).first()
    if row is None:
        raise WaitingRefusal("not_found")
    _revoke(row, "device", now or datetime.now(UTC))
    session.flush()
    return row


def tombstone_device_keys(
    session: Session, device_id: int, *, by: str, now: datetime | None = None
) -> int:
    """Revokes every live waiting key of a removed device; how many there were."""
    current = now or datetime.now(UTC)
    rows = list(
        session.scalars(
            select(PatientPortalMyCarlosWaitingKey)
            .where(
                PatientPortalMyCarlosWaitingKey.device_id == device_id,
                PatientPortalMyCarlosWaitingKey.revoked_at.is_(None),
            )
            .with_for_update()
        )
    )
    for row in rows:
        _revoke(row, by, current)
    session.flush()
    return len(rows)


@dataclass(frozen=True)
class WaitingKeyRecord:
    """A registered waiting key and what it needs to be accepted."""

    row_id: int
    device_id: int
    public_key: bytes
    revoked: bool
    device_status: str


@dataclass(frozen=True)
class WaitingPrincipal:
    """An accepted waiting assertion; its nonce still has to be used once."""

    key_row_id: int
    device_id: int
    key_id: str
    assertion_id: str
    assertion_expires_at: int


def find_waiting_key(session: Session, key_id: str) -> WaitingKeyRecord | None:
    row = session.execute(
        select(PatientPortalMyCarlosWaitingKey, PatientPortalMyCarlosDevice.status)
        .join(
            PatientPortalMyCarlosDevice,
            PatientPortalMyCarlosDevice.id == PatientPortalMyCarlosWaitingKey.device_id,
        )
        .where(PatientPortalMyCarlosWaitingKey.key_id == key_id)
    ).first()
    if row is None:
        return None
    key, status = row
    return WaitingKeyRecord(
        row_id=key.id,
        device_id=key.device_id,
        public_key=key.public_key,
        revoked=key.revoked_at is not None,
        device_status=status,
    )


def verify_waiting_assertion(
    assertion: object,
    *,
    find_key: Callable[[str], WaitingKeyRecord | None],
    expected_request_hash: str,
    now: int,
) -> WaitingPrincipal:
    """A waiting assertion, checked as device assertions are, with its own audience.

    Exactly the waiting claims (no recipient), audience `carlos-patient-portal-waiting-check`,
    a lifetime of at most 60 seconds, the request bound by its hash. A revoked key, or one whose
    device was removed, is refused like an unknown one.
    """
    payload, claims, signature = _parse_compact(assertion)
    _check_claims(claims, audience=WAITING_AUDIENCE, required=WAITING_CLAIMS, optional=frozenset())
    key = find_key(str(claims["kid"]))
    if key is None:
        raise DeviceRefusal(REFUSAL_UNKNOWN_DEVICE)
    _verify_signature(key.public_key, signature, payload)
    if key.revoked or key.device_status != MYCARLOS_DEVICE_STATUS_ACTIVE:
        raise DeviceRefusal(REFUSAL_DEVICE_REMOVED)
    issued_at, expires_at = int(claims["iat"]), int(claims["exp"])
    if (
        expires_at <= issued_at
        or expires_at - issued_at > MAX_WAITING_ASSERTION_LIFETIME_SECONDS
        or issued_at > now + DEVICE_CLOCK_SKEW_SECONDS
    ):
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION)
    if now >= expires_at + DEVICE_CLOCK_SKEW_SECONDS:
        raise DeviceRefusal(REFUSAL_EXPIRED)
    _check_request_hash(claims, expected_request_hash)
    return WaitingPrincipal(
        key_row_id=key.row_id,
        device_id=key.device_id,
        key_id=str(claims["kid"]),
        assertion_id=str(claims["jti"]),
        assertion_expires_at=expires_at,
    )


def consume_waiting_assertion(
    session_factory: sessionmaker[Session], principal: WaitingPrincipal, *, now: int
) -> None:
    """Uses the assertion's nonce once, in the table device, staff and job assertions share.

    Kept until the end of the 30-second grace after `exp`, as for device assertions, so a nonce
    used by any caller type can never be used again by another.
    """
    try:
        consume_assertion_id(
            session_factory,
            principal.assertion_id,
            principal.assertion_expires_at + DEVICE_CLOCK_SKEW_SECONDS,
            now=datetime.fromtimestamp(now, tz=UTC),
        )
    except AssertionExpiredError as exc:
        raise DeviceRefusal(REFUSAL_EXPIRED) from exc
    except AssertionReplayError as exc:
        raise DeviceRefusal("replay") from exc


def _locked_key(session: Session, principal: WaitingPrincipal) -> PatientPortalMyCarlosWaitingKey:
    row = session.scalars(
        select(PatientPortalMyCarlosWaitingKey)
        .where(PatientPortalMyCarlosWaitingKey.id == principal.key_row_id)
        .with_for_update()
    ).first()
    device_status = session.scalar(
        select(PatientPortalMyCarlosDevice.status).where(
            PatientPortalMyCarlosDevice.id == principal.device_id
        )
    )
    # Revoked or removed between the check and this transaction: refused as unknown.
    if row is None or row.revoked_at is not None or device_status != MYCARLOS_DEVICE_STATUS_ACTIVE:
        raise WaitingRefusal("not_found")
    return row


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def answer(session: Session, principal: WaitingPrincipal, *, now: datetime) -> bytes:
    """Whether a not-expired mailbox copy waits for the key's device, at most every 120 s."""
    if not session.in_transaction():
        raise AvailabilityError("transaction_required")
    row = _locked_key(session, principal)
    if row.last_answered_at is not None:
        elapsed = (now - _aware(row.last_answered_at)).total_seconds()
        if elapsed < ANSWER_SPACING_SECONDS:
            raise TooSoon(max(1, ceil(ANSWER_SPACING_SECONDS - elapsed)))
    row.last_answered_at = now
    waiting = session.scalar(
        select(
            exists().where(
                MailboxCopy.device_id == principal.device_id,
                MailboxCopy.status == "waiting",
                MailboxCopy.expires_at > int(now.timestamp()),
            )
        )
    )
    session.flush()
    return ANSWER_WAITING if waiting else ANSWER_NOTHING


def revoke_self(session: Session, principal: WaitingPrincipal, *, now: datetime) -> None:
    """The key gives itself up: a locked app turning its tray notices off."""
    if not session.in_transaction():
        raise AvailabilityError("transaction_required")
    row = _locked_key(session, principal)
    _revoke(row, "waiting_key", now)
    session.flush()
