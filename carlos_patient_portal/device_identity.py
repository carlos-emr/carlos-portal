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

"""Signed requests from a linked myCarlos device (carlos-portal#41, M2).

Every device request carries `X-MyCarlos-Device-Assertion`: a compact Ed25519 object signed with
that link's device key and bound to the exact request, the same shape as CARLOS's staff and job
assertions. The rules, checks and their order are the spec's ("Device requests" and "Linking a
device" in `docs/architecture/mycarlos-delivery.md`), and `tests/test_device_identity.py` runs
every shared vector through them.

- **Device requests:** `verify_device_assertion` does checks 1-7 (parse, find the device, verify,
  status, time, request hash, recipient); `consume_device_assertion` does 8 (replay), in the
  nonce table staff and job assertions use.
- **Linking:** `verify_link_request` checks the body and the assertion signed by the *new* key
  (checks 1-4 but replay); `consume_device_assertion` then records its nonce. The code itself is
  checked by the link route, against the one pending link the body names.

Every refusal is a `DeviceRefusal` whose `code` is one of the spec's response codes.
"""

import json
import re
from base64 import urlsafe_b64encode
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from secrets import compare_digest
from time import time
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal.models import (
    MYCARLOS_DEVICE_STATUS_ACTIVE,
    MYCARLOS_LINK_CODE_LENGTH,
    MYCARLOS_LINK_ID_LENGTH,
    MYCARLOS_PUBLIC_KEY_LENGTH,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosRecipient,
)
from carlos_patient_portal.staff_identity import (
    AssertionExpiredError,
    AssertionReplayError,
    CarlosServiceAuthenticationError,
    _decode_base64url,
    consume_assertion_id,
)

DEVICE_ASSERTION_HEADER = "X-MyCarlos-Device-Assertion"
DEVICE_AUDIENCE = "carlos-patient-portal-device-api"
LINK_AUDIENCE = "carlos-patient-portal-device-link"
LINK_RECOVERY_AUDIENCE = "carlos-patient-portal-device-link-recovery"
DEVICE_ISSUER = "mycarlos"
MAX_DEVICE_ASSERTION_BYTES = 4096
MAX_DEVICE_ASSERTION_LIFETIME_SECONDS = 120
DEVICE_CLOCK_SKEW_SECONDS = 30
DEVICE_KEY_ID_LABEL = b"mycarlos-device-key-v1"
LINK_CODE_ALPHABET = frozenset("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
MAX_DEVICE_NAME_LENGTH = 64

DEVICE_CLAIMS = frozenset(
    {"aud", "iss", "kid", "recipient_id", "jti", "iat", "exp", "request_hash"}
)
DEVICE_OPTIONAL_CLAIMS = frozenset({"vault_head_link"})
LINK_CLAIMS = frozenset({"aud", "iss", "kid", "jti", "iat", "exp", "request_hash"})
LINK_BODY_FIELDS = frozenset(
    {"link_id", "code", "device_name", "x25519_public_key", "ed25519_public_key"}
)
LOWERCASE_HEX_64 = re.compile(r"[0-9a-f]{64}")

REFUSAL_INVALID_ASSERTION = "invalid_assertion"
REFUSAL_UNKNOWN_DEVICE = "unknown_device"
REFUSAL_DEVICE_REMOVED = "device_removed"
REFUSAL_EXPIRED = "expired"
REFUSAL_REQUEST_MISMATCH = "request_mismatch"
REFUSAL_RECIPIENT_MISMATCH = "recipient_mismatch"
REFUSAL_REPLAY = "replay"
DEVICE_REFUSAL_CODES = frozenset(
    {
        REFUSAL_INVALID_ASSERTION,
        REFUSAL_UNKNOWN_DEVICE,
        REFUSAL_DEVICE_REMOVED,
        REFUSAL_EXPIRED,
        REFUSAL_REQUEST_MISMATCH,
        REFUSAL_RECIPIENT_MISMATCH,
        REFUSAL_REPLAY,
    }
)


class DeviceRefusal(Exception):
    """A refused device request. `code` is the spec's response code, safe to return."""

    def __init__(self, code: str) -> None:
        if code not in DEVICE_REFUSAL_CODES:
            raise ValueError(f"unknown device refusal code {code}")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class DeviceRecord:
    """What the checks need about one stored device."""

    device_id: int
    account_id: int
    device_key_id: str
    ed25519_public_key: bytes
    status: str
    recipient_id: str | None


@dataclass(frozen=True)
class DevicePrincipal:
    """A verified device request, before its nonce is recorded."""

    device_id: int
    account_id: int
    device_key_id: str
    assertion_id: str
    assertion_expires_at: int
    vault_head_link: str | None


@dataclass(frozen=True)
class LinkRequest:
    """A verified link request: the new device's keys, its name, and the code it presents."""

    link_id: str
    code: str
    device_name: str
    x25519_public_key: bytes
    ed25519_public_key: bytes
    device_key_id: str
    assertion_id: str
    assertion_expires_at: int


def b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def device_key_id(x25519_public_key: bytes, ed25519_public_key: bytes) -> str:
    """b64url(SHA-256("mycarlos-device-key-v1" || frame(X25519 key, Ed25519 key))), 43 chars."""
    digest = sha256(DEVICE_KEY_ID_LABEL)
    for part in (x25519_public_key, ed25519_public_key):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return b64url(digest.digest())


def _strict_b64url(value: object, *, expected_length: int | None = None) -> bytes:
    """Only the canonical unpadded form; anything else is `invalid_assertion`."""
    if not isinstance(value, str) or not value.isascii():
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION)
    try:
        return _decode_base64url(value, expected_length=expected_length)
    except CarlosServiceAuthenticationError as exc:
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION) from exc


def _no_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    members: dict[str, object] = {}
    for name, value in pairs:
        if name in members:
            raise ValueError("duplicate member")
        members[name] = value
    return members


def _parse_compact(assertion: object) -> tuple[bytes, dict[str, object], bytes]:
    if (
        not isinstance(assertion, str)
        or not assertion
        or len(assertion.encode("utf-8", "surrogateescape")) > MAX_DEVICE_ASSERTION_BYTES
    ):
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION)
    encoded_payload, separator, encoded_signature = assertion.partition(".")
    if not separator or not encoded_payload or "." in encoded_signature:
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION)
    payload = _strict_b64url(encoded_payload)
    signature = _strict_b64url(encoded_signature, expected_length=64)
    try:
        claims = json.loads(payload, object_pairs_hook=_no_duplicate_members)
    # Deeply nested JSON inside the size limit exhausts the decoder's recursion depth (on Python
    # 3.11 at about 1,000 levels): malformed like any other, never a 500.
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION) from exc
    if not isinstance(claims, dict):
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION)
    return payload, claims, signature


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _canonical_uuid(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return value if str(UUID(value)) == value else None
    except ValueError:
        return None


def _is_hex_64(value: object) -> bool:
    return isinstance(value, str) and LOWERCASE_HEX_64.fullmatch(value) is not None


def _check_claims(
    claims: dict[str, object],
    *,
    audience: str,
    required: frozenset[str],
    optional: frozenset[str],
) -> None:
    """Check 1 (parse): exactly the listed claims, of the listed types."""
    if not required <= set(claims) <= required | optional:
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION)
    if (
        claims["aud"] != audience
        or claims["iss"] != DEVICE_ISSUER
        or _canonical_uuid(claims["jti"]) is None
        or not _is_int(claims["iat"])
        or not _is_int(claims["exp"])
        or not isinstance(claims["kid"], str)
        or not _is_hex_64(claims["request_hash"])
        or (
            "recipient_id" in required
            and (
                not isinstance(claims["recipient_id"], str)
                or not claims["recipient_id"].isascii()
            )
        )
        or ("vault_head_link" in claims and not _is_hex_64(claims["vault_head_link"]))
    ):
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION)


def _verify_signature(public_key: bytes, signature: bytes, payload: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION) from exc


def _check_times(claims: dict[str, object], now: int) -> None:
    """Check 5: a lifetime of at most 120 seconds, not from the future, and 30 seconds of grace."""
    issued_at = claims["iat"]
    expires_at = claims["exp"]
    if (
        expires_at <= issued_at
        or expires_at - issued_at > MAX_DEVICE_ASSERTION_LIFETIME_SECONDS
        or issued_at > now + DEVICE_CLOCK_SKEW_SECONDS
    ):
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION)
    if now >= expires_at + DEVICE_CLOCK_SKEW_SECONDS:
        raise DeviceRefusal(REFUSAL_EXPIRED)


def _check_request_hash(claims: dict[str, object], expected_request_hash: str) -> None:
    if not compare_digest(str(claims["request_hash"]), expected_request_hash):
        raise DeviceRefusal(REFUSAL_REQUEST_MISMATCH)


def verify_device_assertion(
    assertion: object,
    *,
    find_device: Callable[[str], DeviceRecord | None],
    expected_request_hash: str,
    now: int | None = None,
) -> DevicePrincipal:
    """Checks 1-7 of a device request, in the spec's order. Check 8 is `consume_device_assertion`.

    `find_device` looks a device up by its `device_key_id`; keys are per link, so it names at most
    one row. `now` (Unix seconds) is for fixed test vectors; routes use the current time.
    """
    current_time = int(time()) if now is None else now
    payload, claims, signature = _parse_compact(assertion)
    _check_claims(
        claims,
        audience=DEVICE_AUDIENCE,
        required=DEVICE_CLAIMS,
        optional=DEVICE_OPTIONAL_CLAIMS,
    )
    device = find_device(str(claims["kid"]))
    if device is None:
        raise DeviceRefusal(REFUSAL_UNKNOWN_DEVICE)
    _verify_signature(device.ed25519_public_key, signature, payload)
    if device.status != MYCARLOS_DEVICE_STATUS_ACTIVE:
        raise DeviceRefusal(REFUSAL_DEVICE_REMOVED)
    _check_times(claims, current_time)
    _check_request_hash(claims, expected_request_hash)
    if device.recipient_id is None or not compare_digest(
        str(claims["recipient_id"]), device.recipient_id
    ):
        raise DeviceRefusal(REFUSAL_RECIPIENT_MISMATCH)
    vault_head_link = claims.get("vault_head_link")
    return DevicePrincipal(
        device_id=device.device_id,
        account_id=device.account_id,
        device_key_id=device.device_key_id,
        assertion_id=str(claims["jti"]),
        assertion_expires_at=int(claims["exp"]),
        vault_head_link=str(vault_head_link) if vault_head_link is not None else None,
    )


def verify_link_recovery_assertion(
    assertion: object,
    *,
    find_device: Callable[[str], DeviceRecord | None],
    expected_request_hash: str,
    now: int | None = None,
) -> DevicePrincipal:
    """Verify pending-link recovery possession, freshness and binding without status disclosure.

    The caller consumes the shared nonce before locking account then device and rechecking
    removal. A normal device audience or extra recipient/anchor claim never authorizes recovery.
    The signature covers the original signed payload, including valid noncanonical JSON.
    """
    current_time = int(time()) if now is None else now
    payload, claims, signature = _parse_compact(assertion)
    _check_claims(
        claims, audience=LINK_RECOVERY_AUDIENCE, required=LINK_CLAIMS, optional=frozenset()
    )
    device = find_device(str(claims["kid"]))
    if device is None:
        raise DeviceRefusal(REFUSAL_UNKNOWN_DEVICE)
    _verify_signature(device.ed25519_public_key, signature, payload)
    _check_times(claims, current_time)
    _check_request_hash(claims, expected_request_hash)
    return DevicePrincipal(
        device_id=device.device_id,
        account_id=device.account_id,
        device_key_id=device.device_key_id,
        assertion_id=str(claims["jti"]),
        assertion_expires_at=int(claims["exp"]),
        vault_head_link=None,
    )


def _is_link_text(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and set(value) <= LINK_CODE_ALPHABET


def _is_device_name(value: object) -> bool:
    return (
        isinstance(value, str) and 1 <= len(value) <= MAX_DEVICE_NAME_LENGTH and value.isprintable()
    )


def verify_link_request(
    body: bytes,
    assertion: object,
    *,
    expected_request_hash: str,
    now: int | None = None,
) -> LinkRequest:
    """The link checks before the code (spec "Linking a device", 3.1-3.4 but replay).

    The assertion must be signed by the Ed25519 key in the body, and its `kid` must be the
    `device_key_id` of the body's two keys, so the signature proves the new device holds its key
    and covers both keys, the name and the code. Every failure here is `invalid_assertion`,
    except `expired` and `request_mismatch`.
    """
    current_time = int(time()) if now is None else now
    try:
        fields = json.loads(body, object_pairs_hook=_no_duplicate_members)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION) from exc
    if not isinstance(fields, dict) or set(fields) != LINK_BODY_FIELDS:
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION)
    x25519_public_key = _strict_b64url(
        fields["x25519_public_key"], expected_length=MYCARLOS_PUBLIC_KEY_LENGTH
    )
    ed25519_public_key = _strict_b64url(
        fields["ed25519_public_key"], expected_length=MYCARLOS_PUBLIC_KEY_LENGTH
    )
    if (
        not _is_device_name(fields["device_name"])
        or not _is_link_text(fields["link_id"], MYCARLOS_LINK_ID_LENGTH)
        or not _is_link_text(fields["code"], MYCARLOS_LINK_CODE_LENGTH)
    ):
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION)

    payload, claims, signature = _parse_compact(assertion)
    _check_claims(claims, audience=LINK_AUDIENCE, required=LINK_CLAIMS, optional=frozenset())
    fingerprint = device_key_id(x25519_public_key, ed25519_public_key)
    if claims["kid"] != fingerprint:
        raise DeviceRefusal(REFUSAL_INVALID_ASSERTION)
    _verify_signature(ed25519_public_key, signature, payload)
    _check_times(claims, current_time)
    _check_request_hash(claims, expected_request_hash)
    return LinkRequest(
        link_id=str(fields["link_id"]),
        code=str(fields["code"]),
        device_name=str(fields["device_name"]),
        x25519_public_key=x25519_public_key,
        ed25519_public_key=ed25519_public_key,
        device_key_id=fingerprint,
        assertion_id=str(claims["jti"]),
        assertion_expires_at=int(claims["exp"]),
    )


def consume_device_assertion(
    session_factory: sessionmaker[Session],
    principal: DevicePrincipal | LinkRequest,
    *,
    now: int | None = None,
) -> None:
    """Check 8: use the assertion's nonce once, in the table staff and job assertions use.

    The nonce is kept until the end of the 30-second grace after `exp`, the last moment the
    assertion could still pass check 5, so pruning can never let it be used again.
    """
    current_time = None if now is None else datetime.fromtimestamp(now, tz=UTC)
    try:
        consume_assertion_id(
            session_factory,
            principal.assertion_id,
            principal.assertion_expires_at + DEVICE_CLOCK_SKEW_SECONDS,
            now=current_time,
        )
    except AssertionExpiredError as exc:
        raise DeviceRefusal(REFUSAL_EXPIRED) from exc
    except AssertionReplayError as exc:
        raise DeviceRefusal(REFUSAL_REPLAY) from exc


def find_device_record(session: Session, device_key_id_value: str) -> DeviceRecord | None:
    """The stored device with this key ID and its account's recipient ID, or None."""
    row = session.execute(
        select(PatientPortalMyCarlosDevice, PatientPortalMyCarlosRecipient.recipient_id)
        .outerjoin(
            PatientPortalMyCarlosRecipient,
            PatientPortalMyCarlosRecipient.account_id == PatientPortalMyCarlosDevice.account_id,
        )
        .where(PatientPortalMyCarlosDevice.device_key_id == device_key_id_value)
    ).first()
    if row is None:
        return None
    device, recipient_id = row
    return DeviceRecord(
        device_id=device.id,
        account_id=device.account_id,
        device_key_id=device.device_key_id,
        ed25519_public_key=device.ed25519_public_key,
        status=device.status,
        recipient_id=recipient_id,
    )
