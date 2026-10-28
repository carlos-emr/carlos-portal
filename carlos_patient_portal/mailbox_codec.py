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

"""Opaque M4 transport parsing. Never decrypts or interprets a clinical document."""

import json
import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
from hashlib import sha256
from secrets import compare_digest
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_SEALED = 20 * 1024 * 1024
MAX_OUTER = 4096
MAX_UPLOAD = MAX_SEALED + MAX_OUTER + 16
SUITE = {"kem_id": 32, "kdf_id": 1, "aead_id": 3}
OUTER_FIELDS = frozenset(
    {
        "v",
        "suite",
        "delivery_id",
        "recipient_id",
        "device_key_id",
        "size",
        "ciphertext_sha256",
        "created_at",
        "expires_at",
    }
)
RECEIPT_FIELDS = frozenset(
    {
        "typ",
        "aud",
        "delivery_id",
        "recipient_id",
        "device_key_id",
        "ciphertext_sha256",
        "document_sha256",
        "picked_up_at",
        "vault_head_link",
        "jti",
    }
)
HEX = re.compile(r"[0-9a-f]{64}\Z")
RECIPIENT = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
CURSOR = re.compile(r"(?:0|[1-9][0-9]{0,18})\Z")
LONG_MAX = (1 << 63) - 1


class MailboxRefusal(ValueError):
    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate member")
        value[key] = item
    return value


def strict_object(raw: bytes, *, limit: int, code: str) -> dict:
    if len(raw) > limit:
        raise MailboxRefusal(code)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite")),
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise MailboxRefusal(code) from exc
    if not isinstance(value, dict):
        raise MailboxRefusal(code)
    return value


def integer(value: object) -> bool:
    return type(value) is int and 0 <= value <= LONG_MAX


def uuid_text(value: object, *, version4: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except ValueError:
        return False
    return str(parsed) == value and (not version4 or parsed.version == 4)


def canonical_key(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 43 or not value.isascii():
        return False
    try:
        raw = urlsafe_b64decode(value + "=")
    except ValueError:
        return False
    return len(raw) == 32 and urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value


def valid_hash(value: object) -> bool:
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def validate_outer(value: dict) -> None:
    suite = value.get("suite")
    if (
        set(value) != OUTER_FIELDS
        or type(value.get("v")) is not int
        or value["v"] != 1
        or not isinstance(suite, dict)
        or set(suite) != set(SUITE)
        or any(
            type(suite[key]) is not int or suite[key] != expected for key, expected in SUITE.items()
        )
        or not uuid_text(value.get("delivery_id"), version4=True)
        or not isinstance(value.get("recipient_id"), str)
        or not RECIPIENT.fullmatch(value["recipient_id"])
        or not canonical_key(value.get("device_key_id"))
        or not integer(value.get("size"))
        or not 49 <= value["size"] <= MAX_SEALED
        or not valid_hash(value.get("ciphertext_sha256"))
        or not integer(value.get("created_at"))
        or not integer(value.get("expires_at"))
        or not 0 < value["expires_at"] - value["created_at"] <= 604800
    ):
        raise MailboxRefusal("invalid_delivery")


@dataclass(frozen=True)
class Upload:
    outer: dict
    sealed: bytes = field(repr=False)
    body_sha256: str


def parse_upload(body: bytes) -> Upload:
    if len(body) > MAX_UPLOAD:
        raise MailboxRefusal("invalid_delivery", 413)
    offset = 0
    parts = []
    for bound in (MAX_OUTER, MAX_SEALED):
        if len(body) - offset < 8:
            raise MailboxRefusal("invalid_delivery")
        length = int.from_bytes(body[offset : offset + 8], "big")
        offset += 8
        # Check bounds before slicing/allocating, including uint64 overflow-looking inputs.
        if length > bound or length > len(body) - offset:
            raise MailboxRefusal("invalid_delivery")
        parts.append(body[offset : offset + length])
        offset += length
    if offset != len(body):
        raise MailboxRefusal("invalid_delivery")
    outer = strict_object(parts[0], limit=MAX_OUTER, code="invalid_delivery")
    validate_outer(outer)
    if outer["size"] != len(parts[1]) or not compare_digest(
        outer["ciphertext_sha256"], sha256(parts[1]).hexdigest()
    ):
        raise MailboxRefusal("invalid_delivery")
    return Upload(outer, parts[1], sha256(body).hexdigest())


def cursor(value: object) -> int:
    if not isinstance(value, str) or CURSOR.fullmatch(value) is None or int(value) > LONG_MAX:
        raise MailboxRefusal("invalid_cursor")
    return int(value)


def parse_ack(body: bytes) -> int:
    value = strict_object(body, limit=1024, code="invalid_cursor")
    if set(value) != {"through"}:
        raise MailboxRefusal("invalid_cursor")
    return cursor(value["through"])


def parse_receipt_body(body: bytes) -> str:
    value = strict_object(body, limit=8192, code="invalid_receipt")
    compact = value.get("receipt")
    if (
        set(value) != {"receipt"}
        or not isinstance(compact, str)
        or not compact.isascii()
        or not 1 <= len(compact) <= 4096
    ):
        raise MailboxRefusal("invalid_receipt")
    return compact


def receipt_claims(compact: str, *, key: bytes, kid: str, recipient: str) -> dict:
    """Verify original M0 receipt bytes; jti is a canonical UUID, delivery_id UUIDv4."""
    try:
        if not compact.isascii() or not 1 <= len(compact) <= 4096:
            raise ValueError("size")
        encoded, signature = compact.split(".")

        def decode(value: str) -> bytes:
            raw = urlsafe_b64decode(value + "=" * (-len(value) % 4))
            if urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
                raise ValueError("encoding")
            return raw

        payload, sig = decode(encoded), decode(signature)
        if len(sig) != 64:
            raise ValueError("signature")
        claims = strict_object(payload, limit=4096, code="invalid_receipt")
        if (
            set(claims) != RECEIPT_FIELDS
            or claims["typ"] != "mycarlos-delivery-receipt"
            or claims["aud"] != "carlos-delivery-receipt"
            or claims["device_key_id"] != kid
            or claims["recipient_id"] != recipient
            or not uuid_text(claims["delivery_id"], version4=True)
            or not uuid_text(claims["jti"])
            or not integer(claims["picked_up_at"])
            or not all(
                valid_hash(claims[name])
                for name in ("ciphertext_sha256", "document_sha256", "vault_head_link")
            )
        ):
            raise ValueError("claims")
        Ed25519PublicKey.from_public_bytes(key).verify(sig, payload)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise MailboxRefusal("invalid_receipt") from exc
    return claims
