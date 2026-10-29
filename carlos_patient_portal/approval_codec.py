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

"""Strict frozen M3 signed objects; portal storage never grants clinic-local acceptance."""

from base64 import urlsafe_b64encode
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from carlos_patient_portal.mailbox_codec import (
    MailboxRefusal,
    canonical_key,
    integer,
    strict_object,
    uuid_text,
    valid_hash,
)
from carlos_patient_portal.mycarlos_devices import strict_b64url_decode

FIELDS = {
    "intent": frozenset(
        {
            "iat",
            "predecessor_device_key_id",
            "iss",
            "clinic_id",
            "candidate_device_key_id",
            "typ",
            "request_id",
            "candidate_x25519_public_key",
            "v",
            "exp",
            "recipient_id",
            "public_portal_base_url",
            "aud",
            "candidate_ed25519_public_key",
        }
    ),
    "challenge": frozenset(
        {
            "candidate_intent_sha256",
            "candidate_x25519_public_key",
            "issued_at",
            "approval_kind",
            "recipient_id",
            "expires_at",
            "predecessor_device_key_id",
            "challenge_id",
            "clinic_id",
            "candidate_device_key_id",
            "typ",
            "request_id",
            "predecessor_version",
            "kid",
            "v",
            "public_portal_base_url",
            "aud",
            "candidate_ed25519_public_key",
        }
    ),
    "approval": frozenset(
        {
            "predecessor_device_key_id",
            "candidate_intent_sha256",
            "iss",
            "challenge_id",
            "clinic_id",
            "candidate_device_key_id",
            "typ",
            "predecessor_version",
            "candidate_x25519_public_key",
            "v",
            "challenge_sha256",
            "recipient_id",
            "aud",
            "jti",
            "candidate_ed25519_public_key",
        }
    ),
    "acceptance": frozenset(
        {
            "approval_sha256",
            "candidate_x25519_public_key",
            "challenge_sha256",
            "approval_kind",
            "recipient_id",
            "accepted_version",
            "predecessor_device_key_id",
            "challenge_id",
            "clinic_id",
            "candidate_device_key_id",
            "typ",
            "request_id",
            "kid",
            "v",
            "public_portal_base_url",
            "accepted_at",
            "aud",
            "candidate_ed25519_public_key",
        }
    ),
}
# Clinic code v1 (mycarlos#141) adds "code": a first device the clinic approves once the patient
# enters the code CARLOS emailed. Like "staff_first" it has no predecessor; "accepted_device" always
# has one.
CODE_APPROVAL_KIND = "code"
# Contract versions (myCarlos #144). v2 changes only lifetimes: a staff_first request may stay
# open 24 hours; code and accepted_device keep 10 minutes, and so does a request with no
# challenge yet. v1 keeps 10 minutes everywhere, for apps that only know v1.
CONTRACT_VERSIONS = (1, 2)
TEN_MINUTES, DAY = 600, 86_400


def intent_life(version: int) -> int:
    return DAY if version == 2 else TEN_MINUTES


def challenge_life(version: int, approval_kind: str) -> int:
    return DAY if version == 2 and approval_kind == "staff_first" else TEN_MINUTES


def challenge_expiry(version: int, approval_kind: str, issued_at: int, intent_exp: int) -> int:
    """When a challenge must end: its kind's life, and never after its intent."""
    return min(issued_at + challenge_life(version, approval_kind), intent_exp)


def unanswered_until(iat: int, exp: int) -> int:
    """How long a request with no challenge yet counts as open (v1 intents end sooner anyway)."""
    return min(exp, iat + TEN_MINUTES)


FIRST_DEVICE_KINDS = frozenset({"staff_first", CODE_APPROVAL_KIND})
APPROVAL_KINDS = FIRST_DEVICE_KINDS | {"accepted_device"}
TYPES = {
    "intent": ("mycarlos-device-approval-intent", "carlos-mycarlos-device-approval-intent"),
    "challenge": ("mycarlos-device-approval-challenge", "carlos-mycarlos-device-approval"),
    "approval": ("mycarlos-device-approval", "carlos-mycarlos-device-approval"),
    "acceptance": ("mycarlos-device-acceptance", "carlos-mycarlos-device-approval"),
}


def invalid(code: str = "invalid_approval", status: int = 400) -> MailboxRefusal:
    return MailboxRefusal(code, status)


def compact_parts(compact: object) -> tuple[dict, bytes, bytes]:
    if not isinstance(compact, str) or not compact.isascii() or len(compact) > 8192:
        raise invalid()
    try:
        payload, signature = compact.split(".")
        raw = strict_b64url_decode(payload)
        sig = strict_b64url_decode(signature)
        if len(sig) != 64:
            raise ValueError("invalid signature size")
        return strict_object(raw, limit=8192, code="invalid_approval"), raw, sig
    except (ValueError, UnicodeError) as exc:
        raise invalid() from exc


def device_keys(claims: dict) -> tuple[str, bytes, bytes]:
    names = (
        "candidate_device_key_id",
        "candidate_x25519_public_key",
        "candidate_ed25519_public_key",
    )
    if not all(canonical_key(claims.get(name)) for name in names):
        raise invalid()
    kid, x, ed = (claims[name] for name in names)
    raw_x, raw_ed = strict_b64url_decode(x), strict_b64url_decode(ed)
    if raw_x == bytes(32) or raw_ed == bytes(32):
        raise invalid()
    framed = len(raw_x).to_bytes(8, "big") + raw_x + len(raw_ed).to_bytes(8, "big") + raw_ed
    computed = (
        urlsafe_b64encode(sha256(b"mycarlos-device-key-v1" + framed).digest()).rstrip(b"=").decode()
    )
    if computed != kid:
        raise invalid()
    return kid, raw_x, raw_ed


def object_claims(
    kind: str, compact: object, *, clinic: str, recipient: str, public_base: str
) -> tuple[dict, bytes, bytes]:
    value, raw, sig = compact_parts(compact)
    if (
        set(value) != FIELDS[kind]
        or type(value.get("v")) is not int
        or value["v"] not in CONTRACT_VERSIONS
        or (value.get("typ"), value.get("aud")) != TYPES[kind]
        or value.get("clinic_id") != clinic
        or value.get("recipient_id") != recipient
    ):
        raise invalid()
    device_keys(value)
    if kind != "approval" and value.get("public_portal_base_url") != public_base:
        raise invalid("approval_conflict", 409)
    for field in ("request_id", "jti"):
        if field in value and not uuid_text(value[field], version4=True):
            raise invalid()
    for field in ("challenge_id", "kid"):
        if field in value and not canonical_key(value[field]):
            raise invalid()
    for field in ("candidate_intent_sha256", "challenge_sha256"):
        if field in value and not valid_hash(value[field]):
            raise invalid()
    for field in ("iat", "exp", "issued_at", "expires_at", "accepted_at"):
        if field in value and not integer(value[field]):
            raise invalid()
    if kind in {"intent", "approval"} and value.get("iss") != "mycarlos":
        raise invalid()
    predecessor = value.get("predecessor_device_key_id")
    if predecessor is not None and not canonical_key(predecessor):
        raise invalid()
    if kind == "intent" and not 0 < value["exp"] - value["iat"] <= intent_life(value["v"]):
        raise invalid()
    if kind in {"challenge", "acceptance"}:
        approval_kind = value["approval_kind"]
        if not isinstance(approval_kind, str) or approval_kind not in APPROVAL_KINDS:
            raise invalid()
        if (predecessor is None) != (approval_kind in FIRST_DEVICE_KINDS):
            raise invalid()
    if "predecessor_version" in value:
        from carlos_patient_portal.mailbox_codec import cursor

        version = value["predecessor_version"]
        if predecessor is None:
            if version is not None:
                raise invalid()
        else:
            try:
                cursor(version)
            except MailboxRefusal as exc:
                raise invalid() from exc
    if kind == "approval" and predecessor is None:
        raise invalid()
    if kind == "challenge" and not (
        0
        < value["expires_at"] - value["issued_at"]
        <= challenge_life(value["v"], value["approval_kind"])
    ):
        raise invalid()
    if kind == "acceptance":
        if value["accepted_version"] != "0":
            raise invalid()
        if predecessor is None:
            if value["approval_sha256"] is not None:
                raise invalid()
        elif not valid_hash(value["approval_sha256"]):
            raise invalid()
    return value, raw, sig


def verify_intent(compact: str, **scope: str) -> dict:
    value, raw, sig = object_claims("intent", compact, **scope)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(device_keys(value)[2]).verify(sig, raw)
    except (InvalidSignature, ValueError) as exc:
        raise invalid() from exc
    return value


def verify_clinic(kind: str, compact: str, *, spki: bytes, **scope: str) -> dict:
    value, raw, sig = object_claims(kind, compact, **scope)
    expected_kid = urlsafe_b64encode(sha256(spki).digest()).rstrip(b"=").decode()
    if value["kid"] != expected_kid:
        raise invalid()
    try:
        key = serialization.load_der_public_key(spki)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise ValueError("invalid clinic key")
        key.verify(
            encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
            raw,
            ec.ECDSA(hashes.SHA256()),
        )
    except (ValueError, InvalidSignature) as exc:
        raise invalid() from exc
    return value


def verify_approval(
    compact: str, *, predecessor_kid: str, predecessor_ed: bytes, **scope: str
) -> dict:
    value, raw, sig = object_claims("approval", compact, **scope)
    if value["predecessor_device_key_id"] != predecessor_kid:
        raise invalid("approval_conflict", 409)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(predecessor_ed).verify(sig, raw)
    except (InvalidSignature, ValueError) as exc:
        raise invalid() from exc
    return value


def compact_hash(value: str) -> str:
    return sha256(value.encode("ascii")).hexdigest()
