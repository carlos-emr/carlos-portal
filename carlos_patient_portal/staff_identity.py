# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This software is published under the GPL GNU General Public License.
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# CARLOS EMR Project

import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import Error as Base64DecodeError
from collections.abc import Sequence
from dataclasses import dataclass
from secrets import compare_digest
from time import time
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from carlos_patient_portal.config import Settings
from carlos_patient_portal.invites import normalize_clinic_id, normalize_staff_actor

MAX_PERMISSION_LENGTH = 64
MAX_PERMISSION_COUNT = 32
PERMISSION_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")
MAX_STAFF_ASSERTION_BYTES = 4096
MAX_STAFF_ASSERTION_TTL_SECONDS = 120
STAFF_ASSERTION_CLOCK_SKEW_SECONDS = 30
STAFF_ASSERTION_AUDIENCE = "carlos-patient-portal-internal-api"
STAFF_ASSERTION_ISSUER = "carlos"
STAFF_ASSERTION_FIELDS = {
    "aud",
    "clinic_id",
    "exp",
    "iat",
    "iss",
    "jti",
    "permissions",
    "provider_id",
    "provider_name",
}


class CarlosServiceAuthenticationError(Exception):
    """Raised when an internal request is not authenticated as CARLOS."""


class CarlosStaffPermissionError(Exception):
    """Raised when the authenticated CARLOS provider lacks a portal permission."""


@dataclass(frozen=True)
class StaffPrincipal:
    provider_id: str
    display_name: str
    clinic_id: str
    permissions: frozenset[str]

    def require(self, permission: str) -> None:
        if permission not in self.permissions:
            raise CarlosStaffPermissionError()


def normalize_permissions(values: Sequence[str]) -> frozenset[str]:
    permissions = tuple(permission.strip().casefold() for permission in values)
    if not permissions or len(permissions) > MAX_PERMISSION_COUNT:
        raise CarlosServiceAuthenticationError()
    if (
        any(
            not permission
            or len(permission) > MAX_PERMISSION_LENGTH
            or not permission.isascii()
            or not set(permission) <= PERMISSION_CHARACTERS
            for permission in permissions
        )
        or len(set(permissions)) != len(permissions)
    ):
        raise CarlosServiceAuthenticationError()
    return frozenset(permissions)


def matches_any_service_token(supplied_token: str, accepted_tokens: tuple[str, ...]) -> bool:
    """Compare against every accepted token without short-circuiting.

    `any(...)` would stop at the first match, so response time would reveal whether the active or
    the retired token was presented. Accumulating instead keeps the work constant for a fixed
    number of accepted tokens, and each comparison itself stays constant-time.
    """
    # Compared as bytes, not str. `compare_digest` refuses str operands containing anything
    # outside ASCII, and Starlette latin-1 decodes header bytes, so any byte >= 0x80 in the
    # Authorization header would raise TypeError here and turn a fail-closed 404 into a 500 —
    # telling an unauthenticated caller that its token reached the comparison at all.
    supplied_bytes = supplied_token.encode("utf-8", "surrogateescape")
    matched = False
    for accepted_token in accepted_tokens:
        matched |= compare_digest(accepted_token.encode("utf-8", "surrogateescape"), supplied_bytes)
    return matched


def _decode_base64url(value: str, *, expected_length: int | None = None) -> bytes:
    try:
        decoded = urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except (Base64DecodeError, ValueError) as exc:
        raise CarlosServiceAuthenticationError() from exc
    if urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise CarlosServiceAuthenticationError()
    if expected_length is not None and len(decoded) != expected_length:
        raise CarlosServiceAuthenticationError()
    return decoded


def verify_staff_assertion(public_key_value: str, assertion: str) -> StaffPrincipal:
    """Verify a short-lived CARLOS provider assertion and return its bound principal."""
    if (
        not assertion
        or len(assertion.encode("utf-8", "surrogateescape")) > MAX_STAFF_ASSERTION_BYTES
    ):
        raise CarlosServiceAuthenticationError()
    encoded_payload, separator, encoded_signature = assertion.partition(".")
    if not separator or not encoded_payload or not encoded_signature or "." in encoded_signature:
        raise CarlosServiceAuthenticationError()
    payload_bytes = _decode_base64url(encoded_payload)
    signature = _decode_base64url(encoded_signature, expected_length=64)
    public_key_bytes = _decode_base64url(public_key_value, expected_length=32)
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, payload_bytes)
        payload = json.loads(payload_bytes)
    except (
        InvalidSignature,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
    ) as exc:
        raise CarlosServiceAuthenticationError() from exc
    if not isinstance(payload, dict) or set(payload) != STAFF_ASSERTION_FIELDS:
        raise CarlosServiceAuthenticationError()
    if (
        payload.get("aud") != STAFF_ASSERTION_AUDIENCE
        or payload.get("iss") != STAFF_ASSERTION_ISSUER
    ):
        raise CarlosServiceAuthenticationError()
    issued_at = payload.get("iat")
    expires_at = payload.get("exp")
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_STAFF_ASSERTION_TTL_SECONDS
    ):
        raise CarlosServiceAuthenticationError()
    now = int(time())
    if issued_at > now + STAFF_ASSERTION_CLOCK_SKEW_SECONDS or expires_at <= now:
        raise CarlosServiceAuthenticationError()
    jti = payload.get("jti")
    try:
        if not isinstance(jti, str) or str(UUID(jti)) != jti:
            raise ValueError
        provider_id = payload["provider_id"]
        provider_name = payload["provider_name"]
        clinic_id = payload["clinic_id"]
        raw_permissions = payload["permissions"]
        if not all(isinstance(value, str) for value in (provider_id, provider_name, clinic_id)):
            raise ValueError
        if (
            not isinstance(raw_permissions, list)
            or not raw_permissions
            or not all(isinstance(permission, str) for permission in raw_permissions)
        ):
            raise ValueError
        return StaffPrincipal(
            provider_id=normalize_staff_actor(provider_id),
            display_name=normalize_staff_actor(provider_name),
            clinic_id=normalize_clinic_id(clinic_id),
            permissions=normalize_permissions(raw_permissions),
        )
    except (KeyError, ValueError) as exc:
        raise CarlosServiceAuthenticationError() from exc


def authenticate_carlos_staff(
    settings: Settings,
    *,
    authorization: str | None,
    staff_assertion: str | None,
) -> StaffPrincipal:
    accepted_tokens = settings.accepted_internal_api_tokens
    scheme, _, supplied_token = (authorization or "").partition(" ")
    if (
        not accepted_tokens
        or scheme.casefold() != "bearer"
        or not supplied_token
        or not matches_any_service_token(supplied_token, accepted_tokens)
        or settings.internal_staff_assertion_public_key is None
        or staff_assertion is None
    ):
        raise CarlosServiceAuthenticationError()
    try:
        principal = verify_staff_assertion(
            settings.internal_staff_assertion_public_key,
            staff_assertion,
        )
        if principal.clinic_id != settings.clinic_id:
            raise CarlosServiceAuthenticationError()
        return principal
    except ValueError as exc:
        raise CarlosServiceAuthenticationError() from exc
