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

"""Verify the signed call a CARLOS job makes, and say exactly why one is refused.

A job (see `system_jobs`) calls the internal API with the shared service token and an
`X-CARLOS-Job-Assertion`: the same compact `b64url(payload).b64url(Ed25519 signature)` format as a
staff assertion, but its own audience, its own per-job keys, no provider claims, and exactly one
permission. It is always bound to the exact request, in every environment.

Two kinds of failure are kept apart on purpose:

- `CarlosServiceAuthenticationError`: nothing proves who sent it (no service token, a malformed
  envelope, an unknown key id, a bad signature). It is the same generic 404 as any unauthenticated
  internal call, and the failure middleware writes its usual unattributed row.
- `CarlosJobRefusal`: the signature verified, so a job key's holder sent it. The refusal names that
  job and a reason code, and the middleware records it as `job.auth_refused`.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from secrets import compare_digest
from time import time
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal.config import Settings
from carlos_patient_portal.staff_identity import (
    MAX_PERMISSION_LENGTH,
    MAX_STAFF_ASSERTION_BYTES,
    MAX_STAFF_ASSERTION_TTL_SECONDS,
    PERMISSION_CHARACTERS,
    REQUEST_HASH_CHARACTERS,
    REQUEST_HASH_HEX_LENGTH,
    STAFF_ASSERTION_CLOCK_SKEW_SECONDS,
    STAFF_ASSERTION_ISSUER,
    AssertionExpiredError,
    AssertionReplayError,
    CarlosServiceAuthenticationError,
    _decode_base64url,
    _reject_duplicate_assertion_claims,
    consume_assertion_id,
    matches_any_service_token,
)
from carlos_patient_portal.system_jobs import SYSTEM_JOBS

JOB_ASSERTION_HEADER = "X-CARLOS-Job-Assertion"
# Its own audience, so a job assertion can never be accepted as a staff one (or the reverse).
JOB_ASSERTION_AUDIENCE = "carlos-patient-portal-job-api"
JOB_ASSERTION_ISSUER = STAFF_ASSERTION_ISSUER
MAX_JOB_ASSERTION_BYTES = MAX_STAFF_ASSERTION_BYTES
MAX_JOB_ASSERTION_TTL_SECONDS = MAX_STAFF_ASSERTION_TTL_SECONDS
JOB_ASSERTION_CLOCK_SKEW_SECONDS = STAFF_ASSERTION_CLOCK_SKEW_SECONDS
JOB_ASSERTION_FIELDS = frozenset(
    {
        "aud",
        "clinic_id",
        "exp",
        "iat",
        "iss",
        "jti",
        "job",
        "kid",
        "permission",
        "request_hash",
    }
)

# Refusal reasons, recorded as the audit row's `reason` once the signature has verified.
JOB_REFUSAL_UNKNOWN_JOB = "unknown_job"
JOB_REFUSAL_WRONG_KEY = "wrong_key"
JOB_REFUSAL_INVALID_CLAIMS = "invalid_claims"
JOB_REFUSAL_EXPIRED = "expired"
JOB_REFUSAL_REQUEST_MISMATCH = "request_mismatch"
JOB_REFUSAL_CLINIC_MISMATCH = "clinic_mismatch"
JOB_REFUSAL_REPLAY = "replay"
JOB_REFUSAL_BOTH_HEADERS = "both_headers"
JOB_REFUSAL_ROUTE_NOT_OPEN = "route_not_open"
JOB_REFUSAL_PERMISSION_NOT_HELD = "permission_not_held"
JOB_REFUSAL_WRONG_PERMISSION = "wrong_permission"
# Only these are a 403: the job reached a route open to it and is told it lacks the right. Every
# other refusal is the generic 404, so a job cannot use the API to learn which routes exist.
FORBIDDEN_JOB_REFUSALS = frozenset({JOB_REFUSAL_PERMISSION_NOT_HELD, JOB_REFUSAL_WRONG_PERMISSION})
JOB_REFUSAL_CODES = frozenset(
    {
        JOB_REFUSAL_UNKNOWN_JOB,
        JOB_REFUSAL_WRONG_KEY,
        JOB_REFUSAL_INVALID_CLAIMS,
        JOB_REFUSAL_EXPIRED,
        JOB_REFUSAL_REQUEST_MISMATCH,
        JOB_REFUSAL_CLINIC_MISMATCH,
        JOB_REFUSAL_REPLAY,
        JOB_REFUSAL_BOTH_HEADERS,
        JOB_REFUSAL_ROUTE_NOT_OPEN,
        *FORBIDDEN_JOB_REFUSALS,
    }
)


@dataclass(frozen=True)
class JobPrincipal:
    """A verified job call: which job, the one permission it claimed, and its key and nonce."""

    job: str
    display_name: str
    clinic_id: str
    permission: str
    key_id: str
    assertion_id: str
    assertion_expires_at: int

    @property
    def actor_id(self) -> str:
        return SYSTEM_JOBS[self.job].actor_id


class CarlosJobRefusal(Exception):
    """A job assertion whose signature verified, refused for a recorded reason.

    `key_owner` is the job whose key verified the signature. It is what the audit row names,
    because the job the payload claims is exactly what may be wrong.
    """

    def __init__(
        self,
        code: str,
        *,
        key_owner: str,
        key_id: str,
        assertion_id: str | None,
    ) -> None:
        if code not in JOB_REFUSAL_CODES:
            raise ValueError(f"unknown job refusal code: {code}")
        super().__init__(code)
        self.code = code
        self.key_owner = key_owner
        self.key_id = key_id
        self.assertion_id = assertion_id

    @property
    def status_code(self) -> int:
        return 403 if self.code in FORBIDDEN_JOB_REFUSALS else 404

    @classmethod
    def for_principal(cls, code: str, principal: JobPrincipal) -> "CarlosJobRefusal":
        return cls(
            code,
            key_owner=principal.job,
            key_id=principal.key_id,
            assertion_id=principal.assertion_id,
        )


def canonical_assertion_id(value: object) -> str | None:
    """The assertion id when it is a canonical (lowercase, hyphenated) UUID, otherwise None."""
    if not isinstance(value, str):
        return None
    try:
        return value if str(UUID(value)) == value else None
    except ValueError:
        return None


def _is_whole_seconds(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_permission_name(value: object) -> bool:
    # Exactly one name, already in canonical form: unlike the staff list, nothing is trimmed or
    # case-folded, because the job signs a fixed string from its own registry.
    return (
        isinstance(value, str)
        and 0 < len(value) <= MAX_PERMISSION_LENGTH
        and value.isascii()
        and set(value) <= PERMISSION_CHARACTERS
    )


def _is_request_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == REQUEST_HASH_HEX_LENGTH
        and value.isascii()
        and set(value) <= REQUEST_HASH_CHARACTERS
    )


def _key_owner(
    job_keys: Mapping[str, Mapping[str, str]],
    key_id: str,
) -> tuple[str, str] | None:
    # Key ids are unique across jobs (settings refuse a repeat), so at most one job matches.
    for job, keys in job_keys.items():
        public_key = keys.get(key_id)
        if public_key is not None:
            return job, public_key
    return None


def verify_job_assertion(
    job_keys: Mapping[str, Mapping[str, str]],
    assertion: str,
    *,
    expected_request_hash: str,
    expected_clinic_id: str,
    staff_assertion_present: bool = False,
    now: int | None = None,
) -> JobPrincipal:
    """Verify one request-bound CARLOS job assertion.

    `job_keys` maps each job to its `{kid: unpadded base64url Ed25519 public key}`. `now` (Unix
    seconds) is for fixed test vectors; the routes always use the current time.
    """
    if (
        not assertion
        or len(assertion.encode("utf-8", "surrogateescape")) > MAX_JOB_ASSERTION_BYTES
    ):
        raise CarlosServiceAuthenticationError()
    encoded_payload, separator, encoded_signature = assertion.partition(".")
    if not separator or not encoded_payload or not encoded_signature or "." in encoded_signature:
        raise CarlosServiceAuthenticationError()
    payload_bytes = _decode_base64url(encoded_payload)
    signature = _decode_base64url(encoded_signature, expected_length=64)
    try:
        payload = json.loads(
            payload_bytes,
            object_pairs_hook=_reject_duplicate_assertion_claims,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
    ) as exc:
        raise CarlosServiceAuthenticationError() from exc
    if not isinstance(payload, dict):
        raise CarlosServiceAuthenticationError()
    key_id = payload.get("kid")
    owner = _key_owner(job_keys, key_id) if isinstance(key_id, str) else None
    if owner is None:
        raise CarlosServiceAuthenticationError()
    key_owner, public_key = owner
    public_key_bytes = _decode_base64url(public_key, expected_length=32)
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, payload_bytes)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise CarlosServiceAuthenticationError() from exc

    # From here the holder of `key_owner`'s key signed this exact payload, so every refusal is
    # attributable and is recorded with its reason.
    def refusal(code: str) -> CarlosJobRefusal:
        return CarlosJobRefusal(
            code,
            key_owner=key_owner,
            key_id=key_id,
            assertion_id=canonical_assertion_id(payload.get("jti")),
        )

    if staff_assertion_present:
        raise refusal(JOB_REFUSAL_BOTH_HEADERS)
    if set(payload) != JOB_ASSERTION_FIELDS:
        raise refusal(JOB_REFUSAL_INVALID_CLAIMS)
    job = payload["job"]
    if not isinstance(job, str):
        raise refusal(JOB_REFUSAL_INVALID_CLAIMS)
    if job not in SYSTEM_JOBS:
        raise refusal(JOB_REFUSAL_UNKNOWN_JOB)
    if job != key_owner:
        raise refusal(JOB_REFUSAL_WRONG_KEY)
    issued_at = payload["iat"]
    expires_at = payload["exp"]
    assertion_id = canonical_assertion_id(payload["jti"])
    permission = payload["permission"]
    clinic_id = payload["clinic_id"]
    request_hash = payload["request_hash"]
    current_time = int(time()) if now is None else now
    if (
        payload["aud"] != JOB_ASSERTION_AUDIENCE
        or payload["iss"] != JOB_ASSERTION_ISSUER
        or not _is_whole_seconds(issued_at)
        or not _is_whole_seconds(expires_at)
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_JOB_ASSERTION_TTL_SECONDS
        or issued_at > current_time + JOB_ASSERTION_CLOCK_SKEW_SECONDS
        or assertion_id is None
        or not _is_permission_name(permission)
        or not isinstance(clinic_id, str)
        or not _is_request_hash(request_hash)
    ):
        raise refusal(JOB_REFUSAL_INVALID_CLAIMS)
    if expires_at <= current_time:
        raise refusal(JOB_REFUSAL_EXPIRED)
    if not compare_digest(request_hash, expected_request_hash):
        raise refusal(JOB_REFUSAL_REQUEST_MISMATCH)
    if clinic_id != expected_clinic_id:
        raise refusal(JOB_REFUSAL_CLINIC_MISMATCH)
    return JobPrincipal(
        job=job,
        display_name=SYSTEM_JOBS[job].display_name,
        clinic_id=clinic_id,
        permission=permission,
        key_id=key_id,
        assertion_id=assertion_id,
        assertion_expires_at=expires_at,
    )


def authenticate_carlos_job(
    settings: Settings,
    *,
    authorization: str | None,
    job_assertion: str,
    expected_request_hash: str,
    staff_assertion_present: bool = False,
) -> JobPrincipal:
    """Check the service token, then the job assertion, exactly as the staff path checks its own."""
    accepted_tokens = settings.accepted_internal_api_tokens
    job_keys = settings.resolved_internal_job_assertion_public_keys
    scheme, _, supplied_token = (authorization or "").partition(" ")
    if (
        not accepted_tokens
        or scheme.casefold() != "bearer"
        or not supplied_token
        or not matches_any_service_token(supplied_token, accepted_tokens)
        or not job_keys
    ):
        raise CarlosServiceAuthenticationError()
    return verify_job_assertion(
        job_keys,
        job_assertion,
        expected_request_hash=expected_request_hash,
        expected_clinic_id=settings.clinic_id,
        staff_assertion_present=staff_assertion_present,
    )


def consume_job_assertion(
    session_factory: sessionmaker[Session],
    principal: JobPrincipal,
) -> None:
    """Use the job assertion's nonce once, in the table staff assertions use."""
    try:
        consume_assertion_id(
            session_factory,
            principal.assertion_id,
            principal.assertion_expires_at,
        )
    except AssertionExpiredError as exc:
        raise CarlosJobRefusal.for_principal(JOB_REFUSAL_EXPIRED, principal) from exc
    except AssertionReplayError as exc:
        raise CarlosJobRefusal.for_principal(JOB_REFUSAL_REPLAY, principal) from exc
