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

"""Self sign-up requests: the patient-facing half of a patient-initiated invite.

A patient asks for a portal account on `/auth/sign-up` with their health card number, date of birth
and email address (carlos-portal#15, designed in #10). The portal looks nothing up and calls
nothing. It validates the request, applies the database rate limits, stores the details encrypted,
and shows the same page in every case. CARLOS collects stored requests later, matches them against
a chart, and sends a normal invite to the email address already on file.

The rule this rests on: nothing typed on the sign-up page is ever used as a destination. The typed
email is kept only so CARLOS can compare it with the one on file.

The seam for carlos-portal#16, the internal API CARLOS polls:

- `pending_signup_request_predicate` is the filter a claim must use, so a request past its TTL is
  never handed out.
- `decrypt_signup_request` turns a claimed row back into `SignupRequestDetails`.
- Reporting a result deletes the row. `health_card_hash` on the row is the keyed hash the
  `signup.request` audit events carry, so a claim or result can be audited without decrypting.

#16 adds what the claim itself needs: a lease column, the `portal.signup.manage` permission, and
the `signup.claim` and `signup.result` audit event types.
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from secrets import token_bytes

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import ColumnElement, delete, func, select
from sqlalchemy.orm import Session

from carlos_patient_portal.audit import hash_sensitive_reference, record_audit_event
from carlos_patient_portal.config import Settings
from carlos_patient_portal.identity import MIN_HEALTH_CARD_NUMBER_LENGTH
from carlos_patient_portal.models import (
    AUDIT_ACTOR_TYPE_PATIENT,
    AUDIT_EVENT_SIGNUP_REQUEST,
    AUDIT_OUTCOME_SUCCESS,
    AUDIT_OUTCOME_THROTTLED,
    SIGNUP_REQUEST_NONCE_LENGTH,
    PatientPortalAuditEvent,
    PatientPortalSignupRequest,
    utc_now,
)

# Same keyring as the outbox, but its own derived key, so a sign-up payload and an outbound email
# payload can never be decrypted with each other's key.
SIGNUP_KEY_DERIVATION_INFO = b"carlos-patient-portal:signup-request:v1"
SIGNUP_ASSOCIATED_DATA_PREFIX = "carlos-patient-portal.signup-request.v1"
MAX_SIGNUP_PAYLOAD_BYTES = 1024
# Keyed-hash purposes, so these hashes never equal one made for activation or sign-in.
SIGNUP_CLIENT_HASH_PURPOSE = "signup_client"
SIGNUP_HEALTH_CARD_HASH_PURPOSE = "signup_health_card"
# The audit row's resource is the keyed hash of the health card, never the number itself. The
# existing (resource_type, resource_id, created_at) index serves the per-card count.
SIGNUP_HEALTH_CARD_RESOURCE_TYPE = "signup_health_card"
SIGNUP_REASON_CLIENT_RATE_LIMITED = "client_rate_limited"
SIGNUP_REASON_HEALTH_CARD_RATE_LIMITED = "health_card_rate_limited"
SIGNUP_OUTCOME_STORED = "stored"
SIGNUP_OUTCOME_RATE_LIMITED = "rate_limited"
# PostgreSQL transaction-scoped advisory lock ("CPSIGNUP"), as the password-reset queue uses: it
# makes the backlog count, both rate-limit counts and the insert one atomic decision across every
# web worker. Sign-up traffic is low, so one lock costs nothing that matters.
SIGNUP_ADMISSION_LOCK_ID = 0x43505349474E5550
# Each submission also deletes up to this many expired requests, so a TTL is kept even between
# cleanup-transient-auth runs. The work does not depend on what was typed.
SIGNUP_PURGE_BATCH_SIZE = 100
# Ontario cards print a one- or two-letter version code after the number.
_TRAILING_VERSION_CODE = re.compile(r"(?P<number>.*[0-9])[A-Z]{1,2}")


class SignupQueueFullError(Exception):
    """The stored-request backlog has reached PATIENT_PORTAL_SELF_SIGNUP_QUEUE_MAX_PENDING."""


class SignupRequestKeyUnavailableError(Exception):
    """The key a stored request was encrypted under is not in the configured outbox keyring."""


class SignupRequestPayloadError(Exception):
    """A stored request could not be authenticated or read."""


@dataclass(frozen=True)
class SelfSignupPolicy:
    """The TTL, the two rate limits, and the backlog cap, from settings."""

    request_ttl: timedelta
    client_window: timedelta
    max_requests_per_client: int
    health_card_window: timedelta
    max_requests_per_health_card: int
    max_pending: int

    @classmethod
    def from_settings(cls, settings: Settings) -> "SelfSignupPolicy":
        return cls(
            request_ttl=timedelta(seconds=settings.self_signup_request_ttl_seconds),
            client_window=timedelta(seconds=settings.self_signup_client_window_seconds),
            max_requests_per_client=settings.self_signup_max_requests_per_client,
            health_card_window=timedelta(
                seconds=settings.self_signup_health_card_window_seconds
            ),
            max_requests_per_health_card=settings.self_signup_max_requests_per_health_card,
            max_pending=settings.self_signup_queue_max_pending,
        )


@dataclass(frozen=True)
class SignupRequestDetails:
    """What the patient typed, normalized. Kept out of repr so it never reaches a log line."""

    health_card_number: str = field(repr=False)
    date_of_birth: date = field(repr=False)
    email: str = field(repr=False)


@dataclass(frozen=True)
class SignupBacklog:
    """Unexpired requests waiting for CARLOS, and when the oldest arrived."""

    pending: int
    oldest_created_at: datetime | None

    def oldest_age_seconds(self, now: datetime) -> int | None:
        if self.oldest_created_at is None:
            return None
        return max(0, int((_as_utc(now) - _as_utc(self.oldest_created_at)).total_seconds()))


def _as_utc(value: datetime) -> datetime:
    # SQLite hands back naive datetimes for timezone-aware columns.
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def health_card_rate_key(normalized_health_card_number: str) -> str:
    """The part of a normalized health card number the per-card limit counts by.

    Patients type an Ontario version code or leave it off (carlos-portal#23), so the limit counts
    the number without one or two trailing letters. Adding, dropping or changing them therefore
    does not start a fresh count. Two cards share a count only when their numbers are the same
    apart from those letters, which makes the limit stricter, never looser.
    """
    match = _TRAILING_VERSION_CODE.fullmatch(normalized_health_card_number)
    if match is None or len(match.group("number")) < MIN_HEALTH_CARD_NUMBER_LENGTH:
        return normalized_health_card_number
    return match.group("number")


def hash_signup_health_card(audit_hash_secret: str, normalized_health_card_number: str) -> str:
    """The keyed hash that stands for a health card in audit events and the stored row."""
    return hash_sensitive_reference(
        audit_hash_secret,
        SIGNUP_HEALTH_CARD_HASH_PURPOSE,
        health_card_rate_key(normalized_health_card_number),
    )


def hash_signup_client(audit_hash_secret: str, client_reference: str) -> str:
    """The keyed hash that stands for the client address in audit events."""
    return hash_sensitive_reference(audit_hash_secret, SIGNUP_CLIENT_HASH_PURPOSE, client_reference)


def derive_signup_key(secret: str) -> bytes:
    normalized = secret.strip()
    if not normalized:
        raise ValueError("sign-up encryption secret must not be blank")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=SIGNUP_KEY_DERIVATION_INFO,
    ).derive(normalized.encode("utf-8"))


def _associated_data(*, clinic_id: str, health_card_hash: str) -> bytes:
    # Binds the ciphertext to its clinic and its card hash: moved to another row, it fails to open.
    return f"{SIGNUP_ASSOCIATED_DATA_PREFIX}:{clinic_id}:{health_card_hash}".encode()


def encrypt_signup_details(
    details: SignupRequestDetails,
    *,
    encryption_secret: str,
    clinic_id: str,
    health_card_hash: str,
) -> tuple[bytes, bytes]:
    """Return (ciphertext, nonce) for the stored row."""
    encoded = json.dumps(
        {
            "date_of_birth": details.date_of_birth.isoformat(),
            "email": details.email,
            "health_card_number": details.health_card_number,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    if len(encoded) > MAX_SIGNUP_PAYLOAD_BYTES:
        raise ValueError("sign-up request payload is too large")
    nonce = token_bytes(SIGNUP_REQUEST_NONCE_LENGTH)
    ciphertext = AESGCM(derive_signup_key(encryption_secret)).encrypt(
        nonce,
        encoded,
        _associated_data(clinic_id=clinic_id, health_card_hash=health_card_hash),
    )
    return ciphertext, nonce


def decrypt_signup_request(
    signup_request: PatientPortalSignupRequest,
    *,
    encryption_keys: Mapping[str, str],
) -> SignupRequestDetails:
    """Read a stored request back. The seam carlos-portal#16's claim builds on."""
    secret = encryption_keys.get(signup_request.encryption_key_id)
    if secret is None:
        raise SignupRequestKeyUnavailableError(
            f"sign-up request key {signup_request.encryption_key_id!r} is not in the keyring"
        )
    try:
        encoded = AESGCM(derive_signup_key(secret)).decrypt(
            signup_request.encryption_nonce,
            signup_request.encrypted_payload,
            _associated_data(
                clinic_id=signup_request.clinic_id,
                health_card_hash=signup_request.health_card_hash,
            ),
        )
        payload = json.loads(encoded)
        return SignupRequestDetails(
            health_card_number=str(payload["health_card_number"]),
            date_of_birth=date.fromisoformat(payload["date_of_birth"]),
            email=str(payload["email"]),
        )
    except (InvalidTag, ValueError, TypeError, KeyError):
        raise SignupRequestPayloadError("sign-up request payload is invalid") from None


def pending_signup_request_predicate(now: datetime) -> ColumnElement[bool]:
    """A request CARLOS may still collect: its TTL has not passed."""
    return PatientPortalSignupRequest.expires_at > now


def count_recent_signup_requests(
    session: Session,
    *,
    since: datetime,
    client_reference_hash: str | None = None,
    health_card_hash: str | None = None,
) -> int:
    """Stored requests since `since` from one client, or for one card, from the audit trail.

    Only stored requests count. A refused one is audited too, but counting it would let a flood
    keep a patient locked out indefinitely.
    """
    if (client_reference_hash is None) == (health_card_hash is None):
        raise ValueError("pass exactly one of client_reference_hash or health_card_hash")
    statement = select(func.count(PatientPortalAuditEvent.id)).where(
        PatientPortalAuditEvent.event_type == AUDIT_EVENT_SIGNUP_REQUEST,
        PatientPortalAuditEvent.outcome == AUDIT_OUTCOME_SUCCESS,
        PatientPortalAuditEvent.created_at >= since,
    )
    if client_reference_hash is not None:
        statement = statement.where(
            PatientPortalAuditEvent.client_reference_hash == client_reference_hash
        )
    else:
        statement = statement.where(
            PatientPortalAuditEvent.resource_type == SIGNUP_HEALTH_CARD_RESOURCE_TYPE,
            PatientPortalAuditEvent.resource_id == health_card_hash,
        )
    return int(session.scalar(statement) or 0)


def purge_expired_signup_requests(
    session: Session,
    *,
    now: datetime | None = None,
    batch_size: int = SIGNUP_PURGE_BATCH_SIZE,
    dry_run: bool = False,
) -> int:
    """Delete up to `batch_size` requests whose TTL has passed; return how many."""
    current_time = now or utc_now()
    expired = PatientPortalSignupRequest.expires_at <= current_time
    candidates = (
        select(PatientPortalSignupRequest.id)
        .where(expired)
        .order_by(PatientPortalSignupRequest.id)
        .limit(batch_size)
    )
    if not dry_run:
        # A row a CARLOS claim holds (carlos-portal#16) is left for the next run.
        candidates = candidates.with_for_update(skip_locked=True)
    request_ids = list(session.scalars(candidates))
    if dry_run or not request_ids:
        return len(request_ids)
    result = session.execute(
        delete(PatientPortalSignupRequest).where(
            PatientPortalSignupRequest.id.in_(request_ids),
            expired,
        )
    )
    return int(result.rowcount or 0)


def summarize_signup_backlog(session: Session, *, now: datetime | None = None) -> SignupBacklog:
    """How many requests wait for CARLOS and since when; counts and a timestamp, nothing else."""
    current_time = now or utc_now()
    count, oldest_created_at = session.execute(
        select(
            func.count(PatientPortalSignupRequest.id),
            func.min(PatientPortalSignupRequest.created_at),
        ).where(pending_signup_request_predicate(current_time))
    ).one()
    return SignupBacklog(pending=int(count or 0), oldest_created_at=oldest_created_at)


# Keyword-only so each security-relevant value is named at the call site.
def submit_signup_request(  # NOSONAR
    session: Session,
    *,
    details: SignupRequestDetails,
    clinic_id: str,
    client_reference_hash: str,
    health_card_hash: str,
    encryption_secret: str,
    encryption_key_id: str,
    policy: SelfSignupPolicy,
    now: datetime | None = None,
) -> str:
    """Rate-limit, then store, one request. Return SIGNUP_OUTCOME_STORED or ..._RATE_LIMITED.

    The work does not depend on who the details belong to: nothing is looked up, and both counts
    are always taken. A request over either limit is refused before anything is stored, and is
    audited with its keyed hashes only. Raises SignupQueueFullError when the backlog is full; the
    caller rolls back so the advisory lock is released at once.
    """
    current_time = now or utc_now()
    if session.get_bind().dialect.name == "postgresql":
        session.execute(select(func.pg_advisory_xact_lock(SIGNUP_ADMISSION_LOCK_ID)))
    purge_expired_signup_requests(session, now=current_time)
    backlog = session.scalar(
        select(func.count(PatientPortalSignupRequest.id)).where(
            pending_signup_request_predicate(current_time)
        )
    )
    if backlog is not None and backlog >= policy.max_pending:
        raise SignupQueueFullError()

    client_count = count_recent_signup_requests(
        session,
        since=current_time - policy.client_window,
        client_reference_hash=client_reference_hash,
    )
    health_card_count = count_recent_signup_requests(
        session,
        since=current_time - policy.health_card_window,
        health_card_hash=health_card_hash,
    )
    refusal_reason = None
    if client_count >= policy.max_requests_per_client:
        refusal_reason = SIGNUP_REASON_CLIENT_RATE_LIMITED
    elif health_card_count >= policy.max_requests_per_health_card:
        refusal_reason = SIGNUP_REASON_HEALTH_CARD_RATE_LIMITED
    if refusal_reason is not None:
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_SIGNUP_REQUEST,
            outcome=AUDIT_OUTCOME_THROTTLED,
            actor_type=AUDIT_ACTOR_TYPE_PATIENT,
            clinic_id=clinic_id,
            client_reference_hash=client_reference_hash,
            resource_type=SIGNUP_HEALTH_CARD_RESOURCE_TYPE,
            resource_id=health_card_hash,
            reason=refusal_reason,
        )
        return SIGNUP_OUTCOME_RATE_LIMITED

    ciphertext, nonce = encrypt_signup_details(
        details,
        encryption_secret=encryption_secret,
        clinic_id=clinic_id,
        health_card_hash=health_card_hash,
    )
    session.add(
        PatientPortalSignupRequest(
            clinic_id=clinic_id,
            health_card_hash=health_card_hash,
            encrypted_payload=ciphertext,
            encryption_nonce=nonce,
            encryption_key_id=encryption_key_id,
            created_at=current_time,
            expires_at=current_time + policy.request_ttl,
        )
    )
    session.flush()
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_SIGNUP_REQUEST,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_PATIENT,
        clinic_id=clinic_id,
        client_reference_hash=client_reference_hash,
        resource_type=SIGNUP_HEALTH_CARD_RESOURCE_TYPE,
        resource_id=health_card_hash,
    )
    return SIGNUP_OUTCOME_STORED
