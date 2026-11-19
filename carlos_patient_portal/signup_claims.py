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

"""The claim and result of a self sign-up request: what CARLOS does with the rows #15 stores.

CARLOS polls (carlos-portal#16, designed in #10); the portal never calls it. A claim leases the
oldest pending requests to the caller, with the decrypted details CARLOS needs to match a chart,
and a result ends the request:

- **Claim.** Up to N pending requests in the caller's clinic that have not expired and are not under
  a running lease, taken `FOR UPDATE SKIP LOCKED` so two pollers never receive the same request at
  once. Each gets its own lease token, which is returned once and stored only as its SHA-256. An
  expired lease makes a request claimable again.
- **Result.** `matched` (with the invite CARLOS made), `no_match` or `ineligible`. It needs the
  request's lease token while the lease runs, deletes the encrypted details, and keeps the result
  so that an identical repeat is answered as a repeat (`recorded` false, nothing changes). A
  different result for a reported request is a conflict.

Disclosure and refusals are deliberately plain:

- An unknown request, a request of another clinic and a wrong lease token are one and the same
  `SignupRequestNotFoundError`, so a caller cannot probe which ids exist or whose lease it is.
- Audit rows carry the keyed health-card hash the request was stored with, the job as the actor, the
  call's key id and assertion id, and the invite id of a match. Never the number, the date of birth,
  or the email, and nothing here logs a request id or a detail.
"""

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest
from secrets import token_urlsafe

from sqlalchemy import ColumnElement, and_, func, or_, select
from sqlalchemy.orm import Session

from carlos_patient_portal.audit import record_audit_event
from carlos_patient_portal.identity import IdentityProof, verify_identity_proof
from carlos_patient_portal.invites import activate_prepared_invite, prepare_create_invite
from carlos_patient_portal.models import (
    AUDIT_ACTOR_TYPE_SYSTEM,
    AUDIT_EVENT_SIGNUP_CLAIM,
    AUDIT_EVENT_SIGNUP_RESULT,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_SUCCESS,
    INVITE_STATUS_ACCEPTED,
    INVITE_STATUS_PENDING,
    INVITE_STATUS_PREPARED,
    SIGNUP_RESULT_MATCHED,
    PatientPortalInvite,
    PatientPortalSignupRequest,
    utc_now,
)
from carlos_patient_portal.self_signup import (
    SIGNUP_HEALTH_CARD_RESOURCE_TYPE,
    SignupRequestDetails,
    SignupRequestKeyUnavailableError,
    SignupRequestPayloadError,
    decrypt_signup_request,
    pending_signup_request_predicate,
)

logger = logging.getLogger(__name__)

# The most requests one claim returns. CARLOS matches each against the chart, so a batch is bounded.
MAX_SIGNUP_CLAIM_BATCH = 50
SIGNUP_CLAIM_REASON_UNREADABLE = "payload_unreadable"
LEASE_TOKEN_BYTES = 32


class SignupResultRefusal(Exception):
    """A result the portal refuses. `reason` and `health_card_hash` are for the audit trail only:
    the caller is told one fixed text per class, never which reason or whose request."""

    reason = "refused"

    def __init__(self, health_card_hash: str | None = None) -> None:
        super().__init__()
        self.health_card_hash = health_card_hash


class SignupRequestNotFoundError(SignupResultRefusal):
    """No such request for this caller: unknown, another clinic's, or a lease token not its own."""

    reason = "request_not_found"


class SignupLeaseTokenMismatchError(SignupRequestNotFoundError):
    """A request of this clinic, presented with a lease token that is not its own.

    The caller gets the same answer as for an unknown id; the audit trail tells them apart.
    """

    reason = "lease_token_mismatch"


class SignupLeaseExpiredError(SignupResultRefusal):
    """The request's lease ran out before the result arrived; it may be claimed again."""

    reason = "lease_expired"


class SignupResultConflictError(SignupResultRefusal):
    """The request already has a different result."""

    reason = "result_conflict"


class SignupResultInvalidError(SignupResultRefusal, ValueError):
    """The result cannot be recorded as sent: a match with no invite made for this request."""

    reason = "invite_not_for_request"


class SignupRequestClosedError(SignupResultRefusal):
    """The request already has a result: no invite can be prepared or committed for it."""

    reason = "request_closed"


class SignupInviteConflictError(SignupResultRefusal):
    """The request already has a prepared invite of another operation, or has none to commit."""

    reason = "invite_conflict"


class SignupInviteUnavailableError(Exception):
    """The request's details cannot be read, so no invite can be prepared from them."""


@dataclass(frozen=True)
class ClaimedSignupRequest:
    """One leased request, with what CARLOS matches on. The details stay out of repr."""

    request_id: int
    lease_token: str = field(repr=False)
    lease_expires_at: datetime
    requested_at: datetime
    details: SignupRequestDetails = field(repr=False)


@dataclass(frozen=True)
class SignupClaim:
    """The leased requests, and how many were skipped because their details could not be read."""

    requests: tuple[ClaimedSignupRequest, ...]
    # Quarantined by this claim: a key the keyring has, a payload that does not authenticate.
    unreadable: int
    # Pending requests left out because their key is not in the keyring (they wait for it).
    without_key: int = 0


@dataclass(frozen=True)
class SignupResultOutcome:
    request_id: int
    result: str
    invite_id: int | None
    # False when this result was already recorded: nothing changed.
    recorded: bool


def _as_utc(value: datetime) -> datetime:
    # SQLite hands back naive datetimes for timezone-aware columns.
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def hash_lease_token(lease_token: str) -> str:
    """The SHA-256 a lease is stored as; the token is 256 random bits, so it needs no keyed hash."""
    return sha256(lease_token.encode("utf-8")).hexdigest()


def claimable_predicate(now: datetime) -> ColumnElement[bool]:
    """A request a claim may lease: pending, and not under a lease that is still running."""
    return and_(
        pending_signup_request_predicate(now),
        or_(
            PatientPortalSignupRequest.lease_expires_at.is_(None),
            PatientPortalSignupRequest.lease_expires_at <= now,
        ),
    )


# Keyword-only so each security-relevant value is named at the call site.
def claim_signup_requests(  # NOSONAR
    session: Session,
    *,
    clinic_id: str,
    limit: int,
    lease_seconds: int,
    encryption_keys: Mapping[str, str],
    actor: str,
    actor_id: str,
    assertion_key_id: str | None,
    assertion_id: str | None,
    now: datetime | None = None,
) -> SignupClaim:
    """Lease up to `limit` pending requests of `clinic_id` and return them with their details.

    The caller's transaction commits the leases and the audit rows together. Two kinds of request
    cannot be read, and neither may starve the readable ones behind it:

    - one stored under a key that is not in the keyring is left out of the claim by its key id, so
      it never takes a place in a batch, is never audited again and again, and becomes claimable the
      moment the key is back; it is only counted (`without_key`) for the caller to log;
    - one stored under a key the keyring has, whose payload does not authenticate, can never heal.
      It is quarantined: leased to a token nobody is given until its own expiry (and then purged
      with the rest), and audited once as a failed claim with the health-card hash.

    An empty claim writes nothing.
    """
    if not 1 <= limit <= MAX_SIGNUP_CLAIM_BATCH:
        raise ValueError("claim limit out of range")
    current_time = now or utc_now()
    candidates = list(
        session.scalars(
            select(PatientPortalSignupRequest)
            .where(
                PatientPortalSignupRequest.clinic_id == clinic_id,
                claimable_predicate(current_time),
                PatientPortalSignupRequest.encryption_key_id.in_(list(encryption_keys)),
            )
            .order_by(PatientPortalSignupRequest.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    without_key = int(
        session.scalar(
            select(func.count(PatientPortalSignupRequest.id)).where(
                PatientPortalSignupRequest.clinic_id == clinic_id,
                claimable_predicate(current_time),
                PatientPortalSignupRequest.encryption_key_id.not_in(list(encryption_keys)),
            )
        )
        or 0
    )
    claimed: list[ClaimedSignupRequest] = []
    unreadable = 0
    lease_ends = current_time + timedelta(seconds=lease_seconds)
    for signup_request in candidates:
        try:
            details = decrypt_signup_request(signup_request, encryption_keys=encryption_keys)
        except (SignupRequestKeyUnavailableError, SignupRequestPayloadError):
            unreadable += 1
            # Quarantined: a lease no caller holds the token of, until the request expires.
            signup_request.lease_token_hash = hash_lease_token(token_urlsafe(LEASE_TOKEN_BYTES))
            signup_request.lease_expires_at = signup_request.expires_at
            session.flush()
            record_audit_event(
                session,
                event_type=AUDIT_EVENT_SIGNUP_CLAIM,
                outcome=AUDIT_OUTCOME_FAILURE,
                actor_type=AUDIT_ACTOR_TYPE_SYSTEM,
                actor=actor,
                actor_id=actor_id,
                clinic_id=clinic_id,
                resource_type=SIGNUP_HEALTH_CARD_RESOURCE_TYPE,
                resource_id=signup_request.health_card_hash,
                reason=SIGNUP_CLAIM_REASON_UNREADABLE,
                assertion_key_id=assertion_key_id,
                assertion_id=assertion_id,
            )
            continue
        lease_token = token_urlsafe(LEASE_TOKEN_BYTES)
        signup_request.lease_token_hash = hash_lease_token(lease_token)
        signup_request.lease_expires_at = lease_ends
        session.flush()
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_SIGNUP_CLAIM,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_SYSTEM,
            actor=actor,
            actor_id=actor_id,
            clinic_id=clinic_id,
            resource_type=SIGNUP_HEALTH_CARD_RESOURCE_TYPE,
            resource_id=signup_request.health_card_hash,
            assertion_key_id=assertion_key_id,
            assertion_id=assertion_id,
        )
        claimed.append(
            ClaimedSignupRequest(
                request_id=signup_request.id,
                lease_token=lease_token,
                lease_expires_at=lease_ends,
                requested_at=signup_request.created_at,
                details=details,
            )
        )
    if unreadable or without_key:
        logger.warning(
            "Self sign-up claim: %d request(s) quarantined as unreadable, %d held back for a "
            "key that is not in the keyring",
            unreadable,
            without_key,
        )
    return SignupClaim(requests=tuple(claimed), unreadable=unreadable, without_key=without_key)


def _lock_request(
    session: Session,
    request_id: int,
    *,
    clinic_id: str,
    lease_token: str,
) -> PatientPortalSignupRequest:
    """The request, locked, for a caller that holds its lease token.

    An unknown id and another clinic's request are one refusal; a request of this clinic with a
    token that is not its own is another, which the caller sees as the same answer and the audit
    trail tells apart. The token is compared even when there is no row or lease, so the work does
    not depend on which it was.
    """
    signup_request = session.scalar(
        select(PatientPortalSignupRequest)
        .where(
            PatientPortalSignupRequest.id == request_id,
            PatientPortalSignupRequest.clinic_id == clinic_id,
        )
        .with_for_update()
    )
    stored_hash = signup_request.lease_token_hash if signup_request is not None else None
    token_matches = compare_digest(hash_lease_token(lease_token), stored_hash or "0" * 64)
    if signup_request is None:
        raise SignupRequestNotFoundError()
    if stored_hash is None or not token_matches:
        raise SignupLeaseTokenMismatchError(signup_request.health_card_hash)
    return signup_request


def _require_running_lease(signup_request: PatientPortalSignupRequest, now: datetime) -> None:
    lease_expires_at = signup_request.lease_expires_at
    if lease_expires_at is None or _as_utc(lease_expires_at) <= now:
        raise SignupLeaseExpiredError(signup_request.health_card_hash)


def _invite_is_live(invite: PatientPortalInvite, now: datetime) -> bool:
    """Whether an invite is one that was sent for a request and can still stand for its answer.

    `pending` (sent, not yet used) while it has not expired, and `accepted` (the patient activated
    before CARLOS reported). Not `prepared` (staged, never committed or delivered), nor `revoked`
    or `superseded` (replaced by a newer invite): the patient would be told to wait for an email
    whose link cannot be used.
    """
    if invite.status == INVITE_STATUS_ACCEPTED:
        return True
    return invite.status == INVITE_STATUS_PENDING and _as_utc(invite.expires_at) > now


def _require_invite_for_request(
    session: Session,
    signup_request: PatientPortalSignupRequest,
    *,
    clinic_id: str,
    invite_id: int | None,
    identity_proof_secret: str,
    encryption_keys: Mapping[str, str],
    now: datetime,
) -> None:
    """Raise SignupResultInvalidError unless the invite was made for this request's details.

    One refusal for every reason (no such invite, another clinic's, not live, older than the
    request, other details, details that cannot be read), so the answer says nothing about which.
    """
    refusal_hash = signup_request.health_card_hash
    invite = session.scalar(
        select(PatientPortalInvite).where(
            PatientPortalInvite.id == invite_id,
            PatientPortalInvite.clinic_id == clinic_id,
        )
    )
    try:
        if (
            invite is None
            or signup_request.prepared_invite_id != invite_id
            or not _invite_is_live(invite, now)
            or _as_utc(invite.created_at) < _as_utc(signup_request.created_at)
        ):
            raise SignupResultInvalidError(refusal_hash)
        details = decrypt_signup_request(signup_request, encryption_keys=encryption_keys)
        proof = IdentityProof(
            email=details.email,
            date_of_birth=details.date_of_birth,
            health_card_number=details.health_card_number,
        )
    except (SignupRequestKeyUnavailableError, SignupRequestPayloadError) as exc:
        raise SignupResultInvalidError(refusal_hash) from exc
    if not verify_identity_proof(
        proof,
        identity_proof_secret,
        salt=invite.proof_salt,
        email_hash=invite.proof_email_hash,
        date_of_birth_hash=invite.proof_date_of_birth_hash,
        health_card_hash=invite.proof_health_card_hash,
    ):
        raise SignupResultInvalidError(refusal_hash)


# Keyword-only so each security-relevant value is named at the call site.
def record_signup_result(  # NOSONAR
    session: Session,
    request_id: int,
    *,
    clinic_id: str,
    lease_token: str,
    result: str,
    invite_id: int | None,
    identity_proof_secret: str,
    encryption_keys: Mapping[str, str],
    actor: str,
    actor_id: str,
    assertion_key_id: str | None,
    assertion_id: str | None,
    now: datetime | None = None,
) -> SignupResultOutcome:
    """Record CARLOS's result for a leased request and delete its stored details.

    Raises SignupRequestNotFoundError for an unknown id, another clinic's request, or a lease token
    that is not this request's (one outcome for all three); SignupResultConflictError for a
    different result than the one already recorded; SignupLeaseExpiredError when the lease ran out
    first; SignupResultInvalidError for a match whose invite is not one made for this request.

    A match must name the invite the sign-up job prepared for this request (`prepared_invite_id`;
    `prepare_signup_invite`), which (1) is this clinic's, (2) is live: `pending` and not expired,
    or `accepted`, (3) was created after the request was stored, and (4) carries the identity proof
    of exactly what the patient typed: the same email, date of birth and health card number,
    checked with the activation's own comparison (`verify_identity_proof`). The invite model has
    no link to a request, so (4) is the link: CARLOS matched those details against the chart, and
    the invite it made for the match holds their hashes. What is not checked is who created the
    invite: under the invite routes as they are, that is the system actor's staff assertion, which
    this module cannot tell from a person's.
    """
    current_time = now or utc_now()
    signup_request = _lock_request(
        session, request_id, clinic_id=clinic_id, lease_token=lease_token
    )

    if signup_request.result is not None:
        if signup_request.result == result and signup_request.invite_id == invite_id:
            return SignupResultOutcome(
                request_id=signup_request.id,
                result=result,
                invite_id=invite_id,
                recorded=False,
            )
        raise SignupResultConflictError(signup_request.health_card_hash)

    lease_expires_at = signup_request.lease_expires_at
    if lease_expires_at is None or _as_utc(lease_expires_at) <= current_time:
        raise SignupLeaseExpiredError(signup_request.health_card_hash)

    if result == SIGNUP_RESULT_MATCHED:
        _require_invite_for_request(
            session,
            signup_request,
            clinic_id=clinic_id,
            invite_id=invite_id,
            identity_proof_secret=identity_proof_secret,
            encryption_keys=encryption_keys,
            now=current_time,
        )

    signup_request.encrypted_payload = None
    signup_request.encryption_nonce = None
    signup_request.result = result
    signup_request.invite_id = invite_id
    signup_request.resulted_at = current_time
    session.flush()
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_SIGNUP_RESULT,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_SYSTEM,
        actor=actor,
        actor_id=actor_id,
        clinic_id=clinic_id,
        invite_id=invite_id,
        resource_type=SIGNUP_HEALTH_CARD_RESOURCE_TYPE,
        resource_id=signup_request.health_card_hash,
        reason=result,
        assertion_key_id=assertion_key_id,
        assertion_id=assertion_id,
    )
    return SignupResultOutcome(
        request_id=signup_request.id,
        result=result,
        invite_id=invite_id,
        recorded=True,
    )


# Keyword-only so each security-relevant value is named at the call site.
def prepare_signup_invite(  # NOSONAR
    session: Session,
    request_id: int,
    *,
    clinic_id: str,
    lease_token: str,
    demographic_no: int,
    delivery_operation_id: str,
    identity_proof_secret: str,
    encryption_secret: str,
    encryption_key_id: str,
    encryption_keys: Mapping[str, str],
    actor: str,
    actor_id: str,
    now: datetime | None = None,
) -> tuple[PatientPortalInvite, str]:
    """Prepare the one invite of a request the caller holds the lease on.

    The identity proof is copied from the request's own stored details, never taken from the
    caller: the invite carries the email, date of birth and health card number the patient typed,
    which CARLOS matched against the chart. The invite's id is recorded on the request, and a
    match can only be reported with it. Preparing again with the same operation id recovers the
    same invite and token; another operation id for a request that has one is a conflict.

    Raises the same refusals as a result for a request that is not the caller's, whose lease ran
    out, or that already has a result; SignupInviteUnavailableError when its details cannot be
    read; and the invite layer's own errors (an account or a pending invite already exists).
    """
    current_time = now or utc_now()
    signup_request = _lock_request(
        session, request_id, clinic_id=clinic_id, lease_token=lease_token
    )
    if signup_request.result is not None:
        raise SignupRequestClosedError(signup_request.health_card_hash)
    _require_running_lease(signup_request, current_time)
    if signup_request.prepared_invite_id is not None:
        prepared = session.get(PatientPortalInvite, signup_request.prepared_invite_id)
        if (
            prepared is None
            or prepared.status != INVITE_STATUS_PREPARED
            or prepared.delivery_operation_id != delivery_operation_id
        ):
            raise SignupInviteConflictError(signup_request.health_card_hash)
    try:
        details = decrypt_signup_request(signup_request, encryption_keys=encryption_keys)
    except (SignupRequestKeyUnavailableError, SignupRequestPayloadError) as exc:
        raise SignupInviteUnavailableError() from exc
    invite, invite_token = prepare_create_invite(
        session,
        demographic_no,
        actor,
        actor_id=actor_id,
        delivery_operation_id=delivery_operation_id,
        identity_proof=IdentityProof(
            email=details.email,
            date_of_birth=details.date_of_birth,
            health_card_number=details.health_card_number,
        ),
        proof_secret=identity_proof_secret,
        encryption_secret=encryption_secret,
        encryption_key_id=encryption_key_id,
        encryption_keys=encryption_keys,
        clinic_id=clinic_id,
    )
    signup_request.prepared_invite_id = invite.id
    session.flush()
    return invite, invite_token


# Keyword-only so each security-relevant value is named at the call site.
def commit_signup_invite(  # NOSONAR
    session: Session,
    request_id: int,
    *,
    clinic_id: str,
    lease_token: str,
    delivery_operation_id: str,
    delivery_reference: str,
    actor: str,
    actor_id: str,
    now: datetime | None = None,
) -> PatientPortalInvite:
    """Release the invite prepared for a request once CARLOS has durably queued its email.

    Only the request's own prepared invite can be committed: the route names no invite id.
    """
    current_time = now or utc_now()
    signup_request = _lock_request(
        session, request_id, clinic_id=clinic_id, lease_token=lease_token
    )
    if signup_request.result is not None:
        raise SignupRequestClosedError(signup_request.health_card_hash)
    _require_running_lease(signup_request, current_time)
    if signup_request.prepared_invite_id is None:
        raise SignupInviteConflictError(signup_request.health_card_hash)
    return activate_prepared_invite(
        session,
        signup_request.prepared_invite_id,
        delivery_operation_id=delivery_operation_id,
        delivery_reference=delivery_reference,
        clinic_id=clinic_id,
        actor=actor,
        actor_id=actor_id,
    )


def record_signup_refusal(
    session: Session,
    refusal: SignupResultRefusal,
    *,
    clinic_id: str,
    actor: str,
    actor_id: str,
    assertion_key_id: str | None,
    assertion_id: str | None,
) -> None:
    """Audit a refused result, from a transaction of its own.

    The result route's transaction is rolled back by the refusal, so this is written by a separate
    session that commits. The row carries the reason (which the caller is never told), the job as
    the actor, the call's key id and assertion id, and, when the request exists, its keyed
    health-card hash. Never the lease token, the details, or the id the caller sent.
    """
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_SIGNUP_RESULT,
        outcome=AUDIT_OUTCOME_FAILURE,
        actor_type=AUDIT_ACTOR_TYPE_SYSTEM,
        actor=actor,
        actor_id=actor_id,
        clinic_id=clinic_id,
        resource_type=SIGNUP_HEALTH_CARD_RESOURCE_TYPE if refusal.health_card_hash else None,
        resource_id=refusal.health_card_hash,
        reason=refusal.reason,
        assertion_key_id=assertion_key_id,
        assertion_id=assertion_id,
    )

