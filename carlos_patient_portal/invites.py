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

from collections.abc import Mapping
from datetime import UTC, timedelta
from hashlib import sha256
from secrets import compare_digest, token_bytes, token_urlsafe

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal.audit import record_audit_event
from carlos_patient_portal.identity import (
    IdentityProof,
    build_identity_hashes,
    reject_control_characters,
)
from carlos_patient_portal.models import (
    AUDIT_ACTOR_TYPE_STAFF,
    AUDIT_EVENT_INVITE_CREATE,
    AUDIT_EVENT_INVITE_RESEND,
    AUDIT_EVENT_INVITE_REVOKE,
    AUDIT_EVENT_STAFF_ACTION,
    AUDIT_OUTCOME_SUCCESS,
    IDENTITY_PROOF_HASH_VERSION,
    INVITE_STATUS_ACCEPTED,
    INVITE_STATUS_PENDING,
    INVITE_STATUS_PREPARED,
    INVITE_STATUS_REVOKED,
    INVITE_STATUS_SUPERSEDED,
    MAX_CLINIC_ID_LENGTH,
    OUTBOX_NONCE_LENGTH,
    PatientPortalAccount,
    PatientPortalInvite,
    utc_now,
)

INVITE_TOKEN_BYTES = 32
DEFAULT_INVITE_TTL = timedelta(days=7)
DEFAULT_INVITE_LIST_LIMIT = 10
MAX_INVITE_LIST_LIMIT = 100
MAX_ACTOR_LENGTH = 128
PROOF_SALT_BYTES = 16
INVITE_PREPARATION_KEY_INFO = b"carlos-patient-portal:invite-preparation:v1"
INVITE_PREPARATION_AAD = "carlos-patient-portal.invite-preparation.v1"


class AccountAlreadyExistsError(Exception):
    """Raised when a patient already has a portal account."""


class PendingInviteExistsError(Exception):
    """Raised when another request creates a pending invite first."""


class InviteNotFoundError(Exception):
    """Raised when an invite id does not exist."""


class RevokedInviteError(Exception):
    """Raised when a revoked invite cannot be reused."""


class AcceptedInviteError(Exception):
    """Raised when an accepted invite cannot be reused."""


class SupersededInviteError(Exception):
    """Raised when a superseded invite cannot be issued again."""


class InvitePreparationConflictError(Exception):
    """Raised when a delivery operation cannot safely prepare or activate an invite."""


class InvitePreparationKeyUnavailableError(Exception):
    """Raised when a prepared token's encryption key is no longer configured."""


def create_invite_token() -> str:
    return token_urlsafe(INVITE_TOKEN_BYTES)


def create_proof_salt() -> str:
    return token_urlsafe(PROOF_SALT_BYTES)


def normalize_clinic_id(clinic_id: str) -> str:
    normalized_clinic_id = clinic_id.strip()
    if not normalized_clinic_id:
        raise ValueError("clinic_id must not be blank")
    if len(normalized_clinic_id) > MAX_CLINIC_ID_LENGTH:
        raise ValueError(f"clinic_id must be {MAX_CLINIC_ID_LENGTH} characters or fewer")
    return normalized_clinic_id


def normalize_staff_actor(actor: str) -> str:
    normalized_actor = actor.strip()
    if not normalized_actor:
        raise ValueError("actor must not be blank")
    if len(normalized_actor) > MAX_ACTOR_LENGTH:
        raise ValueError(f"actor must be {MAX_ACTOR_LENGTH} characters or fewer")
    # Rejected here, on the way in, rather than only on the FHIR read path. The asymmetry was a
    # poison pill: this function accepted "O\x92Brien" from a CARLOS header, and
    # build_fhir_r4_document_reference then raised on every read, permanently 500ing that
    # patient's entire DocumentReference bundle and every Practitioner read with no
    # patient-side recovery. Failing at the write boundary makes it a 422 CARLOS can act on.
    reject_control_characters(normalized_actor, "actor")
    return normalized_actor


def normalize_staff_actor_id(actor_id: str | None, actor: str) -> str:
    return normalize_staff_actor(actor if actor_id is None else actor_id)


def validate_demographic_no(demographic_no: int) -> None:
    if demographic_no <= 0:
        raise ValueError("demographic_no must be positive")


def validate_list_pagination(limit: int, offset: int) -> None:
    if limit < 1 or limit > MAX_INVITE_LIST_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_INVITE_LIST_LIMIT}")
    if offset < 0 or offset > 100_000:
        raise ValueError("offset must be between 0 and 100000")


def hash_invite_token(token: str) -> str:
    """Hash an invite token for storage and lookup.

    Deliberately unkeyed, unlike `auth.hash_auth_token` and the identity-proof hashes in this file.
    The token is 32 random bytes, so an unkeyed digest is not brute-forceable, and keeping the
    lookup key independent of `PATIENT_PORTAL_IDENTITY_PROOF_SECRET` means rotating that secret
    invalidates only the proof comparison — an already-delivered invite link keeps resolving to its
    row and fails with a clean "details could not be verified" rather than "no such invite".
    """
    return sha256(token.encode("utf-8")).hexdigest()


def _invite_preparation_key(secret: str) -> bytes:
    normalized = secret.strip()
    if not normalized:
        raise ValueError("invite preparation encryption secret must not be blank")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=INVITE_PREPARATION_KEY_INFO,
    ).derive(normalized.encode("utf-8"))


def _invite_preparation_aad(invite: PatientPortalInvite) -> bytes:
    return (
        f"{INVITE_PREPARATION_AAD}:{invite.clinic_id}:"
        f"{invite.demographic_no}:{invite.delivery_operation_id}"
    ).encode()


def _protect_prepared_token(
    invite: PatientPortalInvite,
    token: str,
    *,
    encryption_secret: str,
    encryption_key_id: str,
) -> None:
    nonce = token_bytes(OUTBOX_NONCE_LENGTH)
    invite.encrypted_invite_token = AESGCM(_invite_preparation_key(encryption_secret)).encrypt(
        nonce, token.encode(), _invite_preparation_aad(invite)
    )
    invite.invite_token_nonce = nonce
    invite.invite_token_key_id = encryption_key_id


def _disclose_prepared_token(
    invite: PatientPortalInvite,
    *,
    encryption_keys: Mapping[str, str],
) -> str:
    key_id = invite.invite_token_key_id
    if key_id is None or key_id not in encryption_keys:
        raise InvitePreparationKeyUnavailableError()
    if invite.encrypted_invite_token is None or invite.invite_token_nonce is None:
        raise InvitePreparationConflictError()
    try:
        token = AESGCM(_invite_preparation_key(encryption_keys[key_id])).decrypt(
            invite.invite_token_nonce,
            invite.encrypted_invite_token,
            _invite_preparation_aad(invite),
        )
        return token.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError, ValueError):
        raise InvitePreparationKeyUnavailableError() from None


def _same_identity_proof(
    invite: PatientPortalInvite,
    identity_proof: IdentityProof,
    proof_secret: str,
) -> bool:
    if invite.proof_salt is None:
        return False
    candidate = build_identity_hashes(identity_proof, proof_secret, invite.proof_salt)
    return all(
        compare_digest(candidate[name], getattr(invite, name) or "")
        for name in (
            "proof_email_hash",
            "proof_date_of_birth_hash",
            "proof_health_card_hash",
        )
    )


def patient_has_account(
    session: Session,
    *,
    clinic_id: str,
    demographic_no: int,
) -> bool:
    return (
        session.scalar(
            select(PatientPortalAccount.id).where(
                PatientPortalAccount.clinic_id == clinic_id,
                PatientPortalAccount.demographic_no == demographic_no,
            )
        )
        is not None
    )


def revoke_pending_invites_for_patient(
    session: Session,
    *,
    clinic_id: str,
    demographic_no: int,
    actor: str,
    actor_id: str | None = None,
) -> None:
    normalized_actor_id = normalize_staff_actor_id(actor_id, actor)
    now = utc_now()
    pending_invites = list(
        session.scalars(
            select(PatientPortalInvite)
            .where(
                PatientPortalInvite.clinic_id == clinic_id,
                PatientPortalInvite.demographic_no == demographic_no,
                PatientPortalInvite.status == INVITE_STATUS_PENDING,
            )
            .with_for_update()
        )
    )
    for invite in pending_invites:
        invite.status = INVITE_STATUS_REVOKED
        invite.revoked_at = now
        invite.revoked_by = actor
        invite.revoked_by_id = normalized_actor_id
        invite.updated_at = now
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_INVITE_REVOKE,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_STAFF,
            actor=actor,
            actor_id=normalized_actor_id,
            clinic_id=clinic_id,
            demographic_no=demographic_no,
            invite_id=invite.id,
            reason="replaced_by_new_invite",
        )


def create_invite(
    session: Session,
    demographic_no: int,
    actor: str,
    *,
    identity_proof: IdentityProof,
    proof_secret: str,
    clinic_id: str = "default",
    actor_id: str | None = None,
) -> tuple[PatientPortalInvite, str]:
    validate_demographic_no(demographic_no)
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    normalized_actor = normalize_staff_actor(actor)
    normalized_actor_id = normalize_staff_actor_id(actor_id, normalized_actor)
    if not proof_secret or not proof_secret.strip():
        raise ValueError("proof_secret must not be blank")
    proof_salt = create_proof_salt()
    proof_hashes = build_identity_hashes(identity_proof, proof_secret, proof_salt)

    if patient_has_account(
        session,
        clinic_id=normalized_clinic_id,
        demographic_no=demographic_no,
    ):
        raise AccountAlreadyExistsError()
    revoke_pending_invites_for_patient(
        session,
        clinic_id=normalized_clinic_id,
        demographic_no=demographic_no,
        actor=normalized_actor,
        actor_id=normalized_actor_id,
    )
    if patient_has_account(
        session,
        clinic_id=normalized_clinic_id,
        demographic_no=demographic_no,
    ):
        raise AccountAlreadyExistsError()

    invite_token = create_invite_token()
    now = utc_now()
    invite = PatientPortalInvite(
        clinic_id=normalized_clinic_id,
        demographic_no=demographic_no,
        token_hash=hash_invite_token(invite_token),
        status=INVITE_STATUS_PENDING,
        created_by=normalized_actor,
        created_by_id=normalized_actor_id,
        created_at=now,
        updated_at=now,
        sent_count=1,
        last_sent_at=now,
        last_sent_by=normalized_actor,
        last_sent_by_id=normalized_actor_id,
        expires_at=now + DEFAULT_INVITE_TTL,
        proof_salt=proof_salt,
        proof_hash_version=IDENTITY_PROOF_HASH_VERSION,
        **proof_hashes,
    )
    try:
        with session.begin_nested():
            session.add(invite)
            session.flush()
    except IntegrityError as exc:
        raise PendingInviteExistsError() from exc
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_INVITE_CREATE,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor=normalized_actor,
        actor_id=normalized_actor_id,
        clinic_id=normalized_clinic_id,
        demographic_no=demographic_no,
        invite_id=invite.id,
    )
    return invite, invite_token


def get_invite(
    session: Session,
    invite_id: int,
    *,
    clinic_id: str | None = None,
    lock: bool = False,
) -> PatientPortalInvite:
    statement = select(PatientPortalInvite).where(PatientPortalInvite.id == invite_id)
    if lock:
        statement = statement.with_for_update()
    invite = session.scalar(statement)
    if invite is None or (
        clinic_id is not None and invite.clinic_id != normalize_clinic_id(clinic_id)
    ):
        raise InviteNotFoundError()
    return invite


def list_invites(
    session: Session,
    demographic_no: int | None = None,
    limit: int = DEFAULT_INVITE_LIST_LIMIT,
    offset: int = 0,
    *,
    clinic_id: str = "default",
) -> list[PatientPortalInvite]:
    validate_list_pagination(limit, offset)
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    statement = select(PatientPortalInvite).where(
        PatientPortalInvite.clinic_id == normalized_clinic_id
    )
    if demographic_no is not None:
        validate_demographic_no(demographic_no)
        statement = statement.where(PatientPortalInvite.demographic_no == demographic_no)
    statement = statement.order_by(
        desc(PatientPortalInvite.created_at),
        desc(PatientPortalInvite.id),
    )
    return list(session.scalars(statement.offset(offset).limit(limit)))


def _prepared_for_operation(
    session: Session,
    *,
    clinic_id: str,
    delivery_operation_id: str,
    lock: bool = False,
) -> PatientPortalInvite | None:
    statement = select(PatientPortalInvite).where(
        PatientPortalInvite.clinic_id == clinic_id,
        PatientPortalInvite.delivery_operation_id == delivery_operation_id,
    )
    if lock:
        statement = statement.with_for_update()
    return session.scalar(statement)


def _new_prepared_invite(
    session: Session,
    *,
    clinic_id: str,
    demographic_no: int,
    actor: str,
    actor_id: str,
    delivery_operation_id: str,
    proof_hashes: dict[str, str],
    proof_salt: str,
    encryption_secret: str,
    encryption_key_id: str,
    supersedes_invite_id: int | None,
) -> tuple[PatientPortalInvite, str]:
    invite_token = create_invite_token()
    now = utc_now()
    invite = PatientPortalInvite(
        clinic_id=clinic_id,
        demographic_no=demographic_no,
        token_hash=hash_invite_token(invite_token),
        status=INVITE_STATUS_PREPARED,
        created_by=actor,
        created_by_id=actor_id,
        created_at=now,
        updated_at=now,
        sent_count=1,
        last_sent_at=now,
        last_sent_by=actor,
        last_sent_by_id=actor_id,
        expires_at=now + DEFAULT_INVITE_TTL,
        proof_salt=proof_salt,
        proof_hash_version=IDENTITY_PROOF_HASH_VERSION,
        supersedes_invite_id=supersedes_invite_id,
        delivery_operation_id=delivery_operation_id,
        **proof_hashes,
    )
    _protect_prepared_token(
        invite,
        invite_token,
        encryption_secret=encryption_secret,
        encryption_key_id=encryption_key_id,
    )
    session.add(invite)
    session.flush()
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_STAFF_ACTION,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor=actor,
        actor_id=actor_id,
        clinic_id=clinic_id,
        demographic_no=demographic_no,
        invite_id=invite.id,
        resource_type="invite_preparation",
        reason="delivery_pending",
    )
    return invite, invite_token


def prepare_create_invite(
    session: Session,
    demographic_no: int,
    actor: str,
    *,
    delivery_operation_id: str,
    identity_proof: IdentityProof,
    proof_secret: str,
    encryption_secret: str,
    encryption_key_id: str,
    encryption_keys: Mapping[str, str],
    clinic_id: str = "default",
    actor_id: str | None = None,
) -> tuple[PatientPortalInvite, str]:
    """Prepare a first invite without making it usable or replacing another token.

    Repeating the same operation returns the same one-time token while it remains prepared. This
    lets CARLOS recover when the HTTP response is lost before its durable email transaction is
    committed.
    """
    validate_demographic_no(demographic_no)
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    normalized_actor = normalize_staff_actor(actor)
    normalized_actor_id = normalize_staff_actor_id(actor_id, normalized_actor)
    proof_salt = create_proof_salt()
    proof_hashes = build_identity_hashes(identity_proof, proof_secret, proof_salt)

    existing = _prepared_for_operation(
        session,
        clinic_id=normalized_clinic_id,
        delivery_operation_id=delivery_operation_id,
        lock=True,
    )
    if existing is not None:
        if (
            existing.status != INVITE_STATUS_PREPARED
            or existing.demographic_no != demographic_no
            or existing.created_by_id != normalized_actor_id
            or existing.supersedes_invite_id is not None
            or not _same_identity_proof(existing, identity_proof, proof_secret)
        ):
            raise InvitePreparationConflictError()
        return existing, _disclose_prepared_token(existing, encryption_keys=encryption_keys)

    if patient_has_account(session, clinic_id=normalized_clinic_id, demographic_no=demographic_no):
        raise AccountAlreadyExistsError()
    pending = session.scalar(
        select(PatientPortalInvite.id).where(
            PatientPortalInvite.clinic_id == normalized_clinic_id,
            PatientPortalInvite.demographic_no == demographic_no,
            PatientPortalInvite.status == INVITE_STATUS_PENDING,
        )
    )
    if pending is not None:
        raise PendingInviteExistsError()
    try:
        with session.begin_nested():
            return _new_prepared_invite(
                session,
                clinic_id=normalized_clinic_id,
                demographic_no=demographic_no,
                actor=normalized_actor,
                actor_id=normalized_actor_id,
                delivery_operation_id=delivery_operation_id,
                proof_hashes=proof_hashes,
                proof_salt=proof_salt,
                encryption_secret=encryption_secret,
                encryption_key_id=encryption_key_id,
                supersedes_invite_id=None,
            )
    except IntegrityError as exc:
        raise InvitePreparationConflictError() from exc


def prepare_resend_invite(
    session: Session,
    invite_id: int,
    actor: str,
    *,
    delivery_operation_id: str,
    encryption_secret: str,
    encryption_key_id: str,
    encryption_keys: Mapping[str, str],
    clinic_id: str = "default",
    actor_id: str | None = None,
) -> tuple[PatientPortalInvite, str]:
    """Prepare a replacement while leaving the currently delivered token valid."""
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    normalized_actor = normalize_staff_actor(actor)
    normalized_actor_id = normalize_staff_actor_id(actor_id, normalized_actor)
    existing = _prepared_for_operation(
        session,
        clinic_id=normalized_clinic_id,
        delivery_operation_id=delivery_operation_id,
        lock=True,
    )
    if existing is not None:
        if (
            existing.status != INVITE_STATUS_PREPARED
            or existing.created_by_id != normalized_actor_id
            or existing.supersedes_invite_id != invite_id
        ):
            raise InvitePreparationConflictError()
        return existing, _disclose_prepared_token(existing, encryption_keys=encryption_keys)

    invite = get_invite(session, invite_id, clinic_id=normalized_clinic_id, lock=True)
    if invite.status != INVITE_STATUS_PENDING:
        if invite.status == INVITE_STATUS_REVOKED:
            raise RevokedInviteError()
        if invite.status == INVITE_STATUS_ACCEPTED:
            raise AcceptedInviteError()
        raise SupersededInviteError()
    if invite.proof_salt is None:
        raise InvitePreparationConflictError()
    proof_hashes = {
        "proof_email_hash": invite.proof_email_hash,
        "proof_date_of_birth_hash": invite.proof_date_of_birth_hash,
        "proof_health_card_hash": invite.proof_health_card_hash,
    }
    if not all(proof_hashes.values()):
        raise InvitePreparationConflictError()
    try:
        with session.begin_nested():
            return _new_prepared_invite(
                session,
                clinic_id=normalized_clinic_id,
                demographic_no=invite.demographic_no,
                actor=normalized_actor,
                actor_id=normalized_actor_id,
                delivery_operation_id=delivery_operation_id,
                proof_hashes=proof_hashes,
                proof_salt=invite.proof_salt,
                encryption_secret=encryption_secret,
                encryption_key_id=encryption_key_id,
                supersedes_invite_id=invite.id,
            )
    except IntegrityError as exc:
        raise InvitePreparationConflictError() from exc


def activate_prepared_invite(
    session: Session,
    invite_id: int,
    *,
    delivery_operation_id: str,
    delivery_reference: str,
    clinic_id: str,
) -> PatientPortalInvite:
    """Atomically activate a prepared invite after CARLOS durably records its email job."""
    invite = get_invite(session, invite_id, clinic_id=clinic_id, lock=True)
    if invite.delivery_operation_id != delivery_operation_id:
        raise InvitePreparationConflictError()
    if invite.status == INVITE_STATUS_PENDING:
        if invite.delivery_reference != delivery_reference:
            raise InvitePreparationConflictError()
        return invite
    comparable_expiry = invite.expires_at
    if comparable_expiry.tzinfo is None:
        comparable_expiry = comparable_expiry.replace(tzinfo=UTC)
    if invite.status != INVITE_STATUS_PREPARED or comparable_expiry <= utc_now():
        raise InvitePreparationConflictError()

    old_invite: PatientPortalInvite | None = None
    if invite.supersedes_invite_id is not None:
        old_invite = get_invite(
            session,
            invite.supersedes_invite_id,
            clinic_id=clinic_id,
            lock=True,
        )
        if old_invite.status != INVITE_STATUS_PENDING:
            raise InvitePreparationConflictError()
    else:
        old_invite = session.scalar(
            select(PatientPortalInvite)
            .where(
                PatientPortalInvite.clinic_id == invite.clinic_id,
                PatientPortalInvite.demographic_no == invite.demographic_no,
                PatientPortalInvite.status == INVITE_STATUS_PENDING,
                PatientPortalInvite.id != invite.id,
            )
            .with_for_update()
        )
        if old_invite is not None:
            raise InvitePreparationConflictError()

    try:
        with session.begin_nested():
            now = utc_now()
            if old_invite is not None:
                old_invite.status = INVITE_STATUS_SUPERSEDED
                old_invite.updated_at = now
                session.flush()
            invite.status = INVITE_STATUS_PENDING
            invite.delivery_reference = delivery_reference
            invite.encrypted_invite_token = None
            invite.invite_token_nonce = None
            invite.invite_token_key_id = None
            invite.updated_at = now
            session.flush()
    except IntegrityError as exc:
        raise InvitePreparationConflictError() from exc
    record_audit_event(
        session,
        event_type=(
            AUDIT_EVENT_INVITE_RESEND
            if invite.supersedes_invite_id is not None
            else AUDIT_EVENT_INVITE_CREATE
        ),
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor=invite.created_by,
        actor_id=invite.created_by_id,
        clinic_id=invite.clinic_id,
        demographic_no=invite.demographic_no,
        invite_id=invite.id,
        resource_type="delivery_reference",
        resource_id=delivery_reference,
    )
    return invite


def resend_invite(
    session: Session,
    invite_id: int,
    actor: str,
    *,
    clinic_id: str | None = None,
    actor_id: str | None = None,
) -> tuple[PatientPortalInvite, str]:
    invite = get_invite(session, invite_id, clinic_id=clinic_id, lock=True)
    if invite.status == INVITE_STATUS_REVOKED:
        raise RevokedInviteError()
    if invite.status == INVITE_STATUS_ACCEPTED:
        raise AcceptedInviteError()
    if invite.status == INVITE_STATUS_SUPERSEDED:
        raise SupersededInviteError()

    normalized_actor = normalize_staff_actor(actor)
    normalized_actor_id = normalize_staff_actor_id(actor_id, normalized_actor)
    invite_token = create_invite_token()
    now = utc_now()
    invite.status = INVITE_STATUS_SUPERSEDED
    invite.updated_at = now
    session.flush()
    replacement = PatientPortalInvite(
        clinic_id=invite.clinic_id,
        demographic_no=invite.demographic_no,
        token_hash=hash_invite_token(invite_token),
        status=INVITE_STATUS_PENDING,
        created_by=normalized_actor,
        created_by_id=normalized_actor_id,
        created_at=now,
        updated_at=now,
        sent_count=1,
        last_sent_at=now,
        last_sent_by=normalized_actor,
        last_sent_by_id=normalized_actor_id,
        expires_at=now + DEFAULT_INVITE_TTL,
        proof_email_hash=invite.proof_email_hash,
        proof_date_of_birth_hash=invite.proof_date_of_birth_hash,
        proof_health_card_hash=invite.proof_health_card_hash,
        proof_salt=invite.proof_salt,
        proof_hash_version=invite.proof_hash_version,
        supersedes_invite_id=invite.id,
    )
    session.add(replacement)
    session.flush()
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_INVITE_RESEND,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor=normalized_actor,
        actor_id=normalized_actor_id,
        clinic_id=replacement.clinic_id,
        demographic_no=replacement.demographic_no,
        invite_id=replacement.id,
        resource_type="superseded_invite",
        resource_id=str(invite.id),
    )
    return replacement, invite_token


def revoke_invite(
    session: Session,
    invite_id: int,
    actor: str,
    *,
    clinic_id: str | None = None,
    actor_id: str | None = None,
) -> PatientPortalInvite:
    invite = get_invite(session, invite_id, clinic_id=clinic_id, lock=True)
    if invite.status == INVITE_STATUS_ACCEPTED:
        raise AcceptedInviteError()
    if invite.status == INVITE_STATUS_SUPERSEDED:
        raise SupersededInviteError()
    if invite.status != INVITE_STATUS_REVOKED:
        normalized_actor = normalize_staff_actor(actor)
        normalized_actor_id = normalize_staff_actor_id(actor_id, normalized_actor)
        now = utc_now()
        invite.status = INVITE_STATUS_REVOKED
        invite.revoked_at = now
        invite.revoked_by = normalized_actor
        invite.revoked_by_id = normalized_actor_id
        # A revoked preparation must not retain a recoverable one-time credential. The database
        # constraint also makes this erasure part of the state transition rather than cleanup.
        invite.encrypted_invite_token = None
        invite.invite_token_nonce = None
        invite.invite_token_key_id = None
        invite.updated_at = now
        session.flush()
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_INVITE_REVOKE,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_STAFF,
            actor=normalized_actor,
            actor_id=normalized_actor_id,
            clinic_id=invite.clinic_id,
            demographic_no=invite.demographic_no,
            invite_id=invite.id,
        )
    return invite
