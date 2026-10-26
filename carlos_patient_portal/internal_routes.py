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

import logging
from collections.abc import Awaitable, Callable, Generator
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Literal, NoReturn, Protocol, TypeVar

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Request, status
from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    model_validator,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from carlos_patient_portal.account_settings import (
    ContactReviewConflictError,
    ContactReviewNotFoundError,
    count_pending_contact_reviews,
    list_pending_contact_reviews,
    review_contact_update,
)
from carlos_patient_portal.accounts import find_account_id_for_patient
from carlos_patient_portal.audit import hash_sensitive_reference, record_audit_event
from carlos_patient_portal.auth import (
    AccountNotFoundError,
    set_patient_account_access,
    unlock_patient_account,
)
from carlos_patient_portal.booking_choices import (
    MAX_PENDING_CHOICE_LIST,
    BookingChoiceExpiredError,
    BookingChoiceNotPendingError,
    BookingChoiceResultConflictError,
    BookingChoiceWithdrawnError,
    cancel_pending_choices_for_account,
    close_lapsed_choices,
    list_pending_choices,
    record_choice_result,
)
from carlos_patient_portal.booking_offers import OfferedSlotSpec
from carlos_patient_portal.booking_prompts import (
    BookingPromptAccountUnavailableError,
    BookingPromptNotFoundError,
    BookingPromptNotice,
    BookingPromptOperationConflictError,
    booking_account_conditions,
    booking_prompt_state,
    create_booking_prompt,
    list_booking_prompts,
    withdraw_booking_prompt,
)
from carlos_patient_portal.config import Settings
from carlos_patient_portal.identity import IdentityProof, reject_hidden_characters
from carlos_patient_portal.invites import (
    AcceptedInviteError,
    AccountAlreadyExistsError,
    InviteNotFoundError,
    InvitePreparationConflictError,
    InvitePreparationInProgressError,
    InvitePreparationKeyUnavailableError,
    PendingInviteExistsError,
    RevokedInviteError,
    SupersededInviteError,
    activate_prepared_invite,
    create_invite,
    list_invites,
    prepare_create_invite,
    prepare_resend_invite,
    resend_invite,
    revoke_invite,
)
from carlos_patient_portal.job_identity import (
    JOB_ASSERTION_HEADER,
    JOB_REFUSAL_PERMISSION_NOT_HELD,
    JOB_REFUSAL_ROUTE_NOT_OPEN,
    JOB_REFUSAL_WRONG_PERMISSION,
    CarlosJobRefusal,
    JobPrincipal,
    authenticate_carlos_job,
    consume_job_assertion,
)
from carlos_patient_portal.models import (
    AUDIT_ACTOR_TYPE_STAFF,
    AUDIT_ACTOR_TYPE_SYSTEM,
    AUDIT_EVENT_INVITE_LIST,
    AUDIT_EVENT_JOB_AUTH_REFUSED,
    AUDIT_EVENT_MYCARLOS_CLINIC_KEYS_PUBLISH,
    AUDIT_EVENT_MYCARLOS_DEVICE_LIST,
    AUDIT_EVENT_MYCARLOS_DEVICE_REMOVE,
    AUDIT_EVENT_STAFF_ACTION,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_SUCCESS,
    MAX_BOOKING_LOCATION_CODE_LENGTH,
    MAX_BOOKING_PROMPT_ACTOR_LENGTH,
    MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH,
    MAX_BOOKING_SLOT_DURATION_MINUTES,
    MAX_BOOKING_SLOT_ID_LENGTH,
    MAX_DEMOGRAPHIC_NO,
    MAX_INVITE_DELIVERY_OPERATION_ID_LENGTH,
    MAX_INVITE_DELIVERY_REFERENCE_LENGTH,
    MAX_OFFERED_SLOTS,
    MIN_BOOKING_SLOT_DURATION_MINUTES,
    MYCARLOS_REMOVED_BY_STAFF,
    UNLOCK_SECRET_STATUS_PENDING,
    UNLOCK_SECRET_STATUS_REVOKED,
    PatientPortalAccount,
    PatientPortalBookingPrompt,
    PatientPortalClinicKey,
    PatientPortalInvite,
    PatientPortalMyCarlosDevice,
    PatientPortalUnlockSecret,
)
from carlos_patient_portal.mycarlos_devices import (
    MAX_PUBLISHED_CLINIC_KEYS,
    ClinicKeyPublishError,
    ClinicKeySpec,
    as_utc,
    b64url,
    devices_for_account,
    publish_clinic_keys,
    recipient_id_for_account,
    remove_device,
    strict_b64url_decode,
)
from carlos_patient_portal.runtime import MAX_DATABASE_ID
from carlos_patient_portal.schemas import InviteCreateRequest
from carlos_patient_portal.staff_identity import (
    CarlosServiceAuthenticationError,
    CarlosStaffPermissionError,
    StaffPrincipal,
    authenticate_carlos_staff,
    consume_staff_assertion,
    staff_request_hash,
)
from carlos_patient_portal.system_jobs import (
    JOB_BOOKING_SYNC,
    JOB_KEY_PUBLISH,
    JOB_ONLY_PERMISSIONS,
    PERMISSION_BOOKING_PROMPT_SYNC,
    PERMISSION_CLINIC_KEYS_PUBLISH,
    SYSTEM_JOBS,
)
from carlos_patient_portal.unlock_secrets import (
    UnlockSecretDecryptionError,
    UnlockSecretNotFoundError,
    UnlockSecretRevokedError,
    create_unlock_secret,
    get_unlock_secret_by_source_reference,
    publish_unlock_secret,
    read_unlock_secret,
    revoke_unlock_secret,
)
from carlos_patient_portal.web_support import get_request_client_reference

logger = logging.getLogger(__name__)

PERMISSION_INVITE_MANAGE = "portal.invite.manage"
PERMISSION_ACCOUNT_UNLOCK = "portal.account.unlock"
PERMISSION_ACCOUNT_MANAGE = "portal.account.manage"
PERMISSION_SECRET_MANAGE = "portal.secret.manage"
PERMISSION_CONTACT_REVIEW = "portal.contact.review"
PERMISSION_BOOKING_PROMPT_MANAGE = "portal.booking_prompt.manage"
# Read a patient's linked myCarlos devices (with the public keys CARLOS seals to) and remove one.
PERMISSION_MYCARLOS_DEVICE_MANAGE = "portal.mycarlos.device.manage"
# `PERMISSION_BOOKING_PROMPT_SYNC` (from system_jobs) belongs to the `booking-sync` job alone. It
# lists patients' pending picks and reports results; it cannot create prompts, read accounts, or
# manage invites, no other route accepts it, and a staff assertion carrying it is refused
# everywhere.
STAFF_ASSERTION_HEADER = "X-CARLOS-Staff-Assertion"
# Part of the CARLOS/Java boundary: one deliberately generic 404 shared by every account lookup so
# the contract cannot drift branch by branch.
INTERNAL_ACCOUNT_NOT_FOUND_DETAIL = "portal account not found"
UNLOCK_SECRET_NOT_FOUND_DETAIL = "unlock secret not found"
BOOKING_PROMPT_NOT_FOUND_DETAIL = "booking prompt not found"
BOOKING_PROMPT_OPERATION_CONFLICT_DETAIL = "operation id was used for a different booking prompt"
BOOKING_CHOICE_NOT_PENDING_DETAIL = "booking choice is not pending"
BOOKING_CHOICE_WITHDRAWN_DETAIL = "booking choice was withdrawn"
BOOKING_CHOICE_EXPIRED_DETAIL = "booking choice expired"
BOOKING_CHOICE_RESULT_CONFLICT_DETAIL = "booking choice already has a different result"


class InternalErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detail: str


COMMON_INTERNAL_RESPONSES = {
    status.HTTP_403_FORBIDDEN: {
        "description": "Staff permission is required.",
        "model": InternalErrorResponse,
    },
    status.HTTP_404_NOT_FOUND: {
        "description": "Resource or service endpoint was not found.",
        "model": InternalErrorResponse,
    },
}
INTERNAL_CONFLICT_RESPONSES = {
    **COMMON_INTERNAL_RESPONSES,
    status.HTTP_409_CONFLICT: {"description": "The requested state transition conflicts."},
}
INTERNAL_CREATE_INVITE_RESPONSES = {
    **INTERNAL_CONFLICT_RESPONSES,
    status.HTTP_400_BAD_REQUEST: {"description": "The demographic scope does not match."},
}
INVITE_PREPARATION_IN_PROGRESS = "another invite delivery is being prepared"
INTERNAL_PREPARE_INVITE_RESPONSES = {
    **INTERNAL_CONFLICT_RESPONSES,
    status.HTTP_503_SERVICE_UNAVAILABLE: {
        "description": "The encrypted invite preparation cannot be recovered.",
        "model": InternalErrorResponse,
    },
}
INTERNAL_PREPARE_CREATE_INVITE_RESPONSES = {
    **INTERNAL_PREPARE_INVITE_RESPONSES,
    status.HTTP_400_BAD_REQUEST: {"description": "The demographic scope does not match."},
}


class InternalRuntime(Protocol):
    settings: Settings
    session_factory: sessionmaker[Session]
    identity_proof_secret: str
    audit_hash_secret: str
    outbox_encryption_secret: str
    outbox_encryption_keys: dict[str, str] | None
    outbox_active_key_id: str
    unlock_secret_encryption_secret: str
    unlock_secret_encryption_keys: dict[str, str] | None
    unlock_secret_active_key_id: str
    operational_metrics: "InternalOperationalMetrics"


class InternalOperationalMetrics(Protocol):
    def record_failure(self, failure_type: str) -> None:
        raise NotImplementedError


# Staff-supplied text the portal stores and shows back: an account-access reason, an unlock-secret
# revocation reason, and the label and source reference a patient sees beside a stored password.
# Only CARLOS calls these routes. For three of these fields this is the only check; for the
# account-access reason, which CARLOS also checks, it is a backstop where the text is stored.
StaffText = AfterValidator(reject_hidden_characters)


class InternalUnlockSecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_reference: Annotated[str, Field(min_length=1, max_length=128), StaffText]
    label: Annotated[str | None, Field(default=None, max_length=128), StaffText]
    secret_type: str = Field(default="email", pattern="^email$")


class InternalUnlockSecretRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    reason: Annotated[str | None, Field(default=None, max_length=64), StaffText]


class InternalContactReviewDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    approve: bool
    revision: str = Field(min_length=1, max_length=64)


class InternalAccountAccessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    enabled: bool
    reason: Annotated[str, Field(default="staff_action", min_length=1, max_length=64), StaffText]


class InternalInviteResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    clinic_id: str
    demographic_no: int
    status: str
    created_by_id: str | None
    created_by: str
    issued_count: int
    last_issued_at: datetime
    last_issued_by: str
    expires_at: datetime
    accepted_account_id: int | None
    supersedes_invite_id: int | None
    delivery_operation_id: str | None = None
    delivery_reference: str | None = None


class InternalInviteTokenResponse(InternalInviteResponse):
    invite_token: str


class InternalInvitePrepareRequest(InviteCreateRequest):
    delivery_operation_id: str = Field(
        min_length=1,
        max_length=MAX_INVITE_DELIVERY_OPERATION_ID_LENGTH,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )


class InternalInviteResendPrepareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    delivery_operation_id: str = Field(
        min_length=1,
        max_length=MAX_INVITE_DELIVERY_OPERATION_ID_LENGTH,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )


class InternalInviteDeliveryCommitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    delivery_operation_id: str = Field(
        min_length=1,
        max_length=MAX_INVITE_DELIVERY_OPERATION_ID_LENGTH,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    delivery_reference: str = Field(
        min_length=1,
        max_length=MAX_INVITE_DELIVERY_REFERENCE_LENGTH,
        pattern=r"^[A-Za-z0-9._:/-]+$",
    )


class InternalAccountUnlockResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    clinic_id: str
    demographic_no: int
    locked_at: datetime | None
    force_password_reset: bool


class InternalAccountStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    clinic_id: str
    demographic_no: int
    status: str
    locked: bool
    force_password_reset: bool
    disabled_at: datetime | None
    disabled_reason: str | None


class InternalAccountAccessResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    status: str
    force_password_reset: bool


MYCARLOS_KEY_ID_PATTERN = r"^[A-Za-z0-9_-]{43}$"
# Base64url of at most 512 bytes, the stored limit for a clinic key and a replacement signature.
MAX_CLINIC_KEY_TEXT_LENGTH = 683


class InternalClinicKeyEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kid: Annotated[str, Field(pattern=MYCARLOS_KEY_ID_PATTERN)]
    spki: Annotated[str, Field(min_length=1, max_length=MAX_CLINIC_KEY_TEXT_LENGTH)]
    status: Literal["active", "revoked"]
    replaces_kid: Annotated[str | None, Field(default=None, pattern=MYCARLOS_KEY_ID_PATTERN)]
    replacement_signature: Annotated[
        str | None,
        Field(default=None, min_length=1, max_length=MAX_CLINIC_KEY_TEXT_LENGTH),
    ]


class InternalClinicKeysPublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    keys: Annotated[
        list[InternalClinicKeyEntry],
        Field(min_length=1, max_length=MAX_PUBLISHED_CLINIC_KEYS),
    ]


class InternalClinicKeyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kid: str
    status: str
    published_at: datetime
    revoked_at: datetime | None
    replaces_kid: str | None


class InternalClinicKeysPublishResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    clinic_id: str
    changed: bool
    keys: list[InternalClinicKeyResponse]


class InternalMyCarlosDeviceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_key_id: str
    device_name: str
    status: str
    x25519_public_key: str
    ed25519_public_key: str
    linked_at: datetime
    last_seen_at: datetime | None
    removed_at: datetime | None
    removed_by: str | None
    vault_head_link: str | None
    vault_head_link_at: datetime | None


class InternalMyCarlosDevicesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipient_id: str | None
    devices: list[InternalMyCarlosDeviceResponse]


class InternalUnlockSecretCreateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    created: bool
    secret: str
    source_reference: str | None
    status: str


class InternalUnlockSecretStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    status: str


class InternalContactReviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    clinic_id: str
    demographic_no: int
    email_before: str
    email_after: str
    phone_number_before: str | None
    phone_number_after: str | None
    requested_at: datetime
    revision: str


class InternalContactReviewListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[InternalContactReviewResponse]
    limit: int
    offset: int
    total: int
    next_offset: int | None


class InternalContactReviewDecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    status: str
    decision: str | None


BookingPromptState = Literal[
    "sent", "read", "choice_pending", "booked", "declined_all", "withdrawn", "expired"
]


def parse_iso_datetime_text(value: object) -> datetime:
    """Accept only ISO 8601 text with an explicit UTC offset.

    Pydantic alone would also take a number, or a numeric string, as a Unix timestamp; an offered
    appointment time must say which offset it was written in.
    """
    if not isinstance(value, str):
        raise ValueError("must be an ISO 8601 date and time with a UTC offset")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("must be an ISO 8601 date and time with a UTC offset") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("must include a UTC offset")
    return parsed


IsoDateTimeWithOffset = Annotated[AwareDatetime, BeforeValidator(parse_iso_datetime_text)]


class InternalOfferedSlot(BaseModel):
    """One time CARLOS offers the patient. Only what the patient must see; no free text.

    `slot_id` is CARLOS's own identifier, returned when the patient picks this time and never
    interpreted by the portal. `starts_at` must carry an explicit UTC offset.
    """

    model_config = ConfigDict(extra="forbid")

    slot_id: str = Field(
        min_length=1,
        max_length=MAX_BOOKING_SLOT_ID_LENGTH,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    starts_at: IsoDateTimeWithOffset
    duration_minutes: int = Field(
        strict=True,
        ge=MIN_BOOKING_SLOT_DURATION_MINUTES,
        le=MAX_BOOKING_SLOT_DURATION_MINUTES,
    )
    visit_mode: Literal["in_person", "phone", "video"]
    # One of the codes in PATIENT_PORTAL_BOOKING_LOCATIONS; the patient sees its label.
    location_code: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_BOOKING_LOCATION_CODE_LENGTH,
        pattern=r"^[a-z0-9_-]+$",
    )

    def to_spec(self) -> OfferedSlotSpec:
        return OfferedSlotSpec(
            slot_id=self.slot_id,
            starts_at=self.starts_at,
            duration_minutes=self.duration_minutes,
            visit_mode=self.visit_mode,
            location_code=self.location_code,
        )


def offered_slot_specs(slots: list[InternalOfferedSlot] | None) -> tuple[OfferedSlotSpec, ...]:
    return tuple(slot.to_spec() for slot in slots or ())


class InternalBookingPromptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    operation_id: str = Field(
        min_length=1,
        max_length=MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    urgency: Literal["routine", "soon", "as_soon_as_possible"]
    appointment_type: Literal["follow_up", "annual_exam", "lab_review"]
    # The provider the patient is told suggested it, for example "Dr. Singh". Checked like a staff
    # actor name; it is the only variable text in a prompt.
    suggested_by: str | None = Field(default=None, max_length=MAX_BOOKING_PROMPT_ACTOR_LENGTH)
    # Times the patient can pick from (carlos-portal#11). Omitted or empty, the prompt tells the
    # patient to contact the clinic, as before.
    offered_slots: list[InternalOfferedSlot] | None = Field(
        default=None,
        max_length=MAX_OFFERED_SLOTS,
    )


class InternalBookingEligibilityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    clinic_id: str
    demographic_no: int
    eligible: bool


class InternalBookingPromptResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    demographic_no: int
    urgency: str
    appointment_type: str
    suggested_by: str | None
    state: BookingPromptState
    created_by: str
    created_at: datetime
    expires_at: datetime
    notified_at: datetime | None
    read_at: datetime | None
    withdrawn_at: datetime | None
    withdrawn_by: str | None


class InternalBookingPromptCreateResponse(InternalBookingPromptResponse):
    created: bool


class InternalBookingChoiceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_id: int
    choice_id: int
    demographic_no: int
    slot_id: str
    chosen_at: datetime


class InternalBookingChoiceListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[InternalBookingChoiceResponse]
    has_more: bool


class InternalBookingChoiceResultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    choice_id: int = Field(strict=True, gt=0, le=MAX_DATABASE_ID)
    result: Literal["booked", "slot_unavailable"]
    # Replacement times, only with slot_unavailable; added after the times still on offer.
    offered_slots: list[InternalOfferedSlot] | None = Field(
        default=None,
        max_length=MAX_OFFERED_SLOTS,
    )

    @model_validator(mode="after")
    def replacements_only_when_unavailable(self) -> "InternalBookingChoiceResultRequest":
        if self.result == "booked" and self.offered_slots:
            raise ValueError("offered_slots are accepted only with slot_unavailable")
        return self


class InternalBookingChoiceResultResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_id: int
    choice_id: int
    result: Literal["booked", "slot_unavailable"]
    state: BookingPromptState
    # False when this result was already recorded: nothing changed and no notice was queued.
    recorded: bool
    offered_slot_count: int


def booking_prompt_payload(prompt: PatientPortalBookingPrompt) -> dict[str, object]:
    return {
        "id": prompt.id,
        "demographic_no": prompt.demographic_no,
        "urgency": prompt.urgency,
        "appointment_type": prompt.appointment_type,
        "suggested_by": prompt.suggested_by,
        "state": booking_prompt_state(prompt),
        "created_by": prompt.created_by,
        "created_at": prompt.created_at,
        "expires_at": prompt.expires_at,
        "notified_at": prompt.notified_at,
        "read_at": prompt.read_at,
        "withdrawn_at": prompt.withdrawn_at,
        "withdrawn_by": prompt.withdrawn_by,
    }


def require_permission(principal: StaffPrincipal, permission: str) -> None:
    try:
        principal.require(permission)
    except CarlosStaffPermissionError as exc:
        # Sonar cannot associate dependency-level errors with every route's OpenAPI responses.
        raise HTTPException(status_code=403, detail="permission denied") from exc  # NOSONAR
    # A job's own permission never rides on a person's login: a staff assertion carrying one is
    # refused on every route, whatever else it holds. Jobs sign their own calls (job_identity.py).
    if principal.permissions & JOB_ONLY_PERMISSIONS:
        raise HTTPException(status_code=403, detail="permission denied")  # NOSONAR


@dataclass(frozen=True)
class InternalCallerPolicy:
    """Who a route takes: staff holding `permission`, or the one job `job` claiming it."""

    caller: Literal["staff", "job"]
    permission: str
    job: str | None = None


# Set on every route's authorization dependency, so a test can list each route's callers and a
# new route without a decision fails the build.
CALLER_POLICY_ATTRIBUTE = "carlos_caller_policy"
DependencyT = TypeVar("DependencyT", bound=Callable[..., object])


def tag_caller_policy(dependency: DependencyT, policy: InternalCallerPolicy) -> DependencyT:
    setattr(dependency, CALLER_POLICY_ATTRIBUTE, policy)
    return dependency


def internal_route_template(request: Request) -> str:
    """The matched route's template, such as `/internal/carlos/invites/{invite_id}/revoke`.

    Audit rows name the template, never the raw path or query, which carry values the caller chose.
    """
    template = getattr(request.scope.get("route"), "path", None)
    if isinstance(template, str) and template.startswith("/internal/carlos/"):
        return template
    return "/internal/carlos/"


@dataclass(frozen=True)
class RecordedJobRefusal:
    """A refused job call, left on request.state for the failure middleware to record."""

    code: str
    key_owner: str
    key_id: str
    assertion_id: str | None
    route_template: str


def raise_job_refusal(request: Request, refusal: CarlosJobRefusal) -> NoReturn:
    request.state.carlos_job_refusal = RecordedJobRefusal(
        code=refusal.code,
        key_owner=refusal.key_owner,
        key_id=refusal.key_id,
        assertion_id=refusal.assertion_id,
        route_template=internal_route_template(request),
    )
    if refusal.status_code == status.HTTP_403_FORBIDDEN:
        raise HTTPException(status_code=403, detail="permission denied") from refusal  # NOSONAR
    # The same 404 as an unauthenticated call, so a job cannot tell a closed route from no route.
    raise HTTPException(status_code=404, detail="not found") from refusal  # NOSONAR


def require_pending_for_disclosure(unlock_secret: PatientPortalUnlockSecret) -> None:
    """Confine idempotent re-disclosure to the create-then-publish window.

    CARLOS creates a passphrase, sends the correspondence, then publishes; a retry inside that
    window legitimately reads back the record it just created, which is why `read_unlock_secret`
    is called with `allow_pending=True`. Nothing previously tied disclosure to that window, so
    re-POSTing the same `source_reference` a year later returned the live passphrase of an
    already-published record over the internal API.

    Publication is the boundary: once the patient can see the passphrase, a repeat create is no
    longer a retry, and answering it with the plaintext would make the internal token a standing
    read capability over every passphrase ever issued. 409 makes that case visible to CARLOS
    instead of silently re-disclosing.
    """
    if unlock_secret.status != UNLOCK_SECRET_STATUS_PENDING:
        raise HTTPException(
            status_code=409,
            detail="source reference was already published",
        ) from None


def invite_payload(
    invite: PatientPortalInvite,
    *,
    invite_token: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": invite.id,
        "clinic_id": invite.clinic_id,
        "demographic_no": invite.demographic_no,
        "status": invite.status,
        "created_by_id": invite.created_by_id,
        "created_by": invite.created_by,
        "issued_count": invite.sent_count,
        "last_issued_at": invite.last_sent_at,
        "last_issued_by": invite.last_sent_by,
        "expires_at": invite.expires_at,
        "accepted_account_id": invite.accepted_account_id,
        "supersedes_invite_id": invite.supersedes_invite_id,
        "delivery_operation_id": invite.delivery_operation_id,
        "delivery_reference": invite.delivery_reference,
    }
    if invite_token is not None:
        payload["invite_token"] = invite_token
    return payload


@dataclass(frozen=True)
class InternalRouteDependencies:
    """Shared FastAPI dependencies for the CARLOS-facing routes.

    Passed to the per-domain registrars below so each declares only the routes it owns. Holding
    these as fields rather than closing over them keeps a registrar's requirements visible in
    its signature, and stops one domain reaching for another's state.
    """

    staff_principal_requiring: Callable[[str], Callable[..., StaffPrincipal]]
    job_principal_requiring: Callable[[str, str], Callable[..., JobPrincipal]]
    session_dependency: object
    disclose_unlock_secret: Callable[[Session, PatientPortalUnlockSecret, StaffPrincipal], str]


@dataclass(frozen=True)
class InternalFailureRecord:
    """Who a failed internal request's audit row names, and why it failed."""

    event_type: str
    actor_type: str
    actor: str
    reason: str
    actor_id: str | None = None
    clinic_id: str | None = None
    resource_id: str | None = None
    assertion_key_id: str | None = None
    assertion_id: str | None = None


FAILED_INTERNAL_ACTION_REASONS = {
    403: "authorization_failed",
    404: "not_found",
    409: "conflict",
    422: "validation_failed",
    429: "throttled",
}


def describe_failed_internal_action(
    state: object,
    status_code: int,
    *,
    clinic_id: str,
) -> InternalFailureRecord:
    """Attribute one failed request from what its authentication left on request.state.

    A job call that verified and was refused gets its own `job.auth_refused` row, in place of the
    generic one, naming the job whose key signed it and the route template. A verified job that
    later fails (a conflict, a validation error) is named as the system actor it is. Anything that
    did not authenticate stays the unattributed `authentication_failed` row, one per request.
    """
    refusal: RecordedJobRefusal | None = getattr(state, "carlos_job_refusal", None)
    if refusal is not None:
        job = SYSTEM_JOBS[refusal.key_owner]
        return InternalFailureRecord(
            event_type=AUDIT_EVENT_JOB_AUTH_REFUSED,
            actor_type=AUDIT_ACTOR_TYPE_SYSTEM,
            actor=job.display_name,
            actor_id=job.actor_id,
            clinic_id=clinic_id,
            resource_id=refusal.route_template,
            reason=refusal.code,
            assertion_key_id=refusal.key_id,
            assertion_id=refusal.assertion_id,
        )
    reason = FAILED_INTERNAL_ACTION_REASONS.get(status_code, "internal_failure")
    job_principal: JobPrincipal | None = getattr(state, "carlos_job_principal", None)
    if job_principal is not None:
        return InternalFailureRecord(
            event_type=AUDIT_EVENT_STAFF_ACTION,
            actor_type=AUDIT_ACTOR_TYPE_SYSTEM,
            actor=job_principal.display_name,
            actor_id=job_principal.actor_id,
            clinic_id=job_principal.clinic_id,
            reason=reason,
            assertion_key_id=job_principal.key_id,
            assertion_id=job_principal.assertion_id,
        )
    principal: StaffPrincipal | None = getattr(state, "carlos_staff_principal", None)
    if principal is not None:
        return InternalFailureRecord(
            event_type=AUDIT_EVENT_STAFF_ACTION,
            actor_type=AUDIT_ACTOR_TYPE_STAFF,
            actor=principal.display_name,
            actor_id=principal.provider_id,
            clinic_id=principal.clinic_id,
            reason=reason,
        )
    return InternalFailureRecord(
        event_type=AUDIT_EVENT_STAFF_ACTION,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor="carlos-service",
        reason="authentication_failed",
    )


def register_internal_failure_audit(app: FastAPI, runtime: InternalRuntime) -> None:
    """Record every failed /internal/carlos/** request as an audit event."""

    def record_failed_internal_action(request: Request, status_code: int) -> None:
        # Authentication consumes a request-bound nonce. Re-verifying here would either consume it
        # twice or require a replay bypass in the audit path, so the dependency records only a
        # successfully authenticated principal (or a verified job's refusal) on request.state.
        # Authentication failures remain deliberately unattributed.
        failure = describe_failed_internal_action(
            request.state,
            status_code,
            clinic_id=runtime.settings.clinic_id,
        )
        reason = failure.reason
        try:
            with runtime.session_factory() as audit_session:
                with audit_session.begin():
                    record_audit_event(
                        audit_session,
                        event_type=failure.event_type,
                        outcome=AUDIT_OUTCOME_FAILURE,
                        actor_type=failure.actor_type,
                        actor=failure.actor,
                        actor_id=failure.actor_id,
                        clinic_id=failure.clinic_id,
                        resource_type="internal_api",
                        resource_id=failure.resource_id,
                        reason=reason,
                        assertion_key_id=failure.assertion_key_id,
                        assertion_id=failure.assertion_id,
                        # Without this every unauthenticated failure row is identical
                        # ("carlos-service" / "authentication_failed"), so a flood cannot be told
                        # apart from a single misconfigured caller. Patient-facing failure paths
                        # already record the hashed client reference; this one did not.
                        client_reference_hash=hash_sensitive_reference(
                            runtime.audit_hash_secret,
                            "portal_client",
                            get_request_client_reference(request, runtime.settings),
                        ),
                    )
        except SQLAlchemyError as exc:
            runtime.operational_metrics.record_failure("internal_audit")
            # This middleware is the only record of failed staff actions; if it cannot write, the
            # security log stops while the API keeps serving, so it must be loud in the logs.
            logger.error(  # NOSONAR - traceback details can contain patient/database values
                "Internal staff-action audit write failed: %s reason=%s status=%s",
                type(exc).__name__,
                reason,
                status_code,
            )

    @app.middleware("http")
    async def audit_failed_internal_action(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        try:
            response = await call_next(request)
        except Exception:
            if request.url.path.startswith("/internal/carlos/"):
                await run_in_threadpool(record_failed_internal_action, request, 500)
            raise
        if request.url.path.startswith("/internal/carlos/") and response.status_code >= 400:
            await run_in_threadpool(
                record_failed_internal_action,
                request,
                response.status_code,
            )
        return response


def build_internal_dependencies(runtime: InternalRuntime) -> InternalRouteDependencies:
    """Construct the authentication, transaction, and disclosure dependencies once."""

    def get_database_session() -> Generator[Session, None, None]:
        with runtime.session_factory() as session:
            with session.begin():
                yield session

    async def authenticate_job_request(
        request: Request,
        *,
        authorization: str | None,
        job_assertion: str,
        staff_assertion_present: bool,
        expected_request_hash: str,
    ) -> JobPrincipal:
        try:
            principal = authenticate_carlos_job(
                runtime.settings,
                authorization=authorization,
                job_assertion=job_assertion,
                expected_request_hash=expected_request_hash,
                staff_assertion_present=staff_assertion_present,
            )
            await run_in_threadpool(
                consume_job_assertion,
                runtime.session_factory,
                principal,
            )
        except CarlosJobRefusal as refusal:
            raise_job_refusal(request, refusal)
        except CarlosServiceAuthenticationError as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        request.state.carlos_job_principal = principal
        return principal

    async def get_internal_principal(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        staff_assertion: Annotated[str | None, Header(alias=STAFF_ASSERTION_HEADER)] = None,
        job_assertion: Annotated[str | None, Header(alias=JOB_ASSERTION_HEADER)] = None,
    ) -> StaffPrincipal | JobPrincipal:
        """Authenticate the caller as staff or as a job, from whichever assertion it sent.

        A job header always takes the job path, even beside a staff header, so a request carrying
        both is refused and, when the job's signature verifies, recorded as `both_headers`.
        """
        try:
            body = await request.body()
            expected_request_hash = staff_request_hash(
                request.method,
                request.scope.get("raw_path", request.url.path.encode("utf-8")),
                request.scope.get("query_string", b""),
                body,
            )
            if job_assertion is not None:
                return await authenticate_job_request(
                    request,
                    authorization=authorization,
                    job_assertion=job_assertion,
                    staff_assertion_present=staff_assertion is not None,
                    expected_request_hash=expected_request_hash,
                )
            principal = authenticate_carlos_staff(
                runtime.settings,
                authorization=authorization,
                staff_assertion=staff_assertion,
                expected_request_hash=expected_request_hash,
            )
            await run_in_threadpool(
                consume_staff_assertion,
                runtime.session_factory,
                principal,
            )
            request.state.carlos_staff_principal = principal
            return principal
        except CarlosServiceAuthenticationError as exc:
            raise HTTPException(status_code=404, detail="not found") from exc

    def staff_principal_requiring(permission: str) -> Callable[..., StaffPrincipal]:
        """Authorize in the dependency phase, not in the handler body.

        FastAPI resolves dependencies before it validates the request model, so checking the
        permission here makes 403 precede 422 — matching CARLOS's auth-first rule, where
        `hasPrivilege` is the first statement in every 2Action, and keeping a caller who lacks
        permission from learning the endpoint's schema through validation errors.

        This is the default for every internal route: staff only. A job is refused here with the
        generic 404 (`route_not_open`), whatever permission it claims.
        """

        def dependency(
            request: Request,
            principal: Annotated[StaffPrincipal | JobPrincipal, Depends(get_internal_principal)],
        ) -> StaffPrincipal:
            if isinstance(principal, JobPrincipal):
                raise_job_refusal(
                    request,
                    CarlosJobRefusal.for_principal(JOB_REFUSAL_ROUTE_NOT_OPEN, principal),
                )
            require_permission(principal, permission)
            return principal

        return tag_caller_policy(
            dependency,
            InternalCallerPolicy(caller="staff", permission=permission),
        )

    def job_principal_requiring(job: str, permission: str) -> Callable[..., JobPrincipal]:
        """Open a route to one registered job claiming one of its permissions, and to nobody else.

        Raises at registration when the job is not registered or does not hold the permission, so
        a route can never be opened to a right the allowlist in system_jobs.py does not grant.
        """
        registered = SYSTEM_JOBS.get(job)
        if registered is None:
            raise ValueError(f"{job} is not a registered CARLOS job")
        if permission not in registered.permissions:
            raise ValueError(f"the {job} job does not hold {permission}")

        def dependency(
            request: Request,
            principal: Annotated[StaffPrincipal | JobPrincipal, Depends(get_internal_principal)],
        ) -> JobPrincipal:
            if isinstance(principal, StaffPrincipal):
                # A person's login never reaches a job's route, whatever it holds.
                raise HTTPException(status_code=403, detail="permission denied")  # NOSONAR
            if principal.job != job:
                code = JOB_REFUSAL_ROUTE_NOT_OPEN
            elif principal.permission not in registered.permissions:
                code = JOB_REFUSAL_PERMISSION_NOT_HELD
            elif principal.permission != permission:
                code = JOB_REFUSAL_WRONG_PERMISSION
            else:
                return principal
            raise_job_refusal(request, CarlosJobRefusal.for_principal(code, principal))

        return tag_caller_policy(
            dependency,
            InternalCallerPolicy(caller="job", permission=permission, job=job),
        )

    # FastAPI supports function-scoped teardown; Sonar's FastAPI stub does not.
    session_dependency = Depends(get_database_session, scope="function")  # NOSONAR

    def disclose_unlock_secret(
        session: Session,
        unlock_secret: PatientPortalUnlockSecret,
        principal: StaffPrincipal,
    ) -> str:
        try:
            return read_unlock_secret(
                session,
                unlock_secret.id,
                clinic_id=principal.clinic_id,
                encryption_keys=(
                    runtime.unlock_secret_encryption_keys
                    or {"primary": runtime.unlock_secret_encryption_secret}
                ),
                actor_type="staff",
                actor=principal.display_name,
                actor_id=principal.provider_id,
                demographic_no=unlock_secret.demographic_no,
                # CARLOS retries read back the record it just created, before publishing it.
                # `require_pending_for_disclosure` is what confines this to that window: every
                # caller of this helper has already rejected a non-pending record.
                allow_pending=True,
            )
        except UnlockSecretDecryptionError as exc:
            # read_unlock_secret already wrote the `decryption_failed` audit row into this
            # request's transaction, and the 503 raised below would otherwise unwind and discard
            # it — losing the only durable record that a stored secret is unreadable, which is the
            # exact condition the runbook pages on. Committing here ends the transaction opened by
            # `get_database_session`; unwinding through that already-committed context manager is
            # expected and is covered by test_internal_api.py's retry-decryption-failure test.
            session.commit()
            runtime.operational_metrics.record_failure("unlock_secret_decryption")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="unlock secret is temporarily unavailable",
            ) from exc

    return InternalRouteDependencies(
        staff_principal_requiring=staff_principal_requiring,
        job_principal_requiring=job_principal_requiring,
        session_dependency=session_dependency,
        disclose_unlock_secret=disclose_unlock_secret,
    )


def register_internal_invite_routes(
    app: FastAPI,
    runtime: InternalRuntime,
    deps: InternalRouteDependencies,
) -> None:
    """Invite lifecycle: create, list, resend, and revoke."""

    @app.post(
        "/internal/carlos/patients/{demographic_no}/invites/prepare",
        status_code=201,
        response_model=InternalInviteTokenResponse,
        responses=INTERNAL_PREPARE_CREATE_INVITE_RESPONSES,
    )
    def internal_prepare_invite(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        payload: InternalInvitePrepareRequest,
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_INVITE_MANAGE))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        if payload.demographic_no != demographic_no:
            raise HTTPException(status_code=400, detail="demographic scope mismatch")
        try:
            invite, invite_token = prepare_create_invite(
                session,
                demographic_no,
                principal.display_name,
                actor_id=principal.provider_id,
                delivery_operation_id=payload.delivery_operation_id,
                identity_proof=IdentityProof(
                    email=payload.email,
                    date_of_birth=payload.date_of_birth,
                    health_card_number=payload.health_card_number,
                ),
                proof_secret=runtime.identity_proof_secret,
                encryption_secret=runtime.outbox_encryption_secret,
                encryption_key_id=runtime.outbox_active_key_id,
                encryption_keys=runtime.outbox_encryption_keys
                or {runtime.outbox_active_key_id: runtime.outbox_encryption_secret},
                clinic_id=principal.clinic_id,
            )
        except AccountAlreadyExistsError as exc:
            raise HTTPException(status_code=409, detail="portal account already exists") from exc
        except PendingInviteExistsError as exc:
            raise HTTPException(status_code=409, detail="pending invite already exists") from exc
        except InvitePreparationKeyUnavailableError as exc:
            raise HTTPException(status_code=503, detail="invite preparation unavailable") from exc
        except InvitePreparationInProgressError as exc:
            raise HTTPException(status_code=409, detail=INVITE_PREPARATION_IN_PROGRESS) from exc
        except InvitePreparationConflictError as exc:
            raise HTTPException(status_code=409, detail="invite preparation conflicts") from exc
        return invite_payload(invite, invite_token=invite_token)

    @app.post(
        "/internal/carlos/invites/{invite_id}/resend/prepare",
        status_code=201,
        response_model=InternalInviteTokenResponse,
        responses=INTERNAL_PREPARE_INVITE_RESPONSES,
    )
    def internal_prepare_invite_resend(
        invite_id: Annotated[int, Path(gt=0, le=MAX_DATABASE_ID)],
        payload: InternalInviteResendPrepareRequest,
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_INVITE_MANAGE))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        try:
            invite, invite_token = prepare_resend_invite(
                session,
                invite_id,
                principal.display_name,
                actor_id=principal.provider_id,
                delivery_operation_id=payload.delivery_operation_id,
                encryption_secret=runtime.outbox_encryption_secret,
                encryption_key_id=runtime.outbox_active_key_id,
                encryption_keys=runtime.outbox_encryption_keys
                or {runtime.outbox_active_key_id: runtime.outbox_encryption_secret},
                clinic_id=principal.clinic_id,
            )
        except InviteNotFoundError as exc:
            raise HTTPException(status_code=404, detail="invite not found") from exc
        except (RevokedInviteError, AcceptedInviteError, SupersededInviteError) as exc:
            raise HTTPException(status_code=409, detail="invite cannot be resent") from exc
        except InvitePreparationKeyUnavailableError as exc:
            raise HTTPException(status_code=503, detail="invite preparation unavailable") from exc
        except InvitePreparationInProgressError as exc:
            raise HTTPException(status_code=409, detail=INVITE_PREPARATION_IN_PROGRESS) from exc
        except InvitePreparationConflictError as exc:
            raise HTTPException(status_code=409, detail="invite preparation conflicts") from exc
        return invite_payload(invite, invite_token=invite_token)

    @app.post(
        "/internal/carlos/invites/{invite_id}/commit-delivery",
        response_model=InternalInviteResponse,
        responses=INTERNAL_CONFLICT_RESPONSES,
    )
    def internal_commit_invite_delivery(
        invite_id: Annotated[int, Path(gt=0, le=MAX_DATABASE_ID)],
        payload: InternalInviteDeliveryCommitRequest,
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_INVITE_MANAGE))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        try:
            invite = activate_prepared_invite(
                session,
                invite_id,
                delivery_operation_id=payload.delivery_operation_id,
                delivery_reference=payload.delivery_reference,
                clinic_id=principal.clinic_id,
                actor=principal.display_name,
                actor_id=principal.provider_id,
            )
        except InviteNotFoundError as exc:
            raise HTTPException(status_code=404, detail="invite not found") from exc
        except InvitePreparationConflictError as exc:
            raise HTTPException(status_code=409, detail="invite delivery conflicts") from exc
        return invite_payload(invite)

    @app.post(
        "/internal/carlos/patients/{demographic_no}/invites",
        status_code=201,
        response_model=InternalInviteTokenResponse,
        responses=INTERNAL_CREATE_INVITE_RESPONSES,
    )
    def internal_create_invite(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        payload: InviteCreateRequest,
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_INVITE_MANAGE))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        if payload.demographic_no != demographic_no:
            raise HTTPException(status_code=400, detail="demographic scope mismatch")
        try:
            invite, invite_token = create_invite(
                session,
                demographic_no,
                principal.display_name,
                actor_id=principal.provider_id,
                identity_proof=IdentityProof(
                    email=payload.email,
                    date_of_birth=payload.date_of_birth,
                    health_card_number=payload.health_card_number,
                ),
                proof_secret=runtime.identity_proof_secret,
                clinic_id=principal.clinic_id,
            )
        except AccountAlreadyExistsError as exc:
            raise HTTPException(status_code=409, detail="portal account already exists") from exc
        except PendingInviteExistsError as exc:
            raise HTTPException(status_code=409, detail="pending invite already exists") from exc
        except InvitePreparationInProgressError as exc:
            raise HTTPException(status_code=409, detail=INVITE_PREPARATION_IN_PROGRESS) from exc
        return invite_payload(invite, invite_token=invite_token)

    @app.get(
        "/internal/carlos/patients/{demographic_no}/invites",
        response_model=list[InternalInviteResponse],
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_list_invites(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_INVITE_MANAGE))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> list[dict[str, object]]:
        invites = list_invites(
            session,
            demographic_no=demographic_no,
            clinic_id=principal.clinic_id,
            limit=100,
        )
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_INVITE_LIST,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_STAFF,
            actor=principal.display_name,
            actor_id=principal.provider_id,
            clinic_id=principal.clinic_id,
            demographic_no=demographic_no,
        )
        return [invite_payload(invite) for invite in invites]

    @app.post(
        "/internal/carlos/invites/{invite_id}/resend",
        response_model=InternalInviteTokenResponse,
        responses=INTERNAL_CONFLICT_RESPONSES,
    )
    def internal_resend_invite(
        invite_id: Annotated[int, Path(gt=0, le=MAX_DATABASE_ID)],
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_INVITE_MANAGE))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        try:
            invite, invite_token = resend_invite(
                session,
                invite_id,
                principal.display_name,
                actor_id=principal.provider_id,
                clinic_id=principal.clinic_id,
            )
        except InviteNotFoundError as exc:
            raise HTTPException(status_code=404, detail="invite not found") from exc
        except InvitePreparationConflictError as exc:
            raise HTTPException(status_code=409, detail="invite delivery is not committed") from exc
        except (RevokedInviteError, AcceptedInviteError, SupersededInviteError) as exc:
            raise HTTPException(status_code=409, detail="invite cannot be resent") from exc
        return invite_payload(invite, invite_token=invite_token)

    @app.post(
        "/internal/carlos/invites/{invite_id}/revoke",
        response_model=InternalInviteResponse,
        responses=INTERNAL_CONFLICT_RESPONSES,
    )
    def internal_revoke_invite(
        invite_id: Annotated[int, Path(gt=0, le=MAX_DATABASE_ID)],
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_INVITE_MANAGE))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        try:
            invite = revoke_invite(
                session,
                invite_id,
                principal.display_name,
                actor_id=principal.provider_id,
                clinic_id=principal.clinic_id,
            )
        except InviteNotFoundError as exc:
            raise HTTPException(status_code=404, detail="invite not found") from exc
        except AcceptedInviteError as exc:
            raise HTTPException(
                status_code=409,
                detail="accepted invite cannot be revoked",
            ) from exc
        except SupersededInviteError as exc:
            raise HTTPException(
                status_code=409,
                detail="superseded invite cannot be revoked",
            ) from exc
        return invite_payload(invite)


def register_internal_account_routes(
    app: FastAPI,
    deps: InternalRouteDependencies,
) -> None:
    """Portal account state: unlock, status, and access."""

    @app.post(
        "/internal/carlos/patients/{demographic_no}/unlock",
        response_model=InternalAccountUnlockResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_unlock_account(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_ACCOUNT_UNLOCK))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        account_id = find_account_id_for_patient(
            session,
            clinic_id=principal.clinic_id,
            demographic_no=demographic_no,
        )
        if account_id is None:
            raise HTTPException(status_code=404, detail=INTERNAL_ACCOUNT_NOT_FOUND_DETAIL)
        try:
            account = unlock_patient_account(
                session,
                account_id,
                principal.display_name,
                actor_id=principal.provider_id,
                clinic_id=principal.clinic_id,
            )
        except AccountNotFoundError as exc:
            raise HTTPException(status_code=404, detail=INTERNAL_ACCOUNT_NOT_FOUND_DETAIL) from exc
        return {
            "id": account.id,
            "clinic_id": account.clinic_id,
            "demographic_no": account.demographic_no,
            "locked_at": account.locked_at,
            "force_password_reset": account.force_password_reset,
        }

    @app.get(
        "/internal/carlos/patients/{demographic_no}/portal-account",
        response_model=InternalAccountStatusResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_get_account_status(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_ACCOUNT_MANAGE))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        account = session.scalar(
            select(PatientPortalAccount).where(
                PatientPortalAccount.clinic_id == principal.clinic_id,
                PatientPortalAccount.demographic_no == demographic_no,
            )
        )
        if account is None:
            raise HTTPException(status_code=404, detail=INTERNAL_ACCOUNT_NOT_FOUND_DETAIL)
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_STAFF_ACTION,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_STAFF,
            actor=principal.display_name,
            actor_id=principal.provider_id,
            clinic_id=principal.clinic_id,
            demographic_no=demographic_no,
            account_id=account.id,
            resource_type="portal_account",
            resource_id=str(account.id),
            reason="status_viewed",
        )
        return {
            "id": account.id,
            "clinic_id": account.clinic_id,
            "demographic_no": account.demographic_no,
            "status": account.status,
            "locked": account.locked_at is not None,
            "force_password_reset": account.force_password_reset,
            "disabled_at": account.disabled_at,
            "disabled_reason": account.disabled_reason,
        }

    @app.post(
        "/internal/carlos/patients/{demographic_no}/portal-account/access",
        response_model=InternalAccountAccessResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_set_account_access(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        payload: InternalAccountAccessRequest,
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_ACCOUNT_MANAGE))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        account_id = find_account_id_for_patient(
            session,
            clinic_id=principal.clinic_id,
            demographic_no=demographic_no,
        )
        if account_id is None:
            raise HTTPException(status_code=404, detail=INTERNAL_ACCOUNT_NOT_FOUND_DETAIL)
        try:
            account = set_patient_account_access(
                session,
                account_id,
                principal.display_name,
                enabled=payload.enabled,
                clinic_id=principal.clinic_id,
                actor_id=principal.provider_id,
                reason=payload.reason,
            )
        except AccountNotFoundError as exc:
            raise HTTPException(status_code=404, detail=INTERNAL_ACCOUNT_NOT_FOUND_DETAIL) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid account access request") from exc
        if not payload.enabled:
            # Turning an account off cancels the times it was waiting on; turning it back on does
            # not revive them. The account row is already locked, before its prompts.
            cancel_pending_choices_for_account(
                session,
                account.id,
                actor=principal.display_name,
                actor_id=principal.provider_id,
            )
        return {
            "id": account.id,
            "status": account.status,
            "force_password_reset": account.force_password_reset,
        }


def register_internal_unlock_secret_routes(
    app: FastAPI,
    runtime: InternalRuntime,
    deps: InternalRouteDependencies,
) -> None:
    """Unlock secrets: create, publish, and revoke."""

    @app.post(
        "/internal/carlos/patients/{demographic_no}/unlock-secrets",
        status_code=status.HTTP_201_CREATED,
        response_model=InternalUnlockSecretCreateResponse,
        responses=INTERNAL_CONFLICT_RESPONSES,
    )
    def internal_create_unlock_secret(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        payload: InternalUnlockSecretRequest,
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_SECRET_MANAGE))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        existing_secret = get_unlock_secret_by_source_reference(
            session,
            clinic_id=principal.clinic_id,
            demographic_no=demographic_no,
            secret_type=payload.secret_type,
            source_reference=payload.source_reference,
            for_update=True,
        )
        if existing_secret is not None:
            if existing_secret.status == UNLOCK_SECRET_STATUS_REVOKED:
                raise HTTPException(status_code=409, detail="source reference was revoked")
            require_pending_for_disclosure(existing_secret)
            plaintext = deps.disclose_unlock_secret(session, existing_secret, principal)
            return {
                "id": existing_secret.id,
                "created": False,
                "secret": plaintext,
                "source_reference": existing_secret.source_reference,
                "status": existing_secret.status,
            }
        try:
            with session.begin_nested():
                created = create_unlock_secret(
                    session,
                    clinic_id=principal.clinic_id,
                    demographic_no=demographic_no,
                    created_by=principal.display_name,
                    created_by_id=principal.provider_id,
                    encryption_secret=runtime.unlock_secret_encryption_secret,
                    encryption_key_id=runtime.unlock_secret_active_key_id,
                    secret_type=payload.secret_type,
                    label=payload.label,
                    source_reference=payload.source_reference,
                    initial_status=UNLOCK_SECRET_STATUS_PENDING,
                )
        except IntegrityError:
            existing_secret = session.scalar(
                select(PatientPortalUnlockSecret)
                .where(
                    PatientPortalUnlockSecret.clinic_id == principal.clinic_id,
                    PatientPortalUnlockSecret.secret_type == payload.secret_type,
                    PatientPortalUnlockSecret.source_reference == payload.source_reference,
                )
                .with_for_update()
            )
            if existing_secret is None:
                raise
            if existing_secret.demographic_no != demographic_no:
                raise HTTPException(
                    status_code=409,
                    detail="source reference belongs to another patient",
                ) from None
            if existing_secret.status == UNLOCK_SECRET_STATUS_REVOKED:
                raise HTTPException(
                    status_code=409,
                    detail="source reference was revoked",
                ) from None
            require_pending_for_disclosure(existing_secret)
            plaintext = deps.disclose_unlock_secret(session, existing_secret, principal)
            return {
                "id": existing_secret.id,
                "created": False,
                "secret": plaintext,
                "source_reference": existing_secret.source_reference,
                "status": existing_secret.status,
            }
        return {
            "id": created.unlock_secret.id,
            "created": True,
            "secret": created.secret,
            "source_reference": created.unlock_secret.source_reference,
            "status": created.unlock_secret.status,
        }

    @app.post(
        "/internal/carlos/unlock-secrets/{unlock_secret_id}/publish",
        response_model=InternalUnlockSecretStatusResponse,
        responses=INTERNAL_CONFLICT_RESPONSES,
    )
    def internal_publish_unlock_secret(
        unlock_secret_id: Annotated[int, Path(gt=0, le=MAX_DATABASE_ID)],
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_SECRET_MANAGE))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        demographic_no = session.scalar(
            select(PatientPortalUnlockSecret.demographic_no).where(
                PatientPortalUnlockSecret.id == unlock_secret_id,
                PatientPortalUnlockSecret.clinic_id == principal.clinic_id,
            )
        )
        if demographic_no is None:
            raise HTTPException(status_code=404, detail=UNLOCK_SECRET_NOT_FOUND_DETAIL)
        try:
            unlock_secret = publish_unlock_secret(
                session,
                unlock_secret_id,
                clinic_id=principal.clinic_id,
                demographic_no=demographic_no,
                published_by=principal.display_name,
                published_by_id=principal.provider_id,
            )
        except (UnlockSecretNotFoundError, UnlockSecretRevokedError) as exc:
            raise HTTPException(
                status_code=409,
                detail="unlock secret cannot be published",
            ) from exc
        return {"id": unlock_secret.id, "status": unlock_secret.status}

    @app.post(
        "/internal/carlos/unlock-secrets/{unlock_secret_id}/revoke",
        response_model=InternalUnlockSecretStatusResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_revoke_unlock_secret(
        unlock_secret_id: Annotated[int, Path(gt=0, le=MAX_DATABASE_ID)],
        payload: InternalUnlockSecretRevokeRequest,
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_SECRET_MANAGE))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        # Resolved and checked here, matching the publish handler above. Passing a None
        # demographic through to revoke_unlock_secret would still produce a 404, but only via a
        # scope-validation ValueError raised three frames down — an implementation detail, not a
        # decision this route made.
        demographic_no = session.scalar(
            select(PatientPortalUnlockSecret.demographic_no).where(
                PatientPortalUnlockSecret.id == unlock_secret_id,
                PatientPortalUnlockSecret.clinic_id == principal.clinic_id,
            )
        )
        if demographic_no is None:
            raise HTTPException(status_code=404, detail=UNLOCK_SECRET_NOT_FOUND_DETAIL)
        try:
            unlock_secret = revoke_unlock_secret(
                session,
                unlock_secret_id,
                clinic_id=principal.clinic_id,
                revoked_by=principal.display_name,
                revoked_by_id=principal.provider_id,
                demographic_no=demographic_no,
                reason=payload.reason,
            )
        except (UnlockSecretNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=404, detail=UNLOCK_SECRET_NOT_FOUND_DETAIL) from exc
        return {"id": unlock_secret.id, "status": unlock_secret.status}


def register_internal_contact_review_routes(
    app: FastAPI,
    deps: InternalRouteDependencies,
) -> None:
    """CARLOS-chart contact reviews: list and decide."""

    @app.get(
        "/internal/carlos/contact-reviews",
        response_model=InternalContactReviewListResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_list_contact_reviews(
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_CONTACT_REVIEW))
        ],
        session: Annotated[Session, deps.session_dependency],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> dict[str, object]:
        reviews = list_pending_contact_reviews(
            session,
            clinic_id=principal.clinic_id,
            limit=limit,
            offset=offset,
        )
        total = count_pending_contact_reviews(session, clinic_id=principal.clinic_id)
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_STAFF_ACTION,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_STAFF,
            actor=principal.display_name,
            actor_id=principal.provider_id,
            clinic_id=principal.clinic_id,
            resource_type="contact_review",
            resource_id=f"offset:{offset}:limit:{limit}",
            reason="pending_list_viewed",
        )
        return {
            "items": [
                {
                    "id": review.id,
                    "clinic_id": review.clinic_id,
                    "demographic_no": review.demographic_no,
                    "email_before": review.email_before,
                    "email_after": review.email_after,
                    "phone_number_before": review.phone_number_before,
                    "phone_number_after": review.phone_number_after,
                    "requested_at": review.requested_at,
                    "revision": review.revision,
                }
                for review in reviews
            ],
            "limit": limit,
            "offset": offset,
            "total": total,
            "next_offset": offset + limit if offset + len(reviews) < total else None,
        }

    @app.post(
        "/internal/carlos/contact-reviews/{review_request_id}/decision",
        response_model=InternalContactReviewDecisionResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_review_contact_update(
        review_request_id: Annotated[int, Path(gt=0, le=MAX_DATABASE_ID)],
        payload: InternalContactReviewDecision,
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_CONTACT_REVIEW))
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        try:
            review = review_contact_update(
                session,
                review_request_id,
                clinic_id=principal.clinic_id,
                reviewer=principal.display_name,
                reviewer_id=principal.provider_id,
                approve=payload.approve,
                expected_revision=payload.revision,
            )
        except ContactReviewNotFoundError as exc:
            raise HTTPException(status_code=404, detail="contact review not found") from exc
        except ContactReviewConflictError as exc:
            raise HTTPException(status_code=409, detail="contact review revision conflict") from exc
        return {
            "id": review.id,
            "status": review.status,
            "decision": review.review_decision,
        }


def _booking_prompt_sign_in_url(request: Request, settings: Settings) -> str:
    """Where the notice sends the patient: the portal's sign-in page, never an internal origin."""
    if settings.public_base_url is not None:
        return settings.public_base_url.rstrip("/") + "/"
    if settings.is_development:
        return str(request.base_url).rstrip("/") + "/"
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="booking prompts are not configured",
    )


def register_internal_booking_prompt_routes(
    app: FastAPI,
    runtime: InternalRuntime,
    deps: InternalRouteDependencies,
) -> None:
    """Booking prompts: eligibility, create, list, and withdraw (carlos-portal#8)."""

    @app.get(
        "/internal/carlos/patients/{demographic_no}/booking-eligibility",
        response_model=InternalBookingEligibilityResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_get_booking_eligibility(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        principal: Annotated[
            StaffPrincipal,
            Depends(deps.staff_principal_requiring(PERMISSION_BOOKING_PROMPT_MANAGE)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        # Create's own rule, reading only the account id (no details or free text).
        account_id = session.scalar(
            select(PatientPortalAccount.id).where(
                *booking_account_conditions(principal.clinic_id, demographic_no)
            )
        )
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_STAFF_ACTION,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_STAFF,
            actor=principal.display_name,
            actor_id=principal.provider_id,
            clinic_id=principal.clinic_id,
            demographic_no=demographic_no,
            account_id=account_id,
            resource_type="portal_account",
            resource_id=None if account_id is None else str(account_id),
            reason="booking_eligibility_viewed",
        )
        return {
            "clinic_id": principal.clinic_id,
            "demographic_no": demographic_no,
            "eligible": account_id is not None,
        }

    @app.post(
        "/internal/carlos/patients/{demographic_no}/booking-prompts",
        status_code=status.HTTP_201_CREATED,
        response_model=InternalBookingPromptCreateResponse,
        responses=INTERNAL_CONFLICT_RESPONSES,
    )
    def internal_create_booking_prompt(
        request: Request,
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        payload: InternalBookingPromptRequest,
        principal: Annotated[
            StaffPrincipal,
            Depends(deps.staff_principal_requiring(PERMISSION_BOOKING_PROMPT_MANAGE)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        notice = BookingPromptNotice(
            sign_in_url=_booking_prompt_sign_in_url(request, runtime.settings),
            encryption_secret=runtime.outbox_encryption_secret,
            encryption_key_id=runtime.outbox_active_key_id,
        )
        try:
            result = create_booking_prompt(
                session,
                clinic_id=principal.clinic_id,
                demographic_no=demographic_no,
                operation_id=payload.operation_id,
                urgency=payload.urgency,
                appointment_type=payload.appointment_type,
                suggested_by=payload.suggested_by,
                created_by=principal.display_name,
                created_by_id=principal.provider_id,
                ttl=timedelta(days=runtime.settings.booking_prompt_ttl_days),
                notice=notice,
                offered_slots=offered_slot_specs(payload.offered_slots),
                booking_location_codes=runtime.settings.resolved_booking_locations.keys(),
                offer_digest_secret=runtime.audit_hash_secret,
            )
        except BookingPromptAccountUnavailableError as exc:
            # CARLOS falls back to a phone call; nothing was stored.
            raise HTTPException(status_code=404, detail=INTERNAL_ACCOUNT_NOT_FOUND_DETAIL) from exc
        except BookingPromptOperationConflictError as exc:
            raise HTTPException(
                status_code=409,
                detail=BOOKING_PROMPT_OPERATION_CONFLICT_DETAIL,
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="booking prompt is invalid",
            ) from exc
        return {**booking_prompt_payload(result.prompt), "created": result.created}

    @app.get(
        "/internal/carlos/patients/{demographic_no}/booking-prompts",
        response_model=list[InternalBookingPromptResponse],
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_list_booking_prompts(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        principal: Annotated[
            StaffPrincipal,
            Depends(deps.staff_principal_requiring(PERMISSION_BOOKING_PROMPT_MANAGE)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> list[dict[str, object]]:
        prompts = list_booking_prompts(
            session,
            clinic_id=principal.clinic_id,
            demographic_no=demographic_no,
            actor=principal.display_name,
            actor_id=principal.provider_id,
        )
        return [booking_prompt_payload(prompt) for prompt in prompts]

    @app.post(
        "/internal/carlos/booking-prompts/{prompt_id}/withdraw",
        response_model=InternalBookingPromptResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_withdraw_booking_prompt(
        prompt_id: Annotated[int, Path(gt=0, le=MAX_DATABASE_ID)],
        principal: Annotated[
            StaffPrincipal,
            Depends(deps.staff_principal_requiring(PERMISSION_BOOKING_PROMPT_MANAGE)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        try:
            prompt = withdraw_booking_prompt(
                session,
                prompt_id,
                clinic_id=principal.clinic_id,
                withdrawn_by=principal.display_name,
                withdrawn_by_id=principal.provider_id,
            )
        except BookingPromptNotFoundError as exc:
            raise HTTPException(status_code=404, detail=BOOKING_PROMPT_NOT_FOUND_DETAIL) from exc
        return booking_prompt_payload(prompt)


def register_internal_booking_sync_routes(
    app: FastAPI,
    runtime: InternalRuntime,
    deps: InternalRouteDependencies,
) -> None:
    """Offered-time sync for the CARLOS polling job (carlos-portal#11).

    Both routes take the `booking-sync` job claiming `portal.booking_prompt.sync`, and nobody else:
    staff are refused, whatever they hold. The job is audited as the system actor it is, with the
    key id and nonce of the call.
    """

    @app.get(
        "/internal/carlos/booking-prompts/choices",
        response_model=InternalBookingChoiceListResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_list_booking_choices(
        request: Request,
        principal: Annotated[
            JobPrincipal,
            Depends(deps.job_principal_requiring(JOB_BOOKING_SYNC, PERMISSION_BOOKING_PROMPT_SYNC)),
        ],
        session: Annotated[Session, deps.session_dependency],
        state: Annotated[Literal["pending"], Query()],
        limit: Annotated[int, Query(ge=1, le=MAX_PENDING_CHOICE_LIST)] = MAX_PENDING_CHOICE_LIST,
    ) -> dict[str, object]:
        def lapse_notice() -> BookingPromptNotice | None:
            # Built only once something has lapsed. Without a public sign-in address the pick is
            # still closed and the portal message is the notice; the poll itself never fails on it.
            try:
                sign_in_url = _booking_prompt_sign_in_url(request, runtime.settings)
            except HTTPException:
                logger.warning(
                    "Booking picks lapsed without an update email: no public sign-in address"
                )
                return None
            return BookingPromptNotice(
                sign_in_url=sign_in_url,
                encryption_secret=runtime.outbox_encryption_secret,
                encryption_key_id=runtime.outbox_active_key_id,
            )

        # Picks whose time has started are closed first: CARLOS must not book them, and the patient
        # is told the time did not go through.
        close_lapsed_choices(session, clinic_id=principal.clinic_id, notice=lapse_notice)
        page = list_pending_choices(
            session,
            clinic_id=principal.clinic_id,
            actor=principal.display_name,
            actor_id=principal.actor_id,
            limit=limit,
            assertion_key_id=principal.key_id,
            assertion_id=principal.assertion_id,
        )
        return {
            "items": [
                {
                    "prompt_id": pending.choice.prompt_id,
                    "choice_id": pending.choice.id,
                    "demographic_no": pending.demographic_no,
                    "slot_id": pending.choice.slot_id,
                    "chosen_at": pending.choice.chosen_at,
                }
                for pending in page.choices
            ],
            "has_more": page.has_more,
        }

    @app.post(
        "/internal/carlos/booking-prompts/{prompt_id}/choice-result",
        response_model=InternalBookingChoiceResultResponse,
        responses=INTERNAL_CONFLICT_RESPONSES,
    )
    def internal_record_booking_choice_result(
        request: Request,
        prompt_id: Annotated[int, Path(gt=0, le=MAX_DATABASE_ID)],
        payload: InternalBookingChoiceResultRequest,
        principal: Annotated[
            JobPrincipal,
            Depends(deps.job_principal_requiring(JOB_BOOKING_SYNC, PERMISSION_BOOKING_PROMPT_SYNC)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        notice = BookingPromptNotice(
            sign_in_url=_booking_prompt_sign_in_url(request, runtime.settings),
            encryption_secret=runtime.outbox_encryption_secret,
            encryption_key_id=runtime.outbox_active_key_id,
        )
        try:
            outcome = record_choice_result(
                session,
                prompt_id,
                clinic_id=principal.clinic_id,
                choice_id=payload.choice_id,
                result=payload.result,
                replacement_slots=offered_slot_specs(payload.offered_slots),
                booking_location_codes=runtime.settings.resolved_booking_locations.keys(),
                actor=principal.display_name,
                actor_id=principal.actor_id,
                notice=notice,
                assertion_key_id=principal.key_id,
                assertion_id=principal.assertion_id,
            )
        except BookingPromptNotFoundError as exc:
            raise HTTPException(status_code=404, detail=BOOKING_PROMPT_NOT_FOUND_DETAIL) from exc
        except BookingChoiceWithdrawnError as exc:
            raise HTTPException(
                status_code=409,
                detail=BOOKING_CHOICE_WITHDRAWN_DETAIL,
            ) from exc
        except BookingChoiceExpiredError as exc:
            raise HTTPException(
                status_code=409,
                detail=BOOKING_CHOICE_EXPIRED_DETAIL,
            ) from exc
        except BookingChoiceNotPendingError as exc:
            raise HTTPException(
                status_code=409,
                detail=BOOKING_CHOICE_NOT_PENDING_DETAIL,
            ) from exc
        except BookingChoiceResultConflictError as exc:
            raise HTTPException(
                status_code=409,
                detail=BOOKING_CHOICE_RESULT_CONFLICT_DETAIL,
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="booking choice result is invalid",
            ) from exc
        return {
            "prompt_id": outcome.prompt.id,
            "choice_id": outcome.choice.id,
            "result": outcome.choice.state,
            "state": booking_prompt_state(outcome.prompt),
            "recorded": outcome.recorded,
            "offered_slot_count": outcome.offered_slot_count,
        }


def clinic_key_payload(key: PatientPortalClinicKey) -> dict[str, object]:
    return {
        "kid": key.kid,
        "status": key.status,
        "published_at": as_utc(key.published_at),
        "revoked_at": as_utc(key.revoked_at),
        "replaces_kid": key.replaces_kid,
    }


def mycarlos_device_payload(device: PatientPortalMyCarlosDevice) -> dict[str, object]:
    return {
        "device_key_id": device.device_key_id,
        "device_name": device.device_name,
        "status": device.status,
        "x25519_public_key": b64url(device.x25519_public_key),
        "ed25519_public_key": b64url(device.ed25519_public_key),
        "linked_at": as_utc(device.linked_at),
        "last_seen_at": as_utc(device.last_seen_at),
        "removed_at": as_utc(device.removed_at),
        "removed_by": device.removed_by,
        "vault_head_link": device.vault_head_link,
        "vault_head_link_at": as_utc(device.vault_head_link_at),
    }


def decode_clinic_key_entry(entry: InternalClinicKeyEntry) -> ClinicKeySpec:
    try:
        spki = strict_b64url_decode(entry.spki)
        signature = (
            None
            if entry.replacement_signature is None
            else strict_b64url_decode(entry.replacement_signature)
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid_key") from exc
    return ClinicKeySpec(
        kid=entry.kid,
        spki=spki,
        status=entry.status,
        replaces_kid=entry.replaces_kid,
        replacement_signature=signature,
    )


# A refused key list: malformed is 422; a list that would undo what is published is 409.
CLINIC_KEY_CONFLICTS = frozenset({"key_missing", "key_revoked", "key_changed"})


def register_internal_mycarlos_routes(
    app: FastAPI,
    deps: InternalRouteDependencies,
    *,
    mailbox_enabled: bool = False,
) -> None:
    """Send to myCarlos (carlos-portal#41): clinic keys from CARLOS, and a patient's devices.

    Registered only while PATIENT_PORTAL_MYCARLOS_DELIVERY_ENABLED is on; otherwise every path
    here is a plain 404.
    """

    @app.put(
        "/internal/carlos/mycarlos/clinic-keys",
        response_model=InternalClinicKeysPublishResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_publish_clinic_keys(
        payload: InternalClinicKeysPublishRequest,
        principal: Annotated[
            JobPrincipal,
            Depends(deps.job_principal_requiring(JOB_KEY_PUBLISH, PERMISSION_CLINIC_KEYS_PUBLISH)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        """Replace the clinic's published key list. Only CARLOS's key-publish job may call it."""
        specs = [decode_clinic_key_entry(entry) for entry in payload.keys]
        try:
            result = publish_clinic_keys(session, clinic_id=principal.clinic_id, specs=specs)
        except ClinicKeyPublishError as exc:
            status_code = 409 if exc.code in CLINIC_KEY_CONFLICTS else 422
            raise HTTPException(status_code=status_code, detail=exc.code) from exc
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_MYCARLOS_CLINIC_KEYS_PUBLISH,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_SYSTEM,
            actor=principal.display_name,
            actor_id=principal.actor_id,
            clinic_id=principal.clinic_id,
            resource_type="clinic_keys",
            reason="changed" if result.changed else "unchanged",
            assertion_key_id=principal.key_id,
            assertion_id=principal.assertion_id,
        )
        return {
            "clinic_id": principal.clinic_id,
            "changed": result.changed,
            "keys": [clinic_key_payload(key) for key in result.keys],
        }

    @app.get(
        "/internal/carlos/patients/{demographic_no}/mycarlos/devices",
        response_model=InternalMyCarlosDevicesResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_list_mycarlos_devices(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        principal: Annotated[
            StaffPrincipal,
            Depends(deps.staff_principal_requiring(PERMISSION_MYCARLOS_DEVICE_MANAGE)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        """The patient's recipient ID (None before a first link) and every device, removed too."""
        account_id = find_account_id_for_patient(
            session,
            clinic_id=principal.clinic_id,
            demographic_no=demographic_no,
        )
        if account_id is None:
            raise HTTPException(status_code=404, detail=INTERNAL_ACCOUNT_NOT_FOUND_DETAIL)
        devices = devices_for_account(session, account_id)
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_MYCARLOS_DEVICE_LIST,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_STAFF,
            actor=principal.display_name,
            actor_id=principal.provider_id,
            clinic_id=principal.clinic_id,
            demographic_no=demographic_no,
            account_id=account_id,
            resource_type="mycarlos_devices",
            resource_id=str(account_id),
        )
        return {
            "recipient_id": recipient_id_for_account(session, account_id),
            "devices": [mycarlos_device_payload(device) for device in devices],
        }

    @app.post(
        "/internal/carlos/patients/{demographic_no}/mycarlos/devices/{device_key_id}/remove",
        response_model=InternalMyCarlosDeviceResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_remove_mycarlos_device(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        device_key_id: Annotated[str, Path(pattern=MYCARLOS_KEY_ID_PATTERN)],
        principal: Annotated[
            StaffPrincipal,
            Depends(deps.staff_principal_requiring(PERMISSION_MYCARLOS_DEVICE_MANAGE)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        """Remove one of the patient's devices. Removing a removed device changes nothing."""
        account_id = find_account_id_for_patient(
            session,
            clinic_id=principal.clinic_id,
            demographic_no=demographic_no,
        )
        if account_id is None:
            raise HTTPException(status_code=404, detail=INTERNAL_ACCOUNT_NOT_FOUND_DETAIL)
        removal = remove_device(
            session,
            account_id=account_id,
            device_key_id=device_key_id,
            removed_by=MYCARLOS_REMOVED_BY_STAFF,
            mailbox_enabled=mailbox_enabled,
        )
        if removal is None:
            raise HTTPException(status_code=404, detail="device not found")
        device, removed_now = removal
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_MYCARLOS_DEVICE_REMOVE,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_STAFF,
            actor=principal.display_name,
            actor_id=principal.provider_id,
            clinic_id=principal.clinic_id,
            demographic_no=demographic_no,
            account_id=account_id,
            resource_type="mycarlos_device",
            resource_id=str(device.id),
            reason="removed" if removed_now else "already_removed",
        )
        return mycarlos_device_payload(device)


def register_carlos_internal_routes(app: FastAPI, runtime: InternalRuntime) -> None:
    """Register the CARLOS-facing internal API, one registrar per permission domain."""
    if not runtime.settings.is_internal_api_enabled:
        return
    register_internal_failure_audit(app, runtime)
    deps = build_internal_dependencies(runtime)
    register_internal_invite_routes(app, runtime, deps)
    register_internal_account_routes(app, deps)
    register_internal_unlock_secret_routes(app, runtime, deps)
    register_internal_contact_review_routes(app, deps)
    register_internal_booking_prompt_routes(app, runtime, deps)
    register_internal_booking_sync_routes(app, runtime, deps)
    if runtime.settings.mycarlos_delivery_enabled:
        register_internal_mycarlos_routes(
            app, deps, mailbox_enabled=runtime.settings.mycarlos_mailbox_enabled
        )
        if runtime.settings.mycarlos_mailbox_enabled:
            from carlos_patient_portal.routes.mycarlos_mailbox import (
                register_internal_mailbox_routes,
            )

            # The independently configured internal service is origin-root in the
            # current CARLOS adapter. Its actual raw target never borrows the public
            # patient-page prefix; reuse the existing internal authentication policy.
            register_internal_mailbox_routes(app, runtime, deps)
            if runtime.settings.mycarlos_approval_enabled:
                from carlos_patient_portal.routes.mycarlos_approval import register_internal_approval_routes

                register_internal_approval_routes(app, runtime, deps)
