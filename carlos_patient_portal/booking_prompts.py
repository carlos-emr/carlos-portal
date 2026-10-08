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

"""Booking prompts: a clinic asks a patient to book an appointment.

CARLOS creates a prompt through the internal API; the patient reads it after signing in and is
emailed only that a message is waiting. The portal books nothing itself. A prompt is built from
fixed vocabularies, never from staff text, so it carries no clinical detail. It may carry times
CARLOS offers for the patient to pick from; `booking_choices` handles the pick and CARLOS's answer.
"""

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from carlos_patient_portal.audit import record_audit_event
from carlos_patient_portal.booking_offers import (
    BOOKED_TIME_RETENTION_AFTER_START,
    OfferedSlotSpec,
    add_offered_slots,
    as_utc,
    closed_after_expiry_notice,
    delete_offered_slots,
    normalize_offered_slots,
    offer_digest,
    require_future_slots,
)
from carlos_patient_portal.delivery_outbox import enqueue_booking_prompt_delivery
from carlos_patient_portal.invites import (
    normalize_clinic_id,
    normalize_staff_actor,
    normalize_staff_actor_id,
    validate_demographic_no,
)
from carlos_patient_portal.models import (
    ACCOUNT_STATUS_ACTIVE,
    AUDIT_ACTOR_TYPE_PATIENT,
    AUDIT_ACTOR_TYPE_STAFF,
    AUDIT_EVENT_BOOKING_PROMPT_CREATE,
    AUDIT_EVENT_BOOKING_PROMPT_LIST,
    AUDIT_EVENT_BOOKING_PROMPT_OFFER,
    AUDIT_EVENT_BOOKING_PROMPT_READ,
    AUDIT_EVENT_BOOKING_PROMPT_WITHDRAW,
    AUDIT_OUTCOME_SUCCESS,
    BOOKING_CHOICE_STATE_BOOKED,
    BOOKING_CHOICE_STATE_PENDING,
    BOOKING_CHOICE_STATE_WITHDRAWN,
    BOOKING_PROMPT_APPOINTMENT_TYPES,
    BOOKING_PROMPT_STATE_EXPIRED,
    BOOKING_PROMPT_STATUS_BOOKED,
    BOOKING_PROMPT_STATUS_CHOICE_PENDING,
    BOOKING_PROMPT_STATUS_DECLINED_ALL,
    BOOKING_PROMPT_STATUS_READ,
    BOOKING_PROMPT_STATUS_SENT,
    BOOKING_PROMPT_STATUS_WITHDRAWN,
    BOOKING_PROMPT_URGENCIES,
    MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH,
    PatientPortalAccount,
    PatientPortalBookingChoice,
    PatientPortalBookingPrompt,
    utc_now,
)

# The staff list and the patient's messages are capped rather than paginated: a patient with more
# than this many live prompts is a misuse CARLOS should stop, not a page to scroll.
MAX_STAFF_PROMPT_LIST = 100
MAX_PATIENT_PROMPT_LIST = 50


class BookingPromptNotFoundError(Exception):
    """Raised when a prompt does not exist in the caller's scope."""


class BookingPromptAccountUnavailableError(Exception):
    """Raised when the patient has no active portal account to receive a prompt."""


class BookingPromptOperationConflictError(Exception):
    """Raised when an operation id is reused for a different prompt."""


@dataclass(frozen=True, slots=True)
class BookingPromptNotice:
    """What the "message waiting" email needs, supplied by the caller that has the settings."""

    sign_in_url: str
    encryption_secret: str
    encryption_key_id: str


@dataclass(frozen=True, slots=True)
class CreatedBookingPrompt:
    prompt: PatientPortalBookingPrompt
    created: bool


# Statuses that expiry does not override: a booked prompt stays booked, and a patient waiting on
# CARLOS keeps waiting until CARLOS answers, however long the prompt was meant to last.
_STATUSES_THAT_DO_NOT_EXPIRE = frozenset(
    {
        BOOKING_PROMPT_STATUS_WITHDRAWN,
        BOOKING_PROMPT_STATUS_BOOKED,
        BOOKING_PROMPT_STATUS_CHOICE_PENDING,
    }
)


def booking_prompt_state(prompt: PatientPortalBookingPrompt, *, now: datetime | None = None) -> str:
    """The state CARLOS and the patient see.

    One of sent, read, choice_pending, booked, declined_all, withdrawn, or expired. Expired is not
    stored: it is a sent, read, or declined prompt past its expiry.
    """
    if prompt.status in _STATUSES_THAT_DO_NOT_EXPIRE:
        return prompt.status
    if as_utc(prompt.expires_at) <= (now or utc_now()):
        return BOOKING_PROMPT_STATE_EXPIRED
    return prompt.status


def _normalize_operation_id(operation_id: str) -> str:
    normalized = operation_id.strip()
    if not normalized or len(normalized) > MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH:
        raise ValueError(
            f"operation_id must be 1 to {MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH} characters"
        )
    return normalized


@dataclass(frozen=True, slots=True)
class _PromptRequest:
    demographic_no: int
    urgency: str
    appointment_type: str
    suggested_by: str | None
    offer_digest: str | None

    def matches(self, prompt: PatientPortalBookingPrompt) -> bool:
        # The offer is compared by its digest, not against the stored times, which change once
        # the patient picks one and are deleted when the prompt closes.
        return (
            prompt.demographic_no == self.demographic_no
            and prompt.urgency == self.urgency
            and prompt.appointment_type == self.appointment_type
            and prompt.suggested_by == self.suggested_by
            and prompt.offer_digest == self.offer_digest
        )


def _prompt_for_operation(
    session: Session,
    *,
    clinic_id: str,
    operation_id: str,
) -> PatientPortalBookingPrompt | None:
    return session.scalar(
        select(PatientPortalBookingPrompt)
        .where(
            PatientPortalBookingPrompt.clinic_id == clinic_id,
            PatientPortalBookingPrompt.operation_id == operation_id,
        )
        .with_for_update()
    )


def _retry_result(
    prompt: PatientPortalBookingPrompt,
    request: _PromptRequest,
) -> CreatedBookingPrompt:
    """A repeated operation returns its prompt; the same id for a different prompt is refused."""
    if not request.matches(prompt):
        raise BookingPromptOperationConflictError()
    return CreatedBookingPrompt(prompt=prompt, created=False)


def booking_account_conditions(
    clinic_id: str,
    demographic_no: int,
) -> tuple[ColumnElement[bool], ...]:
    """Which account can receive a booking prompt: the patient's active account in this clinic.

    The one rule for both creating a prompt and the eligibility check CARLOS makes before offering
    to send one, so the two cannot drift apart. A locked account is still active and counts.
    `clinic_id` must already be normalized (`normalize_clinic_id`).
    """
    return (
        PatientPortalAccount.clinic_id == clinic_id,
        PatientPortalAccount.demographic_no == demographic_no,
        PatientPortalAccount.status == ACCOUNT_STATUS_ACTIVE,
    )


def create_booking_prompt(
    session: Session,
    *,
    clinic_id: str,
    demographic_no: int,
    operation_id: str,
    urgency: str,
    appointment_type: str,
    suggested_by: str | None,
    created_by: str,
    created_by_id: str | None,
    ttl: timedelta,
    notice: BookingPromptNotice,
    offered_slots: Sequence[OfferedSlotSpec] = (),
    booking_location_codes: Collection[str] = (),
    offer_digest_secret: str | None = None,
) -> CreatedBookingPrompt:
    """Create a prompt, with any offered times, and queue its notice in one transaction.

    Retrying the same operation returns the same prompt and queues nothing, so a CARLOS retry
    after a lost response sends the patient one email. The same operation with different values,
    including different offered times, is refused. A patient without an active account gets
    nothing stored, so CARLOS can tell staff to phone instead.
    """
    validate_demographic_no(demographic_no)
    if urgency not in BOOKING_PROMPT_URGENCIES:
        raise ValueError("urgency is not supported")
    if appointment_type not in BOOKING_PROMPT_APPOINTMENT_TYPES:
        raise ValueError("appointment_type is not supported")
    if ttl <= timedelta(0):
        raise ValueError("ttl must be positive")
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    normalized_operation_id = _normalize_operation_id(operation_id)
    normalized_suggested_by = (
        None if suggested_by is None or not suggested_by.strip()
        else normalize_staff_actor(suggested_by)
    )
    normalized_created_by = normalize_staff_actor(created_by)
    normalized_created_by_id = normalize_staff_actor_id(created_by_id, normalized_created_by)
    normalized_slots = normalize_offered_slots(
        offered_slots,
        location_codes=booking_location_codes,
    )
    if normalized_slots and not offer_digest_secret:
        raise ValueError("offer_digest_secret is required to offer times")
    request = _PromptRequest(
        demographic_no=demographic_no,
        urgency=urgency,
        appointment_type=appointment_type,
        suggested_by=normalized_suggested_by,
        offer_digest=(
            offer_digest(normalized_slots, secret=offer_digest_secret)
            if normalized_slots and offer_digest_secret
            else None
        ),
    )

    existing = _prompt_for_operation(
        session,
        clinic_id=normalized_clinic_id,
        operation_id=normalized_operation_id,
    )
    if existing is not None:
        return _retry_result(existing, request)

    # FOR SHARE: staff turning the account off lock it before cancelling its prompts' picks, so a
    # prompt is either created first (and its picks cancelled there) or waits and finds it off.
    # The prompt's own foreign key takes only KEY SHARE, which would not wait.
    account = session.scalar(
        select(PatientPortalAccount)
        .where(*booking_account_conditions(normalized_clinic_id, demographic_no))
        .with_for_update(read=True)
    )
    if account is None:
        raise BookingPromptAccountUnavailableError()

    now = utc_now()
    require_future_slots(normalized_slots, now=now)
    prompt = PatientPortalBookingPrompt(
        clinic_id=normalized_clinic_id,
        demographic_no=demographic_no,
        account_id=account.id,
        operation_id=normalized_operation_id,
        urgency=urgency,
        appointment_type=appointment_type,
        suggested_by=normalized_suggested_by,
        status=BOOKING_PROMPT_STATUS_SENT,
        created_by=normalized_created_by,
        created_by_id=normalized_created_by_id,
        created_at=now,
        expires_at=now + ttl,
        offer_digest=request.offer_digest,
    )
    try:
        with session.begin_nested():
            session.add(prompt)
            session.flush()
    except IntegrityError:
        # A retry sent while the first request was still in flight loses the insert; it is
        # still a retry, so it returns the prompt the first request created.
        raced = _prompt_for_operation(
            session,
            clinic_id=normalized_clinic_id,
            operation_id=normalized_operation_id,
        )
        if raced is None:
            raise
        return _retry_result(raced, request)

    add_offered_slots(session, prompt.id, normalized_slots)
    enqueue_booking_prompt_delivery(
        session,
        account_id=account.id,
        booking_prompt_id=prompt.id,
        sign_in_url=notice.sign_in_url,
        encryption_secret=notice.encryption_secret,
        encryption_key_id=notice.encryption_key_id,
    )
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_BOOKING_PROMPT_CREATE,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor=normalized_created_by,
        actor_id=normalized_created_by_id,
        clinic_id=normalized_clinic_id,
        demographic_no=demographic_no,
        account_id=account.id,
        resource_type="booking_prompt",
        resource_id=str(prompt.id),
    )
    if normalized_slots:
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_BOOKING_PROMPT_OFFER,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_STAFF,
            actor=normalized_created_by,
            actor_id=normalized_created_by_id,
            clinic_id=normalized_clinic_id,
            demographic_no=demographic_no,
            account_id=account.id,
            resource_type="booking_prompt",
            resource_id=str(prompt.id),
            # A count only: which times were offered is not audit evidence anyone needs.
            reason=f"initial:{len(normalized_slots)}",
        )
    return CreatedBookingPrompt(prompt=prompt, created=True)


def list_booking_prompts(
    session: Session,
    *,
    clinic_id: str,
    demographic_no: int,
    actor: str,
    actor_id: str | None,
) -> list[PatientPortalBookingPrompt]:
    """The patient's prompts, newest first, for staff; the listing itself is audited."""
    validate_demographic_no(demographic_no)
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    normalized_actor = normalize_staff_actor(actor)
    prompts = list(
        session.scalars(
            select(PatientPortalBookingPrompt)
            .where(
                PatientPortalBookingPrompt.clinic_id == normalized_clinic_id,
                PatientPortalBookingPrompt.demographic_no == demographic_no,
            )
            .order_by(
                PatientPortalBookingPrompt.created_at.desc(),
                PatientPortalBookingPrompt.id.desc(),
            )
            .limit(MAX_STAFF_PROMPT_LIST)
        )
    )
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_BOOKING_PROMPT_LIST,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor=normalized_actor,
        actor_id=normalize_staff_actor_id(actor_id, normalized_actor),
        clinic_id=normalized_clinic_id,
        demographic_no=demographic_no,
        resource_type="booking_prompt",
    )
    return prompts


def withdraw_booking_prompt(
    session: Session,
    prompt_id: int,
    *,
    clinic_id: str,
    withdrawn_by: str,
    withdrawn_by_id: str | None,
) -> PatientPortalBookingPrompt:
    """Withdraw a prompt, for example once the patient has booked by phone.

    Withdrawing again returns the prompt unchanged, so a CARLOS retry is safe. A withdrawn
    prompt's pending notice is not sent: the outbox checks the prompt before sending. Its offered
    times are deleted, a choice still waiting for CARLOS is closed so CARLOS cannot book it, and
    no copy of a chosen time is kept, because the patient no longer sees the prompt.
    """
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    normalized_actor = normalize_staff_actor(withdrawn_by)
    normalized_actor_id = normalize_staff_actor_id(withdrawn_by_id, normalized_actor)
    prompt = session.scalar(
        select(PatientPortalBookingPrompt)
        .where(
            PatientPortalBookingPrompt.id == prompt_id,
            PatientPortalBookingPrompt.clinic_id == normalized_clinic_id,
        )
        .with_for_update()
    )
    if prompt is None:
        raise BookingPromptNotFoundError()
    if prompt.status == BOOKING_PROMPT_STATUS_WITHDRAWN:
        return prompt
    now = utc_now()
    prompt.status = BOOKING_PROMPT_STATUS_WITHDRAWN
    prompt.withdrawn_at = now
    prompt.withdrawn_by = normalized_actor
    prompt.withdrawn_by_id = normalized_actor_id
    session.flush()
    delete_offered_slots(session, prompt.id)
    session.execute(
        update(PatientPortalBookingChoice)
        .where(
            PatientPortalBookingChoice.prompt_id == prompt.id,
            PatientPortalBookingChoice.state == BOOKING_CHOICE_STATE_PENDING,
        )
        .values(state=BOOKING_CHOICE_STATE_WITHDRAWN, result_at=now)
        .execution_options(synchronize_session=False)
    )
    session.execute(
        update(PatientPortalBookingChoice)
        .where(PatientPortalBookingChoice.prompt_id == prompt.id)
        .values(
            slot_id=None,
            starts_at=None,
            duration_minutes=None,
            visit_mode=None,
            location_code=None,
        )
        .execution_options(synchronize_session=False)
    )
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_BOOKING_PROMPT_WITHDRAW,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor=normalized_actor,
        actor_id=normalized_actor_id,
        clinic_id=normalized_clinic_id,
        demographic_no=prompt.demographic_no,
        account_id=prompt.account_id,
        resource_type="booking_prompt",
        resource_id=str(prompt.id),
    )
    return prompt


def _active_for_account(account_id: int, now: datetime) -> tuple[ColumnElement[bool], ...]:
    """Which of an account's prompts the patient sees.

    A live sent, read, or declined prompt; a prompt whose chosen time CARLOS has not answered yet,
    even past its expiry, so the patient is not left without an answer; for a few days, a prompt
    whose pick was reported taken, or lapsed, after it expired, so the patient learns to contact
    the clinic; and a booked prompt until a day after the booked time.
    """
    booked_time_upcoming = (
        select(PatientPortalBookingChoice.id)
        .where(
            PatientPortalBookingChoice.prompt_id == PatientPortalBookingPrompt.id,
            PatientPortalBookingChoice.state == BOOKING_CHOICE_STATE_BOOKED,
            PatientPortalBookingChoice.starts_at > now - BOOKED_TIME_RETENTION_AFTER_START,
        )
        .exists()
    )
    return (
        PatientPortalBookingPrompt.account_id == account_id,
        or_(
            and_(
                PatientPortalBookingPrompt.status.in_(
                    (
                        BOOKING_PROMPT_STATUS_SENT,
                        BOOKING_PROMPT_STATUS_READ,
                        BOOKING_PROMPT_STATUS_DECLINED_ALL,
                    )
                ),
                PatientPortalBookingPrompt.expires_at > now,
            ),
            PatientPortalBookingPrompt.status == BOOKING_PROMPT_STATUS_CHOICE_PENDING,
            and_(
                PatientPortalBookingPrompt.status == BOOKING_PROMPT_STATUS_BOOKED,
                booked_time_upcoming,
            ),
            and_(
                PatientPortalBookingPrompt.status == BOOKING_PROMPT_STATUS_READ,
                closed_after_expiry_notice(now),
            ),
        ),
    )


def list_active_prompts_for_account(
    session: Session,
    account_id: int,
) -> list[PatientPortalBookingPrompt]:
    """The patient's live prompts, newest first; withdrawn, expired, and past ones drop out."""
    return list(
        session.scalars(
            select(PatientPortalBookingPrompt)
            .where(*_active_for_account(account_id, utc_now()))
            .order_by(
                PatientPortalBookingPrompt.created_at.desc(),
                PatientPortalBookingPrompt.id.desc(),
            )
            .limit(MAX_PATIENT_PROMPT_LIST)
        )
    )


def count_unread_prompts_for_account(session: Session, account_id: int) -> int:
    return session.scalar(
        select(func.count(PatientPortalBookingPrompt.id)).where(
            *_active_for_account(account_id, utc_now()),
            PatientPortalBookingPrompt.status == BOOKING_PROMPT_STATUS_SENT,
        )
    ) or 0


def open_booking_prompt(
    session: Session,
    prompt_id: int,
    *,
    account: PatientPortalAccount,
) -> PatientPortalBookingPrompt:
    """Show one of the patient's live prompts, recording the first time they open it."""
    prompt = session.scalar(
        select(PatientPortalBookingPrompt)
        .where(
            PatientPortalBookingPrompt.id == prompt_id,
            PatientPortalBookingPrompt.clinic_id == account.clinic_id,
            *_active_for_account(account.id, utc_now()),
        )
        .with_for_update()
    )
    if prompt is None:
        raise BookingPromptNotFoundError()
    if prompt.status == BOOKING_PROMPT_STATUS_SENT:
        prompt.status = BOOKING_PROMPT_STATUS_READ
        prompt.read_at = utc_now()
        session.flush()
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_BOOKING_PROMPT_READ,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_PATIENT,
            actor=account.username,
            actor_id=str(account.id),
            clinic_id=account.clinic_id,
            demographic_no=account.demographic_no,
            account_id=account.id,
            resource_type="booking_prompt",
            resource_id=str(prompt.id),
        )
    return prompt


def find_visible_prompt(
    session: Session,
    prompt_id: int,
    *,
    account: PatientPortalAccount,
) -> PatientPortalBookingPrompt | None:
    """One of the patient's visible prompts, without recording a read; None when not theirs."""
    return session.scalar(
        select(PatientPortalBookingPrompt).where(
            PatientPortalBookingPrompt.id == prompt_id,
            PatientPortalBookingPrompt.clinic_id == account.clinic_id,
            *_active_for_account(account.id, utc_now()),
        )
    )
