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

"""A patient's pick among offered times, and CARLOS's answer (carlos-portal#11).

The patient picks one offered time, or says none of them work. CARLOS polls for pending picks,
tries to book each one, and reports `booked` or `slot_unavailable`; the portal never calls
CARLOS. One pick at a time: every write here locks the prompt row first, so two submissions for
one prompt, or a pick racing a withdrawal or a result, are serialised, and a partial unique index
refuses a second pending pick even for a writer that skipped the lock.
"""

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal.audit import record_audit_event
from carlos_patient_portal.booking_offers import (
    OfferedSlotSpec,
    add_offered_slots,
    as_utc,
    clear_choice_copy,
    current_offered_slots,
    delete_offered_slots,
    normalize_offered_slots,
    require_future_slots,
)
from carlos_patient_portal.booking_prompts import (
    BookingPromptNotFoundError,
    BookingPromptNotice,
)
from carlos_patient_portal.delivery_outbox import enqueue_booking_prompt_update_delivery
from carlos_patient_portal.invites import (
    normalize_clinic_id,
    normalize_staff_actor,
    normalize_staff_actor_id,
)
from carlos_patient_portal.models import (
    AUDIT_ACTOR_TYPE_PATIENT,
    AUDIT_ACTOR_TYPE_STAFF,
    AUDIT_EVENT_BOOKING_PROMPT_CHOICE,
    AUDIT_EVENT_BOOKING_PROMPT_DECLINE,
    AUDIT_EVENT_BOOKING_PROMPT_OFFER,
    AUDIT_EVENT_BOOKING_PROMPT_RESULT,
    AUDIT_EVENT_STAFF_ACTION,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_SUCCESS,
    BOOKING_CHOICE_RESULTS,
    BOOKING_CHOICE_STATE_BOOKED,
    BOOKING_CHOICE_STATE_PENDING,
    BOOKING_CHOICE_STATE_WITHDRAWN,
    BOOKING_PROMPT_STATUS_BOOKED,
    BOOKING_PROMPT_STATUS_CHOICE_PENDING,
    BOOKING_PROMPT_STATUS_DECLINED_ALL,
    BOOKING_PROMPT_STATUS_READ,
    BOOKING_PROMPT_STATUS_SENT,
    MAX_OFFERED_SLOTS,
    PatientPortalAccount,
    PatientPortalBookingChoice,
    PatientPortalBookingOfferedSlot,
    PatientPortalBookingPrompt,
    utc_now,
)

MAX_PENDING_CHOICE_LIST = 100
# Audit reasons for a refused patient pick or decline; fixed codes, never the submitted value.
CHOICE_REFUSED_NOT_AVAILABLE = "not_available"
CHOICE_REFUSED_PROMPT_CLOSED = "prompt_closed"
CHOICE_REFUSED_SLOT_UNAVAILABLE = "slot_unavailable"


class BookingChoiceUnavailableError(Exception):
    """The prompt cannot take a pick now: one is pending, or it is booked or declined."""


class BookingSlotUnavailableError(Exception):
    """The picked time is not one of the prompt's current offered times."""


class BookingChoiceNotPendingError(Exception):
    """A result names a choice that is not this prompt's pending choice."""


class BookingChoiceResultConflictError(Exception):
    """A result differs from the one already recorded for the choice."""


@dataclass(frozen=True, slots=True)
class PendingBookingChoice:
    choice: PatientPortalBookingChoice
    demographic_no: int


@dataclass(frozen=True, slots=True)
class PendingBookingChoicePage:
    choices: tuple[PendingBookingChoice, ...]
    has_more: bool


@dataclass(frozen=True, slots=True)
class BookingChoiceResultOutcome:
    prompt: PatientPortalBookingPrompt
    choice: PatientPortalBookingChoice
    # False when the same result was already recorded: nothing changed and nothing was sent.
    recorded: bool
    offered_slot_count: int


def _pickable_slot_count(
    session: Session,
    prompt: PatientPortalBookingPrompt,
    *,
    now: datetime,
) -> int:
    """How many times the patient could pick now: none unless the prompt is live and open."""
    if (
        prompt.status not in (BOOKING_PROMPT_STATUS_SENT, BOOKING_PROMPT_STATUS_READ)
        or as_utc(prompt.expires_at) <= now
    ):
        return 0
    return len(current_offered_slots(session, prompt.id, now=now))


def _lock_prompt(
    session: Session,
    prompt_id: int,
    *,
    clinic_id: str,
    account_id: int | None = None,
) -> PatientPortalBookingPrompt | None:
    statement = (
        select(PatientPortalBookingPrompt)
        .where(
            PatientPortalBookingPrompt.id == prompt_id,
            PatientPortalBookingPrompt.clinic_id == clinic_id,
        )
        .with_for_update()
        # The row may already be in this session from an earlier read; the locked read must
        # replace it, or a pick would be judged on the state before another writer committed.
        .execution_options(populate_existing=True)
    )
    if account_id is not None:
        statement = statement.where(PatientPortalBookingPrompt.account_id == account_id)
    return session.scalar(statement)


def _pending_choice(session: Session, prompt_id: int) -> PatientPortalBookingChoice | None:
    return session.scalar(
        select(PatientPortalBookingChoice)
        .where(
            PatientPortalBookingChoice.prompt_id == prompt_id,
            PatientPortalBookingChoice.state == BOOKING_CHOICE_STATE_PENDING,
        )
        .with_for_update()
    )


def latest_choice(session: Session, prompt_id: int) -> PatientPortalBookingChoice | None:
    return session.scalar(
        select(PatientPortalBookingChoice)
        .where(PatientPortalBookingChoice.prompt_id == prompt_id)
        .order_by(PatientPortalBookingChoice.id.desc())
        .limit(1)
    )


def _require_open_for_patient(
    prompt: PatientPortalBookingPrompt | None,
    *,
    now: datetime,
) -> PatientPortalBookingPrompt:
    """A prompt the patient can still pick from or decline.

    Not theirs, withdrawn, or expired reads as not found, exactly as opening it does, so a guessed
    id reveals nothing. Their own prompt that is waiting on CARLOS, booked, or declined is a
    conflict: the page they submitted from is out of date.
    """
    if prompt is None:
        raise BookingPromptNotFoundError()
    if prompt.status in (BOOKING_PROMPT_STATUS_SENT, BOOKING_PROMPT_STATUS_READ):
        if as_utc(prompt.expires_at) <= now:
            raise BookingPromptNotFoundError()
        return prompt
    if prompt.status == BOOKING_PROMPT_STATUS_DECLINED_ALL and as_utc(prompt.expires_at) <= now:
        raise BookingPromptNotFoundError()
    if prompt.status in (
        BOOKING_PROMPT_STATUS_CHOICE_PENDING,
        BOOKING_PROMPT_STATUS_BOOKED,
        BOOKING_PROMPT_STATUS_DECLINED_ALL,
    ):
        raise BookingChoiceUnavailableError()
    raise BookingPromptNotFoundError()


def _mark_read(prompt: PatientPortalBookingPrompt, now: datetime) -> None:
    if prompt.read_at is None:
        prompt.read_at = now


def choose_offered_slot(
    session: Session,
    prompt_id: int,
    offered_slot_id: int | None,
    *,
    account: PatientPortalAccount,
) -> PatientPortalBookingChoice:
    """Record the patient's pick of one offered time, for CARLOS to book.

    `offered_slot_id` is the portal's own row id, as the page offered it; CARLOS's slot id never
    reaches the browser.
    """
    now = utc_now()
    prompt = _require_open_for_patient(
        _lock_prompt(session, prompt_id, clinic_id=account.clinic_id, account_id=account.id),
        now=now,
    )
    if _pending_choice(session, prompt.id) is not None:
        raise BookingChoiceUnavailableError()
    slot = (
        None
        if offered_slot_id is None
        else session.scalar(
            select(PatientPortalBookingOfferedSlot).where(
                PatientPortalBookingOfferedSlot.id == offered_slot_id,
                PatientPortalBookingOfferedSlot.prompt_id == prompt.id,
            )
        )
    )
    if slot is None or as_utc(slot.starts_at) <= now:
        raise BookingSlotUnavailableError()
    choice = PatientPortalBookingChoice(
        prompt_id=prompt.id,
        clinic_id=prompt.clinic_id,
        slot_id=slot.slot_id,
        starts_at=slot.starts_at,
        duration_minutes=slot.duration_minutes,
        visit_mode=slot.visit_mode,
        location_code=slot.location_code,
        state=BOOKING_CHOICE_STATE_PENDING,
        chosen_at=now,
    )
    try:
        with session.begin_nested():
            prompt.status = BOOKING_PROMPT_STATUS_CHOICE_PENDING
            _mark_read(prompt, now)
            session.add(choice)
            session.flush()
    except IntegrityError as exc:
        # Only reachable by a writer that did not take the prompt lock; the index still holds.
        raise BookingChoiceUnavailableError() from exc
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_BOOKING_PROMPT_CHOICE,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_PATIENT,
        actor=account.username,
        actor_id=str(account.id),
        clinic_id=account.clinic_id,
        demographic_no=account.demographic_no,
        account_id=account.id,
        resource_type="booking_choice",
        resource_id=str(choice.id),
    )
    return choice


def decline_offered_slots(
    session: Session,
    prompt_id: int,
    *,
    account: PatientPortalAccount,
) -> PatientPortalBookingPrompt:
    """Record that none of the offered times work; the patient is told to contact the clinic."""
    now = utc_now()
    prompt = _require_open_for_patient(
        _lock_prompt(session, prompt_id, clinic_id=account.clinic_id, account_id=account.id),
        now=now,
    )
    if _pending_choice(session, prompt.id) is not None:
        raise BookingChoiceUnavailableError()
    offered_count = len(current_offered_slots(session, prompt.id, now=now))
    if offered_count == 0:
        raise BookingSlotUnavailableError()
    prompt.status = BOOKING_PROMPT_STATUS_DECLINED_ALL
    _mark_read(prompt, now)
    session.flush()
    delete_offered_slots(session, prompt.id)
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_BOOKING_PROMPT_DECLINE,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_PATIENT,
        actor=account.username,
        actor_id=str(account.id),
        clinic_id=account.clinic_id,
        demographic_no=account.demographic_no,
        account_id=account.id,
        resource_type="booking_prompt",
        resource_id=str(prompt.id),
        reason=f"offered:{offered_count}",
    )
    return prompt


def record_patient_booking_refusal(
    session: Session,
    *,
    account: PatientPortalAccount,
    event_type: str,
    prompt_id: int,
    reason: str,
) -> None:
    """Audit a refused pick or decline with a fixed reason code, never the submitted value."""
    record_audit_event(
        session,
        event_type=event_type,
        outcome=AUDIT_OUTCOME_FAILURE,
        actor_type=AUDIT_ACTOR_TYPE_PATIENT,
        actor=account.username,
        actor_id=str(account.id),
        clinic_id=account.clinic_id,
        demographic_no=account.demographic_no,
        account_id=account.id,
        resource_type="booking_prompt",
        resource_id=str(prompt_id),
        reason=reason,
    )


def list_pending_choices(
    session: Session,
    *,
    clinic_id: str,
    actor: str,
    actor_id: str | None,
    limit: int = MAX_PENDING_CHOICE_LIST,
) -> PendingBookingChoicePage:
    """The clinic's picks waiting for CARLOS, oldest first, for the polling job.

    A pick stays listed until CARLOS reports its result or staff withdraw its prompt, including
    after the prompt's expiry: the patient chose while it was live and is still waiting.
    """
    if not 1 <= limit <= MAX_PENDING_CHOICE_LIST:
        raise ValueError(f"limit must be between 1 and {MAX_PENDING_CHOICE_LIST}")
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    normalized_actor = normalize_staff_actor(actor)
    rows = session.execute(
        select(PatientPortalBookingChoice, PatientPortalBookingPrompt.demographic_no)
        .join(
            PatientPortalBookingPrompt,
            PatientPortalBookingPrompt.id == PatientPortalBookingChoice.prompt_id,
        )
        .where(
            PatientPortalBookingChoice.clinic_id == normalized_clinic_id,
            PatientPortalBookingChoice.state == BOOKING_CHOICE_STATE_PENDING,
            PatientPortalBookingPrompt.clinic_id == normalized_clinic_id,
        )
        .order_by(PatientPortalBookingChoice.chosen_at, PatientPortalBookingChoice.id)
        .limit(limit + 1)
    ).all()
    choices = tuple(
        PendingBookingChoice(choice=choice, demographic_no=demographic_no)
        for choice, demographic_no in rows[:limit]
    )
    if choices:
        # An empty poll discloses nothing and would otherwise write a row every minute.
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_STAFF_ACTION,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_STAFF,
            actor=normalized_actor,
            actor_id=normalize_staff_actor_id(actor_id, normalized_actor),
            clinic_id=normalized_clinic_id,
            resource_type="booking_choice",
            resource_id=f"count:{len(choices)}",
            reason="pending_choices_listed",
        )
    return PendingBookingChoicePage(choices=choices, has_more=len(rows) > limit)


def record_choice_result(
    session: Session,
    prompt_id: int,
    *,
    clinic_id: str,
    choice_id: int,
    result: str,
    replacement_slots: Sequence[OfferedSlotSpec] = (),
    booking_location_codes: Collection[str] = (),
    actor: str,
    actor_id: str | None,
    notice: BookingPromptNotice,
) -> BookingChoiceResultOutcome:
    """Record CARLOS's answer to one pick, and tell the patient there is an update.

    Idempotent per choice: the same result again changes nothing and sends nothing, so a repeated
    poll cycle cannot double-report. A different result for a resolved choice is a conflict. On
    `booked` the offered times are deleted. On `slot_unavailable` the taken time is removed, the
    patient can pick again from the rest, and any replacement times are added after them; on an
    expired prompt the patient can no longer pick, so replacements are not stored.
    """
    if result not in BOOKING_CHOICE_RESULTS:
        raise ValueError("result is not supported")
    if result == BOOKING_CHOICE_STATE_BOOKED and replacement_slots:
        raise ValueError("replacement times are only accepted with slot_unavailable")
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    normalized_actor = normalize_staff_actor(actor)
    normalized_actor_id = normalize_staff_actor_id(actor_id, normalized_actor)
    replacements = normalize_offered_slots(
        replacement_slots,
        location_codes=booking_location_codes,
    )
    prompt = _lock_prompt(session, prompt_id, clinic_id=normalized_clinic_id)
    if prompt is None:
        raise BookingPromptNotFoundError()
    choice = session.scalar(
        select(PatientPortalBookingChoice)
        .where(
            PatientPortalBookingChoice.id == choice_id,
            PatientPortalBookingChoice.prompt_id == prompt.id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    now = utc_now()
    if choice is None or choice.state == BOOKING_CHOICE_STATE_WITHDRAWN:
        raise BookingChoiceNotPendingError()
    if choice.state == result:
        return BookingChoiceResultOutcome(
            prompt=prompt,
            choice=choice,
            recorded=False,
            offered_slot_count=_pickable_slot_count(session, prompt, now=now),
        )
    if choice.state != BOOKING_CHOICE_STATE_PENDING:
        raise BookingChoiceResultConflictError()

    prompt_expired = as_utc(prompt.expires_at) <= now
    store_replacements = bool(replacements) and not prompt_expired
    if store_replacements:
        # Checked in full before anything changes, so a refused result leaves the choice pending
        # for CARLOS to report again.
        require_future_slots(replacements, now=now)
        remaining_ids = {
            slot.slot_id
            for slot in current_offered_slots(session, prompt.id, now=now)
            if slot.slot_id != choice.slot_id
        }
        if any(
            slot.slot_id in remaining_ids or slot.slot_id == choice.slot_id
            for slot in replacements
        ):
            raise ValueError("a replacement slot_id is already offered, or was just taken")
        if len(remaining_ids) + len(replacements) > MAX_OFFERED_SLOTS:
            raise ValueError(f"at most {MAX_OFFERED_SLOTS} times can be offered")

    choice.state = result
    choice.result_at = now
    if result == BOOKING_CHOICE_STATE_BOOKED:
        prompt.status = BOOKING_PROMPT_STATUS_BOOKED
        session.flush()
        delete_offered_slots(session, prompt.id)
    else:
        taken_slot_id = choice.slot_id
        clear_choice_copy(choice)
        if prompt.status == BOOKING_PROMPT_STATUS_CHOICE_PENDING:
            prompt.status = BOOKING_PROMPT_STATUS_READ
        session.flush()
        if prompt_expired:
            # The patient can no longer pick from an expired prompt, so nothing offered is kept.
            delete_offered_slots(session, prompt.id)
        elif taken_slot_id is not None:
            delete_offered_slots(session, prompt.id, slot_id=taken_slot_id)
        if store_replacements:
            # Times that have started are no use to the patient and would count against the cap.
            delete_offered_slots(session, prompt.id, started_before=now)
            add_offered_slots(session, prompt.id, replacements)
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_BOOKING_PROMPT_RESULT,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor=normalized_actor,
        actor_id=normalized_actor_id,
        clinic_id=normalized_clinic_id,
        demographic_no=prompt.demographic_no,
        account_id=prompt.account_id,
        resource_type="booking_choice",
        resource_id=str(choice.id),
        reason=result,
    )
    if store_replacements:
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_BOOKING_PROMPT_OFFER,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_STAFF,
            actor=normalized_actor,
            actor_id=normalized_actor_id,
            clinic_id=normalized_clinic_id,
            demographic_no=prompt.demographic_no,
            account_id=prompt.account_id,
            resource_type="booking_prompt",
            resource_id=str(prompt.id),
            reason=f"replacement:{len(replacements)}",
        )
    enqueue_booking_prompt_update_delivery(
        session,
        account_id=prompt.account_id,
        booking_prompt_id=prompt.id,
        sign_in_url=notice.sign_in_url,
        encryption_secret=notice.encryption_secret,
        encryption_key_id=notice.encryption_key_id,
    )
    return BookingChoiceResultOutcome(
        prompt=prompt,
        choice=choice,
        recorded=True,
        offered_slot_count=_pickable_slot_count(session, prompt, now=now),
    )
