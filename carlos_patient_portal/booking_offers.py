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

"""Offered appointment times: what CARLOS may send, and how long the portal keeps it.

CARLOS can attach up to `MAX_OFFERED_SLOTS` open times to a booking prompt (carlos-portal#11).
They are the first appointment data the portal stores, so a time carries only what the patient
must see: its start with an explicit UTC offset, a duration, a visit mode from a fixed vocabulary,
and optionally a location code from `PATIENT_PORTAL_BOOKING_LOCATIONS`. No provider, no reason
for the visit, no free text. The `slot_id` is issued by CARLOS and treated as opaque.

The portal never reads the CARLOS schedule. It shows the times, records the patient's pick, and
waits for CARLOS to poll for it and report whether the time was booked.
"""

import json
import re
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from carlos_patient_portal.audit import hash_sensitive_reference
from carlos_patient_portal.models import (
    BOOKING_VISIT_MODES,
    MAX_BOOKING_LOCATION_CODE_LENGTH,
    MAX_BOOKING_SLOT_DURATION_MINUTES,
    MAX_BOOKING_SLOT_ID_LENGTH,
    MAX_OFFERED_SLOTS,
    MIN_BOOKING_SLOT_DURATION_MINUTES,
    BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE,
    PatientPortalBookingChoice,
    PatientPortalBookingOfferedSlot,
    PatientPortalBookingPrompt,
    utc_now,
)

SLOT_ID_PATTERN = re.compile(rf"[A-Za-z0-9._:-]{{1,{MAX_BOOKING_SLOT_ID_LENGTH}}}")
LOCATION_CODE_PATTERN = re.compile(rf"[a-z0-9_-]{{1,{MAX_BOOKING_LOCATION_CODE_LENGTH}}}")
# A booked time stays shown to the patient, and its copy stays stored, until a day after it starts.
BOOKED_TIME_RETENTION_AFTER_START = timedelta(days=1)
# A prompt that expired while the patient waited on their pick, and whose pick CARLOS then reported
# taken, stays shown this long so the patient learns it fell through and to contact the clinic.
TAKEN_AFTER_EXPIRY_NOTICE = timedelta(days=7)
# How far ahead an offered time may start.
MAX_OFFER_HORIZON = timedelta(days=366)
OFFER_DIGEST_PURPOSE = "booking_offer"


@dataclass(frozen=True, slots=True)
class OfferedSlotSpec:
    """One offered time as CARLOS sends it; `starts_at` must carry a UTC offset."""

    slot_id: str
    starts_at: datetime
    duration_minutes: int
    visit_mode: str
    location_code: str | None = None


def as_utc(value: datetime) -> datetime:
    """SQLite returns naive datetimes for timezone-aware columns; PostgreSQL returns aware ones."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def normalize_offered_slots(
    slots: Sequence[OfferedSlotSpec],
    *,
    location_codes: Collection[str],
) -> tuple[OfferedSlotSpec, ...]:
    """Check what does not depend on the clock, and return the times in UTC.

    Whether a time is still in the future is checked separately, by `require_future_slots`, so a
    CARLOS retry can be matched to its original request after an offered time has passed.
    """
    if len(slots) > MAX_OFFERED_SLOTS:
        raise ValueError(f"at most {MAX_OFFERED_SLOTS} times can be offered")
    normalized: list[OfferedSlotSpec] = []
    seen_slot_ids: set[str] = set()
    for slot in slots:
        if not isinstance(slot.slot_id, str) or SLOT_ID_PATTERN.fullmatch(slot.slot_id) is None:
            raise ValueError("slot_id is not a valid identifier")
        if slot.slot_id in seen_slot_ids:
            raise ValueError("slot_id must be unique within a prompt")
        seen_slot_ids.add(slot.slot_id)
        if slot.starts_at.tzinfo is None or slot.starts_at.utcoffset() is None:
            raise ValueError("starts_at must include a UTC offset")
        if (
            isinstance(slot.duration_minutes, bool)
            or not isinstance(slot.duration_minutes, int)
            or not MIN_BOOKING_SLOT_DURATION_MINUTES
            <= slot.duration_minutes
            <= MAX_BOOKING_SLOT_DURATION_MINUTES
        ):
            raise ValueError("duration_minutes is out of range")
        if slot.visit_mode not in BOOKING_VISIT_MODES:
            raise ValueError("visit_mode is not supported")
        if slot.location_code is not None and (
            LOCATION_CODE_PATTERN.fullmatch(slot.location_code) is None
            or slot.location_code not in location_codes
        ):
            raise ValueError("location_code is not configured")
        try:
            starts_at_utc = slot.starts_at.astimezone(UTC)
        except (OverflowError, ValueError) as exc:
            raise ValueError("starts_at is out of range") from exc
        normalized.append(
            OfferedSlotSpec(
                slot_id=slot.slot_id,
                starts_at=starts_at_utc,
                duration_minutes=slot.duration_minutes,
                visit_mode=slot.visit_mode,
                location_code=slot.location_code,
            )
        )
    return tuple(normalized)


def require_future_slots(slots: Sequence[OfferedSlotSpec], *, now: datetime) -> None:
    if any(as_utc(slot.starts_at) <= now for slot in slots):
        raise ValueError("offered times must be in the future")
    if any(as_utc(slot.starts_at) > now + MAX_OFFER_HORIZON for slot in slots):
        raise ValueError(f"offered times must start within {MAX_OFFER_HORIZON.days} days")


def taken_after_expiry_notice(now: datetime) -> ColumnElement[bool]:
    """A prompt whose pick CARLOS reported taken after the prompt had expired, recently enough to tell
    the patient: they were waiting on that pick and would otherwise never learn it fell through."""
    return (
        select(PatientPortalBookingChoice.id)
        .where(
            PatientPortalBookingChoice.prompt_id == PatientPortalBookingPrompt.id,
            PatientPortalBookingChoice.state == BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE,
            PatientPortalBookingChoice.result_at >= PatientPortalBookingPrompt.expires_at,
            PatientPortalBookingChoice.result_at > now - TAKEN_AFTER_EXPIRY_NOTICE,
        )
        .exists()
    )


def offer_digest(slots: Sequence[OfferedSlotSpec], *, secret: str) -> str | None:
    """A keyed hash of an offer, for matching a retried create after the offer has changed.

    Keyed, so that the digest left on a prompt after its times are deleted cannot be matched
    against guessed times by someone reading the database.
    """
    if not slots:
        return None
    canonical = json.dumps(
        [
            [
                slot.slot_id,
                as_utc(slot.starts_at).isoformat(),
                slot.duration_minutes,
                slot.visit_mode,
                slot.location_code,
            ]
            for slot in slots
        ],
        separators=(",", ":"),
    )
    return hash_sensitive_reference(secret, OFFER_DIGEST_PURPOSE, canonical)


def add_offered_slots(
    session: Session,
    prompt_id: int,
    slots: Sequence[OfferedSlotSpec],
) -> None:
    """Append times after the prompt's existing ones, keeping CARLOS's order."""
    if not slots:
        return
    last_position = session.scalar(
        select(func.max(PatientPortalBookingOfferedSlot.position)).where(
            PatientPortalBookingOfferedSlot.prompt_id == prompt_id
        )
    )
    first_position = 0 if last_position is None else last_position + 1
    now = utc_now()
    for index, slot in enumerate(slots):
        session.add(
            PatientPortalBookingOfferedSlot(
                prompt_id=prompt_id,
                position=first_position + index,
                slot_id=slot.slot_id,
                # Stored in UTC: SQLite keeps the wall-clock time and drops the offset.
                starts_at=as_utc(slot.starts_at).astimezone(UTC),
                duration_minutes=slot.duration_minutes,
                visit_mode=slot.visit_mode,
                location_code=slot.location_code,
                created_at=now,
            )
        )
    session.flush()


def delete_offered_slots(
    session: Session,
    prompt_id: int,
    *,
    slot_id: str | None = None,
    started_before: datetime | None = None,
) -> int:
    """Delete a prompt's offered times: all of them, one by `slot_id`, or those already started."""
    statement = delete(PatientPortalBookingOfferedSlot).where(
        PatientPortalBookingOfferedSlot.prompt_id == prompt_id
    )
    if slot_id is not None:
        statement = statement.where(PatientPortalBookingOfferedSlot.slot_id == slot_id)
    if started_before is not None:
        statement = statement.where(PatientPortalBookingOfferedSlot.starts_at <= started_before)
    result = session.execute(statement.execution_options(synchronize_session=False))
    return int(getattr(result, "rowcount", 0) or 0)


def current_offered_slots(
    session: Session,
    prompt_id: int,
    *,
    now: datetime,
) -> list[PatientPortalBookingOfferedSlot]:
    """The times the patient can still pick, in CARLOS's order; a started time is not one."""
    return list(
        session.scalars(
            select(PatientPortalBookingOfferedSlot)
            .where(
                PatientPortalBookingOfferedSlot.prompt_id == prompt_id,
                PatientPortalBookingOfferedSlot.starts_at > now,
            )
            .order_by(PatientPortalBookingOfferedSlot.position)
        )
    )


def clear_choice_copy(choice: PatientPortalBookingChoice) -> None:
    """Forget which time a choice was for, once nobody needs to be shown it."""
    choice.slot_id = None
    choice.starts_at = None
    choice.duration_minutes = None
    choice.visit_mode = None
    choice.location_code = None
