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

"""What a booking prompt does when another writer got to its pick first.

The prompt lock keeps these from happening in one process, so each case builds the state a writer
that did not take the lock would leave: a prompt that still reads open with a pick already pending,
and a pick another writer resolved between the closing pass's listing and its locked read. Every
value is FAKE.
"""

from datetime import timedelta

from sqlalchemy import select

from carlos_patient_portal import booking_choices
from carlos_patient_portal.booking_choices import close_lapsed_choices
from carlos_patient_portal.models import (
    BOOKING_PROMPT_STATUS_READ,
    PatientPortalBookingChoice,
    PatientPortalBookingPrompt,
    utc_now,
)
from tests.test_booking_offered_slots import (
    decline,
    only_choice,
    patient_with_offer,
    pick,
    slot_row_ids,
    start_the_picked_time,
)


def reopen_the_prompt(app, prompt_id: int) -> None:
    """The prompt reads open again while its pick stays pending, as an unlocked writer leaves it."""
    with app.state.session_factory.begin() as session:
        session.get(PatientPortalBookingPrompt, prompt_id).status = BOOKING_PROMPT_STATUS_READ


def choice_count(app) -> int:
    with app.state.session_factory() as session:
        return len(list(session.scalars(select(PatientPortalBookingChoice))))


def test_a_second_pick_is_refused_while_one_is_already_pending() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    reopen_the_prompt(app, prompt_id)

    other = pick(app, patient, prompt_id, "carlos:slot:2")

    # The prompt is closed to a second pick (the same answer as a prompt that is no longer open).
    assert other.status_code == 409
    assert choice_count(app) == 1
    assert only_choice(app).state == "pending"


def test_declining_is_refused_while_a_pick_is_pending() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    reopen_the_prompt(app, prompt_id)
    offered = slot_row_ids(app, prompt_id)

    refused = decline(patient, prompt_id)

    assert refused.status_code == 409
    # Nothing was declined: the pick and the offered times are as they were.
    assert only_choice(app).state == "pending"
    assert slot_row_ids(app, prompt_id) == offered


def test_a_pick_another_writer_resolved_after_the_listing_is_left_alone(monkeypatch) -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    start_the_picked_time(app, prompt_id)
    # Between the closing pass's listing and its locked read, the pick is no longer pending.
    monkeypatch.setattr(booking_choices, "_pending_choice", lambda *_args, **_kwargs: None)

    with app.state.session_factory.begin() as session:
        closed = close_lapsed_choices(session)

    assert closed == 0
    assert only_choice(app).state == "pending"


def test_a_pick_whose_time_has_not_started_is_not_closed_when_read_under_the_lock(
    monkeypatch,
) -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    start_the_picked_time(app, prompt_id)
    real = booking_choices._pending_choice

    def moved_later(session, prompt):  # noqa: ANN001, ANN202
        found = real(session, prompt)
        # Another writer moved the time ahead after the listing: it has not started now.
        found.starts_at = utc_now() + timedelta(hours=2)
        return found

    monkeypatch.setattr(booking_choices, "_pending_choice", moved_later)

    with app.state.session_factory.begin() as session:
        closed = close_lapsed_choices(session)

    assert closed == 0
    assert only_choice(app).state == "pending"
