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

"""The booking-choice functions refuse a bad argument before they touch the database.

The page size of the pending list, an unknown result, and replacement times sent with a booked
result. None of these reads or writes a row, so no session is needed (a bare object stands in).
Every value is FAKE.
"""

from datetime import UTC, datetime

import pytest

from carlos_patient_portal.booking_choices import (
    MAX_PENDING_CHOICE_LIST,
    list_pending_choices,
    record_choice_result,
)
from carlos_patient_portal.booking_offers import OfferedSlotSpec
from carlos_patient_portal.models import (
    BOOKING_CHOICE_STATE_BOOKED,
    BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE,
)

NO_SESSION = object()


@pytest.mark.parametrize("limit", [0, -1, MAX_PENDING_CHOICE_LIST + 1, 10_000])
def test_a_page_size_outside_one_to_the_maximum_is_refused(limit: int) -> None:
    with pytest.raises(ValueError, match=f"limit must be between 1 and {MAX_PENDING_CHOICE_LIST}"):
        list_pending_choices(
            NO_SESSION, clinic_id="clinic-a", actor="job", actor_id=None, limit=limit
        )


def record(result: str, **changes: object):
    arguments: dict[str, object] = {
        "clinic_id": "clinic-a",
        "choice_id": 1,
        "result": result,
        "actor": "job",
        "actor_id": None,
        "notice": object(),
        **changes,
    }
    return record_choice_result(NO_SESSION, 1, **arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize("result", ["pending", "", "BOOKED", "cancelled"])
def test_a_result_that_is_not_booked_or_slot_unavailable_is_refused(result: str) -> None:
    with pytest.raises(ValueError, match="result is not supported"):
        record(result)


def test_replacement_times_are_refused_with_a_booked_result() -> None:
    with pytest.raises(ValueError, match="replacement times are only accepted with slot_unavail"):
        record(BOOKING_CHOICE_STATE_BOOKED, replacement_slots=(object(),))


def test_the_two_supported_results_are_what_the_refusal_names() -> None:
    # The refused words above are not accidentally the supported ones.
    assert {BOOKING_CHOICE_STATE_BOOKED, BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE}.isdisjoint(
        {"pending", "", "BOOKED", "cancelled"}
    )


# The refusals above must not be too tight: a value that IS allowed gets past the argument checks
# and starts work. The session below raises a marker on its first use, so reaching it proves the
# arguments were accepted (a bare `object()` would also raise, but as an unrelated AttributeError).


class ReachedTheDatabase(Exception):
    pass


class UntouchableSession:
    def __getattr__(self, name: str):
        raise ReachedTheDatabase(name)


@pytest.mark.parametrize("limit", [1, MAX_PENDING_CHOICE_LIST], ids=["smallest", "largest"])
def test_the_smallest_and_largest_page_sizes_get_past_the_check_to_the_database(
    limit: int,
) -> None:
    with pytest.raises(ReachedTheDatabase):
        list_pending_choices(
            UntouchableSession(),  # type: ignore[arg-type]
            clinic_id="clinic-a",
            actor="job",
            actor_id=None,
            limit=limit,
        )


@pytest.mark.parametrize(
    ("result", "with_replacements"),
    [
        (BOOKING_CHOICE_STATE_BOOKED, False),
        (BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE, False),
        (BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE, True),
    ],
    ids=["booked", "slot unavailable", "slot unavailable with replacements"],
)
def test_the_allowed_result_combinations_get_past_the_checks_to_the_database(
    result: str, with_replacements: bool
) -> None:
    replacements = (
        (
            OfferedSlotSpec(
                slot_id="FAKE:slot:9",
                starts_at=datetime(2030, 1, 15, 15, 0, tzinfo=UTC),
                duration_minutes=30,
                visit_mode="phone",
            ),
        )
        if with_replacements
        else ()
    )

    with pytest.raises(ReachedTheDatabase):
        record_choice_result(
            UntouchableSession(),  # type: ignore[arg-type]
            1,
            clinic_id="clinic-a",
            choice_id=1,
            result=result,
            replacement_slots=replacements,
            booking_location_codes={"FAKE-loc"},
            actor="job",
            actor_id=None,
            notice=object(),  # type: ignore[arg-type]
        )
