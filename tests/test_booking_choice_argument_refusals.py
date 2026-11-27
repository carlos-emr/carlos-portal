"""What the booking-choice calls refuse before they ask the database anything.

CARLOS's polling job lists the patients' picks and reports a result for each. A page size outside
what the portal allows, a result the portal does not know, or replacement times sent with a
"booked" answer are mistakes on the caller's side, answered as a refusal and never as a half-done
update (a "booked" answer deletes the offered times, so replacements beside it would be lost
without a word). Every refusal here is decided from the arguments alone, and the session used
raises a marker the moment anything touches it, so a refusal that came after a database call
would show as that marker, not as the expected message. FAKE and synthetic values only.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from carlos_patient_portal import booking_choices
from carlos_patient_portal.booking_offers import OfferedSlotSpec
from carlos_patient_portal.models import (
    BOOKING_CHOICE_RESULTS,
    BOOKING_CHOICE_STATE_BOOKED,
    BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE,
)


class ReachedTheDatabase(Exception):
    """Raised by any use of the session: the arguments were accepted and the work began."""


class UntouchableSession:
    def __getattr__(self, name: str):
        raise ReachedTheDatabase(name)


REPLACEMENT = OfferedSlotSpec(
    slot_id="FAKE:slot:9",
    starts_at=datetime(2030, 1, 15, 15, 0, tzinfo=UTC),
    duration_minutes=30,
    visit_mode="phone",
)


def list_pending(**overrides):
    values = {
        "clinic_id": "FAKE-clinic",
        "actor": "FAKE job",
        "actor_id": None,
        **overrides,
    }
    return booking_choices.list_pending_choices(UntouchableSession(), **values)


def record_result(**overrides):
    values = {
        "clinic_id": "FAKE-clinic",
        "choice_id": 1,
        "result": BOOKING_CHOICE_STATE_BOOKED,
        "actor": "FAKE job",
        "actor_id": None,
        "notice": MagicMock(name="notice"),
        **overrides,
    }
    return booking_choices.record_choice_result(UntouchableSession(), 7, **values)


@pytest.mark.parametrize(
    "limit",
    [0, -1, booking_choices.MAX_PENDING_CHOICE_LIST + 1, 10_000],
    ids=["zero", "negative", "one over the maximum", "far over"],
)
def test_a_page_size_outside_what_the_portal_allows_is_refused_first(limit: int) -> None:
    with pytest.raises(ValueError, match="limit must be between 1 and 100"):
        list_pending(limit=limit)


@pytest.mark.parametrize(
    "limit", [1, booking_choices.MAX_PENDING_CHOICE_LIST], ids=["smallest", "largest"]
)
def test_the_smallest_and_largest_page_sizes_get_past_the_check_to_the_database(
    limit: int,
) -> None:
    with pytest.raises(ReachedTheDatabase):
        list_pending(limit=limit)


@pytest.mark.parametrize("result", ["", "cancelled", "BOOKED", "expired", "pending"])
def test_a_result_the_portal_does_not_know_is_refused_first(result: str) -> None:
    # `expired` and `pending` are states the portal itself moves a pick into; CARLOS cannot
    # report them, so they are not accepted as answers either.
    assert result not in BOOKING_CHOICE_RESULTS

    with pytest.raises(ValueError, match="result is not supported"):
        record_result(result=result)


def test_replacement_times_beside_a_booked_answer_are_refused_first() -> None:
    with pytest.raises(ValueError, match="only accepted with slot_unavailable"):
        record_result(result=BOOKING_CHOICE_STATE_BOOKED, replacement_slots=[REPLACEMENT])


@pytest.mark.parametrize(
    ("result", "replacement_slots"),
    [
        (BOOKING_CHOICE_STATE_BOOKED, ()),
        (BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE, ()),
        (BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE, [REPLACEMENT]),
    ],
    ids=["booked", "slot unavailable", "slot unavailable with replacements"],
)
def test_every_other_combination_gets_past_the_argument_checks_to_the_database(
    result: str, replacement_slots
) -> None:
    with pytest.raises(ReachedTheDatabase):
        record_result(
            result=result,
            replacement_slots=replacement_slots,
            booking_location_codes={"FAKE-loc"},
        )
