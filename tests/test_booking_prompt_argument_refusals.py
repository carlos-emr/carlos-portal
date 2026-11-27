"""What a booking prompt refuses before it asks the database anything.

CARLOS sends these values; a bad one is a bug on its side, answered as a refusal, never as a
half-stored prompt. Every refusal here is decided from the arguments alone, and the session used
raises a marker the moment anything touches it, so a refusal that came only after a database call
would show as that marker and not as the expected message. FAKE and synthetic values only.
"""

from datetime import timedelta
from unittest.mock import MagicMock

import pytest

from carlos_patient_portal import booking_prompts
from carlos_patient_portal.models import (
    BOOKING_PROMPT_APPOINTMENT_TYPES,
    BOOKING_PROMPT_URGENCIES,
    MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH,
)


class ReachedTheDatabase(Exception):
    """Raised by any use of the session: the arguments were accepted and the work began."""


class UntouchableSession:
    def __getattr__(self, name: str):
        raise ReachedTheDatabase(name)


def create(**overrides):
    values = {
        "clinic_id": "FAKE-clinic",
        "demographic_no": 4242,
        "operation_id": "FAKE-operation-1",
        "urgency": BOOKING_PROMPT_URGENCIES[0],
        "appointment_type": BOOKING_PROMPT_APPOINTMENT_TYPES[0],
        "suggested_by": None,
        "created_by": "FAKE staff",
        "created_by_id": None,
        "ttl": timedelta(days=7),
        "notice": MagicMock(name="notice"),
        **overrides,
    }
    return booking_prompts.create_booking_prompt(UntouchableSession(), **values)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"urgency": "whenever"}, "urgency is not supported"),
        ({"urgency": ""}, "urgency is not supported"),
        ({"appointment_type": "surgery"}, "appointment_type is not supported"),
        ({"appointment_type": ""}, "appointment_type is not supported"),
        ({"ttl": timedelta(0)}, "ttl must be positive"),
        ({"ttl": timedelta(seconds=-1)}, "ttl must be positive"),
    ],
    ids=[
        "urgency not listed",
        "urgency blank",
        "type not listed",
        "type blank",
        "no lifetime",
        "negative lifetime",
    ],
)
def test_a_prompt_with_an_unsupported_urgency_type_or_lifetime_is_refused_first(
    overrides, message
) -> None:
    with pytest.raises(ValueError, match=message):
        create(**overrides)


def test_every_listed_urgency_and_type_gets_past_the_argument_checks_to_the_database() -> None:
    # The refusals above are about the value: a listed one is not refused, the work begins and
    # the first thing it does is use the session.
    for urgency in BOOKING_PROMPT_URGENCIES:
        for appointment_type in BOOKING_PROMPT_APPOINTMENT_TYPES:
            with pytest.raises(ReachedTheDatabase):
                create(urgency=urgency, appointment_type=appointment_type)


@pytest.mark.parametrize("operation_id", ["", "   ", "\t\n", "x" * 65, " " + "x" * 65 + " "])
def test_an_operation_id_that_is_blank_or_over_the_limit_is_refused_first(
    operation_id: str,
) -> None:
    with pytest.raises(ValueError, match="operation_id must be 1 to 64 characters"):
        booking_prompts._normalize_operation_id(operation_id)
    with pytest.raises(ValueError, match="operation_id must be 1 to 64 characters"):
        create(operation_id=operation_id)


def test_an_operation_id_is_trimmed_and_the_limit_is_the_trimmed_length() -> None:
    assert booking_prompts._normalize_operation_id("  FAKE-op  ") == "FAKE-op"
    longest = "x" * MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH
    assert MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH == 64
    assert booking_prompts._normalize_operation_id(longest) == longest
    # Spaces around the longest id do not count against it ...
    assert booking_prompts._normalize_operation_id(f"  {longest}  ") == longest
    # ... and one more character does.
    with pytest.raises(ValueError):
        booking_prompts._normalize_operation_id(longest + "x")
