"""The refusals and edge cases of small helpers that no test drove: what an offered booking time may
be (booking_offers), the keyed offer digest, and the email-password dashboard's search, provider and
date filters and the link that carries them (presenters).

Synthetic values only.
"""

from datetime import UTC, date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from carlos_patient_portal.booking_offers import (
    OfferedSlotSpec,
    normalize_offered_slots,
    offer_digest,
)
from carlos_patient_portal.models import (
    BOOKING_VISIT_MODES,
    MAX_BOOKING_SLOT_DURATION_MINUTES,
    MAX_OFFERED_SLOTS,
    MIN_BOOKING_SLOT_DURATION_MINUTES,
)
from carlos_patient_portal.presenters import (
    PORTAL_EMAIL_PASSWORD_PATH,
    _booking_slot_text,
    _dashboard_created_from,
    normalize_email_password_dashboard_provider,
    normalize_email_password_dashboard_search,
    portal_email_password_page_href,
)
from carlos_patient_portal.unlock_secrets import MAX_UNLOCK_SECRET_SEARCH_LENGTH

LOCATIONS = {"main-clinic", "annex"}
NOON = datetime(2031, 5, 6, 12, 0, tzinfo=UTC)


def slot(**change) -> OfferedSlotSpec:
    values = {
        "slot_id": "FAKE-slot-1",
        "starts_at": NOON,
        "duration_minutes": 30,
        "visit_mode": "phone",
        "location_code": None,
    }
    return OfferedSlotSpec(**(values | change))


def normalized(*slots):
    return normalize_offered_slots(list(slots), location_codes=LOCATIONS)


def refused_with(message, *slots):
    with pytest.raises(ValueError) as caught:
        normalized(*slots)
    assert str(caught.value) == message
    return caught.value


def test_a_valid_offer_is_returned_in_utc_in_the_order_given():
    offset = timezone(timedelta(hours=-4))
    result = normalized(
        slot(slot_id="b", starts_at=NOON.astimezone(offset), location_code="annex"),
        slot(slot_id="a", duration_minutes=MAX_BOOKING_SLOT_DURATION_MINUTES),
    )
    assert [one.slot_id for one in result] == ["b", "a"]
    assert result[0].starts_at == NOON and result[0].starts_at.utcoffset() == timedelta(0)
    assert result[0].location_code == "annex"


def test_at_most_the_maximum_number_of_times_can_be_offered():
    many = [slot(slot_id=f"FAKE-{index}") for index in range(MAX_OFFERED_SLOTS)]
    assert len(normalized(*many)) == MAX_OFFERED_SLOTS
    refused_with(
        f"at most {MAX_OFFERED_SLOTS} times can be offered",
        *many,
        slot(slot_id="FAKE-one-too-many"),
    )


@pytest.mark.parametrize(
    "slot_id", ["", "has space", "a/b", "é", "x" * 65, None, 7, "line\nbreak", "trailing-newline\n"]
)
def test_a_slot_id_must_be_a_short_identifier_of_plain_characters(slot_id):
    refused_with("slot_id is not a valid identifier", slot(slot_id=slot_id))


def test_a_slot_id_of_the_longest_allowed_length_and_with_every_allowed_character_is_kept():
    longest = "aZ09._:-" * 8
    assert len(longest) == 64
    assert normalized(slot(slot_id=longest))[0].slot_id == longest


def test_a_slot_id_cannot_repeat_within_an_offer():
    refused_with("slot_id must be unique within a prompt", slot(), slot())


def test_a_time_without_a_utc_offset_is_refused():
    refused_with("starts_at must include a UTC offset", slot(starts_at=datetime(2031, 5, 6, 12)))


@pytest.mark.parametrize(
    "minutes",
    [
        0,
        MIN_BOOKING_SLOT_DURATION_MINUTES - 1,
        MAX_BOOKING_SLOT_DURATION_MINUTES + 1,
        -30,
    ],
)
def test_a_duration_outside_the_allowed_range_is_refused(minutes):
    refused_with("duration_minutes is out of range", slot(duration_minutes=minutes))


@pytest.mark.parametrize(
    "minutes", [MIN_BOOKING_SLOT_DURATION_MINUTES, MAX_BOOKING_SLOT_DURATION_MINUTES]
)
def test_the_shortest_and_longest_allowed_durations_are_accepted(minutes):
    assert normalized(slot(duration_minutes=minutes))[0].duration_minutes == minutes


@pytest.mark.parametrize("mode", ["", "Phone", "in-person", "home visit", None])
def test_a_visit_mode_must_be_one_the_portal_knows(mode):
    refused_with("visit_mode is not supported", slot(visit_mode=mode))


@pytest.mark.parametrize("mode", BOOKING_VISIT_MODES)
def test_every_supported_visit_mode_is_accepted(mode):
    assert normalized(slot(visit_mode=mode))[0].visit_mode == mode


@pytest.mark.parametrize(
    "code", ["", "Main-Clinic", "unknown", "with space", "x" * 33, "annex\n", "main-clinic "]
)
def test_a_location_must_be_a_configured_code(code):
    refused_with("location_code is not configured", slot(location_code=code))


def test_a_time_too_far_to_express_in_utc_is_refused():
    far = datetime.min.replace(tzinfo=timezone(timedelta(hours=14)))
    refused_with("starts_at is out of range", slot(starts_at=far))


def test_an_empty_offer_has_no_digest_and_a_real_one_depends_on_the_secret_and_the_times():
    assert offer_digest([], secret="FAKE-secret") is None
    first = offer_digest([slot()], secret="FAKE-secret")
    assert isinstance(first, str) and first
    assert offer_digest([slot()], secret="FAKE-secret") == first, "the digest is deterministic"
    assert offer_digest([slot()], secret="FAKE-other-secret") != first
    assert offer_digest([slot(duration_minutes=45)], secret="FAKE-secret") != first
    assert offer_digest([slot(), slot(slot_id="FAKE-slot-2")], secret="FAKE-secret") != first


@pytest.mark.parametrize("search", [None, "", "   ", "\t\n"])
def test_a_blank_dashboard_search_is_no_filter(search):
    assert normalize_email_password_dashboard_search(search) is None


def test_a_dashboard_search_is_trimmed_and_cut_to_its_maximum_length():
    assert normalize_email_password_dashboard_search("  FAKE term  ") == "FAKE term"
    long = "a" * (MAX_UNLOCK_SECRET_SEARCH_LENGTH + 20)
    assert normalize_email_password_dashboard_search(long) == "a" * MAX_UNLOCK_SECRET_SEARCH_LENGTH


def test_a_dashboard_provider_filter_is_trimmed_and_a_structured_one_needs_a_value():
    assert normalize_email_password_dashboard_provider(None) is None
    assert normalize_email_password_dashboard_provider("   ") is None
    assert normalize_email_password_dashboard_provider(" id:FAKE ") == "id:FAKE"
    for bare in ("id:", " name: "):
        with pytest.raises(ValueError, match="structured provider filter must include a value"):
            normalize_email_password_dashboard_provider(bare)


def test_the_earliest_possible_date_is_the_earliest_instant_not_a_local_midnight():
    assert _dashboard_created_from(
        date.min, timezone_name="America/Toronto"
    ) == datetime.min.replace(tzinfo=UTC)
    assert _dashboard_created_from(None, timezone_name="UTC") is None
    # An ordinary date is the start of that day in the clinic's own zone, in UTC.
    assert _dashboard_created_from(date(2031, 1, 15), timezone_name="America/Toronto") == datetime(
        2031, 1, 15, 5, tzinfo=UTC
    )


def test_a_dashboard_link_carries_each_filter_and_only_a_page_past_the_first():
    assert (
        portal_email_password_page_href(
            search=None, provider=None, date_from=None, date_to=None, page=1
        )
        == PORTAL_EMAIL_PASSWORD_PATH
    )
    href = portal_email_password_page_href(
        search=" FAKE term ",
        provider="id:FAKE",
        date_from=date(2031, 1, 2),
        date_to=date(2031, 3, 4),
        page=3,
        base_path="/FAKE/path",
    )
    path, _, query = href.partition("?")
    assert path == "/FAKE/path"
    assert sorted(query.split("&")) == [
        "date_from=2031-01-02",
        "date_to=2031-03-04",
        "page=3",
        "provider=id%3AFAKE",
        "q=FAKE+term",
    ]


@pytest.mark.parametrize("missing", ["starts_at", "duration_minutes", "visit_mode"])
def test_a_booking_time_whose_details_were_deleted_cannot_be_described(missing):
    stored = SimpleNamespace(
        starts_at=NOON, duration_minutes=30, visit_mode="phone", location_code=None
    )
    setattr(stored, missing, None)
    with pytest.raises(ValueError, match="the time is no longer stored"):
        _booking_slot_text(stored, text={}, booking_locations={}, timezone_name="UTC", locale="en")
