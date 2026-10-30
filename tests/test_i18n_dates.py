"""Month and weekday names in each portal language: in a date, and in the date-of-birth list."""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from carlos_patient_portal.i18n import format_booking_time, format_portal_datetime, portal_text

# Tuesday 13 October 2026, 10:30 in Toronto.
SLOT = datetime(2026, 10, 13, 14, 30, tzinfo=UTC)


@pytest.mark.parametrize(
    ("locale", "expected"),
    [
        ("en", "Tuesday 13 October"),
        ("fr", "Mardi 13 octobre"),
        ("es", "Martes 13 de octubre"),
        # A Polish date takes the month in the genitive.
        ("pl", "Wtorek, 13 października"),
        ("pt-BR", "Terça-feira, 13 de outubro"),
    ],
)
def test_booking_date_reads_in_one_language(locale: str, expected: str) -> None:
    assert format_booking_time(SLOT, locale, "America/Toronto")[0] == expected


@pytest.mark.parametrize(
    ("locale", "june", "december"),
    [
        ("en", "June", "December"),
        ("fr", "Juin", "Décembre"),
        ("es", "Junio", "Diciembre"),
        # The list takes the plain (nominative) name, not the genitive a date uses.
        ("pl", "Czerwiec", "Grudzień"),
        ("pt-BR", "Junho", "Dezembro"),
    ],
)
def test_date_of_birth_month_list_names_each_month(locale: str, june: str, december: str) -> None:
    text = portal_text(locale)
    assert text["date_of_birth_month_6"] == june
    assert text["date_of_birth_month_12"] == december
    assert all(text[f"date_of_birth_month_{month}"] for month in range(1, 13))


@pytest.mark.parametrize(
    ("instant", "expected_time", "expected_timestamp"),
    [
        # Toronto skips 02:00 through 02:59 when daylight saving time starts.
        (datetime(2026, 3, 8, 6, 59, tzinfo=UTC), "01:59", "2026-03-08 01:59 EST"),
        (datetime(2026, 3, 8, 7, 0, tzinfo=UTC), "03:00", "2026-03-08 03:00 EDT"),
    ],
)
def test_spring_clock_change_uses_the_clinic_wall_time(
    instant: datetime, expected_time: str, expected_timestamp: str
) -> None:
    assert format_booking_time(instant, "en", "America/Toronto") == (
        "Sunday 8 March",
        expected_time,
    )
    assert format_portal_datetime(instant, "en", "America/Toronto") == expected_timestamp


@pytest.mark.parametrize(
    ("instant", "expected_timestamp"),
    [
        (datetime(2026, 11, 1, 5, 30, tzinfo=UTC), "2026-11-01 01:30 EDT"),
        (datetime(2026, 11, 1, 6, 30, tzinfo=UTC), "2026-11-01 01:30 EST"),
    ],
)
def test_repeated_autumn_hour_keeps_the_offset_in_portal_timestamps(
    instant: datetime, expected_timestamp: str
) -> None:
    # Both appointments have the same wall time; the full timestamp distinguishes them.
    assert format_booking_time(instant, "en", "America/Toronto") == (
        "Sunday 1 November",
        "01:30",
    )
    assert format_portal_datetime(instant, "en", "America/Toronto") == expected_timestamp


@pytest.mark.parametrize(
    ("locale", "expected_date"),
    [
        ("en", "Wednesday 31 December"),
        ("fr", "Mercredi 31 décembre"),
        ("es", "Miércoles 31 de diciembre"),
        ("pl", "Środa, 31 grudnia"),
        ("pt-BR", "Quarta-feira, 31 de dezembro"),
    ],
)
def test_booking_date_and_time_cross_the_year_in_the_clinic_timezone(
    locale: str, expected_date: str
) -> None:
    # It is already January in UTC, but still December in the clinic.
    instant = datetime(2026, 1, 1, 0, 15, tzinfo=UTC)
    assert format_booking_time(instant, locale, "America/Toronto") == (expected_date, "19:15")


@pytest.mark.parametrize(
    "instant",
    [
        datetime(2026, 10, 13, 14, 30),
        datetime(2026, 10, 13, 14, 30, tzinfo=UTC),
        datetime(2026, 10, 13, 16, 30, tzinfo=timezone(timedelta(hours=2))),
    ],
)
def test_naive_utc_and_offset_aware_values_render_the_same_instant(instant: datetime) -> None:
    assert format_booking_time(instant, "en", "America/Toronto") == (
        "Tuesday 13 October",
        "10:30",
    )
    assert format_portal_datetime(instant, "en", "America/Toronto") == "2026-10-13 10:30 EDT"
