"""Month and weekday names in each portal language: in a date, and in the date-of-birth list."""

from datetime import UTC, datetime

import pytest

from carlos_patient_portal.i18n import format_booking_time, portal_text

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
