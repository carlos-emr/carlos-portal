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

"""Locale resolution and the portal's user-facing text.

Translations are not written yet. Rather than advertise four languages that do nothing, the
machinery is real and every locale resolves through `TEXT_CATALOG` with a per-key fallback to
English: selecting French switches the locale, persists it, and renders the English string for any
key French has not defined. The strings live one file per locale in
`carlos_patient_portal/locales/`; adding a translation is then only a matter of adding keys to
`locales/fr.py` — no route, template, or context change is needed, and a partial translation
renders rather than raising KeyError.
"""

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from carlos_patient_portal.locales import en as locale_en
from carlos_patient_portal.locales import es as locale_es
from carlos_patient_portal.locales import fr as locale_fr
from carlos_patient_portal.locales import pl as locale_pl
from carlos_patient_portal.locales import pt_BR as locale_pt_br

DEFAULT_LOCALE = "en"
# Display preference only — it selects strings and a date format, and carries no authorization or
# identity meaning, which is why the switch route can accept a GET without a CSRF token.
LOCALE_COOKIE_NAME = "portal_locale"
LOCALE_COOKIE_MAX_AGE_SECONDS = 365 * 24 * 60 * 60
DEFAULT_DATETIME_FORMAT = "%Y-%m-%d %H:%M %Z"
DATETIME_FORMATS = {
    DEFAULT_LOCALE: DEFAULT_DATETIME_FORMAT,
    # Placeholders alongside the English catalog: ISO-style ordering is unambiguous in every one of
    # these locales, so it is a safe default until a translator sets the real convention.
    "fr": DEFAULT_DATETIME_FORMAT,
    "es": DEFAULT_DATETIME_FORMAT,
    "pl": DEFAULT_DATETIME_FORMAT,
    "pt-BR": DEFAULT_DATETIME_FORMAT,
}


@dataclass(frozen=True)
class LocaleOption:
    code: str
    short_label: str
    label: str


SUPPORTED_LOCALES: tuple[LocaleOption, ...] = (
    LocaleOption(code="en", short_label="EN", label="English"),
    LocaleOption(code="fr", short_label="FR", label="French"),
    LocaleOption(code="es", short_label="ES", label="Spanish"),
    LocaleOption(code="pl", short_label="PL", label="Polish"),
    LocaleOption(code="pt-BR", short_label="PT-BR", label="Portuguese (Brazil)"),
)

# The catalogs live one file per locale in `carlos_patient_portal/locales/`, so a translator works
# in one file and translations of different languages never touch the same lines.
_LOCALE_MODULES = {
    "en": locale_en,
    "fr": locale_fr,
    "es": locale_es,
    "pl": locale_pl,
    "pt-BR": locale_pt_br,
}
TEXT_CATALOG: dict[str, dict[str, str]] = {
    code: dict(module.TEXT) for code, module in _LOCALE_MODULES.items()
}

# Every supported locale gets an entry so `portal_text` never falls back wholesale to English and
# a translator can start filling one in without touching anything else. Nearly empty today: the
# per-key merge in `portal_text` supplies the English string for anything a locale has not defined,
# which is what makes a half-finished translation render instead of raising KeyError.
for _locale in SUPPORTED_LOCALES:
    TEXT_CATALOG.setdefault(_locale.code, {})


def normalize_locale(value: str | None) -> str | None:
    """Match a requested locale to a supported one, case- and separator-insensitively.

    Accepts the shapes a browser actually sends: `PT-br`, `pt_BR`, and a bare `pt` all resolve to
    `pt-BR`. Returns None when nothing matches, so callers can distinguish "not supported" from
    "supported and happens to be the default".
    """
    if not value:
        return None
    candidate = value.strip().replace("_", "-").casefold()
    if not candidate:
        return None
    for locale in SUPPORTED_LOCALES:
        if locale.code.casefold() == candidate:
            return locale.code
    # A bare language subtag matches the first supported locale in that language, so `pt` finds
    # `pt-BR` without the caller having to know the region.
    language = candidate.split("-", 1)[0]
    for locale in SUPPORTED_LOCALES:
        if locale.code.casefold().split("-", 1)[0] == language:
            return locale.code
    return None


def _accept_language_weight(parameters: str) -> float:
    weight = 1.0
    for parameter in parameters.split(";"):
        name, _, raw_value = parameter.partition("=")
        if name.strip().casefold() != "q":
            continue
        try:
            weight = float(raw_value)
        except ValueError:
            weight = 0.0
        if not math.isfinite(weight) or not 0 <= weight <= 1:
            weight = 0.0
    return weight


def parse_accept_language(header_value: str | None) -> str | None:
    """Pick the highest-weighted supported locale from an Accept-Language header.

    Deliberately tolerant: a malformed q-value sorts as 0 rather than raising, because a bad header
    from one browser must not turn a page render into a 500.
    """
    if not header_value:
        return None
    candidates: list[tuple[float, int, str]] = []
    for position, part in enumerate(header_value.split(",")):
        tag, _, parameters = part.strip().partition(";")
        if not tag.strip() or tag.strip() == "*":
            continue
        weight = _accept_language_weight(parameters)
        if weight <= 0:
            continue
        # Position breaks ties in header order, which is the order the browser expressed.
        candidates.append((-weight, position, tag.strip()))
    for _, _, tag in sorted(candidates):
        matched = normalize_locale(tag)
        if matched is not None:
            return matched
    return None


def resolve_locale(
    *,
    cookie_value: str | None = None,
    accept_language: str | None = None,
) -> str:
    """Resolve the locale to render in: explicit choice first, then the browser's, then English."""
    return (
        normalize_locale(cookie_value) or parse_accept_language(accept_language) or DEFAULT_LOCALE
    )


MYCARLOS_TEXT_CATALOG: dict[str, dict[str, str]] = {
    code: dict(module.MYCARLOS_TEXT) for code, module in _LOCALE_MODULES.items()
}

for _mycarlos_locale, _mycarlos_strings in MYCARLOS_TEXT_CATALOG.items():
    TEXT_CATALOG.setdefault(_mycarlos_locale, {}).update(_mycarlos_strings)


def portal_text(locale: str = DEFAULT_LOCALE) -> dict[str, str]:
    """The text catalog for `locale`, with English filling any key it has not translated."""
    text = TEXT_CATALOG[DEFAULT_LOCALE].copy()
    if locale != DEFAULT_LOCALE:
        text.update(TEXT_CATALOG.get(locale, {}))
    return text


def supported_locale_options(current_locale: str = DEFAULT_LOCALE) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "code": locale.code,
            "short_label": locale.short_label,
            "label": locale.label,
            "is_selected": locale.code == current_locale,
        }
        for locale in SUPPORTED_LOCALES
    )


def format_booking_time(
    value: datetime,
    locale: str = DEFAULT_LOCALE,
    timezone_name: str = "UTC",
) -> tuple[str, str]:
    """An appointment time as the patient reads it: ("Tuesday 14 October", "10:30").

    Weekday and month names come from the catalog, not the process locale, so they follow the
    patient's language; the time is shown in the clinic's time zone.
    """
    text = portal_text(locale)
    utc_value = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    local_value = utc_value.astimezone(ZoneInfo(timezone_name))
    date_text = text["booking_slot_date"].format(
        weekday=text[f"booking_weekday_{local_value.weekday()}"],
        day=local_value.day,
        month=text[f"booking_month_{local_value.month}"],
    )
    time_text = text["booking_slot_time"].format(
        hour=local_value.hour,
        minute=local_value.minute,
    )
    return date_text, time_text


def format_portal_datetime(
    value: datetime,
    locale: str = DEFAULT_LOCALE,
    timezone_name: str = "UTC",
) -> str:
    date_format = DATETIME_FORMATS.get(locale, DATETIME_FORMATS[DEFAULT_LOCALE])
    utc_value = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return utc_value.astimezone(ZoneInfo(timezone_name)).strftime(date_format)
