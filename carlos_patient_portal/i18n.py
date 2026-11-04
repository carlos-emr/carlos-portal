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

Every locale resolves through `TEXT_CATALOG` with a per-key fallback to English: selecting a
language switches the locale, persists it, and renders the English string for any key that
language has not translated yet. The strings themselves live one file per locale in
`carlos_patient_portal/locales/`; translating is only a matter of adding keys there, and a partial
translation renders rather than raising KeyError. `tests/test_i18n_catalog.py` keeps every locale's
placeholders in line with English and, once a locale is listed there as complete, every key too.
"""

import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from carlos_patient_portal.locales import en as locale_en
from carlos_patient_portal.locales import es as locale_es
from carlos_patient_portal.locales import fr as locale_fr
from carlos_patient_portal.locales import pl as locale_pl
from carlos_patient_portal.locales import pt_BR as locale_pt_br
from carlos_patient_portal.locales import zh_CN as locale_zh_cn
from carlos_patient_portal.locales import zh_TW as locale_zh_tw

DEFAULT_LOCALE = "en"
# Display preference only — it selects strings and a date format, and carries no authorization or
# identity meaning, which is why the switch route can accept a GET without a CSRF token.
LOCALE_COOKIE_NAME = "portal_locale"
LOCALE_COOKIE_MAX_AGE_SECONDS = 365 * 24 * 60 * 60
# How a date and time reads in each language, in ONE place: changing a language's convention is a
# one-line change here. Fields: {year} {month} {day} {hour} {minute} as numbers, {zone} the clinic's
# time zone written out (e.g. "America/Toronto"), and {zone_abbreviation} ("EST"), which only
# English readers know. English keeps its ISO order and abbreviation; the others use their own
# date order with the zone written out. French is Canadian French (2026-01-15 00 h 30, with
# no-break spaces so the time never wraps), the French a Canadian clinic's patients read.
DATETIME_FORMATS: dict[str, str] = {
    DEFAULT_LOCALE: "{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d} {zone_abbreviation}",
    "fr": "{year:04d}-{month:02d}-{day:02d} {hour:02d}\u00a0h\u00a0{minute:02d} ({zone})",
    "es": "{day:02d}/{month:02d}/{year:04d} {hour:02d}:{minute:02d} ({zone})",
    "pl": "{day:02d}.{month:02d}.{year:04d} {hour:02d}:{minute:02d} ({zone})",
    "pt-BR": "{day:02d}/{month:02d}/{year:04d} {hour:02d}:{minute:02d} ({zone})",
    "zh-CN": "{year}年{month}月{day}日 {hour:02d}:{minute:02d}（{zone}）",
    "zh-TW": "{year}年{month}月{day}日 {hour:02d}:{minute:02d}（{zone}）",
}


@dataclass(frozen=True)
class LocaleOption:
    code: str
    short_label: str
    label: str


# Each language is named in its own language: the switcher marks every link with that language's
# `lang`, so a screen reader reads "Français" in French, and a patient looking for their language
# recognizes it. The Chinese short labels are the script names (简体 Simplified, 繁體 Traditional),
# which is how a Chinese reader tells the two apart.
SUPPORTED_LOCALES: tuple[LocaleOption, ...] = (
    LocaleOption(code="en", short_label="EN", label="English"),
    LocaleOption(code="fr", short_label="FR", label="Français"),
    LocaleOption(code="es", short_label="ES", label="Español"),
    LocaleOption(code="pl", short_label="PL", label="Polski"),
    LocaleOption(code="pt-BR", short_label="PT-BR", label="Português (Brasil)"),
    LocaleOption(code="zh-CN", short_label="简体", label="简体中文"),
    LocaleOption(code="zh-TW", short_label="繁體", label="繁體中文"),
)

# The catalogs live one file per locale in `carlos_patient_portal/locales/`, so a translator works
# in one file and translations of different languages never touch the same lines.
_LOCALE_MODULES = {
    "en": locale_en,
    "fr": locale_fr,
    "es": locale_es,
    "pl": locale_pl,
    "pt-BR": locale_pt_br,
    "zh-CN": locale_zh_cn,
    "zh-TW": locale_zh_tw,
}
TEXT_CATALOG: dict[str, dict[str, str]] = {
    code: dict(module.TEXT) for code, module in _LOCALE_MODULES.items()
}

# Every supported locale gets an entry so `portal_text` never falls back wholesale to English: the
# per-key merge in `portal_text` supplies the English string for anything a locale has not defined,
# which is what makes a half-finished translation render instead of raising KeyError.
for _locale in SUPPORTED_LOCALES:
    TEXT_CATALOG.setdefault(_locale.code, {})


# Chinese is chosen by script, not by the first locale in the language: Traditional for a Hant
# script or a region that writes Traditional characters, Simplified for a Hans script or a region
# that writes Simplified. `zh` and Mandarin (`cmn`) default to Simplified, Cantonese (`yue`, also
# written `zh-yue`) to Traditional, as Hong Kong writes it. `chs`/`cht` are the legacy Windows
# script tags.
_CHINESE_LANGUAGE_DEFAULTS = {"zh": "zh-CN", "cmn": "zh-CN", "yue": "zh-TW"}
_CHINESE_SCRIPT_SUBTAGS = {"hans": "zh-CN", "chs": "zh-CN", "hant": "zh-TW", "cht": "zh-TW"}
_SIMPLIFIED_CHINESE_REGIONS = frozenset({"cn", "sg", "my"})
_TRADITIONAL_CHINESE_REGIONS = frozenset({"tw", "hk", "mo"})


def _chinese_locale(language: str, subtags: list[str]) -> str:
    """zh-TW or zh-CN for a Chinese `language` and the subtags after it (already casefolded).

    An explicit script wins over the region, so `zh-Hans-HK` is Simplified and `zh-Hant-SG`
    Traditional; without one, the region decides, and without that the language's default.
    Extension and private-use subtags (after a one-letter subtag such as `u`, `t` or `x`) are not
    read: `zh-CN-x-hant` and `zh-CN-u-sd-hk` are Simplified.
    """
    for position, subtag in enumerate(subtags):
        if len(subtag) == 1:
            subtags = subtags[:position]
            break
    if subtags and subtags[0] == "yue":
        language, subtags = "yue", subtags[1:]
    for subtag in subtags:
        if subtag in _CHINESE_SCRIPT_SUBTAGS:
            return _CHINESE_SCRIPT_SUBTAGS[subtag]
    if _TRADITIONAL_CHINESE_REGIONS.intersection(subtags):
        return "zh-TW"
    if _SIMPLIFIED_CHINESE_REGIONS.intersection(subtags):
        return "zh-CN"
    return _CHINESE_LANGUAGE_DEFAULTS[language]


def normalize_locale(value: str | None) -> str | None:
    """Match a requested locale to a supported one, case- and separator-insensitively.

    Accepts the shapes a browser actually sends: `PT-br`, `pt_BR`, and a bare `pt` all resolve to
    `pt-BR`; Chinese tags resolve by script and region (`zh-Hant-TW`, `zh-HK` → zh-TW;
    `zh-Hans-CN`, `zh-SG`, `zh` → zh-CN). Returns None when nothing matches, so callers can
    distinguish "not supported" from "supported and happens to be the default".
    """
    if not value:
        return None
    candidate = value.strip().replace("_", "-").casefold()
    if not candidate:
        return None
    for locale in SUPPORTED_LOCALES:
        if locale.code.casefold() == candidate:
            return locale.code
    subtags = candidate.split("-")
    if subtags[0] in _CHINESE_LANGUAGE_DEFAULTS:
        return _chinese_locale(subtags[0], subtags[1:])
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
    """A date and time in the clinic's time zone, written the way `locale` writes them.

    The pattern comes from `DATETIME_FORMATS`, not the process locale (which is the server's, not
    the patient's): numbers only, so no month name ever depends on the server's language.
    """
    date_format = DATETIME_FORMATS.get(locale, DATETIME_FORMATS[DEFAULT_LOCALE])
    utc_value = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    local_value = utc_value.astimezone(ZoneInfo(timezone_name))
    return date_format.format(
        year=local_value.year,
        month=local_value.month,
        day=local_value.day,
        hour=local_value.hour,
        minute=local_value.minute,
        zone=timezone_name,
        zone_abbreviation=local_value.tzname() or timezone_name,
    )


# The plural forms each language writes for a whole number (Unicode CLDR plural rules). English
# and Spanish use the singular for 1 only; French and Brazilian Portuguese also for 0 ("0 minute");
# Polish has three forms ("1 minuta, 2 minuty, 5 minut"); Chinese has one.
PLURAL_CATEGORIES: dict[str, tuple[str, ...]] = {
    "en": ("one", "other"),
    "fr": ("one", "other"),
    "es": ("one", "other"),
    "pl": ("one", "few", "many"),
    "pt-BR": ("one", "other"),
    "zh-CN": ("other",),
    "zh-TW": ("other",),
}


def plural_category(locale: str, count: int) -> str:
    """The CLDR plural category of the whole number `count` in `locale`."""
    n = abs(count)
    language = locale.split("-", 1)[0]
    if language == "zh":
        return "other"
    if language == "pl":
        if n == 1:
            return "one"
        if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
            return "few"
        return "many"
    if language in ("fr", "pt"):
        return "one" if n in (0, 1) else "other"
    return "one" if n == 1 else "other"


def plural_text(text: Mapping[str, str], key: str, count: int, locale: str) -> str:
    """The `key` text for `count`: `<key>_<category>`, else `<key>_other`.

    A counted message is one catalog key per plural form, never a word glued to a number. The
    `_other` fallback is what keeps a half-translated locale rendering: a Polish "few" form not
    written yet shows the English plural instead of raising KeyError.
    """
    form_key = f"{key}_{plural_category(locale, count)}"
    return text[form_key] if form_key in text else text[f"{key}_other"]
