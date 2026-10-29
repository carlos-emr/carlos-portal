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

"""The translation catalogs and the plumbing around them.

Catalog parity runs for every locale: a translated string must keep English's placeholders, or
`.format()` raises in front of a patient. Completeness (every key translated) runs only for the
locales in `COMPLETE_LOCALES`: until a translator fills a catalog the locale falls back to
English per key, and the translation PR that completes a locale adds it to that list.
"""

import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from string import Formatter
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from starlette.responses import Response

from carlos_patient_portal import i18n, main, web_support
from carlos_patient_portal.auth import MfaChallengeDelivery, PasswordHashUnusableError
from carlos_patient_portal.i18n import (
    DATETIME_FORMATS,
    LOCALE_COOKIE_NAME,
    PLURAL_CATEGORIES,
    SUPPORTED_LOCALES,
    format_portal_datetime,
    normalize_locale,
    parse_accept_language,
    plural_category,
    plural_text,
    portal_text,
)
from carlos_patient_portal.models import PatientPortalMfaChallenge
from carlos_patient_portal.routes import auth as auth_routes
from tests.support import (
    CSRF_TOKEN_PATTERN,
    DEVELOPMENT_MFA_CODE_PATTERN,
    MFA_CHALLENGE_TOKEN_PATTERN,
    STRONG_PASSWORD,
    STRONG_RESET_PASSWORD,
    RecordingPortalEmailSender,
    activate_seeded_patient_account,
    browser_sign_in_seeded_patient,
    development_settings,
    get_csrf_token,
    migrated_development_app,
    production_settings,
)

# Locales whose catalogs must define every key. English is the source. A translation PR that
# finishes a language adds it here, which turns on the completeness check for that language.
COMPLETE_LOCALES = ("en",)

PACKAGE_DIR = Path(web_support.PACKAGE_DIR)
SUPPORTED_CODES = tuple(locale.code for locale in SUPPORTED_LOCALES)
ENGLISH = {**i18n.TEXT_CATALOG["en"]}
PLURAL_SUFFIXES = ("_zero", "_one", "_two", "_few", "_many", "_other")


def _catalogs(code: str) -> tuple[dict[str, str], dict[str, str]]:
    module = i18n._LOCALE_MODULES[code]
    return module.TEXT, module.MYCARLOS_TEXT


def _own_strings(code: str) -> dict[str, str]:
    """The strings a locale's file defines itself, without the English fallback."""
    text, mycarlos_text = _catalogs(code)
    return {**text, **mycarlos_text}


def _plural_base(key: str) -> str | None:
    for suffix in PLURAL_SUFFIXES:
        if key.endswith(suffix) and f"{key.removesuffix(suffix)}_other" in ENGLISH:
            return key.removesuffix(suffix)
    return None


ENGLISH_PLURAL_BASES = {base for key in ENGLISH if (base := _plural_base(key)) is not None}


def _english_counterpart(key: str) -> str | None:
    """The English key a translated key must match: itself, or the plural's `_other` form."""
    if key in ENGLISH:
        return key
    base = _plural_base(key)
    return f"{base}_other" if base is not None else None


def _placeholders(value: str) -> set[str]:
    return {field for _, field, _, _ in Formatter().parse(value) if field is not None}


def _escaped(value: str) -> str:
    """`value` as the templates write it into the page (Jinja autoescape)."""
    return str(escape(value))


# --------------------------------------------------------------------------------------------
# Catalog parity
# --------------------------------------------------------------------------------------------


def test_every_supported_locale_has_a_catalog_file_and_date_and_plural_rules() -> None:
    assert set(i18n._LOCALE_MODULES) == set(SUPPORTED_CODES)
    assert set(DATETIME_FORMATS) == set(SUPPORTED_CODES)
    assert set(PLURAL_CATEGORIES) == set(SUPPORTED_CODES)


@pytest.mark.parametrize("code", SUPPORTED_CODES)
def test_portal_and_mycarlos_catalogs_do_not_share_keys(code: str) -> None:
    """The two catalogs are merged into one; a shared key would silently shadow the other."""
    text, mycarlos_text = _catalogs(code)
    assert not set(text) & set(mycarlos_text)


@pytest.mark.parametrize("code", SUPPORTED_CODES)
def test_every_translated_key_is_an_english_key(code: str) -> None:
    """A key English lacks is a typo or a leftover: no page ever reads it."""
    strays = sorted(key for key in _own_strings(code) if _english_counterpart(key) is None)
    assert not strays, f"{code} defines keys English does not: {strays}"


@pytest.mark.parametrize("code", SUPPORTED_CODES)
def test_translated_strings_keep_the_english_placeholders(code: str) -> None:
    """A dropped or renamed `{placeholder}` raises KeyError, or loses a value, at render time."""
    mismatched = {}
    for key, value in _own_strings(code).items():
        english_key = _english_counterpart(key)
        if english_key is None:
            continue
        expected = _placeholders(ENGLISH[english_key])
        if _placeholders(value) != expected:
            mismatched[key] = (sorted(_placeholders(value)), sorted(expected))
    assert not mismatched, f"{code} placeholders differ from English: {mismatched}"


@pytest.mark.parametrize("code", SUPPORTED_CODES)
def test_no_translated_string_is_blank(code: str) -> None:
    blank = sorted(key for key, value in _own_strings(code).items() if not value.strip())
    assert not blank, f"{code} has blank strings: {blank}"


@pytest.mark.parametrize("code", SUPPORTED_CODES)
def test_plural_keys_use_only_their_locales_plural_forms(code: str) -> None:
    """Polish writes `_one/_few/_many`, Chinese only `_other`; another form is never read."""
    allowed = set(PLURAL_CATEGORIES[code]) | {"other"}
    wrong = sorted(
        key
        for key in _own_strings(code)
        if (base := _plural_base(key)) is not None and key.removeprefix(f"{base}_") not in allowed
    )
    assert not wrong, f"{code} defines plural forms it never uses: {wrong}"


@pytest.mark.parametrize("code", COMPLETE_LOCALES)
def test_complete_locales_define_every_key_and_plural_form(code: str) -> None:
    own = _own_strings(code)
    missing = [key for key in ENGLISH if _plural_base(key) is None and key not in own]
    for base in sorted(ENGLISH_PLURAL_BASES):
        missing.extend(
            f"{base}_{category}"
            for category in PLURAL_CATEGORIES[code]
            if f"{base}_{category}" not in own
        )
    assert not missing, f"{code} is listed as complete but lacks: {sorted(missing)}"


def test_english_plural_keys_have_both_english_forms() -> None:
    for base in ENGLISH_PLURAL_BASES:
        assert f"{base}_one" in ENGLISH
        assert f"{base}_other" in ENGLISH
        # The plural forms ARE the key: a bare `<base>` would be a second, unpluralized copy.
        assert base not in ENGLISH


def test_every_literal_key_a_template_or_route_reads_exists_in_english() -> None:
    """A retired or misspelled key renders blank (templates) or raises KeyError (routes).

    Literal keys only: a key built at run time (an f-string, or one chosen by a conditional) is
    not seen here, and is covered by the page tests that render it instead.
    """
    used: set[str] = set()
    for template in (PACKAGE_DIR / "templates").glob("*.jinja"):
        used |= set(re.findall(r"\btext\.([A-Za-z_][A-Za-z0-9_]*)", template.read_text()))
    for source_file in PACKAGE_DIR.rglob("*.py"):
        if "locales" in source_file.parts:
            continue
        source = source_file.read_text()
        used |= set(re.findall(r'\btext\)?\["([a-z0-9_]+)"\]', source))
        used |= set(
            re.findall(r'(?:localized_auth_text|portal_text)\([^()]*\)\["([a-z0-9_]+)"\]', source)
        )
        used |= set(
            re.findall(r'\b(?:heading_key|message_key|error_key)=\s*"([a-z0-9_]+)"', source)
        )
        used |= set(re.findall(r'"label_key":\s*"([a-z0-9_]+)"', source))
        # A plural_text() base needs at least its `_other` form.
        plural_bases = re.findall(
            r'plural_text\(\s*[^,()]+(?:\([^()]*\))?,\s*"([a-z0-9_]+)"', source
        )
        used |= {f"{base}_other" for base in plural_bases}

    assert used, "the key scan found nothing; the patterns above have drifted"
    missing = sorted(used - set(ENGLISH))
    assert not missing, f"keys read but not in the English catalog: {missing}"


def test_service_name_follows_the_language_only_when_it_is_the_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(i18n.TEXT_CATALOG["fr"], "service_name_default", "Portail patient (test)")

    default_name = TestClient(main.create_app(development_settings()))
    default_name.cookies.set(LOCALE_COOKIE_NAME, "fr")
    configured_name = TestClient(
        main.create_app(development_settings(service_name="Northside Patient Portal"))
    )
    configured_name.cookies.set(LOCALE_COOKIE_NAME, "fr")

    assert "<strong>Portail patient (test)</strong>" in default_name.get("/").text
    configured_page = configured_name.get("/").text
    assert "<strong>Northside Patient Portal</strong>" in configured_page
    assert "Portail patient (test)" not in configured_page


# --------------------------------------------------------------------------------------------
# Choosing the locale
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        ("zh", "zh-CN"),
        ("zh-CN", "zh-CN"),
        ("zh_cn", "zh-CN"),
        ("zh-Hans", "zh-CN"),
        ("zh-Hans-CN", "zh-CN"),
        ("zh-SG", "zh-CN"),
        ("zh-MY", "zh-CN"),
        # An explicit script beats the region.
        ("zh-Hans-HK", "zh-CN"),
        ("zh-TW", "zh-TW"),
        ("ZH-tw", "zh-TW"),
        ("zh-HK", "zh-TW"),
        ("zh-MO", "zh-TW"),
        ("zh-Hant", "zh-TW"),
        ("zh-Hant-TW", "zh-TW"),
        ("zh-Hant-HK", "zh-TW"),
        ("zh-Hant-SG", "zh-TW"),
        # Mandarin and Cantonese tags, legacy Windows script tags, and private use.
        ("cmn", "zh-CN"),
        ("cmn-Hant-TW", "zh-TW"),
        ("yue", "zh-TW"),
        ("zh-yue", "zh-TW"),
        ("yue-Hant-HK", "zh-TW"),
        ("yue-Hans-CN", "zh-CN"),
        ("zh-CHT", "zh-TW"),
        ("zh-CHS", "zh-CN"),
        ("zh-CN-x-hant", "zh-CN"),
        # Extension subtags are not a script or a region either.
        ("zh-CN-u-sd-hk", "zh-CN"),
        ("zh-CN-t-zh-hk", "zh-CN"),
        ("zh-TW-u-nu-hanidec", "zh-TW"),
    ],
)
def test_chinese_tags_resolve_by_script_then_region(requested: str, expected: str) -> None:
    assert normalize_locale(requested) == expected


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("zh-TW,zh;q=0.9,en;q=0.8", "zh-TW"),
        ("zh-HK,en;q=0.5", "zh-TW"),
        ("en;q=0.5, zh-Hans;q=0.9", "zh-CN"),
        ("zh", "zh-CN"),
        ("ja,zh-Hant-TW;q=0.8", "zh-TW"),
    ],
)
def test_accept_language_picks_the_chinese_script(header: str, expected: str) -> None:
    assert parse_accept_language(header) == expected


def test_chinese_locales_are_named_in_their_own_script() -> None:
    options = {locale.code: locale for locale in SUPPORTED_LOCALES}
    assert (options["zh-CN"].short_label, options["zh-CN"].label) == ("简体", "简体中文")
    assert (options["zh-TW"].short_label, options["zh-TW"].label) == ("繁體", "繁體中文")


def test_language_links_mark_each_language_with_its_own_lang() -> None:
    page = TestClient(main.create_app(development_settings())).get("/").text

    for locale in SUPPORTED_LOCALES:
        if locale.code == "en":
            continue
        assert f'href="/locale/{locale.code}?next=/"' in page
        assert f'lang="{locale.code}"' in page
        assert f">{locale.short_label}</a>" in page


def test_selecting_chinese_sets_the_cookie_and_the_page_language() -> None:
    client = TestClient(main.create_app(development_settings()))

    response = client.get("/locale/zh-TW?next=/")

    assert response.status_code == 200
    assert client.cookies.get(LOCALE_COOKIE_NAME) == "zh-TW"
    assert '<html lang="zh-TW">' in response.text


# --------------------------------------------------------------------------------------------
# Plurals
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("locale", "count", "expected"),
    [
        ("en", 0, "other"),
        ("en", 1, "one"),
        ("en", 2, "other"),
        ("es", 0, "other"),
        ("es", 1, "one"),
        ("fr", 0, "one"),
        ("fr", 1, "one"),
        ("fr", 2, "other"),
        ("pt-BR", 0, "one"),
        ("pt-BR", 1, "one"),
        ("pt-BR", 2, "other"),
        ("pl", 0, "many"),
        ("pl", 1, "one"),
        ("pl", 2, "few"),
        ("pl", 4, "few"),
        ("pl", 5, "many"),
        ("pl", 12, "many"),
        ("pl", 14, "many"),
        ("pl", 21, "many"),
        ("pl", 22, "few"),
        ("pl", 112, "many"),
        ("pl", 124, "few"),
        ("zh-CN", 1, "other"),
        ("zh-TW", 2, "other"),
    ],
)
def test_plural_category_follows_cldr(locale: str, count: int, expected: str) -> None:
    assert plural_category(locale, count) == expected


@pytest.mark.parametrize("code", SUPPORTED_CODES)
def test_plural_category_only_returns_the_locales_own_forms(code: str) -> None:
    assert {plural_category(code, count) for count in range(0, 250)} == set(PLURAL_CATEGORIES[code])


def test_plural_text_picks_the_form_and_falls_back_to_other() -> None:
    english = portal_text("en")
    assert plural_text(english, "booking_slot_duration", 1, "en").format(minutes=1) == ("1 minute")
    assert plural_text(english, "booking_slot_duration", 30, "en").format(minutes=30) == (
        "30 minutes"
    )
    assert plural_text(english, "mfa_rate_limited", 1, "en").format(seconds=1).endswith("1 second.")
    # Polish "few" not translated yet: the English plural renders instead of a KeyError.
    polish = {**english, "booking_slot_duration_one": "{minutes} minuta"}
    assert plural_text(polish, "booking_slot_duration", 3, "pl").format(minutes=3) == ("3 minutes")
    assert plural_text(polish, "booking_slot_duration", 1, "pl").format(minutes=1) == ("1 minuta")
    # The `_other` fallback is only read when the form itself is missing.
    assert plural_text({"count_one": "one"}, "count", 1, "en") == "one"


# --------------------------------------------------------------------------------------------
# Dates
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("locale", "expected"),
    [
        ("en", "2026-01-15 00:30 EST"),
        # No-break spaces around "h", so the time never wraps.
        ("fr", "2026-01-15 00\u00a0h\u00a030 (America/Toronto)"),
        ("es", "15/01/2026 00:30 (America/Toronto)"),
        ("pl", "15.01.2026 00:30 (America/Toronto)"),
        ("pt-BR", "15/01/2026 00:30 (America/Toronto)"),
        ("zh-CN", "2026年1月15日 00:30（America/Toronto）"),
        ("zh-TW", "2026年1月15日 00:30（America/Toronto）"),
        # An unknown locale gets English rather than an error.
        ("xx", "2026-01-15 00:30 EST"),
    ],
)
def test_portal_datetime_uses_each_locales_date_format(locale: str, expected: str) -> None:
    value = datetime(2026, 1, 15, 5, 30, tzinfo=UTC)
    assert format_portal_datetime(value, locale, "America/Toronto") == expected


# --------------------------------------------------------------------------------------------
# The language switcher on the MFA page
# --------------------------------------------------------------------------------------------


def _start_browser_sign_in(app: main.FastAPI, client: TestClient) -> tuple[str, str, str]:
    """Sign in up to the MFA page; return its CSRF token, challenge token, and development code."""
    activate_seeded_patient_account(app, client)
    login_response = client.post(
        "/auth/login",
        data={
            "csrf_token": get_csrf_token(client),
            "username": "patient.user",
            "password": STRONG_PASSWORD,
        },
    )
    assert login_response.status_code == 200
    csrf_match = CSRF_TOKEN_PATTERN.search(login_response.text)
    challenge_match = MFA_CHALLENGE_TOKEN_PATTERN.search(login_response.text)
    code_match = DEVELOPMENT_MFA_CODE_PATTERN.search(login_response.text)
    assert csrf_match is not None
    assert challenge_match is not None
    assert code_match is not None
    return csrf_match.group(1), challenge_match.group(1), code_match.group(1)


def _challenge_row_values(app: main.FastAPI) -> dict[str, object]:
    with app.state.session_factory() as session:
        challenge = session.scalar(select(PatientPortalMfaChallenge))
        assert challenge is not None
        return {
            column.name: getattr(challenge, column.name)
            for column in PatientPortalMfaChallenge.__table__.columns
        }


def test_mfa_page_posts_its_language_buttons_with_the_challenge() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    page = client.post(
        "/auth/login",
        data={
            "csrf_token": get_csrf_token(client),
            "username": "patient.user",
            "password": STRONG_PASSWORD,
        },
    ).text
    challenge_match = MFA_CHALLENGE_TOKEN_PATTERN.search(page)
    assert challenge_match is not None
    switcher = page[page.index('class="language-switch"') : page.index("</nav>")]

    assert 'action="/auth/mfa/language"' in switcher
    assert f'name="mfa_challenge_token" value="{challenge_match.group(1)}"' in switcher
    assert 'aria-current="true" lang="en"' in switcher
    offered = re.findall(r'name="locale"\s+value="([^"]+)"', switcher)
    assert offered == [locale.code for locale in SUPPORTED_LOCALES if locale.code != "en"]
    # No GET link here: following one would drop the sign-in.
    assert "/locale/" not in switcher


def test_mfa_language_switch_rerenders_the_same_sign_in_without_sending_a_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # French does not translate this key yet; a marker proves the page really is in French.
    monkeypatch.setitem(i18n.TEXT_CATALOG["fr"], "mfa_heading", "Code de vérification (test)")
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(email_sender=sender)
    client = TestClient(app)
    csrf_token, challenge_token, code = _start_browser_sign_in(app, client)
    messages_before = len(sender.messages)
    challenge_before = _challenge_row_values(app)

    response = client.post(
        "/auth/mfa/language",
        data={
            "csrf_token": csrf_token,
            "mfa_challenge_token": challenge_token,
            "locale": "fr",
        },
    )

    assert response.status_code == 200
    assert '<html lang="fr">' in response.text
    assert 'class="text-tab selected" aria-current="true" lang="fr"' in response.text
    assert _escaped("Code de vérification (test)") in response.text
    # The same challenge, in every form on the page: the language form, verify and resend.
    assert set(MFA_CHALLENGE_TOKEN_PATTERN.findall(response.text)) == {challenge_token}
    assert len(MFA_CHALLENGE_TOKEN_PATTERN.findall(response.text)) == 3
    assert response.cookies.get(LOCALE_COOKIE_NAME) == "fr"
    assert len(sender.messages) == messages_before
    assert _challenge_row_values(app) == challenge_before

    # And the sign-in carries on with the code from before the switch.
    new_csrf_match = CSRF_TOKEN_PATTERN.search(response.text)
    assert new_csrf_match is not None
    verify_response = client.post(
        "/auth/mfa/verify",
        data={
            "csrf_token": new_csrf_match.group(1),
            "mfa_challenge_token": challenge_token,
            "code": code,
        },
        follow_redirects=False,
    )
    assert verify_response.status_code == 303
    assert verify_response.headers["location"] == "/portal"


def test_mfa_language_switch_requires_the_csrf_token() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    _, challenge_token, _ = _start_browser_sign_in(app, client)

    response = client.post(
        "/auth/mfa/language",
        data={"mfa_challenge_token": challenge_token, "locale": "fr"},
    )

    assert response.status_code == 403
    assert LOCALE_COOKIE_NAME not in response.cookies
    assert challenge_token not in response.text


def test_mfa_language_switch_rejects_an_unsupported_language() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    csrf_token, challenge_token, _ = _start_browser_sign_in(app, client)

    response = client.post(
        "/auth/mfa/language",
        data={"csrf_token": csrf_token, "mfa_challenge_token": challenge_token, "locale": "xx"},
    )

    assert response.status_code == 404
    assert LOCALE_COOKIE_NAME not in response.cookies


@pytest.mark.parametrize("challenge_state", ["unknown", "expired"])
def test_mfa_language_switch_without_a_live_challenge_returns_to_sign_in(
    challenge_state: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(i18n.TEXT_CATALOG["fr"], "mfa_sign_in_again", "Reconnectez-vous (test).")
    app = migrated_development_app()
    client = TestClient(app)
    csrf_token, challenge_token, _ = _start_browser_sign_in(app, client)
    if challenge_state == "unknown":
        challenge_token = "not-a-challenge-token"
    else:
        with app.state.session_factory() as session:
            challenge = session.scalar(select(PatientPortalMfaChallenge))
            assert challenge is not None
            challenge.created_at = datetime.now(UTC) - timedelta(hours=1)
            challenge.expires_at = datetime.now(UTC) - timedelta(minutes=1)
            session.commit()

    response = client.post(
        "/auth/mfa/language",
        data={"csrf_token": csrf_token, "mfa_challenge_token": challenge_token, "locale": "fr"},
    )

    assert response.status_code == 400
    assert '<html lang="fr">' in response.text
    assert 'name="username"' in response.text
    assert "Reconnectez-vous (test)." in response.text
    assert "mfa_challenge_token" not in response.text
    assert response.cookies.get(LOCALE_COOKIE_NAME) == "fr"


@pytest.mark.parametrize(
    ("method", "destination", "expected"),
    [
        ("email", "jane.patient@example.com", "Code sent to ja***@example.com by email."),
        ("email", "not-an-address", "Code sent to your email address."),
        ("sms", "+1 416 555 0123", "Code sent to ***-***-0123 by SMS."),
        ("sms", "12", "Code sent to your mobile number."),
    ],
)
def test_mfa_code_sent_message_is_one_sentence_per_method(
    method: str, destination: str, expected: str
) -> None:
    """The method is part of the translated sentence, never a code spliced into one."""
    delivery = MfaChallengeDelivery(
        challenge_id=1,
        challenge_token="placeholder",
        code="",
        delivery_method=method,
        destination=destination,
        available_delivery_methods=(method,),
        expires_at=datetime(2026, 1, 1, tzinfo=UTC),
        expected_code_hash="placeholder",
    )

    assert web_support.mfa_code_sent_message(delivery, portal_text("en")) == expected


def test_browser_resend_without_a_drawable_challenge_gets_the_sign_in_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = migrated_development_app()
    client = TestClient(app)
    csrf_token, challenge_token, _ = _start_browser_sign_in(app, client)
    # The challenge cannot be redrawn (say its account lost the delivery method meanwhile).
    monkeypatch.setattr(auth_routes, "get_mfa_challenge_delivery_state", lambda *_, **__: None)

    response = client.post(
        "/auth/mfa/resend",
        data={
            "csrf_token": csrf_token,
            "mfa_challenge_token": challenge_token,
            "mfa_delivery_method": "email",
        },
    )

    assert response.status_code == 429
    assert response.headers["content-type"].startswith("text/html")
    assert "Retry-After" in response.headers
    assert 'name="username"' in response.text
    assert "A code was sent recently." in response.text


# --------------------------------------------------------------------------------------------
# The language switcher on signed-in pages and pages answering a POST
# --------------------------------------------------------------------------------------------


def test_signed_in_pages_have_the_language_switcher() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)

    page = client.get("/portal/account").text

    assert 'class="language-switch"' in page
    assert 'href="/locale/fr?next=/portal/account"' in page
    assert 'href="/locale/zh-CN?next=/portal/account"' in page


def test_a_page_answering_a_post_switches_language_back_to_its_get_page() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    csrf_match = CSRF_TOKEN_PATTERN.search(client.get("/portal/account").text)
    assert csrf_match is not None

    failed_change = client.post(
        "/portal/account/password",
        data={
            "csrf_token": csrf_match.group(1),
            "current_password": "Wrong1!password",
            "new_password": STRONG_RESET_PASSWORD,
            "new_password_confirmation": STRONG_RESET_PASSWORD,
        },
    )

    # A wrong current password fails the step-up check: the account page again, with an error.
    assert failed_change.status_code == 403
    assert 'href="/locale/fr?next=/portal/account"' in failed_change.text
    assert "next=/portal/account/password" not in failed_change.text


def test_a_failed_sign_in_switches_language_to_the_sign_in_page() -> None:
    app = migrated_development_app()
    client = TestClient(app)

    response = client.post(
        "/auth/login",
        data={
            "csrf_token": get_csrf_token(client),
            "username": "nobody",
            "password": "Wrong1!password",
        },
    )

    assert response.status_code == 401
    assert 'href="/locale/fr?next=/"' in response.text
    assert "next=/auth/login" not in response.text


def test_a_post_whose_path_also_serves_get_keeps_its_path() -> None:
    """POST /auth/activate re-renders a page GET /auth/activate also serves."""
    client = TestClient(migrated_development_app())

    response = client.post("/auth/activate", data={"invite_code": "x"})

    assert response.status_code == 403
    assert response.headers["content-type"].startswith("text/html")
    assert 'href="/locale/fr?next=/auth/activate"' in response.text
    assert "Retry-After" not in response.headers


def test_a_page_at_a_path_without_a_get_page_links_to_the_front_page() -> None:
    """A 405 (GET /auth/login, e.g. reloading a failed sign-in) or 404 page must not loop."""
    client = TestClient(migrated_development_app())

    method_not_allowed = client.get("/auth/login")
    not_found = client.get("/no-such-page")

    assert method_not_allowed.status_code == 405
    assert method_not_allowed.headers["allow"] == "POST"
    assert 'href="/locale/fr?next=/"' in method_not_allowed.text
    assert "next=/auth/login" not in method_not_allowed.text
    assert not_found.status_code == 404
    assert 'href="/locale/fr?next=/"' in not_found.text
    # Under the static mount too, where the rest of the path looks like another route's.
    static_not_found = client.get("/static/health")
    assert static_not_found.status_code == 404
    assert 'href="/locale/fr?next=/"' in static_not_found.text


@pytest.mark.parametrize("path", ["/auth/password-reset/complete", "/auth/email-change/confirm"])
def test_a_page_answering_an_emailed_link_form_does_not_link_back_to_that_form(
    path: str,
) -> None:
    """These GET pages only work with the emailed token, so a page answering them goes home."""
    client = TestClient(migrated_development_app())

    response = client.post(path, data={"new_password": "x"})

    # Refused for its missing CSRF token: the page answering the form, not the form itself.
    assert response.status_code == 403
    assert response.headers["content-type"].startswith("text/html")
    assert 'href="/locale/fr?next=/"' in response.text
    assert f"next={path}" not in response.text


def test_the_emailed_link_page_itself_links_back_to_itself() -> None:
    """portal.js adds the token to these links as a fragment, which never reaches the server."""
    page = TestClient(migrated_development_app()).get("/auth/password-reset/complete").text

    assert 'href="/locale/fr?next=/auth/password-reset/complete"' in page


def test_switch_targets_keep_the_deployment_prefix() -> None:
    app = migrated_development_app(public_base_url="https://portal.example.test/patient")
    client = TestClient(app, base_url="https://portal.example.test")

    # Inside the static mount, the mount's own prefix is not part of the front page's path.
    assert 'href="/patient/locale/fr?next=/patient/"' in client.get("/static/no-such-file").text

    assert 'href="/patient/locale/fr?next=/patient/"' in client.get("/auth/login").text
    assert 'href="/patient/locale/fr?next=/patient/auth/activate"' in (
        client.post("/auth/activate", data={"invite_code": "x"}).text
    )


# --------------------------------------------------------------------------------------------
# Error pages for browsers, JSON for API clients
# --------------------------------------------------------------------------------------------


def _app_with_failing_routes() -> main.FastAPI:
    app = migrated_development_app()

    for prefix in ("/test", "/api/test"):

        @app.get(f"{prefix}/validated")
        async def validated(count: int) -> dict[str, int]:
            return {"count": count}

        @app.get(f"{prefix}/crash")
        async def crash() -> None:
            raise RuntimeError("patient.secret@example.test")

        @app.get(f"{prefix}/database-down")
        async def database_down() -> None:
            raise OperationalError("SELECT 1", {}, ConnectionError("down"))

        @app.get(f"{prefix}/hash-unusable")
        async def hash_unusable() -> None:
            raise PasswordHashUnusableError()

    return app


@pytest.mark.parametrize(
    ("path", "status_code", "heading_key", "retry_after"),
    [
        ("/test/validated?count=many", 422, "request_failed_heading", None),
        ("/test/crash", 500, "service_unavailable_heading", None),
        ("/test/database-down", 503, "service_unavailable_heading", "1"),
        ("/test/hash-unusable", 503, "service_unavailable_heading", "1"),
    ],
)
def test_browser_errors_are_pages_in_the_patients_language(
    path: str,
    status_code: int,
    heading_key: str,
    retry_after: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Polish does not translate these yet; a marker proves the page really is in Polish.
    monkeypatch.setitem(i18n.TEXT_CATALOG["pl"], heading_key, "Nagłówek (test)")
    client = TestClient(_app_with_failing_routes(), raise_server_exceptions=False)
    client.cookies.set(LOCALE_COOKIE_NAME, "pl")

    response = client.get(path)

    assert response.status_code == status_code
    assert response.headers["content-type"].startswith("text/html")
    assert '<html lang="pl">' in response.text
    assert "Nagłówek (test)" in response.text
    assert response.headers.get("Retry-After") == retry_after
    assert "patient.secret@example.test" not in response.text
    assert '"detail"' not in response.text


def test_the_500_page_carries_the_security_headers() -> None:
    """The 500 handler runs outside the middleware that adds these to other responses."""
    response = TestClient(_app_with_failing_routes(), raise_server_exceptions=False).get(
        "/test/crash"
    )

    assert response.headers["Content-Security-Policy"] == web_support.CONTENT_SECURITY_POLICY
    for header, value in web_support.SECURITY_HEADERS.items():
        assert response.headers[header] == value
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize(
    ("path", "status_code"),
    [
        ("/api/test/validated?count=many", 422),
        ("/api/test/crash", 500),
        ("/api/test/database-down", 503),
        ("/api/test/hash-unusable", 503),
    ],
)
def test_api_errors_stay_json(path: str, status_code: int) -> None:
    response = TestClient(_app_with_failing_routes(), raise_server_exceptions=False).get(path)

    assert response.status_code == status_code
    assert response.headers["content-type"].startswith("application/json")
    assert "detail" in response.json()


def test_a_caller_that_declared_json_gets_json_on_a_browser_path() -> None:
    response = TestClient(_app_with_failing_routes()).get(
        "/test/validated?count=many",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/json")


@pytest.mark.parametrize(
    "headers",
    [
        {"Authorization": "Bearer not-a-real-session"},
        {"Accept": "application/json"},
    ],
)
def test_bearer_and_json_accepting_callers_get_json_on_a_browser_path(
    headers: dict[str, str],
) -> None:
    """/auth/session and /auth/logout serve bearer clients, which send no JSON body."""
    client = TestClient(_app_with_failing_routes(), raise_server_exceptions=False)

    for path, status_code in (
        ("/test/validated?count=many", 422),
        ("/test/crash", 500),
        ("/test/database-down", 503),
        ("/no-such-page", 404),
    ):
        response = client.get(path, headers=headers)
        assert response.status_code == status_code
        assert response.headers["content-type"].startswith("application/json"), path

    # The same holds for a portal in maintenance and for a throttled caller.
    maintenance = TestClient(main.create_app(development_settings(maintenance_mode=True)))
    throttled = TestClient(main.create_app(development_settings(global_rate_limit_max_requests=1)))
    throttled.get("/auth/session", headers=headers)
    for response, status_code in (
        (maintenance.get("/auth/session", headers=headers), 503),
        (throttled.get("/auth/session", headers=headers), 429),
    ):
        assert response.status_code == status_code
        assert response.headers["content-type"].startswith("application/json")
        assert "Retry-After" in response.headers


def test_a_browser_that_also_accepts_json_still_gets_the_page() -> None:
    response = TestClient(_app_with_failing_routes()).get(
        "/test/validated?count=many",
        headers={"Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"},
    )

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("text/html")


def test_the_500_handler_answers_json_if_its_page_cannot_be_drawn(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def broken_page(*_: object, **__: object) -> None:
        raise RuntimeError("template fault with patient.secret@example.test")

    monkeypatch.setattr(main, "service_notice_response", broken_page)
    caplog.set_level(logging.ERROR, logger="carlos_patient_portal.main")

    response = TestClient(_app_with_failing_routes(), raise_server_exceptions=False).get(
        "/test/crash"
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "the request could not be completed"}
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    messages = [record.getMessage() for record in caplog.records]
    assert "Portal error page could not be rendered: RuntimeError" in messages
    assert not any("patient.secret" in message for message in messages)


@pytest.mark.parametrize("path", ["/test/crash", "/api/test/crash", "/fhir/test-crash"])
def test_every_500_answer_gets_the_shared_response_headers(
    path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 500 handler runs outside the middleware, so it must apply them to page and JSON alike."""
    app = _app_with_failing_routes()

    @app.get("/fhir/test-crash")
    async def fhir_crash() -> None:
        raise RuntimeError("fhir fault")

    headed_paths: list[str] = []
    shared_helper = main.apply_standard_response_headers

    def recording_helper(request: object, response: Response, settings: object) -> None:
        headed_paths.append(request.url.path)  # type: ignore[attr-defined]
        shared_helper(request, response, settings)  # type: ignore[arg-type]

    monkeypatch.setattr(main, "apply_standard_response_headers", recording_helper)

    response = TestClient(app, raise_server_exceptions=False).get(path)

    assert response.status_code == 500
    assert headed_paths == [path]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"


def test_the_shared_response_headers_add_hsts_only_in_production() -> None:
    def headers_for(settings: object) -> dict[str, str]:
        response = Response()
        request = SimpleNamespace(url=SimpleNamespace(path="/portal"))
        main.apply_standard_response_headers(request, response, settings)  # type: ignore[arg-type]
        return dict(response.headers)

    production = headers_for(production_settings())
    development = headers_for(development_settings())

    assert production["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "strict-transport-security" not in development
    assert production["content-security-policy"] == web_support.CONTENT_SECURITY_POLICY
    assert production["cache-control"] == "no-store"
