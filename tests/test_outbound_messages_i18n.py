# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Outbound email and SMS texts: every locale renders, says "sign-in code", and has no leftovers."""

import re

import pytest

from carlos_patient_portal import outbound_messages as om
from carlos_patient_portal.i18n import SUPPORTED_LOCALES, portal_text

LOCALES = tuple(option.code for option in SUPPORTED_LOCALES)
KWARGS = {"service_name": "SVC-NAME", "clinic_name": "CLINIC-NAME"}


def every_message(locale: str, expires: int = 600) -> dict[str, om.OutboundMessage | str]:
    return {
        "mfa_email": om.mfa_email_message(
            code="123456", expires_in_seconds=expires, locale=locale, **KWARGS
        ),
        "reset": om.password_reset_email_message(
            reset_url="https://example.test/reset?t=TOKEN", expires_in_seconds=expires,
            locale=locale, **KWARGS,
        ),
        "contact_change": om.contact_change_email_message(locale=locale, **KWARGS),
        "booking": om.booking_prompt_email_message(
            sign_in_url="https://example.test/in", locale=locale, **KWARGS
        ),
        "booking_update": om.booking_prompt_update_email_message(
            sign_in_url="https://example.test/in", locale=locale, **KWARGS
        ),
        "email_confirm": om.email_change_confirmation_email_message(
            confirmation_url="https://example.test/confirm?t=TOKEN",
            expires_in_seconds=expires * 6, locale=locale, **KWARGS,
        ),
        "email_requested": om.email_change_requested_email_message(locale=locale, **KWARGS),
        "sms": om.mfa_sms_message(
            code="123456", expires_in_seconds=expires, locale=locale, **KWARGS
        ),
    }


def flat(message: om.OutboundMessage | str) -> str:
    return message if isinstance(message, str) else f"{message.subject}\n{message.body}"


@pytest.mark.parametrize("locale", LOCALES)
def test_every_message_renders_in_every_locale_without_leftover_placeholders(locale: str) -> None:
    for name, message in every_message(locale).items():
        text = flat(message)
        assert not re.search(r"\{[a-z_]+\}", text), (locale, name, text)
        assert "SVC-NAME" in text and "CLINIC-NAME" in text or name in {"contact_change"}, name


@pytest.mark.parametrize("locale", LOCALES)
def test_codes_and_links_pass_through_untouched(locale: str) -> None:
    messages = every_message(locale)
    assert "123456" in flat(messages["mfa_email"]) and "123456" in flat(messages["sms"])
    assert "https://example.test/reset?t=TOKEN" in flat(messages["reset"])
    assert "https://example.test/confirm?t=TOKEN" in flat(messages["email_confirm"])
    assert "https://example.test/in" in flat(messages["booking"])


@pytest.mark.parametrize("locale", [code for code in LOCALES if code != "en"])
def test_translated_messages_differ_from_english(locale: str) -> None:
    english = every_message("en")
    for name, message in every_message(locale).items():
        assert flat(message) != flat(english[name]), (locale, name)


def test_the_english_texts_say_sign_in_code_not_verification_code() -> None:
    for message in every_message("en").values():
        text = flat(message).lower()
        assert "verification" not in text
    assert "sign-in code" in flat(every_message("en")["mfa_email"])
    assert "sign-in code" in flat(every_message("en")["sms"])


def test_english_wording_is_unchanged_apart_from_the_code_name_and_singular_minutes() -> None:
    mail = om.mfa_email_message(
        service_name="Portal", clinic_name="Clinic", code="123456", expires_in_seconds=600
    )
    assert mail.subject == "Your Portal sign-in code"
    assert mail.body == (
        "Your sign-in code for Portal is:\n\n123456\n\n"
        "This code expires in 10 minutes. Do not share this code with anyone.\n\n"
        "If you did not try to sign in, contact Clinic."
    )
    one = om.mfa_email_message(
        service_name="Portal", clinic_name="Clinic", code="1", expires_in_seconds=30
    )
    assert "expires in 1 minute." in one.body


@pytest.mark.parametrize(
    ("minutes", "expected"),
    [(1, "minutę"), (2, "minuty"), (5, "minut"), (12, "minut"), (22, "minuty"), (25, "minut")],
)
def test_polish_minutes_use_the_right_plural_form(minutes: int, expected: str) -> None:
    body = om.mfa_email_message(
        service_name="P", clinic_name="C", code="1", expires_in_seconds=minutes * 60, locale="pl"
    ).body
    assert re.search(rf"za {minutes} {expected}\b", body), body


def test_french_and_portuguese_zero_or_one_minute_are_singular_and_other_counts_plural() -> None:
    for locale in ("fr", "pt-BR"):
        one = om.mfa_sms_message(
            service_name="P", clinic_name="C", code="1", expires_in_seconds=60, locale=locale
        )
        many = om.mfa_sms_message(
            service_name="P", clinic_name="C", code="1", expires_in_seconds=300, locale=locale
        )
        assert "1 minuto" in one or "1 minute" in one
        assert "5 minutos" in many or "5 minutes" in many


def test_chinese_messages_use_the_locale_s_own_script() -> None:
    simplified = flat(every_message("zh-CN")["mfa_email"])
    traditional = flat(every_message("zh-TW")["mfa_email"])
    assert "登录验证码" in simplified and "登入驗證碼" in traditional
    assert "登入" not in simplified and "登录" not in traditional


def test_an_unknown_locale_is_refused_and_a_partial_catalog_falls_back_per_key() -> None:
    with pytest.raises(ValueError, match="not supported"):
        om.mfa_sms_message(
            service_name="P", clinic_name="C", code="1", expires_in_seconds=60, locale="de"
        )
    assert "outbound_mfa_sms_other" in portal_text("fr")


def test_no_locale_leaves_english_words_in_an_email_body() -> None:
    for locale in (code for code in LOCALES if code != "en"):
        text = flat(every_message(locale)["booking"]).replace("CLINIC-NAME", "")
        english = r"\b(?:sign in|expecting|has sent|you have)\b"
        assert not re.search(english, text, re.I), (locale, text)
