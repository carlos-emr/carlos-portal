# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The language of an outbound message follows the request, or the one stored with the message."""

import smtplib
from types import SimpleNamespace

import pytest

from carlos_patient_portal import notifications
from carlos_patient_portal.config import Settings
from carlos_patient_portal.email_delivery import SmtpPortalEmailSender
from carlos_patient_portal.outbound_messages import (
    DEFAULT_OUTBOUND_LOCALE,
    mfa_email_message,
    sender_locale_kwargs,
    stored_outbound_locale,
)
from tests.test_email_delivery import trusted_clinic_footer as trusted_clinic_footer


class RecordingSmtp:
    messages: list[object] = []

    def __init__(self, host: str, port: int, timeout: int) -> None:
        pass

    def __enter__(self) -> "RecordingSmtp":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def ehlo(self) -> None:
        return None

    def starttls(self, **kwargs: object) -> None:
        return None

    def login(self, username: str, password: str) -> None:
        return None

    def send_message(self, message: object) -> dict[str, tuple[int, bytes]]:
        RecordingSmtp.messages.append(message)
        return {}


def test_default_and_missing_locales_add_no_sender_argument() -> None:
    assert sender_locale_kwargs(None) == {}
    assert sender_locale_kwargs(DEFAULT_OUTBOUND_LOCALE) == {}
    assert sender_locale_kwargs("pl") == {"locale": "pl"}


def test_stored_locale_falls_back_to_the_default_for_anything_unknown() -> None:
    assert stored_outbound_locale("fr") == "fr"
    for bad in (None, "", "xx", 5, ["pl"]):
        assert stored_outbound_locale(bad) == DEFAULT_OUTBOUND_LOCALE


def test_smtp_sender_writes_the_sign_in_code_mail_in_the_requested_language(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    RecordingSmtp.messages = []
    monkeypatch.setattr(smtplib, "SMTP", RecordingSmtp)
    settings = Settings(
        environment="development",
        smtp_host="mail.internal",
        smtp_port=2525,
        smtp_from_address="portal@example.test",
    )
    sender = SmtpPortalEmailSender(settings)
    sender.send_code(
        recipient="patient@example.test", code="123456", expires_in_seconds=600, locale="pl"
    )
    sent = RecordingSmtp.messages[-1]
    expected = mfa_email_message(
        service_name=settings.service_name,
        clinic_name=settings.clinic_name,
        code="123456",
        expires_in_seconds=600,
        locale="pl",
    )
    assert sent["Subject"] == expected.subject
    assert sent["Subject"] != "Your CARLOS Patient Portal sign-in code"


class LocaleRecorder:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def send_code(self, **kwargs: object) -> None:
        self.calls.append(kwargs)

    def send_password_reset(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


def runtime_with(sender: LocaleRecorder) -> SimpleNamespace:
    settings = SimpleNamespace(
        is_development=False, mfa_code_ttl_seconds=600, password_reset_token_ttl_seconds=900
    )
    return SimpleNamespace(email_sender=sender, sms_sender=sender, settings=settings)


def test_notifications_pass_the_request_language_only_when_it_is_not_the_default() -> None:
    recorder = LocaleRecorder()
    runtime = runtime_with(recorder)
    delivery = SimpleNamespace(delivery_method="email", destination="a@example.test", code="1")
    notifications.send_mfa_challenge(runtime, delivery, "pt_BR")  # type: ignore[arg-type]
    notifications.send_mfa_challenge(runtime, delivery)  # type: ignore[arg-type]
    notifications.send_password_reset_email(
        runtime,  # type: ignore[arg-type]
        recipient="a@example.test",
        reset_url="https://example.test/r",
        locale="zh_TW",
    )
    assert recorder.calls[0]["locale"] == "pt_BR"
    assert "locale" not in recorder.calls[1]
    assert recorder.calls[2]["locale"] == "zh_TW"
