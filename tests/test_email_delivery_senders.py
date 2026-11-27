# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""The portal's other emails through the SMTP sender, and the sender protocol's stubs.

The sign-in code, reset link and contact-change notice are covered in `test_email_delivery.py`;
these are the booking-prompt notices and the two email-change messages: each goes to the address
it is given with only what it must carry (never a clinical detail), a message id passes through
only when it is well formed, and a transport or header failure is the one generic error.
"""

import smtplib

import pytest

from carlos_patient_portal.email_delivery import (
    PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE,
    PortalEmailDeliveryError,
    PortalEmailSender,
    SmtpPortalEmailSender,
)
from carlos_patient_portal.outbound_messages import (
    _text,
    email_change_confirmation_email_message,
    email_change_requested_email_message,
)
from tests.test_email_delivery import RecordingSmtp, smtp_settings

SIGN_IN = "https://portal.example.test/sign-in"
CONFIRM = "https://portal.example.test/confirm/abc"


@pytest.fixture
def sender(monkeypatch: pytest.MonkeyPatch) -> SmtpPortalEmailSender:
    RecordingSmtp.refused_recipients = {}
    RecordingSmtp.instance = None
    monkeypatch.setattr(smtplib, "SMTP", RecordingSmtp)
    return SmtpPortalEmailSender(smtp_settings())


def sent() -> RecordingSmtp:
    smtp = RecordingSmtp.instance
    assert smtp is not None
    assert smtp.message is not None
    return smtp


def test_the_booking_prompt_notice_says_a_message_waits_and_names_nothing_else(sender) -> None:
    sender.send_booking_prompt_notice(
        recipient="patient@example.test",
        sign_in_url=SIGN_IN,
        message_id="<prompt-1@portal.example.test>",
    )

    message = sent().message
    assert message["To"] == "patient@example.test"
    assert message["Message-ID"] == "<prompt-1@portal.example.test>"
    assert message["Auto-Submitted"] == "auto-generated"
    body = message.get_content()
    assert SIGN_IN in body
    # What it says about the message is the fixed note, and the sender's name and the clinic's
    # are all it names: the details are shown only after sign-in.
    note = _text("en")["outbound_booking_prompt_note"]
    assert note in body
    assert "patient@example.test" not in body


def test_the_booking_update_notice_goes_to_the_same_address_with_its_own_subject(sender) -> None:
    sender.send_booking_prompt_notice(recipient="a@example.test", sign_in_url=SIGN_IN)
    first_subject = sent().message["Subject"]
    sender.send_booking_prompt_update_notice(
        recipient="patient@example.test",
        sign_in_url=SIGN_IN,
        message_id="<update-1@portal.example.test>",
    )

    message = sent().message
    assert message["To"] == "patient@example.test"
    assert message["Message-ID"] == "<update-1@portal.example.test>"
    assert message["Subject"] != first_subject
    assert SIGN_IN in message.get_content()


def test_the_email_change_confirmation_goes_to_the_proposed_address_with_its_link(sender) -> None:
    sender.send_email_change_confirmation(
        recipient="new@example.test", confirmation_url=CONFIRM, expires_in_seconds=7200
    )

    message = sent().message
    assert message["To"] == "new@example.test"
    assert message["Auto-Submitted"] == "auto-generated"
    body = message.get_content()
    assert CONFIRM in body
    expected = email_change_confirmation_email_message(
        service_name=sender.service_name,
        clinic_name=sender.clinic_name,
        confirmation_url=CONFIRM,
        expires_in_seconds=7200,
    )
    assert (message["Subject"], body.strip()) == (expected.subject, expected.body.strip())
    assert "2 hours" in body or "2 hour" in body


def test_the_email_change_notice_to_the_old_address_does_not_name_the_new_one(sender) -> None:
    sender.send_email_change_requested_notice(recipient="old@example.test")

    message = sent().message
    assert message["To"] == "old@example.test"
    assert "new@example.test" not in message.get_content()
    expected = email_change_requested_email_message(
        service_name=sender.service_name, clinic_name=sender.clinic_name
    )
    assert (message["Subject"], message.get_content().strip()) == (
        expected.subject,
        expected.body.strip(),
    )
    assert message["Auto-Submitted"] == "auto-generated"


@pytest.mark.parametrize("locale", ["fr", "es", "pl"])
def test_the_notices_use_the_patients_locale(sender, locale) -> None:
    sender.send_booking_prompt_notice(
        recipient="patient@example.test", sign_in_url=SIGN_IN, locale=locale
    )
    translated = sent().message["Subject"]
    sender.send_booking_prompt_notice(recipient="patient@example.test", sign_in_url=SIGN_IN)
    assert translated != sent().message["Subject"]


@pytest.mark.parametrize("bad", ["<a\r\nBcc: attacker@example.test>", "id\nwith\nnewlines"])
def test_a_message_id_that_is_not_a_header_value_is_the_generic_failure_and_sends_nothing(
    sender, bad
) -> None:
    with pytest.raises(PortalEmailDeliveryError) as failure:
        sender.send_booking_prompt_notice(
            recipient="patient@example.test", sign_in_url=SIGN_IN, message_id=bad
        )
    assert str(failure.value) == PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE
    assert failure.value.__cause__ is None
    assert RecordingSmtp.instance is None


@pytest.mark.parametrize("call", ["notice", "update", "confirmation", "requested"])
def test_a_header_injection_in_the_recipient_is_the_generic_failure(sender, call) -> None:
    recipient = "patient@example.test\r\nBcc: attacker@example.test"
    with pytest.raises(PortalEmailDeliveryError) as failure:
        if call == "notice":
            sender.send_booking_prompt_notice(recipient=recipient, sign_in_url=SIGN_IN)
        elif call == "update":
            sender.send_booking_prompt_update_notice(recipient=recipient, sign_in_url=SIGN_IN)
        elif call == "confirmation":
            sender.send_email_change_confirmation(
                recipient=recipient, confirmation_url=CONFIRM, expires_in_seconds=3600
            )
        else:
            sender.send_email_change_requested_notice(recipient=recipient)
    assert str(failure.value) == PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE
    assert RecordingSmtp.instance is None


def test_the_protocol_methods_are_stubs_that_refuse_to_run() -> None:
    nothing = object()
    calls = [
        lambda: PortalEmailSender.send_code(nothing, recipient="a", code="1", expires_in_seconds=1),
        lambda: PortalEmailSender.send_password_reset(
            nothing, recipient="a", reset_url="u", expires_in_seconds=1
        ),
        lambda: PortalEmailSender.send_contact_change_notice(nothing, recipient="a"),
        lambda: PortalEmailSender.send_booking_prompt_notice(
            nothing, recipient="a", sign_in_url="u"
        ),
        lambda: PortalEmailSender.send_booking_prompt_update_notice(
            nothing, recipient="a", sign_in_url="u"
        ),
        lambda: PortalEmailSender.send_email_change_confirmation(
            nothing, recipient="a", confirmation_url="u", expires_in_seconds=1
        ),
        lambda: PortalEmailSender.send_email_change_requested_notice(nothing, recipient="a"),
    ]
    for call in calls:
        with pytest.raises(NotImplementedError):
            call()


def test_a_sender_without_a_host_is_refused_at_construction() -> None:
    from carlos_patient_portal.config import Settings

    with pytest.raises(ValueError, match="SMTP host and from address are required"):
        SmtpPortalEmailSender(Settings(environment="development"))
