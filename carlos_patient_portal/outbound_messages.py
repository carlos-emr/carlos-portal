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

from dataclasses import dataclass

from carlos_patient_portal.i18n import DEFAULT_LOCALE, SUPPORTED_LOCALES, plural_text, portal_text

DEFAULT_OUTBOUND_LOCALE = DEFAULT_LOCALE
_OUTBOUND_LOCALES = frozenset(option.code for option in SUPPORTED_LOCALES)


@dataclass(frozen=True)
class OutboundMessage:
    subject: str
    body: str


def _text(locale: str) -> dict[str, str]:
    """The catalog for `locale`, per-key English fallback included. Unknown locales are refused."""
    _require_supported_locale(locale)
    return portal_text(locale)


def mfa_email_message(
    *,
    service_name: str,
    clinic_name: str,
    code: str,
    expires_in_seconds: int,
    locale: str = DEFAULT_OUTBOUND_LOCALE,
) -> OutboundMessage:
    text = _text(locale)
    minutes = max(1, expires_in_seconds // 60)
    expiry = plural_text(text, "outbound_mfa_email_expiry", minutes, locale)
    return OutboundMessage(
        subject=text["outbound_mfa_email_subject"].format(service_name=service_name),
        body=(
            f"{text['outbound_mfa_email_intro'].format(service_name=service_name)}\n\n"
            f"{code}\n\n"
            f"{expiry.format(minutes=minutes)}\n\n"
            f"{text['outbound_mfa_email_contact'].format(clinic_name=clinic_name)}"
        ),
    )


def password_reset_email_message(
    *,
    service_name: str,
    clinic_name: str,
    reset_url: str,
    expires_in_seconds: int,
    locale: str = DEFAULT_OUTBOUND_LOCALE,
) -> OutboundMessage:
    text = _text(locale)
    minutes = max(1, expires_in_seconds // 60)
    expiry = plural_text(text, "outbound_reset_expiry", minutes, locale)
    return OutboundMessage(
        subject=text["outbound_reset_subject"].format(service_name=service_name),
        body=(
            f"{text['outbound_reset_intro'].format(service_name=service_name)}\n\n"
            f"{text['outbound_reset_link_lead']}\n{reset_url}\n\n"
            f"{expiry.format(minutes=minutes)}\n\n"
            f"{text['outbound_reset_contact'].format(clinic_name=clinic_name)}"
        ),
    )


def contact_change_email_message(
    *,
    service_name: str,
    clinic_name: str,
    locale: str = DEFAULT_OUTBOUND_LOCALE,
) -> OutboundMessage:
    text = _text(locale)
    return OutboundMessage(
        subject=text["outbound_contact_change_subject"].format(service_name=service_name),
        body=(
            f"{text['outbound_contact_change_body'].format(service_name=service_name)}\n\n"
            f"{text['outbound_contact_change_contact'].format(clinic_name=clinic_name)}"
        ),
    )


def booking_prompt_email_message(
    *,
    service_name: str,
    clinic_name: str,
    sign_in_url: str,
    locale: str = DEFAULT_OUTBOUND_LOCALE,
) -> OutboundMessage:
    """Tells the patient a message is waiting, and nothing about what it says.

    Email is not a secure channel, so the provider, the kind of appointment and its urgency are
    shown only after sign-in.
    """
    text = _text(locale)
    intro = text["outbound_booking_prompt_intro"].format(
        clinic_name=clinic_name, service_name=service_name
    )
    return OutboundMessage(
        subject=text["outbound_booking_prompt_subject"].format(service_name=service_name),
        body=(
            f"{intro}\n\n"
            f"{text['outbound_sign_in_lead']}\n{sign_in_url}\n\n"
            f"{text['outbound_booking_prompt_note']}\n\n"
            f"{text['outbound_not_expecting_contact'].format(clinic_name=clinic_name)}"
        ),
    )


def booking_prompt_update_email_message(
    *,
    service_name: str,
    clinic_name: str,
    sign_in_url: str,
    locale: str = DEFAULT_OUTBOUND_LOCALE,
) -> OutboundMessage:
    """Tells the patient a message has an update, and nothing about what changed.

    Sent when CARLOS answers a time the patient picked. Whether it was booked, the time, the
    provider, the kind of visit and where it is are shown only after sign-in.
    """
    text = _text(locale)
    intro = text["outbound_booking_update_intro"].format(
        clinic_name=clinic_name, service_name=service_name
    )
    return OutboundMessage(
        subject=text["outbound_booking_update_subject"].format(service_name=service_name),
        body=(
            f"{intro}\n\n"
            f"{text['outbound_sign_in_lead']}\n{sign_in_url}\n\n"
            f"{text['outbound_booking_update_note']}\n\n"
            f"{text['outbound_not_expecting_contact'].format(clinic_name=clinic_name)}"
        ),
    )


def email_change_confirmation_email_message(
    *,
    service_name: str,
    clinic_name: str,
    confirmation_url: str,
    expires_in_seconds: int,
    locale: str = DEFAULT_OUTBOUND_LOCALE,
) -> OutboundMessage:
    """Sent to the proposed address. Carries no patient or clinical detail beyond the clinic name.

    Until this link is opened the change has not happened, so the wording must not imply the
    account already uses this address.
    """
    text = _text(locale)
    hours = max(1, expires_in_seconds // 3600)
    expiry = plural_text(text, "outbound_email_confirm_expiry", hours, locale)
    return OutboundMessage(
        subject=text["outbound_email_confirm_subject"].format(service_name=service_name),
        body=(
            f"{text['outbound_email_confirm_intro'].format(service_name=service_name)}\n\n"
            f"{text['outbound_email_confirm_link_lead']}\n{confirmation_url}\n\n"
            f"{expiry.format(hours=hours)}\n\n"
            f"{text['outbound_email_confirm_contact'].format(clinic_name=clinic_name)}"
        ),
    )


def email_change_requested_email_message(
    *,
    service_name: str,
    clinic_name: str,
    locale: str = DEFAULT_OUTBOUND_LOCALE,
) -> OutboundMessage:
    """Sent to the *current* address. This is the out-of-band alarm for an unwanted change.

    It deliberately does not include the proposed address: this mailbox may already be in someone
    else's hands, and the notice should not hand them confirmation of where the change points.
    """
    text = _text(locale)
    return OutboundMessage(
        subject=text["outbound_email_requested_subject"].format(service_name=service_name),
        body=(
            f"{text['outbound_email_requested_intro'].format(service_name=service_name)}\n\n"
            f"{text['outbound_email_requested_body']}\n\n"
            f"{text['outbound_email_requested_contact'].format(clinic_name=clinic_name)}"
        ),
    )


def mfa_sms_message(
    *,
    service_name: str,
    clinic_name: str,
    code: str,
    expires_in_seconds: int,
    locale: str = DEFAULT_OUTBOUND_LOCALE,
) -> str:
    text = _text(locale)
    minutes = max(1, expires_in_seconds // 60)
    return plural_text(text, "outbound_mfa_sms", minutes, locale).format(
        service_name=service_name, clinic_name=clinic_name, code=code, minutes=minutes
    )


def _require_supported_locale(locale: str) -> None:
    if locale not in _OUTBOUND_LOCALES:
        raise ValueError("outbound message locale is not supported")
