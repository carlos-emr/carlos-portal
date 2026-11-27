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

import json
import os
import smtplib
import ssl
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Protocol

from carlos_patient_portal.config import Settings
from carlos_patient_portal.outbound_messages import (
    DEFAULT_OUTBOUND_LOCALE,
    OutboundMessage,
    booking_prompt_email_message,
    booking_prompt_update_email_message,
    contact_change_email_message,
    email_change_confirmation_email_message,
    email_change_requested_email_message,
    mfa_email_message,
    password_reset_email_message,
)

# One deliberately generic message for every adapter failure path. Detailed SMTP/header failure
# classification belongs in privacy-safe metrics/logs, never in text that can reach a patient.
PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE = "portal email delivery failed"


class PortalEmailDeliveryError(Exception):
    """Raised when a portal authentication email cannot be delivered."""


class PortalEmailSender(Protocol):
    def send_code(
        self,
        *,
        recipient: str,
        code: str,
        expires_in_seconds: int,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        raise NotImplementedError

    def send_password_reset(
        self,
        *,
        recipient: str,
        reset_url: str,
        expires_in_seconds: int,
        message_id: str | None = None,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        raise NotImplementedError

    def send_contact_change_notice(
        self,
        *,
        recipient: str,
        message_id: str | None = None,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        raise NotImplementedError

    def send_booking_prompt_notice(
        self,
        *,
        recipient: str,
        sign_in_url: str,
        message_id: str | None = None,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        raise NotImplementedError

    def send_booking_prompt_update_notice(
        self,
        *,
        recipient: str,
        sign_in_url: str,
        message_id: str | None = None,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        raise NotImplementedError

    def send_email_change_confirmation(
        self,
        *,
        recipient: str,
        confirmation_url: str,
        expires_in_seconds: int,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        raise NotImplementedError

    def send_email_change_requested_notice(
        self, *, recipient: str, locale: str = DEFAULT_OUTBOUND_LOCALE
    ) -> None:
        raise NotImplementedError


class SmtpPortalEmailSender:
    def __init__(self, settings: Settings) -> None:
        if settings.smtp_host is None or settings.resolved_smtp_from_address is None:
            raise ValueError("SMTP host and from address are required")
        self.host = settings.smtp_host
        self.port = settings.smtp_port
        self.from_address = settings.resolved_smtp_from_address
        self.starttls = settings.smtp_starttls
        self.username = settings.smtp_username
        self.password = (
            settings.smtp_password.get_secret_value()
            if settings.smtp_password is not None
            else None
        )
        self.timeout_seconds = settings.smtp_timeout_seconds
        self.service_name = settings.service_name
        self.clinic_name = settings.clinic_name

    def send_code(
        self,
        *,
        recipient: str,
        code: str,
        expires_in_seconds: int,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        self._send_message(
            self._build_message(
                recipient,
                mfa_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                    locale=locale,
                    code=code,
                    expires_in_seconds=expires_in_seconds,
                ),
            )
        )

    def send_password_reset(
        self,
        *,
        recipient: str,
        reset_url: str,
        expires_in_seconds: int,
        message_id: str | None = None,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        self._send_message(
            self._build_message(
                recipient,
                password_reset_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                    locale=locale,
                    reset_url=reset_url,
                    expires_in_seconds=expires_in_seconds,
                ),
                message_id=message_id,
            )
        )

    def send_contact_change_notice(
        self,
        *,
        recipient: str,
        message_id: str | None = None,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        self._send_message(
            self._build_message(
                recipient,
                contact_change_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                    locale=locale,
                ),
                message_id=message_id,
            )
        )

    def send_booking_prompt_notice(
        self,
        *,
        recipient: str,
        sign_in_url: str,
        message_id: str | None = None,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        self._send_message(
            self._build_message(
                recipient,
                booking_prompt_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                    locale=locale,
                    sign_in_url=sign_in_url,
                ),
                message_id=message_id,
            )
        )

    def send_booking_prompt_update_notice(
        self,
        *,
        recipient: str,
        sign_in_url: str,
        message_id: str | None = None,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        self._send_message(
            self._build_message(
                recipient,
                booking_prompt_update_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                    locale=locale,
                    sign_in_url=sign_in_url,
                ),
                message_id=message_id,
            )
        )

    def send_email_change_confirmation(
        self,
        *,
        recipient: str,
        confirmation_url: str,
        expires_in_seconds: int,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        self._send_message(
            self._build_message(
                recipient,
                email_change_confirmation_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                    locale=locale,
                    confirmation_url=confirmation_url,
                    expires_in_seconds=expires_in_seconds,
                ),
            )
        )

    def send_email_change_requested_notice(
        self, *, recipient: str, locale: str = DEFAULT_OUTBOUND_LOCALE
    ) -> None:
        self._send_message(
            self._build_message(
                recipient,
                email_change_requested_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                    locale=locale,
                ),
            )
        )

    def _build_message(
        self,
        recipient: str,
        content: OutboundMessage,
        *,
        message_id: str | None = None,
    ) -> EmailMessage:
        try:
            message = EmailMessage()
            message["From"] = self.from_address
            message["To"] = recipient
            message["Subject"] = content.subject
            message["Auto-Submitted"] = "auto-generated"
            if message_id is not None:
                message["Message-ID"] = message_id
            message.set_content(content.body)
            return message
        except (TypeError, ValueError):
            raise PortalEmailDeliveryError(PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE) from None

    def _send_message(self, message: EmailMessage) -> None:
        try:
            with smtplib.SMTP(
                host=self.host,
                port=self.port,
                timeout=self.timeout_seconds,
            ) as smtp:
                if self.starttls:
                    # create_default_context enables CA validation and hostname checking.
                    smtp.starttls(context=ssl.create_default_context())  # NOSONAR
                if self.username is not None and self.password is not None:
                    smtp.login(self.username, self.password)
                refused_recipients = smtp.send_message(message)
                if refused_recipients:
                    raise PortalEmailDeliveryError(PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE)
        except PortalEmailDeliveryError:
            raise
        except (OSError, smtplib.SMTPException, ValueError):
            raise PortalEmailDeliveryError(PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE) from None


class DevelopmentOutboxEmailSender:
    """Development only: writes each outgoing email to a private file instead of sending it.

    A development portal with no SMTP host used to print the sign-in code and the reset link on
    its pages and in its answers (#135). It prints and returns neither now, so a developer, the
    browser checks and the demo read the message here, or at a test inbox when SMTP is set. One
    JSON object per line (`at`, `kind`, `recipient`, and the code or link the message carries),
    appended to a file only its owner can read, never followed through a link. It is built only
    by `build_portal_email_sender` in development, and refuses to be built anywhere else.
    """

    def __init__(self, settings: Settings) -> None:
        if not settings.is_development:
            raise ValueError("the development mail outbox is only for development")
        self.path = settings.resolved_development_mail_outbox_path

    def _record(self, kind: str, recipient: str, **fields: object) -> None:
        line = json.dumps(
            {"at": datetime.now(UTC).isoformat(), "kind": kind, "recipient": recipient, **fields},
            separators=(",", ":"),
        )
        try:
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except OSError as exc:
            # A link in place of the file (O_NOFOLLOW), a directory, no permission.
            raise PortalEmailDeliveryError(PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE) from exc
        try:
            os.write(descriptor, (line + "\n").encode("utf-8"))
        except OSError as exc:
            raise PortalEmailDeliveryError(PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE) from exc
        finally:
            os.close(descriptor)

    def send_code(
        self,
        *,
        recipient: str,
        code: str,
        expires_in_seconds: int,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        self._record("mfa_code", recipient, code=code, expires_in_seconds=expires_in_seconds)

    def send_password_reset(
        self,
        *,
        recipient: str,
        reset_url: str,
        expires_in_seconds: int,
        message_id: str | None = None,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        self._record(
            "password_reset", recipient, reset_url=reset_url, expires_in_seconds=expires_in_seconds
        )

    def send_contact_change_notice(
        self,
        *,
        recipient: str,
        message_id: str | None = None,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        self._record("contact_change_notice", recipient)

    def send_booking_prompt_notice(
        self,
        *,
        recipient: str,
        sign_in_url: str,
        message_id: str | None = None,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        self._record("booking_prompt_notice", recipient, sign_in_url=sign_in_url)

    def send_booking_prompt_update_notice(
        self,
        *,
        recipient: str,
        sign_in_url: str,
        message_id: str | None = None,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        self._record("booking_prompt_update_notice", recipient, sign_in_url=sign_in_url)

    def send_email_change_confirmation(
        self,
        *,
        recipient: str,
        confirmation_url: str,
        expires_in_seconds: int,
        locale: str = DEFAULT_OUTBOUND_LOCALE,
    ) -> None:
        self._record(
            "email_change_confirmation",
            recipient,
            confirmation_url=confirmation_url,
            expires_in_seconds=expires_in_seconds,
        )

    def send_email_change_requested_notice(
        self, *, recipient: str, locale: str = DEFAULT_OUTBOUND_LOCALE
    ) -> None:
        self._record("email_change_requested_notice", recipient)


def build_portal_email_sender(settings: Settings) -> PortalEmailSender | None:
    if settings.smtp_host is not None:
        return SmtpPortalEmailSender(settings)
    # No SMTP host in development: the outbox file is the only way to read what was "sent".
    if settings.is_development and settings.development_mail_outbox:
        return DevelopmentOutboxEmailSender(settings)
    return None
