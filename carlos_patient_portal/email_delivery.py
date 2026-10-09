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

import logging
import smtplib
import ssl
from email.message import EmailMessage
from html import escape
from typing import Protocol

from carlos_patient_portal.clinic_footer import (
    ClinicFooterProvider,
    ClinicFooterUnavailableError,
    HttpsClinicFooterProvider,
)
from carlos_patient_portal.config import Settings
from carlos_patient_portal.footer_audit import FooterAuditStore, FooterAuditUnavailableError
from carlos_patient_portal.outbound_messages import (
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
logger = logging.getLogger(__name__)


class PortalEmailDeliveryError(Exception):
    """Raised when a portal authentication email cannot be delivered."""


class PortalEmailSender(Protocol):
    def send_code(
        self,
        *,
        recipient: str,
        code: str,
        expires_in_seconds: int,
    ) -> None:
        raise NotImplementedError

    def send_password_reset(
        self,
        *,
        recipient: str,
        reset_url: str,
        expires_in_seconds: int,
        message_id: str | None = None,
    ) -> None:
        raise NotImplementedError

    def send_contact_change_notice(self, *, recipient: str, message_id: str | None = None) -> None:
        raise NotImplementedError

    def send_booking_prompt_notice(
        self, *, recipient: str, sign_in_url: str, message_id: str | None = None
    ) -> None:
        raise NotImplementedError

    def send_booking_prompt_update_notice(
        self, *, recipient: str, sign_in_url: str, message_id: str | None = None
    ) -> None:
        raise NotImplementedError

    def send_email_change_confirmation(
        self,
        *,
        recipient: str,
        confirmation_url: str,
        expires_in_seconds: int,
    ) -> None:
        raise NotImplementedError

    def send_email_change_requested_notice(self, *, recipient: str) -> None:
        raise NotImplementedError


class SmtpPortalEmailSender:
    def __init__(
        self,
        settings: Settings,
        *,
        footer_provider: ClinicFooterProvider | None = None,
        footer_audit: FooterAuditStore | None = None,
    ) -> None:
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
        self._footer_provider = (
            footer_provider if footer_provider is not None else HttpsClinicFooterProvider(settings)
        )
        self._footer_audit = (
            footer_audit
            if footer_audit is not None
            else FooterAuditStore(
                settings.email_footer_audit_directory,
                settings.clinic_id,
            )
        )

    def send_code(
        self,
        *,
        recipient: str,
        code: str,
        expires_in_seconds: int,
    ) -> None:
        self._send_message(
            self._build_message(
                recipient,
                mfa_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                    code=code,
                    expires_in_seconds=expires_in_seconds,
                ),
                kind="mfa",
            )
        )

    def send_password_reset(
        self,
        *,
        recipient: str,
        reset_url: str,
        expires_in_seconds: int,
        message_id: str | None = None,
    ) -> None:
        self._send_message(
            self._build_message(
                recipient,
                password_reset_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                    reset_url=reset_url,
                    expires_in_seconds=expires_in_seconds,
                ),
                message_id=message_id,
                kind="password_reset",
            )
        )

    def send_contact_change_notice(self, *, recipient: str, message_id: str | None = None) -> None:
        self._send_message(
            self._build_message(
                recipient,
                contact_change_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                ),
                message_id=message_id,
                kind="contact_change",
            )
        )

    def send_booking_prompt_notice(
        self, *, recipient: str, sign_in_url: str, message_id: str | None = None
    ) -> None:
        self._send_message(
            self._build_message(
                recipient,
                booking_prompt_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                    sign_in_url=sign_in_url,
                ),
                message_id=message_id,
                kind="booking_prompt",
            )
        )

    def send_booking_prompt_update_notice(
        self, *, recipient: str, sign_in_url: str, message_id: str | None = None
    ) -> None:
        self._send_message(
            self._build_message(
                recipient,
                booking_prompt_update_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                    sign_in_url=sign_in_url,
                ),
                message_id=message_id,
                kind="booking_prompt_update",
            )
        )

    def send_email_change_confirmation(
        self,
        *,
        recipient: str,
        confirmation_url: str,
        expires_in_seconds: int,
    ) -> None:
        self._send_message(
            self._build_message(
                recipient,
                email_change_confirmation_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                    confirmation_url=confirmation_url,
                    expires_in_seconds=expires_in_seconds,
                ),
                kind="email_change_confirmation",
            )
        )

    def send_email_change_requested_notice(self, *, recipient: str) -> None:
        self._send_message(
            self._build_message(
                recipient,
                email_change_requested_email_message(
                    service_name=self.service_name,
                    clinic_name=self.clinic_name,
                ),
                kind="email_change_requested",
            )
        )

    def _build_message(
        self,
        recipient: str,
        content: OutboundMessage,
        *,
        kind: str,
        message_id: str | None = None,
    ) -> tuple[EmailMessage, str]:
        try:
            message = EmailMessage()
            message["From"] = self.from_address
            message["To"] = recipient
            message["Subject"] = content.subject
            message["Auto-Submitted"] = "auto-generated"
            if message_id is not None:
                message["Message-ID"] = message_id
            message.set_content(content.body)
            return message, kind
        except (TypeError, ValueError):
            raise PortalEmailDeliveryError(PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE) from None

    def _send_message(self, draft: tuple[EmailMessage, str]) -> None:
        message, kind = draft
        try:
            # This is the NEW-send preparation boundary. The same immutable value goes
            # into both MIME alternatives, the inline attachment and durable audit.
            footer = self._footer_provider.snapshot()
            body = message.get_content().rstrip()
            message.set_content(body + "\n\n" + footer.plain)
            logo_html = ""
            if footer.logo is not None:
                logo_html = (
                    '<img src="cid:' + footer.logo.content_id + '" alt="" style="max-width:600px;">'
                )
            message.add_alternative(
                '<!doctype html><html><body><div style="white-space:pre-wrap;">'
                + escape(body, quote=False).replace("\n", "<br>")
                + "</div><br>"
                + logo_html
                + "<div>"
                + footer.html
                + "</div></body></html>",
                subtype="html",
            )
            if footer.logo is not None:
                message.get_payload()[-1].add_related(
                    footer.logo.data,
                    maintype="image",
                    subtype=footer.logo.content_type.split("/")[1],
                    cid="<" + footer.logo.content_id + ">",
                    filename=footer.logo.content_id.split("@")[0]
                    + (".png" if footer.logo.content_type == "image/png" else ".jpg"),
                    disposition="inline",
                )
            # Finalize MIME boundaries locally before persistence; no SMTP socket exists yet.
            message.as_bytes()
            attempt = self._footer_audit.prepare(footer, kind)
        except (ClinicFooterUnavailableError, FooterAuditUnavailableError, OSError, ValueError):
            raise PortalEmailDeliveryError(PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE) from None
        submission_started = False
        accepted = False
        outcome = "failed"
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
                submission_started = True
                outcome = "unknown"
                refused_recipients = smtp.send_message(message)
                if refused_recipients:
                    outcome = "failed"
                    raise PortalEmailDeliveryError(PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE)
                accepted = True
                outcome = "accepted"
        except PortalEmailDeliveryError:
            raise
        except Exception as failure:
            if accepted:
                # A failed QUIT after successful DATA must not invite duplicate delivery.
                logger.warning("Portal SMTP accepted email; closing the connection failed")
            else:
                definite_refusal = isinstance(
                    failure,
                    (
                        smtplib.SMTPRecipientsRefused,
                        smtplib.SMTPSenderRefused,
                        smtplib.SMTPDataError,
                    ),
                )
                outcome = "unknown" if submission_started and not definite_refusal else "failed"
                raise PortalEmailDeliveryError(PORTAL_EMAIL_DELIVERY_ERROR_MESSAGE) from None
        finally:
            try:
                self._footer_audit.record_outcome(attempt, outcome)
            except Exception:
                # Acceptance cannot be undone. The immutable prepared artifact remains an
                # honest "acceptance not recorded" if this bookkeeping write is unavailable.
                logger.warning("Portal email footer outcome was not recorded")


def build_portal_email_sender(settings: Settings) -> PortalEmailSender | None:
    if settings.smtp_host is None:
        return None
    return SmtpPortalEmailSender(settings)
