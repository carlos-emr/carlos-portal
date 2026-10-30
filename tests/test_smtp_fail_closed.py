import smtplib
import ssl
import traceback

import pytest

from carlos_patient_portal.email_delivery import PortalEmailDeliveryError, SmtpPortalEmailSender
from tests.test_email_delivery import smtp_settings


@pytest.mark.parametrize("failed_stage", ["starttls", "login"])
def test_smtp_security_failure_stops_delivery_and_hides_provider_details(
    monkeypatch: pytest.MonkeyPatch, failed_stage: str
) -> None:
    recipient = "FAKE-recipient@example.test"
    reset_url = "https://portal.example.test/reset#token=FAKE-reset-token"
    username = "FAKE-smtp-user"
    password = "FAKE-smtp-password"
    private_values = (recipient, reset_url, username, password)
    provider_detail = "FAKE provider detail: " + " ".join(private_values)
    failure = (
        ssl.SSLCertVerificationError(provider_detail)
        if failed_stage == "starttls"
        else smtplib.SMTPAuthenticationError(535, provider_detail.encode())
    )
    calls = []

    class RefusingSmtp:
        def __init__(self, **kwargs):
            calls.append("connect")

        def __enter__(self):
            calls.append("enter")
            return self

        def __exit__(self, exc_type, exc_value, exc_tb):
            calls.append("exit")
            assert exc_value is failure

        def starttls(self, *, context):
            calls.append("starttls")
            assert context.check_hostname is True
            assert context.verify_mode == ssl.CERT_REQUIRED
            if failed_stage == "starttls":
                raise failure

        def login(self, supplied_username, supplied_password):
            calls.append("login")
            assert (supplied_username, supplied_password) == (username, password)
            raise failure

        def send_message(self, message):
            calls.append("send")
            return {}

    monkeypatch.setattr(smtplib, "SMTP", RefusingSmtp)
    sender = SmtpPortalEmailSender(
        smtp_settings(smtp_starttls=True, smtp_username=username, smtp_password=password)
    )
    with pytest.raises(PortalEmailDeliveryError) as caught:
        sender.send_password_reset(recipient=recipient, reset_url=reset_url, expires_in_seconds=600)

    assert calls == ["connect", "enter", "starttls"] + (
        ["login"] if failed_stage == "login" else []
    ) + ["exit"]
    assert str(caught.value) == "portal email delivery failed"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is failure
    assert caught.value.__suppress_context__ is True
    visible_error = "".join(traceback.format_exception(caught.value))
    for value in private_values:
        assert value in str(failure)
        assert value not in visible_error
        assert value not in repr(caught.value)
