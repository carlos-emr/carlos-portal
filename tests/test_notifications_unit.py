"""What the portal sends, to whom, and what it does when it cannot send.

Fake senders and synthetic addresses only; nothing here opens a connection.
"""

from types import SimpleNamespace
from urllib.parse import quote

import pytest

from carlos_patient_portal import notifications
from carlos_patient_portal.email_delivery import PortalEmailDeliveryError, SmtpPortalEmailSender
from carlos_patient_portal.sms_delivery import PortalSmsDeliveryError
from tests.support import development_settings, production_settings

TO = "fake.patient@example.test"


class Sender:
    """Records each call; has only the methods named, so a missing one can be tested."""

    def __init__(self, *names):
        self.calls = []
        for name in names:
            setattr(self, name, self._record(name))

    def _record(self, name):
        def call(**kwargs):
            self.calls.append((name, kwargs))

        return call


def runtime(*, email=None, sms=None, development=True):
    settings = SimpleNamespace(
        is_development=development,
        mfa_code_ttl_seconds=300,
        password_reset_token_ttl_seconds=900,
        email_change_token_ttl_seconds=1800,
    )
    return SimpleNamespace(settings=settings, email_sender=email, sms_sender=sms)


def delivery(method):
    return SimpleNamespace(delivery_method=method, destination=TO, code="123456")


def test_a_sign_in_code_goes_to_the_chosen_destination_with_its_lifetime():
    email, sms = Sender("send_code"), Sender("send_code")
    notifications.send_mfa_challenge(runtime(email=email, sms=sms), delivery("email"), "fr")
    notifications.send_mfa_challenge(runtime(email=email, sms=sms), delivery("sms"))
    assert email.calls == [
        (
            "send_code",
            {"recipient": TO, "code": "123456", "expires_in_seconds": 300, "locale": "fr"},
        )
    ]
    assert sms.calls == [
        ("send_code", {"recipient": TO, "code": "123456", "expires_in_seconds": 300})
    ]


@pytest.mark.parametrize(
    "method,error",
    [("email", PortalEmailDeliveryError), ("sms", PortalSmsDeliveryError)],
)
def test_a_code_is_not_silently_dropped_where_its_channel_is_not_configured(method, error):
    with pytest.raises(error, match="not configured"):
        notifications.send_mfa_challenge(runtime(development=False), delivery(method))
    # Development has no real sender and says nothing, so a local run can sign in.
    notifications.send_mfa_challenge(runtime(development=True), delivery(method))


@pytest.mark.parametrize(
    "build,keyword,path",
    [
        (
            notifications.build_password_reset_url,
            "reset_token",
            "/auth/password-reset/complete",
        ),
        (
            notifications.build_email_change_confirmation_url,
            "confirmation_token",
            "/auth/email-change/confirm",
        ),
    ],
)
def test_a_reset_or_confirmation_link_carries_its_token_in_the_fragment(build, keyword, path):
    token = "a b/c+d"
    settings = production_settings(public_base_url="https://portal.example.test/patients/")
    url = build(None, settings=settings, **{keyword: token})
    assert url == f"https://portal.example.test/patients{path}#token={quote(token, safe='')}"
    assert "?" not in url


def test_a_link_is_built_from_the_request_only_in_development():
    request = SimpleNamespace(base_url="http://localhost:8000/")
    settings = development_settings(public_base_url=None)
    url = notifications.build_password_reset_url(request, settings=settings, reset_token="t")
    assert url == "http://localhost:8000/auth/password-reset/complete#token=t"
    url = notifications.build_email_change_confirmation_url(
        request, settings=settings, confirmation_token="t"
    )
    assert url == "http://localhost:8000/auth/email-change/confirm#token=t"


@pytest.mark.parametrize(
    "build,keyword,message",
    [
        (notifications.build_password_reset_url, "reset_token", "password reset"),
        (
            notifications.build_email_change_confirmation_url,
            "confirmation_token",
            "email-change confirmation",
        ),
    ],
)
def test_a_link_is_refused_outside_development_when_no_public_address_is_set(
    build, keyword, message
):
    settings = SimpleNamespace(public_base_url=None, is_development=False)
    # A request's Host header must never decide where a reset or confirmation link points.
    request = SimpleNamespace(base_url="http://evil.test/")
    with pytest.raises(PortalEmailDeliveryError, match=message):
        build(request, settings=settings, **{keyword: "t"})


def test_a_password_reset_email_goes_to_the_recipient_with_its_lifetime():
    sender = Sender("send_password_reset")
    notifications.send_password_reset_email(
        runtime(email=sender), recipient=TO, reset_url="https://x.test/r#token=t", locale="es"
    )
    assert sender.calls == [
        (
            "send_password_reset",
            {
                "recipient": TO,
                "reset_url": "https://x.test/r#token=t",
                "expires_in_seconds": 900,
                "locale": "es",
            },
        )
    ]


def test_a_reset_email_that_cannot_be_sent_is_refused_outside_development():
    with pytest.raises(PortalEmailDeliveryError, match="not configured"):
        notifications.send_password_reset_email(
            runtime(development=False), recipient=TO, reset_url="u"
        )
    notifications.send_password_reset_email(runtime(), recipient=TO, reset_url="u")


def test_an_email_change_confirmation_is_sent_to_the_new_address():
    sender = Sender("send_email_change_confirmation")
    notifications.send_email_change_confirmation(
        runtime(email=sender), recipient=TO, confirmation_url="https://x.test/c#token=t"
    )
    assert sender.calls == [
        (
            "send_email_change_confirmation",
            {
                "recipient": TO,
                "confirmation_url": "https://x.test/c#token=t",
                "expires_in_seconds": 1800,
            },
        )
    ]


def test_a_confirmation_that_cannot_be_sent_fails_even_in_development_if_the_sender_lacks_it():
    # The confirmation is load-bearing: without it the patient can never finish the change.
    with pytest.raises(PortalEmailDeliveryError, match="not configured"):
        notifications.send_email_change_confirmation(
            runtime(email=Sender(), development=True), recipient=TO, confirmation_url="u"
        )
    with pytest.raises(PortalEmailDeliveryError, match="not configured"):
        notifications.send_email_change_confirmation(
            runtime(development=False), recipient=TO, confirmation_url="u"
        )
    notifications.send_email_change_confirmation(runtime(), recipient=TO, confirmation_url="u")


@pytest.mark.parametrize(
    "send,method,message",
    [
        (
            notifications.send_email_change_requested_notice,
            "send_email_change_requested_notice",
            "email-change notice",
        ),
        (
            notifications.send_contact_change_notice,
            "send_contact_change_notice",
            "contact-change email",
        ),
    ],
)
def test_an_advisory_notice_is_sent_where_it_can_be_and_refused_outside_development(
    send, method, message
):
    sender = Sender(method)
    send(runtime(email=sender), recipient=TO, locale="de")
    assert sender.calls == [(method, {"recipient": TO, "locale": "de"})]
    # Not configured, or a sender that predates the notice: quiet in development only.
    for development in (True, False):
        for email in (None, Sender()):
            if development:
                send(runtime(email=email, development=True), recipient=TO)
            else:
                with pytest.raises(PortalEmailDeliveryError, match=message):
                    send(runtime(email=email, development=False), recipient=TO)


def test_a_delivery_outcome_is_recorded_and_committed(monkeypatch):
    seen = []
    monkeypatch.setattr(
        notifications,
        "record_mfa_delivery_outcome",
        lambda session, *, delivery, outcome: seen.append(("record", delivery, outcome)),
    )
    session = SimpleNamespace(commit=lambda: seen.append(("commit",)))
    notifications.record_mfa_delivery_and_commit(session, delivery="d", outcome="failure")
    assert seen == [("record", "d", "failure"), ("commit",)]


def test_an_smtp_sender_needs_a_host_and_a_from_address():
    with pytest.raises(ValueError, match="SMTP host and from address are required"):
        SmtpPortalEmailSender(
            SimpleNamespace(smtp_host=None, resolved_smtp_from_address="a@b.test")
        )
    with pytest.raises(ValueError, match="SMTP host and from address are required"):
        SmtpPortalEmailSender(
            SimpleNamespace(smtp_host="smtp.test", resolved_smtp_from_address=None)
        )
