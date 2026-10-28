import logging
import smtplib
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser

import pytest

from carlos_patient_portal import footer_audit
from carlos_patient_portal.clinic_footer import FOOTER_FAILURE_REASONS, ClinicFooterUnavailableError
from carlos_patient_portal.config import Settings
from carlos_patient_portal.email_delivery import (
    PortalEmailDeliveryError,
    PortalEmailFooterUnavailableError,
    SmtpPortalEmailSender,
)
from carlos_patient_portal.footer_audit import FooterAuditStore
from carlos_patient_portal.outbound_messages import contact_change_email_message
from tests.footer_support import FakeFooterProvider, fake_footer


class RecordingSmtp:
    messages = []
    instances = 0
    failure = None
    quit_failure = False
    refused = False
    before_connect = None

    def __init__(self, **kwargs):
        type(self).instances += 1
        if self.before_connect is not None:
            type(self).before_connect()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self.quit_failure:
            raise OSError("FAKE connection close failure")

    def starttls(self, **kwargs):
        pass

    def login(self, *args):
        pass

    def send_message(self, message):
        type(self).messages.append(
            BytesParser(policy=policy.default).parsebytes(message.as_bytes())
        )
        if self.failure is not None:
            raise self.failure
        return {"fake.patient@example.test": (550, b"FAKE refused")} if self.refused else {}


@pytest.fixture
def delivery(monkeypatch, tmp_path):
    tmp_path.chmod(0o700)
    RecordingSmtp.messages = []
    RecordingSmtp.instances = 0
    RecordingSmtp.failure = None
    RecordingSmtp.quit_failure = False
    RecordingSmtp.refused = False
    RecordingSmtp.before_connect = None
    monkeypatch.setattr(smtplib, "SMTP", RecordingSmtp)
    settings = Settings(
        environment="development", clinic_id="default", smtp_host="fake-smtp.internal"
    )
    provider = FakeFooterProvider(fake_footer())
    audit = FooterAuditStore(str(tmp_path), settings.clinic_id)
    sender = SmtpPortalEmailSender(settings, footer_provider=provider, footer_audit=audit)
    return sender, provider, audit


OPERATIONS = [
    ("send_code", "mfa", {"code": "FAKE-code", "expires_in_seconds": 600}),
    (
        "send_password_reset",
        "password_reset",
        {"reset_url": "https://portal.example.test/#FAKE-reset-token", "expires_in_seconds": 600},
    ),
    ("send_contact_change_notice", "contact_change", {}),
    (
        "send_booking_prompt_notice",
        "booking_prompt",
        {"sign_in_url": "https://portal.example.test/auth/sign-in"},
    ),
    (
        "send_booking_prompt_update_notice",
        "booking_prompt_update",
        {"sign_in_url": "https://portal.example.test/auth/sign-in"},
    ),
    (
        "send_email_change_confirmation",
        "email_change_confirmation",
        {
            "confirmation_url": "https://portal.example.test/#FAKE-change-token",
            "expires_in_seconds": 600,
        },
    ),
    ("send_email_change_requested_notice", "email_change_requested", {}),
]


def attempts(audit):
    return audit.list_attempts(day=datetime.now(UTC).date().isoformat())["attempts"]


@pytest.mark.parametrize("method,kind,arguments", OPERATIONS)
def test_all_seven_real_smtp_methods_send_frozen_clinic_plain_html_and_inline_logo(
    delivery, tmp_path, method, kind, arguments
):
    sender, provider, audit = delivery

    def durable_before_connect():
        evidence = attempts(audit)
        assert len(evidence) == 1
        assert evidence[0]["status"] == "prepared"

    RecordingSmtp.before_connect = durable_before_connect
    getattr(sender, method)(recipient="fake.patient@example.test", **arguments)
    assert provider.calls == 1
    assert RecordingSmtp.instances == 1
    message = RecordingSmtp.messages[0]
    plain = message.get_body(preferencelist=("plain",)).get_content()
    html = message.get_body(preferencelist=("html",)).get_content()
    assert plain.rstrip().endswith(provider.current.plain)
    assert html.index("cid:" + provider.current.logo.content_id) < html.index(provider.current.html)
    images = [part for part in message.walk() if part.get_content_maintype() == "image"]
    assert len(images) == 1
    assert images[0]["Content-ID"] == "<" + provider.current.logo.content_id + ">"
    assert images[0].get_content() == provider.current.logo.data
    evidence = attempts(audit)[0]
    assert evidence["kind"] == kind
    assert evidence["status"] == "accepted"
    assert evidence["footer_text"] == provider.current.plain
    assert evidence["footer_skipped"] is None
    saved = b"".join(p.read_bytes() for p in tmp_path.rglob("*.json"))
    assert b"fake.patient@example.test" not in saved
    assert b"FAKE-code" not in saved
    assert b"FAKE-reset-token" not in saved
    assert b"FAKE-change-token" not in saved


def test_footer_unavailable_refuses_before_audit_or_smtp(delivery, monkeypatch, tmp_path):
    sender, provider, audit = delivery

    def unavailable():
        raise ClinicFooterUnavailableError("clinic email footer is unavailable")

    monkeypatch.setattr(provider, "snapshot", unavailable)
    # Not a sign-in code or reset: those go out without the footer instead (D138).
    with pytest.raises(PortalEmailDeliveryError, match="^portal email delivery failed$"):
        sender.send_contact_change_notice(recipient="fake.patient@example.test")
    assert RecordingSmtp.instances == 0
    assert list(tmp_path.iterdir()) == []


def test_missing_configuration_has_no_footerless_development_bypass(monkeypatch):
    RecordingSmtp.instances = 0
    monkeypatch.setattr(smtplib, "SMTP", RecordingSmtp)
    sender = SmtpPortalEmailSender(
        Settings(environment="development", smtp_host="fake-smtp.internal")
    )
    with pytest.raises(PortalEmailDeliveryError):
        sender.send_code(
            recipient="fake.patient@example.test", code="FAKE-code", expires_in_seconds=600
        )
    assert RecordingSmtp.instances == 0


def test_durable_audit_failure_refuses_before_any_smtp(delivery, monkeypatch):
    sender, _, audit = delivery

    def disk_full(*args):
        raise OSError("FAKE disk unavailable")

    monkeypatch.setattr(audit, "prepare", disk_full)
    with pytest.raises(PortalEmailDeliveryError):
        sender.send_contact_change_notice(recipient="fake.patient@example.test")
    assert RecordingSmtp.instances == 0


def test_actual_fsync_failure_prevents_smtp(delivery, monkeypatch):
    sender, _, _ = delivery

    def failed_sync(fd):
        raise OSError("FAKE fsync unavailable")

    monkeypatch.setattr(footer_audit.os, "fsync", failed_sync)
    with pytest.raises(PortalEmailDeliveryError):
        sender.send_contact_change_notice(recipient="fake.patient@example.test")
    assert RecordingSmtp.instances == 0


def test_file_and_parent_directory_synced_before_smtp(delivery, monkeypatch):
    sender, _, _ = delivery
    sync = footer_audit.os.fsync
    link = footer_audit.os.link
    events = []

    def recorded_sync(fd):
        import stat

        events.append(
            "file-sync" if stat.S_ISREG(footer_audit.os.fstat(fd).st_mode) else "directory-sync"
        )
        sync(fd)

    def recorded_link(*args, **kwargs):
        events.append("publish")
        link(*args, **kwargs)

    monkeypatch.setattr(footer_audit.os, "fsync", recorded_sync)
    monkeypatch.setattr(footer_audit.os, "link", recorded_link)

    def check_sync():
        assert events[-4:] == ["file-sync", "publish", "directory-sync", "directory-sync"]

    RecordingSmtp.before_connect = check_sync
    sender.send_contact_change_notice(recipient="fake.patient@example.test")


def test_admin_change_after_durable_prepare_keeps_old_capture_and_audit_then_new_attempt_current(
    delivery, monkeypatch
):
    sender, provider, audit = delivery
    old = provider.current
    newer = fake_footer(text="FAKE New Clinic", logo=False)
    prepare = audit.prepare

    def prepare_then_change(snapshot, kind):
        attempt = prepare(snapshot, kind)
        provider.current = newer
        return attempt

    monkeypatch.setattr(audit, "prepare", prepare_then_change)
    sender.send_contact_change_notice(recipient="fake.patient@example.test")
    first = RecordingSmtp.messages[0]
    assert first.get_body(preferencelist=("plain",)).get_content().rstrip().endswith(old.plain)
    assert old.html in first.get_body(preferencelist=("html",)).get_content()
    assert attempts(audit)[0]["revision"] == old.revision
    sender.send_contact_change_notice(recipient="fake.patient@example.test")
    second = RecordingSmtp.messages[1]
    assert second.get_body(preferencelist=("plain",)).get_content().rstrip().endswith(newer.plain)
    assert not any(p.get_content_maintype() == "image" for p in second.walk())
    assert {a["revision"] for a in attempts(audit)} == {old.revision, newer.revision}
    assert provider.calls == 2


def test_confirmed_smtp_acceptance_survives_quit_failure(delivery):
    sender, _, audit = delivery
    RecordingSmtp.quit_failure = True
    sender.send_contact_change_notice(recipient="fake.patient@example.test")
    assert len(RecordingSmtp.messages) == 1
    assert attempts(audit)[0]["status"] == "accepted"


def test_confirmed_acceptance_survives_any_outcome_bookkeeping_failure(
    delivery, monkeypatch, caplog
):
    sender, _, audit = delivery

    def unavailable(*args):
        raise RuntimeError("FAKE bookkeeping unavailable")

    monkeypatch.setattr(audit, "record_outcome", unavailable)
    sender.send_code(
        recipient="fake.patient@example.test", code="FAKE-code", expires_in_seconds=600
    )
    assert len(RecordingSmtp.messages) == 1
    assert attempts(audit)[0]["status"] == "prepared"
    assert "FAKE-code" not in caplog.text
    assert "fake.patient@example.test" not in caplog.text


@pytest.mark.parametrize(
    "failure,status",
    [
        (OSError("FAKE interrupted SMTP"), "unknown"),
        (smtplib.SMTPDataError(550, b"FAKE rejected"), "failed"),
        (RuntimeError("FAKE unclassified transfer failure"), "unknown"),
    ],
)
def test_attempt_outcomes_distinguish_definite_refusal_from_unconfirmed_transfer(
    delivery, failure, status
):
    sender, _, audit = delivery
    RecordingSmtp.failure = failure
    with pytest.raises(PortalEmailDeliveryError):
        sender.send_contact_change_notice(recipient="fake.patient@example.test")
    assert attempts(audit)[0]["status"] == status


def test_refused_recipient_records_failure(delivery):
    sender, _, audit = delivery
    RecordingSmtp.refused = True
    with pytest.raises(PortalEmailDeliveryError):
        sender.send_contact_change_notice(recipient="fake.patient@example.test")
    assert attempts(audit)[0]["status"] == "failed"


@pytest.mark.parametrize("reason", sorted(FOOTER_FAILURE_REASONS))
def test_footer_failure_logs_and_records_its_fixed_reason(delivery, monkeypatch, caplog, reason):
    sender, provider, _ = delivery

    def unavailable():
        raise ClinicFooterUnavailableError(reason)

    monkeypatch.setattr(provider, "snapshot", unavailable)
    with caplog.at_level(logging.WARNING, logger="carlos_patient_portal.email_delivery"):
        with pytest.raises(PortalEmailFooterUnavailableError) as failure:
            sender.send_contact_change_notice(recipient="fake.patient@example.test")
    assert isinstance(failure.value, PortalEmailDeliveryError)
    assert str(failure.value) == "portal email delivery failed"
    assert failure.value.failure_code == "clinic_footer_" + reason
    assert [record.getMessage() for record in caplog.records] == [
        f"Portal email not sent: clinic footer unavailable (reason={reason})"
    ]
    assert RecordingSmtp.instances == 0


def test_audit_and_message_failures_have_their_own_reasons(delivery, monkeypatch, caplog):
    sender, _, audit = delivery

    def disk_full(*args):
        raise OSError("FAKE disk unavailable at /secret/path")

    monkeypatch.setattr(audit, "prepare", disk_full)
    with caplog.at_level(logging.WARNING, logger="carlos_patient_portal.email_delivery"):
        with pytest.raises(PortalEmailFooterUnavailableError) as failure:
            sender.send_contact_change_notice(recipient="fake.patient@example.test")
    assert failure.value.failure_code == "clinic_footer_audit"
    assert "reason=audit" in caplog.text
    assert "FAKE" not in caplog.text and "fake.patient" not in caplog.text
    assert RecordingSmtp.instances == 0


# Ben's D138 on #27: while the clinic footer is unavailable, ONLY sign-in/MFA codes and password
# resets go out, without the footer. Every other email still fails closed.
FOOTER_OPTIONAL = OPERATIONS[:2]
FOOTER_REQUIRED = OPERATIONS[2:]


@pytest.mark.parametrize("reason", sorted(FOOTER_FAILURE_REASONS))
def test_sign_in_codes_and_resets_go_out_without_footer_during_an_outage(
    delivery, monkeypatch, caplog, reason
):
    sender, provider, audit = delivery

    def unavailable():
        raise ClinicFooterUnavailableError(reason)

    monkeypatch.setattr(provider, "snapshot", unavailable)
    with caplog.at_level(logging.WARNING, logger="carlos_patient_portal.email_delivery"):
        for method, _, arguments in FOOTER_OPTIONAL:
            getattr(sender, method)(recipient="fake.patient@example.test", **arguments)
    assert RecordingSmtp.instances == 2
    for message in RecordingSmtp.messages:
        assert not message.is_multipart()  # plain text only: no HTML part, no logo
        assert fake_footer().plain not in message.get_content()
    assert "FAKE-code" in RecordingSmtp.messages[0].get_content()
    assert "FAKE-reset-token" in RecordingSmtp.messages[1].get_content()
    evidence = {item["kind"]: item for item in attempts(audit)}
    assert set(evidence) == {"mfa", "password_reset"}
    for item in evidence.values():
        assert item["status"] == "accepted"
        assert item["footer_skipped"] == reason
        assert (item["revision"], item["footer_text"], item["logo_sha256"]) == (None, None, None)
    assert [record.getMessage() for record in caplog.records] == [
        f"Portal email sent without footer: clinic footer unavailable (reason={reason})"
    ] * 2


@pytest.mark.parametrize("method,kind,arguments", FOOTER_REQUIRED)
def test_every_other_email_still_fails_closed_during_an_outage(
    delivery, monkeypatch, method, kind, arguments
):
    sender, provider, audit = delivery

    def unavailable():
        raise ClinicFooterUnavailableError("signature")

    monkeypatch.setattr(provider, "snapshot", unavailable)
    with pytest.raises(PortalEmailFooterUnavailableError) as failure:
        getattr(sender, method)(recipient="fake.patient@example.test", **arguments)
    assert failure.value.failure_code == "clinic_footer_signature"
    assert RecordingSmtp.instances == 0
    assert attempts(audit) == []


@pytest.mark.parametrize("method,kind,arguments", FOOTER_OPTIONAL)
def test_codes_and_resets_still_need_the_audit_record(
    delivery, monkeypatch, method, kind, arguments
):
    sender, provider, audit = delivery

    def unavailable():
        raise ClinicFooterUnavailableError("transport")

    def disk_full(*args):
        raise OSError("FAKE disk unavailable")

    monkeypatch.setattr(provider, "snapshot", unavailable)
    monkeypatch.setattr(audit, "prepare_skipped", disk_full)
    with pytest.raises(PortalEmailFooterUnavailableError) as failure:
        getattr(sender, method)(recipient="fake.patient@example.test", **arguments)
    assert failure.value.failure_code == "clinic_footer_audit"
    assert RecordingSmtp.instances == 0


def test_only_the_two_named_senders_may_skip_the_footer(delivery):
    sender, _, _ = delivery
    content = contact_change_email_message(service_name="FAKE Portal", clinic_name="FAKE Clinic")
    draft = sender._build_message("fake.patient@example.test", content, kind="contact_change")
    with pytest.raises(ValueError, match="only sign-in codes and password resets"):
        sender._send_message(draft, footer_optional=True)
    assert RecordingSmtp.instances == 0
