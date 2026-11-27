"""The development mail outbox (#135): where a development portal's "sent" email goes.

A development portal prints no sign-in code and returns none, so with no SMTP host it writes each
outgoing email to a private file. FAKE and synthetic values only.
"""

import json
import os
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal.email_delivery import (
    DevelopmentOutboxEmailSender,
    PortalEmailDeliveryError,
    SmtpPortalEmailSender,
    build_portal_email_sender,
)
from tests.support import (
    STRONG_PASSWORD,
    activate_seeded_patient_account,
    development_settings,
    migrated_development_app,
    production_settings,
)


def lines(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def outbox_settings(tmp_path: Path, **overrides: object):
    return development_settings(
        development_mail_outbox=True,
        development_mail_outbox_path=tmp_path / "outbox.jsonl",
        **overrides,
    )


def test_each_kind_of_message_is_one_json_line_with_its_secret_and_no_other(tmp_path) -> None:
    settings = outbox_settings(tmp_path)
    sender = build_portal_email_sender(settings)
    assert isinstance(sender, DevelopmentOutboxEmailSender)

    sender.send_code(recipient="fake@example.test", code="123456", expires_in_seconds=600)
    sender.send_password_reset(
        recipient="fake@example.test",
        reset_url="https://portal.example.test/auth/password-reset/complete#token=FAKE",
        expires_in_seconds=900,
        message_id="FAKE-id",
    )
    sender.send_contact_change_notice(recipient="fake@example.test")
    sender.send_booking_prompt_notice(recipient="fake@example.test", sign_in_url="https://p/x")
    sender.send_booking_prompt_update_notice(
        recipient="fake@example.test", sign_in_url="https://p/y"
    )
    sender.send_email_change_confirmation(
        recipient="fake@example.test", confirmation_url="https://p/c#token=Z", expires_in_seconds=60
    )
    sender.send_email_change_requested_notice(recipient="fake@example.test")

    records = lines(settings.resolved_development_mail_outbox_path)
    assert [record["kind"] for record in records] == [
        "mfa_code",
        "password_reset",
        "contact_change_notice",
        "booking_prompt_notice",
        "booking_prompt_update_notice",
        "email_change_confirmation",
        "email_change_requested_notice",
    ]
    assert all(record["recipient"] == "fake@example.test" and record["at"] for record in records)
    assert records[0]["code"] == "123456" and records[0]["expires_in_seconds"] == 600
    assert records[1]["reset_url"].endswith("#token=FAKE")
    assert records[5]["confirmation_url"] == "https://p/c#token=Z"
    # A notice carries no secret at all.
    assert set(records[2]) == {"at", "kind", "recipient"}


def test_the_file_is_private_and_appended_to_not_replaced(tmp_path) -> None:
    settings = outbox_settings(tmp_path)
    sender = build_portal_email_sender(settings)
    sender.send_code(recipient="a@example.test", code="111111", expires_in_seconds=60)
    sender.send_code(recipient="b@example.test", code="222222", expires_in_seconds=60)

    path = settings.resolved_development_mail_outbox_path
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [record["code"] for record in lines(path)] == ["111111", "222222"]


def test_a_link_in_place_of_the_file_is_not_followed(tmp_path) -> None:
    target = tmp_path / "elsewhere.txt"
    target.write_text("untouched", encoding="utf-8")
    settings = outbox_settings(tmp_path)
    os.symlink(target, settings.resolved_development_mail_outbox_path)
    sender = build_portal_email_sender(settings)

    with pytest.raises(PortalEmailDeliveryError):
        sender.send_code(recipient="a@example.test", code="111111", expires_in_seconds=60)
    assert target.read_text(encoding="utf-8") == "untouched"


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="owner and mode bits need POSIX")
def test_a_file_that_is_not_private_is_refused_and_never_written(tmp_path, caplog) -> None:
    # The default path is a fixed name in the shared temp directory: another user can create it
    # first, readable by everyone. O_NOFOLLOW stops a link, not that. Only a regular file that is
    # this user's alone is written to.
    settings = outbox_settings(tmp_path)
    path = settings.resolved_development_mail_outbox_path
    sender = build_portal_email_sender(settings)
    path.write_text("planted\n", encoding="utf-8")
    for mode in (0o644, 0o640, 0o660, 0o602):
        os.chmod(path, mode)
        with caplog.at_level("WARNING"), pytest.raises(PortalEmailDeliveryError):
            sender.send_code(recipient="a@example.test", code="654321", expires_in_seconds=60)
        assert path.read_text(encoding="utf-8") == "planted\n", oct(mode)
    # The warning names the file and says why; it never carries the code or the address.
    assert "not a private file" in caplog.text and str(path) in caplog.text
    assert "654321" not in caplog.text and "a@example.test" not in caplog.text
    # A private file of ours that was there already is appended to, not refused.
    os.chmod(path, 0o600)
    sender.send_code(recipient="a@example.test", code="654321", expires_in_seconds=60)
    assert path.read_text(encoding="utf-8").startswith("planted\n")
    assert json.loads(path.read_text(encoding="utf-8").splitlines()[-1])["code"] == "654321"


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root, to give a file away"
)
def test_a_private_file_owned_by_someone_else_is_refused(tmp_path) -> None:
    settings = outbox_settings(tmp_path)
    path = settings.resolved_development_mail_outbox_path
    path.write_text("theirs\n", encoding="utf-8")
    os.chmod(path, 0o600)
    os.chown(path, 65534, 65534)
    with pytest.raises(PortalEmailDeliveryError):
        build_portal_email_sender(settings).send_code(
            recipient="a@example.test", code="654321", expires_in_seconds=60
        )
    assert path.read_text(encoding="utf-8") == "theirs\n"


def test_a_directory_in_place_of_the_file_is_refused(tmp_path) -> None:
    settings = outbox_settings(tmp_path)
    settings.resolved_development_mail_outbox_path.mkdir()
    with pytest.raises(PortalEmailDeliveryError):
        build_portal_email_sender(settings).send_code(
            recipient="a@example.test", code="654321", expires_in_seconds=60
        )


def test_a_path_that_cannot_be_written_is_a_delivery_error(tmp_path) -> None:
    sender = build_portal_email_sender(outbox_settings(tmp_path / "no-such-directory"))
    with pytest.raises(PortalEmailDeliveryError):
        sender.send_code(recipient="a@example.test", code="111111", expires_in_seconds=60)


def test_the_outbox_is_for_development_and_nothing_else(tmp_path) -> None:
    # Not built outside development, by the sender itself or by the builder.
    with pytest.raises(ValueError, match="only for development"):
        DevelopmentOutboxEmailSender(production_settings())
    assert build_portal_email_sender(production_settings()) is not None  # the SMTP sender
    # A path for it is a configuration error outside development.
    with pytest.raises(ValueError, match="only for development"):
        production_settings(development_mail_outbox_path=tmp_path / "outbox.jsonl")


def test_the_builder_picks_the_sender_by_what_is_configured(tmp_path) -> None:
    assert isinstance(
        build_portal_email_sender(outbox_settings(tmp_path)), DevelopmentOutboxEmailSender
    )
    # Switched off, a development portal with no SMTP host has no sender, as before.
    assert build_portal_email_sender(development_settings(development_mail_outbox=False)) is None
    # An SMTP host wins: the test inbox gets the mail and no file is written.
    smtp = build_portal_email_sender(
        outbox_settings(tmp_path, smtp_host="127.0.0.1", smtp_port=8463)
    )
    assert isinstance(smtp, SmtpPortalEmailSender)
    assert not (tmp_path / "outbox.jsonl").exists()


def test_a_development_sign_in_is_completed_with_the_code_from_the_file(tmp_path) -> None:
    path = tmp_path / "outbox.jsonl"
    app = migrated_development_app(development_mail_outbox=True, development_mail_outbox_path=path)
    client = TestClient(app)
    activate_seeded_patient_account(app, client)

    login = client.post(
        "/auth/login", json={"username": "patient.user", "password": STRONG_PASSWORD}
    )
    assert login.status_code == 200
    # Nothing in the answer carries the code ...
    codes = [r["code"] for r in lines(path) if r["kind"] == "mfa_code"]
    assert len(codes) == 1
    assert codes[0] not in login.text
    assert "development_mfa_code" not in login.json()
    # ... and the code in the file is the one the portal expects.
    verified = client.post(
        "/auth/mfa/verify",
        json={"mfa_challenge_token": login.json()["mfa_challenge_token"], "code": codes[0]},
    )
    assert verified.status_code == 200
    assert verified.json()["session_token"]
