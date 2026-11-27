"""The development mail outbox as CI meets it (#135): a development portal with no settings at all.

CI's browser step starts the portal in development with no SMTP host and none of the outbox
settings, and workflow files are not ours to change. So with nothing set, a development portal
must write its email to the file the browser checks look for on their own. FAKE values only.
"""

import json
import re
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal.config import Settings
from carlos_patient_portal.email_delivery import (
    DevelopmentOutboxEmailSender,
    build_portal_email_sender,
)
from tests.support import (
    STRONG_PASSWORD,
    activate_seeded_patient_account,
    migrated_development_app,
)

OUTBOX_NAME = "patient-portal-development-mail.jsonl"
REPOSITORY = Path(__file__).resolve().parent.parent


@pytest.fixture
def temp_directory(tmp_path, monkeypatch):
    """The system temp directory, moved, as `tempfile` and Node's `os.tmpdir()` both read it."""
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setattr(tempfile, "tempdir", None)
    return tmp_path


def test_a_development_portal_with_no_settings_has_the_outbox_on_and_in_the_temp_directory(
    temp_directory,
) -> None:
    settings = Settings(environment="development")

    assert settings.smtp_host is None
    assert settings.development_mail_outbox is True
    assert settings.development_mail_outbox_path is None
    assert settings.resolved_development_mail_outbox_path == temp_directory / OUTBOX_NAME
    assert isinstance(build_portal_email_sender(settings), DevelopmentOutboxEmailSender)


def test_the_browser_checks_look_for_the_file_the_portal_writes() -> None:
    # The Python and the Node side name the same file in the temp directory: a rename in one
    # without the other would leave CI's first sign-in waiting for a code that never comes.
    reader = (REPOSITORY / "scripts" / "patient-portal-mail-capture.js").read_text(encoding="utf-8")
    assert re.search(r"path\.join\(os\.tmpdir\(\), '" + re.escape(OUTBOX_NAME) + r"'\)", reader)
    assert Settings(environment="development").resolved_development_mail_outbox_path.name == (
        OUTBOX_NAME
    )


def test_ci_shape_one_sign_in_and_the_code_is_in_the_default_file(temp_directory) -> None:
    # A development app, the outbox settings left at their defaults, no sender brought along.
    app = migrated_development_app(development_mail_outbox=True)
    client = TestClient(app)
    activate_seeded_patient_account(app, client)

    login = client.post(
        "/auth/login", json={"username": "patient.user", "password": STRONG_PASSWORD}
    )
    assert login.status_code == 200

    default_file = temp_directory / OUTBOX_NAME
    records = [json.loads(line) for line in default_file.read_text(encoding="utf-8").splitlines()]
    codes = [record["code"] for record in records if record["kind"] == "mfa_code"]
    assert len(codes) == 1 and re.fullmatch(r"\d{6}", codes[0])
    verified = client.post(
        "/auth/mfa/verify",
        json={"mfa_challenge_token": login.json()["mfa_challenge_token"], "code": codes[0]},
    )
    assert verified.status_code == 200
