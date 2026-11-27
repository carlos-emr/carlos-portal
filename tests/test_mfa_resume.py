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

"""Signing in again inside the code-send cooldown returns to the pending code page (#147).

After a sign-in code is sent, "Back to sign in" and signing in again used to be refused with "a
code was sent recently", although the sent code was still valid and there was no way back to the
page that accepts it. The cooldown stays (no extra code is ever sent inside it); a correct
password with the pending challenge named by a short-lived cookie resumes that challenge instead.
"""

import re
from datetime import UTC, timedelta

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from fastapi import Response
from fastapi.testclient import TestClient
from markupsafe import escape
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal import auth, web_support
from carlos_patient_portal.config import Settings
from carlos_patient_portal.i18n import LOCALE_COOKIE_NAME, SUPPORTED_LOCALES, portal_text
from carlos_patient_portal.models import (
    AUDIT_EVENT_MFA_CHALLENGE,
    AUDIT_OUTCOME_RESUMED,
    AUDIT_OUTCOME_THROTTLED,
    MFA_CHALLENGE_STATUS_CANCELLED,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalMfaChallenge,
    utc_now,
)
from carlos_patient_portal.token_keys import PortalTokenKeys
from tests.support import (
    CSRF_TOKEN_PATTERN,
    DEVELOPMENT_MFA_CODE_PATTERN,
    MFA_CHALLENGE_TOKEN_PATTERN,
    STRONG_PASSWORD,
    RecordingPortalEmailSender,
    activate_seeded_patient_account,
    get_csrf_token,
    migrated_development_app,
    non_development_settings_values,
)
from tests.test_mycarlos_availability_store import migrated  # noqa: F401

PENDING_COOKIE = web_support.MFA_PENDING_COOKIE_NAME


def form_sign_in(client: TestClient):
    """Sign in through the browser form, as the patient does after "Back to sign in"."""
    return client.post(
        "/auth/login",
        data={
            "csrf_token": get_csrf_token(client),
            "username": "patient.user",
            "password": STRONG_PASSWORD,
        },
    )


def first_sign_in(client: TestClient):
    """The first sign-in: a code is sent and the code page is shown; returns the page and values."""
    response = form_sign_in(client)
    assert response.status_code == 200
    token = MFA_CHALLENGE_TOKEN_PATTERN.search(response.text)
    code = DEVELOPMENT_MFA_CODE_PATTERN.search(response.text)
    # The development code line is English text: other languages' pages do not carry it.
    assert token is not None
    return response, token.group(1), code.group(1) if code is not None else ""


def challenge_and_account(app) -> tuple[PatientPortalMfaChallenge, PatientPortalAccount]:
    with app.state.session_factory() as session:
        challenge = session.scalar(select(PatientPortalMfaChallenge))
        account = session.scalar(select(PatientPortalAccount))
        assert challenge is not None and account is not None
        session.expunge_all()
        return challenge, account


def test_the_code_page_remembers_its_challenge_in_a_strict_httponly_cookie() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)

    page, token, _code = first_sign_in(client)

    set_cookies = [
        value for key, value in page.headers.multi_items() if key.lower() == "set-cookie"
    ]
    pending = [value for value in set_cookies if value.startswith(f"{PENDING_COOKIE}=")]
    assert len(pending) == 1
    assert pending[0].startswith(f"{PENDING_COOKIE}={token};")
    assert "HttpOnly" in pending[0]
    assert "SameSite=strict" in pending[0]
    assert "Path=/auth" in pending[0]
    # It lives no longer than the challenge (the development code lifetime is minutes, not hours).
    max_age = int(re.search(r"Max-Age=(\d+)", pending[0]).group(1))  # type: ignore[union-attr]
    assert 0 < max_age <= 3600
    assert client.cookies.get(PENDING_COOKIE) == token


def test_signing_in_again_inside_the_cooldown_resumes_the_page_and_the_old_code_verifies() -> None:
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(email_sender=sender)
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    _page, token, code = first_sign_in(client)
    assert len(sender.messages) == 1

    again = form_sign_in(client)

    # Back on the code page of the SAME challenge, saying when the code was sent; no refusal, no
    # Retry-After, and no second message.
    assert again.status_code == 200
    assert "retry-after" not in again.headers
    assert 'name="mfa_challenge_token"' in again.text
    assert MFA_CHALLENGE_TOKEN_PATTERN.search(again.text).group(1) == token  # type: ignore[union-attr]
    challenge, _account = challenge_and_account(app)
    sent_at = challenge.created_at.strftime("%H:%M")
    assert str(escape(portal_text("en")["mfa_resumed_notice"].format(time=sent_at))) in again.text
    assert len(sender.messages) == 1

    # The code that was sent before still opens the sign-in; the pending cookie is then cleared.
    csrf = CSRF_TOKEN_PATTERN.search(again.text)
    assert csrf is not None
    verified = client.post(
        "/auth/mfa/verify",
        data={"csrf_token": csrf.group(1), "mfa_challenge_token": token, "code": code},
        follow_redirects=False,
    )
    assert verified.status_code == 303
    cleared = [
        value
        for key, value in verified.headers.multi_items()
        if key.lower() == "set-cookie" and value.startswith(f"{PENDING_COOKIE}=")
    ]
    assert len(cleared) == 1
    assert "Max-Age=0" in cleared[0] or "expires=" in cleared[0].lower()
    assert client.cookies.get(PENDING_COOKIE) is None


def test_resuming_resets_no_limit_and_does_not_extend_the_challenge() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    page, token, code = first_sign_in(client)
    wrong = "000000" if code != "000000" else "111111"
    csrf = CSRF_TOKEN_PATTERN.search(page.text)
    assert csrf is not None
    failed = client.post(
        "/auth/mfa/verify",
        data={"csrf_token": csrf.group(1), "mfa_challenge_token": token, "code": wrong},
    )
    assert failed.status_code == 401
    before_challenge, before_account = challenge_and_account(app)
    assert before_challenge.failed_attempts == 1
    assert before_account.failed_mfa_count == 1

    resumed = form_sign_in(client)

    assert resumed.status_code == 200
    after_challenge, after_account = challenge_and_account(app)
    # The code-guess budget, the expiry, the status and the send reservation are all untouched.
    assert after_challenge.id == before_challenge.id
    assert after_challenge.failed_attempts == 1
    assert after_account.failed_mfa_count == 1
    assert after_challenge.expires_at == before_challenge.expires_at
    assert after_challenge.status == before_challenge.status
    assert after_challenge.code_hash == before_challenge.code_hash
    assert after_account.last_mfa_email_sent_at == before_account.last_mfa_email_sent_at
    with app.state.session_factory() as session:
        assert len(list(session.scalars(select(PatientPortalMfaChallenge)))) == 1


def test_without_the_cookie_the_refusal_and_retry_after_are_unchanged() -> None:
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(email_sender=sender)
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    first_sign_in(client)
    client.cookies.delete(PENDING_COOKIE, path="/auth")
    assert client.cookies.get(PENDING_COOKIE) is None

    refused = form_sign_in(client)

    assert refused.status_code == 429
    assert refused.headers["retry-after"] == "60"
    assert "A code was sent recently. Try again in 60 seconds." in refused.text
    assert len(sender.messages) == 1


@pytest.mark.parametrize("stale", ["expired", "cancelled", "unknown_token"])
def test_a_stale_cookie_keeps_the_refusal_and_is_cleared(stale: str) -> None:
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(email_sender=sender)
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    first_sign_in(client)
    if stale == "unknown_token":
        client.cookies.set(PENDING_COOKIE, "x" * 43, path="/auth")
    else:
        with app.state.session_factory() as session:
            challenge = session.scalar(select(PatientPortalMfaChallenge))
            assert challenge is not None
            if stale == "expired":
                # Both in the past (the table requires expires_at > created_at).
                challenge.created_at = utc_now() - timedelta(minutes=30)
                challenge.expires_at = utc_now() - timedelta(minutes=29)
            else:
                challenge.status = MFA_CHALLENGE_STATUS_CANCELLED
            session.commit()

    refused = form_sign_in(client)

    assert refused.status_code == 429
    assert refused.headers["retry-after"] == "60"
    assert len(sender.messages) == 1
    cleared = [
        value
        for key, value in refused.headers.multi_items()
        if key.lower() == "set-cookie" and value.startswith(f"{PENDING_COOKIE}=")
    ]
    assert len(cleared) == 1
    assert "Max-Age=0" in cleared[0] or "expires=" in cleared[0].lower()


def test_another_accounts_challenge_or_method_is_not_resumed() -> None:
    app = migrated_development_app(session_secret="t" * 32)
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    _page, token, _code = first_sign_in(client)
    challenge, account = challenge_and_account(app)
    session_secret = app.state.settings.session_secret
    assert session_secret is not None
    secret = PortalTokenKeys.derive(session_secret.get_secret_value()).mfa
    now = utc_now().astimezone(UTC)

    def resume(candidate: PatientPortalAccount, method: str):
        with app.state.session_factory() as session:
            return auth.resume_pending_mfa_challenge(
                session,
                candidate,
                delivery_method=method,
                challenge_token=token,
                challenge_token_secret=secret,
                allow_email=True,
                now=now,
            )

    assert resume(account, "email") is not None
    # A different account (another id), however the token came to be in the browser:
    other = PatientPortalAccount(id=account.id + 1, username="someone.else")
    assert resume(other, "email") is None
    # The cooldown is per delivery method: a challenge sent by email is not a pending SMS one.
    assert resume(account, "sms") is None
    # A resumed delivery sends nothing: it carries no live code.
    resumed = resume(account, "email")
    assert resumed is not None
    assert resumed.code == ""
    assert resumed.resumed_sent_at == challenge.created_at


def test_the_resume_is_audited_as_its_own_outcome_without_secrets() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    _page, token, code = first_sign_in(client)
    refused_client = TestClient(app)  # a browser without the cookie: today's throttled refusal
    form_sign_in(refused_client)

    form_sign_in(client)

    with app.state.session_factory() as session:
        events = list(
            session.scalars(
                select(PatientPortalAuditEvent).where(
                    PatientPortalAuditEvent.event_type == AUDIT_EVENT_MFA_CHALLENGE
                )
            )
        )
    outcomes = [event.outcome for event in events]
    assert outcomes.count(AUDIT_OUTCOME_RESUMED) == 1
    assert outcomes.count(AUDIT_OUTCOME_THROTTLED) == 1
    resumed = next(event for event in events if event.outcome == AUDIT_OUTCOME_RESUMED)
    assert resumed.reason == "email"
    # No code, token, address or password in the row.
    row = " ".join(
        str(getattr(resumed, column.name)) for column in PatientPortalAuditEvent.__table__.columns
    )
    for secret in (token, code, STRONG_PASSWORD, "@"):
        assert secret not in row


def test_a_json_client_is_never_resumed_and_ignores_the_cookie() -> None:
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(email_sender=sender)
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    _page, token, _code = first_sign_in(client)
    client.cookies.set(PENDING_COOKIE, token, path="/auth")

    refused = client.post(
        "/auth/login",
        json={"username": "patient.user", "password": STRONG_PASSWORD},
    )

    assert refused.status_code == 429
    assert refused.headers["retry-after"] == "60"
    assert len(sender.messages) == 1


def test_a_wrong_password_inside_the_cooldown_is_not_resumed() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    first_sign_in(client)

    wrong = client.post(
        "/auth/login",
        data={
            "csrf_token": get_csrf_token(client),
            "username": "patient.user",
            "password": "Wrong-password-1!",
        },
    )

    assert wrong.status_code == 401
    assert "mfa_challenge_token" not in wrong.text


def test_the_audit_outcome_resumed_has_its_own_migration_and_a_refusing_downgrade(
    migrated,  # noqa: F811
) -> None:
    engine, config = migrated
    script = ScriptDirectory.from_config(config)
    (head,) = script.get_heads()
    assert head == "0027_mfa_resumed_outcome"
    assert script.get_revision(head).down_revision == "0026_mycarlos_push_handles"
    with Session(engine) as session, session.begin():
        session.add(
            PatientPortalAuditEvent(
                event_type=AUDIT_EVENT_MFA_CHALLENGE,
                outcome=AUDIT_OUTCOME_RESUMED,
                actor_type="patient",
                created_at=utc_now(),
            )
        )
    # The old schema cannot hold the retained row: the downgrade refuses until it is gone.
    with pytest.raises(RuntimeError, match="resumed audit events exist"):
        command.downgrade(config, "0026_mycarlos_push_handles")
    with Session(engine) as session, session.begin():
        session.query(PatientPortalAuditEvent).delete()
    command.downgrade(config, "0026_mycarlos_push_handles")
    with Session(engine) as session:
        with pytest.raises(IntegrityError):
            with session.begin():
                session.add(
                    PatientPortalAuditEvent(
                        event_type=AUDIT_EVENT_MFA_CHALLENGE,
                        outcome=AUDIT_OUTCOME_RESUMED,
                        actor_type="patient",
                        created_at=utc_now(),
                    )
                )
    command.upgrade(config, "head")


def test_the_cookie_is_secure_outside_development_and_cleared_when_nothing_is_left() -> None:
    secure = Settings(**non_development_settings_values("staging"))
    response = Response()
    web_support.set_mfa_pending_cookie(response, "t" * 43, expires_in_seconds=120, settings=secure)
    header = response.headers["set-cookie"]
    assert header.startswith(f"{PENDING_COOKIE}=")
    for attribute in ("HttpOnly", "Secure", "SameSite=strict", "Path=/auth", "Max-Age=120"):
        assert attribute in header

    # A challenge with no time left sets nothing: it clears the cookie instead.
    spent = Response()
    web_support.set_mfa_pending_cookie(spent, "t" * 43, expires_in_seconds=0, settings=secure)
    cleared = spent.headers["set-cookie"]
    assert "Max-Age=0" in cleared
    assert "Secure" in cleared and "HttpOnly" in cleared


@pytest.mark.parametrize("locale", [option.code for option in SUPPORTED_LOCALES])
def test_the_resume_notice_is_shown_in_every_language(locale: str) -> None:
    app = migrated_development_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    client.cookies.set(LOCALE_COOKIE_NAME, locale)
    first_sign_in(client)

    again = form_sign_in(client)

    assert again.status_code == 200
    challenge, _account = challenge_and_account(app)
    notice = portal_text(locale)["mfa_resumed_notice"].format(
        time=challenge.created_at.strftime("%H:%M")
    )
    assert str(escape(notice)) in again.text
    # Every language has its own text, not the English fallback (except English itself).
    if locale != "en":
        assert notice != portal_text("en")["mfa_resumed_notice"].format(
            time=challenge.created_at.strftime("%H:%M")
        )
