# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The portal's account and message routes refuse what the browser must not be able to do
(coverage round 3).

With a valid CSRF token but no signed-in session, every mutating portal route sends the browser to
the sign-in page and changes nothing; a message list or message does the same. A signed-in patient
whose new password does not match its confirmation, is too weak, or whose current password is
wrong, or who asks for an MFA method the portal does not have, gets an error page and no change.
FAKE patient and passwords only (the test seed's).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal import web_support
from carlos_patient_portal.models import (
    EMAIL_CHANGE_STATUS_REVOKED,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalEmailChangeRequest,
)
from tests.support import (
    NON_DEVELOPMENT_SESSION_SECRET,
    SEEDED_INVITE_EMAIL,
    STRONG_PASSWORD,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    browser_sign_in_seeded_patient,
    csrf_token_from_response,
    migrated_development_app,
)

UNAUTHENTICATED_POSTS = (
    (
        "/portal/account/password",
        {"current_password": "x", "new_password": "y", "new_password_confirmation": "y"},
    ),
    ("/portal/account/contact", {"email": "a@b.test", "current_password": "x"}),
    ("/portal/account/contact/confirm-phone", {"code": "000000"}),
    ("/portal/account/contact/resend-phone", {}),
    ("/portal/account/mfa", {"preferred_mfa_method": "email", "current_password": "x"}),
    ("/portal/messages/1/choice", {"choice": "yes"}),
    ("/portal/messages/1/decline", {}),
)


@pytest.mark.parametrize(("path", "body"), UNAUTHENTICATED_POSTS)
def test_a_valid_csrf_token_whose_session_has_gone_sends_the_browser_to_sign_in(
    path: str, body: dict
) -> None:
    # The page was loaded signed in and the session is gone when the form is sent (it expired, or
    # was revoked from another browser): the token is still valid, the session is not.
    client, token = signed_in()
    before = stored_state(client.app)
    client.cookies.delete(web_support.PORTAL_SESSION_COOKIE_NAME)
    response = client.post(path, data={"csrf_token": token, **body}, follow_redirects=False)
    assert response.status_code == 303, path
    assert response.headers["location"] == "/", path
    # Nothing was written: not the password, the MFA method, the contact details, a pending
    # change, a failed-attempt counter or an audit row.
    assert stored_state(client.app) == before, path


@pytest.mark.parametrize("path", ["/portal/messages", "/portal/messages/1", "/portal/account"])
def test_a_page_of_the_signed_in_portal_sends_a_visitor_to_sign_in(path: str) -> None:
    app = migrated_development_app()
    client = TestClient(app)
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 303, path
    assert response.headers["location"] == "/", path


def stored_state(app) -> dict[str, object]:  # noqa: ANN001
    """Every column of every account, plus how many change requests and audit rows exist."""
    columns = [column.name for column in PatientPortalAccount.__table__.columns]
    with app.state.session_factory() as session:
        rows = session.scalars(select(PatientPortalAccount).order_by(PatientPortalAccount.id))
        accounts = [{name: getattr(row, name) for name in columns} for row in rows]
        changes = session.scalars(select(PatientPortalEmailChangeRequest))
        audits = session.scalars(select(PatientPortalAuditEvent))
        return {
            "accounts": accounts,
            "change_requests": len(list(changes)),
            "audit_events": len(list(audits)),
        }


def signed_in() -> tuple[TestClient, str]:
    app = migrated_development_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    account = client.get("/portal/account")
    assert account.status_code == 200
    return client, csrf_token_from_response(account)


CSRF_PAGE = "This usually means the page was open for a while"


class Form:
    """A signed-in browser that sends forms with the CSRF token the last page gave it."""

    def __init__(self) -> None:
        self.client, self.token = signed_in()

    def post(self, path: str, **fields: str):  # noqa: ANN201
        response = self.client.post(
            path, data={"csrf_token": self.token, **fields}, follow_redirects=False
        )
        # The error page carries the next token. A refusal of the token itself is a different
        # page, and none of these tests may be satisfied by it.
        assert CSRF_PAGE not in response.text, f"{path}: the CSRF token was refused"
        if response.status_code >= 400:
            self.token = csrf_token_from_response(response)
        return response


def test_a_password_change_that_fails_its_checks_changes_nothing() -> None:
    form = Form()
    # The confirmation differs from the new password.
    mismatch = form.post(
        "/portal/account/password",
        current_password=STRONG_PASSWORD,
        new_password=STRONG_PASSWORD + "-new",
        new_password_confirmation=STRONG_PASSWORD + "-other",
    )
    assert mismatch.status_code == 400
    # A new password the policy refuses (too short) with everything else right.
    weak = form.post(
        "/portal/account/password",
        current_password=STRONG_PASSWORD,
        new_password="short",
        new_password_confirmation="short",
    )
    assert weak.status_code == 400
    # A wrong current password last: it starts a wait after which the right one fails too.
    wrong = form.post(
        "/portal/account/password",
        current_password="not the password",
        new_password=STRONG_PASSWORD + "-new",
        new_password_confirmation=STRONG_PASSWORD + "-new",
    )
    assert wrong.status_code == 403
    # None of these changed anything: the patient is still signed in and the account page loads.
    assert form.client.get("/portal/account").status_code == 200


def test_an_mfa_change_with_the_wrong_password_or_an_unknown_method_fails() -> None:
    form = Form()
    unknown = form.post(
        "/portal/account/mfa",
        current_password=STRONG_PASSWORD,
        preferred_mfa_method="carrier-pigeon",
    )
    assert unknown.status_code == 400
    wrong = form.post(
        "/portal/account/mfa",
        current_password="not the password",
        preferred_mfa_method="email",
    )
    assert wrong.status_code == 403
    assert form.client.get("/portal/account").status_code == 200


# --- a portal with no SMS delivery configured ---


def request_phone_change(app, client: TestClient, phone: str):  # noqa: ANN001, ANN201
    page = client.get("/portal/account")
    return client.post(
        "/portal/account/contact",
        data={
            "csrf_token": csrf_token_from_response(page),
            "email": SEEDED_INVITE_EMAIL,
            "phone_number": phone,
            "current_password": STRONG_PASSWORD,
        },
        follow_redirects=False,
    )


def pending_phone_requests(app) -> list[PatientPortalEmailChangeRequest]:  # noqa: ANN001
    with app.state.session_factory() as session:
        return list(session.scalars(select(PatientPortalEmailChangeRequest)))


def test_a_phone_change_with_no_sms_delivery_configured_is_revoked_and_the_patient_is_told() -> (
    None
):
    # No webhook is configured, so the portal has no SMS sender at all.
    app = migrated_development_app(email_sender=RecordingPortalEmailSender())
    client = TestClient(app)
    account_id = browser_sign_in_seeded_patient(app, client)
    response = request_phone_change(app, client, "+1 555 010 5559")
    # The confirmation cannot be sent, so nothing is left pending and the patient is not left
    # believing a change is in flight.
    assert response.status_code == 303
    assert response.headers["location"] == "/portal/account?status=phone-confirmation-notice-failed"
    requests = pending_phone_requests(app)
    assert [row.status for row in requests] == [EMAIL_CHANGE_STATUS_REVOKED]
    with app.state.session_factory() as session:
        account = session.get(PatientPortalAccount, account_id)
        assert account.phone_number is None


def test_a_phone_code_resent_by_a_portal_with_no_sms_delivery_keeps_the_last_delivered_code(
    tmp_path,  # noqa: ANN001
) -> None:
    database = f"sqlite+pysqlite:///{tmp_path / 'portal.db'}"
    # First, a portal that can send: the patient asks for a phone change and gets a code.
    sender = RecordingPortalSmsSender()
    sending = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        sms_sender=sender,
        database_url=database,
        session_secret=NON_DEVELOPMENT_SESSION_SECRET,
    )
    first = TestClient(sending)
    browser_sign_in_seeded_patient(sending, first)
    requested = request_phone_change(sending, first, "+1 555 010 5558")
    assert requested.headers["location"] == "/portal/account?status=phone-confirmation-required"
    assert len(sender.messages) == 1
    # The code was sent a while ago, so the resend is not rate limited.
    with sending.state.session_factory() as session, session.begin():
        for row in session.scalars(select(PatientPortalEmailChangeRequest)):
            row.phone_code_sent_at = datetime.now(UTC) - timedelta(hours=1)
    before = [(row.status, row.phone_code_hash) for row in pending_phone_requests(sending)]
    # Then the same database and the same session, in a portal with no SMS delivery configured.
    bare = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        database_url=database,
        session_secret=NON_DEVELOPMENT_SESSION_SECRET,
    )
    second = TestClient(bare)
    # Only the session crosses over: the page of this portal gives its own CSRF token and cookie.
    for cookie in first.cookies.jar:
        if cookie.name == web_support.PORTAL_SESSION_COOKIE_NAME:
            second.cookies.set(cookie.name, cookie.value, domain=cookie.domain, path=cookie.path)
    page = second.get("/portal/account", follow_redirects=False)
    assert page.status_code == 200
    resent = second.post(
        "/portal/account/contact/resend-phone",
        data={"csrf_token": csrf_token_from_response(page)},
        follow_redirects=False,
    )
    assert resent.status_code == 303
    assert resent.headers["location"] == "/portal/account?status=phone-confirmation-invalid"
    # Nothing was sent, and the request that was pending still is (its last code is kept).
    assert len(sender.messages) == 1
    assert [(row.status, row.phone_code_hash) for row in pending_phone_requests(bare)] == before
