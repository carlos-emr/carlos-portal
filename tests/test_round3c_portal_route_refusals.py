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

import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal import web_support
from tests.support import (
    STRONG_PASSWORD,
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
    client.cookies.delete(web_support.PORTAL_SESSION_COOKIE_NAME)
    response = client.post(path, data={"csrf_token": token, **body}, follow_redirects=False)
    assert response.status_code == 303, path
    assert response.headers["location"] == "/", path


@pytest.mark.parametrize("path", ["/portal/messages", "/portal/messages/1", "/portal/account"])
def test_a_page_of_the_signed_in_portal_sends_a_visitor_to_sign_in(path: str) -> None:
    app = migrated_development_app()
    client = TestClient(app)
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 303, path
    assert response.headers["location"] == "/", path


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
