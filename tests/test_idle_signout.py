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

"""The signed-in page's idle sign-out, server side (#149).

The page is told how long its session has left (seconds, from the server's own idle clock), a
keep-alive POST restarts the idle clock without ever moving the absolute lifetime, and the sign-in
page can say a session ended for inactivity. The timer itself is tested in
tests/idle-session.test.js and the whole journey in
scripts/patient-portal-session-playwright-checks.js.
"""

import re
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal import auth, web_support
from carlos_patient_portal.i18n import LOCALE_COOKIE_NAME, SUPPORTED_LOCALES, portal_text
from carlos_patient_portal.models import PatientPortalSession, utc_now
from tests.support import (
    CSRF_TOKEN_PATTERN,
    browser_sign_in_seeded_patient,
    migrated_development_app,
)

REMAINING = re.compile(r'data-idle-remaining-seconds="(\d+)"')
LIMIT = re.compile(r'data-idle-limit-seconds="(\d+)"')
KEEPALIVE = "/portal/session/keepalive"


def signed_in(limit_seconds: int = 600):
    app = migrated_development_app(session_idle_timeout_seconds=limit_seconds)
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    return app, client


def page_token(client: TestClient) -> str:
    match = CSRF_TOKEN_PATTERN.search(client.get("/portal").text)
    assert match is not None
    return match.group(1)


def set_session(app, **values) -> None:
    with app.state.session_factory() as session:
        row = session.scalar(select(PatientPortalSession))
        for name, value in values.items():
            setattr(row, name, value)
        session.commit()


def session_row(app):
    with app.state.session_factory() as session:
        row = session.scalar(select(PatientPortalSession))
        session.expunge(row)
        return row


def as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


# ---- what the page is told ------------------------------------------------------------------


def test_the_dashboard_carries_its_idle_numbers_keepalive_and_warning():
    _, client = signed_in(600)
    page = client.get("/portal").text
    assert LIMIT.search(page).group(1) == "600"
    assert 595 <= int(REMAINING.search(page).group(1)) <= 600
    assert f'data-idle-keepalive-url="{KEEPALIVE}"' in page
    assert 'data-idle-signed-out-url="/?signed_out=idle"' in page
    assert "/static/idle-session.js" in page
    text = portal_text("en")
    assert page.count('id="portal-idle-warning"') == 1
    assert 'role="alertdialog"' in page
    assert text["idle_warning_title"] in page
    assert text["idle_stay_signed_in"] in page
    # The warning's words carry the placeholder the script fills; nothing is filled in here.
    assert 'data-idle-body-template="' in page and "{seconds}" in page


def test_the_page_is_told_what_the_server_holds_not_a_full_limit():
    """The server writes the idle clock only every few minutes, so a page loaded just after a
    request that did not write it must still be told the real, shorter remainder."""
    app, client = signed_in(600)
    # 200 s ago: inside the lazy-write interval (300 s), so this request does not rewrite it.
    set_session(app, last_seen_at=utc_now() - timedelta(seconds=200))
    told = int(REMAINING.search(client.get("/portal").text).group(1))
    assert 395 <= told <= 400


def test_a_page_loaded_after_a_long_quiet_spell_is_told_a_full_limit_because_the_server_wrote_it():
    app, client = signed_in(600)
    set_session(app, last_seen_at=utc_now() - timedelta(seconds=400))
    told = int(REMAINING.search(client.get("/portal").text).group(1))
    assert 595 <= told <= 600


def test_the_absolute_session_lifetime_caps_the_number_the_page_is_told():
    app, client = signed_in(600)
    set_session(app, expires_at=utc_now() + timedelta(seconds=90))
    told = int(REMAINING.search(client.get("/portal").text).group(1))
    assert 85 <= told <= 90


# ---- the keep-alive -------------------------------------------------------------------------


def test_a_keepalive_restarts_the_idle_clock_and_says_how_long_is_left():
    app, client = signed_in(600)
    token = page_token(client)
    set_session(app, last_seen_at=utc_now() - timedelta(seconds=200))
    before = as_utc(session_row(app).last_seen_at)
    response = client.post(KEEPALIVE, data={"csrf_token": token})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert 597 <= response.json()["remaining_seconds"] <= 600
    assert set(response.json()) == {"remaining_seconds"}
    after = as_utc(session_row(app).last_seen_at)
    assert after - before > timedelta(seconds=190)
    assert utc_now() - after < timedelta(seconds=5)


def test_a_keepalive_never_moves_the_absolute_lifetime():
    app, client = signed_in(600)
    token = page_token(client)
    expires = utc_now() + timedelta(seconds=90)
    set_session(app, expires_at=expires, last_seen_at=utc_now() - timedelta(seconds=100))
    response = client.post(KEEPALIVE, data={"csrf_token": token})
    assert response.status_code == 200
    # The answer is the smaller of the two limits, and the lifetime itself is untouched.
    assert 85 <= response.json()["remaining_seconds"] <= 90
    assert as_utc(session_row(app).expires_at) == as_utc(expires)


def test_keepalives_close_together_write_once():
    app, client = signed_in(600)
    token = page_token(client)
    set_session(app, last_seen_at=utc_now() - timedelta(seconds=200))
    assert client.post(KEEPALIVE, data={"csrf_token": token}).status_code == 200
    first = session_row(app).last_seen_at
    second = client.post(KEEPALIVE, data={"csrf_token": token})
    assert second.status_code == 200
    assert 597 <= second.json()["remaining_seconds"] <= 600
    assert session_row(app).last_seen_at == first


def test_a_keepalive_needs_the_csrf_token_and_changes_nothing_without_it():
    app, client = signed_in(600)
    old = utc_now() - timedelta(seconds=200)
    set_session(app, last_seen_at=old)
    for data in ({}, {"csrf_token": "FAKE-not-a-token"}):
        response = client.post(KEEPALIVE, data=data)
        assert response.status_code == 403
    assert as_utc(session_row(app).last_seen_at) == as_utc(old)
    # It is POST only.
    assert client.get(KEEPALIVE).status_code == 405


def test_a_keepalive_with_no_session_cookie_is_refused_and_says_where_to_sign_in():
    app, client = signed_in(600)
    token = page_token(client)
    client.cookies.delete(web_support.PORTAL_SESSION_COOKIE_NAME)
    response = client.post(KEEPALIVE, data={"csrf_token": token})
    assert response.status_code == 401
    assert response.headers["location"] == "/"
    assert response.headers["cache-control"] == "no-store"


def test_a_keepalive_cannot_revive_an_idle_expired_session_and_the_expiry_is_recorded():
    app, client = signed_in(600)
    token = page_token(client)
    set_session(app, last_seen_at=utc_now() - timedelta(seconds=700))
    response = client.post(KEEPALIVE, data={"csrf_token": token})
    assert response.status_code == 401
    assert response.headers["location"] == "/"
    # The cookie is cleared, the row says why, and the same call cannot succeed again.
    assert web_support.PORTAL_SESSION_COOKIE_NAME in response.headers.get("set-cookie", "")
    row = session_row(app)
    assert row.revoked_at is not None
    assert row.revoked_reason == auth.SESSION_REVOKED_REASON_IDLE_TIMEOUT
    assert client.post(KEEPALIVE, data={"csrf_token": token}).status_code == 401
    assert client.get("/portal", follow_redirects=False).status_code == 303


def test_a_revoked_session_cannot_keep_itself_alive():
    app, client = signed_in(600)
    token = page_token(client)
    set_session(app, revoked_at=utc_now(), revoked_reason=auth.SESSION_REVOKED_REASON_LOGOUT)
    before = session_row(app).last_seen_at
    assert client.post(KEEPALIVE, data={"csrf_token": token}).status_code == 401
    assert session_row(app).last_seen_at == before


# ---- the sign-in page says why ---------------------------------------------------------------


def test_the_sign_in_page_says_a_session_ended_for_inactivity_in_every_language():
    app = migrated_development_app()
    client = TestClient(app)
    for option in SUPPORTED_LOCALES:
        locale = option.code
        client.cookies.set(LOCALE_COOKIE_NAME, locale)
        notice = portal_text(locale)["signed_out_idle_notice"]
        assert notice in client.get("/?signed_out=idle").text
        assert notice not in client.get("/").text


def test_only_the_known_reason_shows_a_notice_and_nothing_of_the_query_is_echoed():
    app = migrated_development_app()
    client = TestClient(app)
    notice = portal_text("en")["signed_out_idle_notice"]
    hostile = "<script>alert(1)</script>"
    for value in ("", "logout", "IDLE", "idle%20", hostile, "ZQXMARK" + "Q" * 5000):
        page = client.get("/", params={"signed_out": value}).text
        assert notice not in page
        assert 'class="form-notice"' not in page
        # The language links carry the page's own address, percent-encoded, as they always did;
        # nothing of the value is put into the page as markup or as a notice.
        assert hostile not in page
        assert "<script>alert" not in page
    # Repeated: the first value is the one read, and the notice is one paragraph.
    page = client.get("/?signed_out=idle&signed_out=other").text
    assert page.count(notice) <= 1


# ---- the number --------------------------------------------------------------------------------


def authenticated(last_seen_at, expires_at, created_at=None):
    row = PatientPortalSession(
        account_id=1,
        token_hash="FAKE",
        created_at=created_at or utc_now(),
        last_seen_at=None,
        expires_at=expires_at,
    )
    return auth.AuthenticatedPortalSession(
        account=None, portal_session=row, last_seen_at=last_seen_at
    )


def test_remaining_seconds_is_the_nearer_of_the_idle_and_the_absolute_limit_never_negative():
    now = utc_now()
    idle = timedelta(minutes=10)
    far = now + timedelta(days=1)

    def remaining(last_seen_at, expires_at):
        return auth.idle_remaining_seconds(
            authenticated(last_seen_at, expires_at), idle_timeout=idle, now=now
        )

    assert remaining(now, far) == 600
    assert remaining(now - timedelta(seconds=250), far) == 350
    # The absolute lifetime is the nearer limit.
    assert remaining(now, now + timedelta(seconds=45)) == 45
    # Past either limit: zero, not a negative number.
    assert remaining(now - timedelta(hours=1), far) == 0
    assert remaining(now, now - timedelta(seconds=5)) == 0
    # Naive datetimes (as SQLite returns them) are read as UTC.
    assert remaining(now.replace(tzinfo=None), far.replace(tzinfo=None)) == 600
    # Whole seconds, rounded down: a number that is never longer than the truth.
    assert remaining(now - timedelta(milliseconds=1500), far) == 598
