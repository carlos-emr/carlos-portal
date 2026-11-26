"""When a signed-in session may still make a link code, and what making one refuses.

Plain objects with synthetic values; the one database case uses the migrated development app.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from carlos_patient_portal import mycarlos_links as links
from carlos_patient_portal.auth import AUTH_LOCKED_BY_AUTOMATION
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalMyCarlosLinkCode,
    PatientPortalSession,
)
from tests.support import migrated_development_app

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
IDLE = timedelta(minutes=30)


def account(**changes):
    values = {
        "id": 7,
        "status": "active",
        "locked_at": None,
        "locked_by": None,
        "force_password_reset": False,
    }
    return PatientPortalAccount(**{**values, **changes})


def portal_session(**changes):
    values = {
        "id": 1,
        "account_id": 7,
        "created_at": NOW - timedelta(minutes=5),
        "last_seen_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(hours=1),
        "revoked_at": None,
    }
    return PatientPortalSession(**{**values, **changes})


def live(session=None, who=None, now=NOW):
    return links.session_is_live(
        portal_session() if session is None else session,
        account() if who is None else who,
        now=now,
        idle_timeout=IDLE,
    )


def test_a_session_that_is_fine_is_live():
    assert live() is True


@pytest.mark.parametrize(
    "change",
    [
        {"account_id": 8},  # another account's session
        {"revoked_at": NOW - timedelta(minutes=2)},
        {"expires_at": NOW - timedelta(seconds=1)},
        {"last_seen_at": NOW - IDLE - timedelta(seconds=1)},  # idle for too long
    ],
)
def test_a_session_that_is_not_the_accounts_or_has_ended_or_gone_idle_is_not_live(change):
    assert live(portal_session(**change)) is False


def test_a_session_with_no_last_seen_time_counts_from_when_it_began():
    fresh = portal_session(last_seen_at=None, created_at=NOW - timedelta(minutes=1))
    stale = portal_session(last_seen_at=None, created_at=NOW - IDLE - timedelta(minutes=1))
    assert live(fresh) is True
    assert live(stale) is False


def test_no_session_at_all_is_not_live():
    assert links.session_is_live(None, account(), now=NOW, idle_timeout=IDLE) is False


@pytest.mark.parametrize(
    "change",
    [
        {"status": "disabled"},
        {"force_password_reset": True},
        {"locked_at": NOW - timedelta(minutes=1), "locked_by": "staff"},
    ],
)
def test_a_disabled_reset_required_or_staff_locked_account_has_no_live_session(change):
    assert live(who=account(**change)) is False


def test_an_automated_lockout_does_not_by_itself_end_a_session():
    # Only a staff lock is held against the session here; the automation's lock has its own expiry.
    automated = account(locked_at=NOW - timedelta(minutes=1), locked_by=AUTH_LOCKED_BY_AUTOMATION)
    assert live(who=automated) is True


def test_a_link_code_is_not_made_for_an_account_that_does_not_exist():
    app = migrated_development_app(session_secret="t" * 32)
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(ValueError, match="unknown account"):
            links.create_link_code(
                session, account_id=987654, session_id=1, key="k" * 32, idle_timeout=IDLE, now=NOW
            )
        assert session.scalar(select(PatientPortalMyCarlosLinkCode.id)) is None
