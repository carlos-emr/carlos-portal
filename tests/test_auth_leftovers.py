# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Authentication paths no earlier test drove: times with no zone, a login with a name that can
never be an account, a locked account's wrong password, the sign-in code's channel choice, a
delivery outcome for a challenge that is gone, a reset token that is spent or belongs to a locked
account, and a session whose account was locked. Synthetic accounts and codes only.
"""

import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from carlos_patient_portal import auth
from carlos_patient_portal.models import (
    PASSWORD_RESET_STATUS_PENDING,
    PASSWORD_RESET_STATUS_REVOKED,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalPasswordResetToken,
    PatientPortalSession,
    utc_now,
)
from tests.support import STRONG_PASSWORD
from tests.test_auth_refusals import signed_in, verify

NEW_PASSWORD = "Another-FAKE-passw0rd-for-tests!"


# --------------------------------------------------------------------------------------------
# Times that carry no zone are read as UTC
# --------------------------------------------------------------------------------------------


def test_a_time_with_no_zone_is_compared_as_utc_whichever_side_lacks_it() -> None:
    aware = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    naive = datetime(2026, 7, 1, 12, 0)
    assert auth.is_past(aware, naive) and auth.is_past(naive, aware)  # equal counts as past
    assert not auth.is_past(naive + timedelta(seconds=1), aware)
    assert not auth.is_past(aware + timedelta(seconds=1), naive)
    cooldown = timedelta(seconds=60)
    for last, now in (
        (aware, naive + timedelta(seconds=20)),
        (naive, aware + timedelta(seconds=20)),
    ):
        assert auth.seconds_until_allowed(last, now, cooldown) == 40
    # Never less than one second, even when the cooldown has run out.
    assert auth.seconds_until_allowed(aware, naive + timedelta(hours=1), cooldown) == 1


def test_timing_equalisation_never_fails_a_login_when_its_own_hash_is_unusable(
    monkeypatch, caplog
) -> None:
    def unusable(*args, **kwargs):
        raise auth.PasswordHashUnusableError()

    monkeypatch.setattr(auth, "password_matches", unusable)
    caplog.set_level(logging.ERROR, logger="carlos_patient_portal.auth")
    auth.verify_dummy_password("a password nobody has")  # no exception
    assert "Dummy password hash is unusable" in caplog.text
    assert "a password nobody has" not in caplog.text


# --------------------------------------------------------------------------------------------
# start_login
# --------------------------------------------------------------------------------------------


def login(app, keys, policy, **overrides):
    values = {
        "username": "patient.user",
        "password": STRONG_PASSWORD,
        "client_reference_hash": "c" * 64,
        "policy": policy,
        "session_token_secret": keys.session,
        "mfa_challenge_token_secret": keys.mfa,
        "mfa_code_secret": keys.mfa,
        "clinic_id": app.state.settings.clinic_id,
        **overrides,
    }
    # Committed even when the login is refused, as the route does: a refusal is audited.
    with app.state.session_factory() as session:
        try:
            return auth.start_login(session, **values)
        finally:
            session.commit()


def audit_rows(app, event_type):
    with app.state.session_factory() as session:
        return session.scalars(
            select(PatientPortalAuditEvent)
            .where(PatientPortalAuditEvent.event_type == event_type)
            .order_by(PatientPortalAuditEvent.id)
        ).all()


@pytest.mark.parametrize("username", ["", "ab", "has space", "semi;colon", "x" * 200])
def test_a_login_with_a_name_that_can_never_be_an_account_is_just_wrong_credentials(
    username, monkeypatch
) -> None:
    app, _, keys, policy = signed_in()
    before = len(audit_rows(app, auth.AUDIT_EVENT_LOGIN))
    equalised: list[str] = []
    monkeypatch.setattr(auth, "verify_dummy_password", equalised.append)
    with pytest.raises(auth.InvalidCredentialsError):
        login(app, keys, policy, username=username)
    assert equalised == [STRONG_PASSWORD]  # a refusal costs the same hash work as a real login
    [*_, failure] = audit_rows(app, auth.AUDIT_EVENT_LOGIN)
    assert len(audit_rows(app, auth.AUDIT_EVENT_LOGIN)) == before + 1
    assert failure.outcome == auth.AUDIT_OUTCOME_FAILURE
    assert failure.reason == auth.AUTH_REASON_INVALID_CREDENTIALS
    # No account is named: the row carries the client reference only.
    assert failure.account_id is None and failure.actor is None
    assert failure.client_reference_hash == "c" * 64


def test_a_staff_locked_account_says_locked_only_to_the_right_password() -> None:
    app, _, keys, policy = signed_in()
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.locked_at, account.locked_by = utc_now(), "staff"
    with pytest.raises(auth.AccountLockedError):
        login(app, keys, policy)
    # A wrong password is not told the account is locked.
    with pytest.raises(auth.InvalidCredentialsError):
        login(app, keys, policy, password="Wrong-FAKE-passw0rd-entirely!")
    reasons = [row.reason for row in audit_rows(app, auth.AUDIT_EVENT_LOGIN)[-2:]]
    assert reasons == [auth.AUTH_REASON_ACCOUNT_LOCKED, auth.AUTH_REASON_INVALID_CREDENTIALS]


def test_where_email_may_not_carry_the_code_a_login_without_a_choice_goes_by_text_message() -> None:
    app, _, keys, policy = signed_in()
    no_email = replace(policy, allow_email_mfa=False)
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.phone_number = "+16135550123"
    result = login(app, keys, no_email)
    assert result.status == "mfa_required"
    assert result.mfa_challenge.delivery_method == "sms"
    # With email allowed and preferred, the same login goes by email (the fallback is not taken).
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.last_mfa_email_sent_at = None
        account.last_mfa_sms_sent_at = None
        account.preferred_mfa_method = "email"
    assert login(app, keys, policy).mfa_challenge.delivery_method == "email"


# --------------------------------------------------------------------------------------------
# The challenge's delivery state and outcome
# --------------------------------------------------------------------------------------------


def state(app, keys, token, **kwargs):
    with app.state.session_factory() as session:
        return auth.get_mfa_challenge_delivery_state(
            session, token, challenge_token_secret=keys.mfa, **kwargs
        )


def test_a_delivery_state_exists_only_for_an_active_account_and_a_method_it_still_has() -> None:
    app, payload, keys, _ = signed_in()
    token = payload["mfa_challenge_token"]
    assert state(app, keys, token).delivery_method == "email"
    # The email channel is not allowed any more: nothing is offered for this challenge.
    assert state(app, keys, token, allow_email=False) is None
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        auth.set_patient_account_access(
            session, account.id, "staff", enabled=False, clinic_id=account.clinic_id
        )
    assert state(app, keys, token) is None


def test_a_pending_challenge_of_an_account_that_is_no_longer_active_has_no_delivery_state() -> None:
    app, payload, keys, _ = signed_in()
    token = payload["mfa_challenge_token"]
    assert state(app, keys, token) is not None
    # Straight on the row, so the challenge itself is still pending (the staff path cancels it).
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.status, account.disabled_at, account.disabled_by = (
            "disabled",
            utc_now(),
            "FAKE Staff",
        )
    assert state(app, keys, token) is None


def test_an_outcome_for_a_challenge_whose_account_is_gone_is_not_found() -> None:
    app, payload, keys, _ = signed_in()
    delivery = state(app, keys, payload["mfa_challenge_token"])
    answers = iter([SimpleNamespace(account_id=1, id=1), None])  # the challenge, then no account

    class Session:
        def scalar(self, statement):
            return next(answers)

    with pytest.raises(auth.MfaChallengeNotFoundError):
        auth.record_mfa_delivery_outcome(Session(), delivery=delivery, outcome="success")


def test_a_preferred_channel_is_taken_only_when_it_is_real_and_available() -> None:
    app, payload, keys, _ = signed_in()
    token = payload["mfa_challenge_token"]
    with app.state.session_factory() as session, session.begin():
        session.scalar(select(PatientPortalAccount)).phone_number = "+16135550123"
    assert state(app, keys, token).delivery_method == "email"
    assert state(app, keys, token, preferred_delivery_method="sms").delivery_method == "sms"
    # A channel that does not exist leaves the challenge's own; so does one that is not available.
    assert state(app, keys, token, preferred_delivery_method="pigeon").delivery_method == "email"
    assert state(app, keys, token, preferred_delivery_method="email", allow_email=False) is None


def test_an_outcome_for_a_challenge_that_is_gone_or_not_the_accounts_is_not_found(
    monkeypatch,
) -> None:
    app, payload, keys, _ = signed_in()
    delivery = state(app, keys, payload["mfa_challenge_token"])
    with app.state.session_factory() as session:
        with pytest.raises(auth.MfaChallengeNotFoundError):
            auth.record_mfa_delivery_outcome(
                session, delivery=replace(delivery, challenge_id=987654), outcome="success"
            )
        # The challenge disappears between the two reads (another request removed it).
        monkeypatch.setattr(auth, "lock_mfa_challenge", lambda *a, **k: None)
        with pytest.raises(auth.MfaChallengeNotFoundError):
            auth.record_mfa_delivery_outcome(session, delivery=delivery, outcome="success")


def test_an_outcome_is_matched_on_times_the_database_returns_without_a_zone() -> None:
    """The delivery was made for the challenge it names, whatever zone its times are written in.

    A SQLite row gives times with no zone; the delivery's own copies are compared with them. The
    older, verified login below has a newer one after it, so a pair of times that were wrongly
    taken as different would make this look like a stale acknowledgement and be recorded as
    superseded instead of as the delivery it is.
    """
    app, payload, keys, policy = signed_in()
    delivery = state(app, keys, payload["mfa_challenge_token"])
    assert delivery.expires_at.tzinfo is None  # as a SQLite row gives it
    a_session(app, payload, keys, policy)  # the older login is verified
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.last_mfa_email_sent_at = None
    login(app, keys, policy)  # and a newer login follows it
    with app.state.session_factory() as session:
        account = session.scalar(select(PatientPortalAccount))
        sent_before = account.last_mfa_email_sent_at
    assert sent_before is not None and sent_before.tzinfo is None
    with app.state.session_factory() as session, session.begin():
        auth.record_mfa_delivery_outcome(
            session,
            delivery=replace(delivery, expected_account_sent_at=sent_before),
            outcome=auth.AUDIT_OUTCOME_SUCCESS,
        )
    reasons = [row.reason for row in audit_rows(app, auth.AUDIT_EVENT_MFA_DELIVERY)]
    assert "email:superseded" not in reasons
    with app.state.session_factory() as session:
        sent_after = session.scalar(select(PatientPortalAccount)).last_mfa_email_sent_at
    assert sent_after > sent_before  # the delivery moved the reservation, as a delivery does


# --------------------------------------------------------------------------------------------
# Password reset
# --------------------------------------------------------------------------------------------


def request_reset(app, keys, policy, **overrides):
    values = {
        "username": "patient.user",
        "email": None,
        "client_reference_hash": "c" * 64,
        "policy": policy,
        "reset_token_secret": keys.password_reset,
        "clinic_id": app.state.settings.clinic_id,
        **overrides,
    }
    with app.state.session_factory() as session, session.begin():
        if values["email"] is None:
            values["email"] = session.scalar(select(PatientPortalAccount)).email
        return auth.request_password_reset(session, **values)


def complete(app, keys, token):
    # Committed even when refused, as the route does: a spent token stays spent.
    with app.state.session_factory() as session:
        try:
            return auth.complete_password_reset(
                session,
                reset_token=token,
                new_password=NEW_PASSWORD,
                reset_token_secret=keys.password_reset,
                clinic_id=app.state.settings.clinic_id,
            )
        finally:
            session.commit()


def reset_status(app):
    with app.state.session_factory() as session:
        return [
            row.status for row in session.scalars(select(PatientPortalPasswordResetToken)).all()
        ]


def test_a_reset_request_for_a_name_or_address_that_cannot_exist_issues_nothing() -> None:
    app, _, keys, policy = signed_in()
    for overrides in ({"username": "has space"}, {"email": "not an address"}):
        result = request_reset(app, keys, policy, **overrides)
        assert (result.reset_token, result.recipient) == (None, None)
    rows = audit_rows(app, auth.AUDIT_EVENT_PASSWORD_RESET_REQUEST)
    assert [row.outcome for row in rows] == [auth.AUDIT_OUTCOME_FAILURE] * 2
    assert all(row.account_id is None for row in rows)
    assert {row.reason for row in rows} == {auth.AUTH_REASON_INVALID_CREDENTIALS}
    assert reset_status(app) == []


def test_a_new_reset_request_after_the_wait_revokes_the_one_before() -> None:
    app, _, keys, policy = signed_in()
    open_policy = replace(policy, password_reset_request_cooldown=timedelta(0))
    first = request_reset(app, keys, open_policy)
    second = request_reset(app, keys, open_policy)
    assert first.reset_token and second.reset_token and first.reset_token != second.reset_token
    assert sorted(reset_status(app)) == sorted(
        [PASSWORD_RESET_STATUS_REVOKED, PASSWORD_RESET_STATUS_PENDING]
    )
    with pytest.raises(auth.PasswordResetTokenInvalidError):
        complete(app, keys, first.reset_token)
    assert complete(app, keys, second.reset_token).username == "patient.user"


def test_a_reset_token_that_has_expired_is_spent_by_trying_it() -> None:
    app, _, keys, policy = signed_in()
    token = request_reset(app, keys, policy).reset_token
    with app.state.session_factory() as session, session.begin():
        row = session.scalar(select(PatientPortalPasswordResetToken))
        row.created_at = utc_now() - timedelta(hours=2)
        row.expires_at = utc_now() - timedelta(hours=1)
    with pytest.raises(auth.PasswordResetTokenInvalidError):
        complete(app, keys, token)
    assert reset_status(app) == [PASSWORD_RESET_STATUS_REVOKED]
    # It stays spent, and the failure was audited without an account.
    with pytest.raises(auth.PasswordResetTokenInvalidError):
        complete(app, keys, token)
    failures = audit_rows(app, auth.AUDIT_EVENT_PASSWORD_RESET_COMPLETE)
    assert [row.reason for row in failures] == [auth.AUTH_REASON_INVALID_RESET_TOKEN] * 2


def test_a_reset_token_of_an_account_staff_locked_since_is_revoked_and_refused() -> None:
    app, _, keys, policy = signed_in()
    token = request_reset(app, keys, policy).reset_token
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.locked_at, account.locked_by = utc_now(), "staff"
    with pytest.raises(auth.PasswordResetTokenInvalidError):
        complete(app, keys, token)
    assert reset_status(app) == [PASSWORD_RESET_STATUS_REVOKED]
    with app.state.session_factory() as session:
        assert session.scalar(select(PatientPortalAccount)).locked_by == "staff"  # still locked


# --------------------------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------------------------


def a_session(app, payload, keys, policy):
    with app.state.session_factory() as session, session.begin():
        return verify(session, payload, keys, policy)


def check(app, keys, token):
    # Committed even when refused, as the route does: a revocation is kept.
    with app.state.session_factory() as session:
        try:
            return auth.authenticate_session_token(
                session,
                session_token=token,
                session_token_secret=keys.session,
                idle_timeout=timedelta(minutes=30),
            )
        finally:
            session.commit()


def test_a_session_of_an_account_staff_locked_since_is_revoked_for_that_reason() -> None:
    app, payload, keys, policy = signed_in()
    token = a_session(app, payload, keys, policy)
    assert check(app, keys, token).account.username == "patient.user"
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.locked_at, account.locked_by = utc_now(), "staff"
    with pytest.raises(auth.PortalSessionInvalidError):
        check(app, keys, token)
    with app.state.session_factory() as session:
        row = session.scalar(select(PatientPortalSession))
        assert row.revoked_at is not None
        assert row.revoked_reason == auth.AUTH_REASON_ACCOUNT_LOCKED


def test_a_logout_that_loses_a_race_to_another_revocation_is_not_a_second_logout(
    monkeypatch,
) -> None:
    app, payload, keys, policy = signed_in()
    token = a_session(app, payload, keys, policy)
    real = auth.authenticate_session_token

    def authenticate_then_lose(session, **kwargs):
        authenticated = real(session, **kwargs)
        authenticated.portal_session.revoked_at = utc_now()  # another request got there first
        authenticated.portal_session.revoked_reason = "idle_timeout"
        return authenticated

    monkeypatch.setattr(auth, "authenticate_session_token", authenticate_then_lose)
    before = len(audit_rows(app, auth.AUDIT_EVENT_SESSION_LOGOUT))
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(auth.PortalSessionInvalidError):
            auth.logout_patient_session(
                session,
                session_token=token,
                session_token_secret=keys.session,
                idle_timeout=timedelta(minutes=30),
            )
    assert len(audit_rows(app, auth.AUDIT_EVENT_SESSION_LOGOUT)) == before  # no logout recorded
