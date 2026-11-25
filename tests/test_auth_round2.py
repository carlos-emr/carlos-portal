"""The authentication module's remaining refusals (coverage round 2): time arithmetic on stored
times that carry no zone, the dummy-hash fallback, a login that names no real account, a locked
account's correct password, the way a code is delivered when email is not allowed, a delivery
outcome for a challenge that is gone, the password-reset request and completion refusals, and a
session that is idle, revoked, or whose account was locked after it began. Synthetic accounts only.
"""

import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from carlos_patient_portal import auth
from carlos_patient_portal.models import (
    AUDIT_EVENT_LOGIN,
    AUDIT_EVENT_PASSWORD_RESET_REQUEST,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_THROTTLED,
    PASSWORD_RESET_STATUS_PENDING,
    PASSWORD_RESET_STATUS_REVOKED,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalMfaChallenge,
    PatientPortalPasswordResetToken,
    PatientPortalSession,
    utc_now,
)
from tests.support import STRONG_PASSWORD
from tests.test_auth_refusals import signed_in, verify

NAIVE = datetime(2026, 11, 24, 12, 0, 0)  # no zone: what a database that drops it hands back
AWARE = NAIVE.replace(tzinfo=UTC)


# ---- stored times without a zone are read as UTC ----


def test_a_time_with_no_zone_is_read_as_utc_when_asking_whether_it_has_passed():
    assert auth.is_past(NAIVE, AWARE) is True  # the same instant is "past"
    assert auth.is_past(NAIVE, AWARE - timedelta(seconds=1)) is False
    assert auth.is_past(AWARE, NAIVE + timedelta(seconds=1)) is True
    assert auth.is_past(NAIVE - timedelta(hours=1), NAIVE) is True
    assert auth.is_past(NAIVE + timedelta(hours=1), NAIVE) is False


def test_the_wait_after_a_send_is_counted_from_times_with_no_zone_too():
    cooldown = timedelta(seconds=60)
    assert auth.seconds_until_allowed(NAIVE, AWARE + timedelta(seconds=45), cooldown) == 15
    assert auth.seconds_until_allowed(AWARE, NAIVE + timedelta(seconds=45), cooldown) == 15
    # Never less than one second, however long ago it was sent.
    assert auth.seconds_until_allowed(NAIVE, NAIVE + timedelta(hours=1), cooldown) == 1


# ---- the dummy hash that equalises login timing ----


def test_an_unusable_dummy_hash_is_logged_and_never_reaches_the_caller(monkeypatch, caplog):
    def broken(*args, **kwargs):
        raise auth.PasswordHashUnusableError("FAKE")

    monkeypatch.setattr(auth, "password_matches", broken)
    caplog.set_level(logging.ERROR, logger=auth.logger.name)
    auth.verify_dummy_password("anything")  # does not raise
    assert "Dummy password hash is unusable" in caplog.text


# ---- login ----


def login(
    session,
    policy,
    keys,
    *,
    username="patient.user",
    password=STRONG_PASSWORD,
    clinic=None,
    **kwargs,
):
    clinic = clinic or session.scalar(select(PatientPortalAccount.clinic_id))
    return auth.start_login(
        session,
        username=username,
        password=password,
        client_reference_hash="c" * 64,
        policy=policy,
        session_token_secret=keys.session,
        mfa_challenge_token_secret=keys.mfa,
        mfa_code_secret=keys.mfa,
        clinic_id=clinic,
        **kwargs,
    )


def failure_reasons(app, event_type):
    with app.state.session_factory() as session:
        return [
            row.reason
            for row in session.scalars(
                select(PatientPortalAuditEvent)
                .where(
                    PatientPortalAuditEvent.event_type == event_type,
                    PatientPortalAuditEvent.outcome == AUDIT_OUTCOME_FAILURE,
                )
                .order_by(PatientPortalAuditEvent.id)
            )
        ]


def test_a_username_that_cannot_exist_is_refused_like_a_wrong_password(monkeypatch):
    app, _, keys, policy = signed_in()
    hashed = []
    monkeypatch.setattr(auth, "verify_dummy_password", hashed.append)
    with app.state.session_factory() as session, session.begin():
        for username in ("x", "not a valid user name!", "u" * 200):
            with pytest.raises(auth.InvalidCredentialsError):
                login(session, policy, keys, username=username, password="whatever")
    # A password was hashed for each, so the answer takes as long as for a real account.
    assert hashed == ["whatever"] * 3
    assert (
        failure_reasons(app, AUDIT_EVENT_LOGIN)[-3:] == [auth.AUTH_REASON_INVALID_CREDENTIALS] * 3
    )


def test_a_locked_account_refuses_its_correct_password_and_says_why():
    app, _, keys, policy = signed_in()
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.locked_at, account.locked_by = utc_now(), "staff"
        with pytest.raises(auth.AccountLockedError):
            login(session, policy, keys)
        # A wrong password on a locked account does not confirm the lock.
        with pytest.raises(auth.InvalidCredentialsError):
            login(session, policy, keys, password="not-the-password-1!")
    reasons = failure_reasons(app, AUDIT_EVENT_LOGIN)
    assert reasons[-2:] == [auth.AUTH_REASON_ACCOUNT_LOCKED, auth.AUTH_REASON_INVALID_CREDENTIALS]


def test_email_codes_fall_back_to_text_message_where_the_policy_forbids_email():
    app, _, keys, policy = signed_in()
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.preferred_mfa_method = "email"
        account.phone_number = "416 555 0100"
        result = login(session, replace(policy, allow_email_mfa=False), keys)
    assert result.status == "mfa_required"
    assert result.mfa_challenge.delivery_method == "sms"
    assert result.mfa_challenge.available_delivery_methods == ("sms",)


# ---- where a code may be delivered ----


def delivery_state(session, payload, keys, **kwargs):
    return auth.get_mfa_challenge_delivery_state(
        session,
        payload["mfa_challenge_token"],
        challenge_token_secret=keys.mfa,
        **kwargs,
    )


def test_a_challenge_has_no_delivery_for_an_account_that_is_no_longer_active():
    app, payload, keys, _ = signed_in()
    with app.state.session_factory() as session:
        assert delivery_state(session, payload, keys) is not None
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        auth.set_patient_account_access(
            session, account.id, "staff", enabled=False, clinic_id=account.clinic_id
        )
    with app.state.session_factory() as session:
        assert delivery_state(session, payload, keys) is None


def test_a_pending_challenge_has_no_delivery_when_its_account_is_not_active_or_gone_inactive():
    app, payload, keys, _ = signed_in()
    # Disabling the account ends its challenges; put this one back to pending to reach the
    # account check itself.
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        auth.set_patient_account_access(
            session, account.id, "staff", enabled=False, clinic_id=account.clinic_id
        )
        session.scalar(select(PatientPortalMfaChallenge)).status = auth.MFA_CHALLENGE_STATUS_PENDING
    with app.state.session_factory() as session:
        assert delivery_state(session, payload, keys) is None


def test_a_challenge_made_for_email_has_no_delivery_where_email_is_not_allowed():
    app, payload, keys, _ = signed_in()
    with app.state.session_factory() as session:
        assert delivery_state(session, payload, keys, allow_email=True) is not None
        # The account has no phone, so with email refused there is nowhere to send it.
        assert delivery_state(session, payload, keys, allow_email=False) is None


def test_a_preferred_method_that_is_not_one_is_ignored():
    app, payload, keys, _ = signed_in()
    with app.state.session_factory() as session:
        chosen = delivery_state(session, payload, keys, preferred_delivery_method="pigeon")
        plain = delivery_state(session, payload, keys)
    assert chosen is not None
    assert chosen.delivery_method == plain.delivery_method


# ---- a delivery outcome for a challenge that is gone ----


def test_a_delivery_outcome_for_a_challenge_that_does_not_exist_is_not_found():
    app, payload, keys, _ = signed_in()
    with app.state.session_factory() as session:
        delivery = delivery_state(session, payload, keys)
        gone = replace(delivery, challenge_id=987_654_321)
        with pytest.raises(auth.MfaChallengeNotFoundError):
            auth.record_mfa_delivery_outcome(session, delivery=gone, outcome="failure")


# ---- the password-reset request ----


def reset_request(session, policy, keys, *, username="patient.user", email=None):
    account = session.scalar(select(PatientPortalAccount))
    return auth.request_password_reset(
        session,
        username=username,
        email=account.email if email is None else email,
        client_reference_hash="r" * 64,
        policy=policy,
        reset_token_secret=keys.password_reset,
        clinic_id=session.scalar(select(PatientPortalAccount.clinic_id)),
    )


def test_a_reset_for_a_username_or_email_that_cannot_exist_issues_nothing():
    app, _, keys, policy = signed_in()
    with app.state.session_factory() as session, session.begin():
        for username, email in (("x", "a@example.test"), ("patient.user", "not an email")):
            result = reset_request(session, policy, keys, username=username, email=email)
            assert (result.reset_token, result.recipient) == (None, None)
    assert (
        failure_reasons(app, AUDIT_EVENT_PASSWORD_RESET_REQUEST)[-2:]
        == [auth.AUTH_REASON_INVALID_CREDENTIALS] * 2
    )
    with app.state.session_factory() as session:
        assert session.scalar(select(PatientPortalPasswordResetToken)) is None


def test_a_second_reset_inside_the_cooldown_is_throttled_and_one_after_it_replaces_the_first():
    app, _, keys, policy = signed_in()
    with app.state.session_factory() as session, session.begin():
        first = reset_request(session, policy, keys)
        assert first.reset_token is not None
        throttled = reset_request(session, policy, keys)
        assert throttled.reset_token is None
    with app.state.session_factory() as session:
        outcomes = session.scalars(
            select(PatientPortalAuditEvent.outcome).where(
                PatientPortalAuditEvent.event_type == AUDIT_EVENT_PASSWORD_RESET_REQUEST
            )
        ).all()
    assert AUDIT_OUTCOME_THROTTLED in outcomes
    # Once the cooldown has passed, a new request revokes the pending one and issues another.
    with app.state.session_factory() as session, session.begin():
        old = session.scalar(select(PatientPortalPasswordResetToken))
        old.created_at = utc_now() - policy.password_reset_request_cooldown - timedelta(seconds=5)
    with app.state.session_factory() as session, session.begin():
        second = reset_request(session, policy, keys)
        assert second.reset_token not in (None, first.reset_token)
    with app.state.session_factory() as session:
        statuses = session.scalars(
            select(PatientPortalPasswordResetToken.status).order_by(
                PatientPortalPasswordResetToken.id
            )
        ).all()
    assert statuses == [PASSWORD_RESET_STATUS_REVOKED, PASSWORD_RESET_STATUS_PENDING]


# ---- completing a reset ----


def complete(session, keys, token, *, password="A-New-Strong-Passphrase-77!"):  # noqa: S107
    return auth.complete_password_reset(
        session,
        reset_token=token,
        new_password=password,
        reset_token_secret=keys.password_reset,
        clinic_id=session.scalar(select(PatientPortalAccount.clinic_id)),
    )


def test_a_reset_for_an_account_staff_locked_since_is_revoked_and_refused():
    app, _, keys, policy = signed_in()
    with app.state.session_factory() as session, session.begin():
        token = reset_request(session, policy, keys).reset_token
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.locked_at, account.locked_by = utc_now(), "staff"
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(auth.PasswordResetTokenInvalidError):
            complete(session, keys, token)
    with app.state.session_factory() as session:
        assert session.scalar(select(PatientPortalPasswordResetToken.status)) == (
            PASSWORD_RESET_STATUS_REVOKED
        )
        # And the password was not changed.
        account = session.scalar(select(PatientPortalAccount))
        assert auth.password_matches(account.password_hash, STRONG_PASSWORD)


def test_a_reset_for_a_disabled_account_is_revoked_and_refused():
    app, _, keys, policy = signed_in()
    with app.state.session_factory() as session, session.begin():
        token = reset_request(session, policy, keys).reset_token
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        auth.set_patient_account_access(
            session, account.id, "staff", enabled=False, clinic_id=account.clinic_id
        )
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(auth.PasswordResetTokenInvalidError):
            complete(session, keys, token)
    with app.state.session_factory() as session:
        assert session.scalar(select(PatientPortalPasswordResetToken.status)) == (
            PASSWORD_RESET_STATUS_REVOKED
        )


# ---- a session: idle, revoked, or its account locked since ----

IDLE = timedelta(minutes=15)


def new_session_token(app, payload, keys, policy):
    """A real session, as MFA verification makes it, and its token."""
    with app.state.session_factory() as session, session.begin():
        return verify(session, payload, keys, policy)


def authenticate(session, keys, token, idle=IDLE):
    return auth.authenticate_session_token(
        session, session_token=token, session_token_secret=keys.session, idle_timeout=idle
    )


def refused_and_kept(app, keys, token):
    """Authenticates as the web layer does: a refusal still commits the revocation it wrote."""
    with app.state.session_factory() as session:
        try:
            authenticate(session, keys, token)
        except auth.PortalSessionInvalidError:
            session.commit()
            return True
        return False


def revoked_reason(app):
    with app.state.session_factory() as session:
        row = session.scalar(select(PatientPortalSession))
        return row.revoked_at is not None, row.revoked_reason


def test_a_session_authenticates_until_its_account_is_locked_or_disabled():
    app, payload, keys, policy = signed_in()
    token = new_session_token(app, payload, keys, policy)
    with app.state.session_factory() as session:
        assert authenticate(session, keys, token).account.username == "patient.user"
    assert revoked_reason(app) == (False, None)


@pytest.mark.parametrize("change", ["staff_lock", "force_reset", "disabled"])
def test_a_session_whose_account_was_locked_reset_or_disabled_since_is_revoked(change):
    app, payload, keys, policy = signed_in()
    token = new_session_token(app, payload, keys, policy)
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        if change == "staff_lock":
            account.locked_at, account.locked_by = utc_now(), "staff"
        elif change == "force_reset":
            account.force_password_reset = True
        else:
            auth.set_patient_account_access(
                session, account.id, "staff", enabled=False, clinic_id=account.clinic_id
            )
    # (Disabling the account already revoked its sessions; the others are revoked on use.)
    assert refused_and_kept(app, keys, token)
    revoked, reason = revoked_reason(app)
    assert revoked
    if change != "disabled":
        assert reason == auth.AUTH_REASON_ACCOUNT_LOCKED
    # And it stays refused.
    assert refused_and_kept(app, keys, token)


def test_an_automated_lock_leaves_an_existing_session_alone():
    app, payload, keys, policy = signed_in()
    token = new_session_token(app, payload, keys, policy)
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.locked_at, account.locked_by = utc_now(), auth.AUTH_LOCKED_BY_AUTOMATION
    with app.state.session_factory() as session:
        assert authenticate(session, keys, token).account.locked_at is not None
    assert revoked_reason(app) == (False, None)


def test_a_session_idle_too_long_is_revoked_with_its_reason():
    app, payload, keys, policy = signed_in()
    token = new_session_token(app, payload, keys, policy)
    with app.state.session_factory() as session, session.begin():
        row = session.scalar(select(PatientPortalSession))
        row.last_seen_at = utc_now() - IDLE - timedelta(seconds=5)
    assert refused_and_kept(app, keys, token)
    assert revoked_reason(app) == (True, auth.SESSION_REVOKED_REASON_IDLE_TIMEOUT)


def test_an_unknown_or_expired_session_token_is_invalid_and_the_idle_limit_must_be_positive():
    app, payload, keys, policy = signed_in()
    token = new_session_token(app, payload, keys, policy)
    with app.state.session_factory() as session:
        with pytest.raises(auth.PortalSessionInvalidError):
            authenticate(session, keys, "not-a-token-we-issued")
        with pytest.raises(ValueError, match="idle_timeout must be positive"):
            authenticate(session, keys, token, idle=timedelta(0))
    with app.state.session_factory() as session, session.begin():
        row = session.scalar(select(PatientPortalSession))
        row.created_at = utc_now() - timedelta(hours=3)
        row.last_seen_at = row.created_at
        row.expires_at = utc_now() - timedelta(seconds=1)
    assert refused_and_kept(app, keys, token)


def test_logging_out_a_session_that_was_revoked_meanwhile_is_invalid(monkeypatch):
    app, payload, keys, policy = signed_in()
    token = new_session_token(app, payload, keys, policy)
    real = auth.authenticate_session_token

    def revoked_after_authenticating(*args, **kwargs):
        # Another request ends the session between the check and the logout's own locked read.
        result = real(*args, **kwargs)
        result.portal_session.revoked_at = utc_now()
        return result

    monkeypatch.setattr(auth, "authenticate_session_token", revoked_after_authenticating)
    with app.state.session_factory() as session:
        with pytest.raises(auth.PortalSessionInvalidError):
            auth.logout_patient_session(
                session, session_token=token, session_token_secret=keys.session, idle_timeout=IDLE
            )


def test_logging_out_ends_the_session_once():
    app, payload, keys, policy = signed_in()
    token = new_session_token(app, payload, keys, policy)
    with app.state.session_factory() as session, session.begin():
        auth.logout_patient_session(
            session, session_token=token, session_token_secret=keys.session, idle_timeout=IDLE
        )
    assert revoked_reason(app) == (True, auth.SESSION_REVOKED_REASON_LOGOUT)
    assert refused_and_kept(app, keys, token)


# ---- the MFA routes' answers for an account locked or forced to reset since the code was sent ----

from fastapi.testclient import TestClient  # noqa: E402

from tests.support import (  # noqa: E402
    CSRF_TOKEN_PATTERN,
    DEVELOPMENT_MFA_CODE_PATTERN,
    MFA_CHALLENGE_TOKEN_PATTERN,
    RecordingPortalEmailSender,
    activate_seeded_patient_account,
    get_csrf_token,
    migrated_development_app,
)


def browser_challenge():
    """A browser-form sign-in that is waiting on its code: (app, client, form fields)."""
    app = migrated_development_app(email_sender=RecordingPortalEmailSender())
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    login = client.post(
        "/auth/login",
        data={
            "csrf_token": get_csrf_token(client),
            "username": "patient.user",
            "password": STRONG_PASSWORD,
        },
    )
    assert login.status_code == 200
    fields = {
        "mfa_challenge_token": MFA_CHALLENGE_TOKEN_PATTERN.search(login.text).group(1),
        "code": DEVELOPMENT_MFA_CODE_PATTERN.search(login.text).group(1),
        "csrf_token": CSRF_TOKEN_PATTERN.search(login.text).group(1),
    }
    return app, client, fields


def change_account(app, **changes):
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        for name, value in changes.items():
            setattr(account, name, value)


LOCKED = {"locked_at": utc_now(), "locked_by": "staff"}


@pytest.mark.parametrize("path", ["/auth/mfa/verify", "/auth/mfa/resend"])
def test_a_json_mfa_request_for_a_locked_account_is_locked_and_for_a_forced_reset_is_refused(
    path,
):
    app, client, fields = browser_challenge()
    body = {"mfa_challenge_token": fields["mfa_challenge_token"], "code": fields["code"]}
    if path.endswith("resend"):
        body = {
            "mfa_challenge_token": fields["mfa_challenge_token"],
            "mfa_delivery_method": "email",
        }
    change_account(app, locked_at=utc_now(), locked_by="staff")
    locked = client.post(path, json=body)
    assert locked.status_code == 423
    assert locked.json() == {"detail": auth_detail("locked")}
    change_account(app, locked_at=None, locked_by=None, force_password_reset=True)
    forced = client.post(path, json=body)
    assert forced.status_code == 403
    assert forced.json() == {"status": "password_reset_required"}


@pytest.mark.parametrize("path", ["/auth/mfa/verify", "/auth/mfa/resend"])
@pytest.mark.parametrize("state", ["locked", "forced_reset"])
def test_a_browser_mfa_form_shows_the_locked_page_or_the_reset_page(path, state):
    app, client, fields = browser_challenge()
    form = {key: value for key, value in fields.items() if path.endswith("verify") or key != "code"}
    if path.endswith("resend"):
        form["mfa_delivery_method"] = "email"
    if state == "locked":
        change_account(app, locked_at=utc_now(), locked_by="staff")
    else:
        change_account(app, force_password_reset=True)
    response = client.post(path, data=form)
    if state == "locked":
        assert response.status_code == 423
        # The locked page itself (its own heading and title), not the sign-in page with an error.
        assert 'aria-labelledby="locked-title"' in response.text
    else:
        assert response.status_code == 403
        assert "You must reset your password before signing in." in response.text


def auth_detail(kind):
    from carlos_patient_portal.routes.auth import ACCOUNT_LOCKED_DETAIL

    return {"locked": ACCOUNT_LOCKED_DETAIL}[kind]


# ---- the browser forms for sign-in, reset request and reset completion ----


def form_app():
    app = migrated_development_app(email_sender=RecordingPortalEmailSender())
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    return app, client


def test_a_browser_sign_in_for_an_account_that_must_reset_its_password_is_sent_to_the_reset_page():
    app, client = form_app()
    change_account(app, force_password_reset=True)
    response = client.post(
        "/auth/login",
        data={
            "csrf_token": get_csrf_token(client),
            "username": "patient.user",
            "password": STRONG_PASSWORD,
        },
    )
    assert response.status_code == 403
    assert "You must reset your password before signing in." in response.text


def test_a_browser_reset_request_with_missing_details_shows_the_form_again():
    app, client = form_app()
    response = client.post(
        "/auth/password-reset/request",
        data={"csrf_token": get_csrf_token(client), "username": "", "email": ""},
    )
    assert response.status_code == 400
    assert "Reset your password" in response.text
    with app.state.session_factory() as session:
        assert session.scalar(select(PatientPortalPasswordResetToken)) is None


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        (
            {"new_password": "A-New-Strong-Passphrase-77!", "new_password_confirmation": "other"},
            "The password confirmation does not match.",
        ),
        (
            # Too long for the form's own limit: refused before the token is looked at.
            {"new_password": "p" * 5000, "new_password_confirmation": "p" * 5000},
            "The new password does not meet the password requirements.",
        ),
        (
            {
                "new_password": "A-New-Strong-Passphrase-77!",
                "new_password_confirmation": "A-New-Strong-Passphrase-77!",
            },
            "The password reset link is invalid or has expired.",
        ),
    ],
)
def test_a_browser_reset_completion_says_what_is_wrong_and_keeps_the_token_it_was_given(
    fields, message
):
    app, client = form_app()
    response = client.post(
        "/auth/password-reset/complete",
        data={"csrf_token": get_csrf_token(client), "reset_token": "FAKE-token-123", **fields},
    )
    assert response.status_code == 400
    assert message in response.text
    # Nothing changed: the old password still signs in.
    with app.state.session_factory() as session:
        account = session.scalar(select(PatientPortalAccount))
        assert auth.password_matches(account.password_hash, STRONG_PASSWORD)
