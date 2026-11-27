"""What the authentication module refuses: bad input, unknown or spent proofs, locked accounts.

Synthetic accounts and codes only.
"""

from dataclasses import replace
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal import auth, main
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalMfaChallenge,
    PatientPortalOutboundDelivery,
    PatientPortalSession,
    utc_now,
)
from carlos_patient_portal.token_keys import PortalTokenKeys
from tests.support import (
    STRONG_PASSWORD,
    TEST_CLINIC_ID,
    activate_seeded_patient_account,
    migrated_development_app,
    sent_mfa_code,
)


@pytest.mark.parametrize(
    "secret,token", [("", "token"), ("   ", "token"), ("secret", ""), ("secret", "  ")]
)
def test_a_blank_secret_or_token_is_never_hashed(secret, token):
    with pytest.raises(ValueError, match="must not be blank"):
        auth.hash_auth_token(secret, "session", token)


def test_a_delivery_method_must_be_email_or_sms():
    assert auth.normalize_mfa_delivery_method(None) == "email"
    assert auth.normalize_mfa_delivery_method(" SMS ") == "sms"
    with pytest.raises(ValueError, match="email or sms"):
        auth.normalize_mfa_delivery_method("pigeon")


@pytest.mark.parametrize(
    "number,expected",
    [
        (None, None),
        ("   ", None),
        ("416 555 0100", "+14165550100"),
        ("1-416-555-0100", "+14165550100"),
        ("+44 20 7946 0000", "+442079460000"),
    ],
)
def test_phone_numbers_become_international_form(number, expected):
    assert auth.normalize_phone_number(number) == expected


@pytest.mark.parametrize(
    "number,message",
    [
        ("5" * 40, "characters or fewer"),
        ("555-0100", "international format"),  # no area code, not international
        ("20 7946 0000 12", "international format"),  # not a North American length
        ("+1234567", "between 8 and 15 digits"),
        ("+1234567890123456", "between 8 and 15 digits"),
    ],
)
def test_phone_numbers_that_cannot_be_made_international_are_refused(number, message):
    with pytest.raises(ValueError, match=message):
        auth.normalize_phone_number(number)


def signed_in():
    """An app with one activated FAKE patient, a pending MFA challenge, and its keys."""
    app = migrated_development_app(session_secret="t" * 32)
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    login = client.post(
        "/auth/login", json={"username": "patient.user", "password": STRONG_PASSWORD}
    )
    assert login.status_code == 200, login.text
    keys = PortalTokenKeys.derive(app.state.settings.session_secret.get_secret_value())
    policy = main.auth_policy_from_settings(app.state.settings)
    # The answer carries no code (#135): the test reads the one that was emailed.
    return app, {**login.json(), "emailed_code": sent_mfa_code(app)}, keys, policy


def verify(session, payload, keys, policy, *, token=None):
    return auth.verify_mfa_challenge(
        session,
        challenge_token=token or payload["mfa_challenge_token"],
        code=payload["emailed_code"],
        policy=policy,
        challenge_token_secret=keys.mfa,
        session_token_secret=keys.session,
        code_secret=keys.mfa,
    )


def resend(session, payload, keys, policy, *, token=None, method="email"):
    return auth.resend_mfa_challenge(
        session,
        challenge_token=token or payload["mfa_challenge_token"],
        delivery_method=method,
        policy=policy,
        challenge_token_secret=keys.mfa,
        code_secret=keys.mfa,
    )


def nothing_issued(app):
    """What a refused verify or resend leaves behind: no session, no new delivery."""
    with app.state.session_factory() as session:
        sessions = len(session.scalars(select(PatientPortalSession)).all())
        deliveries = len(session.scalars(select(PatientPortalOutboundDelivery)).all())
        challenge = session.scalar(select(PatientPortalMfaChallenge))
        return sessions, deliveries, challenge.code_hash, challenge.status, challenge.verified_at


def test_an_unknown_challenge_token_is_not_found_for_verify_and_resend():
    app, payload, keys, policy = signed_in()
    with app.state.session_factory() as session:
        with pytest.raises(auth.MfaChallengeNotFoundError):
            verify(session, payload, keys, policy, token="not-a-token-we-issued")
        with pytest.raises(auth.MfaChallengeNotFoundError):
            resend(session, payload, keys, policy, token="not-a-token-we-issued")


def test_a_locked_account_gets_neither_a_session_nor_a_new_code():
    app, payload, keys, policy = signed_in()
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.locked_at, account.locked_by = utc_now(), "staff"
    before = nothing_issued(app)
    with app.state.session_factory() as session:
        with pytest.raises(auth.AccountLockedError):
            verify(session, payload, keys, policy)
        with pytest.raises(auth.AccountLockedError):
            resend(session, payload, keys, policy)
    assert nothing_issued(app) == before
    assert before[0] == 0


def test_an_account_that_must_reset_its_password_gets_neither_a_session_nor_a_new_code():
    app, payload, keys, policy = signed_in()
    with app.state.session_factory() as session, session.begin():
        session.scalar(select(PatientPortalAccount)).force_password_reset = True
    before = nothing_issued(app)
    with app.state.session_factory() as session:
        with pytest.raises(auth.PasswordResetRequiredError):
            verify(session, payload, keys, policy)
        with pytest.raises(auth.PasswordResetRequiredError):
            resend(session, payload, keys, policy)
    assert nothing_issued(app) == before
    assert before[0] == 0


def test_a_disabled_account_has_no_challenge_to_answer():
    app, payload, keys, policy = signed_in()
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        auth.set_patient_account_access(
            session, account.id, "staff", enabled=False, clinic_id=account.clinic_id
        )
    with app.state.session_factory() as session:
        with pytest.raises(auth.MfaChallengeNotFoundError):
            verify(session, payload, keys, policy)
        with pytest.raises(auth.MfaChallengeNotFoundError):
            resend(session, payload, keys, policy)


def test_a_code_cannot_be_resent_by_email_where_the_policy_forbids_it():
    app, payload, keys, policy = signed_in()
    refusing = replace(policy, allow_email_mfa=False)
    with app.state.session_factory() as session:
        with pytest.raises(auth.MfaDeliveryUnavailableError):
            resend(session, payload, keys, refusing, method="email")


def test_a_delivery_outcome_is_only_success_or_failure():
    app, *_ = signed_in()
    with app.state.session_factory() as session:
        with pytest.raises(ValueError, match="success or failure"):
            auth.record_mfa_delivery_outcome(session, delivery=None, outcome="maybe")
        with pytest.raises(ValueError, match="success or failure"):
            auth.record_password_reset_delivery_outcome(
                session, result=auth.PasswordResetRequestResult(None, None), outcome="maybe"
            )


def test_a_reset_delivery_outcome_needs_the_reset_it_is_about():
    app, *_ = signed_in()
    with app.state.session_factory() as session:
        with pytest.raises(auth.PasswordResetTokenInvalidError):
            auth.record_password_reset_delivery_outcome(
                session, result=auth.PasswordResetRequestResult(None, None), outcome="failure"
            )
        unknown = auth.PasswordResetRequestResult(
            None, None, reset_token_id=987654, account_id=987654
        )
        with pytest.raises(auth.PasswordResetTokenInvalidError):
            auth.record_password_reset_delivery_outcome(session, result=unknown, outcome="failure")


def test_a_password_cannot_be_reset_with_a_token_nobody_issued():
    app, _, keys, _ = signed_in()
    with app.state.session_factory() as session:
        with pytest.raises(auth.PasswordResetTokenInvalidError):
            auth.complete_password_reset(
                session,
                reset_token="a-token-nobody-issued",
                new_password="Another-FAKE-passw0rd-for-tests!",
                reset_token_secret=keys.password_reset,
                clinic_id=TEST_CLINIC_ID,
            )


def test_a_session_check_needs_a_positive_idle_timeout():
    app, _, keys, _ = signed_in()
    with app.state.session_factory() as session:
        with pytest.raises(ValueError, match="idle_timeout must be positive"):
            auth.authenticate_session_token(
                session,
                session_token="whatever",
                session_token_secret=keys.session,
                idle_timeout=timedelta(0),
            )


def test_a_session_that_was_never_issued_cannot_be_logged_out():
    app, _, keys, _ = signed_in()
    with app.state.session_factory() as session:
        with pytest.raises(auth.PortalSessionInvalidError):
            auth.logout_patient_session(
                session,
                session_token="never-issued",
                session_token_secret=keys.session,
                idle_timeout=timedelta(minutes=30),
            )


def test_staff_actions_on_an_unknown_account_are_not_found():
    app, *_ = signed_in()
    with app.state.session_factory() as session:
        with pytest.raises(auth.AccountNotFoundError):
            auth.unlock_patient_account(session, 987654, "staff")
        with pytest.raises(auth.AccountNotFoundError):
            auth.set_patient_account_access(
                session, 987654, "staff", enabled=False, clinic_id=TEST_CLINIC_ID
            )


@pytest.mark.parametrize("reason", ["   ", "x" * 65])
def test_a_staff_access_change_needs_a_short_reason(reason):
    app, *_ = signed_in()
    with app.state.session_factory() as session:
        with pytest.raises(ValueError, match="1 to 64 characters"):
            auth.set_patient_account_access(
                session, 1, "staff", enabled=False, clinic_id=TEST_CLINIC_ID, reason=reason
            )
