# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""What account activation refuses, what each refusal records, and what it leaves untouched.

FAKE patients and invites only. One migrated app serves the whole module: every test issues its
own invite for its own patient number and its own client reference, so no test sees another's
failures.
"""

import itertools
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from carlos_patient_portal import accounts
from carlos_patient_portal.accounts import (
    ActivationDeliveryUnavailableError,
    ActivationError,
    ActivationPasswordRejectedError,
    ActivationRateLimit,
    ActivationThrottledError,
    UsernameUnavailableError,
    activate_patient_account,
    enforce_activation_rate_limit,
    is_expired,
    lock_activation_rate_limit_keys,
    record_invalid_activation_request,
    seconds_until_failure_window_reset,
)
from carlos_patient_portal.audit import summarize_recent_activation_failures
from carlos_patient_portal.credentials import hash_password
from carlos_patient_portal.invites import hash_invite_token
from carlos_patient_portal.models import (
    INVITE_STATUS_ACCEPTED,
    INVITE_STATUS_PENDING,
    PatientPortalAccount,
    PatientPortalInvite,
    utc_now,
)
from tests.support import (
    IDENTITY_PROOF_SECRET,
    STRONG_PASSWORD,
    TEST_CLINIC_ID,
    create_service_invite,
    migrated_development_app,
    seeded_identity_proof,
)

# Tight, for the tests of the limit itself; every other test runs under the roomy one.
LIMIT = ActivationRateLimit(
    failure_window=timedelta(minutes=15), max_failures_per_invite=3, max_failures_per_client=4
)
ROOMY = ActivationRateLimit(
    failure_window=timedelta(minutes=15), max_failures_per_invite=50, max_failures_per_client=50
)
PATIENTS = itertools.count(5000)


@pytest.fixture(scope="module")
def app():
    return migrated_development_app()


def client_reference() -> str:
    return sha256(uuid4().bytes).hexdigest()


def issue(app, *, clinic_id=TEST_CLINIC_ID):
    """A pending invite for a new FAKE patient: its number and the code the patient was given."""
    number = next(PATIENTS)
    with app.state.session_factory() as session, session.begin():
        _, code = create_service_invite(session, number, clinic_id=clinic_id)
    return number, code


def activate(session, code, *, client=None, **changes):
    values = {
        "invite_code": code,
        "identity_proof": seeded_identity_proof(),
        "username": f"fake.{uuid4().hex[:10]}",
        "password": STRONG_PASSWORD,
        "proof_secret": IDENTITY_PROOF_SECRET,
        "client_reference_hash": client or client_reference(),
        "rate_limit": ROOMY,
        "expected_clinic_id": TEST_CLINIC_ID,
    } | changes
    return activate_patient_account(session, **values)


def failures(session, *, code=None, client=None):
    since = utc_now() - timedelta(minutes=5)
    return summarize_recent_activation_failures(
        session,
        since=since,
        invite_token_hash=hash_invite_token(code) if code is not None else None,
        client_reference_hash=client,
    ).count


def accounts_for(session, number):
    return session.scalar(
        select(func.count())
        .select_from(PatientPortalAccount)
        .where(PatientPortalAccount.demographic_no == number)
    )


def invite_status(session, code):
    return session.scalar(
        select(PatientPortalInvite.status).where(
            PatientPortalInvite.token_hash == hash_invite_token(code)
        )
    )


# ---- clocks that carry no time zone ----


def test_an_expiry_is_compared_whether_or_not_either_clock_has_a_time_zone():
    now = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
    soon = now + timedelta(minutes=1)
    assert is_expired(now - timedelta(seconds=1), now)
    assert is_expired(now, now)  # the instant itself is already over
    assert not is_expired(soon, now)
    # A stored time without a zone is read as UTC, and so is a "now" without one.
    assert is_expired((now - timedelta(seconds=1)).replace(tzinfo=None), now)
    assert not is_expired(soon.replace(tzinfo=None), now)
    assert is_expired(now - timedelta(seconds=1), now.replace(tzinfo=None))
    assert not is_expired(soon, now.replace(tzinfo=None))
    assert not is_expired(soon.replace(tzinfo=None), now.replace(tzinfo=None))


def test_the_wait_for_a_failure_window_is_counted_from_the_oldest_failure():
    now = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
    window = timedelta(minutes=15)
    # No failure to count from: the whole window.
    assert (
        seconds_until_failure_window_reset(oldest_failure_at=None, now=now, failure_window=window)
        == 900
    )
    ten_minutes_ago = now - timedelta(minutes=10)
    for oldest, clock in (
        (ten_minutes_ago, now),
        (ten_minutes_ago.replace(tzinfo=None), now),  # no zone: UTC
        (ten_minutes_ago, now.replace(tzinfo=None)),
        (ten_minutes_ago.replace(tzinfo=None), now.replace(tzinfo=None)),
    ):
        assert (
            seconds_until_failure_window_reset(
                oldest_failure_at=oldest, now=clock, failure_window=window
            )
            == 300
        )
    # A failure that has already aged out never says "wait zero": at least a second.
    assert (
        seconds_until_failure_window_reset(
            oldest_failure_at=now - timedelta(hours=2), now=now, failure_window=window
        )
        == 1
    )


# ---- the lock that serialises attempts on PostgreSQL ----


class RecordingBind:
    def __init__(self, dialect):
        self.dialect = type("Dialect", (), {"name": dialect})()


class RecordingSession:
    """Stands in for a session: records each statement instead of running it."""

    def __init__(self, dialect):
        self.dialect = dialect
        self.keys = []

    def get_bind(self):
        return RecordingBind(self.dialect)

    def execute(self, statement):
        self.keys.extend(statement.compile().params.values())
        return type("Result", (), {"scalar_one": lambda self: None})()


def test_the_attempt_lock_is_taken_on_postgresql_only_and_in_a_fixed_order():
    other = RecordingSession("sqlite")
    lock_activation_rate_limit_keys(
        other, invite_token_hash="a" * 64, client_reference_hash="b" * 64
    )
    assert other.keys == []
    first = RecordingSession("postgresql")
    lock_activation_rate_limit_keys(
        first, invite_token_hash="a" * 64, client_reference_hash="b" * 64
    )
    # Both keys, smallest first, so two requests locking the same pair cannot deadlock.
    assert len(first.keys) == 2 and first.keys == sorted(first.keys)
    assert all(-(2**63) <= key < 2**63 for key in first.keys)
    # The same pair always gives the same keys; the invite and the client never share one.
    again = RecordingSession("postgresql")
    lock_activation_rate_limit_keys(
        again, invite_token_hash="a" * 64, client_reference_hash="b" * 64
    )
    assert again.keys == first.keys
    same_value = RecordingSession("postgresql")
    lock_activation_rate_limit_keys(
        same_value, invite_token_hash="c" * 64, client_reference_hash="c" * 64
    )
    assert len(same_value.keys) == 2 and same_value.keys[0] != same_value.keys[1]


# ---- the rate limit ----


def test_too_many_failures_for_one_invite_or_one_client_throttle_with_the_longer_wait(app):
    _, code = issue(app)
    client = client_reference()
    other_client = client_reference()
    with app.state.session_factory() as session, session.begin():
        for _ in range(LIMIT.max_failures_per_invite):
            with pytest.raises(ActivationError):
                activate(session, code, client=client, username="x", rate_limit=LIMIT)
        # The invite has used its failures: even a right request from a new client waits.
        with pytest.raises(ActivationThrottledError) as raised:
            activate(session, code, client=other_client, rate_limit=LIMIT)
        assert 1 <= raised.value.retry_after_seconds <= 900
        assert invite_status(session, code) == INVITE_STATUS_PENDING
        # And a refused attempt is itself written down as throttled.
        with pytest.raises(ActivationThrottledError):
            enforce_activation_rate_limit(
                session,
                invite_token_hash=hash_invite_token(code),
                client_reference_hash=other_client,
                rate_limit=LIMIT,
                now=utc_now(),
            )


def test_one_client_that_keeps_failing_is_throttled_across_different_invites(app):
    client = client_reference()
    codes = [issue(app)[1] for _ in range(LIMIT.max_failures_per_client)]
    _, fresh = issue(app)
    with app.state.session_factory() as session, session.begin():
        for code in codes:
            with pytest.raises(ActivationError):
                activate(session, code, client=client, username="x", rate_limit=LIMIT)
        with pytest.raises(ActivationThrottledError):
            activate(session, fresh, client=client, rate_limit=LIMIT)


def test_a_request_turned_away_before_it_is_read_still_costs_the_client_a_failure(app):
    client = client_reference()
    with app.state.session_factory() as session, session.begin():
        for _ in range(LIMIT.max_failures_per_client):
            record_invalid_activation_request(
                session,
                invite_code=uuid4().hex,
                client_reference_hash=client,
                rate_limit=LIMIT,
            )
        assert failures(session, client=client) == LIMIT.max_failures_per_client
        with pytest.raises(ActivationThrottledError):
            record_invalid_activation_request(
                session, invite_code=uuid4().hex, client_reference_hash=client, rate_limit=LIMIT
            )


def test_a_code_typed_with_spaces_is_charged_as_it_will_be_redeemed_and_none_as_blank(app):
    typed = f"  {uuid4().hex} "
    with app.state.session_factory() as session, session.begin():
        record_invalid_activation_request(
            session, invite_code=typed, client_reference_hash=client_reference(), rate_limit=LIMIT
        )
        assert failures(session, code=typed.strip()) == 1
        # No code at all is charged to the blank code, not refused.
        record_invalid_activation_request(
            session, invite_code=None, client_reference_hash=client_reference(), rate_limit=ROOMY
        )
        assert failures(session, code="") >= 1


# ---- a request that is wrong before the invite is even looked up ----


@pytest.mark.parametrize(
    "changes",
    [
        {"invite_code": "   "},
        {"username": "x"},
        {"username": "has spaces in it"},
        {"preferred_mfa_method": "pigeon"},
        {"preferred_mfa_method": "sms", "phone_number": None},
        {"phone_number": "555-0100"},
        {"identity_proof": seeded_identity_proof(email="not an address")},
    ],
    ids=[
        "blank code",
        "short username",
        "bad username",
        "unknown method",
        "sms without a phone",
        "phone that is no phone",
        "email that is no email",
    ],
)
def test_malformed_details_are_refused_alike_and_counted_and_leave_the_invite_pending(app, changes):
    number, code = issue(app)
    client = client_reference()
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(ActivationError):
            activate(session, code, client=client, **changes)
        assert failures(session, client=client) == 1
        assert accounts_for(session, number) == 0
        assert invite_status(session, code) == INVITE_STATUS_PENDING


@pytest.mark.parametrize(
    "changes",
    [
        {"allow_email_mfa": False},
        {
            "preferred_mfa_method": "sms",
            "phone_number": "416 555 0100",
            "sms_delivery_available": False,
        },
    ],
    ids=["email codes not allowed", "sms not available"],
)
def test_a_way_to_receive_codes_the_clinic_does_not_offer_is_its_own_refusal(app, changes):
    number, code = issue(app)
    client = client_reference()
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(ActivationDeliveryUnavailableError):
            activate(session, code, client=client, **changes)
        assert failures(session, client=client) == 1
        assert accounts_for(session, number) == 0


def test_a_password_the_policy_refuses_is_told_apart_and_counted(app):
    number, code = issue(app)
    client = client_reference()
    with app.state.session_factory() as session, session.begin():
        for password in (
            "short",  # under the minimum
            "a" * 5000,  # over the maximum
            "abababababab",  # one short unit repeated
            "fake.patient1-Zq7!xx",  # holds the username it is for
            "test-clinic-Zq7!kkk",  # holds the clinic
            "1980-05-20-Zq7!kkk",  # holds the date of birth
        ):
            username = "fake.patient1"
            with pytest.raises(ActivationPasswordRejectedError):
                activate(session, code, client=client, username=username, password=password)
        assert failures(session, client=client) == 6
        assert accounts_for(session, number) == 0
        assert invite_status(session, code) == INVITE_STATUS_PENDING


def test_a_health_card_that_is_not_a_card_cannot_prove_anyone_and_is_refused_as_any_wrong_detail(
    app,
):
    number, code = issue(app)
    client = client_reference()
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(ActivationError):
            activate(
                session,
                code,
                client=client,
                identity_proof=seeded_identity_proof(health_card_number="!!"),
            )
        assert failures(session, client=client) == 1
        assert accounts_for(session, number) == 0


# ---- an invite that cannot be redeemed ----


def test_a_code_nobody_was_given_or_a_wrong_detail_is_one_refusal_and_creates_nothing(app):
    number, code = issue(app)
    with app.state.session_factory() as session, session.begin():
        for changes in (
            {"invite_code": "never-issued-" + uuid4().hex},
            {"identity_proof": seeded_identity_proof(email="someone.else@example.com")},
            {"identity_proof": seeded_identity_proof(date_of_birth=datetime(1990, 1, 1).date())},
            {"identity_proof": seeded_identity_proof(health_card_number="ZZZZ 9999-0000")},
            {"proof_secret": "p" * len(IDENTITY_PROOF_SECRET)},
        ):
            with pytest.raises(ActivationError):
                activate(session, changes.pop("invite_code", code), **changes)
        assert accounts_for(session, number) == 0
        assert invite_status(session, code) == INVITE_STATUS_PENDING


def test_an_expired_or_already_used_invite_cannot_be_redeemed(app):
    _, expired = issue(app)
    _, used = issue(app)
    with app.state.session_factory() as session, session.begin():
        activate(session, used)
    with app.state.session_factory() as session, session.begin():
        for code in (expired,):
            invite = session.scalar(
                select(PatientPortalInvite).where(
                    PatientPortalInvite.token_hash == hash_invite_token(code)
                )
            )
            invite.created_at = utc_now() - timedelta(days=30)
            invite.expires_at = utc_now() - timedelta(seconds=1)
    with app.state.session_factory() as session, session.begin():
        for code in (expired, used):
            with pytest.raises(ActivationError):
                activate(session, code)


def test_an_invite_cannot_be_redeemed_through_another_clinics_runtime(app):
    number, code = issue(app)
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(ActivationError):
            activate(session, code, expected_clinic_id="another-clinic")
        assert accounts_for(session, number) == 0
        assert invite_status(session, code) == INVITE_STATUS_PENDING


# ---- a patient or a username that is already taken ----


def give_the_patient_an_account(app, number, username=None):
    """An account for this patient that already exists, as if made by an earlier invite."""
    with app.state.session_factory() as session, session.begin():
        session.add(
            PatientPortalAccount(
                clinic_id=TEST_CLINIC_ID,
                demographic_no=number,
                username=username or f"earlier.{uuid4().hex[:8]}",
                email="earlier@example.test",
                preferred_mfa_method="email",
                password_hash=hash_password(STRONG_PASSWORD),
                status="active",
            )
        )


def test_a_patient_who_already_has_an_account_cannot_activate_a_second(app):
    number, code = issue(app)
    give_the_patient_an_account(app, number)
    client = client_reference()
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(ActivationError):
            activate(session, code, client=client)
        assert failures(session, client=client) == 1
        assert accounts_for(session, number) == 1
        assert invite_status(session, code) == INVITE_STATUS_PENDING


def test_a_username_that_is_taken_says_so_and_leaves_the_invite_for_another_try(app):
    _, first = issue(app)
    taken = f"taken.{uuid4().hex[:8]}"
    with app.state.session_factory() as session, session.begin():
        activate(session, first, username=taken)
    number, code = issue(app)
    client = client_reference()
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(UsernameUnavailableError):
            activate(session, code, client=client, username=taken.upper())
        assert failures(session, client=client) == 1
        assert accounts_for(session, number) == 0
        assert invite_status(session, code) == INVITE_STATUS_PENDING
        # Then a different name works, and the invite is spent.
        account = activate(session, code, username=f"free.{uuid4().hex[:8]}")
        assert account.demographic_no == number
        assert invite_status(session, code) == INVITE_STATUS_ACCEPTED


def lose_the_race(monkeypatch, name):
    """Make the first look-up find nothing, as if the other request had not committed yet."""
    real = getattr(accounts, name)
    calls = []

    def lookup(*args, **kwargs):
        calls.append(1)
        return None if len(calls) == 1 else real(*args, **kwargs)

    monkeypatch.setattr(accounts, name, lookup)


def test_two_requests_for_one_username_at_once_leave_one_account_and_the_loser_is_told_so(
    app, monkeypatch
):
    _, first = issue(app)
    taken = f"race.{uuid4().hex[:8]}"
    with app.state.session_factory() as session, session.begin():
        activate(session, first, username=taken)
    number, code = issue(app)
    lose_the_race(monkeypatch, "find_account_id_for_username")
    client = client_reference()
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(UsernameUnavailableError) as raised:
            activate(session, code, client=client, username=taken)
        assert isinstance(raised.value.__cause__, IntegrityError)
        assert failures(session, client=client) == 1
        assert accounts_for(session, number) == 0
        assert invite_status(session, code) == INVITE_STATUS_PENDING


def test_two_requests_for_one_patient_at_once_leave_one_account_and_the_loser_is_refused(
    app, monkeypatch
):
    number, code = issue(app)
    give_the_patient_an_account(app, number)
    lose_the_race(monkeypatch, "find_account_id_for_patient")
    client = client_reference()
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(ActivationError) as raised:
            activate(session, code, client=client)
        assert isinstance(raised.value.__cause__, IntegrityError)
        assert failures(session, client=client) == 1
        assert accounts_for(session, number) == 1
        assert invite_status(session, code) == INVITE_STATUS_PENDING
