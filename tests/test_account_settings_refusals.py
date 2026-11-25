# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Refusals in `account_settings.py` that no other test drove: a settings step on an account that is
not usable, a step-up with someone else's session, a phone code to resend that is not there, the
email factor where it is not allowed, the contact-review paging limits and a review that does not
exist or has moved on. FAKE patients and passwords; an in-memory database."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal.account_settings import (
    AccountSettingsStepUpError,
    AccountSettingsValidationError,
    ContactReviewConflictError,
    ContactReviewNotFoundError,
    PhoneChangeCodeInvalidError,
    change_account_password,
    count_pending_contact_reviews,
    list_pending_contact_reviews,
    lock_account_for_settings,
    resend_phone_change_code,
    review_contact_update,
    update_account_mfa_method,
    verify_current_password,
)
from carlos_patient_portal.auth import password_matches
from carlos_patient_portal.credentials import hash_password
from carlos_patient_portal.models import (
    AUDIT_EVENT_ACCOUNT_MFA_UPDATE,
    PatientPortalAccount,
    PatientPortalContactReviewRequest,
    utc_now,
)
from tests.support import STRONG_PASSWORD, TEST_CLINIC_ID, migrated_development_app

SECRET = "FAKE token secret, long enough for the account settings tests, 40+ characters"


@pytest.fixture
def factory() -> Iterator[sessionmaker[Session]]:
    app = migrated_development_app()
    yield app.state.session_factory
    app.state.database_engine.dispose()


def add_account(session: Session, number: int = 1234, **changes: object) -> PatientPortalAccount:
    values: dict[str, object] = {
        "clinic_id": TEST_CLINIC_ID,
        "demographic_no": number,
        "username": f"fake.user{number}",
        "email": f"fake{number}@example.test",
        "preferred_mfa_method": "sms",
        "password_hash": hash_password(STRONG_PASSWORD),
        "status": "active",
        **changes,
    }
    account = PatientPortalAccount(**values)
    session.add(account)
    session.flush()
    return account


def add_review(session: Session, account: PatientPortalAccount, **changes: object):  # noqa: ANN201
    values: dict[str, object] = {
        "account_id": account.id,
        "clinic_id": account.clinic_id,
        "demographic_no": account.demographic_no,
        "status": "pending",
        "revision": "FAKE-revision-1",
        "email_before": account.email,
        "email_after": f"new.{account.email}",
        "requested_at": utc_now(),
        **changes,
    }
    review = PatientPortalContactReviewRequest(**values)
    session.add(review)
    session.flush()
    return review


# --- an account that settings cannot be changed on ---------------------------------------------


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "disabled", "disabled_at": utc_now(), "disabled_by": "FAKE Staff"},
        {"locked_at": utc_now(), "locked_by": "FAKE Staff"},
        {"force_password_reset": True},
    ],
)
def test_settings_are_locked_to_an_account_that_is_active_and_not_locked(
    factory,  # noqa: ANN001
    changes: dict[str, object],
) -> None:
    with factory() as session, session.begin():
        account = add_account(session, **changes)
        with pytest.raises(AccountSettingsStepUpError):
            lock_account_for_settings(session, account.id)
    with factory() as session, session.begin():
        with pytest.raises(AccountSettingsStepUpError):
            lock_account_for_settings(session, 999_999)


def test_an_active_account_is_returned_locked(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        account = add_account(session)
        assert lock_account_for_settings(session, account.id).id == account.id


# --- a password change with someone else's or a revoked session --------------------------------


def test_a_password_change_needs_the_patients_own_live_session(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        account = add_account(session)
        for portal_session in (
            SimpleNamespace(account_id=account.id + 1, revoked_at=None),
            SimpleNamespace(account_id=account.id, revoked_at=utc_now()),
        ):
            with pytest.raises(AccountSettingsStepUpError):
                change_account_password(
                    session,
                    account,
                    portal_session,  # type: ignore[arg-type]
                    current_password=STRONG_PASSWORD,
                    new_password="Another1!strongword",
                    max_failed_password_attempts=5,
                    policy=None,  # type: ignore[arg-type]
                    session_token_secret=SECRET,
                )
        assert password_matches(account.password_hash, STRONG_PASSWORD)


# --- verifying the current password ------------------------------------------------------------


def test_the_failure_limit_must_be_positive(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        account = add_account(session)
        for limit in (0, -1):
            with pytest.raises(ValueError, match="must be positive"):
                verify_current_password(
                    session,
                    account,
                    current_password=STRONG_PASSWORD,
                    event_type=AUDIT_EVENT_ACCOUNT_MFA_UPDATE,
                    max_failed_password_attempts=limit,
                )


# --- the phone code that is not there ----------------------------------------------------------


def test_a_phone_code_cannot_be_resent_when_none_is_pending(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        account = add_account(session)
        with pytest.raises(PhoneChangeCodeInvalidError):
            resend_phone_change_code(
                session,
                account,
                token_secret=SECRET,
                resend_cooldown=timedelta(seconds=30),
            )


# --- the email factor --------------------------------------------------------------------------


def test_email_is_refused_as_a_factor_where_it_is_not_allowed(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        account = add_account(session)
        with pytest.raises(AccountSettingsValidationError):
            update_account_mfa_method(
                session,
                account,
                current_password=STRONG_PASSWORD,
                preferred_mfa_method="email",
                max_failed_password_attempts=5,
                allow_email_mfa=False,
            )
        assert account.preferred_mfa_method == "sms"
        # Where it is allowed, the same request is made.
        update_account_mfa_method(
            session,
            account,
            current_password=STRONG_PASSWORD,
            preferred_mfa_method="email",
            max_failed_password_attempts=5,
            allow_email_mfa=True,
        )
        assert account.preferred_mfa_method == "email"


# --- contact reviews ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("limit", "offset", "message"),
    [
        (0, 0, "limit must be between 1 and 100"),
        (101, 0, "limit must be between 1 and 100"),
        (10, -1, "offset must be between 0 and 100000"),
        (10, 100_001, "offset must be between 0 and 100000"),
    ],
)
def test_the_review_list_refuses_a_page_outside_its_bounds(
    factory,  # noqa: ANN001
    limit: int,
    offset: int,
    message: str,
) -> None:
    with factory() as session, session.begin():
        with pytest.raises(ValueError, match=message):
            list_pending_contact_reviews(
                session, clinic_id=TEST_CLINIC_ID, limit=limit, offset=offset
            )
        assert list_pending_contact_reviews(session, clinic_id=TEST_CLINIC_ID) == []
        assert count_pending_contact_reviews(session, clinic_id=TEST_CLINIC_ID) == 0


def decide(session: Session, review_id: int, **changes: object):  # noqa: ANN201
    values: dict[str, object] = {
        "clinic_id": TEST_CLINIC_ID,
        "reviewer": "FAKE Reviewer",
        "reviewer_id": "fake-reviewer",
        "approve": True,
        "expected_revision": "FAKE-revision-1",
        **changes,
    }
    return review_contact_update(session, review_id, **values)


def test_a_review_that_does_not_exist_or_belongs_to_another_clinic_is_not_found(
    factory,  # noqa: ANN001
) -> None:
    with factory() as session, session.begin():
        account = add_account(session)
        review = add_review(session, account)
        with pytest.raises(ContactReviewNotFoundError):
            decide(session, 987_654)
        with pytest.raises(ContactReviewNotFoundError):
            decide(session, review.id, clinic_id="another-clinic")
        assert review.status == "pending"


def test_a_review_for_another_patient_than_its_account_is_not_found(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        account = add_account(session)
        review = add_review(session, account, demographic_no=account.demographic_no + 1)
        with pytest.raises(ContactReviewNotFoundError):
            decide(session, review.id)
        assert review.status == "pending"


def test_a_review_decided_against_an_old_revision_is_a_conflict(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        account = add_account(session)
        review = add_review(session, account)
        with pytest.raises(ContactReviewConflictError):
            decide(session, review.id, expected_revision="FAKE-an-older-revision")
        assert review.status == "pending"
        assert review.review_decision is None
        # The current revision is accepted.
        decided = decide(session, review.id)
        assert decided.review_decision == "approved"
