# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The booking-prompt notice paths of the delivery outbox that no test drove: who a notice goes to
at send time (the "message waiting" and "there is an update" notices), what is sent when its payload
is damaged, and an outcome recorded for a prompt that is gone. FAKE patients; an in-memory
database."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from carlos_patient_portal import delivery_outbox as outbox
from carlos_patient_portal.booking_offers import CLOSED_AFTER_EXPIRY_NOTICE
from carlos_patient_portal.models import (
    AUDIT_OUTCOME_SUCCESS,
    BOOKING_PROMPT_STATUS_READ,
    BOOKING_PROMPT_STATUS_WITHDRAWN,
    OUTBOX_KIND_BOOKING_PROMPT,
    OUTBOX_KIND_BOOKING_PROMPT_UPDATE,
    OUTBOX_STATUS_PENDING,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalBookingChoice,
    PatientPortalBookingPrompt,
    PatientPortalOutboundDelivery,
    utc_now,
)
from tests.support import (
    OUTBOX_ENCRYPTION_SECRET,
    RecordingPortalEmailSender,
    activate_seeded_patient_account,
)
from tests.test_booking_prompts import PATH, booking_app, headers, prompt_request


@pytest.fixture
def prompt():  # noqa: ANN201
    """An app with a patient who has an account and one sent prompt; yields (app, prompt id)."""
    app = booking_app()
    client = TestClient(app)
    account_id = activate_seeded_patient_account(app, client)
    prompt_id = client.post(PATH, headers=headers(), json=prompt_request()).json()["id"]
    with app.state.session_factory.begin() as session:
        # The notice the route queued is not under test here; clear it so each test makes its own.
        for row in session.scalars(select(PatientPortalOutboundDelivery)):
            session.delete(row)
    yield app, prompt_id, account_id
    app.state.database_engine.dispose()


def recipient_of(app, function, prompt_id):  # noqa: ANN001, ANN201
    with app.state.session_factory() as session:
        return function(session, prompt_id)


FIRST = outbox._booking_prompt_notice_recipient
UPDATE = outbox._booking_prompt_update_recipient


def change_prompt(app, prompt_id: int, **changes: object) -> None:  # noqa: ANN001
    with app.state.session_factory.begin() as session:
        row = session.get(PatientPortalBookingPrompt, prompt_id)
        for name, value in changes.items():
            setattr(row, name, value)


def change_account(app, account_id: int, **changes: object) -> None:  # noqa: ANN001
    with app.state.session_factory.begin() as session:
        row = session.get(PatientPortalAccount, account_id)
        for name, value in changes.items():
            setattr(row, name, value)


# --- who the "message waiting" notice goes to --------------------------------------------------


def test_a_notice_without_a_prompt_goes_nowhere(prompt) -> None:  # noqa: ANN001
    app, _, _ = prompt
    for function in (FIRST, UPDATE):
        assert recipient_of(app, function, None) is None
        assert recipient_of(app, function, 987_654) is None


def test_the_first_notice_goes_to_the_accounts_current_email_while_the_prompt_is_waiting(
    prompt,  # noqa: ANN001
) -> None:
    app, prompt_id, account_id = prompt
    with app.state.session_factory() as session:
        email = session.get(PatientPortalAccount, account_id).email
    assert recipient_of(app, FIRST, prompt_id) == email
    # A contact change after the notice was queued is followed: the current address, not the old.
    change_account(app, account_id, email="changed.fake@example.test")
    assert recipient_of(app, FIRST, prompt_id) == "changed.fake@example.test"


@pytest.mark.parametrize(
    "changes",
    [
        {"status": BOOKING_PROMPT_STATUS_READ, "read_at": utc_now()},
        {
            "status": BOOKING_PROMPT_STATUS_WITHDRAWN,
            "withdrawn_at": utc_now(),
            "withdrawn_by": "FAKE Staff",
        },
    ],
)
def test_the_first_notice_is_not_sent_once_the_prompt_is_read_or_withdrawn(
    prompt,  # noqa: ANN001
    changes: dict[str, object],
) -> None:
    app, prompt_id, _ = prompt
    change_prompt(app, prompt_id, **changes)
    assert recipient_of(app, FIRST, prompt_id) is None


def test_the_first_notice_is_not_sent_once_the_prompt_has_expired(prompt) -> None:  # noqa: ANN001
    app, prompt_id, _ = prompt
    with app.state.session_factory.begin() as session:
        row = session.get(PatientPortalBookingPrompt, prompt_id)
        row.created_at = utc_now() - timedelta(days=60)
        row.expires_at = utc_now() - timedelta(seconds=1)
    assert recipient_of(app, FIRST, prompt_id) is None


@pytest.mark.parametrize("function", [FIRST, UPDATE])
def test_no_notice_goes_to_an_account_staff_disabled_or_locked(
    prompt,  # noqa: ANN001
    function,  # noqa: ANN001
) -> None:
    app, prompt_id, account_id = prompt
    assert recipient_of(app, function, prompt_id) is not None
    change_account(
        app, account_id, status="disabled", disabled_at=utc_now(), disabled_by="FAKE Staff"
    )
    assert recipient_of(app, function, prompt_id) is None
    change_account(
        app,
        account_id,
        status="active",
        disabled_at=None,
        disabled_by=None,
        locked_at=utc_now(),
        locked_by="FAKE Staff",
    )
    assert recipient_of(app, function, prompt_id) is None


# --- who the "there is an update" notice goes to -----------------------------------------------


def test_the_update_notice_follows_the_prompts_state(prompt) -> None:  # noqa: ANN001
    app, prompt_id, _ = prompt
    # A prompt still waiting and not expired: the patient has something to act on.
    assert recipient_of(app, UPDATE, prompt_id) is not None
    # Withdrawn: nothing to act on.
    change_prompt(
        app,
        prompt_id,
        status=BOOKING_PROMPT_STATUS_WITHDRAWN,
        withdrawn_at=utc_now(),
        withdrawn_by="FAKE Staff",
    )
    assert recipient_of(app, UPDATE, prompt_id) is None


def test_the_update_notice_is_not_sent_for_a_prompt_that_expired_unbooked(
    prompt,  # noqa: ANN001
) -> None:
    app, prompt_id, _ = prompt
    with app.state.session_factory.begin() as session:
        row = session.get(PatientPortalBookingPrompt, prompt_id)
        row.created_at = utc_now() - timedelta(days=400)
        row.expires_at = utc_now() - timedelta(days=300)
    assert recipient_of(app, UPDATE, prompt_id) is None


def test_the_update_notice_is_not_sent_for_a_booked_prompt_with_no_booked_time(
    prompt,  # noqa: ANN001
) -> None:
    app, prompt_id, _ = prompt
    change_prompt(app, prompt_id, status="booked", read_at=utc_now())
    # Booked, but no choice is in the booked state: there is no time to tell the patient about.
    assert recipient_of(app, UPDATE, prompt_id) is None


@pytest.mark.parametrize(
    ("starts_in", "expected_notice"),
    [(timedelta(days=3), True), (-timedelta(days=5), False)],
)
def test_the_update_notice_for_a_booked_prompt_needs_a_booked_time_that_has_not_long_passed(
    prompt,  # noqa: ANN001
    starts_in: timedelta,
    expected_notice: bool,
) -> None:
    app, prompt_id, _ = prompt
    change_prompt(app, prompt_id, status="booked", read_at=utc_now())
    with app.state.session_factory.begin() as session:
        session.add(
            PatientPortalBookingChoice(
                prompt_id=prompt_id,
                clinic_id="clinic-a",
                slot_id="carlos:slot:1",
                starts_at=utc_now() + starts_in,
                duration_minutes=30,
                visit_mode="phone",
                state="booked",
                chosen_at=utc_now() - timedelta(days=1),
                result_at=utc_now(),
            )
        )
    assert (recipient_of(app, UPDATE, prompt_id) is not None) is expected_notice


# --- a damaged payload, and an outcome for a prompt that is gone -------------------------------


@pytest.mark.parametrize("kind", [OUTBOX_KIND_BOOKING_PROMPT, OUTBOX_KIND_BOOKING_PROMPT_UPDATE])
@pytest.mark.parametrize("payload", [{}, {"sign_in_url": ""}, {"sign_in_url": 7}])
def test_a_notice_without_a_usable_sign_in_link_is_not_sent(
    prompt,  # noqa: ANN001
    kind: str,
    payload: dict[str, object],
) -> None:
    app, prompt_id, account_id = prompt
    with app.state.session_factory.begin() as session:
        delivery = outbox._enqueue_booking_notice(
            session,
            kind=kind,
            account_id=account_id,
            booking_prompt_id=prompt_id,
            sign_in_url="https://portal.example.test/x",
            encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            encryption_key_id=outbox.OUTBOX_KEY_ID,
        )
        ciphertext, nonce = outbox._encrypt_payload(
            payload,
            encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            kind=kind,
            account_id=account_id,
            message_id=delivery.message_id,
        )
        delivery.encrypted_payload = ciphertext
        delivery.encryption_nonce = nonce
        delivery_id = delivery.id
    sender = RecordingPortalEmailSender()
    result = outbox.process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        max_attempts=3,
        lease_seconds=60,
        delivery_id=delivery_id,
    )
    assert result is not None
    assert sender.messages == []
    with app.state.session_factory() as session:
        row = session.get(PatientPortalOutboundDelivery, delivery_id)
        assert row.last_failure_code == "payload_invalid"
        assert row.status != "delivered"


def test_an_outcome_for_a_prompt_that_no_longer_exists_records_nothing(prompt) -> None:  # noqa: ANN001
    app, prompt_id, account_id = prompt
    with app.state.session_factory.begin() as session:
        delivery = outbox._enqueue_booking_notice(
            session,
            kind=OUTBOX_KIND_BOOKING_PROMPT,
            account_id=account_id,
            booking_prompt_id=prompt_id,
            sign_in_url="https://portal.example.test/x",
            encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            encryption_key_id=outbox.OUTBOX_KEY_ID,
        )
        assert delivery.status == OUTBOX_STATUS_PENDING
        events_before = session.scalar(select(func.count()).select_from(PatientPortalAuditEvent))
        # A copy of the delivery that points at a prompt that is not there.
        gone = PatientPortalOutboundDelivery(
            account_id=account_id,
            booking_prompt_id=987_654,
            kind=OUTBOX_KIND_BOOKING_PROMPT,
        )
        outbox._record_booking_prompt_delivery(session, gone, outcome=AUDIT_OUTCOME_SUCCESS)
        assert (
            session.scalar(select(func.count()).select_from(PatientPortalAuditEvent))
            == events_before
        )
        # For the prompt that is there, the same call records one event and marks it notified.
        outbox._record_booking_prompt_delivery(session, delivery, outcome=AUDIT_OUTCOME_SUCCESS)
        assert (
            session.scalar(select(func.count()).select_from(PatientPortalAuditEvent))
            == events_before + 1
        )
        assert session.get(PatientPortalBookingPrompt, prompt_id).notified_at is not None


# --- suggested additions (agent 4's review): the survivors of four mutants ---------------------


def add_choice(app, prompt_id: int, *, state: str, starts_in: timedelta, result_ago=None) -> None:  # noqa: ANN001
    with app.state.session_factory.begin() as session:
        session.add(
            PatientPortalBookingChoice(
                prompt_id=prompt_id,
                clinic_id="clinic-a",
                slot_id=f"carlos:slot:{state}",
                starts_at=utc_now() + starts_in,
                duration_minutes=30,
                visit_mode="phone",
                state=state,
                chosen_at=utc_now() - timedelta(days=2),
                result_at=None if state == "pending" else utc_now() - (result_ago or timedelta(0)),
            )
        )


def test_a_booked_prompts_time_must_be_in_the_booked_state_to_count(prompt) -> None:  # noqa: ANN001
    app, prompt_id, _ = prompt
    change_prompt(app, prompt_id, status="booked", read_at=utc_now())
    # A coming time that is only pending (or taken) is not a booked time.
    add_choice(app, prompt_id, state="pending", starts_in=timedelta(days=3))
    assert recipient_of(app, UPDATE, prompt_id) is None
    add_choice(app, prompt_id, state="booked", starts_in=timedelta(days=3))
    assert recipient_of(app, UPDATE, prompt_id) is not None


def test_a_pick_that_fell_through_after_the_expiry_is_still_told_for_a_while(
    prompt,  # noqa: ANN001
) -> None:
    app, prompt_id, _ = prompt
    with app.state.session_factory.begin() as session:
        row = session.get(PatientPortalBookingPrompt, prompt_id)
        row.created_at = utc_now() - timedelta(days=40)
        row.expires_at = utc_now() - timedelta(days=30)
    assert recipient_of(app, UPDATE, prompt_id) is None
    # Reported taken after the expiry, recently: the patient was waiting on it and is told.
    add_choice(
        app,
        prompt_id,
        state="slot_unavailable",
        starts_in=timedelta(days=3),
        result_ago=timedelta(hours=1),
    )
    assert recipient_of(app, UPDATE, prompt_id) is not None


def test_a_pick_that_fell_through_long_ago_is_not_told(prompt) -> None:  # noqa: ANN001
    app, prompt_id, _ = prompt
    with app.state.session_factory.begin() as session:
        row = session.get(PatientPortalBookingPrompt, prompt_id)
        row.created_at = utc_now() - timedelta(days=400)
        row.expires_at = utc_now() - timedelta(days=300)
    add_choice(
        app,
        prompt_id,
        state="slot_unavailable",
        starts_in=timedelta(days=3),
        result_ago=CLOSED_AFTER_EXPIRY_NOTICE + timedelta(days=1),
    )
    assert recipient_of(app, UPDATE, prompt_id) is None


def test_an_update_notice_outcome_is_marked_as_one_and_does_not_move_notified_at(
    prompt,  # noqa: ANN001
) -> None:
    app, prompt_id, account_id = prompt
    with app.state.session_factory.begin() as session:
        delivery = outbox._enqueue_booking_notice(
            session,
            kind=OUTBOX_KIND_BOOKING_PROMPT_UPDATE,
            account_id=account_id,
            booking_prompt_id=prompt_id,
            sign_in_url="https://portal.example.test/x",
            encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            encryption_key_id=outbox.OUTBOX_KEY_ID,
        )
        outbox._record_booking_prompt_delivery(session, delivery, outcome=AUDIT_OUTCOME_SUCCESS)
        outbox._record_booking_prompt_delivery(
            session, delivery, outcome=AUDIT_OUTCOME_SUCCESS, reason="x"
        )
        assert session.get(PatientPortalBookingPrompt, prompt_id).notified_at is None
        reasons = session.scalars(
            select(PatientPortalAuditEvent.reason)
            .where(PatientPortalAuditEvent.resource_id == str(prompt_id))
            .order_by(PatientPortalAuditEvent.id)
        ).all()
        assert reasons[-2:] == ["update_notice", "update_notice:x"]
