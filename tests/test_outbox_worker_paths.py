"""The delivery outbox worker's own paths: claiming a row and its lease, taking one back from a
worker that died, the retry delay, giving up, what the heartbeat does when it loses the row, and the
refusals the worker makes before it sends anything. Real database rows, FAKE data and a recording
sender; nothing leaves the process.
"""

import logging
from datetime import UTC, timedelta
from threading import Event, Thread

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError

from carlos_patient_portal import delivery_outbox as outbox
from carlos_patient_portal.models import (
    OUTBOX_KIND_CONTACT_CHANGE,
    OUTBOX_STATUS_DELIVERED,
    OUTBOX_STATUS_FAILED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PROCESSING,
    PASSWORD_RESET_STATUS_REVOKED,
    PatientPortalOutboundDelivery,
    PatientPortalPasswordResetToken,
    utc_now,
)
from carlos_patient_portal.runtime import PortalOperationalMetrics
from tests.support import (
    OUTBOX_ENCRYPTION_SECRET,
    RecordingPortalEmailSender,
    activate_seeded_patient_account,
    migrated_development_app,
)
from tests.test_delivery_outbox import queue_reset

SECRET = OUTBOX_ENCRYPTION_SECRET


@pytest.fixture(scope="module")
def portal():
    app = migrated_development_app(outbox_encryption_secret=SECRET)
    account_id = activate_seeded_patient_account(app, TestClient(app))
    return app, account_id


@pytest.fixture(autouse=True)
def empty_outbox(portal):
    app, _ = portal
    with app.state.session_factory() as session, session.begin():
        session.execute(delete(PatientPortalOutboundDelivery))
    yield


def queue(portal, count=1, *, recipient="fake.patient@example.test"):
    """Contact-change deliveries (the simplest kind); returns their ids, oldest first."""
    app, account_id = portal
    ids = []
    with app.state.session_factory() as session, session.begin():
        for number in range(count):
            row = outbox.enqueue_contact_change_delivery(
                session,
                account_id=account_id,
                recipient=f"{number}.{recipient}",
                encryption_secret=SECRET,
            )
            ids.append(row.id)
    return ids


def when(value):
    """A stored time as an aware one (the test database returns naive times)."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def row(app, delivery_id) -> PatientPortalOutboundDelivery:
    with app.state.session_factory() as session:
        found = session.get(PatientPortalOutboundDelivery, delivery_id)
        session.expunge(found)
        return found


def alter(app, delivery_id, **fields) -> None:
    with app.state.session_factory() as session, session.begin():
        found = session.get(PatientPortalOutboundDelivery, delivery_id)
        for name, value in fields.items():
            setattr(found, name, value)


def claim(app, **kwargs):
    with app.state.session_factory() as session, session.begin():
        claimed = outbox._claim_delivery(session, lease_seconds=kwargs.pop("lease", 60), **kwargs)
        return None if claimed is None else claimed.id


def finish(app, delivery_id, **kwargs):
    defaults = {"succeeded": False, "max_attempts": 3, "expected_attempt_count": 1}
    with app.state.session_factory() as session, session.begin():
        return outbox._finish_delivery(session, delivery_id=delivery_id, **(defaults | kwargs))


def run(app, sender, **kwargs):
    defaults = {"max_attempts": 3, "lease_seconds": 60}
    return outbox.process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=SECRET,
        **(defaults | kwargs),
    )


# ---- claiming a row and its lease ----


def test_nothing_waiting_claims_nothing(portal):
    app, _ = portal
    assert claim(app) is None
    assert run(app, RecordingPortalEmailSender()) is None


def test_a_claim_marks_the_row_processing_counts_the_attempt_and_leases_it(portal):
    app, _ = portal
    (delivery_id,) = queue(portal)
    before = utc_now()
    assert claim(app, lease=90) == delivery_id
    claimed = row(app, delivery_id)
    assert claimed.status == OUTBOX_STATUS_PROCESSING
    assert claimed.attempt_count == 1
    assert (
        before + timedelta(seconds=85)
        <= when(claimed.lease_expires_at)
        <= (utc_now() + timedelta(seconds=90))
    )
    # A claimed row is not claimed again while its lease runs.
    assert claim(app) is None


def test_a_row_that_is_not_yet_available_is_not_claimed(portal):
    app, _ = portal
    (delivery_id,) = queue(portal)
    alter(app, delivery_id, available_at=utc_now() + timedelta(minutes=5))
    assert claim(app) is None
    assert row(app, delivery_id).status == OUTBOX_STATUS_PENDING
    alter(app, delivery_id, available_at=utc_now() - timedelta(seconds=1))
    assert claim(app) == delivery_id


def test_the_oldest_available_row_goes_first_and_equal_times_go_by_id(portal):
    app, _ = portal
    first, second, third = queue(portal, 3)
    now = utc_now()
    alter(app, first, available_at=now - timedelta(seconds=5))
    alter(app, second, available_at=now - timedelta(seconds=30))
    alter(app, third, available_at=now - timedelta(seconds=5))
    # Oldest availability first, then the lower id among equals.
    assert [claim(app), claim(app), claim(app), claim(app)] == [second, first, third, None]


def test_a_delivered_or_failed_row_is_never_claimed(portal):
    app, _ = portal
    delivered, failed = queue(portal, 2)
    alter(app, delivered, status=OUTBOX_STATUS_DELIVERED, delivered_at=utc_now())
    alter(app, failed, status=OUTBOX_STATUS_FAILED)
    assert claim(app) is None


def test_asking_for_one_row_claims_that_row_and_no_other(portal):
    app, _ = portal
    older, newer = queue(portal, 2)
    alter(app, older, available_at=utc_now() - timedelta(minutes=1))
    assert claim(app, delivery_id=newer) == newer
    assert row(app, older).status == OUTBOX_STATUS_PENDING
    # Not waiting any more, so asking for it again finds nothing (the older row is not substituted).
    assert claim(app, delivery_id=newer) is None
    assert row(app, older).attempt_count == 0


def test_a_row_whose_lease_ran_out_is_taken_back_with_a_new_attempt(portal):
    app, _ = portal
    (delivery_id,) = queue(portal)
    assert claim(app) == delivery_id
    # The worker died holding it. Until the lease ends nobody else may have it.
    assert claim(app) is None
    alter(app, delivery_id, lease_expires_at=utc_now() - timedelta(seconds=1))
    assert claim(app) == delivery_id
    taken = row(app, delivery_id)
    assert (taken.status, taken.attempt_count) == (OUTBOX_STATUS_PROCESSING, 2)
    assert when(taken.lease_expires_at) > utc_now()


# ---- finishing a row ----


def test_finishing_a_row_that_is_gone_reports_failed(portal):
    app, _ = portal
    assert finish(app, 10_000_000) == OUTBOX_STATUS_FAILED


def test_a_worker_that_lost_its_lease_cannot_finish_the_row_its_successor_holds(portal):
    app, _ = portal
    (delivery_id,) = queue(portal)
    claim(app)
    alter(app, delivery_id, lease_expires_at=utc_now() - timedelta(seconds=1))
    claim(app)  # the successor: attempt 2
    # The first worker (attempt 1) wakes up and reports success, then failure: neither lands.
    for succeeded in (True, False):
        assert finish(app, delivery_id, succeeded=succeeded) == OUTBOX_STATUS_PROCESSING
    held = row(app, delivery_id)
    assert (held.status, held.attempt_count) == (OUTBOX_STATUS_PROCESSING, 2)
    assert held.lease_expires_at is not None and held.delivered_at is None
    # The successor, with its own attempt count, can.
    assert finish(app, delivery_id, succeeded=True, expected_attempt_count=2) == (
        OUTBOX_STATUS_DELIVERED
    )


def test_a_row_that_is_not_processing_is_not_finished_again(portal):
    app, _ = portal
    (delivery_id,) = queue(portal)
    claim(app)
    assert finish(app, delivery_id, succeeded=True) == OUTBOX_STATUS_DELIVERED
    delivered_at = row(app, delivery_id).delivered_at
    # A second report, from a worker that thought it still held it, changes nothing.
    assert finish(app, delivery_id, succeeded=False, failure_code="late") == (
        OUTBOX_STATUS_DELIVERED
    )
    again = row(app, delivery_id)
    assert (again.status, again.delivered_at, again.last_failure_code) == (
        OUTBOX_STATUS_DELIVERED,
        delivered_at,
        None,
    )


def test_a_delivered_row_has_no_lease_and_no_failure_left_over(portal):
    app, _ = portal
    (delivery_id,) = queue(portal)
    claim(app)
    alter(app, delivery_id, last_failure_code="earlier")
    finish(app, delivery_id, succeeded=True)
    done = row(app, delivery_id)
    assert done.status == OUTBOX_STATUS_DELIVERED
    assert done.lease_expires_at is None
    assert done.last_failure_code is None
    assert done.delivered_at is not None


def test_a_failed_attempt_is_retried_later_with_the_lease_dropped(portal):
    app, _ = portal
    (delivery_id,) = queue(portal)
    claim(app)
    before = utc_now()
    assert finish(app, delivery_id, failure_code="x" * 100) == OUTBOX_STATUS_PENDING
    retried = row(app, delivery_id)
    assert retried.lease_expires_at is None
    # The code is cut to what the column holds, and the retry is not due yet.
    assert retried.last_failure_code == "x" * 64
    assert when(retried.available_at) > before
    assert claim(app) is None
    # With no code given, the generic one is recorded.
    alter(app, delivery_id, available_at=utc_now() - timedelta(seconds=1))
    claim(app)
    finish(app, delivery_id, expected_attempt_count=2)
    assert row(app, delivery_id).last_failure_code == "delivery_failed"


def test_the_last_attempt_ends_the_row_as_failed_and_it_is_not_retried(portal):
    app, _ = portal
    (delivery_id,) = queue(portal)
    claim(app)
    assert finish(app, delivery_id, max_attempts=1, failure_code="relay_down") == (
        OUTBOX_STATUS_FAILED
    )
    ended = row(app, delivery_id)
    assert ended.status == OUTBOX_STATUS_FAILED
    assert ended.last_failure_code == "relay_down"
    assert claim(app) is None


def test_attempts_below_the_limit_keep_retrying_until_the_limit(portal):
    app, _ = portal
    (delivery_id,) = queue(portal)
    statuses = []
    for attempt in (1, 2, 3):
        alter(app, delivery_id, available_at=utc_now() - timedelta(seconds=1))
        assert claim(app) == delivery_id
        statuses.append(finish(app, delivery_id, max_attempts=3, expected_attempt_count=attempt))
    assert statuses == [OUTBOX_STATUS_PENDING, OUTBOX_STATUS_PENDING, OUTBOX_STATUS_FAILED]


# ---- the lease heartbeat ----


def test_a_lease_is_renewed_only_for_the_attempt_that_holds_it(portal):
    app, _ = portal
    (delivery_id,) = queue(portal)
    claim(app, lease=5)
    soon = row(app, delivery_id).lease_expires_at

    def renew(attempt, lease=600):
        return outbox._renew_delivery_lease(
            app.state.session_factory,
            delivery_id=delivery_id,
            expected_attempt_count=attempt,
            lease_seconds=lease,
        )

    assert renew(2) is False  # another attempt's number
    assert row(app, delivery_id).lease_expires_at == soon
    assert renew(1) is True
    assert when(row(app, delivery_id).lease_expires_at) > when(soon) + timedelta(minutes=5)
    # A row that is no longer processing cannot have its lease renewed.
    finish(app, delivery_id, succeeded=True)
    assert renew(1) is False


def test_the_heartbeat_stops_when_it_has_lost_the_row(portal, monkeypatch):
    app, _ = portal
    calls = []
    monkeypatch.setattr(outbox, "_renew_delivery_lease", lambda *a, **k: calls.append(1) or False)
    stop = Event()
    # It ends by itself, without being told to stop, as soon as a renewal says the row is gone.
    # (Run on a thread so that a heartbeat that never ends fails the test instead of hanging it.)
    heartbeat = Thread(
        target=outbox._renew_delivery_lease_until_stopped,
        kwargs={
            "session_factory": app.state.session_factory,
            "stop": stop,
            "delivery_id": 1,
            "expected_attempt_count": 1,
            "lease_seconds": 0,
        },
        daemon=True,
    )
    heartbeat.start()
    heartbeat.join(timeout=5)
    ended_by_itself = not heartbeat.is_alive()
    stop.set()
    heartbeat.join(timeout=5)
    assert ended_by_itself
    assert calls == [1]


def test_the_heartbeat_keeps_renewing_until_it_is_stopped(portal, monkeypatch):
    app, _ = portal
    stop = Event()
    calls = []

    def renewed(*args, **kwargs):
        calls.append(1)
        if len(calls) == 3:
            stop.set()
        return True

    monkeypatch.setattr(outbox, "_renew_delivery_lease", renewed)
    # lease_seconds=0 gives the loop its 0.1 s floor between renewals, so three take about 0.3 s.
    # On a thread, so that a heartbeat that never stops fails the test instead of hanging the suite.
    heartbeat = Thread(
        target=outbox._renew_delivery_lease_until_stopped,
        kwargs={
            "session_factory": app.state.session_factory,
            "stop": stop,
            "delivery_id": 1,
            "expected_attempt_count": 1,
            "lease_seconds": 0,
        },
        daemon=True,
    )
    heartbeat.start()
    try:
        heartbeat.join(timeout=5)
        ended = not heartbeat.is_alive()
    finally:
        stop.set()
        heartbeat.join(timeout=5)
    assert ended, "the heartbeat did not end after it was stopped"
    assert len(calls) == 3


def test_a_database_error_ends_the_heartbeat_and_keeps_its_text_out_of_the_log(
    portal, monkeypatch, caplog
):
    app, _ = portal

    def broken(*args, **kwargs):
        raise SQLAlchemyError("FAKE-statement with FAKE-parameter-value")

    monkeypatch.setattr(outbox, "_renew_delivery_lease", broken)
    caplog.set_level(logging.ERROR, logger="carlos_patient_portal.delivery_outbox")
    stop = Event()
    heartbeat = Thread(
        target=outbox._renew_delivery_lease_until_stopped,
        kwargs={
            "session_factory": app.state.session_factory,
            "stop": stop,
            "delivery_id": 42,
            "expected_attempt_count": 1,
            "lease_seconds": 0,
        },
        daemon=True,
    )
    heartbeat.start()
    heartbeat.join(timeout=5)
    ended_by_itself = not heartbeat.is_alive()
    stop.set()
    heartbeat.join(timeout=5)
    assert ended_by_itself, "the heartbeat kept going after a database error"
    text = " ".join(record.getMessage() for record in caplog.records)
    assert "delivery 42" in text and "SQLAlchemyError" in text
    assert "FAKE-parameter-value" not in text and "FAKE-statement" not in text


# ---- what the worker refuses before it sends ----


def test_no_sender_configured_keeps_the_row_for_a_later_attempt(portal):
    app, _ = portal
    (delivery_id,) = queue(portal)
    result = run(app, None)
    assert (result.delivery_id, result.status) == (delivery_id, OUTBOX_STATUS_PENDING)
    assert row(app, delivery_id).last_failure_code == "email_unconfigured"


def test_a_payload_with_no_recipient_is_refused_and_nothing_is_sent(portal):
    app, _ = portal
    sender = RecordingPortalEmailSender()
    (delivery_id,) = queue(portal)
    # Replace the payload with one whose recipient is blank, encrypted properly for the row.
    stored = row(app, delivery_id)
    ciphertext, nonce = outbox._encrypt_payload(
        {"recipient": ""},
        encryption_secret=SECRET,
        kind=stored.kind,
        account_id=stored.account_id,
        message_id=stored.message_id,
    )
    alter(app, delivery_id, encrypted_payload=ciphertext, encryption_nonce=nonce)
    result = run(app, sender)
    assert result.status == OUTBOX_STATUS_PENDING
    assert row(app, delivery_id).last_failure_code == "payload_invalid"
    assert sender.messages == []


def test_a_reset_whose_token_was_revoked_before_the_send_is_not_sent(portal):
    app, account_id = portal
    sender = RecordingPortalEmailSender()
    delivery_id, reset_id = queue_reset(app, account_id)
    with app.state.session_factory() as session, session.begin():
        session.get(
            PatientPortalPasswordResetToken, reset_id
        ).status = PASSWORD_RESET_STATUS_REVOKED
    result = run(app, sender, max_attempts=1)
    assert result.status == OUTBOX_STATUS_FAILED
    assert row(app, delivery_id).last_failure_code == "payload_invalid"
    assert sender.messages == []


def test_a_reset_request_with_no_context_is_kept_not_dropped(portal):
    app, _ = portal
    with app.state.session_factory() as session, session.begin():
        queued = outbox.enqueue_password_reset_request(
            session,
            username="fake.patient",
            email="fake.patient@example.test",
            client_reference_hash="0" * 64,
            encryption_secret=SECRET,
        )
        delivery_id = queued.id
    result = run(app, RecordingPortalEmailSender())
    assert (result.delivery_id, result.status) == (delivery_id, OUTBOX_STATUS_PENDING)
    assert row(app, delivery_id).last_failure_code == "reset_request_unconfigured"


def test_a_failed_delivery_counts_against_its_kind_and_a_missing_counter_is_fine(portal):
    app, _ = portal

    class Refusing:
        def send_contact_change_notice(self, **kwargs):
            raise outbox.PortalEmailDeliveryError("relay refused")

    (delivery_id,) = queue(portal)
    metrics = PortalOperationalMetrics()
    run(app, Refusing(), operational_metrics=metrics)
    assert metrics.snapshot()["failures"][f"outbox_{OUTBOX_KIND_CONTACT_CHANGE}"] == 1
    assert row(app, delivery_id).last_failure_code == "PortalEmailDeliveryError"
    # The same failure with no metrics object is simply not counted.
    alter(app, delivery_id, available_at=utc_now() - timedelta(seconds=1))
    assert run(app, Refusing()).status == OUTBOX_STATUS_PENDING
    assert metrics.snapshot()["failures"][f"outbox_{OUTBOX_KIND_CONTACT_CHANGE}"] == 1


def test_a_success_is_not_counted_as_a_failure(portal):
    app, _ = portal
    queue(portal)
    metrics = PortalOperationalMetrics()
    result = run(app, RecordingPortalEmailSender(), operational_metrics=metrics)
    assert result.status == OUTBOX_STATUS_DELIVERED
    assert metrics.snapshot()["failures"] == {}
    with app.state.session_factory() as session:
        assert session.scalar(select(PatientPortalOutboundDelivery.status)) == (
            OUTBOX_STATUS_DELIVERED
        )
