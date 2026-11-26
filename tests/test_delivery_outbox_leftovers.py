# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""The delivery outbox's remaining refusals and fault paths: the encryption helpers' limits, a
queue admission that locks on PostgreSQL, the superseded-reset audit failing, a request command
whose payload is damaged, a booking notice whose key is gone, and a kind the worker does not know.
FAKE data only; real rows in an in-memory database where a row is needed.
"""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from carlos_patient_portal import delivery_outbox as outbox
from carlos_patient_portal.auth import PasswordResetRequestResult, PasswordResetTokenInvalidError
from carlos_patient_portal.models import (
    AUDIT_EVENT_BOOKING_PROMPT_DELIVERY,
    AUDIT_OUTCOME_FAILURE,
    OUTBOX_KIND_PASSWORD_RESET,
    OUTBOX_KIND_PASSWORD_RESET_REQUEST,
    OUTBOX_STATUS_FAILED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PROCESSING,
    PatientPortalAuditEvent,
    PatientPortalOutboundDelivery,
    utc_now,
)
from tests.support import (
    OUTBOX_ENCRYPTION_SECRET,
    RecordingPortalEmailSender,
    activate_seeded_patient_account,
    migrated_development_app,
)
from tests.test_booking_prompts import PATH, booking_app, headers, prompt_request
from tests.test_delivery_outbox import queue_reset

SECRET = OUTBOX_ENCRYPTION_SECRET


# --------------------------------------------------------------------------------------------
# The encryption helpers and the queue admission (no database)
# --------------------------------------------------------------------------------------------


def test_an_outbox_key_needs_a_secret_that_is_not_blank() -> None:
    for blank in ("", "   ", "\n"):
        with pytest.raises(ValueError, match="must not be blank"):
            outbox.derive_outbox_key(blank)
    assert len(outbox.derive_outbox_key(SECRET)) == 32
    assert outbox.derive_outbox_key(f"  {SECRET}  ") == outbox.derive_outbox_key(SECRET)


def test_a_payload_over_the_size_limit_is_never_encrypted() -> None:
    def encrypt(size: int):
        return outbox._encrypt_payload(
            {"text": "x" * size},
            encryption_secret=SECRET,
            kind="contact_change",
            account_id=1,
            message_id="<m@example.invalid>",
        )

    overhead = len(json.dumps({"text": ""}, separators=(",", ":")))
    assert encrypt(outbox.MAX_OUTBOX_PAYLOAD_BYTES - overhead)  # exactly the limit
    with pytest.raises(ValueError, match="payload is too large"):
        encrypt(outbox.MAX_OUTBOX_PAYLOAD_BYTES - overhead + 1)


def test_a_payload_that_decrypts_to_something_other_than_an_object_is_invalid() -> None:
    nonce = b"n" * 12
    delivery = PatientPortalOutboundDelivery(
        account_id=3,
        kind="contact_change",
        message_id="<m@example.invalid>",
        encryption_key_id="primary",
        encryption_nonce=nonce,
    )
    data = outbox._associated_data(
        kind="contact_change", account_id=3, message_id="<m@example.invalid>"
    )
    key = outbox.derive_outbox_key(SECRET)
    for body in (b'["a list"]', b'"a string"', b"17", b"not json at all"):
        delivery.encrypted_payload = AESGCM(key).encrypt(nonce, body, data)
        with pytest.raises(outbox.OutboxPayloadError, match="payload is invalid"):
            outbox._decrypt_payload(delivery, encryption_secret=SECRET)
    delivery.encrypted_payload = AESGCM(key).encrypt(nonce, b'{"ok": true}', data)
    assert outbox._decrypt_payload(delivery, encryption_secret=SECRET) == {"ok": True}


def test_a_reset_delivery_needs_a_token_an_account_and_a_recipient() -> None:
    complete = {
        "reset_token": "t",
        "recipient": "fake@example.test",
        "reset_token_id": 1,
        "account_id": 2,
    }
    for missing in ("recipient", "reset_token_id", "account_id"):
        result = PasswordResetRequestResult(**{**complete, missing: None})
        with pytest.raises(PasswordResetTokenInvalidError):
            outbox.enqueue_password_reset_delivery(
                object(),  # never reached: refused before anything is stored
                result=result,
                reset_url="https://portal.example.test/reset",
                expires_in_seconds=60,
                encryption_secret=SECRET,
            )


def test_the_reset_queue_limit_is_positive_and_postgresql_admission_takes_its_lock() -> None:
    for limit in (0, -1):
        with pytest.raises(ValueError, match="max_pending must be positive"):
            outbox.enqueue_password_reset_request(
                object(),
                username="fake",
                email="fake@example.test",
                client_reference_hash="h",
                encryption_secret=SECRET,
                max_pending=limit,
            )

    statements: list[str] = []

    class Stop(Exception):
        pass

    class Session:
        def get_bind(self):
            return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

        def execute(self, statement):
            statements.append(str(statement.compile(compile_kwargs={"literal_binds": True})))

        def scalar(self, statement):
            raise Stop  # the lock came first; the count is not needed here

    with pytest.raises(Stop):
        outbox.enqueue_password_reset_request(
            Session(),
            username="fake",
            email="fake@example.test",
            client_reference_hash="h",
            encryption_secret=SECRET,
        )
    assert len(statements) == 1
    assert "pg_advisory_xact_lock" in statements[0]
    assert str(outbox.PASSWORD_RESET_QUEUE_ADMISSION_LOCK_ID) in statements[0]


# --------------------------------------------------------------------------------------------
# Reset failure and audit paths (a stand-in session)
# --------------------------------------------------------------------------------------------


class Untouchable:
    """A session that fails the test if anything uses it."""

    def __getattr__(self, name):
        raise AssertionError(f"the session must not be used ({name})")


def test_a_delivery_without_a_reset_token_has_no_reset_to_fail() -> None:
    delivery = PatientPortalOutboundDelivery(
        account_id=1, kind="contact_change", reset_token_id=None
    )
    assert outbox._mark_terminal_reset_failure(Untouchable(), delivery) is None


def test_a_superseded_audit_for_an_account_that_is_gone_records_nothing(monkeypatch) -> None:
    monkeypatch.setattr(outbox, "record_audit_event", lambda *a, **k: pytest.fail("recorded"))
    session = SimpleNamespace(scalar=lambda statement: None)
    delivery = PatientPortalOutboundDelivery(account_id=999, kind=OUTBOX_KIND_PASSWORD_RESET)
    assert outbox._record_reset_delivery_superseded(session, delivery, outcome="success") is None


class NestedSession:
    @contextmanager
    def begin_nested(self):
        yield

    def flush(self):
        return None


def test_a_superseded_audit_that_cannot_be_written_sends_the_row_for_another_attempt(
    monkeypatch, caplog
) -> None:
    def token_gone(*args, **kwargs):
        raise PasswordResetTokenInvalidError()

    def database_down(*args, **kwargs):
        raise SQLAlchemyError("FAKE host=db.internal password=FAKE-secret")

    monkeypatch.setattr(outbox, "record_password_reset_delivery_outcome", token_gone)
    monkeypatch.setattr(outbox, "_record_reset_delivery_superseded", database_down)
    caplog.set_level(logging.ERROR, logger="carlos_patient_portal.delivery_outbox")
    delivery = PatientPortalOutboundDelivery(
        id=41, account_id=1, reset_token_id=2, kind=OUTBOX_KIND_PASSWORD_RESET
    )

    kept = outbox._record_reset_delivery_outcome_best_effort(
        NestedSession(), delivery, outcome="success"
    )

    assert kept is False  # not completed as-is: it goes back for another attempt
    assert "delivery 41" in caplog.text and "SQLAlchemyError" in caplog.text
    assert "FAKE-secret" not in caplog.text and "db.internal" not in caplog.text
    # And when the superseded row is written, the same path completes.
    monkeypatch.setattr(outbox, "_record_reset_delivery_superseded", lambda *a, **k: None)
    assert (
        outbox._record_reset_delivery_outcome_best_effort(
            NestedSession(), delivery, outcome="success"
        )
        is True
    )


def test_a_reset_request_with_a_missing_field_is_an_invalid_payload() -> None:
    good = {"username": "fake", "email": "fake@example.test", "client_reference_hash": "h"}
    for field in good:
        for damaged in (
            {**good, field: ""},
            {**good, field: 5},
            {k: v for k, v in good.items() if k != field},
        ):
            with pytest.raises(outbox.OutboxPayloadError, match="request payload is invalid"):
                outbox._materialize_password_reset_request(
                    Untouchable(),
                    delivery_id=1,
                    expected_attempt_count=1,
                    payload=damaged,
                    context=None,
                    outbox_encryption_secret=SECRET,
                )


# --------------------------------------------------------------------------------------------
# With a database: the worker's refusals
# --------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def portal():
    app = migrated_development_app(outbox_encryption_secret=SECRET)
    account_id = activate_seeded_patient_account(app, TestClient(app))
    yield app, account_id
    app.state.database_engine.dispose()


def insert(app, *, kind, payload, account_id=None, reset_token_id=None, message_id=None):
    message_id = message_id or outbox._new_message_id()
    ciphertext, nonce = outbox._encrypt_payload(
        payload,
        encryption_secret=SECRET,
        kind=kind,
        account_id=account_id or 0,
        message_id=message_id,
    )
    with app.state.session_factory() as session, session.begin():
        row = PatientPortalOutboundDelivery(
            account_id=account_id,
            reset_token_id=reset_token_id,
            kind=kind,
            status=OUTBOX_STATUS_PENDING,
            encrypted_payload=ciphertext,
            encryption_nonce=nonce,
            encryption_key_id="primary",
            message_id=message_id,
            attempt_count=0,
            available_at=utc_now(),
            created_at=utc_now(),
        )
        session.add(row)
        session.flush()
        return row.id


def fetch(app, delivery_id):
    with app.state.session_factory() as session:
        row = session.get(PatientPortalOutboundDelivery, delivery_id)
        session.expunge(row)
        return row


def run(app, sender=None, **kwargs):
    defaults = {"max_attempts": 3, "lease_seconds": 60}
    return outbox.process_one_delivery(
        app.state.session_factory,
        email_sender=sender or RecordingPortalEmailSender(),
        encryption_secret=SECRET,
        **(defaults | kwargs),
    )


def test_a_reset_request_command_that_is_gone_or_not_one_is_not_materialized(portal) -> None:
    app, account_id = portal
    context = SimpleNamespace()
    payload = {"username": "fake", "email": "fake@example.test", "client_reference_hash": "h"}

    def materialize(delivery_id, attempt=1):
        return outbox._materialize_password_reset_request(
            app.state.session_factory,
            delivery_id=delivery_id,
            expected_attempt_count=attempt,
            payload=payload,
            context=context,
            outbox_encryption_secret=SECRET,
        )

    # No such row: reported as failed, nothing created.
    assert materialize(987654) == (OUTBOX_STATUS_FAILED, None)
    # Each of the three conditions alone refuses: a row of another kind that is otherwise exactly
    # what a worker holds (processing, the attempt it expects), a request command that is not being
    # processed (attempt matching), and one that another worker reclaimed (attempt differs).
    other = insert(
        app,
        kind="contact_change",
        payload={"recipient": "fake@example.test"},
        account_id=account_id,
    )
    with app.state.session_factory() as session, session.begin():
        row = session.get(PatientPortalOutboundDelivery, other)
        row.status, row.attempt_count, row.lease_expires_at = OUTBOX_STATUS_PROCESSING, 1, utc_now()
    assert materialize(other, attempt=1) == (OUTBOX_STATUS_PROCESSING, None)
    command = insert(app, kind=OUTBOX_KIND_PASSWORD_RESET_REQUEST, payload=payload)
    assert materialize(command, attempt=0) == (
        OUTBOX_STATUS_PENDING,
        None,
    )  # pending, not processing
    with app.state.session_factory() as session, session.begin():
        row = session.get(PatientPortalOutboundDelivery, command)
        row.status, row.attempt_count, row.lease_expires_at = OUTBOX_STATUS_PROCESSING, 2, utc_now()
    assert materialize(command, attempt=1) == (OUTBOX_STATUS_PROCESSING, None)  # another worker's


def test_a_reset_request_with_a_damaged_payload_fails_as_payload_invalid(portal) -> None:
    app, _ = portal
    command = insert(
        app,
        kind=OUTBOX_KIND_PASSWORD_RESET_REQUEST,
        payload={"username": "fake", "email": "", "client_reference_hash": "h"},
    )
    result = run(app, password_reset_request_context=SimpleNamespace(), delivery_id=command)
    assert result.delivery_id == command
    row = fetch(app, command)
    assert row.last_failure_code == "payload_invalid"
    assert row.status == OUTBOX_STATUS_PENDING  # retried until the attempts run out


def test_a_reset_delivery_whose_payload_has_the_wrong_types_is_payload_invalid(portal) -> None:
    app, account_id = portal
    delivery_id, _ = queue_reset(app, account_id)
    with app.state.session_factory() as session, session.begin():
        row = session.get(PatientPortalOutboundDelivery, delivery_id)
        ciphertext, nonce = outbox._encrypt_payload(
            {"recipient": "fake@example.test", "reset_url": 5, "expires_in_seconds": "soon"},
            encryption_secret=SECRET,
            kind=row.kind,
            account_id=row.account_id,
            message_id=row.message_id,
        )
        row.encrypted_payload, row.encryption_nonce = ciphertext, nonce
    sender = RecordingPortalEmailSender()
    run(app, sender, delivery_id=delivery_id)
    assert fetch(app, delivery_id).last_failure_code == "payload_invalid"
    assert sender.messages == []


def test_a_delivery_of_a_kind_the_worker_does_not_know_is_payload_invalid(
    portal, monkeypatch
) -> None:
    app, account_id = portal
    delivery_id = insert(
        app,
        kind="contact_change",
        payload={"recipient": "fake@example.test"},
        account_id=account_id,
    )
    # The stored kind is no longer any of the kinds this worker handles.
    monkeypatch.setattr(outbox, "OUTBOX_KIND_CONTACT_CHANGE", "renamed_kind")
    sender = RecordingPortalEmailSender()
    run(app, sender, delivery_id=delivery_id)
    assert fetch(app, delivery_id).last_failure_code == "payload_invalid"


# --------------------------------------------------------------------------------------------
# A booking notice whose key is gone
# --------------------------------------------------------------------------------------------


def test_a_booking_notice_whose_key_is_not_in_the_keyring_fails_at_once_and_is_audited() -> None:
    app = booking_app()
    try:
        client = TestClient(app)
        account_id = activate_seeded_patient_account(app, client)
        prompt_id = client.post(PATH, headers=headers(), json=prompt_request()).json()["id"]
        with app.state.session_factory.begin() as session:
            for existing in session.scalars(select(PatientPortalOutboundDelivery)):
                session.delete(existing)
            delivery = outbox.enqueue_booking_prompt_delivery(
                session,
                account_id=account_id,
                booking_prompt_id=prompt_id,
                sign_in_url="https://portal.example.test/sign-in",
                encryption_secret=SECRET,
            )
            delivery_id = delivery.id
        sender = RecordingPortalEmailSender()
        # The keyring does not hold the key the row was written with: retrying cannot help.
        outbox.process_one_delivery(
            app.state.session_factory,
            email_sender=sender,
            encryption_secret=SECRET,
            encryption_keys={"another": "k" * 32},
            max_attempts=5,
            lease_seconds=60,
            delivery_id=delivery_id,
        )
        row = fetch(app, delivery_id)
        assert row.status == OUTBOX_STATUS_FAILED and row.attempt_count == 1
        assert row.last_failure_code == outbox.OUTBOX_FAILURE_KEY_UNAVAILABLE
        with app.state.session_factory() as session:
            audited = session.scalars(
                select(PatientPortalAuditEvent).where(
                    PatientPortalAuditEvent.event_type == AUDIT_EVENT_BOOKING_PROMPT_DELIVERY,
                    PatientPortalAuditEvent.resource_id == str(prompt_id),
                )
            ).all()
        assert [(event.outcome, event.reason) for event in audited] == [
            (AUDIT_OUTCOME_FAILURE, outbox.OUTBOX_FAILURE_KEY_UNAVAILABLE)
        ]
    finally:
        app.state.database_engine.dispose()
