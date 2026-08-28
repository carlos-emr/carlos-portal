import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from carlos_patient_portal import delivery_outbox
from carlos_patient_portal.auth import PasswordResetRequestResult
from carlos_patient_portal.delivery_outbox import (
    PasswordResetRequestContext,
    enqueue_contact_change_delivery,
    enqueue_password_reset_delivery,
    process_one_delivery,
)
from carlos_patient_portal.email_delivery import PortalEmailDeliveryError
from carlos_patient_portal.maintenance import cleanup_transient_auth_rows, summarize_outbox
from carlos_patient_portal.models import (
    AUDIT_EVENT_ACCOUNT_CONTACT_UPDATE,
    AUDIT_EVENT_PASSWORD_RESET_DELIVERY,
    AUDIT_OUTCOME_FAILURE,
    OUTBOX_KIND_PASSWORD_RESET,
    OUTBOX_KIND_PASSWORD_RESET_REQUEST,
    OUTBOX_STATUS_DELIVERED,
    OUTBOX_STATUS_FAILED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PROCESSING,
    PASSWORD_RESET_STATUS_PENDING,
    PASSWORD_RESET_STATUS_REVOKED,
    PatientPortalAuditEvent,
    PatientPortalOutboundDelivery,
    PatientPortalPasswordResetToken,
    utc_now,
)
from carlos_patient_portal.runtime import (
    PortalOperationalMetrics,
    auth_policy_from_settings,
)
from carlos_patient_portal.token_keys import PortalTokenKeys
from tests.support import (
    OUTBOX_ENCRYPTION_SECRET,
    SEEDED_INVITE_EMAIL,
    RecordingPortalEmailSender,
    activate_seeded_patient_account,
    activation_request,
    carlos_staff_headers,
    development_settings,
    migrated_development_app,
    migrated_staging_app,
    seeded_invite_request,
)


def queue_reset(
    app: object,
    account_id: int,
    *,
    encryption_secret: str = OUTBOX_ENCRYPTION_SECRET,
    encryption_key_id: str = "primary",
) -> tuple[int, int]:
    with app.state.session_factory() as session:
        with session.begin():
            reset = PatientPortalPasswordResetToken(
                account_id=account_id,
                token_hash="r" * 64,
                status=PASSWORD_RESET_STATUS_PENDING,
                created_at=utc_now(),
                expires_at=utc_now() + timedelta(hours=1),
            )
            session.add(reset)
            session.flush()
            delivery = enqueue_password_reset_delivery(
                session,
                result=PasswordResetRequestResult(
                    reset_token="raw-reset-token",
                    recipient="patient@example.test",
                    reset_token_id=reset.id,
                    account_id=account_id,
                ),
                reset_url="https://portal.example.test/reset#token=raw-reset-token",
                expires_in_seconds=3600,
                encryption_secret=encryption_secret,
                encryption_key_id=encryption_key_id,
            )
            return delivery.id, reset.id


def test_outbox_encrypts_and_delivers_reset_with_stable_message_id() -> None:
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(
        email_sender=sender,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
    )
    account_id = activate_seeded_patient_account(app, TestClient(app))
    delivery_id, reset_id = queue_reset(app, account_id)

    with app.state.session_factory() as session:
        queued = session.get(PatientPortalOutboundDelivery, delivery_id)
        assert queued is not None
        assert b"raw-reset-token" not in queued.encrypted_payload
        assert b"patient@example.test" not in queued.encrypted_payload
        expected_message_id = queued.message_id

    result = process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        max_attempts=3,
        lease_seconds=60,
    )

    assert result is not None
    assert result.status == OUTBOX_STATUS_DELIVERED
    assert sender.messages[-1]["message_id"] == expected_message_id
    with app.state.session_factory() as session:
        assert session.get(PatientPortalPasswordResetToken, reset_id).status == (
            PASSWORD_RESET_STATUS_PENDING
        )
        assert session.scalar(
            select(PatientPortalAuditEvent).where(
                PatientPortalAuditEvent.event_type == AUDIT_EVENT_PASSWORD_RESET_DELIVERY
            )
        ) is not None


def test_outbox_rotation_retains_the_old_key_for_queued_delivery() -> None:
    old_secret = "v" * 32
    active_secret = "n" * 32
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(
        email_sender=sender,
        outbox_encryption_secret=old_secret,
    )
    account_id = activate_seeded_patient_account(app, TestClient(app))
    delivery_id, _ = queue_reset(
        app,
        account_id,
        encryption_secret=old_secret,
        encryption_key_id="2026-07",
    )

    result = process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=active_secret,
        encryption_keys={"2026-07": old_secret, "2026-08": active_secret},
        max_attempts=3,
        lease_seconds=60,
    )

    assert result is not None
    assert result.status == OUTBOX_STATUS_DELIVERED
    with app.state.session_factory() as session:
        assert session.get(PatientPortalOutboundDelivery, delivery_id).status == (
            OUTBOX_STATUS_DELIVERED
        )


def test_delivery_retries_when_its_audit_row_cannot_be_written(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unwritable audit row must send the delivery back, not close it as delivered.

    Falling through to `delivered` meant a live password-reset link reached the patient with
    neither a SUCCESS nor a FAILURE row behind it - the exact condition a breach review cannot
    reconstruct. Retrying risks a duplicate email, which is the cheaper failure.
    """
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(
        email_sender=sender,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
    )
    account_id = activate_seeded_patient_account(app, TestClient(app))
    delivery_id, reset_id = queue_reset(app, account_id)

    def fail_audit(*args: object, **kwargs: object) -> None:
        raise SQLAlchemyError("audit unavailable")

    monkeypatch.setattr(
        delivery_outbox,
        "record_password_reset_delivery_outcome",
        fail_audit,
    )
    result = process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        max_attempts=3,
        lease_seconds=60,
    )

    assert result is not None
    assert result.status == OUTBOX_STATUS_PENDING
    with app.state.session_factory() as session:
        delivery = session.get(PatientPortalOutboundDelivery, delivery_id)
        assert delivery.status == OUTBOX_STATUS_PENDING
        assert delivery.delivered_at is None
        # The token stays usable: the message did go out, and the patient must still be able
        # to complete the reset while the row is retried.
        assert session.get(PatientPortalPasswordResetToken, reset_id).status == (
            PASSWORD_RESET_STATUS_PENDING
        )


def test_reset_delivered_during_a_token_race_is_audited_as_superseded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reset email that went out must never be recorded as a delivery failure.

    If the patient completes the reset, or requests another, between the send and
    _finish_delivery, record_password_reset_delivery_outcome raises. That previously set the
    row to `failed` - terminal, so the terminal handler never ran either - leaving a link that
    physically landed in the mailbox with neither a SUCCESS nor a FAILURE audit row, and
    sending operators after an SMTP problem that never happened.
    """
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(
        email_sender=sender,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
    )
    account_id = activate_seeded_patient_account(app, TestClient(app))
    delivery_id, reset_id = queue_reset(app, account_id)

    def token_already_consumed(*args: object, **kwargs: object) -> None:
        raise delivery_outbox.PasswordResetTokenInvalidError()

    monkeypatch.setattr(
        delivery_outbox,
        "record_password_reset_delivery_outcome",
        token_already_consumed,
    )
    result = process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        max_attempts=3,
        lease_seconds=60,
    )

    assert result is not None
    assert result.status == OUTBOX_STATUS_DELIVERED
    assert len(sender.messages) == 1
    with app.state.session_factory() as session:
        assert session.get(PatientPortalOutboundDelivery, delivery_id).status == (
            OUTBOX_STATUS_DELIVERED
        )
        superseded = session.scalar(
            select(PatientPortalAuditEvent).where(
                PatientPortalAuditEvent.event_type == AUDIT_EVENT_PASSWORD_RESET_DELIVERY,
                PatientPortalAuditEvent.reason == "password_reset:superseded",
            )
        )
        assert superseded is not None
        assert superseded.account_id == account_id


def test_retry_backoff_reaches_its_cap_and_is_jittered() -> None:
    """The retry budget must outlast an ordinary relay outage, and must not stampede it.

    At the previous 8 attempts the schedule was 2+4+8+16+32+64+128+256 = 510 seconds, so the
    15-minute cap was unreachable and a commonplace ~10-minute SMTP outage terminally failed
    everything queued - revoking each patient's pending reset token. The delay was also fully
    deterministic, so every queued row became available in the same instant.
    """
    settings = development_settings()
    ceilings = [
        min(delivery_outbox.OUTBOX_MAX_RETRY_DELAY_SECONDS, 2 ** min(attempt, 10))
        for attempt in range(1, settings.outbox_max_attempts + 1)
    ]

    # The cap is actually engaged rather than being dead configuration.
    assert delivery_outbox.OUTBOX_MAX_RETRY_DELAY_SECONDS in ceilings
    # And the budget outlasts a long relay outage.
    assert sum(ceilings) > 60 * 60

    samples = {delivery_outbox._retry_delay_seconds(6) for _ in range(50)}
    assert len(samples) > 1, "a deterministic delay stampedes the relay on recovery"
    assert all(0 < sample <= 2**6 for sample in samples)


def test_active_delivery_renews_its_lease_during_a_slow_provider_call(tmp_path) -> None:
    entered_provider = Event()
    release_provider = Event()

    class BlockingSender:
        def send_password_reset(self, **kwargs: object) -> None:
            entered_provider.set()
            assert release_provider.wait(timeout=5)

    app = migrated_development_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'outbox.db'}",
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
    )
    account_id = activate_seeded_patient_account(app, TestClient(app))
    queue_reset(app, account_id)

    with ThreadPoolExecutor(max_workers=1) as executor:
        first_worker = executor.submit(
            process_one_delivery,
            app.state.session_factory,
            email_sender=BlockingSender(),
            encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            max_attempts=3,
            lease_seconds=1,
        )
        assert entered_provider.wait(timeout=5)
        time.sleep(1.2)
        second_worker = process_one_delivery(
            app.state.session_factory,
            email_sender=RecordingPortalEmailSender(),
            encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            max_attempts=3,
            lease_seconds=1,
        )
        release_provider.set()
        first_result = first_worker.result(timeout=5)

    assert second_worker is None
    assert first_result is not None
    assert first_result.status == OUTBOX_STATUS_DELIVERED


def test_terminal_delivery_failure_revokes_reset_token() -> None:
    sender = RecordingPortalEmailSender(fail=True)
    app = migrated_development_app(
        email_sender=sender,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
    )
    account_id = activate_seeded_patient_account(app, TestClient(app))
    delivery_id, reset_id = queue_reset(app, account_id)

    result = process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        max_attempts=1,
        lease_seconds=60,
    )

    assert result is not None
    assert result.status == OUTBOX_STATUS_FAILED
    with app.state.session_factory() as session:
        assert session.get(PatientPortalOutboundDelivery, delivery_id).last_failure_code == (
            "PortalEmailDeliveryError"
        )
        assert session.get(PatientPortalPasswordResetToken, reset_id).status == (
            PASSWORD_RESET_STATUS_REVOKED
        )


def test_expired_lease_recovers_after_worker_loss() -> None:
    class CrashingSender:
        def send_password_reset(self, **kwargs: object) -> None:
            # Model SMTP accepting the message followed by worker death before the delivery-state
            # commit. The retry must reuse the same Message-ID so downstream deduplication works.
            sender.send_password_reset(**kwargs)
            raise KeyboardInterrupt

    sender = RecordingPortalEmailSender()
    app = migrated_development_app(
        email_sender=sender,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
    )
    account_id = activate_seeded_patient_account(app, TestClient(app))
    delivery_id, _ = queue_reset(app, account_id)

    with pytest.raises(KeyboardInterrupt):
        process_one_delivery(
            app.state.session_factory,
            email_sender=CrashingSender(),
            encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            max_attempts=3,
            lease_seconds=60,
        )
    with app.state.session_factory() as session:
        with session.begin():
            delivery = session.get(PatientPortalOutboundDelivery, delivery_id)
            assert delivery is not None
            assert delivery.status == OUTBOX_STATUS_PROCESSING
            delivery.lease_expires_at = utc_now() - timedelta(seconds=1)

    recovered = process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        max_attempts=3,
        lease_seconds=60,
    )
    assert recovered is not None
    assert recovered.status == OUTBOX_STATUS_DELIVERED
    assert sender.messages[0]["message_id"] == sender.messages[1]["message_id"]


def test_reset_and_outbox_rollback_together_when_the_source_transaction_fails() -> None:
    app = migrated_development_app(outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET)
    account_id = activate_seeded_patient_account(app, TestClient(app))

    def fail_source_transaction() -> None:
        with app.state.session_factory() as session, session.begin():
            reset = PatientPortalPasswordResetToken(
                account_id=account_id,
                token_hash="t" * 64,
                status=PASSWORD_RESET_STATUS_PENDING,
                created_at=utc_now(),
                expires_at=utc_now() + timedelta(hours=1),
            )
            session.add(reset)
            session.flush()
            enqueue_password_reset_delivery(
                session,
                result=PasswordResetRequestResult(
                    reset_token="rolled-back-token",
                    recipient="patient@example.test",
                    reset_token_id=reset.id,
                    account_id=account_id,
                ),
                reset_url="https://portal.example.test/reset#token=rolled-back-token",
                expires_in_seconds=3600,
                encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            )
            raise RuntimeError("simulated source transaction failure")

    with pytest.raises(RuntimeError):
        fail_source_transaction()

    with app.state.session_factory() as session:
        assert session.scalar(
            select(PatientPortalPasswordResetToken).where(
                PatientPortalPasswordResetToken.token_hash == "t" * 64
            )
        ) is None
        assert session.scalar(select(PatientPortalOutboundDelivery)) is None


def test_failed_delivery_is_identifiable_counted_and_queryable(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A failure must name the row, raise a counter, and be findable afterwards.

    All three outbox log calls previously interpolated only a failure code or an exception
    class, so "Outbound delivery attempt failed: SMTPException" could not tell an operator
    whether this was one message or ten thousand. No metric was recorded at all - the worker is
    a separate process with no metrics endpoint - and rows piled up in `failed` were invisible:
    readiness checks only connectivity and the schema head.
    """
    caplog.set_level(logging.ERROR, logger="carlos_patient_portal.delivery_outbox")

    class FailingSender:
        def send_password_reset(self, **kwargs: object) -> None:
            raise PortalEmailDeliveryError("relay refused")

    metrics = PortalOperationalMetrics()
    app = migrated_development_app(outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET)
    account_id = activate_seeded_patient_account(app, TestClient(app))
    delivery_id, _reset_id = queue_reset(app, account_id)

    result = process_one_delivery(
        app.state.session_factory,
        email_sender=FailingSender(),
        encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        max_attempts=3,
        lease_seconds=60,
        operational_metrics=metrics,
    )

    assert result is not None
    logged = [r.message for r in caplog.records if "outbox_delivery_failed" in r.message]
    assert logged, "the failure carried no identity"
    assert f'"delivery_id":{delivery_id}' in logged[0]
    assert '"kind":"password_reset"' in logged[0]
    assert '"attempt_count":1' in logged[0]
    assert metrics.snapshot()["failures"].get("outbox_password_reset") == 1

    # And the row is queryable rather than invisible.
    with app.state.session_factory() as session:
        summary = summarize_outbox(session)
    assert summary
    assert summary[0]["kind"] == "password_reset"
    assert summary[0]["count"] == 1


def test_cleanup_bounds_outbox_retention_and_reports_what_it_removes() -> None:
    """The outbox must have retention, and the report must not understate the deletion.

    PatientPortalOutboundDelivery appeared in no cleanup predicate. Contact-change rows carry
    reset_token_id = NULL so nothing cascaded them either, and the table grew without bound
    holding encrypted recipient addresses and reset URLs. Reset-linked rows were cascaded away
    by the reset-token delete without the report ever mentioning it, so deliveries are now
    removed first, under their own predicate, and counted.
    """
    app = migrated_development_app(outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET)
    account_id = activate_seeded_patient_account(app, TestClient(app))
    delivery_id, _reset_id = queue_reset(app, account_id)

    stale = utc_now() - timedelta(days=90)
    with app.state.session_factory() as session:
        with session.begin():
            delivery = session.get(PatientPortalOutboundDelivery, delivery_id)
            delivery.status = OUTBOX_STATUS_DELIVERED
            delivery.delivered_at = stale
            delivery.lease_expires_at = None
            delivery.created_at = stale

    with app.state.session_factory() as session:
        with session.begin():
            result = cleanup_transient_auth_rows(session, before=utc_now() - timedelta(days=30))

    assert result.outbound_deliveries == 1
    assert result.total >= 1
    with app.state.session_factory() as session:
        assert session.get(PatientPortalOutboundDelivery, delivery_id) is None


def test_cleanup_does_not_cascade_a_linked_delivery_outside_the_outbox_batch() -> None:
    """The reset pass must not bypass the independent outbox batch or undercount deletions."""
    app = migrated_development_app(outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET)
    account_id = activate_seeded_patient_account(app, TestClient(app))
    stale = utc_now() - timedelta(days=90)
    cutoff = utc_now() - timedelta(days=30)

    # Insert an unrelated delivery first so it consumes the one-row outbox batch before the
    # reset-linked delivery. The reset parent must remain until that linked row gets its own turn.
    with app.state.session_factory() as session:
        with session.begin():
            unrelated = enqueue_contact_change_delivery(
                session,
                account_id=account_id,
                recipient="previous@example.test",
                encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            )
            unrelated.status = OUTBOX_STATUS_DELIVERED
            unrelated.created_at = stale
            unrelated.delivered_at = stale
            unrelated_id = unrelated.id

    linked_delivery_id, reset_id = queue_reset(app, account_id)
    with app.state.session_factory() as session:
        with session.begin():
            reset = session.get(PatientPortalPasswordResetToken, reset_id)
            linked = session.get(PatientPortalOutboundDelivery, linked_delivery_id)
            assert reset is not None
            assert linked is not None
            reset.created_at = stale - timedelta(hours=1)
            reset.expires_at = stale
            linked.status = OUTBOX_STATUS_DELIVERED
            linked.created_at = stale
            linked.delivered_at = stale
            linked.lease_expires_at = None

    with app.state.session_factory() as session:
        with session.begin():
            first_dry_run = cleanup_transient_auth_rows(
                session,
                before=cutoff,
                batch_size=1,
                dry_run=True,
            )
        with session.begin():
            first_live_run = cleanup_transient_auth_rows(
                session,
                before=cutoff,
                batch_size=1,
            )

    assert first_dry_run.outbound_deliveries == 1
    assert first_dry_run.reset_records == 0
    assert first_live_run.outbound_deliveries == 1
    assert first_live_run.reset_records == 0
    with app.state.session_factory() as session:
        assert session.get(PatientPortalOutboundDelivery, unrelated_id) is None
        assert session.get(PatientPortalOutboundDelivery, linked_delivery_id) is not None
        assert session.get(PatientPortalPasswordResetToken, reset_id) is not None

    with app.state.session_factory() as session:
        with session.begin():
            second_dry_run = cleanup_transient_auth_rows(
                session,
                before=cutoff,
                batch_size=1,
                dry_run=True,
            )
        with session.begin():
            second_live_run = cleanup_transient_auth_rows(
                session,
                before=cutoff,
                batch_size=1,
            )

    assert second_dry_run.outbound_deliveries == 1
    assert second_dry_run.reset_records == 1
    assert second_live_run.outbound_deliveries == 1
    assert second_live_run.reset_records == 1
    with app.state.session_factory() as session:
        assert session.get(PatientPortalOutboundDelivery, linked_delivery_id) is None
        assert session.get(PatientPortalPasswordResetToken, reset_id) is None


@pytest.mark.parametrize("unsettled_status", [OUTBOX_STATUS_PENDING, OUTBOX_STATUS_PROCESSING])
def test_cleanup_preserves_unsettled_contact_change_notices(unsettled_status: str) -> None:
    """Retention must not erase a security notice before its delivery reaches an outcome."""
    app = migrated_development_app(outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET)
    account_id = activate_seeded_patient_account(app, TestClient(app))
    stale = utc_now() - timedelta(days=90)

    with app.state.session_factory() as session:
        with session.begin():
            delivery = enqueue_contact_change_delivery(
                session,
                account_id=account_id,
                recipient="previous@example.test",
                encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            )
            delivery.status = unsettled_status
            delivery.created_at = stale
            delivery.lease_expires_at = (
                utc_now() + timedelta(minutes=5)
                if unsettled_status == OUTBOX_STATUS_PROCESSING
                else None
            )
            session.flush()
            delivery_id = delivery.id

    with app.state.session_factory() as session:
        with session.begin():
            result = cleanup_transient_auth_rows(session, before=utc_now() - timedelta(days=30))

    assert result.outbound_deliveries == 0
    with app.state.session_factory() as session:
        retained = session.get(PatientPortalOutboundDelivery, delivery_id)
        assert retained is not None
        assert retained.status == unsettled_status


@pytest.mark.parametrize("unsettled_status", [OUTBOX_STATUS_PENDING, OUTBOX_STATUS_PROCESSING])
def test_cleanup_preserves_expired_reset_parent_with_unsettled_delivery(
    unsettled_status: str,
) -> None:
    """Deleting an expired reset parent must not cascade queued or leased delivery work."""
    app = migrated_development_app(outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET)
    account_id = activate_seeded_patient_account(app, TestClient(app))
    delivery_id, reset_id = queue_reset(app, account_id)
    stale = utc_now() - timedelta(days=90)

    with app.state.session_factory() as session:
        with session.begin():
            reset = session.get(PatientPortalPasswordResetToken, reset_id)
            delivery = session.get(PatientPortalOutboundDelivery, delivery_id)
            assert reset is not None
            assert delivery is not None
            reset.created_at = stale - timedelta(hours=1)
            reset.expires_at = stale
            delivery.created_at = stale
            delivery.status = unsettled_status
            delivery.lease_expires_at = (
                utc_now() + timedelta(minutes=5)
                if unsettled_status == OUTBOX_STATUS_PROCESSING
                else None
            )

    with app.state.session_factory() as session:
        with session.begin():
            result = cleanup_transient_auth_rows(session, before=utc_now() - timedelta(days=30))

    assert result.outbound_deliveries == 0
    assert result.reset_records == 0
    with app.state.session_factory() as session:
        assert session.get(PatientPortalPasswordResetToken, reset_id) is not None
        retained = session.get(PatientPortalOutboundDelivery, delivery_id)
        assert retained is not None
        assert retained.status == unsettled_status


def test_rotating_the_outbox_secret_does_not_strand_queued_mail() -> None:
    """A row encrypted under a retired key must stay deliverable across a rotation.

    _decrypt_payload hard-rejected any key id but "primary" against a single SecretStr, so
    rotating PATIENT_PORTAL_OUTBOX_ENCRYPTION_SECRET made every already-queued row permanently
    undecryptable: each burned its full retry budget and each password-reset row then hit
    _mark_terminal_reset_failure, revoking a token the patient was waiting on.
    """
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(
        email_sender=sender,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
    )
    account_id = activate_seeded_patient_account(app, TestClient(app))
    queue_reset(app, account_id)

    rotated_secret = f"rotated-{OUTBOX_ENCRYPTION_SECRET}"
    result = process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=rotated_secret,
        encryption_keys={"primary": OUTBOX_ENCRYPTION_SECRET, "next": rotated_secret},
        max_attempts=3,
        lease_seconds=60,
    )

    assert result is not None
    assert result.status == OUTBOX_STATUS_DELIVERED
    assert len(sender.messages) == 1


def test_an_absent_outbox_key_fails_terminally_without_revoking_the_token() -> None:
    """A key that is genuinely gone must not spend the retry budget.

    Every attempt would fail identically, and the exhausted budget ends at
    _mark_terminal_reset_failure - revoking a live reset token because of a configuration
    fault the patient had no part in.
    """
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(
        email_sender=sender,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
    )
    account_id = activate_seeded_patient_account(app, TestClient(app))
    delivery_id, reset_id = queue_reset(app, account_id)
    with app.state.session_factory() as session:
        with session.begin():
            session.get(PatientPortalOutboundDelivery, delivery_id).encryption_key_id = "retired"

    result = process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        encryption_keys={"primary": OUTBOX_ENCRYPTION_SECRET},
        max_attempts=3,
        lease_seconds=60,
    )

    assert result is not None
    assert result.status == OUTBOX_STATUS_FAILED
    assert sender.messages == []
    with app.state.session_factory() as session:
        row = session.get(PatientPortalOutboundDelivery, delivery_id)
        assert row.attempt_count == 1, "a missing key must not be retried"
        assert row.last_failure_code == delivery_outbox.OUTBOX_FAILURE_KEY_UNAVAILABLE
        # A previous attempt may have sent the message before losing its audit transaction, so
        # the token remains usable; the terminal configuration failure is still reconstructable.
        assert session.get(PatientPortalPasswordResetToken, reset_id).status == (
            PASSWORD_RESET_STATUS_PENDING
        )
        failure = session.scalar(
            select(PatientPortalAuditEvent).where(
                PatientPortalAuditEvent.event_type == AUDIT_EVENT_PASSWORD_RESET_DELIVERY,
                PatientPortalAuditEvent.outcome == AUDIT_OUTCOME_FAILURE,
                PatientPortalAuditEvent.reason
                == "email:encryption_key_unavailable",
            )
        )
        assert failure is not None
        assert failure.account_id == account_id


def test_an_absent_outbox_key_audits_undelivered_contact_change_notice() -> None:
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(
        email_sender=sender,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
    )
    account_id = activate_seeded_patient_account(app, TestClient(app))
    with app.state.session_factory() as session:
        with session.begin():
            delivery = enqueue_contact_change_delivery(
                session,
                account_id=account_id,
                recipient="previous@example.test",
                encryption_secret=OUTBOX_ENCRYPTION_SECRET,
                encryption_key_id="retired",
            )
            delivery_id = delivery.id

    result = process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        encryption_keys={"primary": OUTBOX_ENCRYPTION_SECRET},
        max_attempts=3,
        lease_seconds=60,
    )

    assert result is not None
    assert result.status == OUTBOX_STATUS_FAILED
    assert sender.messages == []
    with app.state.session_factory() as session:
        delivery = session.get(PatientPortalOutboundDelivery, delivery_id)
        assert delivery is not None
        assert delivery.last_failure_code == delivery_outbox.OUTBOX_FAILURE_KEY_UNAVAILABLE
        failure = session.scalar(
            select(PatientPortalAuditEvent).where(
                PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACCOUNT_CONTACT_UPDATE,
                PatientPortalAuditEvent.outcome == AUDIT_OUTCOME_FAILURE,
                PatientPortalAuditEvent.reason == "delivery_unavailable",
            )
        )
        assert failure is not None
        assert failure.account_id == account_id


def test_password_reset_route_resolves_every_identity_through_the_outbox() -> None:
    """A matching queued command materializes and delivers the second-stage reset email."""
    sender = RecordingPortalEmailSender()
    app = migrated_staging_app(
        email_sender=sender,
        outbox_encryption_secret=None,
        outbox_encryption_keyring=json.dumps(
            {
                "2026-07": "v" * 32,
                "2026-08": "n" * 32,
            }
        ),
        outbox_active_key_id="2026-08",
    )
    # TrustedHostMiddleware allows the configured public base URL, not "testserver".
    client = TestClient(app, base_url="https://portal.example.test")

    # /dev/admin is development-only, so the account is seeded the way a real staging
    # deployment would: through the authenticated internal API.
    invite = client.post(
        "/internal/carlos/patients/1234/invites",
        headers=carlos_staff_headers("portal.invite.manage"),
        json=seeded_invite_request(),
    )
    assert invite.status_code == 201, invite.text
    activation = client.post(
        "/auth/activate",
        json=activation_request(
            invite.json()["invite_token"],
            mfa_delivery_method="sms",
            phone_number="+16135550199",
        ),
    )
    assert activation.status_code in {200, 201}, activation.text

    response = client.post(
        "/auth/password-reset/request",
        json={"username": "patient.user", "email": SEEDED_INVITE_EMAIL},
    )

    assert response.status_code == 202
    with app.state.session_factory() as session:
        queued_commands = session.scalars(
            select(PatientPortalOutboundDelivery).order_by(PatientPortalOutboundDelivery.id)
        ).all()
        assert session.scalars(select(PatientPortalPasswordResetToken)).all() == []
    assert [row.kind for row in queued_commands] == [OUTBOX_KIND_PASSWORD_RESET_REQUEST]
    assert queued_commands[0].account_id is None

    settings = app.state.settings
    assert settings.session_secret is not None
    assert settings.public_base_url is not None
    reset_context = PasswordResetRequestContext(
        policy=auth_policy_from_settings(settings),
        reset_token_secret=PortalTokenKeys.derive(
            settings.session_secret.get_secret_value()
        ).password_reset,
        clinic_id=settings.clinic_id,
        public_base_url=settings.public_base_url,
        token_ttl_seconds=settings.password_reset_token_ttl_seconds,
        outbox_active_key_id=settings.outbox_active_key_id,
    )
    processed = process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=settings.resolved_outbox_keyring[settings.outbox_active_key_id],
        encryption_keys=settings.resolved_outbox_keyring,
        max_attempts=settings.outbox_max_attempts,
        lease_seconds=settings.outbox_lease_seconds,
        password_reset_request_context=reset_context,
    )
    assert processed is not None
    assert processed.status == OUTBOX_STATUS_DELIVERED

    with app.state.session_factory() as session:
        valid_rows = session.scalars(
            select(PatientPortalOutboundDelivery).order_by(PatientPortalOutboundDelivery.id)
        ).all()
    assert [row.kind for row in valid_rows] == [
        OUTBOX_KIND_PASSWORD_RESET_REQUEST,
        OUTBOX_KIND_PASSWORD_RESET,
    ]
    assert valid_rows[0].account_id is None
    assert all(
        row.encryption_key_id == app.state.settings.outbox_active_key_id for row in valid_rows
    )

    invalid_response = client.post(
        "/auth/password-reset/request",
        json={"username": "missing.patient", "email": "missing@example.test"},
    )

    assert invalid_response.status_code == 202
    processed_invalid = process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=settings.resolved_outbox_keyring[settings.outbox_active_key_id],
        encryption_keys=settings.resolved_outbox_keyring,
        max_attempts=settings.outbox_max_attempts,
        lease_seconds=settings.outbox_lease_seconds,
        password_reset_request_context=reset_context,
    )
    assert processed_invalid is not None
    assert processed_invalid.status == OUTBOX_STATUS_DELIVERED
    with app.state.session_factory() as session:
        all_rows = session.scalars(
            select(PatientPortalOutboundDelivery).order_by(PatientPortalOutboundDelivery.id)
        ).all()
    # Both public submissions durably enqueue the same encrypted, account-neutral command. Only
    # the worker can distinguish them, and only the matching command produces the second-stage
    # email delivery after the response path is complete.
    assert [row.kind for row in all_rows] == [
        OUTBOX_KIND_PASSWORD_RESET_REQUEST,
        OUTBOX_KIND_PASSWORD_RESET,
        OUTBOX_KIND_PASSWORD_RESET_REQUEST,
    ]
    assert all_rows[-1].account_id is None


def test_password_reset_hit_and_miss_enqueue_identical_account_neutral_work() -> None:
    sender = RecordingPortalEmailSender()
    app = migrated_staging_app(
        email_sender=sender,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
    )
    client = TestClient(app, base_url="https://portal.example.test")
    invite = client.post(
        "/internal/carlos/patients/1234/invites",
        headers=carlos_staff_headers("portal.invite.manage"),
        json=seeded_invite_request(),
    )
    assert invite.status_code == 201
    assert client.post(
        "/auth/activate",
        json=activation_request(
            invite.json()["invite_token"],
            mfa_delivery_method="sms",
            phone_number="+16135550199",
        ),
    ).status_code in {200, 201}

    valid_response = client.post(
        "/auth/password-reset/request",
        json={"username": "patient.user", "email": SEEDED_INVITE_EMAIL},
    )
    invalid_response = client.post(
        "/auth/password-reset/request",
        json={"username": "missing.patient", "email": "missing@example.test"},
    )

    assert valid_response.status_code == invalid_response.status_code == 202
    assert valid_response.json() == invalid_response.json()
    with app.state.session_factory() as session:
        commands = session.scalars(
            select(PatientPortalOutboundDelivery).order_by(PatientPortalOutboundDelivery.id)
        ).all()
        reset_tokens = session.scalars(select(PatientPortalPasswordResetToken)).all()
    assert [command.kind for command in commands] == [
        OUTBOX_KIND_PASSWORD_RESET_REQUEST,
        OUTBOX_KIND_PASSWORD_RESET_REQUEST,
    ]
    assert all(command.account_id is None for command in commands)
    assert reset_tokens == []


def test_password_reset_queue_applies_account_neutral_durable_backpressure() -> None:
    app = migrated_staging_app(
        email_sender=RecordingPortalEmailSender(),
        password_reset_queue_max_pending=10,
        password_reset_queue_retry_after_seconds=45,
    )
    client = TestClient(app, base_url="https://portal.example.test")

    admitted = [
        client.post(
            "/auth/password-reset/request",
            json={
                "username": f"missing.patient{index}",
                "email": f"missing{index}@example.test",
            },
        )
        for index in range(10)
    ]
    rejected = client.post(
        "/auth/password-reset/request",
        json={"username": "patient.user", "email": SEEDED_INVITE_EMAIL},
    )

    assert all(response.status_code == 202 for response in admitted)
    assert rejected.status_code == 503
    assert rejected.headers["retry-after"] == "45"
    assert rejected.json() == {"detail": "password reset is temporarily unavailable"}
    with app.state.session_factory() as session:
        commands = session.scalars(select(PatientPortalOutboundDelivery)).all()
    assert len(commands) == 10
    assert all(command.kind == OUTBOX_KIND_PASSWORD_RESET_REQUEST for command in commands)
    assert app.state.operational_metrics.snapshot()["failures"] == {
        "password_reset_queue_full": 1
    }
