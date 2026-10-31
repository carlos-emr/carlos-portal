import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, func, select, text

from carlos_patient_portal.models import (
    AUDIT_EVENT_RETENTION_POLICY_OVERRIDE,
    PatientPortalAuditEvent,
)
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    migrated_development_app,
)


def test_startup_continues_after_a_real_retention_notice_write_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        audit_retention_days=365,
        allow_short_audit_retention=True,
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    engine = app.state.database_engine
    marker = "FAKE private startup audit details"
    failures = []
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE fake_startup_reuse (value TEXT)"))
        connection.execute(
            text(
                "CREATE TRIGGER fake_reject_policy_audit BEFORE INSERT "
                "ON patient_portal_audit_events "
                "WHEN NEW.event_type = 'retention.policy_override' BEGIN "
                "SELECT RAISE(ABORT, 'FAKE private startup audit details'); END"
            )
        )

    @event.listens_for(engine, "handle_error")
    def observe_real_driver_failure(context):
        failures.append(
            (type(context.original_exception).__name__, str(context.original_exception))
        )

    caplog.set_level(logging.WARNING)
    try:
        with TestClient(app) as client:
            health = client.get("/health")
            assert health.status_code == 200
            assert health.json() == {"status": "ok"}
            assert failures == [("IntegrityError", marker)]
            assert (
                app.state.operational_metrics.snapshot()["failures"]["retention_policy_audit"] == 1
            )
            with app.state.session_factory() as session:
                assert (
                    session.scalar(
                        select(func.count())
                        .select_from(PatientPortalAuditEvent)
                        .where(
                            PatientPortalAuditEvent.event_type
                            == AUDIT_EVENT_RETENTION_POLICY_OVERRIDE
                        )
                    )
                    == 0
                )
            # Fresh work can commit after the failed startup transaction rolled back.
            with engine.begin() as connection:
                connection.execute(text("INSERT INTO fake_startup_reuse VALUES ('FAKE reuse')"))
            with engine.connect() as connection:
                assert connection.execute(text("SELECT value FROM fake_startup_reuse")).all() == [
                    ("FAKE reuse",)
                ]
            errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
            assert any("IntegrityError" in record.getMessage() for record in errors)
            assert all(record.exc_info is None for record in errors)
            assert marker not in caplog.text
    finally:
        engine.dispose()
