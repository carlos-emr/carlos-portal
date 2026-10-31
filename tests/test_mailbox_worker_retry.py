from itertools import count

import anyio
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from carlos_patient_portal import mailbox_worker, main
from carlos_patient_portal.mailbox_models import MailboxBase, MailboxClinic
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    development_settings,
    upgrade_to_head,
)


def test_mailbox_worker_recovers_after_database_refusal_without_logging_driver_details(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    runtime = main.build_portal_runtime(
        development_settings(database_url=f"sqlite+pysqlite:///{tmp_path / 'worker-retry.db'}"),
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
    )
    engine = runtime.database_engine
    driver_detail = "FAKE-private-mailbox-driver-detail"
    real_sweep = mailbox_worker.sweep
    failures = []
    recovered = None

    def observe_sweep(active_runtime):
        try:
            result = real_sweep(active_runtime)
        except IntegrityError as exc:
            assert driver_detail in str(exc)
            failures.append(type(exc).__name__)
            # The real failing sweep's session has exited/rolled back before this repair.
            with runtime.session_factory() as session, session.begin():
                assert session.get(MailboxClinic, runtime.settings.clinic_id) is None
                session.execute(text("DROP TRIGGER fake_mailbox_refusal"))
            raise
        else:
            anyio.from_thread.run_sync(recovered.set)
            return result

    async def exercise_worker():
        nonlocal recovered
        recovered = anyio.Event()
        async with anyio.create_task_group() as workers:
            workers.start_soon(mailbox_worker.run_worker, runtime)
            try:
                with anyio.fail_after(5):
                    await recovered.wait()
            finally:
                workers.cancel_scope.cancel()

    # Only the scheduling clock advances beyond its deadline: real AnyIO sleep/cancellation
    # and real sweep transactions are retained, without waiting a minute in the fixture.
    ticks = count(start=0, step=100)
    monkeypatch.setattr(mailbox_worker, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(mailbox_worker, "sweep", observe_sweep)
    try:
        upgrade_to_head(engine)
        MailboxBase.metadata.create_all(engine)
        with runtime.session_factory() as session, session.begin():
            assert session.get(MailboxClinic, runtime.settings.clinic_id) is None
            session.execute(
                text("""
                CREATE TRIGGER fake_mailbox_refusal
                BEFORE INSERT ON patient_portal_mycarlos_mailbox_clinics
                BEGIN
                    SELECT RAISE(ABORT, 'FAKE-private-mailbox-driver-detail');
                END
            """)
            )

        anyio.run(exercise_worker)

        assert failures == ["IntegrityError"]
        with runtime.session_factory() as session:
            clinic = session.get(MailboxClinic, runtime.settings.clinic_id)
            assert clinic is not None
            assert clinic.waiting_count == clinic.waiting_bytes == 0
        failure_logs = [
            record for record in caplog.records if record.name == mailbox_worker.__name__
        ]
        assert failure_logs
        assert all("IntegrityError" in record.getMessage() for record in failure_logs)
        assert all(record.exc_info is None for record in failure_logs)
        assert driver_detail not in caplog.text
    finally:
        engine.dispose()
