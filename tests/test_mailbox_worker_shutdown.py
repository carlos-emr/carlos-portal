from threading import Event

import anyio
import pytest
from sqlalchemy import event, text

from carlos_patient_portal import mailbox_worker
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    migrated_development_app,
)


def test_mailbox_lifespan_waits_for_owned_database_work_before_disposing_engine(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = migrated_development_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'mailbox-shutdown.db'}",
        mycarlos_delivery_enabled=True,
        mycarlos_mailbox_enabled=True,
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
    )
    engine = app.state.database_engine
    entered = Event()
    cancellation_seen = Event()
    release = Event()
    worker_stopped = Event()
    disposed = Event()
    journal = []
    worker_tasks = []
    cancellation_types = []
    real_worker = mailbox_worker.run_worker

    def observe_disposal(disposed_engine):
        assert disposed_engine is engine
        journal.append("engine-disposed")
        disposed.set()

    def held_database_work(runtime):
        # Substitute the sweep payload, retaining the real worker/thread/lifespan machinery.
        with runtime.session_factory() as session, session.begin():
            assert session.scalar(text("SELECT 1")) == 1
            journal.append("transaction-entered")
            entered.set()
            # Acknowledge actual parent cancellation through AnyIO's public thread API.
            # The short wait yields this thread; it is not the shutdown correctness oracle.
            while not release.wait(0.01):
                try:
                    anyio.from_thread.check_cancelled()
                except cancellation_types[0]:
                    journal.append("cancellation-observed")
                    cancellation_seen.set()
                    break
            assert release.wait(5), "fixture did not release owned database work"
            assert session.scalar(text("SELECT 1")) == 1
        journal.append("transaction-finished")
        return 0, 0

    async def observed_worker(runtime):
        worker_tasks.append(anyio.get_current_task())
        try:
            await real_worker(runtime)
        finally:
            journal.append("worker-stopped")
            worker_stopped.set()

    async def release_after_cancellation():
        try:
            assert await anyio.to_thread.run_sync(cancellation_seen.wait, 5)
            # Cancellation is requested while the SQL transaction is still held. The worker
            # task must remain shielded/owned, rather than exiting and abandoning its thread.
            assert not worker_stopped.is_set()
            assert not worker_tasks[0].has_pending_cancellation()
            assert not disposed.is_set()
        finally:
            release.set()

    async def exercise_lifespan():
        cancellation_types.append(anyio.get_cancelled_exc_class())
        async with anyio.create_task_group() as controls:
            controls.start_soon(release_after_cancellation)
            async with app.router.lifespan_context(app):
                assert await anyio.to_thread.run_sync(entered.wait, 5)
            assert worker_stopped.is_set()
            assert disposed.is_set()

    event.listen(engine, "engine_disposed", observe_disposal)
    monkeypatch.setattr(mailbox_worker, "sweep", held_database_work)
    monkeypatch.setattr(mailbox_worker, "run_worker", observed_worker)
    try:
        anyio.run(exercise_lifespan)

        assert journal == [
            "transaction-entered",
            "cancellation-observed",
            "transaction-finished",
            "worker-stopped",
            "engine-disposed",
        ]
        assert "myCarlos mailbox maintenance failed" not in caplog.text
    finally:
        release.set()
        event.remove(engine, "engine_disposed", observe_disposal)
        engine.dispose()
