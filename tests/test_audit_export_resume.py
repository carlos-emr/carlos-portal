import json
from datetime import datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from carlos_patient_portal import cli
from carlos_patient_portal.config import Settings
from carlos_patient_portal.database import create_portal_engine
from carlos_patient_portal.models import PatientPortalAuditEvent
from tests.support import upgrade_to_head


def test_audit_export_cli_resumes_across_sparse_ids_and_later_backdated_event(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'audit-resume.db'}"
    settings = Settings(environment="development", database_url=database_url)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    engine = create_portal_engine(database_url)
    table = PatientPortalAuditEvent.__table__

    def snapshot():
        with engine.connect() as connection:
            return [
                dict(row)
                for row in connection.execute(select(table).order_by(table.c.id)).mappings()
            ]

    def export(after_id):
        cli.maintenance(["export-audit", "--after-id", str(after_id), "--batch-size", "2"])
        output = capsys.readouterr()
        assert output.err == ""
        return [json.loads(line) for line in output.out.splitlines()]

    try:
        upgrade_to_head(engine)
        with Session(engine) as session, session.begin():
            # Missing IDs and timestamps out of ID order model a retained, sparse trail.
            for event_id, day in [(10, 3), (30, 1), (90, 2)]:
                session.add(
                    PatientPortalAuditEvent(
                        id=event_id,
                        event_type="login",
                        outcome="success",
                        actor_type="system",
                        reason=f"FAKE-event-{event_id}",
                        created_at=datetime(2026, 1, day),
                    )
                )
        before_first_export = snapshot()
        capsys.readouterr()

        first = export(0)
        assert [event["id"] for event in first] == [10, 30]
        assert snapshot() == before_first_export

        # A committed later append remains eligible even when its timestamp is older.
        with Session(engine) as session, session.begin():
            session.add(
                PatientPortalAuditEvent(
                    id=140,
                    event_type="login",
                    outcome="success",
                    actor_type="system",
                    reason="FAKE-event-140",
                    created_at=datetime(2025, 1, 1),
                )
            )
        before_resume = snapshot()

        second = export(first[-1]["id"])
        assert [event["id"] for event in second] == [90, 140]
        assert [event["reason"] for event in first + second] == [
            "FAKE-event-10",
            "FAKE-event-30",
            "FAKE-event-90",
            "FAKE-event-140",
        ]
        assert export(second[-1]["id"]) == []
        assert snapshot() == before_resume
    finally:
        engine.dispose()
