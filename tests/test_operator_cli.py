import math
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from carlos_patient_portal import cli
from carlos_patient_portal.database import create_portal_engine
from carlos_patient_portal.maintenance import BackupDestinationExistsError
from carlos_patient_portal.models import PatientPortalAuditEvent
from tests.support import development_settings, upgrade_to_head


def database_value(path: Path) -> str:
    with closing(sqlite3.connect(path)) as connection:
        return connection.execute("SELECT value FROM sample").fetchone()[0]


def test_backup_restore_cli_preserves_live_data_until_explicit_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    live = tmp_path / "live.db"
    backup = tmp_path / "backup.db"
    with closing(sqlite3.connect(live)) as connection, connection:
        connection.execute("CREATE TABLE sample (value TEXT NOT NULL)")
        connection.execute("INSERT INTO sample VALUES ('before backup')")
    settings = development_settings(database_url=f"sqlite+pysqlite:///{live}")
    monkeypatch.setattr(cli, "get_settings", lambda: settings)

    cli.maintenance(["backup-sqlite", "--output", str(backup)])
    assert capsys.readouterr().out.strip() == f"backed up SQLite database to {backup}"
    assert backup.stat().st_mode & 0o777 == 0o600
    with closing(sqlite3.connect(live)) as connection, connection:
        connection.execute("UPDATE sample SET value = 'after backup'")

    with pytest.raises(BackupDestinationExistsError):
        cli.maintenance(["restore-sqlite", "--input", str(backup)])
    assert capsys.readouterr().out == ""
    assert database_value(live) == "after backup"

    cli.maintenance(["restore-sqlite", "--input", str(backup), "--overwrite"])
    assert capsys.readouterr().out.strip() == f"restored SQLite database to {live}"
    assert database_value(live) == "before backup"
    assert database_value(backup) == "before backup"
    assert live.stat().st_mode & 0o777 == 0o600


def test_backup_cli_requires_overwrite_to_replace_a_previous_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    live, backup = tmp_path / "live.db", tmp_path / "backup.db"
    for path, value in [(live, "current"), (backup, "previous backup")]:
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("CREATE TABLE sample (value TEXT NOT NULL)")
            connection.execute("INSERT INTO sample VALUES (?)", (value,))
    settings = development_settings(database_url=f"sqlite+pysqlite:///{live}")
    monkeypatch.setattr(cli, "get_settings", lambda: settings)

    with pytest.raises(BackupDestinationExistsError):
        cli.maintenance(["backup-sqlite", "--output", str(backup)])
    assert capsys.readouterr().out == ""
    assert database_value(backup) == "previous backup"

    cli.maintenance(["backup-sqlite", "--output", str(backup), "--overwrite"])
    assert capsys.readouterr().out.strip() == f"backed up SQLite database to {backup}"
    assert database_value(backup) == "current"
    assert database_value(live) == "current"


@pytest.mark.parametrize("operations", [0, 1001])
def test_password_benchmark_cli_rejects_out_of_range_work_before_creating_database(
    operations,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "unused.db"
    settings = development_settings(database_url=f"sqlite+pysqlite:///{path}")
    monkeypatch.setattr(cli, "get_settings", lambda: settings)

    with pytest.raises(SystemExit) as exit_info:
        cli.maintenance(["benchmark-password-hashing", "--operations", str(operations)])

    assert exit_info.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "--operations must be between 1 and 1000" in output.err
    assert not path.exists()


def test_password_benchmark_cli_reports_real_bounded_argon2_work_without_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "unused.db"
    settings = development_settings(
        database_url=f"sqlite+pysqlite:///{path}",
        password_hash_time_cost=2,
        password_hash_memory_kib=16384,
        password_hash_parallelism=1,
        password_hash_max_concurrency=2,
    )
    monkeypatch.setattr(cli, "get_settings", lambda: settings)

    cli.maintenance(["benchmark-password-hashing", "--operations", "2"])

    output = capsys.readouterr()
    assert output.err == ""
    fields = dict(pair.split("=", 1) for pair in output.out.split())
    assert fields["operations"] == "2"
    assert fields["concurrency"] == "2"
    assert fields["estimated_peak_memory_mib"] == "32"
    for key in ["elapsed_seconds", "median_seconds", "operations_per_second"]:
        assert math.isfinite(float(fields[key])) and float(fields[key]) > 0
    assert not path.exists()


def test_prune_audit_cli_dry_run_counts_expired_rows_without_maintenance_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = development_settings(database_url=f"sqlite+pysqlite:///{tmp_path / 'audit.db'}")
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    engine = create_portal_engine(settings.database_url)
    try:
        upgrade_to_head(engine)
        with Session(engine) as session, session.begin():
            session.add_all(
                [
                    PatientPortalAuditEvent(
                        event_type="login",
                        outcome="success",
                        actor_type="system",
                        created_at=created,
                    )
                    for created in [datetime(2000, 1, 1, tzinfo=UTC), datetime.now(UTC)]
                ]
            )
        with engine.connect() as connection:
            before = list(connection.execute(select(PatientPortalAuditEvent.__table__)))
        capsys.readouterr()

        cli.maintenance(["prune-audit", "--dry-run"])

        assert capsys.readouterr().out.strip() == "1 audit events older than retention"
        with engine.connect() as connection:
            assert list(connection.execute(select(PatientPortalAuditEvent.__table__))) == before
    finally:
        engine.dispose()


def test_maintenance_deployment_probe_requires_its_dedicated_database_url(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "get_settings", development_settings)

    with pytest.raises(SystemExit) as exit_info:
        cli.deployment_probe(["maintenance"])

    assert exit_info.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "PATIENT_PORTAL_MAINTENANCE_DATABASE_URL is required" in output.err


@pytest.mark.parametrize(
    "probe", ["outbox-configuration-sha256", "runtime-outbox-configuration-sha256"]
)
def test_outbox_configuration_probe_refuses_a_digest_without_session_key_material(
    probe,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = development_settings(session_secret=None)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "get_outbox_settings", lambda: settings)

    with pytest.raises(SystemExit) as exit_info:
        cli.deployment_probe([probe])

    assert str(exit_info.value) == (
        "outbox compatibility probe requires PATIENT_PORTAL_SESSION_SECRET"
    )
    output = capsys.readouterr()
    assert output.out == output.err == ""
