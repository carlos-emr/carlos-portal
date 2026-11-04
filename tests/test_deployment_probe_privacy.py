import psycopg
import pytest
from sqlalchemy import event

from carlos_patient_portal import cli
from tests.support import development_settings


@pytest.mark.parametrize("probe", ["migration", "runtime", "outbox", "maintenance"])
def test_live_deployment_probe_refusal_is_safe_and_disposes_engine(
    probe,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The real SQLAlchemy driver boundary fails before opening any network socket."""
    password = "FAKE-probe-password"
    private_detail = "FAKE-private-driver-diagnostic"
    database_url = f"postgresql+psycopg://operator:{password}@probe.invalid/portal"
    settings = development_settings(
        database_url=database_url,
        maintenance_database_url=database_url,
    )
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "get_outbox_settings", lambda: settings)
    monkeypatch.setattr(cli, "get_migration_database_url", lambda: database_url)
    factory_name = "create_engine" if probe == "migration" else "create_portal_engine"
    real_factory = getattr(cli, factory_name)
    engines, disposed, attempts = [], [], []

    def refuse_connection(dialect, record, args, params):
        assert params["password"] == password
        attempts.append(True)
        raise psycopg.OperationalError(f"{private_detail}: {database_url}")

    def observed_factory(*args, **kwargs):
        engine = real_factory(*args, **kwargs)
        engines.append(engine)
        event.listen(engine, "do_connect", refuse_connection)
        event.listen(engine, "engine_disposed", disposed.append)
        return engine

    monkeypatch.setattr(cli, factory_name, observed_factory)
    try:
        with pytest.raises(SystemExit) as exit_info:
            cli.deployment_probe([probe])

        assert exit_info.value.code == 2
        assert attempts and engines and all(engine in disposed for engine in engines)
        output = capsys.readouterr()
        assert output.out == ""
        assert "deployment probe database check failed" in output.err
        for value in (password, private_detail, database_url):
            assert value not in output.out + output.err + caplog.text + str(exit_info.value)
    finally:
        for engine in engines:
            event.remove(engine, "do_connect", refuse_connection)
            engine.dispose()
