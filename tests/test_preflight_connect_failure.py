import json

import psycopg
import pytest
from sqlalchemy import event

from carlos_patient_portal import cli, preflight
from tests.support import production_settings


def test_preflight_cli_classifies_driver_refusal_without_disclosing_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    password = "FAKE-preflight-database-password"
    database_url = (
        f"postgresql+psycopg://portal_runtime:{password}"
        "@preflight.invalid/portal?sslmode=verify-full"
    )
    driver_detail = "FAKE-private-driver-diagnostic"
    refusal = psycopg.OperationalError(f"{driver_detail}: {database_url}")
    assert password in str(refusal)
    settings = production_settings(database_url=database_url)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    real_create_engine = preflight.create_portal_engine
    engines = []
    disposed = []
    connection_attempts = []

    def refuse_connection(dialect, connection_record, connect_args, connect_params):
        # Refuse before the real driver opens any socket, preserving SQLAlchemy's wrapper.
        assert connect_params["password"] == password
        connection_attempts.append(True)
        raise refusal

    def observe_engine(*args, **kwargs):
        engine = real_create_engine(*args, **kwargs)
        engines.append(engine)
        event.listen(engine, "do_connect", refuse_connection)
        event.listen(engine, "engine_disposed", disposed.append)
        return engine

    monkeypatch.setattr(preflight, "create_portal_engine", observe_engine)
    try:
        with pytest.raises(SystemExit) as exit_info:
            cli.production_preflight([])

        assert exit_info.value.code == 1
        assert connection_attempts
        assert engines and all(engine in disposed for engine in engines)
        output = capsys.readouterr()
        payload = json.loads(output.out)
        assert payload["status"] == "failed"
        checks = {check["name"]: check for check in payload["checks"]}
        assert {name: check["status"] for name, check in checks.items()} == {
            "environment": "pass",
            "database_backend": "pass",
            "database_connectivity": "fail",
        }
        assert "OperationalError" in checks["database_connectivity"]["detail"]
        assert output.err == ""
        for private_value in (password, database_url, driver_detail):
            assert private_value not in output.out + output.err + caplog.text
    finally:
        for engine in engines:
            event.remove(engine, "do_connect", refuse_connection)
            engine.dispose()
