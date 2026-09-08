import json

import pytest
from pydantic_settings import SettingsError

from carlos_patient_portal import cli
from carlos_patient_portal.config import Settings
from carlos_patient_portal.database import create_portal_engine
from carlos_patient_portal.preflight import (
    collect_production_preflight,
    database_preflight_checks,
    evaluate_runtime_role_policy,
)


def compliant_runtime_role() -> dict[str, bool]:
    return {
        "audit_select": True,
        "audit_insert": True,
        "audit_sequence_usage": True,
        "audit_sequence_select": True,
        "schema_usage": True,
        "audit_update": False,
        "audit_delete": False,
        "audit_truncate": False,
        "audit_references": False,
        "audit_trigger": False,
        "audit_owner": False,
        "schema_create": False,
        "role_elevated": False,
    }


def test_runtime_role_policy_accepts_only_append_only_audit_access() -> None:
    check = evaluate_runtime_role_policy(compliant_runtime_role())

    assert check.passed
    assert check.detail == "runtime role is non-admin and audit evidence is append-only"


@pytest.mark.parametrize(
    "privilege",
    [
        "audit_insert",
        "audit_update",
        "audit_delete",
        "audit_truncate",
        "audit_owner",
        "schema_create",
        "role_elevated",
    ],
)
def test_runtime_role_policy_reports_each_privilege_violation(privilege: str) -> None:
    values = compliant_runtime_role()
    values[privilege] = not values[privilege]

    check = evaluate_runtime_role_policy(values)

    assert not check.passed
    assert privilege in check.detail


def test_database_preflight_rejects_sqlite_before_running_postgresql_queries() -> None:
    engine = create_portal_engine("sqlite+pysqlite:///:memory:")
    try:
        checks = database_preflight_checks(engine)
    finally:
        engine.dispose()

    assert [(check.name, check.status) for check in checks] == [("database_backend", "fail")]


def test_real_data_preflight_rejects_development_policy_and_database() -> None:
    settings = Settings(environment="development", database_url="sqlite+pysqlite:///:memory:")

    checks = collect_production_preflight(settings)

    assert [(check.name, check.status) for check in checks] == [
        ("environment", "fail"),
        ("database_backend", "fail"),
    ]


def test_preflight_cli_emits_machine_readable_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = Settings(environment="development", database_url="sqlite+pysqlite:///:memory:")
    monkeypatch.setattr(cli, "get_settings", lambda: settings)

    with pytest.raises(SystemExit) as exit_info:
        cli.production_preflight([])

    assert exit_info.value.code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert payload["checks"][0]["name"] == "environment"


def test_preflight_cli_omits_configuration_inputs_from_errors(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def invalid_production_settings() -> Settings:
        return Settings(
            environment="production",
            session_secret="must-not-appear-in-preflight-output",
        )

    monkeypatch.setattr(cli, "get_settings", invalid_production_settings)

    with pytest.raises(SystemExit):
        cli.production_preflight([])

    output = capsys.readouterr().out
    assert "must-not-appear-in-preflight-output" not in output
    assert json.loads(output)["checks"][0]["name"] == "configuration"


def test_preflight_cli_omits_settings_source_values_from_errors(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def invalid_environment_file() -> Settings:
        raise SettingsError("raw-environment-secret-must-not-appear")

    monkeypatch.setattr(cli, "get_settings", invalid_environment_file)

    with pytest.raises(SystemExit):
        cli.production_preflight([])

    output = capsys.readouterr().out
    assert "raw-environment-secret-must-not-appear" not in output
    assert "SettingsError" in output
