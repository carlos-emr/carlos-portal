import json

import pytest
from pydantic_settings import SettingsError

from carlos_patient_portal import cli
from carlos_patient_portal.config import Settings
from carlos_patient_portal.database import create_portal_engine
from carlos_patient_portal.preflight import (
    EXPECTED_SEQUENCE_PRIVILEGES,
    EXPECTED_TABLE_PRIVILEGES,
    collect_production_preflight,
    database_preflight_checks,
    evaluate_runtime_database_allowlist,
    evaluate_runtime_role_policy,
)


def compliant_runtime_role() -> dict[str, bool]:
    return {
        "audit_select": True,
        "audit_insert": True,
        "audit_sequence_usage": True,
        "audit_sequence_select": True,
        "schema_usage": True,
        "alembic_select": True,
        "alembic_insert": False,
        "alembic_update": False,
        "alembic_delete": False,
        "alembic_truncate": False,
        "alembic_references": False,
        "alembic_trigger": False,
        "alembic_owner": False,
        "audit_update": False,
        "audit_delete": False,
        "audit_truncate": False,
        "audit_references": False,
        "audit_trigger": False,
        "audit_owner": False,
        "schema_create": False,
        "database_create": False,
        "database_owner": False,
        "role_membership": False,
        "schema_object_owner": False,
        "schema_function_execute": False,
        "table_dangerous_privilege": False,
        "sequence_update": False,
        "session_role_changed": False,
        "role_elevated": False,
    }


def compliant_runtime_data_privileges() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    table_values = [
        {
            "name": table_name,
            **{
                f"can_{privilege}": privilege in expected
                for privilege in ("select", "insert", "update", "delete")
            },
        }
        for table_name, expected in EXPECTED_TABLE_PRIVILEGES.items()
    ]
    sequence_values = [
        {
            "name": sequence_name,
            "can_usage": "usage" in expected,
            "can_select": "select" in expected,
        }
        for sequence_name, expected in EXPECTED_SEQUENCE_PRIVILEGES.items()
    ]
    return table_values, sequence_values


def test_runtime_role_policy_accepts_only_append_only_audit_access() -> None:
    check = evaluate_runtime_role_policy(compliant_runtime_role())

    assert check.passed
    assert check.detail == (
        "runtime role is non-admin; schema revision and audit evidence are protected"
    )


@pytest.mark.parametrize(
    "privilege",
    compliant_runtime_role(),
)
def test_runtime_role_policy_reports_each_privilege_violation(privilege: str) -> None:
    values = compliant_runtime_role()
    values[privilege] = not values[privilege]

    check = evaluate_runtime_role_policy(values)

    assert not check.passed
    assert privilege in check.detail


def test_runtime_database_allowlist_accepts_only_the_exact_policy() -> None:
    tables, sequences = compliant_runtime_data_privileges()

    check = evaluate_runtime_database_allowlist(tables, sequences)

    assert check.passed


@pytest.mark.parametrize("object_kind", ["table", "sequence"])
def test_runtime_database_allowlist_rejects_privileges_on_unknown_objects(
    object_kind: str,
) -> None:
    tables, sequences = compliant_runtime_data_privileges()
    if object_kind == "table":
        tables.append(
            {
                "name": "unexpected_patient_data",
                "can_select": True,
                "can_insert": False,
                "can_update": True,
                "can_delete": False,
            }
        )
    else:
        sequences.append(
            {
                "name": "unexpected_patient_data_id_seq",
                "can_usage": True,
                "can_select": True,
            }
        )

    check = evaluate_runtime_database_allowlist(tables, sequences)

    assert not check.passed
    assert "unexpected_patient_data" in check.detail


def test_runtime_database_allowlist_rejects_missing_required_access() -> None:
    tables, sequences = compliant_runtime_data_privileges()
    tables[0]["can_select"] = False

    check = evaluate_runtime_database_allowlist(tables, sequences)

    assert not check.passed
    assert str(tables[0]["name"]) in check.detail


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
