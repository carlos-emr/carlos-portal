# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This software is published under the GPL GNU General Public License.

"""Fail-closed checks that must pass before a deployment may receive real patient data."""

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Literal

from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from carlos_patient_portal.config import Settings
from carlos_patient_portal.database import (
    DatabaseSchemaMismatchError,
    check_database,
    check_database_schema_current,
    create_portal_engine,
)

PreflightStatus = Literal["pass", "fail"]


@dataclass(frozen=True)
class PreflightCheck:
    """One secret-free, machine-readable deployment assertion."""

    name: str
    status: PreflightStatus
    detail: str

    @property
    def passed(self) -> bool:
        return self.status == "pass"

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def preflight_check(
    name: str,
    passed: bool,
    *,
    passed_detail: str,
    failed_detail: str,
) -> PreflightCheck:
    return PreflightCheck(
        name=name,
        status="pass" if passed else "fail",
        detail=passed_detail if passed else failed_detail,
    )


def evaluate_runtime_role_policy(values: Mapping[str, object]) -> PreflightCheck:
    """Verify the connected application role cannot rewrite audit evidence or administer PG."""
    required = {
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
    violations = sorted(
        name for name, expected in required.items() if values.get(name) is not expected
    )
    return preflight_check(
        "runtime_database_role",
        not violations,
        passed_detail="runtime role is non-admin and audit evidence is append-only",
        failed_detail=(
            "runtime database privilege policy failed: " + ",".join(violations)
            if violations
            else "runtime database privilege policy failed"
        ),
    )


def query_runtime_role_policy(session: Session) -> PreflightCheck:
    values = session.execute(
        text(
            """
            SELECT
              has_table_privilege(current_user, 'public.patient_portal_audit_events', 'SELECT')
                AS audit_select,
              has_table_privilege(current_user, 'public.patient_portal_audit_events', 'INSERT')
                AS audit_insert,
              has_table_privilege(current_user, 'public.patient_portal_audit_events', 'UPDATE')
                AS audit_update,
              has_table_privilege(current_user, 'public.patient_portal_audit_events', 'DELETE')
                AS audit_delete,
              has_table_privilege(current_user, 'public.patient_portal_audit_events', 'TRUNCATE')
                AS audit_truncate,
              has_table_privilege(current_user, 'public.patient_portal_audit_events', 'REFERENCES')
                AS audit_references,
              has_table_privilege(current_user, 'public.patient_portal_audit_events', 'TRIGGER')
                AS audit_trigger,
              has_sequence_privilege(
                current_user,
                pg_get_serial_sequence('public.patient_portal_audit_events', 'id'),
                'USAGE'
              ) AS audit_sequence_usage,
              has_sequence_privilege(
                current_user,
                pg_get_serial_sequence('public.patient_portal_audit_events', 'id'),
                'SELECT'
              ) AS audit_sequence_select,
              has_schema_privilege(current_user, 'public', 'USAGE') AS schema_usage,
              has_schema_privilege(current_user, 'public', 'CREATE') AS schema_create,
              (
                SELECT c.relowner = r.oid
                FROM pg_class c
                JOIN pg_roles r ON r.rolname = current_user
                WHERE c.oid = 'public.patient_portal_audit_events'::regclass
              ) AS audit_owner,
              (
                SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls
                FROM pg_roles
                WHERE rolname = current_user
              ) AS role_elevated
            """
        )
    ).mappings().one()
    return evaluate_runtime_role_policy(values)


def query_database_tls(session: Session) -> PreflightCheck:
    # Check the libpq connection used by this process. A pg_stat_ssl query describes the backend
    # leg and can report plaintext when a managed pooler correctly terminates client TLS.
    driver_connection = session.connection().connection.driver_connection
    postgres_connection = getattr(driver_connection, "pgconn", None)
    tls_enabled = bool(getattr(postgres_connection, "ssl_in_use", False))
    return preflight_check(
        "database_tls",
        tls_enabled is True,
        passed_detail="PostgreSQL connection uses TLS",
        failed_detail="PostgreSQL connection does not use TLS",
    )


def database_preflight_checks(engine: Engine) -> list[PreflightCheck]:
    backend_check = preflight_check(
        "database_backend",
        engine.dialect.name == "postgresql",
        passed_detail="database backend is PostgreSQL",
        failed_detail="real-data deployments require PostgreSQL",
    )
    checks = [backend_check]
    if not backend_check.passed:
        return checks

    connected = False
    try:
        with Session(engine) as session:
            check_database(session)
            connected = True
            checks.append(
                PreflightCheck("database_connectivity", "pass", "database connection succeeded")
            )
            schema_current = False
            try:
                check_database_schema_current(session)
            except DatabaseSchemaMismatchError:
                checks.append(
                    PreflightCheck(
                        "database_schema",
                        "fail",
                        "database schema does not match the packaged migration head",
                    )
                )
            else:
                schema_current = True
                checks.append(
                    PreflightCheck(
                        "database_schema",
                        "pass",
                        "database schema matches the packaged migration head",
                    )
                )
            checks.append(query_database_tls(session))
            if schema_current:
                checks.append(query_runtime_role_policy(session))
            else:
                checks.append(
                    PreflightCheck(
                        "runtime_database_role",
                        "fail",
                        "runtime privileges cannot be verified until the schema is current",
                    )
                )
    except SQLAlchemyError as exc:
        checks.append(
            PreflightCheck(
                "database_preflight_queries" if connected else "database_connectivity",
                "fail",
                f"database check failed ({type(exc).__name__})",
            )
        )
    return checks


def collect_production_preflight(settings: Settings) -> list[PreflightCheck]:
    checks = [
        preflight_check(
            "environment",
            settings.is_production,
            passed_detail="production policy is enabled",
            failed_detail="real-data deployments must use PATIENT_PORTAL_ENVIRONMENT=production",
        )
    ]
    try:
        database_engine = create_portal_engine(
            settings.database_url,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_timeout_seconds=settings.database_pool_timeout_seconds,
            connect_timeout_seconds=settings.database_connect_timeout_seconds,
            statement_timeout_ms=settings.database_statement_timeout_ms,
            lock_timeout_ms=settings.database_lock_timeout_ms,
            sqlite_busy_timeout_ms=settings.sqlite_busy_timeout_ms,
        )
    except (SQLAlchemyError, ValueError) as exc:
        checks.append(
            PreflightCheck(
                "database_configuration",
                "fail",
                f"database engine could not be configured ({type(exc).__name__})",
            )
        )
        return checks
    try:
        checks.extend(database_preflight_checks(database_engine))
    finally:
        database_engine.dispose()
    return checks
