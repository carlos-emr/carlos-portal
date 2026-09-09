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

ORDINARY_TABLE_PRIVILEGES = frozenset({"select", "insert", "update", "delete"})
EXPECTED_TABLE_PRIVILEGES = {
    "alembic_version": frozenset({"select"}),
    "patient_portal_accounts": ORDINARY_TABLE_PRIVILEGES,
    "patient_portal_audit_events": frozenset({"select", "insert"}),
    "patient_portal_contact_review_requests": ORDINARY_TABLE_PRIVILEGES,
    "patient_portal_email_change_requests": ORDINARY_TABLE_PRIVILEGES,
    "patient_portal_invites": ORDINARY_TABLE_PRIVILEGES,
    "patient_portal_mfa_challenges": ORDINARY_TABLE_PRIVILEGES,
    "patient_portal_outbound_deliveries": ORDINARY_TABLE_PRIVILEGES,
    "patient_portal_password_reset_tokens": ORDINARY_TABLE_PRIVILEGES,
    "patient_portal_sessions": ORDINARY_TABLE_PRIVILEGES,
    "patient_portal_unlock_secrets": ORDINARY_TABLE_PRIVILEGES,
}
EXPECTED_SEQUENCE_PRIVILEGES = {
    f"{table_name}_id_seq": frozenset({"usage", "select"})
    for table_name in EXPECTED_TABLE_PRIVILEGES
    if table_name not in {"alembic_version"}
}


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
        "nonpublic_schema_usage": False,
        "public_schema_privilege": False,
        "search_path_unsafe": False,
        "database_create": False,
        "database_temporary": False,
        "database_owner": False,
        "role_membership": False,
        "schema_object_owner": False,
        "schema_function_execute": False,
        "table_dangerous_privilege": False,
        "sequence_update": False,
        "session_role_changed": False,
        "role_elevated": False,
        "unexpected_acl_grantee": False,
        "unexpected_object_owner": False,
    }
    violations = sorted(
        name for name, expected in required.items() if values.get(name) is not expected
    )
    return preflight_check(
        "runtime_database_role",
        not violations,
        passed_detail=(
            "runtime role is non-admin; schema revision and audit evidence are protected"
        ),
        failed_detail=(
            "runtime database privilege policy failed: " + ",".join(violations)
            if violations
            else "runtime database privilege policy failed"
        ),
    )


def evaluate_runtime_database_allowlist(
    table_values: list[Mapping[str, object]],
    sequence_values: list[Mapping[str, object]],
) -> PreflightCheck:
    """Require the runtime role's ordinary data access to match the deployment allowlist exactly."""
    violations: list[str] = []
    expected_tables = {
        ("public", table_name): privileges
        for table_name, privileges in EXPECTED_TABLE_PRIVILEGES.items()
    }
    actual_tables = {
        (str(values.get("schema", "public")), str(values["name"])): values
        for values in table_values
    }
    for table_key in sorted(set(actual_tables) | set(expected_tables)):
        table_name = ".".join(table_key)
        expected = expected_tables.get(table_key, frozenset())
        values = actual_tables.get(table_key)
        if values is None:
            violations.append(f"missing_table:{table_name}")
            continue
        granted = frozenset(
            privilege
            for privilege in ("select", "insert", "update", "delete")
            if values.get(f"can_{privilege}") is True
        )
        if granted != expected:
            violations.append(f"table:{table_name}")
        if values.get("grant_option") is True:
            violations.append(f"table_grant_option:{table_name}")
        if values.get("public_privilege") is True:
            violations.append(f"public_table:{table_name}")
        if values.get("unexpected_column_acl") is True:
            violations.append(f"column_acl:{table_name}")

    expected_sequences = {
        ("public", sequence_name): privileges
        for sequence_name, privileges in EXPECTED_SEQUENCE_PRIVILEGES.items()
    }
    actual_sequences = {
        (str(values.get("schema", "public")), str(values["name"])): values
        for values in sequence_values
    }
    for sequence_key in sorted(set(actual_sequences) | set(expected_sequences)):
        sequence_name = ".".join(sequence_key)
        expected = expected_sequences.get(sequence_key, frozenset())
        values = actual_sequences.get(sequence_key)
        if values is None:
            violations.append(f"missing_sequence:{sequence_name}")
            continue
        granted = frozenset(
            privilege
            for privilege in ("usage", "select")
            if values.get(f"can_{privilege}") is True
        )
        if granted != expected:
            violations.append(f"sequence:{sequence_name}")
        if values.get("grant_option") is True:
            violations.append(f"sequence_grant_option:{sequence_name}")
        if values.get("public_privilege") is True:
            violations.append(f"public_sequence:{sequence_name}")

    return preflight_check(
        "runtime_database_allowlist",
        not violations,
        passed_detail="runtime table and sequence privileges match the explicit allowlist",
        failed_detail=(
            "runtime database allowlist failed: " + ",".join(violations)
            if violations
            else "runtime database allowlist failed"
        ),
    )


def query_runtime_database_allowlist(session: Session) -> PreflightCheck:
    table_values = list(
        session.execute(
            text(
                """
                SELECT
                  n.nspname AS schema,
                  c.relname AS name,
                  has_table_privilege(current_user, c.oid, 'SELECT') AS can_select,
                  has_table_privilege(current_user, c.oid, 'INSERT') AS can_insert,
                  has_table_privilege(current_user, c.oid, 'UPDATE') AS can_update,
                  has_table_privilege(current_user, c.oid, 'DELETE') AS can_delete,
                  EXISTS (
                    SELECT 1
                    FROM aclexplode(c.relacl) acl
                    WHERE acl.grantee = (
                      SELECT oid FROM pg_roles WHERE rolname = current_user
                    )
                      AND acl.is_grantable
                  ) AS grant_option,
                  EXISTS (
                    SELECT 1
                    FROM aclexplode(c.relacl) acl
                    WHERE acl.grantee = 0
                  ) AS public_privilege,
                  EXISTS (
                    SELECT 1
                    FROM pg_attribute attribute_record
                    CROSS JOIN LATERAL aclexplode(attribute_record.attacl) acl
                    WHERE attribute_record.attrelid = c.oid
                      AND attribute_record.attnum > 0
                      AND NOT attribute_record.attisdropped
                      AND acl.grantee IN (
                        0,
                        (SELECT oid FROM pg_roles WHERE rolname = current_user)
                      )
                  ) AS unexpected_column_acl
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                """
            )
        ).mappings()
    )
    sequence_values = list(
        session.execute(
            text(
                """
                SELECT
                  n.nspname AS schema,
                  c.relname AS name,
                  has_sequence_privilege(current_user, c.oid, 'USAGE') AS can_usage,
                  has_sequence_privilege(current_user, c.oid, 'SELECT') AS can_select,
                  EXISTS (
                    SELECT 1
                    FROM aclexplode(c.relacl) acl
                    WHERE acl.grantee = (
                      SELECT oid FROM pg_roles WHERE rolname = current_user
                    )
                      AND acl.is_grantable
                  ) AS grant_option,
                  EXISTS (
                    SELECT 1
                    FROM aclexplode(c.relacl) acl
                    WHERE acl.grantee = 0
                  ) AS public_privilege
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND c.relkind = 'S'
                """
            )
        ).mappings()
    )
    return evaluate_runtime_database_allowlist(table_values, sequence_values)


def query_runtime_role_policy(
    session: Session,
    *,
    schema_owner_role: str = "portal_schema_owner",
    maintenance_role: str = "portal_audit_maintenance",
) -> PreflightCheck:
    values = session.execute(
        text(
            """
            WITH trusted_role_oids AS (
              SELECT oid
              FROM pg_roles
              WHERE rolname IN (current_user, :schema_owner_role, :maintenance_role)
              UNION
              SELECT datdba
              FROM pg_database
              WHERE datname = current_database()
            ), declared_owner_oids AS (
              SELECT oid
              FROM pg_roles
              WHERE rolname IN (current_user, :schema_owner_role, 'pg_database_owner')
              UNION
              SELECT datdba
              FROM pg_database
              WHERE datname = current_database()
            )
            SELECT
              session_user <> current_user AS session_role_changed,
              regexp_replace(current_setting('search_path'), '\\s', '', 'g')
                <> 'pg_catalog,public' AS search_path_unsafe,
              has_table_privilege(current_user, 'public.alembic_version', 'SELECT')
                AS alembic_select,
              has_table_privilege(current_user, 'public.alembic_version', 'INSERT')
                AS alembic_insert,
              has_table_privilege(current_user, 'public.alembic_version', 'UPDATE')
                AS alembic_update,
              has_table_privilege(current_user, 'public.alembic_version', 'DELETE')
                AS alembic_delete,
              has_table_privilege(current_user, 'public.alembic_version', 'TRUNCATE')
                AS alembic_truncate,
              has_table_privilege(current_user, 'public.alembic_version', 'REFERENCES')
                AS alembic_references,
              has_table_privilege(current_user, 'public.alembic_version', 'TRIGGER')
                AS alembic_trigger,
              (
                SELECT c.relowner = r.oid
                FROM pg_class c
                JOIN pg_roles r ON r.rolname = current_user
                WHERE c.oid = 'public.alembic_version'::regclass
              ) AS alembic_owner,
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
              EXISTS (
                SELECT 1
                FROM pg_namespace n
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND has_schema_privilege(current_user, n.oid, 'CREATE')
              ) AS schema_create,
              EXISTS (
                SELECT 1
                FROM pg_namespace n
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND n.nspname <> 'public'
                  AND has_schema_privilege(current_user, n.oid, 'USAGE')
              ) AS nonpublic_schema_usage,
              EXISTS (
                SELECT 1
                FROM pg_namespace n
                CROSS JOIN LATERAL aclexplode(n.nspacl) acl
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND acl.grantee = 0
              ) AS public_schema_privilege,
              has_database_privilege(current_user, current_database(), 'CREATE')
                AS database_create,
              has_database_privilege(current_user, current_database(), 'TEMPORARY')
                AS database_temporary,
              (
                SELECT d.datdba = r.oid
                FROM pg_database d
                JOIN pg_roles r ON r.rolname = current_user
                WHERE d.datname = current_database()
              ) AS database_owner,
              (
                EXISTS (
                  SELECT 1
                  FROM pg_auth_members membership
                  WHERE (
                    membership.roleid IN (SELECT oid FROM trusted_role_oids)
                    OR membership.member IN (SELECT oid FROM trusted_role_oids)
                  )
                    AND NOT (
                      membership.roleid = (
                        SELECT oid FROM pg_roles WHERE rolname = :schema_owner_role
                      )
                      AND membership.member = (
                        SELECT datdba
                        FROM pg_database
                        WHERE datname = current_database()
                      )
                    )
                )
              ) AS role_membership,
              EXISTS (
                SELECT 1
                FROM pg_namespace n
                JOIN pg_roles r ON r.oid = n.nspowner
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND r.rolname = current_user
                UNION ALL
                SELECT 1
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_roles r ON r.oid = c.relowner
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND r.rolname = current_user
                UNION ALL
                SELECT 1
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                JOIN pg_roles r ON r.oid = p.proowner
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND r.rolname = current_user
                UNION ALL
                SELECT 1
                FROM pg_type t
                JOIN pg_namespace n ON n.oid = t.typnamespace
                JOIN pg_roles r ON r.oid = t.typowner
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND r.rolname = current_user
              ) AS schema_object_owner,
              EXISTS (
                SELECT 1
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND has_function_privilege(current_user, p.oid, 'EXECUTE')
              ) AS schema_function_execute,
              EXISTS (
                SELECT 1
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                  AND has_table_privilege(
                    current_user,
                    c.oid,
                    'TRUNCATE,REFERENCES,TRIGGER'
                  )
              ) AS table_dangerous_privilege,
              EXISTS (
                SELECT 1
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND c.relkind = 'S'
                  AND has_sequence_privilege(current_user, c.oid, 'UPDATE')
              ) AS sequence_update,
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
              ) AS role_elevated,
              EXISTS (
                SELECT 1
                FROM pg_namespace n
                CROSS JOIN LATERAL aclexplode(n.nspacl) acl
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND acl.grantee <> n.nspowner
                  AND acl.grantee NOT IN (SELECT oid FROM trusted_role_oids)
                UNION ALL
                SELECT 1
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                CROSS JOIN LATERAL aclexplode(c.relacl) acl
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND acl.grantee <> c.relowner
                  AND acl.grantee NOT IN (SELECT oid FROM trusted_role_oids)
                UNION ALL
                SELECT 1
                FROM pg_attribute attribute_record
                JOIN pg_class c ON c.oid = attribute_record.attrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                CROSS JOIN LATERAL aclexplode(attribute_record.attacl) acl
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND attribute_record.attnum > 0
                  AND NOT attribute_record.attisdropped
                  AND acl.grantee <> c.relowner
                  AND acl.grantee NOT IN (SELECT oid FROM trusted_role_oids)
                UNION ALL
                SELECT 1
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                CROSS JOIN LATERAL aclexplode(p.proacl) acl
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND acl.grantee <> p.proowner
                  AND acl.grantee NOT IN (SELECT oid FROM trusted_role_oids)
                UNION ALL
                SELECT 1
                FROM pg_default_acl default_acl
                CROSS JOIN LATERAL aclexplode(default_acl.defaclacl) acl
                WHERE default_acl.defaclrole = (
                    SELECT oid FROM pg_roles WHERE rolname = :schema_owner_role
                  )
                  AND acl.grantee <> default_acl.defaclrole
                  AND acl.grantee NOT IN (SELECT oid FROM trusted_role_oids)
              ) AS unexpected_acl_grantee,
              EXISTS (
                SELECT 1
                FROM pg_namespace n
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND n.nspowner NOT IN (SELECT oid FROM declared_owner_oids)
                UNION ALL
                SELECT 1
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND c.relowner NOT IN (SELECT oid FROM declared_owner_oids)
                UNION ALL
                SELECT 1
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND p.proowner NOT IN (SELECT oid FROM declared_owner_oids)
                UNION ALL
                SELECT 1
                FROM pg_type t
                JOIN pg_namespace n ON n.oid = t.typnamespace
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND t.typowner NOT IN (SELECT oid FROM declared_owner_oids)
              ) AS unexpected_object_owner
            """
        ),
        {
            "schema_owner_role": schema_owner_role,
            "maintenance_role": maintenance_role,
        },
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


def database_preflight_checks(
    engine: Engine,
    *,
    schema_owner_role: str = "portal_schema_owner",
    maintenance_role: str = "portal_audit_maintenance",
) -> list[PreflightCheck]:
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
                checks.append(
                    query_runtime_role_policy(
                        session,
                        schema_owner_role=schema_owner_role,
                        maintenance_role=maintenance_role,
                    )
                )
                checks.append(query_runtime_database_allowlist(session))
            else:
                checks.append(
                    PreflightCheck(
                        "runtime_database_role",
                        "fail",
                        "runtime privileges cannot be verified until the schema is current",
                    )
                )
                checks.append(
                    PreflightCheck(
                        "runtime_database_allowlist",
                        "fail",
                        "runtime data access cannot be verified until the schema is current",
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
        checks.extend(
            database_preflight_checks(
                database_engine,
                schema_owner_role=settings.database_schema_owner_role,
                maintenance_role=settings.database_maintenance_role,
            )
        )
    finally:
        database_engine.dispose()
    return checks
