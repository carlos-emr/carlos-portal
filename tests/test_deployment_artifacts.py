from pathlib import Path

from carlos_patient_portal import models
from carlos_patient_portal.config import Settings

PACKAGE_ROOT = Path(__file__).parents[1] / "carlos_patient_portal"
REPOSITORY_ROOT = PACKAGE_ROOT.parent


def test_repository_ignores_local_secrets_and_patient_databases() -> None:
    patterns = set((REPOSITORY_ROOT / ".gitignore").read_text().splitlines())

    assert {
        ".env",
        ".env.*",
        ".envrc",
        ".direnv/",
        "deploy/*.env",
        "*.key",
        "*.pem",
        "*.p12",
        "*.pfx",
        "*.db",
        "*.db-wal",
        "*.db-shm",
        "*.sqlite",
        "*.sqlite3",
    } <= patterns


def test_production_image_is_pinned_locked_and_unprivileged() -> None:
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text()

    assert "python:3.12.14-slim-bookworm@sha256:" in dockerfile
    assert "slim-bookworm@sha256:" in dockerfile
    assert dockerfile.count("--require-hashes") == 2
    assert "--no-isolation" in dockerfile
    assert 'PYTHONPATH="/opt/portal/lib/python3.12/site-packages"' in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert 'CMD ["uvicorn"' in dockerfile


def test_production_compose_separates_runtime_and_privileged_jobs() -> None:
    compose = (REPOSITORY_ROOT / "compose.production.yaml").read_text()

    assert "${PORTAL_IMAGE:?" in compose
    assert "127.0.0.1}:${PORTAL_BIND_PORT:-8090}:8090" in compose
    assert "carlos-patient-portal-outbox-worker" in compose
    outbox_block = compose.split("  outbox:", 1)[1].split("  migrate:", 1)[0]
    assert "healthcheck:" in outbox_block
    assert "carlos-patient-portal-maintenance" in outbox_block
    assert "outbox-status" in outbox_block
    assert "${PORTAL_MIGRATION_ENV_FILE:-deploy/migration.env}" in compose
    assert "${PORTAL_DATABASE_ADMIN_ENV_FILE:-deploy/database-admin.env}" in compose
    assert "${PORTAL_MAINTENANCE_ENV_FILE:-deploy/maintenance.env}" in compose
    assert "postgresql-audit-roles.sql" in compose
    assert "postgresql-database-identity.sql" in compose
    assert "carlos-patient-portal-preflight" in compose
    assert "PATIENT_PORTAL_TRUSTED_PROXY_CIDRS" in compose
    assert "--forwarded-allow-ips=*" not in compose
    assert "--forwarded-allow-ips=${PORTAL_TRUSTED_PROXY_CIDR" in compose
    assert "carlos-patient-portal-maintenance" in compose
    assert "postgres:16.15-bookworm@sha256:" in compose
    maintenance_block = compose.split("  maintenance:", 1)[1].split(
        "  audit-maintenance:", 1
    )[0]
    assert "PORTAL_MAINTENANCE_ENV_FILE" not in maintenance_block
    audit_maintenance_block = compose.split("  audit-maintenance:", 1)[1].split(
        "  database-policy:", 1
    )[0]
    assert "PORTAL_MAINTENANCE_ENV_FILE" in audit_maintenance_block
    assert compose.count("read_only: true") >= 3
    assert compose.count("no-new-privileges:true") >= 2
    assert "profiles:\n      - operations" in compose
    assert "postgres:" not in compose.split("database-policy:", 1)[0]
    migration_block = compose.split("  migrate:", 1)[1].split("  preflight:", 1)[0]
    assert "PORTAL_ENV_FILE" not in migration_block
    assert "PORTAL_MIGRATION_ENV_FILE" in migration_block
    assert "PORTAL_MIGRATION_LOCK_TIMEOUT_MS:-10000" in migration_block
    assert "PORTAL_MIGRATION_STATEMENT_TIMEOUT_MS:-900000" in migration_block
    assert "-c search_path=public" in migration_block
    assert "-c search_path=pg_catalog,public" not in migration_block
    preflight_block = compose.split("  preflight:", 1)[1].split("  maintenance:", 1)[0]
    assert "PORTAL_MAINTENANCE_ENV_FILE" not in preflight_block
    database_policy_block = compose.split("  database-policy:", 1)[1]
    assert "PORTAL_DATABASE_POLICY_LOCK_TIMEOUT_MS:-10000" in database_policy_block
    assert "PORTAL_DATABASE_POLICY_STATEMENT_TIMEOUT_MS:-60000" in database_policy_block
    assert "-c search_path=pg_catalog,public" in database_policy_block


def test_database_policy_explicitly_grants_every_application_table_and_sequence() -> None:
    policy = (
        PACKAGE_ROOT / "deploy" / "postgresql-audit-roles.sql"
    ).read_text()

    for table in models.Base.metadata.tables.values():
        assert f"public.{table.name}" in policy
        if table.name != "patient_portal_staff_assertion_uses":
            assert f"public.{table.name}_id_seq" in policy
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES" not in policy
    assert "GRANT USAGE, SELECT ON ALL SEQUENCES" not in policy
    assert "session_user = current_user" in policy
    assert "WHERE rolname = current_user" in policy
    assert "granted_role.rolname <> :'owner_role'" in policy
    assert "REVOKE SELECT (%1$s), INSERT (%1$s), UPDATE (%1$s), REFERENCES (%1$s)" in policy
    assert "non-system-schema objects" in policy
    assert "REVOKE TEMPORARY ON DATABASE" in policy
    assert "hold privileges outside public" in policy
    assert "membership.roleid" in policy
    assert "only the database admin may inherit the schema owner" in policy
    assert "aclexplode(namespace_record.nspacl)" in policy
    assert "aclexplode(relation_record.relacl)" in policy
    assert "aclexplode(attribute_record.attacl)" in policy
    assert "aclexplode(function_record.proacl)" in policy
    assert "aclexplode(default_acl.defaclacl)" in policy
    assert "ACLs must not grant access to undeclared roles" in policy
    assert "User-schema objects must be owned by the declared schema owner" in policy


def test_database_identity_query_attests_live_tls() -> None:
    identity_query = (
        PACKAGE_ROOT / "deploy" / "postgresql-database-identity.sql"
    ).read_text()

    assert "pg_stat_ssl" in identity_query
    assert "pg_backend_pid()" in identity_query
    assert "'tls'" in identity_query
    assert "'plaintext'" in identity_query
    assert "current_setting('search_path')" in identity_query
    assert "name = 'lock_timeout'" in identity_query
    assert "name = 'statement_timeout'" in identity_query
    assert "'safe'" in identity_query
    assert "'unsafe'" in identity_query


def test_production_deploy_requires_digests_and_never_auto_downgrades() -> None:
    script_path = REPOSITORY_ROOT / "scripts" / "production-deploy"
    script = script_path.read_text()

    assert script_path.stat().st_mode & 0o111
    assert "^[0-9a-f]{64}$" in script
    assert "PORTAL_ROLLBACK_IMAGE" in script
    assert "PORTAL_COMPOSE_OVERRIDE_FILE" in script
    assert 'PORTAL_BIND_ADDRESS:-127.0.0.1' in script
    assert 'PORTAL_BIND_ADDRESS" != "127.0.0.1' in script
    assert "PORTAL_TRUSTED_PROXY_CIDR" in script
    assert "PORTAL_DEPLOY_LOCK_FILE" in script
    assert "flock --nonblock 9" in script
    assert "deploy|export-audit|cleanup-auth|prune-audit|rollback" in script
    assert "run --rm audit-maintenance prune-audit" in script
    assert "carlos-patient-portal-migrate" not in script
    assert "alembic downgrade" not in script
    assert "carlos-patient-portal-migrate -" not in script
    assert "compose --profile operations run --rm migrate" in script
    assert "compose --profile operations run --rm database-policy" in script
    assert "compose --profile operations run --rm preflight" in script
    assert "verify_database_artifacts" in script
    assert "verify_database_targets" in script
    assert "carlos-patient-portal-deployment-probe" in script
    assert "database-artifacts-sha256" in script
    assert "postgresql-database-identity.sql" in script
    assert "does not match the policy packaged in PORTAL_IMAGE" in script
    assert "identity query does not match the query packaged in PORTAL_IMAGE" in script
    assert "targets a different PostgreSQL database" in script
    assert "Database admin connection does not use TLS" in script
    assert "does not enforce the deployment session policy" in script
    migrate_block = script.split("  migrate)", 1)[1].split("    ;;", 1)[0]
    prune_block = script.split("  prune-audit)", 1)[1].split("    ;;", 1)[0]
    assert "verify_database_artifacts" in migrate_block
    assert "verify_database_artifacts" in prune_block
    assert script.index("run --rm database-policy") < script.index("run --rm preflight")
    assert script.index("run --rm preflight") < script.index("compose up --detach")
    assert script.count("--wait --wait-timeout 90") == 2
    rollback_block = script.split("  rollback)", 1)[1].split("  *)", 1)[0]
    assert "validate" in rollback_block
    assert "run --rm preflight" in rollback_block
    assert rollback_block.index("PORTAL_IMAGE=$PORTAL_ROLLBACK_IMAGE") < rollback_block.index(
        "validate"
    )
    assert rollback_block.index("run --rm preflight") < rollback_block.index("compose up")


def test_release_image_includes_sbom_and_provenance() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "release-image.yml").read_text()

    assert "docker buildx build" in workflow
    assert "--provenance=mode=max" in workflow
    assert "--sbom=true" in workflow
    assert 'digest_reference="$image_repository@$digest"' in workflow
    assert "fetch-depth: 0" in workflow
    assert 'release_commit=$(git rev-parse "$GITHUB_SHA^{commit}")' in workflow
    assert 'git merge-base --is-ancestor "$release_commit" origin/main' in workflow
    assert '--build-arg "OCI_REVISION=$RELEASE_COMMIT"' in workflow
    assert "group: release-patient-portal-${{ github.ref }}" in workflow
    assert "checks: read" in workflow
    assert '{"patient-portal (3.11)", "patient-portal (3.12)"}' in workflow


def test_ci_audits_python_and_browser_dependency_graphs() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text()

    assert "python -m pip_audit --strict" in workflow
    assert "npm audit --audit-level=high" in workflow


def test_real_data_readiness_record_covers_external_controls() -> None:
    record = (REPOSITORY_ROOT / "deploy" / "REAL_DATA_READINESS.md").read_text()

    for evidence in (
        "immutable image digest",
        "Run `scripts/production-deploy preflight`",
        "Restore the latest backup",
        "Complete penetration testing",
        "privacy impact",
        "screen-reader",
        "operations owner",
    ):
        assert evidence in record


def test_production_stack_smoke_covers_success_replay_and_fail_closed_role() -> None:
    smoke_path = REPOSITORY_ROOT / "tests" / "production_stack_smoke.sh"
    environment_path = REPOSITORY_ROOT / "tests" / "production-smoke.env"
    smoke = smoke_path.read_text()

    assert smoke_path.stat().st_mode & 0o111
    assert "sslmode=verify-full" in smoke
    assert "postgres:16.15-bookworm@sha256:" in smoke
    assert smoke.count('scripts/production-deploy\" deploy') == 2
    assert "production-elevated.env" in smoke
    assert "preflight accepted an elevated runtime database role" in smoke
    assert "database policy accepted an elevated maintenance role" in smoke
    assert "failed database policy did not roll back its partial grants" in smoke
    assert "concurrent migration bypassed the deployment lock" in smoke
    assert "runtime role could rewrite the migration revision" in smoke
    assert "preflight accepted a stale runtime TRUNCATE grant" in smoke
    assert "preflight accepted column, grant-option, or PUBLIC privilege drift" in smoke
    assert "preflight accepted a runtime-owned shadow schema" in smoke
    assert "database policy accepted an elevated database admin" in smoke
    assert "database policy accepted an extra database-admin membership" in smoke
    assert "database policy accepted a database-admin connection after SET ROLE" in smoke
    assert "preflight accepted UPDATE through an undeclared view" in smoke
    assert "preflight accepted runtime privileges outside public" in smoke
    assert "preflight accepted runtime temporary-object creation" in smoke
    assert "migration accepted a different PostgreSQL database target" in smoke
    assert "audit pruning accepted a different PostgreSQL database target" in smoke
    assert "audit pruning accepted a role other than the declared maintenance role" in smoke
    assert "database policy accepted an unexpected member of privileged roles" in smoke
    assert "preflight accepted patient data owned by an undeclared database role" in smoke
    smoke_override = (
        REPOSITORY_ROOT / "tests" / "compose.production-smoke.yaml"
    ).read_text()
    assert "POSTGRES_USER: portal_cluster_admin" in smoke_override
    assert "CREATE ROLE portal_database_admin LOGIN NOSUPERUSER" in smoke
    assert "GRANT portal_schema_owner TO portal_database_admin" in smoke
    assert "ALTER DATABASE carlos_portal OWNER TO portal_database_admin" in smoke
    assert "POSTGRES_USER: portal_schema_owner" not in smoke_override
    assert "outbox is empty" in smoke

    settings = Settings(_env_file=environment_path)
    assert settings.environment == "production"
    assert settings.clinic_id == "smoke-clinic"


def test_production_environment_example_can_satisfy_runtime_policy(tmp_path: Path) -> None:
    example_path = REPOSITORY_ROOT / "deploy" / "production.env.example"
    example = example_path.read_text()
    assert "PATIENT_PORTAL_DATABASE_SCHEMA_OWNER_ROLE=portal_schema_owner" in example
    assert "PATIENT_PORTAL_DATABASE_MAINTENANCE_ROLE=portal_audit_maintenance" in example
    values = {
        key: value
        for line in example.splitlines()
        if line and not line.startswith("#")
        for key, value in [line.split("=", 1)]
    }
    secret_names = (
        "PATIENT_PORTAL_SESSION_SECRET",
        "PATIENT_PORTAL_IDENTITY_PROOF_SECRET",
        "PATIENT_PORTAL_AUDIT_HASH_SECRET",
        "PATIENT_PORTAL_INTERNAL_HEALTH_TOKEN",
        "PATIENT_PORTAL_INTERNAL_API_TOKEN",
        "PATIENT_PORTAL_SMS_WEBHOOK_TOKEN",
    )
    for index, name in enumerate(secret_names):
        values[name] = f"production-example-{index}-" + ("x" * 32)
    values["PATIENT_PORTAL_INTERNAL_STAFF_ASSERTION_PUBLIC_KEYRING"] = (
        '{"initial":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}'
    )
    values["PATIENT_PORTAL_OUTBOX_ENCRYPTION_KEYRING"] = (
        '{"initial":"outbox-example-' + ("x" * 32) + '"}'
    )
    values["PATIENT_PORTAL_UNLOCK_SECRET_ENCRYPTION_KEYRING"] = (
        '{"initial":"unlock-example-' + ("x" * 32) + '"}'
    )

    configured_path = tmp_path / "production.env"
    configured_path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    settings = Settings(_env_file=configured_path)

    assert settings.environment == "production"
    assert settings.resolved_outbox_keyring.keys() == {"initial"}
    assert settings.resolved_unlock_secret_keyring.keys() == {"initial"}


def test_reference_proxy_omits_raw_request_target_and_limits_expensive_routes() -> None:
    configuration = (PACKAGE_ROOT / "deploy" / "nginx.conf").read_text()

    # The property being guarded is that the *access log* carries no raw request target, so the
    # assertion is scoped to the log_format directive. A file-wide ban also caught the port-80
    # redirect, where echoing the path back to the patient's own browser is both correct and
    # necessary - and banning it there would have meant dropping the path on redirect.
    log_format_block = configuration.split("limit_req_zone", 1)[0]
    assert "$request_uri" not in log_format_block
    assert "$uri" not in log_format_block
    assert "$args" not in log_format_block
    safe_access_log = "access_log /var/log/nginx/patient-portal-access.log portal_safe"
    assert configuration.count(safe_access_log) == 2
    for route in (
        "/auth/login",
        "/auth/password-reset/request",
        "/auth/activate",
        "/auth/mfa/",
    ):
        assert route in configuration
    assert configuration.count("limit_req zone=") == 8
    assert "location ^~ /internal/carlos/" in configuration
    assert "allow 10.0.0.0/8" not in configuration
    assert "allow 127.0.0.1/32" in configuration
    assert "deny all" in configuration
    assert "proxy_set_header X-Forwarded-Proto $scheme" in configuration
    assert configuration.count('proxy_set_header X-CARLOS-Provider-ID ""') == 1
    assert configuration.count('proxy_set_header X-CARLOS-Staff-Assertion ""') == 1
    assert (
        configuration.count(
            "proxy_set_header X-CARLOS-Staff-Assertion $http_x_carlos_staff_assertion"
        )
        == 1
    )
    assert configuration.count("proxy_set_header Host $host") == 2
    assert "location ^~ /patient/" in configuration
    assert "proxy_pass http://carlos_patient_portal/;" in configuration


def test_reference_proxy_restricts_every_internal_prefix_not_just_the_carlos_one() -> None:
    """The source-address restriction must cover /internal/** and be unreachable via /patient/.

    nginx matches prefix locations against the start of the URI, so `^~ /internal/carlos/` never
    matched `/patient/internal/carlos/...` and its `deny all` did not apply there. The trailing
    slash on the `/patient/` proxy_pass then stripped the prefix, handing the application the
    internal route with no source check. Separately, the probe and telemetry endpoints matched only
    `location /` and were served to the public internet.
    """
    configuration = (PACKAGE_ROOT / "deploy" / "nginx.conf").read_text()

    assert "location ^~ /internal/ {" in configuration
    assert "location ^~ /patient/internal/ {" in configuration
    # Both /internal/ and /internal/carlos/ carry their own allow + deny pair.
    # Directives only -- the surrounding comments mention the same words.
    assert configuration.count("allow 127.0.0.1/32;") == 2
    assert configuration.count("deny all;") == 2
    # The patient deployment prefix must refuse the internal API outright rather than proxy it.
    patient_internal_block = configuration.split("location ^~ /patient/internal/ {", 1)[1]
    patient_internal_block = patient_internal_block.split("}", 1)[0]
    assert "return 404;" in patient_internal_block
    assert "proxy_pass" not in patient_internal_block


def test_reference_proxy_replaces_untrusted_forwarded_for_in_every_proxy_block() -> None:
    """The public edge must discard an attacker-supplied forwarding chain.

    Uvicorn consumes X-Forwarded-For before the application sees the ASGI scope. Preserving a
    client-supplied leading value would therefore make request.client, rate-limit keys, and audit
    source hashes attacker-controlled even though the application also has a trusted-proxy parser.
    The directive is asserted twice because the CARLOS location replaces inherited proxy headers.
    """
    configuration = (PACKAGE_ROOT / "deploy" / "nginx.conf").read_text()

    assert configuration.count("proxy_set_header X-Forwarded-For $remote_addr;") == 2
    assert "$proxy_add_x_forwarded_for" not in configuration
    # Never the bare client-provided value, which is the spoofable form.
    assert "proxy_set_header X-Forwarded-For $http_x_forwarded_for" not in configuration

    internal_block = configuration.split("location ^~ /internal/carlos/ {", 1)[1]
    internal_block = internal_block.split("\n  }", 1)[0]
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in internal_block


def test_audit_role_policy_keeps_runtime_append_only_and_pruning_separate() -> None:
    policy = (PACKAGE_ROOT / "deploy" / "postgresql-audit-roles.sql").read_text()

    assert "ALTER TABLE public.patient_portal_audit_events OWNER TO" in policy
    assert "REVOKE UPDATE, DELETE, TRUNCATE" in policy
    assert "GRANT SELECT, INSERT ON public.patient_portal_audit_events" in policy
    assert "GRANT SELECT, DELETE ON public.patient_portal_audit_events" in policy
    assert "REVOKE ALL ON ALL TABLES IN SCHEMA public" in policy


def test_reference_proxy_terminates_tls_and_bounds_request_resources() -> None:
    """An operator copying this file must get a working, PHI-appropriate TLS edge.

    `listen 443 ssl` shipped with no certificate, no TLS floor and no port-80 listener, so
    `nginx -t` failed with "no ssl_certificate is defined for the listen ... ssl directive"
    and the operator improvised TLS from scratch for a PHIPA-regulated service. The header
    comment described upstreams, CIDRs and rates but never mentioned certificates.
    """
    configuration = (PACKAGE_ROOT / "deploy" / "nginx.conf").read_text()

    assert "ssl_certificate " in configuration
    assert "ssl_certificate_key " in configuration
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in configuration
    assert "TLSv1.1" not in configuration
    assert "TLSv1;" not in configuration
    assert "listen 80;" in configuration
    assert "return 301 https://" in configuration
    assert "return 301 https://$host" not in configuration
    assert "listen 80 default_server;" in configuration
    assert "return 444;" in configuration

    # HSTS stays the application's job; duplicating it here is what the review warned against.
    assert "Strict-Transport-Security" not in configuration

    for bound in (
        "client_max_body_size",
        "client_body_timeout",
        "client_header_timeout",
        "proxy_connect_timeout",
        "proxy_send_timeout",
        "proxy_read_timeout",
        "limit_conn portal_conn",
    ):
        assert bound in configuration, f"{bound} left at the nginx default"

    # limit_conn_zone is http-context; declaring it inside server{} does not load.
    zone_line = "limit_conn_zone $binary_remote_addr zone=portal_conn:10m;"
    assert zone_line in configuration
    assert configuration.index(zone_line) < configuration.index("server {")
