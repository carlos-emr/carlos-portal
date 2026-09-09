#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d)
tls_directory="$test_root/tls"
mkdir -p "$tls_directory"

export PORTAL_IMAGE=${PORTAL_IMAGE:?Set PORTAL_IMAGE to the locally built test image}
export PORTAL_ALLOW_MUTABLE_IMAGE=true
export PORTAL_BIND_PORT=${PORTAL_BIND_PORT:-18090}
export PORTAL_ENV_FILE="$test_root/production.env"
export PORTAL_MIGRATION_ENV_FILE="$test_root/migration.env"
export PORTAL_DATABASE_ADMIN_ENV_FILE="$test_root/database-admin.env"
export PORTAL_MAINTENANCE_ENV_FILE="$test_root/maintenance.env"
export PORTAL_DB_CA_FILE="$tls_directory/ca.crt"
export PORTAL_TEST_SERVER_CERT_FILE="$tls_directory/server.crt"
export PORTAL_TEST_SERVER_KEY_FILE="$tls_directory/server.key"
export PORTAL_TEST_POSTGRES_IMAGE="postgres:16.15-bookworm@sha256:bb3e1a57e5407e0a5280b4211980a5e537f4abd234a87014ac979849a78dd825"
export PORTAL_COMPOSE_FILE="$repository_root/compose.production.yaml"
export PORTAL_COMPOSE_OVERRIDE_FILE="$repository_root/tests/compose.production-smoke.yaml"
export PORTAL_DEPLOY_LOCK_FILE="$test_root/production-deploy.lock"

compose() {
  docker compose \
    --file "$PORTAL_COMPOSE_FILE" \
    --file "$PORTAL_COMPOSE_OVERRIDE_FILE" \
    "$@"
}

cleanup() {
  compose --profile operations down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$test_root"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$tls_directory/ca.key" \
  -out "$tls_directory/ca.crt" \
  -subj "/CN=CARLOS portal CI CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$tls_directory/server.key" \
  -out "$tls_directory/server.csr" \
  -subj "/CN=production-test-database" >/dev/null 2>&1
cat > "$tls_directory/server.ext" <<'EOF'
subjectAltName=DNS:production-test-database
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -days 1 -sha256 \
  -in "$tls_directory/server.csr" \
  -CA "$tls_directory/ca.crt" \
  -CAkey "$tls_directory/ca.key" \
  -CAcreateserial \
  -extfile "$tls_directory/server.ext" \
  -out "$tls_directory/server.crt" >/dev/null 2>&1
chmod 0644 "$tls_directory/ca.crt" "$tls_directory/server.crt"
chmod 0600 "$tls_directory/server.key"
postgres_uid=$(docker run --rm --entrypoint id "$PORTAL_TEST_POSTGRES_IMAGE" -u postgres)
postgres_gid=$(docker run --rm --entrypoint id "$PORTAL_TEST_POSTGRES_IMAGE" -g postgres)
if [ "$(id -u)" -eq 0 ]; then
  chown "$postgres_uid:$postgres_gid" "$tls_directory/server.key"
elif command -v sudo >/dev/null 2>&1; then
  sudo chown "$postgres_uid:$postgres_gid" "$tls_directory/server.key"
else
  printf '%s\n' 'root or sudo is required to prepare the PostgreSQL TLS key' >&2
  exit 1
fi

cp "$repository_root/tests/production-smoke.env" "$PORTAL_ENV_FILE"
cat > "$PORTAL_MIGRATION_ENV_FILE" <<'EOF'
PATIENT_PORTAL_ENVIRONMENT=production
PATIENT_PORTAL_DATABASE_URL=postgresql+psycopg://portal_schema_owner:schema-owner-test-password@production-test-database:5432/carlos_portal?sslmode=verify-full&sslrootcert=/run/secrets/postgresql-ca.pem
EOF
cat > "$PORTAL_DATABASE_ADMIN_ENV_FILE" <<'EOF'
DATABASE_ADMIN_URL=postgresql://portal_database_admin:database-admin-test-password@production-test-database:5432/carlos_portal?sslmode=verify-full&sslrootcert=/run/secrets/postgresql-ca.pem
PORTAL_SCHEMA_OWNER_ROLE=portal_schema_owner
PORTAL_RUNTIME_ROLE=portal_runtime
PORTAL_MAINTENANCE_ROLE=portal_audit_maintenance
EOF
cat > "$PORTAL_MAINTENANCE_ENV_FILE" <<'EOF'
PATIENT_PORTAL_MAINTENANCE_DATABASE_URL=postgresql+psycopg://portal_audit_maintenance:maintenance-test-password@production-test-database:5432/carlos_portal?sslmode=verify-full&sslrootcert=/run/secrets/postgresql-ca.pem
EOF
chmod 0600 \
  "$PORTAL_ENV_FILE" \
  "$PORTAL_MIGRATION_ENV_FILE" \
  "$PORTAL_DATABASE_ADMIN_ENV_FILE" \
  "$PORTAL_MAINTENANCE_ENV_FILE"

(
  flock --nonblock 8
  if "$repository_root/scripts/production-deploy" migrate \
    > "$test_root/deployment-lock.log" 2>&1; then
    printf '%s\n' 'concurrent migration bypassed the deployment lock' >&2
    exit 1
  fi
  grep -F 'Another portal operation holds the deployment lock' \
    "$test_root/deployment-lock.log"
) 8> "$PORTAL_DEPLOY_LOCK_FILE"

compose up --detach --wait database
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE portal_database_admin LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'database-admin-test-password';
CREATE ROLE portal_schema_owner LOGIN PASSWORD 'schema-owner-test-password';
CREATE ROLE portal_runtime LOGIN PASSWORD 'runtime-test-password';
CREATE ROLE portal_audit_maintenance LOGIN PASSWORD 'maintenance-test-password';
GRANT portal_schema_owner TO portal_database_admin;
ALTER DATABASE carlos_portal OWNER TO portal_database_admin;
GRANT CREATE, USAGE ON SCHEMA public TO portal_schema_owner;
SQL

"$repository_root/scripts/production-deploy" deploy
curl --fail --silent --show-error \
  --header 'Host: portal.test' \
  --header 'X-Forwarded-Proto: https' \
  "http://127.0.0.1:$PORTAL_BIND_PORT/health" | grep -F '"status":"ok"'
"$repository_root/scripts/production-deploy" readiness
"$repository_root/scripts/production-deploy" outbox-status | grep -F 'outbox is empty'
if compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'SET ROLE portal_runtime; UPDATE public.alembic_version SET version_num = version_num'; then
  printf '%s\n' 'runtime role could rewrite the migration revision' >&2
  exit 1
fi
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'GRANT TRUNCATE ON public.patient_portal_accounts TO portal_runtime'
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/dangerous-table-privilege.json"; then
  printf '%s\n' 'preflight accepted a stale runtime TRUNCATE grant' >&2
  exit 1
fi
grep -F 'table_dangerous_privilege' "$test_root/dangerous-table-privilege.json"
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight

# A second complete rollout proves migrations, grants, preflight, and service replacement are
# idempotent before an operator depends on the same sequence for upgrades.
"$repository_root/scripts/production-deploy" deploy

# A direct ordinary-data grant on an undeclared object is privilege drift even when it omits the
# separately checked TRUNCATE/REFERENCES/TRIGGER privileges. The standalone real-data gate must
# catch it, and reapplying the explicit policy must remove it.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
SET ROLE portal_schema_owner;
CREATE TABLE public.allowlist_drift_probe (id integer);
RESET ROLE;
GRANT SELECT, UPDATE ON public.allowlist_drift_probe TO portal_runtime;
SQL
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/allowlist-drift.json"; then
  printf '%s\n' 'preflight accepted ordinary DML on an undeclared table' >&2
  exit 1
fi
grep -F 'runtime_database_allowlist' "$test_root/allowlist-drift.json"
grep -F 'table:allowlist_drift_probe' "$test_root/allowlist-drift.json"
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'DROP TABLE public.allowlist_drift_probe'

privileged_environment="$test_root/production-elevated.env"
sed \
  's#portal_runtime:runtime-test-password#portal_schema_owner:schema-owner-test-password#' \
  "$PORTAL_ENV_FILE" > "$privileged_environment"
chmod 0600 "$privileged_environment"
PORTAL_ENV_FILE="$privileged_environment"
export PORTAL_ENV_FILE
if "$repository_root/scripts/production-deploy" preflight > "$test_root/elevated.json"; then
  printf '%s\n' 'preflight accepted an elevated runtime database role' >&2
  exit 1
fi
grep -F '"name":"runtime_database_role"' "$test_root/elevated.json"
grep -F '"status":"failed"' "$test_root/elevated.json"

compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
SET ROLE portal_schema_owner;
CREATE TABLE public.policy_rollback_probe (id integer);
RESET ROLE;
GRANT CREATE ON DATABASE carlos_portal TO portal_audit_maintenance;
SQL
if "$repository_root/scripts/production-deploy" apply-db-policy \
  > "$test_root/elevated-ownership.log" 2>&1; then
  printf '%s\n' 'database policy accepted database CREATE privilege' >&2
  exit 1
fi
grep -F 'must not own public-schema objects or create database/schema objects' \
  "$test_root/elevated-ownership.log"
probe_privilege=$(compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --tuples-only \
  --no-align \
  --command "SELECT has_table_privilege('portal_runtime', 'public.policy_rollback_probe', 'SELECT')")
if [ "$probe_privilege" != "f" ]; then
  printf '%s\n' 'failed database policy did not roll back its partial grants' >&2
  exit 1
fi
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
REVOKE CREATE ON DATABASE carlos_portal FROM portal_audit_maintenance;
DROP TABLE public.policy_rollback_probe;
SQL

compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'ALTER ROLE portal_audit_maintenance SUPERUSER'
if "$repository_root/scripts/production-deploy" apply-db-policy \
  > "$test_root/elevated-maintenance.log" 2>&1; then
  printf '%s\n' 'database policy accepted an elevated maintenance role' >&2
  exit 1
fi
grep -F 'without elevated attributes or memberships' "$test_root/elevated-maintenance.log"

printf '%s\n' 'production stack smoke test passed'
