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
export PORTAL_OUTBOX_ENV_FILE="$test_root/outbox.env"
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
cp "$repository_root/tests/production-smoke-outbox.env" "$PORTAL_OUTBOX_ENV_FILE"
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
  "$PORTAL_OUTBOX_ENV_FILE" \
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

# The policy job uses psql directly, so verify its live connection is encrypted before allowing
# any database mutation instead of relying only on application URL validation.
plaintext_admin_environment="$test_root/database-admin-plaintext.env"
sed 's/sslmode=verify-full/sslmode=disable/' \
  "$PORTAL_DATABASE_ADMIN_ENV_FILE" > "$plaintext_admin_environment"
chmod 0600 "$plaintext_admin_environment"
if PORTAL_DATABASE_ADMIN_ENV_FILE="$plaintext_admin_environment" \
  "$repository_root/scripts/production-deploy" apply-db-policy \
  > "$test_root/database-admin-plaintext.log" 2>&1; then
  printf '%s\n' 'database policy accepted a plaintext database-admin connection' >&2
  exit 1
fi
grep -F 'Database admin connection does not use TLS' \
  "$test_root/database-admin-plaintext.log"

unsafe_admin_environment="$test_root/database-admin-unsafe-session.env"
sed 's#sslmode=verify-full#options=-c%20lock_timeout%3D0\&sslmode=verify-full#' \
  "$PORTAL_DATABASE_ADMIN_ENV_FILE" > "$unsafe_admin_environment"
chmod 0600 "$unsafe_admin_environment"
if PORTAL_DATABASE_ADMIN_ENV_FILE="$unsafe_admin_environment" \
  "$repository_root/scripts/production-deploy" apply-db-policy \
  > "$test_root/database-admin-unsafe-session.log" 2>&1; then
  printf '%s\n' 'database policy accepted unbounded database-admin lock waits' >&2
  exit 1
fi
grep -F 'Database admin connection does not enforce the deployment session policy' \
  "$test_root/database-admin-unsafe-session.log"

# Every credential is stored separately, so a copied clinic file must be rejected before a
# migration or retention command can mutate the wrong PostgreSQL database or use the wrong role.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'CREATE DATABASE portal_wrong_target OWNER portal_database_admin'
wrong_migration_environment="$test_root/migration-wrong-target.env"
sed 's#/carlos_portal?#/portal_wrong_target?#' \
  "$PORTAL_MIGRATION_ENV_FILE" > "$wrong_migration_environment"
chmod 0600 "$wrong_migration_environment"
if PORTAL_MIGRATION_ENV_FILE="$wrong_migration_environment" \
  "$repository_root/scripts/production-deploy" migrate \
  > "$test_root/migration-wrong-target.log" 2>&1; then
  printf '%s\n' 'migration accepted a different PostgreSQL database target' >&2
  exit 1
fi
grep -F 'Migration connection targets a different PostgreSQL database' \
  "$test_root/migration-wrong-target.log"

wrong_maintenance_environment="$test_root/maintenance-wrong-target.env"
sed 's#/carlos_portal?#/portal_wrong_target?#' \
  "$PORTAL_MAINTENANCE_ENV_FILE" > "$wrong_maintenance_environment"
chmod 0600 "$wrong_maintenance_environment"
if PORTAL_MAINTENANCE_ENV_FILE="$wrong_maintenance_environment" \
  "$repository_root/scripts/production-deploy" prune-audit \
  > "$test_root/maintenance-wrong-target.log" 2>&1; then
  printf '%s\n' 'audit pruning accepted a different PostgreSQL database target' >&2
  exit 1
fi
grep -F 'Maintenance connection targets a different PostgreSQL database' \
  "$test_root/maintenance-wrong-target.log"

wrong_maintenance_role_environment="$test_root/maintenance-wrong-role.env"
sed \
  's#portal_audit_maintenance:maintenance-test-password#portal_schema_owner:schema-owner-test-password#' \
  "$PORTAL_MAINTENANCE_ENV_FILE" > "$wrong_maintenance_role_environment"
chmod 0600 "$wrong_maintenance_role_environment"
if PORTAL_MAINTENANCE_ENV_FILE="$wrong_maintenance_role_environment" \
  "$repository_root/scripts/production-deploy" prune-audit \
  > "$test_root/maintenance-wrong-role.log" 2>&1; then
  printf '%s\n' 'audit pruning accepted a role other than the declared maintenance role' >&2
  exit 1
fi
grep -F 'deployment probe configuration is invalid' \
  "$test_root/maintenance-wrong-role.log"
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'DROP DATABASE portal_wrong_target WITH (FORCE)'

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

# The schema-owner privilege is needed by the next migration, not by the running application.
# Keep it in the live preflight so drift is found before an upgrade window, and make policy replay
# repair it instead of relying on a one-time database bootstrap command.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'REVOKE CREATE ON SCHEMA public FROM portal_schema_owner'
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/schema-owner-create-drift.json"; then
  printf '%s\n' 'preflight accepted a schema owner unable to run the next migration' >&2
  exit 1
fi
grep -F 'schema_owner_schema_create' "$test_root/schema-owner-create-drift.json"
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight

# Standalone preflight must detect privilege drift on the offline maintenance role too. Otherwise a
# leaked maintenance credential could quietly gain patient-table access between deployments while
# the runtime role continued to look perfectly restricted.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'GRANT SELECT ON public.patient_portal_accounts TO portal_audit_maintenance'
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/maintenance-privilege-drift.json"; then
  printf '%s\n' 'preflight accepted patient-table access for the maintenance role' >&2
  exit 1
fi
grep -F 'maintenance_unexpected_table_privilege' \
  "$test_root/maintenance-privilege-drift.json"
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight

# CONNECT is made explicit for the roles used by future migrations and audit retention. Detect a
# missing direct grant even while PostgreSQL's default PUBLIC grant happens to keep it effective.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'REVOKE CONNECT ON DATABASE carlos_portal FROM portal_audit_maintenance'
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/maintenance-connect-drift.json"; then
  printf '%s\n' 'preflight accepted a missing maintenance CONNECT grant' >&2
  exit 1
fi
grep -F 'maintenance_database_connect' "$test_root/maintenance-connect-drift.json"
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
grep -F 'table:public.allowlist_drift_probe' "$test_root/allowlist-drift.json"
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'DROP TABLE public.allowlist_drift_probe'

# Views are table-like privilege objects too. A grant on an updatable view must not sit outside the
# explicit base-table allowlist, especially when the view's owner can update the audit table.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
SET ROLE portal_schema_owner;
CREATE VIEW public.audit_update_escape AS
  SELECT outcome FROM public.patient_portal_audit_events;
RESET ROLE;
GRANT UPDATE ON public.audit_update_escape TO portal_runtime;
SQL
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/view-drift.json"; then
  printf '%s\n' 'preflight accepted UPDATE through an undeclared view' >&2
  exit 1
fi
grep -F 'table:public.audit_update_escape' "$test_root/view-drift.json"
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight
if compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command "SET ROLE portal_runtime; UPDATE public.audit_update_escape SET outcome = 'rewritten'"; then
  printf '%s\n' 'database policy left runtime UPDATE on an undeclared view' >&2
  exit 1
fi
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'DROP VIEW public.audit_update_escape'

# Privileges in another user schema must survive neither policy validation nor preflight. An
# owner-controlled updatable view there can otherwise route runtime UPDATE back to protected data.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
CREATE SCHEMA privilege_escape AUTHORIZATION portal_schema_owner;
SET ROLE portal_schema_owner;
CREATE VIEW privilege_escape.audit_update_escape AS
  SELECT outcome FROM public.patient_portal_audit_events;
RESET ROLE;
GRANT USAGE ON SCHEMA privilege_escape TO portal_runtime;
GRANT UPDATE ON privilege_escape.audit_update_escape TO portal_runtime;
SQL
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/nonpublic-privilege.json"; then
  printf '%s\n' 'preflight accepted runtime privileges outside public' >&2
  exit 1
fi
grep -F 'nonpublic_schema_usage' "$test_root/nonpublic-privilege.json"
grep -F 'table:privilege_escape.audit_update_escape' "$test_root/nonpublic-privilege.json"
if "$repository_root/scripts/production-deploy" apply-db-policy \
  > "$test_root/nonpublic-policy.log" 2>&1; then
  printf '%s\n' 'database policy accepted runtime privileges outside public' >&2
  exit 1
fi
grep -F 'hold privileges outside public' "$test_root/nonpublic-policy.log"
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'DROP SCHEMA privilege_escape CASCADE'
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight

# pg_temp implicitly precedes even a fixed search_path. The runtime role does not need temporary
# objects, so preflight must detect the drift and policy replay must revoke it.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'GRANT TEMPORARY ON DATABASE carlos_portal TO portal_runtime'
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/temporary-privilege.json"; then
  printf '%s\n' 'preflight accepted runtime temporary-object creation' >&2
  exit 1
fi
grep -F 'database_temporary' "$test_root/temporary-privilege.json"
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight
if compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'SET ROLE portal_runtime; CREATE TEMP TABLE patient_portal_audit_events (id integer)'; then
  printf '%s\n' 'database policy left runtime temporary-object creation enabled' >&2
  exit 1
fi

# Column ACLs and grant options are independent privilege paths. They must fail preflight even when
# the effective table-level booleans still look like the intended allowlist, and policy replay must
# remove both forms of drift.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
GRANT UPDATE (outcome) ON public.patient_portal_audit_events TO portal_runtime;
GRANT SELECT ON public.patient_portal_accounts TO portal_runtime WITH GRANT OPTION;
GRANT SELECT ON public.patient_portal_accounts TO PUBLIC;
SQL
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/acl-drift.json"; then
  printf '%s\n' 'preflight accepted column, grant-option, or PUBLIC privilege drift' >&2
  exit 1
fi
grep -F 'column_acl:public.patient_portal_audit_events' "$test_root/acl-drift.json"
grep -F 'table_grant_option:public.patient_portal_accounts' "$test_root/acl-drift.json"
grep -F 'public_table:public.patient_portal_accounts' "$test_root/acl-drift.json"
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight

# A role outside the declared admin/owner/runtime/maintenance set must not retain direct patient
# access. Runtime's own effective privileges can still look perfect while this separate login reads
# the same tables, so both standalone preflight and policy reconciliation must fail closed.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE portal_unexpected_reader LOGIN;
GRANT SELECT ON public.patient_portal_accounts TO portal_unexpected_reader;
SQL
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/unexpected-acl-grantee.json"; then
  printf '%s\n' 'preflight accepted patient access for an undeclared database role' >&2
  exit 1
fi
grep -F 'unexpected_acl_grantee' "$test_root/unexpected-acl-grantee.json"
if "$repository_root/scripts/production-deploy" apply-db-policy \
  > "$test_root/unexpected-acl-grantee-policy.log" 2>&1; then
  printf '%s\n' 'database policy accepted patient access for an undeclared role' >&2
  exit 1
fi
grep -F 'ACLs must not grant access to undeclared roles' \
  "$test_root/unexpected-acl-grantee-policy.log"
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
REVOKE ALL ON public.patient_portal_accounts FROM portal_unexpected_reader;
DROP ROLE portal_unexpected_reader;
SQL
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight

# Ownership is an implicit privilege that does not appear in an object's ACL. An undeclared owner
# must be rejected even when the runtime role's own effective grants still match the allowlist.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE portal_unexpected_owner LOGIN;
ALTER TABLE public.patient_portal_accounts OWNER TO portal_unexpected_owner;
SQL
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/unexpected-object-owner.json"; then
  printf '%s\n' 'preflight accepted patient data owned by an undeclared database role' >&2
  exit 1
fi
grep -F 'unexpected_object_owner' "$test_root/unexpected-object-owner.json"
if "$repository_root/scripts/production-deploy" apply-db-policy \
  > "$test_root/unexpected-object-owner-policy.log" 2>&1; then
  printf '%s\n' 'database policy accepted patient data owned by an undeclared role' >&2
  exit 1
fi
grep -F 'User-schema objects must be owned by the declared schema owner' \
  "$test_root/unexpected-object-owner-policy.log"
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
ALTER TABLE public.patient_portal_accounts OWNER TO portal_schema_owner;
DROP ROLE portal_unexpected_owner;
SQL
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight

# PostgreSQL's default role-named schema can shadow unqualified application tables. Connections pin
# their search path, while both preflight and the grant policy reject restricted-role ownership in
# every non-system schema.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'CREATE SCHEMA portal_runtime AUTHORIZATION portal_runtime'
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/shadow-schema.json"; then
  printf '%s\n' 'preflight accepted a runtime-owned shadow schema' >&2
  exit 1
fi
grep -F 'schema_create' "$test_root/shadow-schema.json"
grep -F 'schema_object_owner' "$test_root/shadow-schema.json"
if "$repository_root/scripts/production-deploy" apply-db-policy \
  > "$test_root/shadow-schema-policy.log" 2>&1; then
  printf '%s\n' 'database policy accepted a runtime-owned shadow schema' >&2
  exit 1
fi
grep -F 'User-schema objects must be owned by the declared schema owner' \
  "$test_root/shadow-schema-policy.log"
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'DROP SCHEMA portal_runtime'
"$repository_root/scripts/production-deploy" preflight

# The policy administrator is itself part of the trust boundary. Database ownership alone must not
# allow a superuser (or another role-management credential) to bless restricted-role grants.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'ALTER ROLE portal_database_admin SUPERUSER'
if "$repository_root/scripts/production-deploy" apply-db-policy \
  > "$test_root/elevated-admin.log" 2>&1; then
  printf '%s\n' 'database policy accepted an elevated database admin' >&2
  exit 1
fi
grep -F 'Database admin must connect directly' "$test_root/elevated-admin.log"
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 \
  --command 'ALTER ROLE portal_database_admin NOSUPERUSER'

compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE portal_admin_extra NOLOGIN;
GRANT portal_admin_extra TO portal_database_admin;
SQL
if "$repository_root/scripts/production-deploy" apply-db-policy \
  > "$test_root/admin-membership.log" 2>&1; then
  printf '%s\n' 'database policy accepted an extra database-admin membership' >&2
  exit 1
fi
grep -F 'direct member only of the schema-owner role' "$test_root/admin-membership.log"
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
REVOKE portal_admin_extra FROM portal_database_admin;
DROP ROLE portal_admin_extra;
SQL

# Membership in the other direction is equally privileged: a member of runtime can read patient
# data, a member of maintenance can delete audit rows, and a member of the owner can rewrite them.
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE portal_incoming_member NOLOGIN;
GRANT portal_database_admin, portal_schema_owner, portal_runtime, portal_audit_maintenance
  TO portal_incoming_member;
SQL
incoming_privileges=$(compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --tuples-only \
  --no-align \
  --command "SELECT has_table_privilege('portal_incoming_member', 'public.patient_portal_accounts', 'SELECT') AND has_table_privilege('portal_incoming_member', 'public.patient_portal_audit_events', 'UPDATE') AND has_table_privilege('portal_incoming_member', 'public.patient_portal_audit_events', 'DELETE')")
if [ "$incoming_privileges" != "t" ]; then
  printf '%s\n' 'incoming-role membership fixture did not obtain the protected privileges' >&2
  exit 1
fi
if "$repository_root/scripts/production-deploy" apply-db-policy \
  > "$test_root/incoming-membership.log" 2>&1; then
  printf '%s\n' 'database policy accepted an unexpected member of privileged roles' >&2
  exit 1
fi
grep -F 'not be inherited by another role' "$test_root/incoming-membership.log"
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/incoming-membership-preflight.log" 2>&1; then
  printf '%s\n' 'runtime preflight accepted a role that inherits runtime privileges' >&2
  exit 1
fi
grep -F 'role_membership' "$test_root/incoming-membership-preflight.log"
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
REVOKE portal_database_admin, portal_schema_owner, portal_runtime, portal_audit_maintenance
  FROM portal_incoming_member;
DROP ROLE portal_incoming_member;
SQL
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight

compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE portal_owner_incoming_member NOLOGIN;
GRANT portal_schema_owner TO portal_owner_incoming_member;
SQL
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/owner-incoming-membership-preflight.log" 2>&1; then
  printf '%s\n' 'runtime preflight accepted a role that inherits schema-owner privileges' >&2
  exit 1
fi
grep -F 'role_membership' "$test_root/owner-incoming-membership-preflight.log"
compose exec -T database psql \
  --username portal_cluster_admin \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
REVOKE portal_schema_owner FROM portal_owner_incoming_member;
DROP ROLE portal_owner_incoming_member;
SQL
"$repository_root/scripts/production-deploy" preflight

set_role_admin_environment="$test_root/database-admin-set-role.env"
cat > "$set_role_admin_environment" <<'EOF'
DATABASE_ADMIN_URL=postgresql://portal_database_admin:database-admin-test-password@production-test-database:5432/carlos_portal?sslmode=verify-full&sslrootcert=/run/secrets/postgresql-ca.pem&options=-c%20role%3Dportal_schema_owner
PORTAL_SCHEMA_OWNER_ROLE=portal_schema_owner
PORTAL_RUNTIME_ROLE=portal_runtime
PORTAL_MAINTENANCE_ROLE=portal_audit_maintenance
EOF
chmod 0600 "$set_role_admin_environment"
if PORTAL_DATABASE_ADMIN_ENV_FILE="$set_role_admin_environment" \
  "$repository_root/scripts/production-deploy" apply-db-policy \
  > "$test_root/admin-set-role.log" 2>&1; then
  printf '%s\n' 'database policy accepted a database-admin connection after SET ROLE' >&2
  exit 1
fi
grep -F 'Database admin must connect directly' "$test_root/admin-set-role.log"
"$repository_root/scripts/production-deploy" apply-db-policy
"$repository_root/scripts/production-deploy" preflight

privileged_environment="$test_root/production-elevated.env"
sed \
  's#portal_runtime:runtime-test-password#portal_schema_owner:schema-owner-test-password#' \
  "$PORTAL_ENV_FILE" > "$privileged_environment"
chmod 0600 "$privileged_environment"
PORTAL_ENV_FILE="$privileged_environment"
export PORTAL_ENV_FILE
if "$repository_root/scripts/production-deploy" preflight \
  > "$test_root/elevated.log" 2>&1; then
  printf '%s\n' 'preflight accepted an elevated runtime database role' >&2
  exit 1
fi
grep -F 'production database runtime, schema-owner, and maintenance roles must differ' \
  "$test_root/elevated.log"
PORTAL_ENV_FILE="$test_root/production.env"

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
grep -F 'must not own non-system-schema objects' \
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
