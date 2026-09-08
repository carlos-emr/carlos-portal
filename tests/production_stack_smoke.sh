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
export PORTAL_TEST_POSTGRES_IMAGE="postgres:16@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
export PORTAL_COMPOSE_FILE="$repository_root/compose.production.yaml"
export PORTAL_COMPOSE_OVERRIDE_FILE="$repository_root/tests/compose.production-smoke.yaml"

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

cat > "$PORTAL_ENV_FILE" <<'EOF'
PATIENT_PORTAL_ENVIRONMENT=production
PATIENT_PORTAL_CLINIC_ID=production-smoke-clinic
PATIENT_PORTAL_CLINIC_NAME=Production Smoke Clinic
PATIENT_PORTAL_CLINIC_TIMEZONE=America/Toronto
PATIENT_PORTAL_PUBLIC_BASE_URL=https://portal.test
PATIENT_PORTAL_DATABASE_URL=postgresql+psycopg://portal_runtime:runtime-test-password@production-test-database:5432/carlos_portal?sslmode=verify-full&sslrootcert=/run/secrets/postgresql-ca.pem
PATIENT_PORTAL_TRUSTED_CLIENT_IP_HEADER=x-forwarded-for
PATIENT_PORTAL_TRUSTED_PROXY_CIDRS=172.30.80.1/32
PATIENT_PORTAL_SESSION_SECRET=ssssssssssssssssssssssssssssssssssssssss
PATIENT_PORTAL_IDENTITY_PROOF_SECRET=iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
PATIENT_PORTAL_AUDIT_HASH_SECRET=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
PATIENT_PORTAL_INTERNAL_HEALTH_TOKEN=hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh
PATIENT_PORTAL_INTERNAL_API_TOKEN=pppppppppppppppppppppppppppppppppppppppp
PATIENT_PORTAL_INTERNAL_STAFF_ASSERTION_PUBLIC_KEY=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
PATIENT_PORTAL_OUTBOX_ENCRYPTION_KEYRING={"ci":"oooooooooooooooooooooooooooooooooooooooo"}
PATIENT_PORTAL_OUTBOX_ACTIVE_KEY_ID=ci
PATIENT_PORTAL_UNLOCK_SECRET_ENCRYPTION_KEYRING={"ci":"uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu"}
PATIENT_PORTAL_UNLOCK_SECRET_ACTIVE_KEY_ID=ci
PATIENT_PORTAL_SMTP_HOST=smtp.test.invalid
PATIENT_PORTAL_SMTP_PORT=587
PATIENT_PORTAL_SMTP_FROM_ADDRESS=no-reply@portal.test
PATIENT_PORTAL_SMTP_STARTTLS=true
PATIENT_PORTAL_SMTP_USERNAME=production-smoke
PATIENT_PORTAL_SMTP_PASSWORD=smtp-test-password
PATIENT_PORTAL_SMS_WEBHOOK_URL=https://sms.test.invalid/send
PATIENT_PORTAL_SMS_WEBHOOK_TOKEN=tttttttttttttttttttttttttttttttttttttttt
PATIENT_PORTAL_SMS_SENDER_ID=CARLOS
PATIENT_PORTAL_ENABLE_DEV_ADMIN=false
PATIENT_PORTAL_REQUIRE_MFA=true
EOF
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

compose up --detach --wait database
compose exec -T database psql \
  --username portal_schema_owner \
  --dbname carlos_portal \
  --set ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE portal_runtime LOGIN PASSWORD 'runtime-test-password';
CREATE ROLE portal_audit_maintenance LOGIN PASSWORD 'maintenance-test-password';
CREATE ROLE portal_database_admin LOGIN SUPERUSER PASSWORD 'database-admin-test-password';
SQL

"$repository_root/scripts/production-deploy" deploy
curl --fail --silent --show-error \
  --header 'Host: portal.test' \
  --header 'X-Forwarded-Proto: https' \
  "http://127.0.0.1:$PORTAL_BIND_PORT/health" | grep -F '"status":"ok"'
"$repository_root/scripts/production-deploy" readiness
"$repository_root/scripts/production-deploy" outbox-status | grep -F 'outbox is empty'

# A second complete rollout proves migrations, grants, preflight, and service replacement are
# idempotent before an operator depends on the same sequence for upgrades.
"$repository_root/scripts/production-deploy" deploy

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

printf '%s\n' 'production stack smoke test passed'
