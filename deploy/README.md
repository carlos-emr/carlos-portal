# Production deployment

This deployment runs one clinic's portal as two long-lived processes: the FastAPI web service and
the durable outbound-message worker. A one-shot migration process uses the schema-owner database
role, and a second one-shot process reapplies the audit-table grants. PostgreSQL remains external so
patient data can use managed encryption, backups, point-in-time recovery, and restore tooling.

The same immutable image runs every process. `scripts/production-deploy` refuses a mutable image
tag during a production deployment, applies migrations and database grants before restarting the
application, and verifies the authenticated readiness endpoint afterward.

## Prerequisites

- Docker Engine with the Compose v2 plugin.
- A managed PostgreSQL 16 database with TLS certificate verification and tested PITR or backups.
- Pre-created schema-owner, runtime, audit-maintenance, and database-admin roles. The web and outbox
  credentials must use the runtime role.
- Host nginx (or an equivalent edge) terminating TLS and proxying to `127.0.0.1:8090`. Start with
  `carlos_patient_portal/deploy/nginx.conf`, replace its example hostname, certificate paths, and
  exact CARLOS source CIDRs, then run `nginx -t` before reloading it.
- SMTP and SMS provider credentials and CARLOS's Ed25519 public assertion key.
- A deployment secret manager capable of writing root-readable files with mode `0600`.

The host nginx source address inside the default Compose bridge is `172.30.80.1`. The supplied
environment example trusts only that address. If `PORTAL_DOCKER_SUBNET` changes, update
`PATIENT_PORTAL_TRUSTED_PROXY_CIDRS` to the new bridge gateway `/32` before deployment.

## Prepare one clinic

Copy the three examples and restrict access before adding credentials:

```bash
install -m 0600 deploy/production.env.example deploy/production.env
install -m 0600 deploy/migration.env.example deploy/migration.env
install -m 0600 deploy/database-admin.env.example deploy/database-admin.env
```

Replace every `replace-*` value. Use separate random values for every application secret. Keep the
database passwords URL-encoded and mount the database provider's CA certificate using
`PORTAL_DB_CA_FILE`. The deployment loads the owner and admin files only into their one-shot jobs;
the web and worker never receive those elevated credentials.

Use a capacity-appropriate value for `PORTAL_WEB_WORKERS`. Each worker can open
`PATIENT_PORTAL_DATABASE_POOL_SIZE + PATIENT_PORTAL_DATABASE_MAX_OVERFLOW` connections and the
default Argon2 concurrency reserves roughly 256 MiB at peak. Benchmark the target host before
changing either value:

```bash
docker compose -f compose.production.yaml run --rm web \
  carlos-patient-portal-maintenance benchmark-password-hashing
```

## Release and deploy

Tags matching `v*` publish an image to GitHub Container Registry. Record the digest emitted by the
release workflow; use that digest rather than its tag:

```bash
export PORTAL_IMAGE='ghcr.io/carlos-emr/carlos-portal@sha256:replace-with-release-digest'
export PORTAL_DB_CA_FILE='/etc/carlos-portal/postgresql-ca.pem'
scripts/production-deploy validate
scripts/production-deploy deploy
scripts/production-deploy status
```

Before `deploy`, take or verify a recoverable database snapshot. The command runs Alembic with the
schema-owner URL, reapplies the append-only audit policy through the database-admin URL, starts the
web and outbox processes, and waits for database/schema readiness. It does not configure DNS, TLS,
managed backups, or monitoring on the host.

The portal is published only on host loopback. Expose it through the reference nginx policy so
route-specific shared rate limits and CARLOS/internal endpoint ACLs remain in force. Do not publish
port 8090 on a public interface.

## Roll back the application

Keep the prior image digest with the deployment record. If the prior application version is
compatible with the current database schema, restart the processes without changing the schema:

```bash
export PORTAL_IMAGE='ghcr.io/carlos-emr/carlos-portal@sha256:current-digest'
export PORTAL_ROLLBACK_IMAGE='ghcr.io/carlos-emr/carlos-portal@sha256:previous-digest'
export PORTAL_DB_CA_FILE='/etc/carlos-portal/postgresql-ca.pem'
scripts/production-deploy rollback
```

Database downgrades are deliberately never automatic. Several migrations refuse to discard queued
messages or audit evidence. If an application rollback is not schema-compatible, enter maintenance
mode and follow a reviewed data migration and Alembic downgrade plan from a restored copy first.

## Operational commands

```bash
scripts/production-deploy readiness
docker compose -f compose.production.yaml logs --tail 100 web outbox
docker compose -f compose.production.yaml run --rm web \
  carlos-patient-portal-maintenance outbox-status
docker compose -f compose.production.yaml run --rm web \
  carlos-patient-portal-maintenance cleanup-transient-auth --dry-run
```

Ship container logs and audit exports to the clinic's protected central sink. Alert separately on
container restarts, readiness failures, terminal outbox rows, queue age, database saturation, and
certificate expiry. Schedule audit export, transient-auth cleanup, and retention pruning under the
clinic's approved retention policy.
