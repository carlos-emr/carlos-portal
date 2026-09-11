# Production deployment

This deployment runs one clinic's portal as two long-lived processes: the FastAPI web service and
the durable outbound-message worker. A one-shot migration process uses the schema-owner database
role, and a second one-shot process reapplies the audit-table grants. PostgreSQL remains external so
patient data can use managed encryption, backups, point-in-time recovery, and restore tooling.

The same immutable image runs every portal process. `scripts/production-deploy` refuses a mutable
image tag, applies migrations and database grants, runs the real-data preflight, and verifies the
authenticated readiness endpoint after rollout. Mutating commands also hold a nonblocking host lock
at `/var/lock/carlos-patient-portal-deploy.lock` so overlapping operator or scheduler runs fail
before changing the database or containers. Set `PORTAL_DEPLOY_LOCK_FILE` only when the deployment
account needs a different persistent, host-local path.

Before introducing patient information, complete the per-clinic evidence record in
[`REAL_DATA_READINESS.md`](REAL_DATA_READINESS.md). The automated preflight covers live application
and database controls; the record covers external delivery, recovery, privacy, security, and
operational controls that a container cannot verify.

## Prerequisites

- Docker Engine with the Compose v2 plugin.
- A dedicated managed PostgreSQL 16 database with TLS certificate verification and tested PITR or
  backups. The portal owns its `public` schema and does not share it with another application.
- Pre-created, distinct LOGIN roles for schema ownership, runtime, and audit maintenance, without
  administrator attributes or inherited memberships, plus a separately controlled, non-superuser
  database-admin LOGIN role that directly owns the database and connects without `SET ROLE`. Grant
  the schema owner only `CREATE, USAGE` on `public`, and grant that role directly—and no other
  roles—to the database admin so it can reconcile grants and default privileges without a
  superuser login. The web and outbox credentials must use the runtime role. Provider-managed
  administrator roles require an explicit compatibility check against these ownership and
  membership requirements before selection.
- Host nginx (or an equivalent edge) terminating TLS and proxying to `127.0.0.1:8090`. Start with
  `carlos_patient_portal/deploy/nginx.conf`, replace its example hostname, certificate paths, and
  exact CARLOS source CIDRs, then run `nginx -t` before reloading it.
- SMTP and SMS provider credentials and CARLOS's Ed25519 public assertion keyring.
- A deployment secret manager capable of writing root-readable files with mode `0600`.

The host nginx source address inside the default Compose bridge is `172.30.80.1`. The supplied
environment and Compose defaults trust only that address. If `PORTAL_DOCKER_SUBNET` changes, set
`PORTAL_TRUSTED_PROXY_CIDR` to the exact new bridge gateway `/32` (or `/128` for IPv6) before
deployment. Compose supplies the same value to Uvicorn and the application's trust policy; wildcard
or multi-address proxy trust is rejected.

## Prepare one clinic

Copy the four examples and restrict access before adding credentials:

```bash
install -m 0600 deploy/production.env.example deploy/production.env
install -m 0600 deploy/migration.env.example deploy/migration.env
install -m 0600 deploy/database-admin.env.example deploy/database-admin.env
install -m 0600 deploy/maintenance.env.example deploy/maintenance.env
```

Replace every `replace-*` value. Use separate random values for every application secret. Keep the
database passwords URL-encoded and mount the database provider's CA certificate using
`PORTAL_DB_CA_FILE`. The deployment loads the owner and admin files only into their one-shot jobs,
and loads the audit-deletion credential only for `prune-audit`; web, worker, and general operator
commands never receive those elevated credentials.

Use a capacity-appropriate value for `PORTAL_WEB_WORKERS`. Each worker can open
`PATIENT_PORTAL_DATABASE_POOL_SIZE + PATIENT_PORTAL_DATABASE_MAX_OVERFLOW` connections and the
default Argon2 concurrency reserves roughly 256 MiB at peak. Benchmark the target host before
changing either value:

```bash
docker compose -f compose.production.yaml run --rm web \
  carlos-patient-portal-maintenance benchmark-password-hashing
```

## Release and deploy

Tags matching `v*` publish an image with SBOM and build-provenance attestations to GitHub Container
Registry. Record the digest emitted by the release workflow; use that digest rather than its tag:

```bash
export PORTAL_IMAGE='ghcr.io/carlos-emr/carlos-portal@sha256:replace-with-release-digest'
export PORTAL_DB_CA_FILE='/etc/carlos-portal/postgresql-ca.pem'
scripts/production-deploy validate
scripts/production-deploy deploy
scripts/production-deploy status
```

Before `deploy`, take or verify a recoverable database snapshot. Each migration must remain
compatible with both the currently running image and the rollback image; use a reviewed maintenance
window for a breaking migration. The command runs Alembic with the schema-owner URL, reapplies the
append-only audit policy through the database-admin URL, and runs a
fail-closed preflight through the restricted runtime role. Preflight requires production policy,
PostgreSQL, a current schema, database TLS, a runtime role without inherited privileges or owned
non-system-schema objects, and exact relation, column, sequence, function, grant-option, and
`PUBLIC` ACLs across every user schema. ACLs or object ownership granting user-schema access to
roles outside the declared database admin, schema owner, runtime, and maintenance set are rejected.
Runtime and maintenance roles cannot access non-`public` schemas or create temporary objects. Runtime
connections pin `search_path` to
`pg_catalog,public`, so a role-named schema cannot shadow portal objects. Migrations pin it to
`public`; PostgreSQL still searches the implicitly trusted `pg_catalog` first while using `public`
as the creation target. Only after those checks pass does it start web and outbox, then wait for
both containers to become healthy. It does not configure
DNS, edge TLS, managed backups, or monitoring on the host.

Before any migration, policy change, or audit prune, the wrapper queries every credential and
requires the same PostgreSQL system identifier, database OID, and database name, with TLS active on
every connection. It also requires the migration, runtime, and maintenance sessions to use the
roles declared by database policy, and requires a direct database-admin session. Production URLs
cannot use libpq query parameters such as `host`, `dbname`, or `service` to override their declared
target or `options` to replace the enforced search path and bounded waits. Before any migration,
policy application, or audit prune, the wrapper compares both the host policy SQL and
database-identity query checksums with the copies packaged in `PORTAL_IMAGE`; run the wrapper from
the same reviewed release checkout as the image.

Migration connections fail after 10 seconds, lock waits after 10 seconds, and statements after 15
minutes. Database-policy connections use the same connect and lock limits and a 60-second statement
limit. Override these only for a reviewed migration using
`PORTAL_MIGRATION_CONNECT_TIMEOUT_SECONDS`, `PORTAL_MIGRATION_LOCK_TIMEOUT_MS`,
`PORTAL_MIGRATION_STATEMENT_TIMEOUT_MS`, or the corresponding `PORTAL_DATABASE_POLICY_*` variable.

The deployment command rejects any bind address except `127.0.0.1`, because the web process trusts
forwarding headers from its private bridge. Expose it through the reference nginx policy so
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
scripts/production-deploy preflight
scripts/production-deploy outbox-status
scripts/production-deploy export-audit 0 1000 > audit-batch.jsonl
scripts/production-deploy cleanup-auth 30
scripts/production-deploy prune-audit
docker compose -f compose.production.yaml logs --tail 100 web outbox
```

Advance the audit export checkpoint only after `audit-batch.jsonl` is durably accepted by the
clinic's protected append-only sink. Schedule these commands with the host's audited scheduler and
capture their exit status. Alert separately on container restarts, readiness failures, terminal
outbox rows, queue age, database saturation, and certificate expiry. Run retention pruning only
under the clinic's approved retention policy.
