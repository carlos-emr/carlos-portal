# Real-data readiness record

Complete this record for each clinic deployment before any real patient information is created,
imported, or transmitted. Attach evidence to the clinic's change record; a checked box without a
test result, ticket, or named approver is not evidence.

## Release and runtime

- [ ] Record the reviewed portal commit, version tag, immutable image digest, and successful CI run.
- [ ] Verify the image SBOM and provenance attestations and record the image vulnerability scan.
- [ ] Run `scripts/production-deploy preflight` and attach its successful JSON output.
- [ ] Confirm the portal is reachable only through the approved TLS edge and port 8090 is loopback.
- [ ] Record the selected worker count, database connection budget, and Argon2 benchmark.

## Database and recovery

- [ ] Record the managed PostgreSQL service, region, encryption control, and TLS CA source.
- [ ] Verify schema-owner, runtime, maintenance, and database-admin role separation.
- [ ] Verify PITR or encrypted backups, retention, monitoring, and separate backup credentials.
- [ ] Restore the latest backup into isolation and test schema readiness, authentication, audit
      history, and encrypted-secret reads. Record recovery time and recovery point.
- [ ] Record off-host escrow and recovery ownership for every encryption key and backup credential.

## CARLOS, email, and SMS

- [ ] Complete CARLOS invite, resend, revoke, staff unlock, and contact-review workflows end to end.
- [ ] Verify CARLOS assertions use the expected clinic, audience, permissions, expiry, key ID, and
      request hash; confirm an exact replay and a changed body/path are rejected.
- [ ] Exercise assertion-key rotation with old and new public keys overlapping, then remove the old
      key after its final assertion expires.
- [ ] Complete password stage, send, publish, revoke, replay, resend, and reconciliation workflows.
- [ ] Verify SMTP STARTTLS, authentication, SPF, DKIM, DMARC, bounce handling, and provider alerts.
- [ ] Verify SMS authentication, delivery, retry behavior, invalid-number handling, and alerts.
- [ ] Simulate CARLOS, SMTP, SMS, portal, and database outages and attach the observed recovery.

## Audit, monitoring, and maintenance

- [ ] Send application and proxy logs to the approved access-controlled central destination.
- [ ] Export an audit batch, confirm durable append-only receipt, and record checkpoint ownership.
- [ ] Alert on readiness, restarts, database saturation, authentication failures, terminal outbox
      work, oldest queued-message age, audit export failure, backup failure, and certificate expiry.
- [ ] Schedule outbox review, transient-auth cleanup, audit export, and approved retention pruning.
- [ ] Exercise session, internal API, outbox, and unlock-key rotation procedures.

## Patient safety, privacy, and access

- [ ] Obtain the clinic's privacy impact and threat-risk approvals, with every service provider and
      PHI flow identified.
- [ ] Approve retention, deletion, breach response, patient notification, and complaint procedures.
- [ ] Complete penetration testing and resolve every launch-blocking finding.
- [ ] Complete keyboard, screen-reader, zoom, contrast, and reviewed WCAG testing.
- [ ] Confirm supported languages, support contacts, and the treatment of unfinished modules.
- [ ] Name the application, database, security, privacy, and patient-support owners and escalation
      paths.

## Go-live authorization

- [ ] Take or verify a recoverable pre-deployment snapshot.
- [ ] Rehearse application rollback using the prior image digest without downgrading the database.
- [ ] Complete one synthetic end-to-end go-live rehearsal through the production edge.
- [ ] Record approval from the clinic owner, privacy owner, security owner, and operations owner.

Deployment record:

- Clinic:
- Public hostname:
- Change ticket:
- Portal commit and version:
- Image digest:
- CI run:
- Preflight output:
- Backup/restore evidence:
- Security review:
- Privacy approval:
- Accessibility review:
- Operations approval:
- Approved activation time:
