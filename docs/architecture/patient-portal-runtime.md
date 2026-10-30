# Patient Portal Runtime — why the portal is a separate Python service

**Status:** accepted for the MVP / pilot, open to revisit before general availability
**Applies to:** this repository
**Written:** 2026-08-13, from the implementation in
[`carlos-emr/carlos#3220`](https://github.com/carlos-emr/carlos/pull/3220)

## Context

CARLOS needs a patient-facing surface: patients receive encrypted email from the clinic and need
somewhere to retrieve the generated passphrase that opens it, plus the account, contact, and
help screens that go with having a login at all.

Every other line of CARLOS is Java on Struts/Spring/Hibernate against MariaDB, deployed as one WAR
in Tomcat. The portal is Python on FastAPI/SQLAlchemy/Alembic against PostgreSQL, deployed as a
separate process with its own database. That is the single largest structural decision in the
codebase, and this document records the reasoning so it can be argued with rather than inferred.

The forcing constraint: **the patient-facing surface is reachable from the public internet, and
the CARLOS application is not.** Everything below follows from wanting that boundary to be a
process and network boundary rather than a servlet filter.

## Decision

Build the portal as a standalone service with its own datastore, and connect it to CARLOS through
a narrow authenticated HTTP contract (`/internal/carlos/*`) rather than a shared database or a
shared deployment.

### Why a separate process rather than a module in the WAR

- **Blast radius.** A defect in the patient surface cannot reach the EMR's session handling, its
  Struts action mappings, its filter chain, or its database credentials. An RCE in the portal
  yields the portal's database — portal accounts, hashed credentials, and encrypted passphrases —
  not the chart.
- **Different threat model, different controls.** The portal needs internet-grade rate limiting,
  MFA, lockout, CSRF on every mutation, and a strict CSP; CARLOS needs none of those at the same
  settings, and retrofitting them onto the shared filter chain would change behaviour for staff
  users. The response-rewriting-filter incidents recorded in the
  [CARLOS contributor guidance](https://github.com/carlos-emr/carlos/blob/develop/CLAUDE.md) are the
  precedent: shared filters are where changes intended for one route family break another.
- **Independent deployment.** Patient-facing downtime and EMR downtime are different incidents with
  different urgency. Separating them lets either be restarted without the other.
- **Data separation is the point.** The portal deliberately holds no chart data. It stores portal
  accounts, invites, audit events, and encrypted passphrases — nothing clinical. Sharing the
  CARLOS schema would have made that boundary a convention instead of a fact. (Offered appointment
  times are a bounded exception; see *Amendment: offered appointment times* below.)

### Why Python/FastAPI rather than a second Java service

This is the weakest link in the argument and should be read as a genuine trade, not a slam dunk.

In favour: the portal is a small, self-contained web service whose whole job is HTTP, validation,
and crypto. FastAPI/Pydantic gives request validation, the OpenAPI contract CARLOS integrates
against, and typed settings validation with far less ceremony than the equivalent Java stack; the
whole service is ~9k lines including its own migrations.

Against, and unresolved: **it is a second language in a Java shop.** Every contributor who can
review the EMR cannot necessarily review the portal, and vice versa. Security patching now has two
cadences and two advisory feeds. This is a real, ongoing tax — see *Consequences* for what has to
be true for it to stay acceptable.

### Why PostgreSQL rather than the MariaDB already deployed

The portal leans on two PostgreSQL features that MariaDB does not offer equivalently:

- **Partial unique indexes** (`WHERE status = 'pending'` or `WHERE status = 'prepared'`), used to
  enforce one pending and one delivery-prepared invite per patient, one pending reset token per
  account, one pending contact review per account, and one pending email-change request per account.
  A first prepared invite also reserves the pending-invite slot, preventing races with legacy
  invite creation while allowing a prepared resend beside its original pending invite.
  These are correctness invariants held by the database rather than by application code, and
  MariaDB has no partial-index equivalent — they would become application-level checks with a race
  window.
- **Transactional advisory locks** (`pg_advisory_xact_lock`), used to serialise activation-attempt
  throttling so a burst of concurrent activation attempts cannot each read a stale failure count.

Concurrency behaviour that depends on these is exercised in CI against PostgreSQL 16
(`tests/test_postgresql_integration.py`), not only against the SQLite used for unit tests.

The cost is real: a clinic now runs two database engines, with two backup, restore, and upgrade
procedures. If the portal ever needs to run on the clinic's existing MariaDB, both invariants would
have to be re-expressed, and the migration would not be mechanical.

### Why a narrow HTTP contract rather than a shared database

Sharing tables would have coupled the portal's schema to Hibernate's mapping and made every portal
migration an EMR migration. The internal API keeps the coupling to a handful of documented
operations (invite lifecycle, account unlock and enable/disable, unlock-secret create/publish/
revoke, contact-review listing and decision, booking prompts and the offered-time sync) with
explicit request and response models.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Java module inside the CARLOS WAR | Shares the filter chain, session handling, and database credentials with the EMR; a public-internet defect reaches the chart. |
| Separate Java/Spring Boot service | Keeps one language and one skill set. Would have avoided the two-language tax entirely; rejected on development speed for the MVP, which is a weaker reason than the others here and is the alternative most worth revisiting. |
| Portal on the existing MariaDB | Loses partial unique indexes and advisory locks; four uniqueness invariants become racy application checks. |
| Shared database between EMR and portal | Couples schemas and migration cadence; removes the data-separation property that motivates the split. |

## Consequences

Accepted costs, stated plainly:

- Two languages, two dependency ecosystems, two lockfile/audit pipelines, two migration tools, two
  database engines, two backup/restore procedures, two sets of security advisories.
- Portal dependency advisories are release-blocking, not routine — the service handles credentials
  and the AES-256-GCM keys that protect patient passphrases. `cryptography` in particular is called
  out in `README.md`.
- The clinic/deployment operator owns SMTP/SMS delivery, database and backup alerting, restore
  drills, and incident response; CARLOS maintainers own application regressions and migration
  compatibility. Runbooks must name both before pilot traffic.

Conditions under which this decision should be revisited:

- If the portal grows to need chart data directly, the "holds nothing clinical" property is gone
  and the calculus changes.
- If Python ownership cannot be staffed — that is, if there is no named maintainer who patches this
  service on a defined SLA — the two-language tax is not being paid and a Java rewrite is cheaper
  than a stale service handling credentials.
- If a multi-clinic deployment is ever wanted. The MVP is deliberately one deployment, one
  database, one origin, one clinic identity per clinic, and several of the schema decisions assume
  it.

## Amendment: offered appointment times (carlos-portal#11)

**Recorded:** 2026-09-30.

CARLOS can attach open appointment times to a booking prompt so the patient can pick one in the
portal. These are **the first appointment data the portal stores**, and they sit uneasily with
"holds nothing clinical": a time, a visit mode, and a location tell a reader of the portal database
that a patient has a follow-up coming. The decision is to accept that narrowly, on these terms.

The direction of the contract does not change. The portal never reads the CARLOS schedule and
CARLOS never accepts calls from the portal. CARLOS pushes the times with the prompt; the CARLOS
`booking-sync` job, signing its own job assertion with `portal.booking_prompt.sync` (see
*Amendment: CARLOS jobs as internal callers*), polls for the patient's pick and reports whether it
was booked. That permission can list pending picks and report results and nothing else.

What is stored, per offered time (`patient_portal_booking_offered_slots`): the CARLOS `slot_id`
(opaque, never interpreted), the start with its UTC offset normalised to UTC, a duration, a visit
mode from a fixed vocabulary (in person, phone, video), and optionally a location code from the
deployment's configured list. What is not stored: the provider, the reason for the visit, the
appointment type beyond the prompt's existing fixed vocabulary, and any free text. Per pick
(`patient_portal_booking_choices`): which time was picked, as a copy of those same fields so the
confirmation survives the offered rows being deleted, when it was picked, and CARLOS's answer. The
prompt keeps a keyed digest of the original offer, used only to recognise a retried create.

When it is deleted:

- Offered times: when the prompt is booked, withdrawn, or declined, in the same transaction; and
  by `cleanup-transient-auth` at its first run after a time starts or its prompt expires, without
  waiting for the transient retention window.
- The copy of a picked time: when CARLOS reports that time taken, the prompt is withdrawn, staff
  turn the account off, or the time starts before CARLOS answers (the pick lapses), in the same
  transaction; for a booked time, CARLOS's `slot_id` at booking and the rest by
  `cleanup-transient-auth` one day after the appointment's start. The pick row itself stays, without the time, so a repeated CARLOS result is
  still answered idempotently, and goes with its prompt.
- The prompt, with its picks: by `cleanup-transient-auth` once it is past its expiry by the
  retention window, any booked time is more than a day past, and any pick reported taken, or lapsed,
  after the expiry was closed more than 7 days ago (the patient is shown that notice). Unanswered
  choices and their
  prompts survive every cleanup until CARLOS reports a result, staff withdraws the prompt or turns
  the account off, or the picked time starts (the pick then closes as `expired`, and its copy goes
  with it).
  Cleanup locks each prompt before its slots or choices and skips busy prompts, matching result
  processing so concurrent cleanup cannot discard pending work or invert its lock order.

The emails the portal sends about a prompt carry none of it: "a message is waiting" and "there is
an update" with a sign-in link, and nothing about times, providers, visit types, or locations.
Audit events record offers, picks, results, and declines with keyed ids and counts only.

These deletions depend on `cleanup-transient-auth` running at least daily, and deleted times remain
in database backups and point-in-time recovery until those age out under the clinic's backup
retention.

This amendment does not make the portal a scheduler: it cannot cancel or move a booking, and it
shows no times CARLOS did not push. A later change that stores more appointment data than this,
or keeps it longer, should amend this section rather than extend it silently.

## Amendment: self sign-up requests (carlos-portal#15)

**Recorded:** 2026-10-15.

A patient can ask for a portal account on a public page, off by default, with their health card
number, date of birth, and email address. Until now the portal held a health card number and a date
of birth only as salted keyed hashes on an invite. A sign-up request holds them, with the typed
email, as data CARLOS can read back, so it is accepted narrowly, on these terms.

The direction of the contract does not change. The portal looks nothing up and never calls CARLOS:
it stores the request, and a CARLOS job polls for it (carlos-portal#16), matches it against a chart,
and sends a normal invite to the email already on file. Nothing typed on the page is ever used as a
destination, so the portal never learns whether a request matched.

What is stored, per request (`patient_portal_signup_requests`): the three details inside one
AES-256-GCM payload under the outbox keyring, a keyed hash of the health card number (the same one
the audit events carry), and the time it arrived and expires. Nothing else: no client address, no
name, no chart number. Audit events carry keyed hashes only.

When it is deleted: when CARLOS reports a result, or at the first sign-up submission or
`cleanup-transient-auth` run after its TTL (one day by default) passes, whichever comes first. As
with offered times, deleted requests remain in database backups and point-in-time recovery until
those age out. A later change that keeps these details longer, or stores more of them, should amend
this section.

## Open items owned by the author

These belong in this document but cannot be reconstructed from the code:

- Whether a Java service was evaluated and on what grounds it was set aside.
- Who the named Python maintainer is, and the patch SLA for portal dependency advisories.
- Whether any clinic in the pilot cohort has an operational constraint against running PostgreSQL.

## See also

- `README.md` — configuration, operations, and the current pilot-blocker list
- [CARLOS layer naming policy](https://github.com/carlos-emr/carlos/blob/develop/docs/architecture/layer-names.md)
  — the naming policy the portal's `*ViewModel`, `*ViewModelAssembler`, and service modules follow

## Amendment: CARLOS jobs as internal callers

**Recorded:** 2026-10-20.

The internal API has two caller types, kept apart:

| | Staff | Job |
| --- | --- | --- |
| Who | a CARLOS provider acting in CARLOS | a CARLOS background job with no person behind it |
| Header | `X-CARLOS-Staff-Assertion` | `X-CARLOS-Job-Assertion` |
| Audience | `carlos-patient-portal-internal-api` | `carlos-patient-portal-job-api` |
| Keys | `PATIENT_PORTAL_INTERNAL_STAFF_ASSERTION_PUBLIC_KEYRING` | `PATIENT_PORTAL_INTERNAL_JOB_ASSERTION_PUBLIC_KEYRING`, one key pair per job |
| Identity claims | `provider_id`, `provider_name`, a `permissions` list | `job`, exactly one `permission` |

Before this, the booking sync signed as a non-login CARLOS provider holding only the sync
permission. That made a job pretend to be a person: the provider row sat in CARLOS's provider lists,
someone could later give it a login or a role without the portal noticing, it signed with the staff
key (so anything able to make CARLOS sign a staff assertion could sign as the job), and every new
job meant another provider row per clinic. A job is now its own caller type with its own key.

Both caller types send the shared Bearer service token, use the same compact Ed25519 format with
strict base64url and duplicate-claim refusal, the same 4096-byte limit, the same 120-second
lifetime with 30 seconds of skew, the same one-time `jti` store, and the same request hash. A job
assertion is always bound to the request, in every environment, and its claim set is exactly
`aud`, `clinic_id`, `exp`, `iat`, `iss`, `jti`, `job`, `kid`, `permission`, `request_hash`. The
different audience and the separate header mean a job assertion can never pass as a staff one or
the reverse, and the staff verifier is unchanged.

**Jobs are code, keys are configuration.** `system_jobs.py` names each job, its display name and
the permissions it may hold: `booking-sync` ("Clinic booking", `portal.booking_prompt.sync`) and
`signup-poll` ("Patient self sign-up", `portal.signup.manage` and `portal.invite.manage`, with no
routes yet; its routes, and the rule that its invite must name a sign-up request it has claimed,
come with self sign-up). Configuration supplies only public keys. Startup refuses an unknown job,
an empty job entry, a malformed key ID, a key ID used twice or shared with the staff keyring, a key
that is not 32 bytes, and a public key used by two jobs or by staff. A job without keys is off. Key
IDs are unique across jobs, so the verifier finds the key by its ID and then requires the signed
`job` to be that key's owner.

**Every route declares its callers.** The default is staff only (`staff_principal_requiring`); a
route opened to a job names one job and one permission (`job_principal_requiring`, which refuses at
startup a job that is not registered or a permission it does not hold). The two booking-sync
routes take the `booking-sync` job only. A staff assertion carrying `portal.booking_prompt.sync`
is refused everywhere, and a test lists every internal route with its callers, failing when a
route is added without that decision. There is no provider-based path left: the portal was not yet
in production, so the transition release was skipped and CARLOS and the portal move together.

**Refusals.** Anything that does not prove who sent it (no or wrong service token, a malformed
envelope, an unknown key ID, a bad signature) is the same `404` "not found" as any unauthenticated
internal call. Once the signature has verified, the refusal has a reason: `unknown_job`,
`wrong_key`, `invalid_claims`, `expired`, `request_mismatch`, `clinic_mismatch`, `replay`,
`both_headers` (both headers on one request) and `route_not_open` (which includes every staff
route) are also `404`, so a job cannot use the API to learn which routes exist; only
`permission_not_held` and `wrong_permission`, on a route open to that job, are `403`.

**Audit.** Unsigned or invalid job headers keep the per-request `staff.action`
`authentication_failed` row that staff failures write, unattributed, with the hashed client
reference. A flood of unsigned or invalid job headers therefore stays visible in the audit log, one
row per request, exactly as for staff. A refusal after the signature verified writes one
`job.auth_refused` row in its place: actor type `system`, the display name and `job:<name>` of the
job whose key signed it, the portal's clinic, the route template (never the raw path or query), the
reason, and the new `assertion_key_id` and `assertion_id` columns (migration 0016). A verified job
whose request later fails gets the usual failure row with that attribution, and a job's successful
actions keep their existing event types with the same actor, key ID and assertion ID. No job event
carries patient details beyond what the same event already records.

**Keys.** CARLOS keeps each job's private key beside the staff key and never falls back to the
staff key; portal operators hold only public halves. Rotation needs no downtime: add the new `kid`
to the portal, switch CARLOS to the new key, and remove the old `kid` after two minutes, the longest
a signed call lives. For a leaked key, remove its `kid` at once; the job stops until CARLOS has the
new key, which is the intended trade.

### Making a job key by hand

A carlos-ctl command for this is planned. Until then, make each job's key by hand, on a trusted
machine, once per job (`booking-sync` shown; use the job's own name throughout):

1. Make the key pair, in a file only you can read:

   ```bash
   umask 077
   openssl genpkey -algorithm ed25519 -out booking-sync.pem
   ```

2. Choose its key ID as `<job>-<yyyymmdd>-<6 hex>`:

   ```bash
   kid="booking-sync-$(date -u +%Y%m%d)-$(openssl rand -hex 3)"
   ```

   It must match `[A-Za-z0-9._-]{1,64}` and differ from the staff key ID and from every other
   job's key ID; the portal refuses to start otherwise.

3. CARLOS side: in `/etc/carlos-emr/carlos.properties` (installed `0640 root:carlos`), set the
   private key as the unpadded base64url of its PKCS#8 DER form, and the key ID:

   ```bash
   openssl pkey -in booking-sync.pem -outform DER | basenc --base64url | tr -d '=\n'
   ```

   ```properties
   patient_portal.job.booking-sync.private_key=<the output above>
   patient_portal.job.booking-sync.key_id=<the kid>
   ```

4. Portal side: the public key is the raw 32-byte Ed25519 key as unpadded base64url:

   ```bash
   openssl pkey -in booking-sync.pem -pubout -outform DER | tail -c 32 | basenc --base64url | tr -d '=\n'
   ```

   Put it in `PATIENT_PORTAL_INTERNAL_JOB_ASSERTION_PUBLIC_KEYRING` under the job and the key ID:
   `{"booking-sync": {"<kid>": "<public key>"}}`. With both jobs configured, and `booking-sync` in
   the middle of a rotation (two key IDs at once), it looks like this:

   ```json
   {
     "booking-sync": {
       "booking-sync-20261020-4f2a9c": "<booking-sync public key, current>",
       "booking-sync-20261101-0a1b2c": "<booking-sync public key, next>"
     },
     "signup-poll": {
       "signup-poll-20261020-9f8e7d": "<signup-poll public key>"
     }
   }
   ```

   In the environment file it goes on one line, for example
   `PATIENT_PORTAL_INTERNAL_JOB_ASSERTION_PUBLIC_KEYRING={"booking-sync":{"<kid>":"<public key>"}}`.

5. Rotation, in short: add the new key ID to the portal keyring and restart the portal first, then
   switch CARLOS to the new private key and key ID and restart every CARLOS node, then remove the
   old key ID from the portal after 2 minutes.

6. Once both values are set, shred or securely delete the `.pem` file (`shred -u booking-sync.pem`
   on a local disk); the private key now lives only in the CARLOS properties file.
