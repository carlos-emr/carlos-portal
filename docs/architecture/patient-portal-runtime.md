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
CARLOS never accepts calls from the portal. CARLOS pushes the times with the prompt; a CARLOS job,
signed as a dedicated non-login system provider holding only `portal.booking_prompt.sync`, polls
for the patient's pick and reports whether it was booked. That permission can list pending picks
and report results and nothing else.

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
- The copy of a picked time: when CARLOS reports that time taken, or the prompt is withdrawn, in
  the same transaction; for a booked time, by `cleanup-transient-auth` one day after the
  appointment's start. The pick row itself stays, without the time, so a repeated CARLOS result is
  still answered idempotently, and goes with its prompt.
- The prompt, with its picks: by `cleanup-transient-auth` once it is past its expiry by the
  retention window and any booked time is more than a day past. Unanswered choices and their
  prompts survive every cleanup until CARLOS reports a result or staff withdraws the prompt.
  Cleanup locks each prompt before its slots or choices and skips busy prompts, matching result
  processing so concurrent cleanup cannot discard pending work or invert its lock order.

The emails the portal sends about a prompt carry none of it: "a message is waiting" and "there is
an update" with a sign-in link, and nothing about times, providers, visit types, or locations.
Audit events record offers, picks, results, and declines with keyed ids and counts only.

This amendment does not make the portal a scheduler: it cannot cancel or move a booking, and it
shows no times CARLOS did not push. A later change that stores more appointment data than this,
or keeps it longer, should amend this section rather than extend it silently.

## Open items owned by the author

These belong in this document but cannot be reconstructed from the code:

- Whether a Java service was evaluated and on what grounds it was set aside.
- Who the named Python maintainer is, and the patch SLA for portal dependency advisories.
- Whether any clinic in the pilot cohort has an operational constraint against running PostgreSQL.

## See also

- `README.md` — configuration, operations, and the current pilot-blocker list
- [CARLOS layer naming policy](https://github.com/carlos-emr/carlos/blob/develop/docs/architecture/layer-names.md)
  — the naming policy the portal's `*ViewModel`, `*ViewModelAssembler`, and service modules follow
