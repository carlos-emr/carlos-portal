# Patient portal product spec

> Moved here from issue #6 on 15 Oct 2026, so the spec can change in the same pull requests as the code. The discussion history (the 16 comments carried over from carlos-emr/carlos#3207) stays in #6. The architecture decision record is [`architecture/patient-portal-runtime.md`](architecture/patient-portal-runtime.md).

## Current product spec

This document is the current product spec for a minimal patient-facing CARLOS credential portal. Developers should be able to read this document from top to bottom as the canonical current version.

## MVP Goal

Build a small patient portal/intermediary that lets verified patients manage their portal account and retrieve random per-email passwords used to unlock encrypted CARLOS email/PDF content.

The MVP is not a full patient health record. CARLOS remains the clinical source of truth and owns clinical data, provider workflows, email/document metadata, unlock-secret creation, revocation behavior, and patient scoping.

## In Scope

- Staff-created CARLOS invite linked to a specific `demographic_no`.
- Patient activation from invite with identity proofing.
- Patient username/password login.
- MFA for production accounts, with email and SMS delivery.
- Password reset and staff-assisted lost-MFA recovery.
- Account lockout after high failed-attempt volume, with staff unlock and forced password reset.
- Patient account settings for password, contact info, and MFA management.
- Automatic clinic review request when patient contact info changes and a matching CARLOS chart update may be needed.
- Patient dashboard with `Account`, `Email passwords`, and `Help` modules.
- Patient view/copy of generated per-email PDF unlock passphrases.
- Portal list of successful encrypted email records, newest first, searchable/filterable, 10 per page.
- New encrypted CARLOS unlock-secret table or CARLOS-owned storage surface for generated passphrases.
- Narrow internal CARLOS APIs for portal access; no direct portal access to CARLOS database tables.
- Structured audit for login, invite, reset, MFA, secret view, revoke, masked preview, account lock/unlock, and support actions.
- Generic CARLOS branding for MVP.
- Responsive desktop and mobile UI.

## Out Of Scope For MVP

- Full PHR/document library. This stays out of scope after the MVP as well: the portal never becomes a place where patients keep or read documents.
- Portal-hosted document storage or document byte delivery in the MVP. The first post-MVP feature, Send to myCarlos (see Post-MVP Direction), adds sealed copies that the portal can't open and deletes on pickup.
- Labs, medications, appointments, patient messaging, proxy/dependent access, or clinical editing.
- Patient uploads.
- Staff raw unlock-password reveal, including as downtime fallback.
- Full FHIR CDR, broad/general-purpose FHIR server behavior, SMART-on-FHIR launch, or third-party app platform.
- Arbitrary HL7 v2 ingestion by the portal or general HL7 v2 listener behavior.
- Medplum or HAPI sidecar unless future scope changes.

## Stack Decision

Recommended MVP stack:

- Python/FastAPI portal service.
- PostgreSQL portal database.
- SQLAlchemy or SQLModel with Alembic migrations.
- Server-rendered responsive UI for MVP.
- FHIR libraries used where practical for serialization, validation, and conformance tests.
- CARLOS internal APIs as the integration boundary.

Reasoning: this keeps the patient-facing auth/session/UI separate from provider-facing CARLOS screens while minimizing CARLOS changes and preserving room for a broader portal later.

## Medplum Decision

Use Medplum as product and architecture inspiration only, not as an MVP dependency.

Do not run Medplum, embed Medplum, use Medplum as the portal database, or make Medplum the source of truth for patient identity, documents, passwords, audit, or permissions.

Medplum-inspired ideas to implement locally:

- FHIR-shaped API behavior where it fits the MVP.
- Tenant/project-style clinic isolation.
- Membership, role, and permission patterns.
- Invitation/account lifecycle patterns.
- Structured audit events that can later map to FHIR `AuditEvent` if needed.
- Clear conformance docs and validation tests for the standards surface we claim.

## FHIR And HL7 MVP Requirement

The MVP must be FHIR and HL7 compliant in a scoped, testable way.

FHIR R4 is required for the shipped MVP API surface:

- `/fhir/metadata` `CapabilityStatement`.
- `application/fhir+json` responses.
- `OperationOutcome` errors.
- Search `Bundle` responses and pagination.
- Documented MVP resources/search parameters.
- Validation tests for emitted resources.
- Initial resources: `Patient`, `DocumentReference`, `Organization`, and `Practitioner`; `AuditEvent` optional for admin/internal export.

FHIR boundary:

- Unlock passwords must not be exposed through a general FHIR API.
- FHIR may expose portal-visible metadata, while password retrieval stays inside the authenticated portal/CARLOS workflow with audit.
- Do not claim the portal is a full FHIR CDR, broad FHIR server, SMART-on-FHIR platform, or general clinical data repository.

HL7 v2 requirement:

- Include one concrete CARLOS-owned HL7 v2 message profile/interface in MVP.
- Default candidate: patient identity/update profile for portal-relevant demographics.
- Exact message type, trigger event, version, profile identifier, required fields, and test messages still need to be selected.
- CARLOS remains owner of existing HL7 v2 behavior.
- The portal should not ingest arbitrary ADT, ORU, MDM, SIU, or other HL7 v2 feeds in MVP.

## Core Workflows

Staff invite/admin:

1. Staff opens a patient in CARLOS.
2. Staff with portal permission invites, resends invite, unlocks account, revokes access, or views masked portal status.
3. Actions are logged with provider identity.

Patient activation:

1. Patient follows clinic invite.
2. Patient verifies invite code, email, and clinic-approved identity details such as HCN/HIN, DOB, and postal code or local equivalent.
3. Patient chooses username, password, and MFA method.
4. Activation errors avoid revealing whether a patient account exists.

Patient sign-in:

1. Patient signs in with username and password.
2. MFA is required for production sessions.
3. MFA supports email and SMS, with rate limits.
4. Generic errors avoid account enumeration.
5. Account lockout routes to clinic help and fresh reset after staff unlock.

Email passwords:

1. CARLOS generates a random per-email PDF passphrase when sending encrypted portal-linked email.
2. Patient opens portal and views/copies the passphrase.
3. List is newest-first, searchable/filterable, and paginated.
4. Already-sent encrypted PDFs cannot have their embedded passwords changed unless content is re-encrypted/resent or later delivered through server-hosted document access.

## Security Defaults

- Argon2id password hashing.
- Hashed invite/reset/MFA tokens.
- Dedicated encrypted unlock-secret storage controlled by CARLOS.
- No raw unlock passwords, HCN/HIN, reset tokens, invite tokens, or MFA codes in app logs.
- Tenant and patient scope enforced in both portal and CARLOS API layers.
- Step-up checks for risky account changes.
- Staff-only unlock after lockout, with forced password reset.
- Audit retention default: at least 25 years; indefinite retention acceptable if policy/storage supports it.
- Generic no-reveal wording for sign-in, reset, activation, MFA, and downtime states.

## Product Mocks

Current mock artifact set:

https://github.com/carlos-emr/carlos/tree/f37d55bde9431bfca2a18a9503acc55ad61c09b0/patient-portal-mocks

Screens covered with desktop and mobile screenshots:

- Sign in.
- Sign-in error.
- Portal account activation.
- Password reset.
- MFA with email/SMS switch.
- MFA error.
- Locked account.
- Patient dashboard.
- Email passwords.
- Empty email passwords.
- Account settings.
- CARLOS staff invite/admin view.
- Future patient messages concept.

## Post-MVP Direction

**The first post-MVP feature is Send to myCarlos** ([#41](https://github.com/carlos-emr/carlos-portal/issues/41)). CARLOS signs a document and seals one copy to each of the patient's linked and accepted myCarlos devices. The portal holds each sealed copy until that device picks it up, then deletes it, or deletes it unpicked after 7 days. The portal never stores a readable document, a title or a patient name. The format and the contract between CARLOS, the portal and myCarlos are in [`architecture/mycarlos-delivery.md`](architecture/mycarlos-delivery.md). Everything ships behind `PATIENT_PORTAL_MYCARLOS_DELIVERY_ENABLED`, off by default.

So documents come first after the MVP, before patient messaging, as planned. Patient messaging is viable later and should integrate with the existing CARLOS/OSCAR messaging interface rather than creating a separate staff inbox.

Future patient messaging should support attachments by reference, questionnaires, response enable/disable, hidden sender display, and unread/unacknowledged reminders, but only after release rules, retention, routing, scanning, storage, and staff review workflows are defined.

## Open Decisions

- Choose exact HL7 v2 message/profile for MVP conformance.
- Confirm what revocation/regeneration can guarantee for already-sent encrypted PDFs.
- Decide production cloud provider/region while preserving Canadian data residency.
- Confirm whether any consent tracking, privacy masking, break-glass behavior, or patient directives are needed in MVP.
- Define criteria for expanding beyond credential/unlock-password workflows into broader document/PHR features. Send to myCarlos (#41) is the first such feature; a hosted document library stays out of scope.

## Local Planning Source

Detailed local planning document: `DESIGN_PLAN.md`.

---

## Spec update (2026-08-13): unlock-secret integration direction

Supersedes the In Scope bullet *"Narrow internal CARLOS APIs for portal access; no direct portal access to CARLOS database tables"* **for unlock secrets specifically**. That bullet stands unchanged for staff invites, account unlock, and contact-review requests, where the portal does call into CARLOS.

Unlock secrets go the other way. The passphrase generator that landed for carlos-emr/carlos#3134 (PR carlos-emr/carlos#3135) deliberately **does not persist** the generated passphrase anywhere in CARLOS — it is generated per send, held server-side behind a single-use token for the duration of the compose window, and discarded. That non-persistence is being kept.

Therefore:

- **The escrow lives in the portal, not in CARLOS.** The portal already implements encrypted passphrase storage, reveal auditing, revocation, and encryption-key rotation (carlos-emr/carlos#3220). CARLOS will not build a second secret store.
- **CARLOS pushes; the portal ingests.** There is no CARLOS-side record for the portal to pull. This matches carlos-emr/carlos#3220's existing *"publish generated unlock-secret records"* / *"idempotent CARLOS ingestion"* wording.
- **Key-domain separation is structural.** Separate service, database, and keys from the CARLOS outbound email archive (carlos-emr/carlos#3448) — which permanently retains the encrypted PDF. Neither compromise alone yields both the ciphertext and its unlock secret.
- **Publish precedes transport and fails closed.** If publish fails, the send is blocked by default; a provider may proceed only through an audited break-glass modal that hands them manual delivery of the passphrase. Deployments with no portal configured keep today's carlos-emr/carlos#3135 behavior with no modal.

The `Out Of Scope For MVP` entry *"staff raw unlock-password reveal, including as downtime fallback"* is unaffected and still holds: the break-glass modal is a pre-send delivery handoff for a message not yet sent, not a lookup of a previously issued secret.

Full design and task list: carlos-emr/carlos#3449.
