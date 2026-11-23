# Send to the clinic from myCarlos: message format and contract (`mycarlos-send/1`)

**Status:** contract draft, Ben reviews before any code. Nothing is built. Every part would ship
behind off-by-default switches.
**Applies to:** carlos-portal (a blind store-and-forward mailbox), CARLOS (the receiving adapter),
myCarlos (the sender).
**Tracking:** [mycarlos#282](https://github.com/carlos-emr/mycarlos/issues/282). Related: the
clinic-to-patient contract in [mycarlos-delivery.md](mycarlos-delivery.md) (this document mirrors it
and reuses its keys, framing and device assertions), [link lifecycle
v1](mycarlos-link-lifecycle-v1.md), and the job-principal pattern of the sign-up claim and result
routes.
**Shared vectors:** [`tests/fixtures/send-contract-v1.json`](../../tests/fixtures/send-contract-v1.json),
made by [`tests/send_contract_reference.py`](../../tests/send_contract_reference.py) (FAKE data, no
keys, no randomness).
**Written:** 2026-11-23. **Design background:**
`/root/supervisor/for-ben/mycarlos-282-send-to-clinic-design-20261123.md` (the reasoning; this
document is the contract).

This document is meant to be the single source for the format once approved: CARLOS and myCarlos
would link here and carry a byte-identical copy of the fixture. **Until Ben approves it, it is a
proposal.**

## Defaults chosen for the draft (Ben may change any)

These come from the supervisor's defaults and the design's recommendations. Each is written into the
contract below where it matters.

| # | Question | Default in this draft |
|---|---|---|
| Q1 | Which platforms send | **Desktop only in v1.** The Android portal client is switched off by design today; phone sending is a separate piece (an issue to enable and review the Android portal client, with its threat-model change) |
| Q2 | Who owns the inbox | CARLOS **refuses to enable** until an owner group is named; a standing "this is not an emergency line" notice; **no response-time promise** anywhere |
| Q3 | What the sent record keeps | A **descriptor only** (name, type, size, hash, provenance) for files that did not come from the vault; vault files are referenced by record id |
| Q4 | Video | **Phase 2**, with the caps in the phase table below; the protocol already carries it |
| Q5 | Scanning | A scanner hook on the CARLOS side with `required` and `optional` modes; **required plus scanner down means not filed** |
| Q6 | Portal storage | **Database blobs in v1** with a documented ceiling (phase 1 limits); video needs an object store |
| Q7 | Who can open it | A **new X25519 clinic inbox key**; the portal never re-encrypts or reads |
| Q8 | Whose messages | **The link's own person only**; dependents and guardians are a separate verified-relationship project |
| Q9 | Recall | **Only before the clinic accepts it** (before it is filed into a chart); never after |
| Q10 | Acknowledgement signing | CARLOS signs acknowledgements with an existing **clinic signing key (ES256)** so the app never shows "filed" on the portal's word |
| Q11 | Replies | **Not in v1.** `conversation_id` is carried and `in_reply_to` is reserved (must be null); replies need a clinic-to-patient message type, which does not exist yet, as its own contract version |
| Q12 | Order of work | This contract first, reviewed (security **and** clinical-safety) before any code |

## What it does

A patient opens myCarlos on a desktop, chooses the clinic (a link) and the person (the link's own
person), writes a message and may attach documents from the vault or a file, reviews all of it, and
presses Send. myCarlos seals the message to the clinic's **inbox key** and uploads it in
independently checked chunks to the portal, which stores ciphertext it cannot open. CARLOS polls the
portal, claims a waiting message with a lease, opens it, checks it, and files it **for staff review**
in a pending queue linked to the patient. CARLOS then returns a **signed acknowledgement**. The
portal deletes what it held once the clinic has filed it, or after 7 days.

The patient is told exactly what happened, and **no state means a staff member has read or reviewed
anything**.

**Off switches** (every one stays off until the whole flow works end to end):
- **portal:** `PATIENT_PORTAL_MYCARLOS_SEND_ENABLED=false`. While off, no route below is registered:
  they answer 404, and `send-capabilities` answers 404 so the app says the clinic cannot receive.
- **CARLOS:** `patient_portal.mycarlos.send.enabled=false`; it also refuses to enable without an owner
  group (Q2).
- **myCarlos:** the Send step appears only when the clinic's capabilities say it can receive.

## Keys

| Key | Held by | Used for |
|---|---|---|
| **Clinic inbox key**, X25519 (**new**) | CARLOS, in its keyring file, with rotation | Opening the message's content key. Published to the app by the `key-publish` job, like the clinic signing keys |
| Clinic signing key, ECDSA P-256 (existing) | CARLOS | Signing acknowledgements (and, unchanged, delivery manifests) |
| Device signing key, Ed25519 (existing, per link) | myCarlos, in the vault | Device requests (the assertion), and the signature on the envelope |
| Content key, 32 random bytes (**new**, per message) | myCarlos, only in memory while sending | Sealing the envelope and the chunks |
| Job keys (existing pattern) | CARLOS | The job assertion for `send-sync` |

The device encryption key (X25519) is **not** used here: this direction seals to the clinic.

## Versioning and unknown fields

- Every signed or sealed object carries `v`, an integer. This contract is `v: 1`. A parser that does
  not know the value refuses with `unsupported_version` **before** looking at any other field.
- **Strict parsing.** Every object in this contract (outer record, envelope, attachment, provenance,
  acknowledgement) has exactly the fields listed. An unknown or missing field is refused. There is no
  "ignore what you do not know" in a signed or sealed object, because the signature would then cover
  bytes a verifier did not read.
- **Capabilities are additive.** The `send-capabilities` answer may gain fields in `v: 1`; a client
  ignores fields it does not know there, and never sends something the capabilities do not name.
- A new major version is a new `typ`/route set (`mycarlos-send/2`); both may be served side by side.
  The app picks the highest version the capabilities name that it supports, and says so plainly when
  there is none.
- **Reserved:** `in_reply_to` must be `null` in v1 (Q11).
- **Canonical form:** an object is hashed and signed as its canonical bytes: keys sorted, no spaces,
  UTF-8, only strings, integers and `null` (so this equals RFC 8785 for every object here). The
  fixture gives each object's canonical bytes and SHA-256.

## Identifiers and idempotency

- `message_id`: a UUID v4 **chosen by myCarlos** when the patient presses Send, written to the vault
  **before** any network use. It is the idempotency key for every hop. `conversation_id` equals
  the first message's `message_id`. `attachment_id`: a UUID v4 per attachment.
- Every request that changes something is idempotent on its ids; the table below fixes the status
  codes. A retry never makes a second message, a second chunk or a second chart entry.
- A lost acknowledgement is recovered by **reading the state** (`GET /sends/{message_id}`), never by
  sending the message again.

| Request | Case | Answer | Effect |
|---|---|---|---|
| create | first request | 201 | created |
| create | same outer record, byte for byte | 200 | nothing written |
| create | same `message_id`, different outer record | 409 `send_conflict` | nothing changed |
| envelope or chunk | first time | 200 | stored |
| envelope or chunk | same bytes again | 200 | nothing written |
| envelope or chunk | different bytes for the same place | 409 `chunk_conflict` | nothing changed |
| complete | all parts present, chain matches | 200 `received` | state `received` |
| complete | again, once received | 200 | unchanged |
| complete | a part missing, or a hash that does not chain | 422 `chain_mismatch` (missing parts listed) | unchanged |
| cancel | before received | 200 | everything deleted, state `cancelled` |
| cancel | after received | 200 `recall_requested` | the clinic decides (Q9) |
| result (CARLOS) | same outcome and acknowledgement again | 200 `recorded: false` | nothing written |
| result (CARLOS) | a different outcome for a finished message | 409 | conflict |
| result (CARLOS) | lease expired before the answer | 409 `lease_expired` | the message can be claimed again |

## The objects

### The envelope (sealed; the portal never sees it)

JSON, canonical form, **signed by the device's Ed25519 key** over the canonical bytes
(`b64url(payload).b64url(signature)`, the form device assertions use), then sealed (see "Sealing").
It holds everything personal. At most 64 KiB sealed.

| Field | Meaning |
|---|---|
| `v`, `typ` | `1`, `"mycarlos-send-envelope"` |
| `message_id`, `conversation_id` | UUIDs (see above) |
| `in_reply_to` | `null` (reserved) |
| `clinic_id`, `recipient_id`, `device_key_id` | the link's own; both the portal and CARLOS check them |
| `created_at`, `expires_at` | Unix seconds; `expires_at` is at most 7 days after `created_at` |
| `body` | the patient's text: UTF-8, **at most 8,192 bytes**, plain text only (never markup), no control characters except a line feed. May be empty only if there is an attachment |
| `attachments` | at most **10**; see below |

**No sender name, date of birth or health card number is carried.** Who the patient is comes from the
link's binding in CARLOS (`recipient_id` to the chart) and the device's signature, never from text
the message says about itself.

**Attachment descriptor:** `attachment_id`, `name` (display only: 1 to 120 characters, never a path:
no `/`, `\`, `:` or control characters), `media_type` (from the allow-list), `size` (plaintext
bytes), `sha256` (of the plaintext), `chunk_size` (always 4 MiB), `chunk_count` (must equal
`ceil(size / chunk_size)`), `chain_head` (see "The hash chain"), and `provenance`:
- `{"kind": "patient-original"}`: a file the patient added (a photo, a PDF they made or received
  elsewhere, a video);
- `{"kind": "clinic-signed-copy", "delivery_id": …, "manifest": "<the clinic's own compact manifest,
  unchanged, at most 16 KiB>"}`: a document the clinic delivered, sent back as the **original signed
  bytes**, untouched, so the clinic can check its own signature. It must be a PDF. The sender cannot
  re-sign it.

**Provenance is a claim the receiver re-checks.** For a `clinic-signed-copy` CARLOS verifies, from
the bytes alone, its own signature and manifest and that the `delivery_id` and document hash are ones
it sent **to this recipient**, and stores the result of that check as data
(`matches_sent_document`, `signature_valid_but_unknown_document`, `signature_invalid`,
`not_signed`). A "Verified" label is never copied across, and a patient upload is never turned into a
clinic-authored record: it stays "patient-submitted" in every store.

### The outer record (visible to the portal; nothing personal)

Sent as the body of `POST /sends`. Canonical JSON; the device assertion's `request_hash` covers it.
At most 8 KiB. It names sizes and hashes and nothing else:

`v`, `typ: "mycarlos-send-outer"`, `message_id`, `recipient_id`, `device_key_id`, `clinic_id`,
`created_at`, `expires_at`, `kind` (`message` or `documents`; `message` means no attachments),
`attachment_count`, `attachments` (per attachment: `index`, `chunk_count`, `size` of the sealed
bytes, `chain_head`), `envelope_size`, `envelope_sha256` (of the sealed envelope), `chunk_total`,
`total_size`, `chain_head` (of the message), `sealed_key` (the HPKE-sealed content key, b64url) and
`sealed_key_kid` (which inbox key it was sealed to).

The portal checks: the assertion; `recipient_id`, `device_key_id` and `clinic_id` against the
device; the version; the sizes against the capabilities and quotas; the totals add up; and later, at
`complete`, that the parts it received chain to `chain_head`. It cannot check anything inside.

### The acknowledgement (signed by the clinic)

Canonical JSON signed by a clinic signing key (ES256, `b64url(payload).b64url(signature)`), at most
4 KiB: `v`, `typ: "mycarlos-send-ack"`, `message_id`, `clinic_id`, `recipient_id`, `device_key_id`,
`chain_head` (of the message it is about), `state` (`collected`, `filed` or `refused`), `reason`
(`null` unless `refused`; one of the fixed list), `ref` (opaque, 1 to 64 of `A-Za-z0-9_-`: the clinic's
own handle, never an id the app interprets), `at` (Unix seconds) and `kid` (the signing key's id).

The app verifies it against the **pinned** clinic keys of the link (the same rule as delivery
manifests). It accepts the transitions in the table below only; an acknowledgement it cannot verify,
or whose `chain_head` is not its message's, is shown as **unverified** and never as success.

## Sealing

One 32-byte **content key** per message, random, in memory only. It is sealed to the clinic inbox key
with HPKE (base mode; X25519-HKDF-SHA256, HKDF-SHA256, ChaCha20-Poly1305; info
`"carlos-emr/mycarlos-send/v1"`); the result is `sealed_key`. The envelope and every chunk are sealed
with ChaCha20-Poly1305 under the content key:

- **nonce** (12 bytes): the attachment's position as 4 bytes (`0xFFFFFFFF` for the envelope), then the
  chunk's index as 8 bytes;
- **AAD:** the framed values listed in the fixture (`envelope_aad`, `chunk_aad`, `key_aad`): they bind
  the message, the attachment, the chunk index and count, the recipient, device, clinic and, for the
  key, the sealed envelope's hash. A chunk moved to another place or message fails to open.

`frame(...)` is the existing framing: each part preceded by its length as eight bytes, big endian.

**Chunks.** An attachment is split into plaintext chunks of **at most 4 MiB** (the last may be
shorter); each is sealed separately (plus a 16-byte tag), so a retry re-sends only the chunks the
portal does not have. At most 128 chunks per attachment.

## The hash chain

So that nothing can be dropped, repeated, reordered or borrowed from another message without
detection, and each side can check without opening anything:

- `chain_start = sha256(frame("mycarlos-send/1 chain-start", message_id, attachment_id, chunk_count))`
  (ids as their 16 bytes, the count as 8 bytes);
- `link_i = sha256(frame("mycarlos-send/1 chain-link", link_{i-1}, i, sha256(sealed_chunk_i)))`, with
  `link_{-1} = chain_start`;
- an attachment's `chain_head` is the link after its last chunk;
- the message's `chain_head = sha256(frame("mycarlos-send/1 message", message_id,
  sha256(sealed_envelope), head_of_attachment_0, head_of_attachment_1, ...))`.

The portal recomputes every head from the ciphertext it holds at `complete` (it answers 422
`chain_mismatch` otherwise). CARLOS recomputes them before opening anything, then, after decrypting,
checks each attachment's plaintext against its `sha256` and `size`. The acknowledgement carries the
message head, so the app knows which message it is about. The fixture has the cases that **must not**
agree with the base: a swapped chunk, a dropped one, a repeated one, one changed byte, the same
chunks under another `message_id`, the same chunks as another attachment, and the attachments in the
other order.

## Routes

All device routes use the existing **device assertion** (`X-MyCarlos-Device-Assertion`, `aud`
`carlos-patient-portal-device-api`, `request_hash` over the method, path, query and the exact body;
the `jti` consumed before the operation, so a retry is re-signed). Failed assertions answer a generic
404; a verified device that is refused gets 403 `device_removed` or `recipient_mismatch`. Every
answer carries `Cache-Control: no-store` and the error shape `{"code": ...}`; 429 adds `Retry-After`.
Request and response bodies are read with the bounded reader, never `request.body()`.

| Method and path | Purpose | Answers |
|---|---|---|
| `GET /api/mycarlos/send-capabilities` | what the clinic can receive (below) | 200; 404 when not enabled |
| `POST /api/mycarlos/sends` | create: the outer record | 201, 200, 409 `send_conflict` |
| `PUT /api/mycarlos/sends/{message_id}/envelope` | the sealed envelope | 200, 409 `chunk_conflict` |
| `PUT /api/mycarlos/sends/{message_id}/attachments/{a}/chunks/{n}` | one sealed chunk (the SHA-256 in `X-Chunk-SHA256`) | 200, 409 `chunk_conflict`, 413 |
| `GET /api/mycarlos/sends/{message_id}` | state, and the parts received (the resume point) | 200; 404 |
| `POST /api/mycarlos/sends/{message_id}/complete` | verify and close the upload | 200 `received`; 422 `chain_mismatch` |
| `POST /api/mycarlos/sends/{message_id}/cancel` | cancel, or ask for recall | 200 `cancelled`, or `recall_requested` |
| `GET /api/mycarlos/sends` | list states (`?after&limit`, at most 50) | 200 |

**Capabilities** (`send-capabilities`): `versions` (`["mycarlos-send/1"]`), `enabled`, `phase`
(`phase1` or `phase2_video`), `max_attachment_bytes`, `max_message_bytes`, `max_attachments`,
`chunk_size`, `media_types`, `inbox_key` (`kid` and the public key), `retention_days`, and `notice`
(the clinic's standing notice text key, see "Notices"). **A client that finds no capabilities (404) or
`enabled: false` does not offer Send**, and says why, before the patient writes anything. A second
adapter publishes different limits; that is how "unsupported gateway" is tested.

**Internal routes (CARLOS only; job `send-sync`, permissions `portal.mycarlos.send.claim`, `.read`,
`.result`)**, the sign-up claim and result pattern:

| Method and path | Purpose | Answers |
|---|---|---|
| `POST /internal/carlos/mycarlos/sends/claim` | `{"limit": 1..20}`: complete, unexpired messages not under a lease, `FOR UPDATE SKIP LOCKED`, oldest first; each with a 32-byte lease token (returned once, stored as its SHA-256), lease 300 s (30 to 3600) | 200 |
| `GET /internal/carlos/mycarlos/sends/{id}/parts/{part}` | stream a sealed part (`envelope`, or `a/n`) under the lease | 200 octet-stream; 404 |
| `POST /internal/carlos/mycarlos/sends/{id}/result` | `{lease_token, outcome, ack}` with `outcome` of `collected`, `filed`, `refused` and the signed acknowledgement | 200, 409, 404 |

An unknown id, another clinic's message and a wrong token are the same 404 (constant-time compare,
done even when no row exists). The portal stores and relays the acknowledgement; it deletes the parts
on `filed`, `refused`, `expired`, `cancelled` and after a recall. An unreadable message must not
starve the queue (it is leased to a back-off), refused results are audited, and nothing personal is
logged (the sign-up claim review's findings, applied from the start).

## What each state means

The patient sees these words and **no others about delivery**. Never "read", "seen", "reviewed" or
"sent to a clinician".

| State | Set by | Means | Never means |
|---|---|---|---|
| `queued` | app | kept in the sent record; nothing has been sent yet | that anything left the device |
| `sending` | app | parts are being uploaded; resumes where it stopped | that the portal has all of it |
| `received` | portal (a reply the app checks: `message_id`, `chain_head`, `received_at`) | the portal holds every part and the chain checked; it cannot read them | that the clinic has it |
| `collected` | clinic system, signed acknowledgement | the clinic's system fetched, opened and checked it | filed, seen or read by anyone |
| `filed` | clinic system, signed acknowledgement | stored in the clinic's pending-review queue for staff | that any staff member has read, reviewed or acted on it |
| `refused` | portal (limits, device) or clinic system (signed, with a reason) | not accepted, for one reason from a fixed list; nothing is kept | a judgement about the content |
| `expired` | app or portal, when `expires_at` passes first | the portal deleted what it held | that it was delivered |
| `recalled` | clinic system, signed acknowledgement after a recall request | removed from the pending queue before it was accepted into a chart | that nobody saw it |

Allowed transitions (the fixture lists them as data): `queued` to `sending` or `cancelled`;
`sending` to `received`, `cancelled`, `expired` or `refused`; `received` to `collected`, `refused`,
`expired` or `recalled`; `collected` to `filed`, `refused`, `expired` or `recalled`; `filed` to
`recalled`; the rest are final. **Received** is the portal's own claim and the device cannot verify
it, so the screen says "received by the portal", never "by the clinic". **Collected** and **filed**
come only from the signed acknowledgement.

**Refusal reasons (fixed list):** `unsupported_version`, `bad_signature`, `device_not_accepted`,
`clinic_mismatch`, `expired`, `too_large`, `type_not_allowed`, `active_content`, `scan_failed`,
`chain_mismatch`, `hash_mismatch`, `duplicate_message`, `owner_group_missing`, `not_enabled`.

**Required scanner and the scanner down (Q5):** the message is `collected` (signed) and **not filed**;
it stays `collected` until the scanner is back (then `filed` or `refused: scan_failed`) or it
expires. The screen says "received by the clinic's system", not "filed".

## Limits and media types (defaults; a deployment advertises its own, never larger)

| | Phase 1 (database blobs) | Phase 2, video (object store) |
|---|---|---|
| Per attachment | 20 MiB | 512 MiB |
| Per message | 64 MiB | 1 GiB |
| Media types | `application/pdf`, `image/jpeg`, `image/png`, `image/heic` | those, plus `video/mp4`, `video/quicktime`, `video/webm` |

Hard ceilings the parser enforces whatever a deployment enables: 10 attachments, 8,192 bytes of text,
4 MiB chunks, 128 chunks per attachment, 7 days, 64 KiB sealed envelope, 16 KiB manifest, 4 KiB
acknowledgement. Quota defaults the portal should enforce (proposed): waiting bytes per device
2 GiB, per account 4 GiB, per clinic 50 GiB (phase 1 stays far below with the 64 MiB message cap);
waiting messages per device 20, per account 50, per clinic 5,000; upload 64 chunks a minute per
device; breaching one is 429 `quota_exceeded` with `Retry-After`. **Phase 2 is not available on
database blobs** (Q6): the capabilities stay `phase1` until an object store is configured.

Types are checked **by content** (magic bytes) on the sending side, to save the patient a wasted
upload, and again on the CARLOS side, which is the check that counts. Never allowed: executables,
scripts, archives, Office documents with macros. CARLOS refuses PDFs with launch or script actions or
sanitizes them by policy (`active_content`).

## CARLOS: where it lands, who may act, what is recorded

- **Adapter:** the job `send-sync` (its own key and permissions), polled about every 30 to 60 s. It
  fetches parts to a temporary file confined by `PathValidationUtils`, decrypts chunk by chunk (never
  holding a whole video), and verifies in this order: the signature of the envelope against the
  accepted-device table (a pending, removed or unknown device is refused: this also closes the gap
  that the portal cannot know whether CARLOS approved a device); `clinic_id`, `recipient_id`,
  `device_key_id`; not expired; not already seen (`message_id` is unique); the chains; sizes and
  hashes; types by content; active content; the scanner (Q5); and, for a `clinic-signed-copy`, the
  provenance check above.
- **Where it lands:** a message becomes a Messenger message **from the patient** to the owner group,
  linked to the bound chart, marked "patient message via myCarlos, content not verified by the
  clinic". A document lands in a dedicated incoming queue as a document for the bound patient with
  status **pending**, routed to the owner group, and goes into the chart only by an explicit staff
  action that re-checks access. `Document.source` is `mycarlos-patient`; the provenance result is a
  visible line on the inbox row and in the chart.
- **Wrong patient:** the chart is the **binding's** (`recipient_id` to the chart, set when the device
  was accepted), never a name the message says. Staff see the name from their own chart.
- **Authorization and audit:** a new security object (`_mycarlos_inbox`, read to see the queue, write
  to accept or reject, administrator by default) plus the existing patient-access checks. `LogAction`
  for collected, filed, accepted into a chart, rejected and recalled (the job as the system provider;
  staff as themselves). No message text in any log.
- **Owner group and notices (Q2):** the adapter does not start until an owner group is named. CARLOS
  shows the count and age of unreviewed messages. The patient-facing notice is standing text:
  "This is not an emergency line. Staff may not read this for some time." (the wording needs a
  clinical-safety review); **no response time is promised anywhere**.
- **Recall (Q9):** while the message is not yet accepted into a chart, a recall request removes it
  from the queue and CARLOS returns a signed `recalled` acknowledgement; after, CARLOS answers that it
  is already in the chart and the screen says to contact the clinic.

## myCarlos: the sent record and what it shows

- **A durable, encrypted sent record** (a new manifest field and history events, with its own vault
  format number taken at merge): `message_id`, `conversation_id`, link, person, times, state, the
  patient's own text, the attachment **descriptors** (and, for vault files, the record id; **Q3**: a
  descriptor only for any other file), the acknowledgements as received (kept as proof), a refusal
  reason, and attempts. History events carry ids and states, never text or names. Older builds refuse
  the new format. Bounded (about 200 messages, pruned oldest-final-first with a visible note).
- **Review before Send:** the recipient, the person, the text, and every attachment with its name,
  type, size and provenance line ("Your copy of a document signed by the clinic" or "A file you
  added"). Send is explicit; there is no background send and no "always send".
- **Retries and resume:** the message id is written first; uploads resume from `GET /sends/{id}`;
  the app asks before resuming one whose `expires_at` is near; **cancel** before the last chunk
  deletes everything; after `received` the patient may **request recall** (stated as a request).
- **Desktop only in v1 (Q1).**

## Retention, deletion, revocation

- **Portal:** ciphertext for at most 7 days; deleted on `filed`, `refused`, `expired`, `cancelled`
  and after a recall; tombstones (no content) to the audit horizon. A removed device stops all
  uploads at once (403); its waiting messages are not collected.
- **myCarlos:** the sent record follows the vault's rules (hiding keeps; no permanent delete; older
  backups keep it). The patient is told at Review that a filed message cannot be unsent.
- **CARLOS:** a filed message is a clinical record under the clinic's retention duty; deleting it is a
  clinic process, not a button in the app.
- **Link removed or clinic key changed:** a queued message for a removed link is refused locally and
  kept as "not sent: link removed". A clinic signing-key rotation affects only verifying
  acknowledgements (a key not reachable from the link's pinned set shows the acknowledgement as
  unverified).

## Threat model additions

| # | Threat | Mitigation | Proved by |
|---|---|---|---|
| S-01 | Flooding the portal (disk, other patients) | quotas, per-minute caps, 7-day expiry, hard clinic ceiling, 429 | quota and rate tests |
| S-02 | Malicious file reaches staff | content allow-list both ends, no active content, size ceilings, scanner hook (required fails closed), never rendered on a server | hostile fixtures |
| S-03 | Wrong patient | binding only; accepted device; signature; staff see their own chart's name | cross-patient, removed-device, pending-device cases |
| S-04 | Forged or replayed message | device signature on the envelope; unique `message_id`; consumed `jti`; expiry | replay and tamper tests |
| S-05 | The portal reads or changes content | sealed to the inbox key, AAD-bound ids, hash chain, signed acknowledgements | the chain cases in the fixture |
| S-06 | The portal says "filed" when it was not | only the clinic-signed acknowledgement counts | forged-acknowledgement tests |
| S-07 | A patient upload treated as clinic-authored or "verified" | provenance kinds, re-verified from bytes, stored as a check result | altered-document and other-patient cases |
| S-08 | Duplicates | client ids, unique rows at every hop, resume by reading state | duplicate-retry, kill-mid-upload, lost-acknowledgement tests |
| S-09 | Urgent matters sent to a queue nobody watches | standing notice; refuses to enable without an owner group; unreviewed count and age | the enable refusal |
| S-10 | Personal text in logs or errors | route templates only; generic errors; no body in telemetry | log-content tests |
| S-11 | Key compromise | per-link device keys; inbox key rotation (old and new listed); a rotated-out key still opens waiting messages | rotation and wrong-key tests |
| S-12 | Hostile text | plain text only; bounded; controls refused; never rendered as markup | text fixtures |
| S-13 | Recall used to alter a chart | only before acceptance | recall-after-filed test |

## Conformance

A component is conformant when it passes the fixture: the chain vectors (including those that must
differ), the nonce and AAD bytes, the canonical bytes and hashes of the envelope, outer record and
acknowledgements, the accept and refuse lists for the outer record, envelope and acknowledgement, the
state transitions, the idempotency table and the route list. A **second test adapter** (a minimal
gateway with different limits and no `phase2_video`) runs the same lists, so "wrong clinic, revoked
link, altered document, unsupported gateway, interruption, duplicate retry" are exercised against
more than one implementation. The fixture contains no keys, signatures or randomness; the signature
and HPKE checks are done by the implementations' own tests with FAKE keys.

## Not in this contract

- **Replies** (Q11): the next contract version.
- **Phones** (Q1): the Android portal client is off; enabling it is its own reviewed change.
- **Dependents and guardians** (Q8).
- **Anything in CARLOS beyond the adapter's contract** (the chart screens, the queue wording): the
  CARLOS pull requests.
- **Server code, schema and migrations**: after Ben approves this.

## Rollout (proposed, after approval)

`P1` portal device routes, tables, quotas (PostgreSQL grants and the nginx limits are `deploy/`
changes for Ben to queue); `P2` the internal claim, read and result routes and the `send-sync` job;
`C1` the inbox key, the job and flags in CARLOS; `C2` the adapter with a fake portal; `C3` the filing,
the queue, the security object and the audit; `C4` operator documentation; `M1` the types, sealing,
chunking, the sent record and a fake gateway in myCarlos; `M2` the upload client, outbox, retries and
acknowledgement checks; `M3` the screens in seven languages; `M4` the second adapter and the
interoperability tests. Contract first; the three repositories test against one fixture.
