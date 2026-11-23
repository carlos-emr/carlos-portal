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
**Written:** 2026-11-23, revised the same day after the design review (nine must-fixes).
**Design background:** `/root/supervisor/for-ben/mycarlos-282-send-to-clinic-design-20261123.md`.

This document is meant to be the single source for the format once approved: CARLOS and myCarlos
would link here and carry a byte-identical copy of the fixture. **Until Ben approves it, it is a
proposal.**

## Defaults chosen for the draft (Ben may change any)

| # | Question | Default in this draft |
|---|---|---|
| Q1 | Which platforms send | **Desktop only in v1.** The Android portal client is switched off by design today; phone sending is a separate piece (an issue to enable and review the Android portal client, with its threat-model change) |
| Q2 | Who owns the inbox | CARLOS **refuses to enable** until an owner group is named; a standing "this is not an emergency line" notice; **no response-time promise** anywhere |
| Q3 | What the sent record keeps | A **descriptor only** (name, type, size, hash, provenance) for files that did not come from the vault; vault files are referenced by record id |
| Q4 | Video | **Phase 2**, with the caps in the phase table below; the protocol already carries it |
| Q5 | Scanning | A scanner hook on the CARLOS side with `required` and `optional` modes; **required plus scanner down means not filed** |
| Q6 | Portal storage | **Database blobs in v1** with a documented ceiling (phase 1 limits); video needs an object store |
| Q7 | Who can open it | A **new X25519 clinic inbox key** (authenticated by a signed statement, below); the portal never re-encrypts or reads |
| Q8 | Whose messages | **The link's own person only**; dependents and guardians are a separate verified-relationship project |
| Q9 | Recall | **Only before the clinic accepts it** into a chart; never after; by a device-signed request (below) |
| Q10 | Acknowledgement signing | CARLOS signs acknowledgements with an existing **clinic signing key (ES256)** so the app never shows "filed" on the portal's word |
| Q11 | Replies | **Not in v1.** `conversation_id` is carried and `in_reply_to` is reserved (must be null); replies need a clinic-to-patient message type, which does not exist yet, as its own contract version |
| Q12 | Order of work | This contract first, reviewed (security **and** clinical-safety) before any code |

## What it does

A patient opens myCarlos on a desktop, chooses the clinic (a link) and the person (the link's own
person), writes a message and may attach documents from the vault or a file, reviews all of it, and
presses Send. myCarlos seals the message to the clinic's **inbox key** (after checking that key's
signed statement) and uploads it in independently checked chunks to the portal, which stores
ciphertext it cannot open. CARLOS polls the portal, claims a waiting message with a lease, opens it,
checks it, and files it **for staff review** in a pending queue linked to the patient. CARLOS then
returns a **signed acknowledgement**. The portal deletes what it held once the clinic has filed it,
or after 7 days.

The patient is told exactly what happened, and **no state means a staff member has read or reviewed
anything**.

**Off switches** (every one stays off until the whole flow works end to end):
- **portal:** `PATIENT_PORTAL_MYCARLOS_SEND_ENABLED=false`. While off, no route below is registered:
  they answer 404, and `send-capabilities` answers 404 so the app says the clinic cannot receive.
- **CARLOS:** `patient_portal.mycarlos.send.enabled=false`; it also refuses to enable without an
  owner group (Q2).
- **myCarlos:** the Send step appears only when the clinic's capabilities say it can receive.

## Keys

| Key | Held by | Used for |
|---|---|---|
| **Clinic inbox key**, X25519 (**new**) | CARLOS, in its keyring file, with rotation | Opening the message's content key. **Named to the app only by a signed statement** (next section) |
| Clinic signing key, ECDSA P-256 (existing) | CARLOS | Signing acknowledgements, the inbox key statement and (unchanged) delivery manifests |
| Device signing key, Ed25519 (existing, per link) | myCarlos, in the vault | Device requests (the assertion), the signature on the envelope and on a recall request |
| Content key, 32 random bytes (**new**, per message) | myCarlos, **only in memory** while sending | Sealing the envelope and the chunks |
| Job keys (existing pattern) | CARLOS | The job assertion for `send-sync` |

The device encryption key (X25519) is **not** used here: this direction seals to the clinic.

## The inbox key is authenticated (a signed statement)

If the app took the inbox key from the portal's word, a dishonest portal could hand out its own key,
read everything and re-seal it to the real clinic: a total break with no trace. So **the key is named
by a statement the clinic signs**, which the app checks against the clinic signing keys the link
already pins (the same trust anchor as delivery manifests and acknowledgements):

`typ: "mycarlos-send-inbox-key"`, `v`, `clinic_id`, `kid` (must equal `b64url(sha256(public_key))`),
`public_key` (b64url, 32 bytes), `signer_kid` (the pinned signing key that signed it), `serial`
(an integer from 1, rising with each key), `not_before`, `not_after` (Unix seconds; validity **at most 30 days**) and `status` (`active` or
`revoked`). Statements are short-lived and re-signed by key-publish, so **expiry is the real
revocation channel** for a device that has not seen a revocation.

- The capabilities carry the statement (compact signed form, at most 2 KiB), and the portal may also
  carry earlier statements. The app **verifies the signature first**, then the rules above, and
  **seals only to an `active` key that is inside its validity** and whose `clinic_id` is the link's.
- **No rollback.** The app persists, per link, a **high-water mark**: the highest `serial` it has ever
  accepted and whether that serial revoked the key. It refuses any lower serial (`serial_rollback`: a
  dishonest portal replaying an older, still-unexpired statement), a statement for another clinic
  (`clinic_mismatch`), and **at an equal serial a revocation wins** (`revoked_wins`): an active statement
  at the serial of a known revocation is refused. A revocation should also take a higher serial than the
  statement it revokes.
- **Rotation:** a new key gets a new statement with a higher `serial` and an overlapping validity; CARLOS
  keeps decrypting with the old key until nothing is waiting under it. **Revocation:** a statement with
  `status: "revoked"` for that `kid`; the app stops sealing to it at once.
- **CARLOS refuses what is sealed to a revoked key** and created after the revocation, with a signed
  `refused` / `key_revoked`; a message created before the revocation is still opened (the clinic holds the
  key).
- **The sealed key names which statement it was sealed to** (`sealed_key_kid` in the outer record).
  CARLOS refuses a message sealed to a `kid` it does not hold.
- A statement that does not verify, or that names no active key, means **the app does not send** and
  says "this clinic's key could not be checked".
- The capabilities themselves are **not signed**: a dishonest portal can lower the limits or hide the
  feature, which is a denial of service, never a way to read a message. The app never raises a limit
  above its own ceilings because the capabilities say so.

## Versioning, unknown fields and signed bytes

- Every signed or sealed object carries `v`, **exactly the integer `1`** (not `true`, not `1.0`, not
  `"1"`, not `null`). A parser that does not find exactly that refuses with `unsupported_version`
  before looking at any other field; a missing `v` is a missing field.
- **Strict parsing.** Every object has exactly the fields listed. An unknown or missing field is
  refused. There is no "ignore what you do not know" in a signed or sealed object.
- **Capabilities are additive**: new fields may appear in `v: 1`; a client ignores unknown fields
  there and never sends what the capabilities do not name.
- A new major version is a new `typ` and route set (`mycarlos-send/2`), served side by side.
- **Canonical form is RFC 8785 (JCS) over I-JSON (RFC 7493):** keys sorted, no spaces, UTF-8, only
  strings, **integers in 0..2^53-1** and `null`. A float (`1.0`, `1e3`), `NaN`, `Infinity`, an integer
  above 2^53-1 or below 0, and a **lone surrogate** (an escape such as `\ud800` with no partner) are
  refused at parse (`not_json` or `bad_number`, never an uncaught exception). Escaping is only `"`, `\`
  and the controls below U+0020 (short forms `\b \t \n \f \r`, else lower-case `\u00xx`). **Implementers:
  use a real RFC 8785 serialiser.** In Java that is not Gson, whose HTML-safe escaping (`<`, `>`, `&`, `'`
  as `\u003c` ...) is NOT canonical and breaks every signature.
- **What is signed, exactly.** The compact form is `b64url(payload).b64url(signature)`, unpadded. The
  **signature covers `frame(domain, payload)`**, where `payload` is the canonical bytes and `domain` is
  one of these, each ending the object's own purpose (the device key also signs request assertions and
  the clinic key also signs delivery manifests, so a signature made for one purpose can never be
  replayed as another):
  `"mycarlos-send/1 envelope-signature"`, `"... ack-signature"`, `"... recall-signature"`,
  `"... inbox-key-signature"`. Never the base64 text, never the payload alone. The fixture gives each
  signing input as bytes.
- **Check order, for every signed or sealed object:** (1) the signature over `frame(domain, payload)`;
  (2) the payload is unpadded base64url, valid UTF-8 JSON under the I-JSON rules above; (3)
  `canonical(parse(payload)) == payload` (`not_canonical`); (4) `v` is exactly 1 (`unsupported_version`),
  before any other field is read; (5) exactly the listed fields, then the field rules.
- **One byte string per object.** Before verifying or hashing anything, a verifier decodes the payload
  and requires `canonical(parse(bytes)) == bytes`. A payload with unsorted keys, spaces, a key twice or
  a trailing line feed is refused (`not_canonical`).
- **Text rules** (the body and every name): NFC; no control character except a line feed in a body (so
  no C0 or C1, no U+2028 or U+2029), no format character (zero-width, byte order mark, left-to-right and
  right-to-left marks, bidirectional embeddings, overrides and isolates), no private-use or surrogate code point (**unassigned code points are allowed**, so the answer does not
  depend on an implementation's Unicode version; the categories are those of **Unicode 16.0**); a name has no line feed and no leading or trailing white space. "Empty" means
  only Unicode White_Space characters.

## Identifiers and idempotency

- `message_id`: a UUID v4 **chosen by myCarlos** when the patient presses Send, written to the vault
  before any network use. `conversation_id` equals the first message's `message_id`. `attachment_id`: a
  random UUID v4 per attachment (it is in the outer record, so the portal can check the chain).
- **Ids are scoped to the device.** The portal's uniqueness is on (device, `message_id`); an id that
  belongs to another device, or does not exist, gets the same 404, so no device can probe for another's
  ids. A tombstoned id is never recreated.
- Every request that changes something is idempotent on its ids; the table fixes the answers. A lost
  acknowledgement is recovered by **reading the state** (`GET /sends/{message_id}`), never by sending
  the message again.
- **CARLOS keys its own filing on (device, `message_id`, `chain_head`)**: the same triple again issues
  the original acknowledgement again, byte for byte, and files nothing twice; the same (device,
  `message_id`) with a different `chain_head` is a signed refusal, `duplicate_message`.

| Request | Case | Answer | Effect |
|---|---|---|---|
| create | first request | 201 | created |
| create | same outer record, byte for byte | 200 | nothing written |
| create | same `message_id` from this device, different outer record | 409 `send_conflict` | nothing changed |
| create | an id this device used and the portal deleted (a tombstone) | 410 `gone` | never recreated |
| create | `expires_at` in the past | 422 `expired` | refused |
| create | `created_at` more than 300 s ahead of the portal's clock | 422 `bad_time` | refused |
| any | an id of another device, or none | 404 | the same answer: no existence oracle |
| envelope or chunk | first time | 200 | stored |
| envelope or chunk | same bytes again | 200 | nothing written |
| envelope or chunk | different bytes for the same place | 409 `chunk_conflict` | nothing changed |
| complete | all parts present, chain matches | 200 `received` | state `received` |
| complete | again, once received | 200 | unchanged |
| complete | a part missing, or a hash that does not chain | 422 `chain_mismatch` | unchanged |
| complete | after a cancel | 409 `cancelled` | unchanged |
| cancel | before complete | 200 | everything deleted, state `cancelled` |
| cancel | after complete | 409 `use_recall` | unchanged |
| recall | device-signed, for a received message | 200 | `recall_requested` |
| recall | the same recall again | 200 | nothing written |
| recall | for a deleted message | 409 `gone` | unchanged |
| result (CARLOS) | same outcome and acknowledgement again | 200 `recorded: false` | nothing written |
| result (CARLOS) | a different outcome for a finished message | 409 | conflict |
| result (CARLOS) | lease expired before the answer | 409 `lease_expired` | claimable again |

Concurrent **cancel and complete** are ordered by one row lock on the message: the first wins; the
other gets the 409 above.

## The objects

### The envelope (sealed; the portal never sees it)

Canonical JSON, **signed by the device's Ed25519 key** over `frame("mycarlos-send/1
envelope-signature", payload)`, then sealed (see "Sealing"). It holds everything personal.
**What is sealed.** The plaintext the content key seals is the ASCII compact signed form
`b64url(canonical payload).b64url(64-byte signature)`, unpadded (not the bare JSON); the sealed envelope is
that plus the 16-byte tag, so its smallest size is derived (`min_sealed_size` in the fixture), not a magic
number. The end-to-end vector includes the compact form with a FAKE signature of the right length.
**Budget:** the sealed envelope is at most **256 KiB**. That is sized for the worst case the contract
allows: ten clinic-signed copies, each carrying a manifest of up to 16 KiB (about 21 KiB as text), plus
the text and names, with room to spare; a parser refuses a manifest over 16 KiB and an envelope over the
budget. The fixture pins the **worst case** (ten 16 KiB manifests, a body of 8,192 escaped bytes, 120
escaped bytes of name each): 250,878 bytes sealed, about **11 KB of headroom**, accepted by the checker.

| Field | Meaning |
|---|---|
| `v`, `typ` | `1`, `"mycarlos-send-envelope"` |
| `message_id`, `conversation_id` | UUIDs (see above) |
| `in_reply_to` | `null` (reserved) |
| `clinic_id`, `recipient_id`, `device_key_id` | the link's own; both the portal and CARLOS check them. Each is 1 to 128 characters of `A-Za-z0-9_.:-` (every id field in this contract is type-checked the same way) |
| `created_at`, `expires_at` | Unix seconds; `expires_at` at most 7 days after `created_at` |
| `body` | plain text, UTF-8, **at most 8,192 bytes**, under the text rules above. May be empty only if there is an attachment |
| `attachments` | at most **10** |

**No sender name, date of birth or health card number is carried.** Who the patient is comes from the
link's binding in CARLOS (`recipient_id` to the chart) and the device's signature, never from text the
message says about itself.

**Attachment descriptor:** `attachment_id`, `name` (display only: 1 to 120 characters under the text
rules; never a path: no `/`, `\`, `:` or NUL, not `.` or `..`), `media_type` (from the allow-list), `size`
(plaintext bytes), `sha256` (of the plaintext), `chunk_size` (always 4 MiB), `chunk_count` (must equal
`ceil(size / chunk_size)`), `chain_head` (see "The hash chain"), and `provenance`:
- `{"kind": "patient-original"}`: a file the patient added;
- `{"kind": "clinic-signed-copy", "delivery_id": …, "manifest": "<the clinic's own compact manifest,
  unchanged, at most 16 KiB>"}`: a document the clinic delivered, sent back as the **original signed
  bytes**, so the clinic can check its own signature. It must be a PDF. The sender cannot re-sign it.

**Provenance is a claim the receiver re-checks.** For a `clinic-signed-copy` CARLOS verifies, from the
bytes alone, its own signature and manifest and that the `delivery_id` and document hash are ones it sent
**to this recipient**, and stores the result as data (`matches_sent_document`,
`signature_valid_but_unknown_document`, `signature_invalid`, `not_signed`). A "Verified" label is never
copied across, and a patient upload never becomes a clinic-authored record: it stays "patient-submitted"
in every store.

### The outer record (visible to the portal)

The body of `POST /sends`, canonical JSON, at most 16 KiB; the device assertion's `request_hash` covers
it. It names sizes, hashes and random ids and **nothing personal**:

`v`, `typ: "mycarlos-send-outer"`, `message_id`, `recipient_id`, `device_key_id`, `clinic_id`,
`created_at`, `expires_at`, `kind` (`message` means no attachments, `documents` otherwise),
`attachment_count`, `attachments` (each: `index`, **`attachment_id`**, `chunk_count`, `size` of the sealed
bytes, `chain_head`), `envelope_size`, `envelope_sha256` (of the sealed envelope), `chunk_total`,
`total_size`, `chain_head` (of the message), `sealed_key` and `sealed_key_kid`.

`sealed_key` is `b64url(enc || ciphertext)` of the HPKE seal of the 32-byte content key, **exactly 80
bytes** (32 for the encapsulated key, 32 for the key, 16 for the tag), unpadded.

**The portal checks:** the assertion; the ids against the device; the version; the clock (`created_at`
not more than 300 s ahead, `expires_at` not past); that every attachment's sealed size fits its chunk
count (every chunk but the last is full); that the totals add up; the sizes against the capabilities and
quotas; and, at `complete`, that the parts it holds chain to the heads in the record. It cannot check
anything inside. **What it learns, stated honestly:** that a message exists, when, for which device,
recipient and clinic, how many attachments and each one's size and chunk count (not name or type), the
total size, when each part arrived, and the states. Padding the sealed envelope and the last chunk to
size buckets would hide the sizes; it is **not in v1** and is a named residual.

### The acknowledgement (signed by the clinic)

Canonical JSON signed with a clinic signing key (ES256) over `frame("mycarlos-send/1 ack-signature",
payload)`, at most 4 KiB: `v`, `typ: "mycarlos-send-ack"`, `message_id`, `clinic_id`, `recipient_id`,
`device_key_id`, `chain_head` (of the message it is about), `state`, `reason`, `ref`, `at` and `kid`.

- `state` is `collected`, `filed`, `refused`, `recalled` or `recall_refused`. `reason` is `null` except
  for `refused` (one reason from the fixed list below, including `key_revoked`) and `recall_refused` (`recall_too_late` or
  `recall_unknown_message`).
- `ref` is **22 characters of `A-Za-z0-9_-`: a random 128-bit handle**, never derived from a chart,
  message or patient id (it is shown to nobody and means nothing to the app).

ES256 signatures are randomised, so CARLOS **stores** the acknowledgement it signed and re-issues those
exact bytes on a repeat; it never re-signs. The app verifies it against the link's **pinned** clinic keys. It accepts only the transitions in the
state table; an acknowledgement it cannot verify, or whose `chain_head` is not its message's, is shown as
**unverified** and never as success.

### The recall request (signed by the device)

Canonical JSON signed by the device Ed25519 key over `frame("mycarlos-send/1 recall-signature",
payload)`, at most 1 KiB: `v`, `typ: "mycarlos-send-recall"`, `message_id`, `chain_head`, `clinic_id`,
`recipient_id`, `device_key_id`, `at`. See "Recall".

## Sealing

One 32-byte **content key** per message, random, **in memory only**. It is sealed to the clinic inbox key
with HPKE (base mode; X25519-HKDF-SHA256, HKDF-SHA256, ChaCha20-Poly1305; info
`"carlos-emr/mycarlos-send/v1"`) with the AAD `key_aad` in the fixture (ids and the sealed envelope's
hash). The envelope and every chunk are sealed with ChaCha20-Poly1305 under the content key:

- **nonce** (12 bytes): the attachment's position as 4 bytes (`0xFFFFFFFF` for the envelope), then the
  chunk's index as 8 bytes;
- **AAD:** the framed values in the fixture (`envelope_aad`, `chunk_aad`): they bind the message, the
  attachment, the chunk index and count, and the ids. A chunk moved to another place or message fails to
  open.

**An interrupted send is not resumed across a restart.** The content key is never written to disk, and a
fixed nonce under a key must never meet two different plaintexts. So a restart, a lock or a crash ends the
send: the app cancels what the portal holds and the patient presses Send again as a **new `message_id`**
(a new content key); the sent record keeps the first as "not sent: interrupted". Within the same run of
the app, with the vault unlocked, a dropped connection resumes from `GET /sends/{message_id}` (which
lists each part and whether it is held, with its SHA-256) and re-sends the **same bytes** for any part.

**Chunks.** An attachment is split into plaintext chunks of at most 4 MiB (the last may be shorter), each
sealed separately plus a 16-byte tag; at most 128 per attachment.

## The hash chain

So that nothing can be dropped, repeated, reordered or borrowed from another message without detection:

- `chain_start = sha256(frame("mycarlos-send/1 chain-start", message_id, attachment_id, chunk_count))`
  (ids as 16 bytes, the count as 8);
- `link_i = sha256(frame("mycarlos-send/1 chain-link", link_{i-1}, i, sha256(sealed_chunk_i)))`, with
  `link_{-1} = chain_start`;
- an attachment's `chain_head` is the link after its last chunk;
- the message's `chain_head = sha256(frame("mycarlos-send/1 message", message_id,
  sha256(sealed_envelope), head_of_attachment_0, head_of_attachment_1, ...))`.

**Who checks what.** The portal recomputes every head from the ciphertext it holds (it can: the outer
record has the `attachment_id`s), which finds **corruption and loss**. It does **not** protect against the
portal: a dishonest portal can recompute any head. **The protective check is CARLOS's:** after opening, the
chain heads named inside the **signed envelope** must equal the heads it recomputes from what it fetched,
the outer record must describe the same message (`pair` cases in the fixture), and each attachment's
plaintext must match its `sha256` and `size`.

## Routes

All device routes use the existing **device assertion** (`X-MyCarlos-Device-Assertion`, `aud`
`carlos-patient-portal-device-api`, `request_hash` over method, path, query and the exact body; the `jti`
consumed before the operation, so a retry is re-signed). A failed assertion answers a generic 404; a
verified device that is refused gets 403 `device_removed` or `recipient_mismatch`. Every answer carries
`Cache-Control: no-store` and the error shape `{"code": ...}`; 429 adds `Retry-After`. Bodies are read
with the bounded reader.

| Method and path | Purpose | Answers |
|---|---|---|
| `GET /api/mycarlos/send-capabilities` | what the clinic can receive (below) | 200; 404 when not enabled |
| `POST /api/mycarlos/sends` | create: the outer record | 201, 200, 409, 410, 422 |
| `PUT /api/mycarlos/sends/{message_id}/envelope` | the sealed envelope | 200, 409, 413 |
| `PUT /api/mycarlos/sends/{message_id}/attachments/{a}/chunks/{n}` | one sealed chunk (`X-Chunk-SHA256`) | 200, 409, 413 |
| `GET /api/mycarlos/sends/{message_id}` | state, and each part held with its SHA-256 | 200; 404 |
| `POST /api/mycarlos/sends/{message_id}/complete` | verify and close the upload | 200; 409; 422 |
| `POST /api/mycarlos/sends/{message_id}/cancel` | cancel, **only before complete** | 200; 409 `use_recall` |
| `POST /api/mycarlos/sends/{message_id}/recall` | the device-signed recall (compact) | 200 `recall_requested`; 409 |
| `GET /api/mycarlos/sends` | list states (`?after&limit`, at most 50) | 200 |

**Capabilities:** `versions` (`["mycarlos-send/1"]`), `enabled`, `phase`, `max_attachment_bytes`,
`max_message_bytes`, `max_attachments`, `chunk_size`, `media_types`, `inbox_key_statement` (compact
signed), `retention_days`, `notice`. A client that finds no capabilities (404) or `enabled: false` does
not offer Send, and says why.

**Internal routes (CARLOS only; job `send-sync`; permissions `portal.mycarlos.send.claim`, `.read`,
`.result`)**, the sign-up claim and result pattern:

| Method and path | Purpose | Answers |
|---|---|---|
| `POST /internal/carlos/mycarlos/sends/claim` | `{"limit": 1..20}`: complete, unexpired messages not under a lease, `FOR UPDATE SKIP LOCKED`, oldest first; each with a 32-byte lease token (returned once, stored as its SHA-256), lease 300 s (30 to 3600) | 200 |
| `GET /internal/carlos/mycarlos/sends/{id}/envelope` | the sealed envelope, under the lease | 200 octet-stream; 404 |
| `GET /internal/carlos/mycarlos/sends/{id}/attachments/{a}/chunks/{n}` | one sealed chunk, under the lease | 200 octet-stream; 404 |
| `POST /internal/carlos/mycarlos/sends/recalls` | `{"limit"}`: pending recalls, each with its device-signed recall object | 200 |
| `POST /internal/carlos/mycarlos/sends/{id}/result` | `{lease_token or recall, outcome, ack}` | 200; 409; 404 |

An unknown id, another clinic's message and a wrong token are the same 404 (constant-time compare, done
even when no row exists). The portal stores and relays the acknowledgement; it deletes the parts on
`filed`, `refused`, `expired`, `cancelled` and after a recall. An unreadable message must not starve the
queue (it is leased to a back-off), refused results are audited, and nothing personal is logged.

## What each state means

The patient sees these words and **no others about delivery**. Never "read", "seen", "reviewed" or "sent
to a clinician". `by` says who can make the claim true: the app, the **portal** (an unsigned claim the
device cannot verify), or the **clinic's system** (signed, verified against the link's pinned keys).

| State | By | Means | Never means |
|---|---|---|---|
| `queued` | app | kept in the sent record; nothing has been sent yet | that anything left this device |
| `sending` | app | parts are being uploaded in this run of the app | that the portal has all of it |
| `received` | portal (claim) | the portal says it holds every part and the chain it can recompute matches | that the clinic has it; or that the portal's own check protects against the portal |
| `collected` | clinic (signed) | the clinic's system fetched, opened and checked it | filed, seen or read by anyone |
| `filed` | clinic (signed) | stored in the clinic's pending-review queue, **not yet in a chart** | that any staff member has read, reviewed or acted on it |
| `refused` | clinic (signed), or the portal (claim) before the clinic collected it | not accepted, for one fixed reason; nothing is kept | a judgement about the content |
| `expired` | portal (claim) or app, **only before** a signed `collected` | the time ran out before the clinic's system collected it | that it was delivered |
| `recalled` | clinic (signed) | removed from the pending queue before it was accepted into a chart | that nobody saw it |
| `cancelled` | app and portal, before `complete` | the upload was stopped and everything deleted | anything about a completed message |

Transitions: `queued` to `sending` or `cancelled`; `sending` to `received`, `cancelled`, `expired` or
`refused`; `received` to `collected`, `refused`, `expired` or `recalled`; `collected` to `filed`, `refused`
or `recalled`; `filed` to `recalled`; the rest are final. "Recall requested" is a mark on `received`,
`collected` or `filed`, not a state; a signed `recall_refused` clears it.

**After a signed `collected`, only the clinic's signed `filed`, `refused` or `recalled` ends the message.**
The portal's own unsigned `refused` or `expired` is then shown as "the portal says …" and changes
nothing; CARLOS enforces `expires_at` itself (a signed `refused` with reason `expired` when it is past
and the message is not filed). If the clinic never answers, the screen says so after `expires_at` plus a
grace period ("no answer from the clinic's system: ask the clinic") and never claims delivery.

**Refusal reasons (fixed list):** `unsupported_version`, `bad_signature`, `device_not_accepted`,
`clinic_mismatch`, `expired`, `too_large`, `type_not_allowed`, `active_content`, `scan_failed`,
`chain_mismatch`, `hash_mismatch`, `duplicate_message`, `owner_group_missing`, `not_enabled`.

**Required scanner and the scanner down (Q5):** the message is `collected` (signed) and **not filed**; it
stays `collected` until the scanner is back (then `filed`, or `refused` with `scan_failed`) or `expires_at`
passes (a signed `refused: expired`). The screen says "received by the clinic's system", not "filed".

## Recall (Q9): only before acceptance, by a signed request

The patient may ask for a message to be recalled while it is `received`, `collected` or `filed` (in the
pending queue). It is a **request**, said as one.

1. The app sends a **recall request signed by the device** (`message_id`, `chain_head`, `clinic_id`, the
   ids). The portal checks the device assertion and relays it (`recall_requested`); it cannot forge one.
2. CARLOS learns of it through the recalls route, **verifies the device signature against its
   accepted-device table and the `chain_head` against its own record**, and acts.
3. **Atomic rule:** the recall handling and "accept into a chart" take the same row lock on the inbound
   row; **the first wins** and the loser reads the other's result. CARLOS answers with a signed `recalled`
   (removed from the queue) or a signed `recall_refused` (`recall_too_late` when it is already in a chart,
   `recall_unknown_message` only for a message the clinic never held and the portal no longer holds).
4. After acceptance into a chart there is no recall: the screen says to contact the clinic.
5. **A recall that arrives before the clinic has claimed the message:** CARLOS stores the verified recall
   keyed by (device, `message_id`, `chain_head`), so a later claim of that message is answered with a
   signed `recalled` and nothing is filed; the portal also **withholds the message from claim while a
   recall is pending**. `recall_unknown_message` is never the answer for a message the portal still holds;
   it is only for a (device, `message_id`, `chain_head`) the clinic never held and the portal no longer holds.
6. **The recall must be about that message:** its `device_key_id`, `clinic_id`, `recipient_id`,
   `message_id` and `chain_head` must equal the message's (`recall_binding_cases`), else it is ignored.

## Limits and media types (defaults; a deployment advertises its own, never larger)

| | Phase 1 (database blobs) | Phase 2, video (object store) |
|---|---|---|
| Per attachment | 20 MiB | 512 MiB |
| Per message | 64 MiB | 1 GiB |
| Media types | `application/pdf`, `image/jpeg`, `image/png`, `image/heic` | those, plus `video/mp4`, `video/quicktime`, `video/webm` |

Hard ceilings the parser enforces whatever a deployment enables: 10 attachments, 8,192 bytes of text,
4 MiB chunks, 128 chunks per attachment, 7 days, a 256 KiB sealed envelope, a 16 KiB manifest, a 16 KiB
outer record, a 4 KiB acknowledgement, a 1 KiB recall and a 2 KiB inbox key statement. Quota defaults the
portal should enforce (proposed): waiting bytes per device 2 GiB, per account 4 GiB, per clinic 50 GiB;
waiting messages per device 20, per account 50, per clinic 5,000; upload 64 chunks a minute per device;
breaching one is 429 `quota_exceeded` with `Retry-After`. **Phase 2 is not available on database blobs**
(Q6): the capabilities stay `phase1` until an object store is configured.

Types are checked **by content** (magic bytes) on the sending side and again on the CARLOS side, which is
the check that counts. Never allowed: executables, scripts, archives, Office documents with macros. CARLOS
refuses PDFs with launch or script actions or sanitizes them by policy (`active_content`).

## CARLOS: where it lands, who may act, what is recorded

- **Adapter:** the job `send-sync` (its own key and permissions), polled about every 30 to 60 s. It
  fetches parts to a temporary file confined by `PathValidationUtils`, decrypts chunk by chunk, and
  verifies in this order: the sealing key is one it holds; the signature of the envelope against the
  accepted-device table (a pending, removed or unknown device is refused, which also closes the portal's
  gap that it cannot know whether CARLOS approved a device); the ids; the clock; not already seen
  (the (device, `message_id`, `chain_head`) rule above); the chain heads in the signed envelope against
  what it recomputes; sizes and hashes; types by content; active content; the scanner (Q5); and, for a
  `clinic-signed-copy`, the provenance check.
- **Where it lands:** a message becomes a Messenger message **from the patient** to the owner group,
  linked to the bound chart, marked "patient message via myCarlos, content not verified by the clinic". A
  document lands in a dedicated incoming queue as a document for the bound patient with status
  **pending**, routed to the owner group, and goes into the chart only by an explicit staff action that
  re-checks access. `Document.source` is `mycarlos-patient`; the provenance result is a visible line on
  the inbox row and in the chart.
- **Wrong patient:** the chart is the **binding's** (`recipient_id` to the chart, set when the device was
  accepted), never a name the message says. Staff see the name from their own chart.
- **Authorization and audit:** a new security object (`_mycarlos_inbox`, read to see the queue, write to
  accept or reject, administrator by default) plus the existing patient-access checks. `LogAction` for
  collected, filed, accepted into a chart, rejected and recalled (the job as the system provider; staff as
  themselves). No message text in any log.
- **Owner group and notices (Q2):** the adapter does not start until an owner group is named. CARLOS
  shows the count and age of unreviewed messages. The patient-facing notice is standing text: "This is not
  an emergency line. Staff may not read this for some time." (the wording needs a clinical-safety review);
  **no response time is promised anywhere**.

## myCarlos: the sent record and what it shows

- **A durable, encrypted sent record** (a new manifest field and history events, with its own vault
  format number taken at merge): `message_id`, `conversation_id`, link, person, times, state, the patient's
  own text, the attachment **descriptors** (and, for vault files, the record id; **Q3**: a descriptor only
  for any other file), the acknowledgements as received (kept as proof), a refusal reason and attempts.
  History events carry ids and states, never text or names. Older builds refuse the new format. Bounded
  (about 200 messages, pruned oldest-final-first with a visible note).
- **Review before Send:** the recipient, the person, the text, and every attachment with its name, type,
  size and provenance line. Send is explicit; there is no background send and no "always send".
- **Retries:** within a run, resume as above; across a restart, a new message. Cancel before `complete`
  deletes everything; after it, a signed recall request.
- **Desktop only in v1 (Q1).**

## Retention, deletion, revocation

- **Portal:** ciphertext for at most 7 days; deleted on `filed`, `refused`, `expired`, `cancelled` and
  after a recall; tombstones (no content) to the audit horizon. A removed device stops all uploads at once
  (403); its waiting messages are not collected.
- **myCarlos:** the sent record follows the vault's rules (hiding keeps; no permanent delete; older
  backups keep it). The patient is told at Review that a filed message cannot be unsent once accepted into
  a chart.
- **CARLOS:** a filed message is a clinical record under the clinic's retention duty; deleting it is a
  clinic process, not a button in the app.
- **Link removed or clinic key changed:** a queued message for a removed link is refused locally and kept
  as "not sent: link removed". A clinic signing-key rotation affects verifying acknowledgements and inbox
  key statements (a signer not reachable from the link's pinned set means unverified, so the app does not
  send).

## Threat model additions

| # | Threat | Mitigation | Proved by |
|---|---|---|---|
| S-01 | Flooding the portal | quotas, per-minute caps, 7-day expiry, hard clinic ceiling, 429 | quota and rate tests |
| S-02 | Malicious file reaches staff | content allow-list both ends, no active content, size ceilings, scanner hook (required fails closed) | hostile fixtures |
| S-03 | Wrong patient | binding only; accepted device; signature; staff see their own chart's name | cross-patient, removed-device, pending-device cases |
| S-04 | Forged or replayed message | device signature over a domain-separated, canonical payload; unique ids; consumed `jti`; expiry | replay and tamper tests; `compact_cases` |
| S-05 | The portal reads or changes content | sealed to an inbox key the clinic signed for; AAD-bound ids; chain heads inside the signed envelope | the chain and pair cases |
| S-06 | The portal says "filed" when it was not | only a clinic-signed acknowledgement counts; portal claims are labelled | forged-acknowledgement tests |
| S-07 | A patient upload treated as clinic-authored or "verified" | provenance kinds re-verified from bytes, stored as a check result | altered-document and other-patient cases |
| S-08 | Duplicates | client ids, per-device scope, unique rows, CARLOS keyed on (device, message_id, chain_head) | duplicate-retry, kill-mid-upload, lost-acknowledgement tests |
| S-09 | Urgent matters sent to a queue nobody watches | standing notice; refuses to enable without an owner group; unreviewed count and age | the enable refusal |
| S-10 | Personal text in logs or errors | route templates only; generic errors; no body in telemetry | log-content tests |
| S-11 | Key compromise or rotation | signed inbox key statements with serial, validity and revocation; per-link device keys | `inbox_key_cases` |
| S-12 | Hostile text | the text rules; plain text only; never rendered as markup | `text_cases` |
| S-13 | Recall used to alter a chart, or forged | device-signed recall; verified by CARLOS; one lock, first wins; never after a chart | recall cases and the race test |
| S-14 | **Key substitution by the portal** | the inbox key is named only by a signed statement checked against the pinned clinic keys | `inbox_key_cases`; a test with a forged statement |
| S-15 | **Nonce reuse after a crash** | the content key is never persisted; a restart is a new message and a new key | the interrupted-send rule |
| S-16 | **Existence oracle across devices** | ids scoped to the device; the same 404 for another's or none | the idempotency rows |
| S-18 | **Inbox-key rollback or replay** | per-link high-water serial, equal-serial revoked wins, 30-day statements, `key_revoked` refusal | `inbox_key_cases` |
| S-19 | **Recall that lands before the claim, or about another message** | stored recall keyed by (device, message_id, chain_head), portal withholds from claim, binding check | `recall_binding_cases` |
| S-17 | **A dishonest portal lowers limits or hides the feature** | a denial of service only; capabilities carry no key and no secret | stated residual |

## Conformance

A component is conformant when it passes the fixture: the chain vectors (including those that must
differ), the nonce and AAD bytes, the signing inputs, the canonical and compact payload cases, the one
**end-to-end consistent message** (the outer record, the envelope and the chunk hashes agree with each
other), the accept and refuse lists for the outer record, envelope, pair, acknowledgement, recall and
inbox key statement, the clock and text cases, the state transitions, the idempotency table and the route
list. A **second test adapter** (a minimal gateway with different limits and no `phase2_video`) runs the
same lists, so "wrong clinic, revoked link, altered document, unsupported gateway, interruption,
duplicate retry" are exercised against more than one implementation. The fixture contains no keys,
signatures or randomness; the signature and HPKE checks are done by the implementations' own tests with
FAKE keys.

## Not in this contract

- **Replies** (Q11), **phones** (Q1), **dependents and guardians** (Q8).
- **Size bucketing** of sealed parts (stated residual above).
- **Anything in CARLOS beyond the adapter's contract**: the chart screens and the queue wording.
- **Server code, schema and migrations**: after Ben approves this.

## Rollout (proposed, after approval)

`P1` portal device routes, tables, quotas (PostgreSQL grants and the nginx limits are `deploy/` changes for
Ben to queue); `P2` the internal claim, read, recalls and result routes and the `send-sync` job; `C1` the
inbox key, its signed statement, the job and flags in CARLOS; `C2` the adapter with a fake portal; `C3` the
filing, the queue, the security object, the audit and the recall handling; `C4` operator documentation;
`M1` the types, sealing, chunking, the sent record and a fake gateway in myCarlos; `M2` the upload client,
outbox, recall and acknowledgement and statement checks; `M3` the screens in seven languages; `M4` the
second adapter and the interoperability tests. Contract first; the three repositories test against one
fixture.
