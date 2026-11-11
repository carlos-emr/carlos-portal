# Send to myCarlos: delivery format and contract (v1)

**Status:** draft for review (milestone M0). Nothing is built yet. Every part ships behind
off-by-default switches.
**Applies to:** carlos-portal (the mailbox), carlos (the sender), mycarlos (the receiver)
**Tracking:** [carlos-portal#41](https://github.com/carlos-emr/carlos-portal/issues/41). Related:
the clinic signing key in [carlos#4691](https://github.com/carlos-emr/carlos/issues/4691), and
signed-document checks and linking in
[mycarlos#55](https://github.com/carlos-emr/mycarlos/issues/55).
**Shared vectors:** [`tests/fixtures/delivery-contract.json`](../../tests/fixtures/delivery-contract.json),
made by [`tests/delivery_contract_reference.py`](../../tests/delivery_contract_reference.py).
**Written:** 2026-10-21

This document is the single source for the format. CARLOS and myCarlos link here and carry a
byte-identical copy of the fixture. A change lands here first, then gets copied.

The versioned protocol supports independently configured producer adapters. See
[producer interoperability](producer-interoperability.md) for signing/encryption roles and
requirements for other EMRs, and [link lifecycle v1](mycarlos-link-lifecycle-v1.md) for the additive
key-refresh/recovery contract. Existing CARLOS-named wire identifiers remain exact compatibility
constants; they do not impose an application-brand allowlist.

## What it does

Staff press "Send to myCarlos" in CARLOS. CARLOS signs the document and a small manifest with the
clinic key, then seals one copy to each of the patient's accepted devices. The portal stores
each sealed copy. It can't open them. The patient's myCarlos picks up its copy, checks it, files
it in the vault as "From <clinic> · Verified", and only then sends a receipt signed by the device.
The portal hard-deletes the copy and passes the receipt on to CARLOS. Copies nobody picks up are
deleted after 7 days, and CARLOS shows staff "not picked up".

Anything email can send today can be sent this way. CARLOS already renders every attachment
(eDocs, eForms, forms, labs and HRM reports) to PDF for email. A send with several documents
makes one delivery per document, each with its own delivery ID.

**Off switches:**
- **portal:** `PATIENT_PORTAL_MYCARLOS_DELIVERY_ENABLED=false`. While it's off, none of the routes
  below are registered, so they answer 404.
- **CARLOS:** `patient_portal.mycarlos_delivery.enabled=false`.
- **myCarlos:** a hidden Settings item.

Every switch stays off until the whole flow works end to end.

## Keys

| Key | Held by | Used for |
|---|---|---|
| Clinic signing key, ECDSA P-256 ([carlos#4691](https://github.com/carlos-emr/carlos/issues/4691)) | CARLOS, encrypted at rest | The PDF's own PAdES signature, and the delivery manifest |
| Device encryption key, X25519 | myCarlos, inside the vault | Opening copies sealed to that device |
| Device signing key, Ed25519 | myCarlos, inside the vault | Device requests to the portal, and pickup receipts |
| Waiting key, Ed25519 ([carlos-portal#87](https://github.com/carlos-emr/carlos-portal/issues/87)) | myCarlos, outside the vault, in the OS-protected store | Only the "anything waiting?" check while the vault is locked (below) |
| Portal TLS and server keys | Portal | Transport only. Never a document key. |

**Device keys are per link.** myCarlos makes a fresh X25519 and Ed25519 pair for each portal link
and keeps it in the vault with that link.
- **`device_key_id`:** the key ID of this device's link. Keys are never shared across the
  patient's devices, or across links. So two portals never see the same ID, and a link can be
  removed without touching any other.
- **`recipient_id`:** per patient account, shared by all of that patient's devices.

myCarlos pins the clinic's public keys when it links (below). Key changes follow
[mycarlos#55](https://github.com/carlos-emr/mycarlos/issues/55): a replacement signed by the
current key is accepted, and a revoked key stops verifying.

## Encoding rules

- **b64url:** base64url ([RFC 4648 §5](https://www.rfc-editor.org/rfc/rfc4648#section-5)) with no
  padding, in its canonical form only. A value that doesn't re-encode to the same text is refused.
- **frame(a, b, …):** each part is preceded by its length as 8 bytes, big-endian. No two
  different part lists can give the same bytes. This is the same framing the portal already
  uses for its staff and job request hash (`staff_request_hash`).
- **Duplicate members:** every JSON object in the contract refuses a member name that appears
  twice. That covers the manifest, device and link assertions, link request bodies and receipts.
  A parser that silently keeps the first or the last value doesn't meet the contract. The
  refusal codes are `bad_manifest`, `invalid_assertion` and `invalid_receipt`, and the vectors
  cover each one.
- **JSON:** UTF-8. Signers produce
  [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JCS) form; the claims use only strings,
  integers and objects. Verifiers check the bytes as received and never re-serialize them.
- **Compact signed object:** `b64url(payload) "." b64url(signature)`. The payload is the JSON
  claims.
- **Times:** integer Unix seconds.
- **Hashes:** SHA-256. Content hashes (ciphertext, document, request, vault head) are lowercase
  hex; key IDs are b64url (below).

## Identifiers

| Identifier | Made by | Form |
|---|---|---|
| `delivery_id` | CARLOS, per document sent | UUID v4, canonical lowercase. One delivery ID covers every device's copy of that document. |
| `recipient_id` | Portal, per patient account (clinic ID and demographic number) | Opaque, 128-bit random, as b64url (1–64 characters from `A-Z a-z 0-9 _ -`). The same for all of that patient's devices. Never derived from the health card number. CARLOS gets it from the patient's portal link; myCarlos gets it when it links. |
| `device_key_id` | Anyone, from the public keys of one device's link | `b64url(SHA-256("mycarlos-device-key-v1" ‖ frame(X25519 public key, Ed25519 public key)))`, 43 characters |
| `kid` (clinic key) | Anyone, from the clinic public key | `b64url(SHA-256(SubjectPublicKeyInfo DER))` |

## The package

### 1. The manifest, signed by the clinic

A compact signed object. The signature is **ES256**: ECDSA P-256 with SHA-256, as 64 bytes
`r ‖ s`, not DER. Deterministic signing ([RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)) is
recommended, so a sender's test can match the fixture byte for byte. Receivers accept any valid
signature.

The manifest has exactly these claims, no more and no fewer:

| Claim | Value |
|---|---|
| `v` | `1` |
| `typ` | `"mycarlos-delivery-manifest"` |
| `delivery_id`, `recipient_id`, `device_key_id` | As above. They must equal the outer record's values. |
| `clinic_id`, `clinic_name` | The sending clinic |
| `provider_name` | The provider the document is from |
| `patient` | `{"name", "birth_date"}` as on the chart (birth date `YYYY-MM-DD`). Used to file the document under the right person (decision M). |
| `document` | `{"title", "type", "service_date", "media_type", "size", "sha256"}`. `media_type` is `application/pdf` in v1. `type` is a short hint such as `lab_report`, `imaging_report`, `letter` or `other`; receivers treat an unknown value as `other`. `size` and `sha256` cover the exact PDF bytes. |
| `created_at`, `expires_at` | `expires_at` is at most 7 days after `created_at` (decision C) |
| `kid` | The clinic key that signed it |

The PDF keeps its own PAdES signature (carlos#4691), so it stays verifiable after it leaves the
vault. The manifest signature also covers the PDF, through `document.sha256`.

The PDF also carries CARLOS's embedded document manifest, `carlos-document-manifest.json`. It is
added in the same update as that PAdES signature, so the signature covers it. It names the
issuing clinic and the patient, and gives the document a stable ID and version, so the PDF still
says what it is once it leaves the vault. A receiver reads it only after the PDF signature checks
out. Its field names match this manifest's where the two overlap. Its format is set in CARLOS
(`DocumentManifest`, carlos#4691), not here.

The PAdES signature also binds the embedded manifest directly, so the binding holds even in a
password-protected email copy, where the embedded file is encrypted and can't be found as is in the
signed bytes:
- **The attribute:** one CMS signed attribute, `id-aa-carlos-documentManifestSha256`, OID
  `2.25.132515939282652475535231260060469025505` (under the UUID arc of ITU-T X.667, which needs
  no registration).
- **Its value:** exactly one OCTET STRING of exactly 32 bytes, the SHA-256 of the embedded file's
  exact bytes, after its stream filters and the PDF's own encryption are removed. These are the
  bytes CARLOS wrote.
- **The receiver:** compares the SHA-256 of the manifest it read with that value. More than one
  such attribute or value, or a value that isn't 32 bytes long, is refused. So is a PDF that has
  an embedded manifest but no such attribute: every CARLOS signature over a manifest carries one,
  so its absence means the manifest isn't bound, and the document isn't Verified.
- **Uncompressed:** in a copy without a password, CARLOS also stores the embedded file
  uncompressed, so it appears verbatim, exactly once, inside the signed byte ranges.

`document.service_date` is a required JSON string: a valid Gregorian date in `YYYY-MM-DD` form,
or `""` when the service date was not recorded. Receivers display the latter as "Date not recorded".
For an unknown date, a new CARLOS embedded PDF manifest uses JSON `null`; a legacy PDF's `""` is
also accepted, and either matches only `""` in the delivery manifest. For a known date, both
manifests must contain the same valid date string. Missing date members, JSON `null` in the
delivery manifest, invalid nonempty dates and known/unknown mismatches are refused. Senders must
not substitute an upload or creation date. These representations retain the existing signature,
exact PDF hash, clinic, recipient and embedded document-manifest checks.

### 2. The sealed plaintext

```
frame("mycarlos-delivery/1", manifest, pdf)            # 3 parts
frame("mycarlos-delivery/1", manifest, pdf, padding)   # or 4
```

- **`manifest`:** the compact object's ASCII bytes.
- **`padding`:** optional. It is reserved so copies can later be padded to hide their size
  without a version change. Receivers ignore its content. v1 senders don't send it.
- **Other part counts:** any other count is `bad_package`. A first part that starts with
  `mycarlos-delivery/` but names another version is `unsupported_version`.

### 3. The seal

**HPKE** ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)), base mode, one message (sequence
0):

| Setting | Value |
|---|---|
| KEM | DHKEM(X25519, HKDF-SHA256), `0x0020` |
| KDF | HKDF-SHA256, `0x0001` |
| AEAD | ChaCha20-Poly1305, `0x0003` |
| Recipient key | The device's X25519 public key |
| `info` | `carlos-emr/mycarlos-delivery/v1` |
| AAD | `frame(delivery_id, recipient_id, device_key_id)`, each as UTF-8 |

**The sealed copy** is `enc (32 bytes) ‖ ciphertext (16-byte tag included)`.

**Ephemeral keys:** every copy uses a fresh random ephemeral key. The fixture fixes the
ephemeral key only so its vectors can be reproduced.

**Sign, then encrypt:** the clinic signature is inside the seal, so the portal can't see who
signed what.

The AAD binds the routing IDs into the seal. The portal therefore can't re-target a copy to
another device or patient, or replay it under another delivery ID: the seal won't open, or the
signed IDs won't match.

### 4. The outer record

This is what the portal stores next to the sealed copy. It is not signed. Its fields:
- `v` (`1`)
- `suite` (`{"kem_id": 32, "kdf_id": 1, "aead_id": 3}`)
- `delivery_id`, `recipient_id`, `device_key_id`
- `size` (bytes of the sealed copy)
- `ciphertext_sha256`
- `created_at`, `expires_at`

The portal never receives or stores a title, a name or any document content.

### Limits

- **Size:** a sealed copy is at most **20 MiB** (20,971,520 bytes). CARLOS's email limit
  (`SMTPEmailSender.MAX_PREPARED_MESSAGE_BYTES`) is 50 MiB, and the smaller limit applies. CARLOS
  refuses to build a larger copy, and staff send that document another way.
- **Lifetime:** at most 7 days from `created_at` to `expires_at`.
- **Quotas:** per-clinic and per-patient quotas and rates are milestone M4 detail.

**Not in v1:** transparency-log inclusion proofs
([carlos-portal#37](https://github.com/carlos-emr/carlos-portal/issues/37), decision H). They
would come as format version 2.

## Opening a package (myCarlos)

myCarlos checks each downloaded copy in this order, and stops at the first failure. Each check
names the code the vectors expect.

1. The outer record's `v` and `suite` are the ones above. Else `unsupported_version`.
2. The size and SHA-256 of the downloaded bytes match the outer record. Else `hash_mismatch`.
3. The outer `recipient_id` and `device_key_id` are this link's (the copy was fetched through
   this link). Else `wrong_recipient` or `wrong_device`. Nothing is decrypted for someone else.
4. Open the seal with this link's X25519 key and the AAD built from the outer record. Else
   `decrypt_failed`.
5. Split the plaintext. Else `bad_package` (or `unsupported_version`, as in "The sealed plaintext"
   above). Parse the manifest. If it isn't a compact object with exactly the claims listed, of
   the types listed, with `v` 1, the right `typ` and a PDF `media_type`: `bad_manifest`.
6. Look up `kid` in **this link's** pinned key list:
   - not there, but pinned on another of the device's links: `wrong_clinic`;
   - not pinned anywhere: `unknown_clinic_key`;
   - revoked: `revoked_clinic_key`.

   Then, if the manifest's `clinic_id` isn't this link's clinic: `wrong_clinic`.
7. Verify the ES256 signature over the payload bytes. Else `bad_signature`.
8. The signed `delivery_id`, `recipient_id` and `device_key_id` equal the outer record's. Else
   `id_mismatch`.
9. The PDF's size and SHA-256 match `document`. Else `document_hash_mismatch`.
10. **Expiry, with clock skew:** refuse as `expired` only when
    `now > expires_at + 86400` (24 hours). A wrong device clock must never lose a document the
    portal still serves; replays are stopped by step 11, not by expiry.
11. **Already seen:** if this `delivery_id` was filed before:
    - **same copy** (`ciphertext_sha256` equals the one recorded when it was filed): the outcome
      is `already_filed`. The receipt was lost after filing, so send the kept receipt again
      (below) and file nothing.
    - **different copy:** `replayed`.

    Otherwise the outcome is `file`.

**After `file`:**
1. Write the document to the vault and wait until the write is durable.
2. Record the delivery in the vault history, with the delivery ID and ciphertext hash.
3. Sign the receipt and keep it in the vault with the filed delivery. It is kept outside the
   history chain, because the receipt carries an anchor of the chain's head.
4. Only then send the receipt.

A crash before step 3 means the copy is simply downloaded and filed again next time. A crash after
it ends in `already_filed`.

**Re-sending a receipt:** a re-sent receipt is always the kept one, byte for byte, with the same
`jti`; it is never re-signed.
- **When:** myCarlos re-sends it after a lost response, after a crash, or on `already_filed`.
- **Until:** the portal answers 200, or `delivery_not_found`. Either answer means done: the portal
  has the receipt, or no longer has the copy.

**A refused copy:** it is not filed, and no receipt is sent. The patient sees a plain message.
The copy expires on the portal, and CARLOS shows "not picked up".

## Reading aids: a paired second delivery

A **reading aid** is the AI-generated summary of one document that a clinician reviewed and
affirmed in CARLOS (carlos#5537; the review and approval are carlos#5585 and carlos#5634). It is
delivered as a **second copy** of its own, bound to the original it reads. The v1 original format
above does not change: a v1 copy is still one PDF, and a device that knows only v1 never files an
aid. This section is the contract for milestones P1 to P7 of the delivery plan; the vectors are in
`tests/fixtures/reading-aid-pair-contract.json` (reference and generator:
`tests/reading_aid_pair_reference.py`).

### The rules in one place

- **Two copies, one pair.** The original is sent exactly as in v1, byte for byte. The aid is a
  second delivery with its own `delivery_id` and its own sealed copy, carrying a `pair` that
  names the original's `delivery_id` and the SHA-256 of the exact PDF it reads. The `pair_id` in
  it is CARLOS's bookkeeping (its outbox holds the same id on both rows); the original's copy
  carries none, so a receiver records `pair_id` but cannot verify it. The binding a receiver
  checks is the original's delivery ID, PDF hash and lifetime. Delivery IDs form one space:
  an aid never reuses an original's, or the other way round.
- **The original is never held back by the aid.** CARLOS stages, sends and retries the two copies
  on their own: a lost response re-sends that copy's exact retained bytes, and a failure part-way
  leaves the original on its way and the aid to follow. The device files the aid when its original
  is present, whichever arrives first ("waiting_for_original" below). An aid is never re-signed:
  if the original changes after approval, CARLOS fences the aid (and the device would refuse it as
  `pair_mismatch`), and a new review is needed (maintainer answer 1).
- **Approved means exact.** An aid is staged only when a persisted clinician approval names the
  exact original (`original_document_sha256`) and the exact summary (`summary_version`) being sent
  (maintainer answer 2). The approval record is referenced by an opaque `approval.id`, not derived from
  the reviewer's provider number or name; the `approval` claim carries a role, never a name.
  (`provider_name`, copied from the original's manifest, is the document's provider, who is often
  the reviewing clinician too: the "no reviewer name" promise is about the approval claim.)
- **Original plus aid by default.** When an approved summary exists for the exact original being
  sent, the send includes the aid unless the sending staff member ticks "leave the reading aid
  out". When the aid cannot be staged (no matching approval, a limit), the original is sent alone
  and the status says so (maintainer answer 3).
- **Signed JSON for now.** The aid is canonical JSON (RFC 8785) that the clinic key signs through
  the manifest; a PDF rendering may come later as a new `media_type`, not a change to this one
  (maintainer answer 4).
- **Reading aids are part of the myCarlos baseline** (maintainer answer 6): there is no production
  use of myCarlos yet, so no device without reading-aid support has to be served. The `kind` and
  `accept` handshake below is kept only as a format-version guard, not as an old-device rule.
- **Never shown alone.** A device shows an aid only from the original it reads, under the notice,
  and never files one whose original it does not hold (see "Showing a reading aid").

### Who receives a reading aid

The portal cannot see what a copy holds, so the kind of a copy is written on its outer record:
- The aid's **outer record** has every v1 field plus `kind`: `"reading-aid/1"`. An original has no
  `kind`. On upload the portal accepts `kind` only as printable ASCII of at most 64 characters
  matching `name/version` (`[a-z0-9-]+/[0-9]+`), else `invalid_delivery`; it stores and echoes
  it unchanged and never interprets it.
- A pickup (`GET /api/mycarlos/deliveries`) declares the kinds the device implements, `accept`,
  as a repeated query parameter (`?accept=reading-aid/1`); every myCarlos build names
  `reading-aid/1`. The portal serves a copy with a `kind` only to a pickup that accepts that kind,
  and serves a copy without a `kind` to every pickup. This is a format-version guard, so that a
  later `reading-aid/2` reaches only devices that implement it; it is not an old-device rule, and
  CARLOS stages an aid for every link. The portal stores and echoes `accept` values, so it bounds
  them: at most 8 per pickup, each a valid kind as above, no duplicates, else `invalid_request`.
  A listing may also show a copy's `size`, and a device may refuse a reading aid above its 1 MiB
  limit as `too_large` from the listing, before any download.
- A copy with a `kind` the portal has never seen is still stored and served to pickups that name
  it; the portal does not interpret kinds.

The vectors `portal.serve` fix the serve rule.

### The aid's manifest

A compact ES256 object, signed by the clinic key exactly as the original's manifest, with exactly
these claims:

| Claim | Value |
|---|---|
| `v` | `1` |
| `typ` | `"mycarlos-reading-aid-manifest"` |
| `delivery_id`, `recipient_id`, `device_key_id` | As for an original. They equal the outer record's. `delivery_id` is the aid's own and differs from the original's. |
| `clinic_id`, `clinic_name`, `provider_name`, `patient` | Copied from the original's manifest |
| `pair` | `{"pair_id", "original_delivery_id", "original_document_sha256"}`. `pair_id` is a UUID v4 shared by the two copies; `original_delivery_id` is the original's; `original_document_sha256` equals the original manifest's `document.sha256`. |
| `reading_aid` | `{"media_type", "size", "sha256", "language", "summary_version", "generated_at", "revised_at", "notice_version"}`. `media_type` is `application/vnd.carlos.reading-aid+json`; `size` and `sha256` cover the exact JSON bytes; `language` is a BCP 47 tag and equals the JSON's; `summary_version` is CARLOS's 64-hex fingerprint of the exact approved content; `generated_at` and `revised_at` (or `null`) are when the model draft was made and last corrected; `notice_version` names the patient notice carried in the JSON, `<scheme>-<language>-<n>` matched by shape (`[a-z0-9-]+-[a-z]{2,3}(-[A-Z]{2})?-[0-9]+`: a lower-case primary subtag, then an upper-case two-letter region when the notice is for a region; `carlos-5537-en-1`, `-fr-1`, `-es-1`, `-pl-1` and `carlos-5537-pt-BR-1` today), and its language tag (the primary subtag, before any region) must equal `language`'s primary subtag. A lower-case region is not a region: `carlos-5537-pt-br-1` parses as scheme `carlos-5537-pt` and tag `br`, which does not equal the primary subtag `pt` of an aid in `pt-BR`, so it is `bad_manifest`. |
| `approval` | `{"id", "reviewer_role", "reviewed_at"}`. `id` is opaque (CARLOS's persisted approval record), never derived from the reviewer's provider number or name; `reviewer_role` is one of a closed set, today only `clinician`. |
| `created_at`, `expires_at` | The original's values: a pair shares one lifetime |
| `kid` | The clinic key that signed it |

Any other claim, a missing claim, a `pair.original_delivery_id` equal to the aid's own
`delivery_id`, a `reviewer_role` outside the closed set, a `notice_version` whose language tag is
not the aid's language, or a `reading_aid.size` above the limit is `bad_manifest`.

### The aid's sealed plaintext

```
frame("mycarlos-reading-aid/1", manifest, reading_aid)            # 3 parts
frame("mycarlos-reading-aid/1", manifest, reading_aid, padding)   # or 4
```

The seal is v1's exactly (same suite, same `info`, same AAD from the outer IDs); only the first
plaintext part differs, so a v1 receiver stops at step 5 with `bad_package` and files nothing.

`reading_aid` is the canonical JSON (RFC 8785, UTF-8, no whitespace) of:

| Field | Value |
|---|---|
| `v` | `1` |
| `typ` | `"mycarlos-reading-aid"` |
| `language` | As in the manifest |
| `notice` | `{"version", "heading", "body"}`: the patient notice, in the aid's language, as approved with the summary. `version` equals the manifest's `notice_version`. |
| `overview` | One or two sentences |
| `points` | 1 to 50 of `{"text", "evidence": [1 to 5 strings]}`; every evidence string is an exact excerpt of the original's text, as validated by CARLOS before approval |

Limits: the JSON is at most **64 KiB** (65,536 bytes), the sealed aid at most **1 MiB**. A JSON
that is not canonical, not this shape, in another language than the manifest says, or whose
`notice.version` differs, is `bad_reading_aid`.

### Opening a reading aid (myCarlos)

The device runs v1's steps 1 to 4 unchanged (outer record, hash, routing IDs, seal), except that
a listed `kind` `reading-aid/1` whose outer `size` is above 1 MiB is `too_large` at step 1, before
any download. Then:

5. Split the plaintext. A first part `mycarlos-delivery/…` is an original: continue with v1's
   steps. A first part `mycarlos-reading-aid/` with another version is `unsupported_version`; any
   other first part or part count is `bad_package`. Parse the manifest: exactly the claims above,
   of the listed types, else `bad_manifest`.
6. to 8. As v1 (`kid` lookup, signature, signed IDs equal the outer record's).
9. `reading_aid.size` and `.sha256` match the JSON bytes. Else `reading_aid_hash_mismatch`. The
   JSON is canonical, well formed as above, and agrees with the manifest's `language` and
   `notice_version`. Else `bad_reading_aid`.
10. Expiry with the same 24-hour skew: `expired`.
11. Already seen. An aid whose `delivery_id` is a filed original's is `replayed` (one ID space).
    By the aid's own `delivery_id`: `already_filed` for the same copy as filed (send the kept
    receipt again), `replayed` for a different copy under a filed or a waiting aid's ID.
12. **The pair.** Look up `pair.original_delivery_id` among the originals this link has filed:
    - not filed: the outcome is `waiting_for_original`. Keep the downloaded copy by its
      `delivery_id` and `ciphertext_sha256`, send no receipt, and check it again after each
      original is filed. A later listing with the same hash is not downloaded again; a different
      hash under that ID is `replayed`. A waiting aid that passes its expiry (with the skew) is
      deleted silently: no receipt, nothing shown. (The two copies travel on their own, so the
      portal may list the aid first.)
    - filed, with `document.sha256` equal to `pair.original_document_sha256` and `created_at`
      and `expires_at` equal to the original's: the outcome is `file`;
    - filed with another `document.sha256`, or another lifetime: `pair_mismatch`. The original
      was replaced after the aid was approved; the aid is refused, never shown, and no receipt is
      sent.

13. **A second aid for the same original** (amendment, 4 Nov; default pending the maintainer). An
    original holds at most one aid. When the outcome is `file` and the original already holds an
    aid with another `delivery_id`, compare the two aids by `(approval.reviewed_at, approval.id)`,
    the review time first and, for the same second, the larger `approval.id` compared byte by
    byte, so that two devices always pick the same aid. (The summary version is an opaque hash
    and cannot be ordered.)
    - the new aid is greater: it replaces the held aid. One vault commit records the new aid on
      the original and drops the held one, and the vault history entry says it replaced an earlier
      aid. The new aid's receipt is sent as for any filed aid.
    - the new aid is not greater (earlier, or the same approval under another delivery ID): the aid
      is not filed. The device signs a receipt for it as for any aid (`document_sha256` is its
      JSON's SHA-256) and sends it once, without keeping it, so the portal marks that delivery
      picked up and stops offering it. If the send fails, the next listing offers the aid again
      and the same rule applies.
    - the replaced aid's own receipt, if it was still unsent, is dropped with its custody: the
      device keeps no receipt for an aid it no longer holds. The portal may still offer the
      replaced aid; at the next listing the device downloads it, finds it is less than the held
      aid and acknowledges it by the rule above, so the portal stops offering it.
    The pair check of step 12 applies first: a second aid that does not name the filed original's
    document hash and lifetime is `pair_mismatch`, as before.

**After `file`:** store the aid attached to the original, never as a document of its own; record
it in the vault history with its delivery ID and ciphertext hash; sign and keep its receipt
(`document_sha256` is the JSON's SHA-256); then send the receipt. Deleting the original deletes
its aid.

### Showing a reading aid

- The aid is reached only from the original it reads, never from a list or a search as a document.
- `notice.heading` and `notice.body` are shown above the overview and points every time, in the
  aid's language, with a link that opens the original.
- Evidence strings are shown with their points, as the clinician saw them.
- The aid may be opened before the original (maintainer answer 5): the notice comes first every
  time, with the link to the original.

### What CARLOS must hold (for P2 to P4)

- A persisted approval: document ID, `original_document_sha256`, `summary_version`, the content
  hash of the approved JSON, reviewer, `reviewed_at`, `notice_version`.
- A pair relation in its outbox: both rows share `pair_id`, but each row is staged, sent and
  retried on its own with its exact retained bytes; fencing the original (its source changed)
  fences the aid too, and fencing the aid alone leaves the original. The send includes the aid by
  default when an approval matches the original; the "leave the reading aid out" tick is recorded
  with the send.
- The sender stages at most one live aid for an original and device with the same content: a
  second aid with identical content under a fresh delivery ID is refused while the first is live
  (not fenced, errored, removed or expired). A changed aid is staged, and the device judges it by
  step 13, because the sender cannot read the `approval.reviewed_at` of an aid it already sealed.
  If P4b's outbox gets a `(original, kind)` uniqueness key, the sender will have to fence the
  earlier live aid before staging a changed one; that is decided with P4b.
- The original it sends must be byte-identical to the source the clinician reviewed (the aid's
  `pair.original_document_sha256` is that source's hash): the sender never re-renders, stamps or
  re-signs the PDF after approval, or the pair will not file.
- The device list's `accepts` per link, from the portal.

### Changing the aid

A new claim, field or JSON part means `mycarlos-reading-aid/2` and `v` 2 of its manifest and
JSON; the outer `kind` becomes `reading-aid/2`, and a device accepts it only when it names that
kind. The v1 original format is untouched by any of this.

## The portal mailbox

The portal checks requests, receipts and outer records. It never opens a package. The reference
for its checks is `tests/test_delivery_contract.py`; the M2 and M4 routes must decide every
vector the same way.

### Routes

| Route | Caller | Purpose |
|---|---|---|
| `POST /api/mycarlos/link` | myCarlos, signed with the new device key | Link a device (milestone M2) |
| `GET /api/mycarlos/deliveries` | Device | List this device's waiting copies (outer records). Also the check-in. |
| `GET /api/mycarlos/deliveries/{delivery_id}` | Device | Download one copy (`application/octet-stream`) |
| `POST /api/mycarlos/deliveries/{delivery_id}/receipt` | Device | Body `{"receipt": "<compact receipt>"}`. Deletes the copy. |
| `/internal/carlos/...` | CARLOS, staff or job assertion (the existing contract) | Upload copies, list a patient's devices and fetch delivery events. Their exact shape is M2–M4 detail; the stored fields are fixed above. |

### Upload checks

An upload is refused as `invalid_delivery` unless all of these hold:
- the outer record has exactly the fields above, with `v` and `suite` as listed;
- the delivery ID is a UUID, and the opaque IDs use the allowed characters;
- `size` equals the bytes received, more than 48 and at most 20 MiB;
- `ciphertext_sha256` matches the bytes received;
- `created_at < expires_at ≤ created_at + 7 days`.

The device must also be an active device of the patient in the route, checked against the
portal's own tables:
- **A removed device:** `device_removed`.
- **An unknown device, or one linked to another patient:** `invalid_delivery`.

### Removing a device

**Who:** the patient, under Linked devices, or staff, through CARLOS.

**What happens:** removing a device removes that one link (keys are per link). The portal then:
- marks the device removed;
- hard-deletes all of that link's waiting copies at once;
- records an event for CARLOS's delivery-sync job. CARLOS then shows those copies as "removed"
  and stops sending to that device.

**Afterwards:**
- Every request signed with that link's key, including a late pickup or receipt, gets
  `device_removed` (403).
- A CARLOS upload for it gets `device_removed` as well.
- A removed link never comes back. Linking again makes a new link, with fresh keys.
- The link's waiting key is revoked in the same transaction (`device_removed` when the patient
  removes it, `staff` through CARLOS), so the waiting check answers 404 from then on.
- So are its availability subscriptions, with the same `revoked_by`, and their pending notices
  are deleted. Dispatch already refused a removed device; now its push destinations stay only as
  tombstones, so a removed destination never enrolls again.

### The waiting check (a locked myCarlos)

A locked myCarlos cannot sign device requests: the device key is inside the vault. It holds a
second, separate Ed25519 key, the **waiting key**, which can ask one thing only: is a copy
waiting for this device? The check is only there while `PATIENT_PORTAL_MYCARLOS_DELIVERY_ENABLED`
and `PATIENT_PORTAL_MYCARLOS_AVAILABILITY_ENABLED` are both on.

**The key.** The device makes it. The portal stores only the public key, bound to the device row,
so to one link, with at most one live key per device.
- `key_id` = b64url(SHA-256(`mycarlos-waiting-key-v1` ‖ u64be(32) ‖ public key)), 43 characters:
  the same framing as `device_key_id`, under its own label.
- A waiting key id never names a device, and a device key id never names a waiting key.

**Registering, with the device key** (a device request, like every route above):
- `POST /api/mycarlos/availability/waiting-keys`, body exactly
  `{"key_id", "public_key" (b64url of 32 bytes), "alg": "ed25519"}`.
  - 201 for a new key; 200 for the same live key again. A different key replaces the live one,
    which stays as a tombstone.
  - 400 `invalid_waiting_key`: bad shape, a key id that is not the key's, or the device's own key.
  - 409 `waiting_key_taken`: a key id ever registered before, by any device, or revoked. A
    revoked key never comes back.
- `DELETE /api/mycarlos/availability/waiting-keys/{key_id}`: 200 `{"key_id", "revoked": true}`,
  also again; 404 if it is not this device's key.

**Asking, with the waiting key.** Header `X-MyCarlos-Waiting-Assertion`, the same compact form as
a device assertion.
- Claims exactly `aud` (`carlos-patient-portal-waiting-check`), `iss`, `kid` (the key id), `jti`,
  `iat`, `exp` and `request_hash`. There is no `recipient_id`.
- At most 60 seconds of lifetime. The nonce is used once, in the same table as device, staff and
  job assertions.
- The audience is the domain separator: a waiting assertion never passes a device route, and a
  device assertion never passes the check.

The routes:
- `POST /api/mycarlos/availability/waiting`, body exactly `{"key_id"}` (the assertion's `kid`).
  - **200**, with exactly `{"waiting": true}` or `{"waiting":false}`. Both are 17 bytes, so their
    size never tells them apart. True while a not-expired copy is `waiting` for the device.
  - **429** `{"detail": "too soon"}` with `Retry-After`, less than 120 seconds after the key's
    last answer. It still uses up the assertion.
  - **404** `{"detail": "not found"}` for every other refusal: a bad, expired or replayed
    assertion, an unknown or revoked key, or a removed device.
  - The answer carries no count, no delivery id, no name, date or clinic name.
- `DELETE /api/mycarlos/availability/waiting`, body exactly `{"key_id"}`: the key gives itself up
  (a locked app turning its tray notices off). 200 `{"revoked": true}`; afterwards, only 404.

**Who revoked it** is kept on the tombstone:
- `device`: given up or replaced with the device key;
- `waiting_key`: given up by the key itself;
- `device_removed`: the patient removed the device;
- `staff`: removed through CARLOS;
- `unlink`: reserved for a device unlink route, which does not exist yet.

### Device requests

**Header:** each device request carries `X-MyCarlos-Device-Assertion`, a compact Ed25519 object.
The Ed25519 signature is 64 bytes, and the assertion is at most 4096 bytes.

| Claim | Value |
|---|---|
| `aud` | `"carlos-patient-portal-device-api"` |
| `iss` | `"mycarlos"` |
| `kid` | The device's `device_key_id` |
| `recipient_id` | The device's recipient ID |
| `jti` | A canonical UUID, used once |
| `iat`, `exp` | myCarlos uses 60 seconds; the portal accepts at most 120 |
| `request_hash` | `SHA-256(frame(METHOD, raw path, raw query, body))` as hex, the staff request framing |
| `vault_head_link` | Optional, on any request: this link's anchor of the vault history head (decision L, below). The portal keeps it for that device. |

**The portal's checks, in order:**
1. **Parse:** the canonical encoding, exactly the claims above (`vault_head_link` optional), the right
   `aud` and `iss`, a UUID `jti`, integer times, and hex hashes. Else `invalid_assertion`.
2. **Find the device** by `kid`. Keys are per link, so `kid` names one row. Else
   `unknown_device`.
3. **Verify the signature** with that device's stored Ed25519 key. Else `invalid_assertion`.
4. **Device status:** a removed device gets `device_removed`.
5. **Time:** `exp > iat`, `exp − iat ≤ 120`, and `iat ≤ now + 30`. Else `invalid_assertion`.
   If `now ≥ exp + 30`, the code is `expired`.
6. **Request hash:** it must match the request as received. Else `request_mismatch`.
7. **Recipient:** `recipient_id` must be the device's account's ID. Else `recipient_mismatch`.
8. **Replay:** a `jti` already used gets `replay`. This uses the jti table shared with staff and
   job assertions.
9. **The route itself:** a copy that isn't this device's, has expired or is gone gets
   `delivery_not_found`. Another device's copy also gets `delivery_not_found`, so a device can't
   tell whether that copy exists.

### Linking a device

1. **The code:** the patient signs in to the portal with MFA and presses "Link myCarlos". The
   portal makes a pending link:
   - a public `link_id` and a secret `code`;
   - bound to that patient account and to the signed-in session that made it;
   - valid for 10 minutes, and usable once.

   It shows them as one string and as a QR code. The QR code holds the portal address, the
   `link_id` and the `code`.
2. **The request:** myCarlos makes a fresh pair of keys for this link and sends this body.
   **`device_name` (client MUST):** myCarlos suggests a plain name, which the patient can edit.
   - **Allowed:** the OS family, as in "myCarlos on Windows" (or macOS, Linux, Android, iOS).
   - **Never sent:** the computer's host name, the phone's own name, the user account's name or
     the OS version.

   The portal can't check this.
   ```json
   {"link_id": "…", "code": "…", "device_name": "…", "x25519_public_key": "<b64url>", "ed25519_public_key": "<b64url>"}
   ```
   It goes with a compact Ed25519 assertion signed by the new device key. The assertion has the
   claims of a device request, except that `aud` is `"carlos-patient-portal-device-link"`,
   there's no `recipient_id` and no `vault_head_link`, and `kid` is the `device_key_id` of the keys in
   the body. Its `request_hash` covers the whole body. So the signature covers both public keys,
   the device name and the code, and proves the device holds the key.
3. **The portal's checks, in order:**
   1. **Body:** exactly these fields, with no duplicates. The keys are 32 bytes, the device name
      is 1–64 printable characters, and `link_id` and `code` are in the form below. Else
      `invalid_assertion`.
   2. **Assertion:** it parses, and `kid` equals the body keys' `device_key_id`. Else
      `invalid_assertion`.
   3. **Signature:** it verifies with the body's Ed25519 key. Else `invalid_assertion`.
   4. **Time, request hash and replay:** as for device requests.
   5. **Clinic keys:** the clinic must have published at least one active signing key. Else
      `clinic_keys_missing`. A first link has no earlier pins: the device's trust in the
      clinic's keys starts with the key list it links with (see
      [the link lifecycle](mycarlos-link-lifecycle-v1.md)), so a device linked while no key is
      active would have nothing to verify a document with.
      This check is for the whole clinic and comes before the code, so it says nothing about the
      link the request names, the code stays usable once a key is published, and nothing is
      counted.
   6. **The code:**
      - it is checked only against the pending link that `link_id` names, so a code never works
        with another account's link;
      - the link must still be pending: unused, unexpired, its session still signed in, and
        under 5 wrong codes;
      - the account must be under its limit (below);
      - only then is the code compared. A wrong code counts against that link and against its
        account.

      A wrong code for a link that has ended counts nothing. Its `link_id` was on screen once,
      and counting would let whoever saw it keep the patient from linking. The portal deletes
      ended links, or keeps them only as markers that answer `link_code_invalid`.

      Every failure here gives the same `link_code_invalid`, so the code can't be used to probe
      which links exist.
   7. **Device key:** a key that is already linked, to any account, gets `device_exists`. Keys
      are per link, so a second link always brings a fresh pair.
4. **On success:** the portal records the device as linked to the code's account, never to an
   account named in the request. It marks the code used and returns:
   - the `recipient_id`;
   - the clinic's ID and name;
   - the clinic's key list (`kid`, SubjectPublicKeyInfo and status for each key).

   Notices go out at once: an email, and a message to the patient's other devices. myCarlos pins
   the key list for this link.
5. **CARLOS still decides:** the new device stays **pending** in CARLOS until it is confirmed
   outside the portal (decision B: staff approval, a code CARLOS texts, or approval from an
   already linked device). CARLOS sends nothing to a pending device. A takeover of the portal
   or of the patient's portal account can link a device, but can't make CARLOS send it anything.

**The link code:**

| Part | Rule |
|---|---|
| Alphabet | Crockford base32: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I, L, O or U) |
| `link_id` | 8 characters (40 bits), random, unique among pending links. Names one pending link; not secret. |
| `code` | 10 characters (50 bits), random from a cryptographic generator. The secret. |
| On the wire | Exactly these characters, upper case, with no separators |
| Shown to the patient | `<link_id>-<first 5 of code>-<last 5 of code>`, e.g. `FAKE0001-FAKE7-Q2M4K` |
| Typed into myCarlos | myCarlos drops spaces and hyphens, upper-cases, and reads O as 0 and I or L as 1. The first 8 characters are the `link_id`, the other 10 the `code`. Anything else is `not_a_link_code`, shown locally; nothing is sent. |

**The limits:**
- **Per link:** 10 minutes, one use, and 5 wrong codes end it.
- **Per account:** at most 3 pending links at a time; a fourth replaces the oldest. 10 wrong codes
  within 24 hours, counted only on pending links, stop every link for that account until 24
  hours after the last wrong code.
- **Per caller:** the portal's usual per-IP rate limits also apply.

With 50 bits and 5 tries, a guess succeeds about once in 2^47 links.

### Pickup receipts

A receipt is a compact Ed25519 object signed by the device. CARLOS can check it without trusting
the portal. It has exactly these claims:

| Claim | Value |
|---|---|
| `typ` | `"mycarlos-delivery-receipt"` |
| `aud` | `"carlos-delivery-receipt"` |
| `delivery_id`, `recipient_id`, `device_key_id` | The copy's |
| `ciphertext_sha256` | The sealed copy as downloaded |
| `document_sha256` | The PDF as filed |
| `picked_up_at` | When it was filed |
| `vault_head_link` | This link's anchor of the vault history head after filing (decision L, below) |
| `jti` | A canonical UUID. It identifies this receipt: re-sends carry the same `jti`, so the portal and CARLOS can de-duplicate. |

**The portal:**
1. Finds the device's copy named in the route.
   - **None there**, but this device sent this exact receipt for this delivery before: answer
     200, already done. The portal keeps each accepted receipt, or its hash, until the copy's
     expiry.
   - **Otherwise:** `delivery_not_found`.
2. Checks the receipt:
   - the claims, `typ` and `aud` are as listed;
   - the signature verifies with the device's key;
   - the receipt's `device_key_id` and `recipient_id` are the requesting device's.

   Else `invalid_receipt`.
3. Checks that `delivery_id` matches the route and `ciphertext_sha256` matches the stored copy.
   Else `receipt_mismatch`.
4. Hard-deletes the copy, and holds the receipt until CARLOS's delivery-sync job collects it.

**The vault head anchor (`vault_head_link`, decision L):** the raw head hash of the vault history
is the same on every link at a given moment, so sending it would let two portals tie their links
to one device. Each link sends its own anchor instead:

```
K_link          = HKDF-SHA256(ikm = this link's Ed25519 private seed (32 bytes),
                              salt = none, info = "mycarlos/vault-head/v1", length = 32)
vault_head_link = lowercase hex of HMAC-SHA256(K_link, head)
```

Here `head` is the vault history's current head hash, as 32 bytes. The vectors include both
links' anchors for the same head.

**Who checks an anchor:** only the device, or an auditor the patient gives that link's key, can
recompute `vault_head_link`. The portal and CARLOS hold anchors but not `K_link`: they just store
the values and hand them back.
- **The device itself:** it fetches the anchors stored for a link and compares them with its own
  history, recomputing each anchor from the head recorded at that time. A mismatch means the
  history was rewritten after that anchor was recorded. The route that returns stored anchors
  is M4 detail.
- **An auditor, in a dispute:** myCarlos gives the auditor two things:
  - that link's `K_link`. It is an HKDF output, so it reveals nothing about the link's signing
    key and nothing about any other link;
  - its history heads.

  The auditor recomputes the anchors and compares them with the ones CARLOS has on record.

**CARLOS** checks the receipt against its own record of the delivery:
- the accepted device's key;
- the delivery ID;
- the ciphertext hash of the copy it uploaded;
- the SHA-256 of the PDF it signed.

CARLOS records the first valid receipt for each delivery ID and device. A repeat with the same
`jti` and bytes changes nothing.

### Response codes

The portal logs the code in its audit trail, never content. On the wire:
- **Failed assertions:** `invalid_assertion`, `unknown_device`, `expired`, `request_mismatch` and
  `replay` give the same generic 404 as the job routes, so the device API reveals nothing to a
  caller without a device key.
- **A verified device that is refused:** 403 with `{"code": …}`. The codes are `device_removed`
  and `recipient_mismatch`.

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_delivery` | 400 | Upload refused: the outer record or bytes are wrong |
| `delivery_not_found` | 404 with code | No such copy for this device: wrong ID, another device's, expired, or deleted |
| `invalid_receipt` | 400 | The receipt is malformed, isn't the device's, or names another patient |
| `receipt_mismatch` | 409 | The receipt doesn't match the route or the stored copy |
| `link_code_invalid` | 403 | Wrong, expired, used or locked code, or one whose session has ended |
| `device_exists` | 409 | That device key is already linked (keys are per link) |
| `clinic_keys_missing` | 409 | Linking refused: the clinic hasn't published an active signing key yet. The link code stays usable. Link recovery answers the same while no key is active, and key refresh when the clinic has published no keys at all (see [the link lifecycle](mycarlos-link-lifecycle-v1.md)). |
| `device_removed` | 403 on device requests, 409 on uploads | The link was removed; its copies are gone |

**Clock problems:** the portal sends a `Date` header, so myCarlos can tell the patient when its
clock is far off.

## Clinic code v1

Issue carlos-emr/mycarlos#141. A patient's first device can be approved with a 9-digit code that
CARLOS emails to the patient, instead of by clinic staff. The shared contract is the same for
myCarlos, CARLOS and the portal; its test vectors are `tests/fixtures/clinic-code-v1.json`, copied
unchanged from that contract. A re-link or recovery on the same device still uses the existing
predecessor approval, with no code.

### The code

- `code_r`: 6 ASCII digits, uniformly random (000000–999999), made by CARLOS with a CSPRNG, one per
  approval request.
- `check_t`: 3 ASCII digits = (the big-endian unsigned 64-bit integer of the first 8 bytes of
  SHA-256(input)) mod 1000, zero-padded. The input is the UTF-8 of these five fields joined by a
  single LF (0x0A), with no trailing LF:
  `carlos-mycarlos-clinic-code-check-v1`, `clinic_kid`, `device_key_id`, `request_id`, `code_r`.
  - `clinic_kid`: the `kid` of the clinic signing key that signs this request's code challenge.
  - `device_key_id`: the candidate device's key ID, as in the intent's `candidate_device_key_id`.
  - `request_id`: the approval request ID (the lowercase UUID on the wire).
- The code is `code_r` followed by `check_t`, shown as `ddd ddd ddd` (for example `482 193 644`).
  myCarlos accepts it with spaces, dashes or neither, and refuses anything that isn't 9 digits.

`check_t` lets myCarlos check, before sending anything, that the code was made for the clinic key
it pinned. A code from a look-alike portal fails that check. The portal never uses `check_t`;
`tests/test_approval_code.py` recomputes it for every shared vector to guard the contract.

### The flow

1. **Link and request:** unchanged. myCarlos links, then sends its signed approval intent.
2. **Policy (CARLOS):** `code`, the default for new clinics, when the patient has a usable email
   on file (and email consent under CARLOS's rules); `code_and_staff`, which also waits for staff;
   or `staff_only`, also used when there is no usable email (today's staff flow, unchanged).
3. **CARLOS:** makes `code_r`, computes `check_t` with its signing key's kid and keeps `code_r`
   privately with the request. It emails the patient "Your <clinic name> myCarlos code is
   482 193 644. It expires in <N> minutes. Never enter it on a website." (no health information).
   It then publishes the challenge as today, signed with that key, with `approval_kind: "code"`.
   The challenge never holds `code_r`, `check_t` or a hash of them.
4. **myCarlos:** when the challenge's `approval_kind` is `code`, it asks for the code, verifies
   the challenge with the pinned clinic key and recomputes `check_t`. On a mismatch it sends
   nothing (after 5 local mismatches it stops taking codes for that request). On a match it sends
   `code_r` to the portal (below).
5. **Portal:** stores the submission for CARLOS. It never compares codes; it doesn't know them.
6. **CARLOS:** reads submissions, compares each in constant time with its `code_r`, and publishes
   the existing decision: `accepted` with an acceptance of kind `code` on a match, or `refused`
   with reason `code_attempts` after 5 wrong codes. It polls the code route every few seconds
   while any code request is open.
7. **myCarlos:** its status checks pick up the acceptance and verify it exactly as today.

### Signed objects

`approval_kind` is an existing field of the challenge and the acceptance. Version 1.1 adds one
value:

| `approval_kind` | Meaning | `predecessor_device_key_id`, `predecessor_version` | Acceptance `approval_sha256` |
|---|---|---|---|
| `staff_first` | First device, approved by staff | `null` | `null` |
| `accepted_device` | A later device, approved by an earlier one | set | set |
| `code` | First device, approved by the emailed code | `null` | `null` |

A code request is an intent with no predecessor. `code_and_staff` also publishes kind `code`.
The acceptance's `approval_kind` must equal the challenge's. Decisions gain the refusal reason
`code_attempts`.

### Device route

`POST /api/mycarlos/device-approvals/{request_id}/code`, with the same device assertion header,
audience, request-hash binding and single-use rule as `POST /api/mycarlos/device-approval-requests`.
`vault_head_link` is optional, as on every device request. There is no query string, and the body
is exactly `{"code_r":"482193"}`: one string of 6 ASCII digits, at most 256 bytes.

It is accepted only for this device's request, in status `challenge_ready`, not expired, whose
challenge has `approval_kind: "code"`. Each accepted POST stores one attempt, numbered 1 to 5; the
same code sent twice counts twice. The answer is `202 {"status":"submitted"}`.

Refusals:

| HTTP | Body | When |
|---|---|---|
| 413 | `{"detail":"request too large"}` | The body is over 256 bytes. As on every device route, this is checked as the body is read, before the assertion. |
| 404 | `{"detail":"not found"}` | The assertion is missing, bad, unknown, expired, replayed or for another request |
| 403 | `{"code":"device_removed"}` or `{"code":"recipient_mismatch"}` | As on the other device routes |
| 400 | `{"code":"invalid_approval"}` | The body isn't exactly `{"code_r": 6 digits}`, or there is a query string |
| 404 | `{"code":"approval_not_found"}` | The request ID isn't a v4 UUID, is unknown, or is another device's |
| 409 | `{"code":"approval_not_code"}` | No challenge yet, or its kind isn't `code` |
| 409 | `{"code":"approval_not_pending"}` | The request already has a decision |
| 410 | `{"code":"approval_expired"}` | `challenge_ready`, but past its `expires_at` |
| 429 | `{"code":"code_attempts"}` | 5 attempts are already stored. This is final for the request; the generic `Retry-After: 60` doesn't apply. |

### CARLOS's job routes

Both take the `device-approval-sync` job, with the permission named below in the job assertion.

- `GET /internal/carlos/mycarlos/device-approval-codes?after=<seq>&limit=<1..20, default 10>`,
  permission `portal.mycarlos.device_approval.codes.read`:
  `200 {"codes":[{"sequence":"7","request_id":"<uuid>","challenge_id":"<id>","attempt":1,"code_r":"482193","submitted_at":1761660000}],"last_sequence":"7","next_cursor":null}`.
  The sequence is per clinic, with the same cursor rules as `GET …/device-approval-requests`
  (`after` beyond the latest gives 400 `invalid_cursor`). `code_r` is `null` once that attempt is
  consumed, once the request has a decision, or once it has expired.
- `PUT /internal/carlos/mycarlos/device-approval-requests/{request_id}/codes/{attempt}/consumed`,
  permission `portal.mycarlos.device_approval.codes.consume`, empty body:
  `200 {"status":"consumed"}`. Repeating it is harmless. It erases that `code_r`. An unknown
  request or attempt gives 404 `approval_not_found`.
- The existing `PUT …/device-approval-requests/{request_id}/decision` is unchanged: `accepted` with
  an acceptance of kind `code`, or `refused` with reason `code_attempts`. Storing any decision
  erases the request's remaining codes.

### Storage

Migration 0020 adds `patient_portal_mycarlos_approval_codes` (clinic, request, attempt 1–5,
`code_r`, submitted and consumed times, and a per-clinic `code_sequence`) and a `code_sequence`
counter on the approval clinic row. A plain `code_r` is kept at most until it is consumed, the
request is decided or the request expires (a code request lives about 10 minutes). The attempt rows
stay, so the limit of 5 holds. A downgrade is refused while any attempt row exists.

**What the portal can and can't do with a code:** it sees the codes devices send, briefly. It
can't approve a device with one: an acceptance needs the clinic's signing key, and CARLOS
compares the code only for the request and device it was made for.

## Device approval contract v2: request lifetimes (myCarlos #144)

v2 changes only how long a device approval request lives, so that staff can approve a device
later in the day. Fields, signatures, hash links and checks are those of v1
(`tests/fixtures/device-approval-contract-v1.json`).

| Seconds | v1 | v2 |
|---|---|---|
| intent: `0 < exp − iat ≤` | 600 | 86 400 |
| `staff_first` challenge: `0 < expires_at − issued_at ≤` | 600 | 86 400 |
| `code` challenge (clinic code) | 600 | 600 |
| `accepted_device` challenge | 600 | 600 |
| a request with no challenge yet is open until | intent `exp` | `min(exp, iat + 600)` |

- Every object of a v2 flow carries `"v": 2`. A challenge, approval or acceptance carries its
  intent's `v`; any other value, or a mismatch, is refused.
- A challenge's `expires_at` is exactly `min(issued_at + life(kind, v), intent.exp)`.
- The portal stores a pending request's end as `min(exp, iat + 600)`. A challenge published after
  that is refused (`410 approval_expired`), so a late answer can't revive a request the device may
  already have replaced. Codes keep their 10 minutes and their erasure.
- **Version check:** `GET /api/mycarlos/device-approval-versions`, with the same device
  assertion as the other approval routes, answers `{"versions":[1,2]}`. myCarlos signs v2 only
  when 2 is listed. An older portal answers 404, and the app signs v1. Existing replies gain no
  field, because older apps parse them strictly.
- v1 apps keep v1 rules everywhere, including 10-minute staff requests.
- **Deploy order:** the portal lists v2 only when
  `PATIENT_PORTAL_MYCARLOS_APPROVAL_CONTRACT_V2_ENABLED` is on (off by default); while off it also
  refuses v2 intents. Turn it on only after the clinic's CARLOS takes v2: an app signs v2 when the
  portal lists it, and an older CARLOS can't approve a v2 request.
- The limit of 50 open requests per account counts a `staff_first` request for its whole 24
  hours, so many unapproved staff requests on one account hold new ones back for longer.
- Shared fixture: `tests/fixtures/device-approval-contract-v2.json`. It holds the three v2 flows,
  signed vectors for the limits, expiry-rule cases and open-request cases. Its FAKE keys are
  v1's, by reference; it records the hash of v1's public keys.
- CARLOS needs a database change for v2: its challenge table checks `expires_at` against 600
  seconds.

## How each side is tested

- **Every HPKE implementation** first reproduces RFC 9180 Appendix A.2.1, sequence 0. The
  fixture carries it as `hpke_rfc9180_a2_1`.
- **Receivers (myCarlos)** must get exactly the listed outcome for every vector in
  `packages.accept` (`file` or `already_filed`) and `packages.refuse`. They use the device key in
  `keys.device` and the links and filed copies in `receiver`. myCarlos also splits every
  `portal.link_code_display_examples` entry as listed.
- **Senders (CARLOS)** can't reproduce a seal, since the ephemeral key is random, so they are
  checked by round trip:
  1. Build the manifest for `sender.manifest_claims` and compare it byte for byte with
     `sender.manifest` (JCS plus RFC 6979).
  2. Check the AAD and the plaintext hash.
  3. Seal with a fresh ephemeral key, open the result with `keys.device`, and compare.
- **The portal:** `tests/test_delivery_contract.py` holds the reference checks for uploads,
  device requests, link requests and receipts. Its first test fails if the fixture is
  hand-edited.

**FAKE keys:** every key in the fixture is FAKE, derived from readable seed text
(`keys.derivation`). The fixture holds no key material.

## Changing the format

A new claim, field, suite or plaintext part means version 2:
- a new `v`;
- a new plaintext label (`mycarlos-delivery/2`);
- a new HPKE `info`.

A v1 receiver refuses anything newer with `unsupported_version`. The padding part exists so size
hiding can come without a version change.

## What the portal can and can't do

| If the portal is taken over, it can… | It can't… |
|---|---|
| Hold back or delete copies (CARLOS shows "not picked up") | Read a copy (no device key) |
| Link a rogue device to a patient account | Get CARLOS to send to it (CARLOS's own confirmation) |
| Swap, re-target or replay copies | Get them filed: the AAD, signed IDs and the filed-copy check stop them |
| Learn routing metadata: IDs, sizes and times | Learn titles, names or content |
