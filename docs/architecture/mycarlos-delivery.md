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
   5. **The code:**
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
   6. **Device key:** a key that is already linked, to any account, gets `device_exists`. Keys
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
| `device_removed` | 403 on device requests, 409 on uploads | The link was removed; its copies are gone |

**Clock problems:** the portal sends a `Date` header, so myCarlos can tell the patient when its
clock is far off.

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
