# Additive link lifecycle v1

This is the frozen additive contract for the existing delivery format v1. It adds key refresh,
replacement proofs and recovery of an incomplete link whose original response was lost. It
does not change the delivery envelope or add transparency-log proofs. Implementations and
independent Java/Python/Rust checks must pass before feature enablement.

The canonical source fixture is [link-lifecycle-v1.json](../../tests/fixtures/link-lifecycle-v1.json),
authored by [link_lifecycle_reference.py](../../tests/link_lifecycle_reference.py). Consumers copy
the fixture unchanged. The original delivery-contract fixture remains independent and unchanged.

## Key inventories and replacement proofs

`GET /api/mycarlos/clinic-keys` uses the unchanged device API assertion audience, exact request
binding and shared replay policy, with an empty body. Its response has exactly five fields:
`recipient_id`, `device_key_id`, `clinic_id`, `clinic_name`, and `clinic_keys`. Each key retains
`kid`, canonical DER SPKI encoded as unpadded base64url, and `status`. Optional `replaces_kid`
and `replacement_signature` appear together in initial link, refresh and recovery responses.

A proof signs these bytes:

```text
ASCII("mycarlos-clinic-key-replacement-v1") || 0x00 ||
frame(UTF8(clinic_id), UTF8(replaces_kid), UTF8(new_kid), canonical_DER(new_spki))
```

`frame` prefixes every part with its unsigned 64-bit big-endian byte length. The signature is
ECDSA P-256/SHA-256, exactly 64-byte IEEE P1363 `r || s`, encoded as canonical unpadded base64url.
Standard valid high-S and low-S signatures are accepted. The producer persists the minted proof
once; a different valid signature over the same statement cannot replace stored proof bytes.

Inventories retain every historical key and immutable binding. Revocation is monotonic. The
complete graph has 1–16 keys, at most 15 edges, no cycle and at most one successor per predecessor.
Every supplied proof must validate; an invalid proof is never interpreted as an unsigned change.
Publication takes a stable clinic database mutex before checking the complete inventory, even
when no key row exists yet. Existing-key row locks alone do not serialize first publication.

For a completed link, new signed edges anchor at the nearest previously active ancestor, or at
a new unsigned root accepted with the required plain notice and encrypted history. Previously
revoked keys cannot authorize new outgoing edges. Unchanged historical edges survive earlier
revocation. Skipped rotations may introduce already-revoked intermediates. For example, a device
that knew A may accept unsigned B followed by valid B→C, even if B is already revoked, with the
unsigned-root and current descendant fingerprints recorded in the notice. No acknowledgment
gate is added. Apply the entire validated state, notices, history and document rechecks atomically;
locked or stale session/trust revisions cannot apply a partial result.

Initial administrative provisioning can import valid historical chains without previous pins.
Initial device linking and pending recovery also have no previous pins: trust begins with the
explicit portal-address consent and authenticated HTTPS link ceremony. They validate the entire
graph and require an active clinic key. A completed link may refresh and reopen an all-revoked
inventory. A portal that withholds a new revocation remains an explicit v1 freshness limitation.

## Pending-only lost-response recovery

`GET /api/mycarlos/link` has an empty body and the separate assertion audience
`carlos-patient-portal-device-link-recovery`. Exact claims are `aud`, `exp`, `iat`, `iss`, `jti`,
`kid`, and `request_hash`. No recipient, code, account, supplied origin or vault anchor is added.
The device signs using the original per-link keys persisted before the original POST.

The server verifies strict claims, stored Ed25519 possession, freshness, exact prefixed raw
path/query/body binding and shared replay protection before any removed-device disclosure.
Unknown, forged, expired, mismatched or replayed assertions return generic `404`. A fresh valid
assertion for a removed device returns `403 {"code":"device_removed"}` only after the current
account→device transaction recheck. Missing account/recipient returns generic `404`. An inventory
with no active key returns `409 {"code":"clinic_keys_missing"}`. Success returns the current
complete five-field link response. Recovery creates no device, consumes no code and never
resurrects removal.

Only an incomplete durable provisional link may recover, at its stored portal base. A completed
link uses refresh and never resets its pins through recovery. Locking or a stale epoch cancels
completion and retains the provisional keys. Redirects are not followed.

Signed objects retain the existing encoding rule: producers emit JCS, verifiers strictly parse
exact duplicate-free claims and verify the signature over the original payload bytes. A valid
noncanonical signed JSON representation is not rejected by reserializing it. The separately
unsigned QR link format requires its own strict raw-JCS byte comparison before URL normalization.
