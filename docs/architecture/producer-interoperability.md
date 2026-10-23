# Producer interoperability

This protocol connects a configured clinic system, a portal and patient devices. CARLOS is the
first producer implementation. Other EMRs can implement an adapter to the documented, versioned
[delivery contract](mycarlos-delivery.md) and its shared byte fixtures. This does not mean a
generic EMR adapter is already implemented or enabled.

The clinic signs documents and delivery manifests with its own private signing key. Devices
verify those signatures with the public keys pinned for that clinic. The producer encrypts a
separate delivery to each accepted device's public encryption key; only that device's private
key can decrypt its copy. Signing and encryption serve different purposes and use different
keys. The portal stores opaque ciphertext, not the document decryption key or clinic signing
private key.

A producer adapter must provide:

- An independently configured clinic identity, signing-key catalogue and authenticated portal
  connection. Every clinic retains its own signing private keys; a shared vendor private key
  must not impersonate multiple clinics.
- The existing patient-to-recipient binding and accepted-device workflow: staff approve the
  first device, later devices require the existing-device approval flow. A portal link alone
  does not authorize delivery to a device.
- The exact signed PDF, manifest, per-device HPKE package, request binding and encoding rules
  in delivery format v1. An adapter must preserve original signed document bytes and must not
  substitute a patient name for the protocol's recipient binding.
- Durable submission/retry state and independently verified device receipts. A receipt follows
  durable device storage of the document, original bytes, verification/history and retained
  receipt. Only a valid receipt permits the portal to hard-delete that device's ciphertext copy;
  downloading it does not. Expiry and removal cleanup remain part of the delivery contract.
- Complete immutable public-key history, monotonic revocation and the additive
  [link lifecycle contract](mycarlos-link-lifecycle-v1.md). Key replacement proofs are minted
  once with an explicitly retained predecessor key and reused on retry.
- Independent checks against unchanged shared fixtures, plus an actual FAKE delivery through
  the portal into durable verified device storage and back through receipt/deletion/status.
  Passing serialization fixtures alone does not establish an interoperable producer.

Identifiers such as `carlos-patient-portal-device-api`, existing `/internal/carlos/` paths and
the `carlos-emr/mycarlos-delivery/v1` HPKE context are compatibility constants. Implementations
must preserve their exact bytes. They do not impose a producer application-brand allowlist.
Changing those identifiers requires an explicitly versioned protocol change and shared vectors.

The current portal deployment configuration has one configured clinic identity. Independent
clinic identities and keys do not imply an implemented multi-tenant portal or automatic trust
of an arbitrary EMR. A new producer needs its own reviewed adapter and configured credentials;
it never receives another clinic's private key.
