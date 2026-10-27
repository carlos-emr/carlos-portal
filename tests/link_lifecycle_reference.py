"""Canonical FAKE byte fixture for the frozen additive link lifecycle v1.

Author once here and copy the generated JSON unchanged to the Java and Rust repositories.
This reference uses the existing reviewed cryptographic library and deterministic FAKE seeds.
It is not a production signer, trust engine, transport or end-to-end delivery demonstration.
"""

import argparse
import hashlib
import json
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from tests import delivery_contract_reference as ref

FIXTURE = Path(__file__).parent / "fixtures" / "link-lifecycle-v1.json"
CONTRACT_SHA256 = "87c2cc6446fb5884ecad0c77c714178288934f4525f17722a6bc4966a75eaafa"
REPLACEMENT_DOMAIN = b"mycarlos-clinic-key-replacement-v1\x00"
RECOVERY_AUDIENCE = "carlos-patient-portal-device-link-recovery"
CLINIC = "clinic-a"
UNICODE_CLINIC = "clinique-é-患者"
RECIPIENT = ref.RECIPIENT_ID
PREFIXED_PATH = b"/patients/api/mycarlos/link"


def replacement_statement(clinic, predecessor, successor):
    return REPLACEMENT_DOMAIN + ref.frame(
        clinic.encode("utf-8"),
        predecessor.kid.encode("utf-8"),
        successor.kid.encode("utf-8"),
        successor.spki,
    )


def entry(key, *, status="active", predecessor=None, signature=None):
    result = {"kid": key.kid, "spki": ref.b64url(key.spki), "status": status}
    if predecessor is not None:
        proof = (
            signature
            if signature is not None
            else predecessor.sign(replacement_statement(key.clinic_id, predecessor, key))
        )
        result.update(replaces_kid=predecessor.kid, replacement_signature=ref.b64url(proof))
    return result


def response(device, entries):
    return {
        "recipient_id": RECIPIENT,
        "device_key_id": device.device_key_id,
        "clinic_id": CLINIC,
        "clinic_name": "FAKE independent clinic",
        "clinic_keys": entries,
    }


def generate():
    keys = {name: ref.ClinicKey("lifecycle-v1 " + name, CLINIC) for name in "ABCD"}
    a, b, c, d = (keys[name] for name in "ABCD")
    ua = ref.ClinicKey("lifecycle-v1 Unicode predecessor", UNICODE_CLINIC)
    ub = ref.ClinicKey("lifecycle-v1 Unicode successor", UNICODE_CLINIC)
    device = ref.DeviceKeys("lifecycle-v1 registered device")
    stranger = ref.DeviceKeys("lifecycle-v1 unknown device")
    statement = replacement_statement(CLINIC, a, b)
    signature = a.sign(statement)
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    low_s = min(s, ref.P256_ORDER - s)
    high_s = ref.P256_ORDER - low_s
    low = r.to_bytes(32, "big") + low_s.to_bytes(32, "big")
    high = r.to_bytes(32, "big") + high_s.to_bytes(32, "big")

    def proof_vector(name, old=a, new=b, clinic=CLINIC, proof=None, valid=True):
        raw = replacement_statement(clinic, old, new)
        proof = old.sign(raw) if proof is None else proof
        return {
            "name": name,
            "clinic_id": clinic,
            "replaces_kid": old.kid,
            "predecessor_spki": ref.b64url(old.spki),
            "kid": new.kid,
            "spki": ref.b64url(new.spki),
            "statement_hex": raw.hex(),
            "signature": ref.b64url(proof),
            "expect_valid": valid,
        }

    proofs = [
        proof_vector("valid-low-s", proof=low),
        proof_vector("valid-high-s", proof=high),
        proof_vector("valid-unicode-framing", old=ua, new=ub, clinic=UNICODE_CLINIC),
        proof_vector("wrong-clinic", clinic="clinic-b", proof=low, valid=False),
        proof_vector("wrong-successor", new=c, proof=low, valid=False),
        proof_vector("wrong-predecessor", old=d, proof=low, valid=False),
        proof_vector("wrong-signature-bytes", proof=b"\x00" * 64, valid=False),
        proof_vector("wrong-signature-length", proof=low[:-1], valid=False),
        proof_vector("der-not-p1363", proof=encode_dss_signature(r, low_s), valid=False),
    ]
    padded = proof_vector("padded-base64url", proof=low, valid=False)
    padded["signature"] += "=="
    proofs.append(padded)

    inventories = []

    def inventory(name, previous, incoming, *, mode="refresh", accept=True, notice=None):
        current_response = response(device, incoming)
        inventories.append(
            {
                "name": name,
                "mode": mode,
                "previous": previous,
                "incoming": incoming,
                "response_utf8_hex": ref.canonical_json(current_response).hex(),
                "expect_accept": accept,
                "required_notice": notice,
                "refusal_preserves_previous": not accept,
            }
        )

    active_a = entry(a)
    revoked_a = entry(a, status="revoked")
    signed_b = entry(b, predecessor=a, signature=low)
    revoked_b = {**signed_b, "status": "revoked"}
    signed_c = entry(c, predecessor=b)
    inventory("bootstrap-historical-chain", [], [revoked_a, revoked_b, signed_c], mode="bootstrap")
    inventory("bootstrap-all-revoked", [], [revoked_a], mode="bootstrap", accept=False)
    inventory("signed-replacement", [active_a], [revoked_a, signed_b], notice="signed")
    inventory("historical-edge-stays-valid", [revoked_a, signed_b], [revoked_a, signed_b])
    inventory(
        "two-skipped-rotations", [active_a], [revoked_a, revoked_b, signed_c], notice="signed"
    )
    inventory(
        "nearest-prior-active-ancestor",
        [active_a, signed_b],
        [revoked_a, revoked_b, signed_c],
        notice="signed",
    )
    inventory("unsigned-replacement", [active_a], [revoked_a, entry(b)], notice="unsigned")
    inventory(
        "offline-unsigned-root-then-signed-child",
        [active_a],
        [revoked_a, entry(b, status="revoked"), signed_c],
        notice="unsigned",
    )
    inventory(
        "previously-revoked-cannot-authorize-new-edge",
        [revoked_a],
        [revoked_a, signed_b],
        accept=False,
    )
    inventory("revocation-replay-cannot-revive", [revoked_a], [active_a], accept=False)
    inventory("all-revoked-refresh-and-reopen", [active_a], [revoked_a], notice="revocation")
    inventory("omitted-historical-key", [revoked_a, signed_b], [signed_b], accept=False)
    changed_proof_b = entry(b, predecessor=a, signature=high)
    inventory(
        "valid-resigned-proof-cannot-replace-immutable-bytes",
        [revoked_a, signed_b],
        [revoked_a, changed_proof_b],
        accept=False,
    )
    inventory(
        "fork-two-valid-successors",
        [active_a],
        [revoked_a, signed_b, entry(d, predecessor=a)],
        accept=False,
    )
    inventory(
        "cycle-valid-individual-signatures",
        [],
        [entry(a, predecessor=b), signed_b],
        mode="bootstrap",
        accept=False,
    )
    inventory("missing-predecessor", [], [signed_b], mode="bootstrap", accept=False)
    invalid_proof_b = entry(b, predecessor=a, signature=b"\x00" * 64)
    inventory(
        "invalid-proof-is-not-unsigned", [active_a], [revoked_a, invalid_proof_b], accept=False
    )
    missing_pair = dict(signed_b)
    del missing_pair["replacement_signature"]
    inventory("one-paired-field-missing", [active_a], [revoked_a, missing_pair], accept=False)
    chain = [ref.ClinicKey(f"lifecycle-v1 long-chain {index}", CLINIC) for index in range(17)]
    long_entries = [
        entry(
            key,
            status="revoked" if index < 15 else "active",
            predecessor=chain[index - 1] if index else None,
        )
        for index, key in enumerate(chain)
    ]
    inventory("sixteen-keys-fifteen-edges", [entry(chain[0])], long_entries[:16], notice="signed")
    inventory("seventeen-keys-over-limit", [entry(chain[0])], long_entries, accept=False)

    assertions = []

    def recovery(
        name,
        *,
        changes=None,
        key=device,
        known=True,
        removed=False,
        account=True,
        recipient=True,
        replay=False,
        method="GET",
        path=PREFIXED_PATH,
        query=b"",
        body=b"",
        expected=200,
        duplicate=False,
        pretty=False,
    ):
        claims = {
            "aud": RECOVERY_AUDIENCE,
            "exp": ref.NOW + 60,
            "iat": ref.NOW,
            "iss": "mycarlos",
            "jti": str(UUID(int=len(assertions) + 1)),
            "kid": device.device_key_id,
            "request_hash": ref.request_hash("GET", PREFIXED_PATH, b"", b""),
        }
        claims.update(changes or {})
        payload = ref.canonical_json(claims)
        if duplicate:
            payload = payload[:-1] + b',"aud":"' + RECOVERY_AUDIENCE.encode() + b'"}'
        if pretty:
            payload = json.dumps(claims, ensure_ascii=False, indent=1).encode()
        compact = ref.compact_ed25519_bytes(key.ed25519, payload)
        expected_body = (
            response(device, [revoked_a, signed_b])
            if expected == 200
            else ({"code": "device_removed"} if expected == 403 else {"detail": "not found"})
        )
        assertions.append(
            {
                "name": name,
                "assertion": compact,
                "payload_hex": payload.hex(),
                "method": method,
                "raw_path_hex": path.hex(),
                "raw_query_hex": query.hex(),
                "body_hex": body.hex(),
                "now": ref.NOW,
                "known_device": known,
                "device_status": "removed" if removed else "active",
                "account_exists": account,
                "recipient_exists": recipient,
                "nonce_already_consumed": replay,
                "expected_status": expected,
                "expected_response_utf8_hex": ref.canonical_json(expected_body).hex(),
            }
        )

    recovery("valid-prefixed-recovery")
    recovery("valid-original-noncanonical-signed-json", pretty=True)
    recovery("wrong-audience", changes={"aud": ref.DEVICE_AUDIENCE}, expected=404)
    recovery("extra-recipient-claim", changes={"recipient_id": RECIPIENT}, expected=404)
    recovery("extra-vault-anchor", changes={"vault_head_link": "00" * 32}, expected=404)
    recovery("boolean-iat", changes={"iat": True}, expected=404)
    recovery("expired", changes={"iat": ref.NOW - 100, "exp": ref.NOW - 40}, expected=404)
    recovery("future", changes={"iat": ref.NOW + 31, "exp": ref.NOW + 91}, expected=404)
    recovery("duplicate-signed-claim", duplicate=True, expected=404)
    recovery(
        "unknown-key",
        changes={"kid": stranger.device_key_id},
        key=stranger,
        known=False,
        expected=404,
    )
    recovery("forged-known-key", key=stranger, expected=404)
    recovery("wrong-prefix", path=b"/api/mycarlos/link", expected=404)
    recovery("wrong-method", method="POST", expected=404)
    recovery("wrong-query", query=b"changed=1", expected=404)
    recovery("nonempty-body", body=b"{}", expected=404)
    recovery("nonce-replay", replay=True, expected=404)
    recovery("fresh-valid-removed", removed=True, expected=403)
    recovery(
        "expired-removed-is-generic",
        removed=True,
        changes={"iat": ref.NOW - 100, "exp": ref.NOW - 40},
        expected=404,
    )
    recovery("replayed-removed-is-generic", removed=True, replay=True, expected=404)
    recovery("missing-account", account=False, expected=404)
    recovery("missing-recipient", recipient=False, expected=404)

    return {
        "description": (
            "FAKE shared link lifecycle v1 byte vectors; generated once by "
            "tests/link_lifecycle_reference.py and copied unchanged. No real patient or "
            "production key. Fixed scenario clock; do not use these test seeds operationally."
        ),
        "fixture_version": 1,
        "frozen_contract_sha256": CONTRACT_SHA256,
        "existing_delivery_fixture_sha256": hashlib.sha256(
            ref.FIXTURE_PATH.read_bytes()
        ).hexdigest(),
        "constants": {
            "replacement_domain_hex": REPLACEMENT_DOMAIN.hex(),
            "frame_length_bytes": 8,
            "recovery_audience": RECOVERY_AUDIENCE,
            "recovery_route": "/api/mycarlos/link",
            "refresh_route": "/api/mycarlos/clinic-keys",
            "maximum_keys": 16,
            "maximum_edges": 15,
            "signature_bytes": 64,
            "accept_high_and_low_s": True,
            "now": ref.NOW,
        },
        "keys": {
            **{name: key.described() for name, key in keys.items()},
            "unicode_predecessor": ua.described(),
            "unicode_successor": ub.described(),
        },
        "device": device.described(),
        "unknown_device": stranger.described(),
        "proof_vectors": proofs,
        "inventory_vectors": inventories,
        "recovery_vectors": assertions,
        "state_cases": [
            {
                "name": "pending-recovery-after-restart",
                "expect": (
                    "Reuse persisted original keys, bind returned device, save link/history "
                    "atomically; never reuse code."
                ),
            },
            {
                "name": "completed-link-never-recovers",
                "expect": "No recovery request; preserve pinned trust and use refresh.",
            },
            {
                "name": "lock-or-stale-trust-revision",
                "expect": (
                    "Cancel pending result; no partial keys/notices/history/document-result "
                    "mutation."
                ),
            },
            {
                "name": "unsigned-notice-durability",
                "expect": (
                    "Persist root and accepted descendant fingerprints with plain notice/history "
                    "before trust can produce Verified; no acknowledgment gate."
                ),
            },
            {
                "name": "cross-origin-redirect",
                "expect": "No follow-up request and no completed link.",
            },
            {
                "name": "remove-during-recovery",
                "expect": (
                    "Fresh account then device lock/recheck gives removed403 if removal committed "
                    "first; never resurrect."
                ),
            },
            {
                "name": "first-publish-concurrency",
                "expect": (
                    "Stable clinic mutex precedes full proof/graph/count validation even when "
                    "inventory was empty."
                ),
            },
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = (json.dumps(generate(), ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if args.check:
        if not FIXTURE.exists() or FIXTURE.read_bytes() != generated:
            raise SystemExit("link lifecycle fixture differs from canonical generator")
    else:
        FIXTURE.write_bytes(generated)
    print(hashlib.sha256(generated).hexdigest(), FIXTURE.name)


if __name__ == "__main__":
    main()
