# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Affero General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

"""ONE test-only M4 byte fixture; never imported by production code.

M0 supplies the unchanged real FAKE sealed package and signed device proofs. This
generator adds transport framing, request hashes, strict parser cases and exact
event/ack bytes. It does not claim HPKE, custody, database or clinical verification.
Generate/check ONLY under Root's authorized resource slot. No keys or randomness.
"""

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

M0_SHA = "e342041d5620238e6e0b8ae0aa0b767b51965fb839aee671600b8a0d63e90016"
CONTRACT_SHA = "d01777267371530ea49654eb183a5c845c503ea5bf2259c42f7de43c4e9c1148"
FIXTURES = Path(__file__).parent / "fixtures"
OUTPUT = FIXTURES / "mailbox-contract-v1.json"
MAX_COPY = 20 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def frame(*parts):
    return b"".join(len(part).to_bytes(8, "big") + part for part in parts)


def encoded(raw):
    return {"hex": raw.hex(), "size": len(raw), "sha256": digest(raw)}


def build():
    raw = (FIXTURES / "delivery-contract.json").read_bytes()
    assert digest(raw) == M0_SHA
    m0 = json.loads(raw)
    package = m0["packages"]["accept"][0]
    outer = package["outer"]
    sealed = base64.urlsafe_b64decode(package["blob"] + "=" * (-len(package["blob"]) % 4))
    assert len(sealed) == outer["size"] and digest(sealed) == outer["ciphertext_sha256"]
    outer_bytes = canonical(outer)
    upload = frame(outer_bytes, sealed)
    cases = []

    def upload_case(name, body, expect, expected_outer=None):
        case = {"name": name, "body": encoded(body), "expect": expect}
        if expected_outer is not None:
            case["outer"] = expected_outer
        cases.append(case)

    upload_case("unchanged M0 package in exactly two frames", upload, "accept", outer)
    reordered = json.dumps(outer, indent=1, sort_keys=False).encode("utf-8")
    upload_case("signed upload outer need not be raw JCS", frame(reordered, sealed), "accept", outer)
    for name, body in [
        ("missing both lengths", b""),
        ("truncated first uint64", b"\x00" * 7),
        ("first declared length exceeds available", (4096).to_bytes(8, "big") + b"{}"),
        ("outer declared length4097", (4097).to_bytes(8, "big")),
        ("outer declared length uint64 max", b"\xff" * 8),
        ("missing second frame", frame(outer_bytes)),
        ("truncated second length", frame(outer_bytes) + b"\x00" * 7),
        ("second declared length20MiBplus1", frame(outer_bytes) + (MAX_COPY + 1).to_bytes(8, "big")),
        ("second declared length uint64 max", frame(outer_bytes) + b"\xff" * 8),
        ("truncated sealed copy", upload[:-1]),
        ("trailing byte", upload + b"x"),
        ("third empty frame", upload + b"\x00" * 8),
        ("invalid UTF8 outer", frame(b"\xff", sealed)),
        ("outer array", frame(b"[]", sealed)),
        ("duplicate outer v", frame(b'{"v":1,' + outer_bytes[1:], sealed)),
        ("nested suite duplicate", frame(outer_bytes.replace(b'"aead_id":3', b'"aead_id":3,"aead_id":3'), sealed)),
    ]:
        upload_case(name, body, "invalid_delivery")
    changes = [
        ("boolean version", "v", True), ("float version", "v", 1.0),
        ("unknown version", "v", 2), ("boolean size", "size", True),
        ("float time", "created_at", float(outer["created_at"])),
        ("negative time", "created_at", -1),
        ("wrong hash", "ciphertext_sha256", "00" * 32),
        ("uppercase hash", "ciphertext_sha256", outer["ciphertext_sha256"].upper()),
        ("wrong declared size", "size", len(sealed) + 1),
        ("UUIDv1", "delivery_id", "6f1c2a7e-0b9d-1e53-8a41-2d7c9b0e5f13"),
        ("uppercase UUID", "delivery_id", outer["delivery_id"].upper()),
        ("recipient65", "recipient_id", "a" * 65),
        ("unicode recipient", "recipient_id", "cliniqué"),
        ("padded device kid", "device_key_id", outer["device_key_id"] + "="),
        ("unknown suite", "suite", {"kem_id": 32, "kdf_id": 1, "aead_id": 4}),
        ("boolean suite id", "suite", {"kem_id": 32, "kdf_id": True, "aead_id": 3}),
        ("lifetime seven days plus1", "expires_at", outer["created_at"] + 604801),
        ("zero lifetime", "expires_at", outer["created_at"]),
    ]
    for name, key, value in changes:
        bad = copy.deepcopy(outer); bad[key] = value
        upload_case(name, frame(canonical(bad), sealed), "invalid_delivery")
    for name, change in [
        ("missing outer field", lambda value: value.pop("recipient_id")),
        ("unknown outer field", lambda value: value.update(title="FAKE forbidden metadata")),
        ("unknown suite field", lambda value: value["suite"].update(alg="unknown")),
    ]:
        bad = copy.deepcopy(outer); change(bad)
        upload_case(name, frame(canonical(bad), sealed), "invalid_delivery")
    for length, expect in [(48, "invalid_delivery"), (49, "accept")]:
        blob = b"\xa5" * length
        value = dict(outer, size=length, ciphertext_sha256=digest(blob))
        upload_case(f"opaque sealed copy length{length}", frame(canonical(value), blob), expect,
                    value if expect == "accept" else None)

    requests = []
    for name, method, path, query, body in [
        ("binary upload prefixed", "POST", b"/patients/internal/carlos/patients/6001/mycarlos/deliveries", b"", upload),
        ("binary upload missing external prefix", "POST", b"/internal/carlos/patients/6001/mycarlos/deliveries", b"", upload),
        ("binary upload changed final byte", "POST", b"/patients/internal/carlos/patients/6001/mycarlos/deliveries", b"", upload[:-1] + bytes([upload[-1] ^ 1])),
        ("event feed raw query", "GET", b"/patients/internal/carlos/mycarlos/delivery-events", b"after=7&limit=25", b""),
        ("event feed reordered raw query", "GET", b"/patients/internal/carlos/mycarlos/delivery-events", b"limit=25&after=7", b""),
        ("event ack", "POST", b"/patients/internal/carlos/mycarlos/delivery-events/ack", b"", b'{"through":"7"}'),
    ]:
        requests.append({"name": name, "method": method, "raw_path_hex": path.hex(),
                         "raw_query_hex": query.hex(), "body": encoded(body),
                         "request_hash": digest(frame(method.encode("ascii"), path, query, body))})

    cursor = []
    for value, expect in [("0", "accept"), ("7", "accept"), ("9223372036854775807", "accept"),
                          ("01", "invalid_cursor"), ("-1", "invalid_cursor"), ("+1", "invalid_cursor"),
                          ("1.0", "invalid_cursor"), ("1e0", "invalid_cursor"), (" 1", "invalid_cursor"),
                          ("١", "invalid_cursor"), ("9223372036854775808", "invalid_cursor")]:
        cursor.append({"text": value, "expect": expect})
    acks = []
    for body, expect in [(b'{"through":"7"}', "accept"), (b'{ "through" : "7" }', "accept"),
                         (b'{"through":7}', "invalid_cursor"), (b'{"through":true}', "invalid_cursor"),
                         (b'{"through":"07"}', "invalid_cursor"), (b'{}', "invalid_cursor"),
                         (b'{"through":"7","through":"7"}', "invalid_cursor"),
                         (b'{"through":"7","other":0}', "invalid_cursor")]:
        acks.append({"body": encoded(body), "expect": expect})

    receipt = next(v["receipt"] for v in m0["portal"]["receipts"] if v["expect"] == "accept")
    assertion = next(v["assertion"] for v in m0["portal"]["device_requests"] if v["name"] == "send the receipt")
    anchor_assertion = next(v["assertion"] for v in m0["portal"]["device_requests"] if v["name"] == "check in with the vault head anchor")
    receipt_payload = receipt.split(".")[0]
    receipt_claims = json.loads(base64.urlsafe_b64decode(receipt_payload + "=" * (-len(receipt_payload) % 4)))
    events = []
    copy_payload = {key: outer[key] for key in ("ciphertext_sha256", "size", "created_at", "expires_at")}
    for sequence, kind in enumerate(("picked_up", "expired", "removed", "device_removed", "anchor"), 1):
        payload = dict(copy_payload) if kind in {"picked_up", "expired", "removed"} else {}
        if kind == "picked_up": payload.update(receipt=receipt, request_assertion=assertion)
        if kind == "anchor": payload.update(vault_head_link=receipt_claims["vault_head_link"], request_assertion=anchor_assertion)
        event = {"sequence": str(sequence), "kind": kind, "occurred_at": m0["portal"]["state"]["now"],
                 "recipient_id": outer["recipient_id"], "device_key_id": outer["device_key_id"],
                 "delivery_id": outer["delivery_id"] if kind in {"picked_up", "expired", "removed"} else None,
                 "payload": payload}
        events.append({"name": kind, "json": encoded(canonical(event)), "expect": "accept",
                       "proof_note": "Original M0 signed bytes; delayed collector checks signatures/bindings, not present-day request freshness."})
    base_event = json.loads(bytes.fromhex(events[0]["json"]["hex"]))
    for name, key, value in [
        ("unknown kind", "kind", "unknown"), ("numeric sequence", "sequence", 1),
        ("zero event sequence", "sequence", "0"), ("boolean occurrence", "occurred_at", True),
        ("UUIDv1 event", "delivery_id", "6f1c2a7e-0b9d-1e53-8a41-2d7c9b0e5f13"),
        ("null delivery for pickup", "delivery_id", None),
        ("recipient65 event", "recipient_id", "a" * 65),
        ("unknown top field", "other", 0),
    ]:
        value_event = copy.deepcopy(base_event); value_event[key] = value
        events.append({"name": name, "json": encoded(canonical(value_event)), "expect": "reject"})
    for name, edit in [
        ("missing receipt proof", lambda value: value["payload"].pop("receipt")),
        ("unknown payload field", lambda value: value["payload"].update(title="forbidden")),
        ("missing envelope field", lambda value: value.pop("recipient_id")),
    ]:
        value_event = copy.deepcopy(base_event); edit(value_event)
        events.append({"name": name, "json": encoded(canonical(value_event)), "expect": "reject"})
    events.append({"name": "duplicate event sequence", "json": encoded(b'{"sequence":"1",' + canonical(base_event)[1:]), "expect": "reject"})
    return {"description": "FAKE shared M4 transport bytes; no database/custody/end-to-end success implied",
            "format_version": 1, "frozen_contract_sha256": CONTRACT_SHA, "m0_sha256": M0_SHA,
            "binary_encoding": "hex is exact; sha256 covers full decoded bytes; no JSON/body reserialization before hashing",
            "limits": {"outer_max": 4096, "sealed_min": 49, "sealed_max": MAX_COPY,
                       "body_max": MAX_COPY + 4096 + 16, "event_max": 16384, "event_page_max": 1048576},
            "uploads": cases, "request_hashes": requests, "cursors": cursor, "ack_bodies": acks,
            "events": events,
            "event_scenario_note": "The five accepted event examples are ALTERNATIVE independent shape/proof vectors, not one state feed. One copy cannot terminate as picked_up, expired and removed together. Bound constants are not large-body consumer execution proof.",
            "semantic_expectations_only": ["known exact body after expiry200 without resurrection", "removed upload409 before known idempotency", "same receipt200 and different receipt404 throughout tombstone retention", "retained exact anchor proof survives event pruning", "committed-prefix and quota/race/crash proofs require real PostgreSQL"]}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = json.dumps(build(), indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    if args.check:
        assert OUTPUT.read_bytes() == output, "shared fixture differs; never silently overwrite approved bytes"
    else:
        with OUTPUT.open("xb") as destination:
            destination.write(output)
    print(digest(output))


if __name__ == "__main__":
    main()
