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

"""Reference vectors for `mycarlos-send/1` (patient to clinic); never imported by production code.

DRAFT for review (docs/architecture/mycarlos-send.md). No server code exists for this contract. This
generator uses only the standard library, no keys and no randomness: every identifier, hash and
"ciphertext" below is FAKE and fixed. It produces:

- the byte-exact framing, hash-chain, nonce and AAD derivations the three implementations
  (carlos-portal, CARLOS, myCarlos) must agree on, with cases that must NOT agree;
- canonical bytes (and their hashes) of an outer record, an envelope and the three acknowledgements;
- a small reference validator for the outer record and the envelope, and the accept/refuse cases it
  gives, so a second implementation can be tested against the same list;
- the state machine, the idempotency table and the routes, as data.

It does not do HPKE, AEAD, signatures, storage or any clinical check: signing inputs are given as
bytes, and a signature is never produced here. Regenerate with no arguments (refuses to overwrite an
approved file); verify with `--check`.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
OUTPUT = FIXTURES / "send-contract-v1.json"

VERSION = 1
MIB = 1024 * 1024

# Ceilings the PARSER enforces, whatever a deployment enables. A deployment advertises smaller
# working limits in its capabilities; a larger one needs a new contract version.
LIMITS = {
    "envelope_sealed_max": 64 * 1024,
    "body_max_bytes": 8192,
    "attachments_max": 10,
    "name_max_chars": 120,
    "chunk_plain_max": 4 * MIB,
    "aead_tag": 16,
    "lifetime_max_seconds": 7 * 24 * 3600,
    "manifest_max_bytes": 16 * 1024,
    "ref_max_chars": 64,
    "ack_max_bytes": 4096,
    "outer_max_bytes": 8192,
    "chunks_per_attachment_max": 128,
}

# What a deployment may turn on. Phase 1 fits database blobs; phase 2 (video) needs object storage.
PHASES = {
    "phase1": {
        "attachment_max_bytes": 20 * MIB,
        "message_max_bytes": 64 * MIB,
        "media_types": ["application/pdf", "image/jpeg", "image/png", "image/heic"],
        "storage": "database_blobs",
    },
    "phase2_video": {
        "attachment_max_bytes": 512 * MIB,
        "message_max_bytes": 1024 * MIB,
        "media_types": [
            "application/pdf",
            "image/jpeg",
            "image/png",
            "image/heic",
            "video/mp4",
            "video/quicktime",
            "video/webm",
        ],
        "storage": "object_store",
    },
}
ALL_MEDIA_TYPES = PHASES["phase2_video"]["media_types"]

# Fixed FAKE identifiers (UUID version 4 shape).
MESSAGE_ID = "5b0f6f0a-1c3d-4e8a-9a41-0d1e2f3a4b5c"
OTHER_MESSAGE_ID = "6c1a7a1b-2d4e-4f9b-8b52-1e2f3a4b5c6d"
CONVERSATION_ID = MESSAGE_ID
ATTACHMENT_A = "7d2b8b2c-3e5f-4a0c-9c63-2f3a4b5c6d7e"
ATTACHMENT_B = "8e3c9c3d-4f60-4b1d-ad74-3a4b5c6d7e8f"
DELIVERY_ID = "9f4dad4e-5071-4c2e-be85-4b5c6d7e8f90"
CLINIC_ID = "clinic-FAKE0001"
RECIPIENT_ID = "rcp-FAKE0001aaaaaaaaaaaa"
DEVICE_KEY_ID = "FAKEdevicekeyidFAKEdevicekeyidFAKEdevicekeyid0"
CLINIC_KID = "FAKEclinickidFAKEclinickidFAKEclinickidFAKEcl0"
INBOX_KID = "FAKEinboxkidFAKEinboxkidFAKEinboxkidFAKEinbo0"
CREATED_AT = 1_792_450_800
EXPIRES_AT = CREATED_AT + 3 * 24 * 3600

UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
OPAQUE_REF = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def canonical(value):
    """The bytes every object is hashed and signed as: sorted keys, no spaces, UTF-8, integers and
    strings only (so this equals RFC 8785 for every object of this contract)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def digest(value):
    return hashlib.sha256(value).hexdigest()


def frame(*parts):
    """Each part, preceded by its length as eight bytes, big endian (the other contracts' frame)."""
    return b"".join(len(part).to_bytes(8, "big") + part for part in parts)


def uuid_bytes(text):
    return bytes.fromhex(text.replace("-", ""))


def encoded(raw):
    return {"hex": raw.hex(), "size": len(raw), "sha256": digest(raw)}


# --- the hash chain -----------------------------------------------------------------------------


def chain_start(message_id, attachment_id, chunk_count):
    return hashlib.sha256(
        frame(
            b"mycarlos-send/1 chain-start",
            uuid_bytes(message_id),
            uuid_bytes(attachment_id),
            chunk_count.to_bytes(8, "big"),
        )
    ).digest()


def chain_link(previous, index, chunk_sha256):
    return hashlib.sha256(
        frame(b"mycarlos-send/1 chain-link", previous, index.to_bytes(8, "big"), chunk_sha256)
    ).digest()


def attachment_head(message_id, attachment_id, chunk_ciphertexts):
    """The chain over the SHA-256 of each sealed chunk, in order, bound to the message, the
    attachment and the chunk count: a dropped, repeated, reordered or borrowed chunk changes it."""
    head = chain_start(message_id, attachment_id, len(chunk_ciphertexts))
    for index, chunk in enumerate(chunk_ciphertexts):
        head = chain_link(head, index, hashlib.sha256(chunk).digest())
    return head


def message_head(message_id, envelope_ciphertext, attachment_heads):
    return hashlib.sha256(
        frame(
            b"mycarlos-send/1 message",
            uuid_bytes(message_id),
            hashlib.sha256(envelope_ciphertext).digest(),
            *attachment_heads,
        )
    ).digest()


def fake_chunks(seed, sizes):
    """FAKE 'sealed chunks': fixed bytes of the right sizes; the chain never looks inside."""
    return [bytes([seed + index]) * size for index, size in enumerate(sizes)]


# --- AEAD inputs (bytes only: no cipher runs here) ----------------------------------------------

ENVELOPE_ATTACHMENT_INDEX = 0xFFFFFFFF


def nonce(attachment_index, chunk_index):
    """4 bytes of the attachment's position (all ones for the envelope), then 8 of the chunk's."""
    return attachment_index.to_bytes(4, "big") + chunk_index.to_bytes(8, "big")


def chunk_aad(message_id, attachment_id, chunk_index, chunk_count):
    return frame(
        b"mycarlos-send/1 chunk",
        uuid_bytes(message_id),
        uuid_bytes(attachment_id),
        chunk_index.to_bytes(8, "big"),
        chunk_count.to_bytes(8, "big"),
    )


def envelope_aad(message_id, recipient_id, device_key_id, clinic_id):
    return frame(
        b"mycarlos-send/1 envelope",
        uuid_bytes(message_id),
        recipient_id.encode(),
        device_key_id.encode(),
        clinic_id.encode(),
    )


def key_aad(message_id, recipient_id, device_key_id, clinic_id, envelope_sha256):
    """The AAD of the HPKE seal of the message's content key to the clinic inbox key."""
    return frame(
        b"mycarlos-send/1 key",
        uuid_bytes(message_id),
        recipient_id.encode(),
        device_key_id.encode(),
        clinic_id.encode(),
        envelope_sha256,
    )


# --- the objects --------------------------------------------------------------------------------


def attachment(attachment_id, name, media_type, size, plaintext_sha256, chunk_count, head, prov):
    return {
        "attachment_id": attachment_id,
        "chain_head": head,
        "chunk_count": chunk_count,
        "chunk_size": LIMITS["chunk_plain_max"],
        "media_type": media_type,
        "name": name,
        "provenance": prov,
        "sha256": plaintext_sha256,
        "size": size,
    }


def envelope_object(attachments, body="FAKE message: please see the attached FAKE results."):
    return {
        "attachments": attachments,
        "body": body,
        "clinic_id": CLINIC_ID,
        "conversation_id": CONVERSATION_ID,
        "created_at": CREATED_AT,
        "device_key_id": DEVICE_KEY_ID,
        "expires_at": EXPIRES_AT,
        "in_reply_to": None,
        "message_id": MESSAGE_ID,
        "recipient_id": RECIPIENT_ID,
        "typ": "mycarlos-send-envelope",
        "v": VERSION,
    }


def outer_object(envelope_ciphertext, attachments_visible, chain_head, sealed_key):
    chunk_total = sum(item["chunk_count"] for item in attachments_visible)
    return {
        "attachment_count": len(attachments_visible),
        "attachments": attachments_visible,
        "chain_head": chain_head,
        "chunk_total": chunk_total,
        "clinic_id": CLINIC_ID,
        "created_at": CREATED_AT,
        "device_key_id": DEVICE_KEY_ID,
        "envelope_sha256": digest(envelope_ciphertext),
        "envelope_size": len(envelope_ciphertext),
        "expires_at": EXPIRES_AT,
        "kind": "documents" if attachments_visible else "message",
        "message_id": MESSAGE_ID,
        "recipient_id": RECIPIENT_ID,
        "sealed_key": sealed_key,
        "sealed_key_kid": INBOX_KID,
        "total_size": len(envelope_ciphertext) + sum(item["size"] for item in attachments_visible),
        "typ": "mycarlos-send-outer",
        "v": VERSION,
    }


def ack_object(state, reason=None, ref="ref-FAKE0001", at=CREATED_AT + 600, head=None):
    return {
        "at": at,
        "chain_head": head,
        "clinic_id": CLINIC_ID,
        "device_key_id": DEVICE_KEY_ID,
        "kid": CLINIC_KID,
        "message_id": MESSAGE_ID,
        "reason": reason,
        "recipient_id": RECIPIENT_ID,
        "ref": ref,
        "state": state,
        "typ": "mycarlos-send-ack",
        "v": VERSION,
    }


# --- the reference validator (the contract in code) ---------------------------------------------

OUTER_FIELDS = {
    "attachment_count",
    "attachments",
    "chain_head",
    "chunk_total",
    "clinic_id",
    "created_at",
    "device_key_id",
    "envelope_sha256",
    "envelope_size",
    "expires_at",
    "kind",
    "message_id",
    "recipient_id",
    "sealed_key",
    "sealed_key_kid",
    "total_size",
    "typ",
    "v",
}
VISIBLE_ATTACHMENT_FIELDS = {"chain_head", "chunk_count", "index", "size"}
ENVELOPE_FIELDS = {
    "attachments",
    "body",
    "clinic_id",
    "conversation_id",
    "created_at",
    "device_key_id",
    "expires_at",
    "in_reply_to",
    "message_id",
    "recipient_id",
    "typ",
    "v",
}
ATTACHMENT_FIELDS = {
    "attachment_id",
    "chain_head",
    "chunk_count",
    "chunk_size",
    "media_type",
    "name",
    "provenance",
    "sha256",
    "size",
}
ACK_FIELDS = {
    "at",
    "chain_head",
    "clinic_id",
    "device_key_id",
    "kid",
    "message_id",
    "reason",
    "recipient_id",
    "ref",
    "state",
    "typ",
    "v",
}
REFUSAL_REASONS = [
    "unsupported_version",
    "bad_signature",
    "device_not_accepted",
    "clinic_mismatch",
    "expired",
    "too_large",
    "type_not_allowed",
    "active_content",
    "scan_failed",
    "chain_mismatch",
    "hash_mismatch",
    "duplicate_message",
    "owner_group_missing",
    "not_enabled",
]


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def has_control(text):
    return any(ord(c) < 32 and c != "\n" or ord(c) == 127 for c in text)


def check_outer(obj, working=PHASES["phase1"]):
    """None when the outer record is acceptable, else the first reason (a stable name)."""
    if not isinstance(obj, dict):
        return "not_object"
    if is_int(obj.get("v")) and obj["v"] != VERSION:
        return "unsupported_version"
    if set(obj) != OUTER_FIELDS:
        return "unknown_or_missing_field"
    if obj["typ"] != "mycarlos-send-outer" or obj["kind"] not in ("message", "documents"):
        return "bad_type"
    for field in ("message_id",):
        if not isinstance(obj[field], str) or not UUID4.match(obj[field]):
            return "bad_id"
    for field in ("chain_head", "envelope_sha256"):
        if not isinstance(obj[field], str) or not HEX64.match(obj[field]):
            return "bad_hash"
    if not isinstance(obj["sealed_key"], str) or not B64URL.match(obj["sealed_key"]):
        return "bad_sealed_key"
    for field in ("created_at", "expires_at", "envelope_size", "total_size", "chunk_total"):
        if not is_int(obj[field]) or obj[field] < 0:
            return "bad_number"
    if obj["expires_at"] <= obj["created_at"]:
        return "bad_lifetime"
    if obj["expires_at"] - obj["created_at"] > LIMITS["lifetime_max_seconds"]:
        return "lifetime_too_long"
    if not 49 <= obj["envelope_size"] <= LIMITS["envelope_sealed_max"]:
        return "envelope_size"
    items = obj["attachments"]
    if not isinstance(items, list) or len(items) != obj["attachment_count"]:
        return "attachment_count"
    if len(items) > LIMITS["attachments_max"]:
        return "too_many_attachments"
    if (obj["kind"] == "message") != (len(items) == 0):
        return "kind_mismatch"
    chunks = 0
    size = obj["envelope_size"]
    for position, item in enumerate(items):
        if not isinstance(item, dict) or set(item) != VISIBLE_ATTACHMENT_FIELDS:
            return "unknown_or_missing_field"
        if item["index"] != position:
            return "attachment_order"
        if not isinstance(item["chain_head"], str) or not HEX64.match(item["chain_head"]):
            return "bad_hash"
        if not is_int(item["chunk_count"]) or not (
            1 <= item["chunk_count"] <= LIMITS["chunks_per_attachment_max"]
        ):
            return "bad_chunk_count"
        if not is_int(item["size"]) or item["size"] < item["chunk_count"] * LIMITS["aead_tag"]:
            return "bad_size"
        # Sealed size: at most the plain chunks plus a tag each.
        most = item["chunk_count"] * (LIMITS["chunk_plain_max"] + LIMITS["aead_tag"])
        if item["size"] > most:
            return "bad_size"
        if (
            item["size"]
            > working["attachment_max_bytes"] + item["chunk_count"] * LIMITS["aead_tag"]
        ):
            return "too_large"
        chunks += item["chunk_count"]
        size += item["size"]
    if chunks != obj["chunk_total"] or size != obj["total_size"]:
        return "totals_mismatch"
    if obj["total_size"] > working["message_max_bytes"]:
        return "too_large"
    return None


def check_envelope(obj, working=PHASES["phase1"]):
    """None when the (decrypted, signature-checked elsewhere) envelope is acceptable."""
    if not isinstance(obj, dict):
        return "not_object"
    if is_int(obj.get("v")) and obj["v"] != VERSION:
        return "unsupported_version"
    if set(obj) != ENVELOPE_FIELDS:
        return "unknown_or_missing_field"
    if obj["typ"] != "mycarlos-send-envelope":
        return "bad_type"
    for field in ("message_id", "conversation_id"):
        if not isinstance(obj[field], str) or not UUID4.match(obj[field]):
            return "bad_id"
    if obj["in_reply_to"] is not None:
        return "reply_not_supported"  # reserved: null in v1
    if not is_int(obj["created_at"]) or not is_int(obj["expires_at"]):
        return "bad_number"
    if obj["expires_at"] <= obj["created_at"]:
        return "bad_lifetime"
    if obj["expires_at"] - obj["created_at"] > LIMITS["lifetime_max_seconds"]:
        return "lifetime_too_long"
    body = obj["body"]
    if not isinstance(body, str) or len(body.encode("utf-8")) > LIMITS["body_max_bytes"]:
        return "body_too_long"
    if has_control(body):
        return "body_control_characters"
    items = obj["attachments"]
    if not isinstance(items, list) or len(items) > LIMITS["attachments_max"]:
        return "too_many_attachments"
    if not body.strip() and not items:
        return "empty_message"
    seen = set()
    total = 0
    for item in items:
        if not isinstance(item, dict) or set(item) != ATTACHMENT_FIELDS:
            return "unknown_or_missing_field"
        if not isinstance(item["attachment_id"], str) or not UUID4.match(item["attachment_id"]):
            return "bad_id"
        if item["attachment_id"] in seen:
            return "duplicate_attachment_id"
        seen.add(item["attachment_id"])
        name = item["name"]
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= LIMITS["name_max_chars"]
            or any(c in name for c in "/\\:\x00")
            or has_control(name)
            or name in (".", "..")
        ):
            return "bad_name"
        if item["media_type"] not in working["media_types"]:
            return "type_not_allowed"
        if not is_int(item["size"]) or not 1 <= item["size"] <= working["attachment_max_bytes"]:
            return "too_large"
        total += item["size"]
        if not isinstance(item["sha256"], str) or not HEX64.match(item["sha256"]):
            return "bad_hash"
        if not isinstance(item["chain_head"], str) or not HEX64.match(item["chain_head"]):
            return "bad_hash"
        if item["chunk_size"] != LIMITS["chunk_plain_max"]:
            return "bad_chunk_size"
        expected_chunks = -(-item["size"] // item["chunk_size"])
        if item["chunk_count"] != expected_chunks:
            return "bad_chunk_count"
        prov = item["provenance"]
        if not isinstance(prov, dict) or prov.get("kind") not in (
            "patient-original",
            "clinic-signed-copy",
        ):
            return "bad_provenance"
        if prov["kind"] == "patient-original":
            if set(prov) != {"kind"}:
                return "bad_provenance"
        else:
            if set(prov) != {"kind", "delivery_id", "manifest"}:
                return "bad_provenance"
            if not isinstance(prov["delivery_id"], str) or not UUID4.match(prov["delivery_id"]):
                return "bad_id"
            manifest = prov["manifest"]
            if (
                not isinstance(manifest, str)
                or len(manifest.encode()) > LIMITS["manifest_max_bytes"]
                or manifest.count(".") != 1
            ):
                return "bad_manifest"
            if item["media_type"] != "application/pdf":
                return "type_not_allowed"
    if total > working["message_max_bytes"]:
        return "too_large"
    return None


def check_ack(obj):
    if not isinstance(obj, dict):
        return "not_object"
    if is_int(obj.get("v")) and obj["v"] != VERSION:
        return "unsupported_version"
    if set(obj) != ACK_FIELDS:
        return "unknown_or_missing_field"
    if obj["typ"] != "mycarlos-send-ack" or obj["state"] not in ("collected", "filed", "refused"):
        return "bad_type"
    if (obj["state"] == "refused") != (obj["reason"] is not None):
        return "reason_mismatch"
    if obj["reason"] is not None and obj["reason"] not in REFUSAL_REASONS:
        return "bad_reason"
    if not isinstance(obj["ref"], str) or not OPAQUE_REF.match(obj["ref"]):
        return "bad_ref"
    if not isinstance(obj["chain_head"], str) or not HEX64.match(obj["chain_head"]):
        return "bad_hash"
    if not is_int(obj["at"]) or obj["at"] < 0:
        return "bad_number"
    return None


# State the app shows, and what each means (the words never say read, reviewed or seen).
STATES = {
    "queued": {
        "set_by": "app",
        "means": "kept in the sent record; nothing has been sent yet",
        "never_means": "that anything left this device",
    },
    "sending": {
        "set_by": "app",
        "means": "parts are being uploaded; resumes where it stopped",
        "never_means": "that the portal has all of it",
    },
    "received": {
        "set_by": "portal (reply the app checks: message_id, chain_head, received_at)",
        "means": "the portal holds every part and the chain checked; it cannot read them",
        "never_means": "that the clinic has it",
    },
    "collected": {
        "set_by": "clinic system, by a signed acknowledgement (state collected)",
        "means": "the clinic's system fetched, opened and checked the message",
        "never_means": "filed, seen or read by anyone",
    },
    "filed": {
        "set_by": "clinic system, by a signed acknowledgement (state filed)",
        "means": "stored in the clinic's pending-review queue for staff",
        "never_means": "that any staff member has read, reviewed or acted on it",
    },
    "refused": {
        "set_by": "portal (limits, device) or clinic system (signed acknowledgement with a reason)",
        "means": "not accepted, with one reason from a fixed list; nothing is kept",
        "never_means": "a judgement about the content",
    },
    "expired": {
        "set_by": "app or portal, when expires_at passes before the clinic collected it",
        "means": "the portal deleted what it held; the sent record keeps that it expired",
        "never_means": "that it was delivered",
    },
    "recalled": {
        "set_by": "clinic system, by a signed acknowledgement after a recall request",
        "means": "removed from the pending-review queue before it was accepted into a chart",
        "never_means": "that nobody saw it",
    },
}
TRANSITIONS = {
    "queued": ["sending", "cancelled"],
    "sending": ["received", "cancelled", "expired", "refused"],
    "received": ["collected", "refused", "expired", "recalled"],
    "collected": ["filed", "refused", "expired", "recalled"],
    "filed": ["recalled"],
    "refused": [],
    "expired": [],
    "recalled": [],
    "cancelled": [],
}

ROUTES = [
    ["GET", "/api/mycarlos/send-capabilities", "device assertion", "200; 404 when not enabled"],
    [
        "POST",
        "/api/mycarlos/sends",
        "device assertion; body is the JCS outer record",
        "201, 200, 409 send_conflict",
    ],
    [
        "PUT",
        "/api/mycarlos/sends/{message_id}/envelope",
        "device assertion; body the sealed envelope",
        "200, 409 chunk_conflict",
    ],
    [
        "PUT",
        "/api/mycarlos/sends/{message_id}/attachments/{a}/chunks/{n}",
        "device assertion; body one sealed chunk",
        "200, 409 chunk_conflict, 413",
    ],
    [
        "GET",
        "/api/mycarlos/sends/{message_id}",
        "device assertion",
        "200 with state and received parts; 404",
    ],
    [
        "POST",
        "/api/mycarlos/sends/{message_id}/complete",
        "device assertion; empty body",
        "200 received; 422 chain_mismatch",
    ],
    [
        "POST",
        "/api/mycarlos/sends/{message_id}/cancel",
        "device assertion; empty body",
        "200 cancelled; 200 recall_requested after received",
    ],
    ["GET", "/api/mycarlos/sends", "device assertion; ?after&limit (max 50)", "200 list of states"],
    [
        "POST",
        "/internal/carlos/mycarlos/sends/claim",
        "job send-sync, portal.mycarlos.send.claim",
        "200 claims with lease tokens",
    ],
    [
        "GET",
        "/internal/carlos/mycarlos/sends/{id}/parts/{part}",
        "job send-sync, portal.mycarlos.send.read; lease token",
        "200 octet-stream; 404",
    ],
    [
        "POST",
        "/internal/carlos/mycarlos/sends/{id}/result",
        "job send-sync, portal.mycarlos.send.result; lease token",
        "200, 409 lease_expired or conflict, 404",
    ],
]

IDEMPOTENCY = [
    ["create", "first request", 201, "created"],
    ["create", "same outer record, byte for byte", 200, "nothing written"],
    ["create", "same message_id, different outer record", 409, "send_conflict; nothing changed"],
    ["envelope or chunk", "first time", 200, "stored"],
    ["envelope or chunk", "same bytes again", 200, "nothing written"],
    [
        "envelope or chunk",
        "different bytes for the same place",
        409,
        "chunk_conflict; nothing changed",
    ],
    ["complete", "all parts present and the chain matches", 200, "state received"],
    ["complete", "again, once received", 200, "unchanged"],
    [
        "complete",
        "a part missing or a hash that does not chain",
        422,
        "chain_mismatch or missing parts listed",
    ],
    ["cancel", "before received", 200, "everything deleted; state cancelled"],
    ["cancel", "after received", 200, "recall_requested; the clinic decides"],
    ["result", "same outcome and acknowledgement again", 200, "recorded: false"],
    ["result", "a different outcome for a finished message", 409, "conflict"],
    [
        "result",
        "lease expired before the answer",
        409,
        "lease_expired; the message can be claimed again",
    ],
]


def build():
    # Three sealed chunks of an attachment (the last short) and a one-chunk attachment: FAKE bytes.
    envelope_ciphertext = bytes([0xE0]) * 700
    chunks_a = fake_chunks(0x10, [64, 64, 21])
    chunks_b = fake_chunks(0x40, [48])
    head_a = attachment_head(MESSAGE_ID, ATTACHMENT_A, chunks_a)
    head_b = attachment_head(MESSAGE_ID, ATTACHMENT_B, chunks_b)
    message = message_head(MESSAGE_ID, envelope_ciphertext, [head_a, head_b])

    base = {
        "attachment_chunk_sha256": [digest(c) for c in chunks_a],
        "attachment_head": head_a.hex(),
        "message_head": message.hex(),
    }
    cases = []

    def chain_case(name, head, expect):
        cases.append({"name": name, "head": head.hex(), "expect": expect})

    chain_case("the base chain", head_a, "equals base")
    chain_case(
        "chunks 1 and 2 swapped",
        attachment_head(MESSAGE_ID, ATTACHMENT_A, [chunks_a[0], chunks_a[2], chunks_a[1]]),
        "differs",
    )
    chain_case(
        "last chunk dropped (count 2)",
        attachment_head(MESSAGE_ID, ATTACHMENT_A, chunks_a[:2]),
        "differs",
    )
    chain_case(
        "first chunk repeated",
        attachment_head(MESSAGE_ID, ATTACHMENT_A, [chunks_a[0]] + chunks_a),
        "differs",
    )
    chain_case(
        "one byte of a chunk changed",
        attachment_head(
            MESSAGE_ID, ATTACHMENT_A, [chunks_a[0], chunks_a[1][:-1] + b"\x00", chunks_a[2]]
        ),
        "differs",
    )
    chain_case(
        "the same chunks under another message_id",
        attachment_head(OTHER_MESSAGE_ID, ATTACHMENT_A, chunks_a),
        "differs",
    )
    chain_case(
        "the same chunks as another attachment",
        attachment_head(MESSAGE_ID, ATTACHMENT_B, chunks_a),
        "differs",
    )
    cases.append(
        {
            "name": "message head with the attachments in the other order",
            "head": message_head(MESSAGE_ID, envelope_ciphertext, [head_b, head_a]).hex(),
            "expect": "differs from message_head",
        }
    )

    prov_clinic = {
        "delivery_id": DELIVERY_ID,
        "kind": "clinic-signed-copy",
        "manifest": "FAKEmanifestpayload.FAKEmanifestsignature",
    }
    att_a = attachment(
        ATTACHMENT_A,
        "FAKE-lab-result.pdf",
        "application/pdf",
        64 + 64 + 21 - 3 * LIMITS["aead_tag"] if False else 5 * MIB + 17,
        digest(b"FAKE plaintext A"),
        2,
        head_a.hex(),
        prov_clinic,
    )
    att_b = attachment(
        ATTACHMENT_B,
        "FAKE-photo.jpg",
        "image/jpeg",
        1000,
        digest(b"FAKE plaintext B"),
        1,
        head_b.hex(),
        {"kind": "patient-original"},
    )
    envelope = envelope_object([att_a, att_b])
    envelope_bytes = canonical(envelope)

    visible = [
        {"chain_head": head_a.hex(), "chunk_count": 2, "index": 0, "size": 5 * MIB + 17 + 2 * 16},
        {"chain_head": head_b.hex(), "chunk_count": 1, "index": 1, "size": 1000 + 16},
    ]
    outer = outer_object(envelope_ciphertext, visible, message.hex(), "RkFLRXNlYWxlZGtleQ")
    outer_bytes = canonical(outer)
    request_hash = lambda method, path, body: digest(  # noqa: E731
        frame(method.encode(), path.encode(), b"", body)
    )

    acks = {
        name: encoded(canonical(ack_object(*args, head=message.hex())))
        for name, args in {
            "collected": ("collected",),
            "filed": ("filed",),
            "refused": ("refused", "scan_failed"),
        }.items()
    }

    outer_cases = []

    def outer_case(name, mutate):
        value = json.loads(outer_bytes)
        mutate(value)
        outer_cases.append(
            {"name": name, "object": value, "expect": check_outer(value) or "accept"}
        )

    outer_case("exactly as built", lambda o: None)
    outer_case("an unknown field", lambda o: o.update(extra=1))
    outer_case("a missing field", lambda o: o.pop("sealed_key"))
    outer_case("version 2", lambda o: o.update(v=2))
    outer_case("version as text", lambda o: o.update(v="1"))
    outer_case("message_id not a UUID", lambda o: o.update(message_id="not-a-uuid"))
    outer_case("chain_head not hex", lambda o: o.update(chain_head="zz" * 32))
    outer_case(
        "lifetime over seven days",
        lambda o: o.update(expires_at=o["created_at"] + 7 * 24 * 3600 + 1),
    )
    outer_case("expires before it is created", lambda o: o.update(expires_at=o["created_at"]))
    outer_case(
        "eleven attachments",
        lambda o: o.update(attachments=o["attachments"] * 6, attachment_count=12),
    )
    outer_case("count disagrees with the list", lambda o: o.update(attachment_count=3))
    outer_case("kind message with attachments", lambda o: o.update(kind="message"))
    outer_case("attachments out of order", lambda o: o["attachments"].reverse())
    outer_case("a chunk count of zero", lambda o: o["attachments"][0].update(chunk_count=0))
    outer_case("totals do not add up", lambda o: o.update(total_size=o["total_size"] + 1))
    outer_case("over the phase 1 message limit", lambda o: o.update(total_size=65 * MIB))

    envelope_cases = []

    def envelope_case(name, mutate, working=PHASES["phase1"]):
        value = json.loads(envelope_bytes)
        mutate(value)
        envelope_cases.append(
            {"name": name, "object": value, "expect": check_envelope(value, working) or "accept"}
        )

    envelope_case("exactly as built", lambda e: None)
    envelope_case("an unknown field", lambda e: e.update(sender_name="FAKE Person"))
    envelope_case("version 2", lambda e: e.update(v=2))
    envelope_case("a reply (reserved, null in v1)", lambda e: e.update(in_reply_to=MESSAGE_ID))
    envelope_case("body of 8193 bytes", lambda e: e.update(body="x" * 8193))
    envelope_case("a control character in the body", lambda e: e.update(body="hello\x07"))
    envelope_case("no text and no attachment", lambda e: e.update(body=" ", attachments=[]))
    envelope_case(
        "an attachment id repeated",
        lambda e: e["attachments"][1].update(attachment_id=ATTACHMENT_A),
    )
    envelope_case(
        "a name with a path separator", lambda e: e["attachments"][0].update(name="../x.pdf")
    )
    envelope_case("a name of 121 characters", lambda e: e["attachments"][0].update(name="a" * 121))
    envelope_case(
        "an executable type",
        lambda e: e["attachments"][1].update(media_type="application/x-msdownload"),
    )
    envelope_case("video in phase 1", lambda e: e["attachments"][1].update(media_type="video/mp4"))
    envelope_case(
        "video in phase 2",
        lambda e: e["attachments"][1].update(media_type="video/mp4"),
        PHASES["phase2_video"],
    )
    envelope_case(
        "a wrong chunk count for the size", lambda e: e["attachments"][0].update(chunk_count=3)
    )
    envelope_case(
        "a clinic-signed copy that is not a PDF",
        lambda e: e["attachments"][0].update(media_type="image/png"),
    )
    envelope_case(
        "a clinic-signed copy without its manifest",
        lambda e: e["attachments"][0]["provenance"].pop("manifest"),
    )
    envelope_case(
        "an unknown provenance kind",
        lambda e: e["attachments"][1].update(provenance={"kind": "clinic-authored"}),
    )
    envelope_case(
        "an attachment over 20 MiB in phase 1",
        lambda e: e["attachments"][1].update(size=21 * MIB, chunk_count=6),
    )

    ack_cases = []
    for name, value in [
        ("collected", ack_object("collected", head=message.hex())),
        ("filed", ack_object("filed", head=message.hex())),
        ("refused with a reason", ack_object("refused", "type_not_allowed", head=message.hex())),
        ("refused without a reason", ack_object("refused", None, head=message.hex())),
        ("filed with a reason", ack_object("filed", "scan_failed", head=message.hex())),
        ("an unknown reason", ack_object("refused", "because", head=message.hex())),
        ("a state that means read", ack_object("read", head=message.hex())),
        ("a ref with spaces", ack_object("filed", ref="a b", head=message.hex())),
    ]:
        ack_cases.append({"name": name, "object": value, "expect": check_ack(value) or "accept"})

    return {
        "description": (
            "FAKE reference vectors for mycarlos-send/1 (patient to clinic), DRAFT for review. "
            "No signature, key, cipher or randomness is used: signing inputs are bytes, and every "
            "hash below is over fixed FAKE bytes. Not a conformance claim for any real component."
        ),
        "format_version": 1,
        "contract": "mycarlos-send/1",
        "canonical_json": (
            "sorted keys, no spaces, UTF-8, strings and integers only (RFC 8785 for these objects)"
        ),
        "frame": "each part preceded by its length as eight bytes, big endian",
        "limits": LIMITS,
        "phases": PHASES,
        "refusal_reasons": REFUSAL_REASONS,
        "identifiers": {
            "message_id": MESSAGE_ID,
            "attachment_a": ATTACHMENT_A,
            "attachment_b": ATTACHMENT_B,
            "clinic_id": CLINIC_ID,
            "recipient_id": RECIPIENT_ID,
        },
        "chain": {
            "definition": {
                "start": (
                    "sha256(frame('mycarlos-send/1 chain-start', message_id16, "
                    "attachment_id16, chunk_count8))"
                ),
                "link": (
                    "sha256(frame('mycarlos-send/1 chain-link', previous32, index8, "
                    "sha256(sealed_chunk)))"
                ),
                "attachment_head": "the link after the last chunk",
                "message_head": (
                    "sha256(frame('mycarlos-send/1 message', message_id16, "
                    "sha256(sealed_envelope), head_of_attachment_0, "
                    "head_of_attachment_1, ...))"
                ),
            },
            "chunks_a_sizes": [len(c) for c in chunks_a],
            "chunks_b_sizes": [len(c) for c in chunks_b],
            "envelope_ciphertext": {"fill": "0xe0", "size": len(envelope_ciphertext)},
            "base": base,
            "attachment_b_head": head_b.hex(),
            "cases": cases,
        },
        "aead": {
            "note": "bytes only; the cipher is ChaCha20-Poly1305 with the message's content key",
            "envelope_nonce": encoded(nonce(ENVELOPE_ATTACHMENT_INDEX, 0)),
            "chunk_nonce_a0_n0": encoded(nonce(0, 0)),
            "chunk_nonce_a1_n2": encoded(nonce(1, 2)),
            "envelope_aad": encoded(
                envelope_aad(MESSAGE_ID, RECIPIENT_ID, DEVICE_KEY_ID, CLINIC_ID)
            ),
            "chunk_aad_a0_n1": encoded(chunk_aad(MESSAGE_ID, ATTACHMENT_A, 1, 3)),
            "key_aad": encoded(
                key_aad(
                    MESSAGE_ID,
                    RECIPIENT_ID,
                    DEVICE_KEY_ID,
                    CLINIC_ID,
                    hashlib.sha256(envelope_ciphertext).digest(),
                )
            ),
        },
        "envelope": {
            "object": envelope,
            "canonical": encoded(envelope_bytes),
            "signed_by": (
                "the device Ed25519 key over the canonical bytes; compact "
                "b64url(payload).b64url(signature)"
            ),
        },
        "outer": {
            "object": outer,
            "canonical": encoded(outer_bytes),
            "create_request_hash": request_hash("POST", "/api/mycarlos/sends", outer_bytes),
            "chunk_request_hash": request_hash(
                "PUT",
                f"/api/mycarlos/sends/{MESSAGE_ID}/attachments/0/chunks/1",
                chunks_a[1],
            ),
        },
        "acks": {
            "signed_by": (
                "a clinic signing key (ECDSA P-256, ES256) over the canonical bytes; "
                "compact b64url(payload).b64url(signature)"
            ),
            "payloads": acks,
        },
        "outer_cases": outer_cases,
        "envelope_cases": envelope_cases,
        "ack_cases": ack_cases,
        "states": STATES,
        "transitions": TRANSITIONS,
        "routes": ROUTES,
        "idempotency": IDEMPOTENCY,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = json.dumps(build(), indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    if args.check:
        assert OUTPUT.read_bytes() == output, (
            "shared fixture differs; never silently overwrite approved bytes"
        )
    else:
        with OUTPUT.open("xb") as destination:
            destination.write(output)
    print(digest(output))


if __name__ == "__main__":
    main()
