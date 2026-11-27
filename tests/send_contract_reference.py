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

- the byte-exact framing, hash-chain, nonce, AAD and signing-input derivations the three
  implementations (carlos-portal, CARLOS, myCarlos) must agree on, with cases that must NOT agree;
- canonical bytes (and their hashes) of every signed or sealed object, and ONE fully consistent
  end-to-end vector (an envelope, the outer record, the chunks and every hash agree);
- a small reference validator for each object and the accept/refuse cases it gives, so a second
  implementation can be tested against the same list;
- the state machine, the idempotency table and the routes, as data.

It does not do HPKE, AEAD, signatures, storage or any clinical check: a signature is never produced
here, only the exact bytes that would be signed. Regenerate with no arguments (refuses to overwrite
an approved file); verify with `--check`.
"""

import argparse
import base64
import hashlib
import json
import re
import unicodedata
import uuid
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
OUTPUT = FIXTURES / "send-contract-v1.json"

VERSION = 1
KIB = 1024
MIB = 1024 * 1024

# Ceilings the PARSER enforces, whatever a deployment enables. A deployment advertises smaller
# working limits in its capabilities; a larger one needs a new contract version.
LIMITS = {
    # Ten clinic-signed copies carry ten manifests of up to 16 KiB (about 21 KiB each as text) next
    # to the text and names: the sealed envelope is allowed 256 KiB, and the plain envelope the same
    # less the tag. (A smaller budget would make ten manifests impossible.)
    "envelope_sealed_max": 256 * KIB,
    "body_max_bytes": 8192,
    "attachments_max": 10,
    "name_max_chars": 120,
    "chunk_plain_max": 4 * MIB,
    "aead_tag": 16,
    "lifetime_max_seconds": 7 * 24 * 3600,
    "created_skew_seconds": 300,
    "manifest_max_bytes": 16 * KIB,
    "ack_max_bytes": 4096,
    "recall_max_bytes": 1024,
    "inbox_key_statement_max_bytes": 2048,
    "inbox_key_validity_max_days": 30,
    "outer_max_bytes": 16 * KIB,
    "chunks_per_attachment_max": 128,
    "sealed_key_bytes": 80,
    "ref_chars": 22,
    "id_chars_max": 128,
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

# Domain separation: the device key also signs request assertions and the clinic key also signs
# delivery manifests, so each object here is signed over its own prefix, never over bare bytes.
SIGN_DOMAINS = {
    "envelope": b"mycarlos-send/1 envelope-signature",
    "ack": b"mycarlos-send/1 ack-signature",
    "recall": b"mycarlos-send/1 recall-signature",
    "inbox_key": b"mycarlos-send/1 inbox-key-signature",
}

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
CREATED_AT = 1_792_450_800
EXPIRES_AT = CREATED_AT + 3 * 24 * 3600
FAKE_INBOX_PUBLIC_KEY = bytes(range(32))
FAKE_REF = "AbCdEfGhIjKlMnOpQrStUv"  # 22 characters: a random 128-bit handle in the real thing

UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
ID_TEXT = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
MANIFEST_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")  # compact signed: payload.signature
OPAQUE_REF = re.compile(r"^[A-Za-z0-9_-]{22}$")


MAX_SAFE_INT = 2**53 - 1  # I-JSON (RFC 7493) and RFC 8785: the largest integer every language holds


def canonical(value):
    """The bytes every object is hashed and signed as: sorted keys, no spaces, UTF-8, integers in
    0..2^53-1, strings and null only. For such objects this IS RFC 8785 (the JSON Canonicalization
    Scheme): there are no floats, so no number formatting; key order is by UTF-16 code unit, which
    equals code point order for the ASCII keys used here; and only `"`, `\\` and the controls
    below U+0020 are escaped (the short forms \\b \\t \\n \\f \\r, otherwise \\u00xx lower case).
    Implementers: use a real RFC 8785 serialiser (in Java not Gson, which also escapes <, >, & and
    ' as \\u003c ...: that is NOT canonical and would break every signature)."""
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


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def encoded(raw):
    return {"hex": raw.hex(), "size": len(raw), "sha256": digest(raw)}


def signing_input(kind, payload):
    """The EXACT bytes a signature covers: the domain prefix and the canonical payload, framed. The
    signature never covers the base64 text, and never the payload alone."""
    return frame(SIGN_DOMAINS[kind], payload)


FAKE_DEVICE_SIGNATURE = bytes([0x5A]) * 64  # an Ed25519 signature is 64 bytes: FAKE, no key runs


def sealed_plaintext(payload, signature=FAKE_DEVICE_SIGNATURE):
    """What the content key seals as the envelope: ASCII, the compact signed form
    `b64url(payload).b64url(signature)`, unpadded. It is NOT the bare canonical JSON; the sealed
    envelope is this many bytes plus the 16-byte tag."""
    return (b64u(payload) + "." + b64u(signature)).encode("ascii")


def min_sealed_envelope_size():
    """The smallest possible sealed envelope, derived (not a magic number): the compact signed form
    of the smallest valid envelope (no attachments, a one character body) plus the tag."""
    return len(sealed_plaintext(canonical(envelope_object([], body="x")))) + LIMITS["aead_tag"]


def _refuse_number(_text):
    raise ValueError("float, NaN or Infinity")


def _i_json_problem(value):
    """The I-JSON rules a parsed object must meet: strings without lone surrogates (they have no
    UTF-8 form), integers only and within 0..2^53-1, no float anywhere."""
    if isinstance(value, dict):
        for key, item in value.items():
            problem = _i_json_problem(key) or _i_json_problem(item)
            if problem:
                return problem
    elif isinstance(value, list):
        for item in value:
            problem = _i_json_problem(item)
            if problem:
                return problem
    elif isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            return "not_json"
    elif isinstance(value, bool) or value is None:
        return None
    elif isinstance(value, int):
        if not 0 <= value <= MAX_SAFE_INT:
            return "bad_number"
    else:
        return "not_json"
    return None


def check_compact_payload(payload_b64):
    """What a verifier does with the first half of `b64url(payload).b64url(signature)` BEFORE it
    verifies anything: unpadded base64url, JSON, and the payload must already be its own canonical
    form (`canonical(parse(bytes)) == bytes`), so there is one byte string per object and a verifier
    never signs-over or hashes bytes it did not itself reproduce. Returns (object, None) or
    (None, reason)."""
    if not isinstance(payload_b64, str) or not B64URL.match(payload_b64):
        return None, "not_base64url"
    try:
        raw = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    except ValueError:
        return None, "not_base64url"
    try:
        value = json.loads(
            raw.decode("utf-8"), parse_float=_refuse_number, parse_constant=_refuse_number
        )
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None, "not_json"
    problem = _i_json_problem(value)
    if problem:
        return None, problem
    if canonical(value) != raw:
        return None, "not_canonical"
    return value, None


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
    return head_from_hashes(
        message_id,
        attachment_id,
        [hashlib.sha256(chunk).digest() for chunk in chunk_ciphertexts],
    )


def head_from_hashes(message_id, attachment_id, chunk_hashes):
    head = chain_start(message_id, attachment_id, len(chunk_hashes))
    for index, chunk_hash in enumerate(chunk_hashes):
        head = chain_link(head, index, chunk_hash)
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


def attachment(attachment_id, name, media_type, size, plaintext_sha256, head, prov):
    return {
        "attachment_id": attachment_id,
        "chain_head": head,
        "chunk_count": -(-size // LIMITS["chunk_plain_max"]),
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


def sealed_size(size):
    """The sealed bytes of `size` plaintext bytes in 4 MiB chunks: each chunk and its tag."""
    chunks = -(-size // LIMITS["chunk_plain_max"])
    return size + chunks * LIMITS["aead_tag"]


def outer_object(envelope_ciphertext, visible, chain_head, sealed_key, kid):
    return {
        "attachment_count": len(visible),
        "attachments": visible,
        "chain_head": chain_head,
        "chunk_total": sum(item["chunk_count"] for item in visible),
        "clinic_id": CLINIC_ID,
        "created_at": CREATED_AT,
        "device_key_id": DEVICE_KEY_ID,
        "envelope_sha256": digest(envelope_ciphertext),
        "envelope_size": len(envelope_ciphertext),
        "expires_at": EXPIRES_AT,
        "kind": "documents" if visible else "message",
        "message_id": MESSAGE_ID,
        "recipient_id": RECIPIENT_ID,
        "sealed_key": sealed_key,
        "sealed_key_kid": kid,
        "total_size": len(envelope_ciphertext) + sum(item["size"] for item in visible),
        "typ": "mycarlos-send-outer",
        "v": VERSION,
    }


def ack_object(state, reason=None, ref=FAKE_REF, at=CREATED_AT + 600, head=None):
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


def recall_object(head, at=CREATED_AT + 900):
    return {
        "at": at,
        "chain_head": head,
        "clinic_id": CLINIC_ID,
        "device_key_id": DEVICE_KEY_ID,
        "message_id": MESSAGE_ID,
        "recipient_id": RECIPIENT_ID,
        "typ": "mycarlos-send-recall",
        "v": VERSION,
    }


def inbox_key_kid(public_key):
    return b64u(hashlib.sha256(public_key).digest())


def inbox_key_statement(
    public_key=FAKE_INBOX_PUBLIC_KEY,
    not_before=CREATED_AT - 86_400,
    not_after=CREATED_AT + 20 * 86_400,
    status="active",
    serial=1,
):
    return {
        "clinic_id": CLINIC_ID,
        "kid": inbox_key_kid(public_key),
        "not_after": not_after,
        "not_before": not_before,
        "public_key": b64u(public_key),
        "serial": serial,
        "signer_kid": CLINIC_KID,
        "status": status,
        "typ": "mycarlos-send-inbox-key",
        "v": VERSION,
    }


# --- the reference validators (the contract in code) --------------------------------------------

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
VISIBLE_ATTACHMENT_FIELDS = {"attachment_id", "chain_head", "chunk_count", "index", "size"}
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
RECALL_FIELDS = {
    "at",
    "chain_head",
    "clinic_id",
    "device_key_id",
    "message_id",
    "recipient_id",
    "typ",
    "v",
}
INBOX_KEY_FIELDS = {
    "clinic_id",
    "kid",
    "not_after",
    "not_before",
    "public_key",
    "serial",
    "signer_kid",
    "status",
    "typ",
    "v",
}
# Why a message was not accepted (one per refusal, from a fixed list).
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
    "key_revoked",
]
# Why a recall was not honoured.
RECALL_REFUSAL_REASONS = ["recall_too_late", "recall_unknown_message"]
ACK_STATES = ["collected", "filed", "refused", "recalled", "recall_refused"]


def is_int(value):
    """An integer in 0..2^53-1 (never a bool, never a float such as 1.0)."""
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_SAFE_INT


def version_ok(obj):
    """`v` is exactly the integer 1: not true, not 1.0, not "1", not null."""
    return "v" in obj and is_int(obj["v"]) and obj["v"] == VERSION


def id_text(value):
    return isinstance(value, str) and bool(ID_TEXT.match(value))


def uuid4(value):
    return isinstance(value, str) and bool(UUID4.match(value))


def hex64(value):
    return isinstance(value, str) and bool(HEX64.match(value))


def check_text(text, *, name=False):
    """Text the app may show: NFC, one line feed allowed in a body, no other control, format,
    separator or private-use characters (C0, C1, bidirectional controls, zero-width, U+2028 and
    U+2029, and the like), and in a name no leading or trailing white space. Code points not yet
    assigned (category Cn) are ALLOWED: refusing them would make the answer depend on each
    implementation's Unicode version. The categories are those of Unicode 16.0. This reference
    uses its runtime's tables (Python 3.12 = Unicode 15.0); no case here depends on a code point
    whose category changed between them."""
    if not isinstance(text, str):
        return "bad_text"
    if unicodedata.normalize("NFC", text) != text:
        return "not_nfc"
    for char in text:
        category = unicodedata.category(char)
        if char == "\n" and not name:
            continue
        if category in ("Cc", "Cf", "Zl", "Zp", "Cs", "Co"):
            return "forbidden_character"
    if name and text != text.strip():
        return "edge_white_space"
    return None


def b64url_decoded_size(text):
    if not isinstance(text, str) or not B64URL.match(text):
        return None
    try:
        return len(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
    except ValueError:
        return None


def check_times(created_at, expires_at, now):
    """The lifetime rules with a clock: created no later than the skew allowance ahead, not older
    than the longest lifetime, and not yet expired."""
    if not is_int(created_at) or not is_int(expires_at) or not is_int(now):
        return "bad_number"
    if expires_at <= created_at:
        return "bad_lifetime"
    if expires_at - created_at > LIMITS["lifetime_max_seconds"]:
        return "lifetime_too_long"
    if created_at > now + LIMITS["created_skew_seconds"]:
        return "bad_time"
    if expires_at <= now:
        return "expired"
    return None


def check_outer(obj, working=PHASES["phase1"], now=None):
    """None when the outer record is acceptable, else the first reason (a stable name)."""
    if not isinstance(obj, dict):
        return "not_object"
    if "v" in obj and not version_ok(obj):
        return "unsupported_version"
    if set(obj) != OUTER_FIELDS:
        return "unknown_or_missing_field"
    if obj["typ"] != "mycarlos-send-outer" or obj["kind"] not in ("message", "documents"):
        return "bad_type"
    if not uuid4(obj["message_id"]):
        return "bad_id"
    for field in ("clinic_id", "recipient_id", "device_key_id", "sealed_key_kid"):
        if not id_text(obj[field]):
            return "bad_id"
    for field in ("chain_head", "envelope_sha256"):
        if not hex64(obj[field]):
            return "bad_hash"
    if b64url_decoded_size(obj["sealed_key"]) != LIMITS["sealed_key_bytes"]:
        return "bad_sealed_key"
    for field in ("created_at", "expires_at", "envelope_size", "total_size", "chunk_total"):
        if not is_int(obj[field]) or obj[field] < 0:
            return "bad_number"
    if now is not None:
        reason = check_times(obj["created_at"], obj["expires_at"], now)
        if reason:
            return reason
    else:
        if obj["expires_at"] <= obj["created_at"]:
            return "bad_lifetime"
        if obj["expires_at"] - obj["created_at"] > LIMITS["lifetime_max_seconds"]:
            return "lifetime_too_long"
    if not min_sealed_envelope_size() <= obj["envelope_size"] <= LIMITS["envelope_sealed_max"]:
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
    seen = set()
    chunk = LIMITS["chunk_plain_max"] + LIMITS["aead_tag"]
    for position, item in enumerate(items):
        if not isinstance(item, dict) or set(item) != VISIBLE_ATTACHMENT_FIELDS:
            return "unknown_or_missing_field"
        if item["index"] != position:
            return "attachment_order"
        if not uuid4(item["attachment_id"]):
            return "bad_id"
        if item["attachment_id"] in seen:
            return "duplicate_attachment_id"
        seen.add(item["attachment_id"])
        if not hex64(item["chain_head"]):
            return "bad_hash"
        count = item["chunk_count"]
        if not is_int(count) or not 1 <= count <= LIMITS["chunks_per_attachment_max"]:
            return "bad_chunk_count"
        if not is_int(item["size"]):
            return "bad_size"
        # Every chunk but the last is full: the sealed size is bounded on both sides by the count.
        if not (count - 1) * chunk + LIMITS["aead_tag"] + 1 <= item["size"] <= count * chunk:
            return "bad_size"
        if item["size"] > working["attachment_max_bytes"] + count * LIMITS["aead_tag"]:
            return "too_large"
        chunks += count
        size += item["size"]
    if chunks != obj["chunk_total"] or size != obj["total_size"]:
        return "totals_mismatch"
    if obj["total_size"] > working["message_max_bytes"] + LIMITS["envelope_sealed_max"]:
        return "too_large"
    return None


def check_envelope(obj, working=PHASES["phase1"]):
    """None when the (decrypted, signature-checked elsewhere) envelope is acceptable."""
    if not isinstance(obj, dict):
        return "not_object"
    if "v" in obj and not version_ok(obj):
        return "unsupported_version"
    if set(obj) != ENVELOPE_FIELDS:
        return "unknown_or_missing_field"
    if obj["typ"] != "mycarlos-send-envelope":
        return "bad_type"
    for field in ("message_id", "conversation_id"):
        if not uuid4(obj[field]):
            return "bad_id"
    for field in ("clinic_id", "recipient_id", "device_key_id"):
        if not id_text(obj[field]):
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
    reason = check_text(body)
    if reason:
        return "body_" + reason
    items = obj["attachments"]
    if not isinstance(items, list) or len(items) > LIMITS["attachments_max"]:
        return "too_many_attachments"
    # Empty means only White_Space characters (Python's str.strip), in a body with no attachment.
    if not body.strip() and not items:
        return "empty_message"
    seen = set()
    total = 0
    for item in items:
        if not isinstance(item, dict) or set(item) != ATTACHMENT_FIELDS:
            return "unknown_or_missing_field"
        if not uuid4(item["attachment_id"]):
            return "bad_id"
        if item["attachment_id"] in seen:
            return "duplicate_attachment_id"
        seen.add(item["attachment_id"])
        name = item["name"]
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= LIMITS["name_max_chars"]
            or any(c in name for c in "/\\:\x00")
            or name in (".", "..")
        ):
            return "bad_name"
        reason = check_text(name, name=True)
        if reason:
            return "name_" + reason
        if item["media_type"] not in working["media_types"]:
            return "type_not_allowed"
        if not is_int(item["size"]) or not 1 <= item["size"] <= working["attachment_max_bytes"]:
            return "too_large"
        total += item["size"]
        if not hex64(item["sha256"]) or not hex64(item["chain_head"]):
            return "bad_hash"
        if item["chunk_size"] != LIMITS["chunk_plain_max"]:
            return "bad_chunk_size"
        if item["chunk_count"] != -(-item["size"] // item["chunk_size"]):
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
            if not uuid4(prov["delivery_id"]):
                return "bad_id"
            manifest = prov["manifest"]
            if (
                not isinstance(manifest, str)
                or len(manifest.encode()) > LIMITS["manifest_max_bytes"]
                or not MANIFEST_RE.match(manifest)
            ):
                return "bad_manifest"
            if item["media_type"] != "application/pdf":
                return "type_not_allowed"
    if total > working["message_max_bytes"]:
        return "too_large"
    return None


def check_pair(outer, envelope):
    """CARLOS's check after opening: the envelope (signed) and the outer record (what the portal
    held) describe the same message. The signed envelope's chain heads are the ones that count."""
    if outer["message_id"] != envelope["message_id"]:
        return "pair_message"
    for field in ("clinic_id", "recipient_id", "device_key_id", "created_at", "expires_at"):
        if outer[field] != envelope[field]:
            return "pair_" + field
    if outer["attachment_count"] != len(envelope["attachments"]):
        return "pair_attachment_count"
    for visible, described in zip(outer["attachments"], envelope["attachments"], strict=True):
        if (
            visible["attachment_id"] != described["attachment_id"]
            or visible["chain_head"] != described["chain_head"]
            or visible["chunk_count"] != described["chunk_count"]
            or visible["size"] != sealed_size(described["size"])
        ):
            return "pair_attachment"
    return None


def check_ack(obj):
    if not isinstance(obj, dict):
        return "not_object"
    if "v" in obj and not version_ok(obj):
        return "unsupported_version"
    if set(obj) != ACK_FIELDS:
        return "unknown_or_missing_field"
    if obj["typ"] != "mycarlos-send-ack" or obj["state"] not in ACK_STATES:
        return "bad_type"
    needs_reason = obj["state"] in ("refused", "recall_refused")
    if needs_reason != (obj["reason"] is not None):
        return "reason_mismatch"
    allowed = REFUSAL_REASONS if obj["state"] == "refused" else RECALL_REFUSAL_REASONS
    if needs_reason and obj["reason"] not in allowed:
        return "bad_reason"
    for field in ("message_id",):
        if not uuid4(obj[field]):
            return "bad_id"
    for field in ("clinic_id", "recipient_id", "device_key_id", "kid"):
        if not id_text(obj[field]):
            return "bad_id"
    # The handle is the clinic's own and random: never derived from a chart or message id.
    if not isinstance(obj["ref"], str) or not OPAQUE_REF.match(obj["ref"]):
        return "bad_ref"
    if not hex64(obj["chain_head"]):
        return "bad_hash"
    if not is_int(obj["at"]) or obj["at"] < 0:
        return "bad_number"
    return None


def check_recall(obj):
    if not isinstance(obj, dict):
        return "not_object"
    if "v" in obj and not version_ok(obj):
        return "unsupported_version"
    if set(obj) != RECALL_FIELDS:
        return "unknown_or_missing_field"
    if obj["typ"] != "mycarlos-send-recall":
        return "bad_type"
    if not uuid4(obj["message_id"]):
        return "bad_id"
    for field in ("clinic_id", "recipient_id", "device_key_id"):
        if not id_text(obj[field]):
            return "bad_id"
    if not hex64(obj["chain_head"]):
        return "bad_hash"
    if not is_int(obj["at"]) or obj["at"] < 0:
        return "bad_number"
    return None


def check_recall_binding(recall, outer):
    """CARLOS's check that a verified recall is about THIS message: every identifying field equal
    to the outer record's (the recall's device_key_id must be the message's)."""
    for field in ("message_id", "chain_head", "clinic_id", "recipient_id", "device_key_id"):
        if recall[field] != outer[field]:
            return "recall_" + field
    return None


def check_inbox_key(obj, now, *, link_clinic_id=CLINIC_ID, known=None):
    """What the app checks of a clinic inbox key statement (its signature, by a pinned clinic key,
    is checked first, elsewhere) before it seals anything to the key. `known` is the app's
    persisted high-water mark for this link, {"serial": n, "revoked": bool}: the highest serial it
    has ever accepted, and whether that serial revoked the key. A statement below it is a rollback
    (a dishonest portal replaying an older, still-unexpired statement) and is refused; at the SAME
    serial a revocation wins over an active statement. Statements are short-lived (at most 30 days,
    re-signed by key-publish), so expiry is the real revocation channel for a device that has not
    seen the revocation."""
    if not isinstance(obj, dict):
        return "not_object"
    if "v" in obj and not version_ok(obj):
        return "unsupported_version"
    if set(obj) != INBOX_KEY_FIELDS:
        return "unknown_or_missing_field"
    if obj["typ"] != "mycarlos-send-inbox-key" or obj["status"] not in ("active", "revoked"):
        return "bad_type"
    for field in ("clinic_id", "kid", "signer_kid"):
        if not id_text(obj[field]):
            return "bad_id"
    if b64url_decoded_size(obj["public_key"]) != 32:
        return "bad_public_key"
    raw = base64.urlsafe_b64decode(obj["public_key"] + "=")
    if obj["kid"] != inbox_key_kid(raw):
        return "kid_mismatch"
    if obj["clinic_id"] != link_clinic_id:
        return "clinic_mismatch"
    if not is_int(obj["serial"]) or obj["serial"] < 1:
        return "bad_serial"
    if known is not None:
        if obj["serial"] < known["serial"]:
            return "serial_rollback"
        if obj["serial"] == known["serial"] and known["revoked"] and obj["status"] == "active":
            return "revoked_wins"
    if not is_int(obj["not_before"]) or not is_int(obj["not_after"]):
        return "bad_number"
    if obj["not_after"] <= obj["not_before"]:
        return "bad_validity"
    if obj["not_after"] - obj["not_before"] > LIMITS["inbox_key_validity_max_days"] * 86_400:
        return "validity_too_long"
    if obj["status"] == "revoked":
        return "revoked"
    if now < obj["not_before"]:
        return "not_yet_valid"
    if now >= obj["not_after"]:
        return "expired"
    return None


# What the patient sees and what each means. `by` says who can make the claim true: the app, the
# portal (an unsigned claim the device cannot verify) or the clinic system (signed, verified against
# the link's pinned clinic keys). The words never say read, seen or reviewed.
STATES = {
    "queued": {
        "by": "app",
        "means": "kept in the sent record; nothing has been sent yet",
        "never_means": "that anything left this device",
    },
    "sending": {
        "by": "app",
        "means": "parts are being uploaded in this run of the app",
        "never_means": "that the portal has all of it",
    },
    "received": {
        "by": "portal-claim",
        "means": "the portal says it holds every part and that the chain it can recompute matches",
        "never_means": "that the clinic has it, or that the portal's check protects against "
        "the portal",
    },
    "collected": {
        "by": "clinic-signed",
        "means": "the clinic's system fetched, opened and checked the message",
        "never_means": "filed, seen or read by anyone",
    },
    "filed": {
        "by": "clinic-signed",
        "means": "stored in the clinic's pending-review queue for staff, not yet in a chart",
        "never_means": "that any staff member has read, reviewed or acted on it",
    },
    "refused": {
        "by": "clinic-signed, or portal-claim before the clinic collected it",
        "means": "not accepted, for one reason from a fixed list; nothing is kept",
        "never_means": "a judgement about the content",
    },
    "expired": {
        "by": "portal-claim or app, only before the clinic collected it",
        "means": "the time ran out before the clinic's system collected it; the portal deleted it",
        "never_means": "that it was delivered; after a signed collected only the clinic's signed "
        "answer ends the message",
    },
    "recalled": {
        "by": "clinic-signed",
        "means": "removed from the pending queue before it was accepted into a chart",
        "never_means": "that nobody saw it",
    },
    "cancelled": {
        "by": "app and portal, before the upload was completed",
        "means": "the upload was stopped and everything deleted",
        "never_means": "anything about a message that was completed",
    },
}
# `recall requested` is a mark on received, collected or filed, not a state of its own.
TRANSITIONS = {
    "queued": ["sending", "cancelled"],
    "sending": ["received", "cancelled", "expired", "refused"],
    "received": ["collected", "refused", "expired", "recalled"],
    "collected": ["filed", "refused", "recalled"],
    "filed": ["recalled"],
    "refused": [],
    "expired": [],
    "recalled": [],
    "cancelled": [],
}
RULES = {
    "after_a_signed_collected": (
        "only the clinic's signed filed, refused or recalled ends the message; the portal's "
        "unsigned refused or expired is shown as 'the portal says ...' and changes nothing; the "
        "clinic's system enforces expires_at itself (a signed refused with reason expired)"
    ),
    "cancel_vs_complete": (
        "one row lock on the message: the first wins; a cancel after complete is 409 use_recall, a "
        "complete after cancel is 409 cancelled"
    ),
    "recall_vs_accept": (
        "the clinic's recall handling and its accept-into-chart take the same row lock on the "
        "inbound row: the first wins and the loser reads the other's result (recalled, or "
        "recall_refused with reason recall_too_late)"
    ),
    "recall": (
        "a recall is a device-signed object (message_id, chain_head, clinic_id); the portal relays "
        "it, the clinic verifies the signature against its accepted-device table and the chain "
        "head against its own record, then answers with a signed recalled or recall_refused"
    ),
    "recall_before_collect": (
        "a recall can reach the clinic before it has claimed the message: the clinic's system "
        "stores the verified recall keyed by (device, message_id, chain_head), and a later claim "
        "of that message is answered with a signed recalled and nothing is filed; the portal also "
        "withholds a message from claim while a recall is pending. recall_unknown_message is "
        "never the answer for a message the portal still holds; it is for a (device, message_id, "
        "chain_head) the clinic has never held and the portal no longer holds either"
    ),
    "recall_binding": (
        "the recall's device_key_id, clinic_id, recipient_id, message_id and chain_head must all "
        "equal those of the message it names, or it is ignored (never acted on, never an ack)"
    ),
    "key_revoked": (
        "a message sealed to a kid the clinic has revoked, with created_at after the revocation, "
        "is refused with a signed refused / key_revoked; a message created before the revocation "
        "is still opened (the clinic holds the key)"
    ),
    "interrupted_send": (
        "the content key lives only in memory: a restart, a lock or a crash ends the send. The "
        "app cancels what the portal holds and the patient sends again as a NEW message_id, so a "
        "nonce is never used twice under one key"
    ),
}

# What every verifier does, in this order, to every signed or sealed object. Refusing early on the
# bytes means a later field check never runs on something that was not the signed object.
CHECK_ORDER = [
    "1 signature over frame(domain, payload) verifies (the compact form is split at the one '.')",
    "2 payload is unpadded base64url, valid UTF-8 JSON with no float, NaN, Infinity, lone "
    "surrogate or integer outside 0..2^53-1 (not_json, bad_number)",
    "3 canonical(parse(payload)) == payload byte for byte (not_canonical)",
    "4 v is exactly the integer 1 (unsupported_version), before any other field is read",
    "5 exactly the listed fields, then the field rules (unknown_or_missing_field, ...)",
]

ROUTES = [
    ["GET", "/api/mycarlos/send-capabilities", "device assertion", "200; 404 when not enabled"],
    [
        "POST",
        "/api/mycarlos/sends",
        "device assertion; body is the canonical outer record",
        "201, 200, 409 send_conflict, 410 gone, 422",
    ],
    [
        "PUT",
        "/api/mycarlos/sends/{message_id}/envelope",
        "device assertion; body the sealed envelope",
        "200, 409 chunk_conflict, 413",
    ],
    [
        "PUT",
        "/api/mycarlos/sends/{message_id}/attachments/{a}/chunks/{n}",
        "device assertion; body one sealed chunk (header X-Chunk-SHA256)",
        "200, 409 chunk_conflict, 413",
    ],
    [
        "GET",
        "/api/mycarlos/sends/{message_id}",
        "device assertion",
        "200 with state, and for each part whether it is held and its SHA-256; 404",
    ],
    [
        "POST",
        "/api/mycarlos/sends/{message_id}/complete",
        "device assertion; empty body",
        "200 received; 409 cancelled; 422 chain_mismatch",
    ],
    [
        "POST",
        "/api/mycarlos/sends/{message_id}/cancel",
        "device assertion; empty body; only before complete",
        "200 cancelled; 409 use_recall",
    ],
    [
        "POST",
        "/api/mycarlos/sends/{message_id}/recall",
        "device assertion; body the device-signed recall (compact)",
        "200 recall_requested; 409 gone",
    ],
    ["GET", "/api/mycarlos/sends", "device assertion; ?after&limit (at most 50)", "200"],
    [
        "POST",
        "/internal/carlos/mycarlos/sends/claim",
        "job send-sync, portal.mycarlos.send.claim",
        "200 claims with lease tokens",
    ],
    [
        "GET",
        "/internal/carlos/mycarlos/sends/{id}/envelope",
        "job send-sync, portal.mycarlos.send.read; lease token",
        "200 octet-stream; 404",
    ],
    [
        "GET",
        "/internal/carlos/mycarlos/sends/{id}/attachments/{a}/chunks/{n}",
        "job send-sync, portal.mycarlos.send.read; lease token",
        "200 octet-stream; 404",
    ],
    [
        "POST",
        "/internal/carlos/mycarlos/sends/recalls",
        "job send-sync, portal.mycarlos.send.read; body {limit}",
        "200 pending recalls with their device-signed recall objects",
    ],
    [
        "POST",
        "/internal/carlos/mycarlos/sends/{id}/result",
        "job send-sync, portal.mycarlos.send.result; lease token or recall",
        "200, 409 lease_expired or conflict, 404",
    ],
]

IDEMPOTENCY = [
    ["create", "first request", 201, "created"],
    ["create", "same outer record, byte for byte", 200, "nothing written"],
    ["create", "same message_id from this device, different outer record", 409, "send_conflict"],
    [
        "create",
        "a message_id that this device used and the portal has deleted (a tombstone)",
        410,
        "gone; never recreated",
    ],
    ["create", "expires_at in the past", 422, "expired"],
    ["create", "created_at more than 300 s ahead of the portal's clock", 422, "bad_time"],
    [
        "any",
        "a message_id that belongs to another device or does not exist",
        404,
        "the same answer: no existence oracle; ids are scoped to the device",
    ],
    ["envelope or chunk", "first time", 200, "stored"],
    ["envelope or chunk", "same bytes again", 200, "nothing written"],
    ["envelope or chunk", "different bytes for the same place", 409, "chunk_conflict"],
    ["complete", "all parts present, chain matches", 200, "state received"],
    ["complete", "again, once received", 200, "unchanged"],
    ["complete", "a part missing, or a hash that does not chain", 422, "chain_mismatch"],
    ["complete", "after a cancel", 409, "cancelled"],
    ["cancel", "before complete", 200, "everything deleted, state cancelled"],
    ["cancel", "after complete", 409, "use_recall"],
    ["recall", "device-signed, for a received message", 200, "recall_requested"],
    ["recall", "the same recall again", 200, "nothing written"],
    ["recall", "for a deleted message", 409, "gone"],
    [
        "result",
        "same outcome and the same acknowledgement again",
        200,
        "recorded: false",
    ],
    ["result", "a different outcome for a finished message", 409, "conflict"],
    ["result", "lease expired before the answer", 409, "lease_expired; claimable again"],
    [
        "CARLOS filing",
        "the same (device, message_id, chain_head) again",
        "n/a",
        "the original acknowledgement is issued again, byte for byte; nothing is filed twice",
    ],
    [
        "CARLOS filing",
        "the same (device, message_id) with a different chain_head",
        "n/a",
        "a signed refused, reason duplicate_message",
    ],
]

PORTAL_LEARNS = [
    "that a message exists, when it was created and when it expires",
    "which device, recipient and clinic it is for (it knows them already)",
    "the number of attachments, and each one's chunk count and sealed size (not its name or type)",
    "the total size, and when each part arrived",
    "the state, and the clinic's signed acknowledgements it relays",
]
PORTAL_DOES_NOT_LEARN = [
    "the text, the names, the types or the content of anything",
    "who the patient is beyond the account the device already belongs to",
    "whether a document is the clinic's own signed copy",
]


# --- fake data: a fully consistent message ------------------------------------------------------


def fake_bytes(seed, size):
    return bytes([seed]) * size


def build_message():
    """One end-to-end consistent message: an 8 MiB + 17 byte PDF (three chunks) the clinic signed
    earlier, and a 1000 byte photo (one chunk). 'Sealed' bytes are FAKE fixed bytes of the right
    sizes (no cipher runs); every size, count, hash, head and descriptor below agrees."""
    chunk = LIMITS["chunk_plain_max"]
    tag = LIMITS["aead_tag"]
    size_a = 2 * chunk + 17
    size_b = 1000
    plain_a = fake_bytes(0xA1, size_a)
    plain_b = fake_bytes(0xB2, size_b)
    sealed_a = [
        fake_bytes(0x10, chunk + tag),
        fake_bytes(0x11, chunk + tag),
        fake_bytes(0x12, 17 + tag),
    ]
    sealed_b = [fake_bytes(0x40, size_b + tag)]
    head_a = attachment_head(MESSAGE_ID, ATTACHMENT_A, sealed_a)
    head_b = attachment_head(MESSAGE_ID, ATTACHMENT_B, sealed_b)
    prov_clinic = {
        "delivery_id": DELIVERY_ID,
        "kind": "clinic-signed-copy",
        "manifest": "FAKEmanifestpayload.FAKEmanifestsignature",
    }
    att_a = attachment(
        ATTACHMENT_A,
        "FAKE-lab-result.pdf",
        "application/pdf",
        size_a,
        digest(plain_a),
        head_a.hex(),
        prov_clinic,
    )
    att_b = attachment(
        ATTACHMENT_B,
        "FAKE-photo.jpg",
        "image/jpeg",
        size_b,
        digest(plain_b),
        head_b.hex(),
        {"kind": "patient-original"},
    )
    envelope = envelope_object([att_a, att_b])
    envelope_bytes = canonical(envelope)
    # The sealed envelope is the ASCII compact signed form (payload and signature) and the tag.
    envelope_compact = sealed_plaintext(envelope_bytes)
    envelope_ciphertext = fake_bytes(0xE0, len(envelope_compact) + tag)
    head = message_head(MESSAGE_ID, envelope_ciphertext, [head_a, head_b])
    visible = [
        {
            "attachment_id": ATTACHMENT_A,
            "chain_head": head_a.hex(),
            "chunk_count": 3,
            "index": 0,
            "size": sum(len(c) for c in sealed_a),
        },
        {
            "attachment_id": ATTACHMENT_B,
            "chain_head": head_b.hex(),
            "chunk_count": 1,
            "index": 1,
            "size": sum(len(c) for c in sealed_b),
        },
    ]
    kid = inbox_key_kid(FAKE_INBOX_PUBLIC_KEY)
    sealed_key = b64u(fake_bytes(0x5E, LIMITS["sealed_key_bytes"]))
    outer = outer_object(envelope_ciphertext, visible, head.hex(), sealed_key, kid)
    return {
        "plain_a": plain_a,
        "plain_b": plain_b,
        "sealed_a": sealed_a,
        "sealed_b": sealed_b,
        "head_a": head_a,
        "head_b": head_b,
        "head": head,
        "envelope": envelope,
        "envelope_bytes": envelope_bytes,
        "envelope_compact": envelope_compact,
        "envelope_ciphertext": envelope_ciphertext,
        "outer": outer,
        "outer_bytes": canonical(outer),
    }


def worst_case_envelope():
    """The largest envelope the contract allows, measured against the 256 KiB budget: ten
    attachments each carrying a 16 KiB clinic manifest, a body of 8,192 bytes made of line feeds
    (each escaped to two bytes), and names of 120 emoji (four bytes each in UTF-8, the widest a
    name can be; the manifest is restricted to base64url so it cannot escape). Returns
    (envelope, compact_plaintext, sealed_size)."""
    manifest = "a" * 8191 + "." + "b" * 8192  # exactly 16 KiB (16384 bytes)
    items = []
    for i in range(10):
        items.append(
            attachment(
                str(uuid.UUID(int=0x1000 + i, version=4)),
                "\U0001f600" * 120,
                "application/pdf",
                6 * MIB,
                "f" * 64,
                "e" * 64,
                {
                    "delivery_id": DELIVERY_ID,
                    "kind": "clinic-signed-copy",
                    "manifest": manifest,
                },
            )
        )
    envelope = envelope_object(items, body="\n" * 8192)
    compact = sealed_plaintext(canonical(envelope))
    return envelope, compact, len(compact) + LIMITS["aead_tag"]


def build():
    m = build_message()
    envelope, outer = m["envelope"], m["outer"]
    envelope_bytes, outer_bytes = m["envelope_bytes"], m["outer_bytes"]
    sealed_a, sealed_b = m["sealed_a"], m["sealed_b"]
    head_a, head_b = m["head_a"], m["head_b"]
    head = m["head"]
    envelope_ciphertext = m["envelope_ciphertext"]

    # --- the chain cases: what must equal the base, and everything that must not.
    chain_cases = []

    def chain_case(name, value, expect):
        chain_cases.append({"name": name, "head": value.hex(), "expect": expect})

    chain_case("the base chain", head_a, "equals base")
    chain_case(
        "chunks 1 and 2 swapped",
        attachment_head(MESSAGE_ID, ATTACHMENT_A, [sealed_a[0], sealed_a[2], sealed_a[1]]),
        "differs",
    )
    chain_case(
        "last chunk dropped (count 2)",
        attachment_head(MESSAGE_ID, ATTACHMENT_A, sealed_a[:2]),
        "differs",
    )
    chain_case(
        "first chunk repeated",
        attachment_head(MESSAGE_ID, ATTACHMENT_A, [sealed_a[0], *sealed_a]),
        "differs",
    )
    changed = sealed_a[1][:-1] + b"\x00"
    chain_case(
        "one byte of a chunk changed",
        attachment_head(MESSAGE_ID, ATTACHMENT_A, [sealed_a[0], changed, sealed_a[2]]),
        "differs",
    )
    chain_case(
        "the same chunks under another message_id",
        attachment_head(OTHER_MESSAGE_ID, ATTACHMENT_A, sealed_a),
        "differs",
    )
    chain_case(
        "the same chunks as another attachment",
        attachment_head(MESSAGE_ID, ATTACHMENT_B, sealed_a),
        "differs",
    )
    chain_case(
        "message head with the attachments in the other order",
        message_head(MESSAGE_ID, envelope_ciphertext, [head_b, head_a]),
        "differs from message_head",
    )
    chain_case(
        "message head with another sealed envelope",
        message_head(MESSAGE_ID, envelope_ciphertext[:-1] + b"\x00", [head_a, head_b]),
        "differs from message_head",
    )

    # --- outer record cases.
    outer_cases = []

    def outer_case(name, mutate, now=None):
        value = json.loads(outer_bytes)
        mutate(value)
        outer_cases.append(
            {
                "name": name,
                "now": now,
                "object": value,
                "expect": check_outer(value, now=now) or "accept",
            }
        )

    outer_case("exactly as built", lambda o: None)
    outer_case("with a clock inside its lifetime", lambda o: None, now=CREATED_AT + 60)
    outer_case("an unknown field", lambda o: o.update(extra=1))
    outer_case("a missing field", lambda o: o.pop("sealed_key"))
    for label, value in [("2", 2), ("as text", "1"), ("true", True), ("1.0", 1.0), ("null", None)]:
        outer_case(f"version {label}", lambda o, value=value: o.update(v=value))
    outer_case("no version at all", lambda o: o.pop("v"))
    outer_case("message_id not a UUID", lambda o: o.update(message_id="not-a-uuid"))
    outer_case("clinic_id a number", lambda o: o.update(clinic_id=7))
    outer_case("recipient_id with a space", lambda o: o.update(recipient_id="a b"))
    outer_case("device_key_id empty", lambda o: o.update(device_key_id=""))
    outer_case("sealed_key_kid too long", lambda o: o.update(sealed_key_kid="k" * 129))
    outer_case("chain_head not hex", lambda o: o.update(chain_head="zz" * 32))
    outer_case("sealed_key of 79 bytes", lambda o: o.update(sealed_key=b64u(b"x" * 79)))
    outer_case("sealed_key with padding", lambda o: o.update(sealed_key=o["sealed_key"] + "="))
    outer_case(
        "lifetime over seven days",
        lambda o: o.update(expires_at=o["created_at"] + 7 * 24 * 3600 + 1),
    )
    outer_case("expires before it is created", lambda o: o.update(expires_at=o["created_at"]))
    outer_case("expires_at in the past", lambda o: None, now=EXPIRES_AT + 1)
    outer_case(
        "created_at ahead of the clock beyond the skew", lambda o: None, now=CREATED_AT - 301
    )
    outer_case(
        "created_at ahead of the clock within the skew", lambda o: None, now=CREATED_AT - 300
    )

    def eleven(o):
        item = {
            "attachment_id": ATTACHMENT_A,
            "chain_head": "0" * 64,
            "chunk_count": 1,
            "index": 0,
            "size": 1016,
        }
        o["attachments"] = [
            {**item, "attachment_id": f"7d2b8b2c-3e5f-4a0c-9c63-2f3a4b5c6d{n:02x}", "index": n}
            for n in range(11)
        ]
        o["attachment_count"] = 11
        o["chunk_total"] = 11
        o["total_size"] = o["envelope_size"] + 11 * 1016

    outer_case("eleven attachments (consistent totals)", eleven)
    outer_case("count disagrees with the list", lambda o: o.update(attachment_count=3))
    outer_case("kind message with attachments", lambda o: o.update(kind="message"))
    outer_case("attachments out of order", lambda o: o["attachments"].reverse())
    outer_case(
        "an attachment id repeated",
        lambda o: o["attachments"][1].update(attachment_id=ATTACHMENT_A),
    )
    outer_case(
        "an attachment id not a UUID", lambda o: o["attachments"][0].update(attachment_id="x")
    )
    outer_case("a chunk count of zero", lambda o: o["attachments"][0].update(chunk_count=0))
    outer_case(
        "a size too small for its chunk count",
        lambda o: o["attachments"][0].update(size=o["attachments"][0]["size"] - 4 * MIB),
    )
    outer_case("totals do not add up", lambda o: o.update(total_size=o["total_size"] + 1))

    def over_attachment(o):
        count = 6  # 6 sealed chunks hold up to 24 MiB: over the 20 MiB phase 1 limit
        size = 5 * (4 * MIB + 16) + 4 * MIB // 2
        o["attachments"][0].update(chunk_count=count, size=size)
        o["chunk_total"] = count + 1
        o["total_size"] = o["envelope_size"] + size + o["attachments"][1]["size"]

    outer_case("an attachment over the phase 1 limit (consistent totals)", over_attachment)

    def over_message(o):
        items = []
        for n in range(4):  # four attachments of 17 MiB: each allowed, 68 MiB together: over 64
            size = 4 * (4 * MIB + 16) + 1 * MIB
            items.append(
                {
                    "attachment_id": f"7d2b8b2c-3e5f-4a0c-9c63-2f3a4b5c6d{n:02x}",
                    "chain_head": "1" * 64,
                    "chunk_count": 5,
                    "index": n,
                    "size": size,
                }
            )
        o["attachments"] = items
        o["attachment_count"] = 4
        o["chunk_total"] = 20
        o["total_size"] = o["envelope_size"] + sum(i["size"] for i in items)

    outer_case("a message over the phase 1 limit (consistent totals)", over_message)

    # --- envelope cases.
    envelope_cases = []

    def envelope_case(name, mutate, working=PHASES["phase1"]):
        value = json.loads(envelope_bytes)
        mutate(value)
        envelope_cases.append(
            {
                "name": name,
                "object": value,
                "phase": "phase2_video" if working is PHASES["phase2_video"] else "phase1",
                "expect": check_envelope(value, working) or "accept",
            }
        )

    envelope_case("exactly as built", lambda e: None)
    envelope_case("an unknown field", lambda e: e.update(sender_name="FAKE Person"))
    for label, value in [("2", 2), ("as text", "1"), ("true", True), ("1.0", 1.0), ("null", None)]:
        envelope_case(f"version {label}", lambda e, value=value: e.update(v=value))
    envelope_case("clinic_id a number", lambda e: e.update(clinic_id=1))
    envelope_case("a reply (reserved, null in v1)", lambda e: e.update(in_reply_to=MESSAGE_ID))
    envelope_case("body of 8193 bytes", lambda e: e.update(body="x" * 8193))
    for label, char in [
        ("a C0 control character", "\x07"),
        ("a C1 control character", "\x85"),
        ("U+2028", " "),
        ("U+2029", " "),
        ("a bidirectional override", "‮"),
        ("a bidirectional isolate", "⁦"),
        ("a zero-width space", "​"),
        ("a byte order mark", "﻿"),
        ("a private-use character", ""),
    ]:
        envelope_case(f"{label} in the body", lambda e, char=char: e.update(body=f"hello{char}x"))
    envelope_case("a decomposed letter in the body", lambda e: e.update(body="é"))
    envelope_case(
        "a line feed in the body is allowed", lambda e: e.update(body="line one\nline two")
    )
    envelope_case("no text and no attachment", lambda e: e.update(body="  ", attachments=[]))
    envelope_case("text and no attachment", lambda e: e.update(body="FAKE hello", attachments=[]))
    envelope_case(
        "an attachment id repeated",
        lambda e: e["attachments"][1].update(attachment_id=ATTACHMENT_A),
    )
    envelope_case(
        "a name with a path separator", lambda e: e["attachments"][0].update(name="../x.pdf")
    )
    envelope_case("a name of 121 characters", lambda e: e["attachments"][0].update(name="a" * 121))
    envelope_case(
        "a name with a bidirectional control",
        lambda e: e["attachments"][0].update(name="a‮b.pdf"),
    )
    envelope_case("a name with a line feed", lambda e: e["attachments"][0].update(name="a\nb.pdf"))
    envelope_case(
        "a name with edge white space", lambda e: e["attachments"][0].update(name=" a.pdf")
    )
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
        "a wrong chunk count for the size", lambda e: e["attachments"][0].update(chunk_count=2)
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
        "a clinic-signed copy with a manifest over 16 KiB",
        lambda e: e["attachments"][0]["provenance"].update(manifest="a" * 8192 + "." + "b" * 9000),
    )
    envelope_case(
        "a manifest with characters outside base64url (a quotation mark)",
        lambda e: e["attachments"][0]["provenance"].update(manifest='a"b.c"d'),
    )
    envelope_case(
        "a manifest with no separator",
        lambda e: e["attachments"][0]["provenance"].update(manifest="abcdef"),
    )
    envelope_case(
        "an unknown provenance kind",
        lambda e: e["attachments"][1].update(provenance={"kind": "clinic-authored"}),
    )
    envelope_case(
        "an attachment over 20 MiB in phase 1",
        lambda e: e["attachments"][1].update(size=21 * MIB, chunk_count=6),
    )

    # --- pair cases (CARLOS's check once it has opened the message).
    pair_cases = []

    def pair_case(name, mutate):
        out = json.loads(outer_bytes)
        env = json.loads(envelope_bytes)
        mutate(out, env)
        pair_cases.append(
            {"name": name, "expect": check_pair(out, env) or "accept"},
        )

    pair_case("as built", lambda o, e: None)
    pair_case("another message id", lambda o, e: e.update(message_id=OTHER_MESSAGE_ID))
    pair_case(
        "an attachment head the portal held that the signed envelope does not name",
        lambda o, e: o["attachments"][0].update(chain_head="f" * 64),
    )
    pair_case("an attachment count that differs", lambda o, e: e["attachments"].pop())
    pair_case(
        "a size that is not the sealed size of the plaintext",
        lambda o, e: o["attachments"][1].update(size=999),
    )

    # --- compact payload cases.
    ack_collected = ack_object("collected", head=head.hex())
    canonical_ack = canonical(ack_collected)
    unsorted = dict(reversed(list(ack_collected.items())))
    reordered = json.dumps(unsorted, separators=(",", ":")).encode()  # keys not sorted
    spaced = json.dumps(ack_collected, sort_keys=True).encode()
    duplicate_key = canonical_ack[:-1] + b',"v":1}'
    compact_cases = []
    for name, raw in [
        ("the canonical payload", canonical_ack),
        ("keys not sorted", reordered),
        ("spaces after the separators", spaced),
        ("a key twice", duplicate_key),
        ("a trailing line feed", canonical_ack + b"\n"),
        ("not JSON", b"not json"),
        ("a float 1.0 for v", b'{"v":1.0}'),
        ("a float with an exponent", b'{"at":1e3,"v":1}'),
        ("NaN", b'{"at":NaN,"v":1}'),
        ("Infinity", b'{"at":Infinity,"v":1}'),
        ("an integer of 2^100", b'{"at":' + str(2**100).encode() + b',"v":1}'),
        ("the largest safe integer 2^53-1", b'{"at":9007199254740991,"v":1}'),
        ("2^53", b'{"at":9007199254740992,"v":1}'),
        ("a negative integer", b'{"at":-1,"v":1}'),
        ("a lone surrogate in a string", b'{"ref":"\\ud800","v":1}'),
        ("a lone surrogate in a key", b'{"\\udc00":"x","v":1}'),
        ("an escaped pair that is a valid character", b'{"ref":"\\ud83d\\ude00","v":1}'),
    ]:
        payload = b64u(raw)
        value, reason = check_compact_payload(payload)
        compact_cases.append(
            {"name": name, "payload_b64url": payload, "expect": reason or "accept"}
        )
    compact_cases.append(
        {
            "name": "padded base64url",
            "payload_b64url": b64u(canonical_ack) + "=",
            "expect": check_compact_payload(b64u(canonical_ack) + "=")[1] or "accept",
        }
    )

    # --- acknowledgement cases.
    ack_cases = []
    for name, value in [
        ("collected", ack_object("collected", head=head.hex())),
        ("filed", ack_object("filed", head=head.hex())),
        ("refused with a reason", ack_object("refused", "type_not_allowed", head=head.hex())),
        ("recalled", ack_object("recalled", head=head.hex())),
        (
            "recall refused with a reason",
            ack_object("recall_refused", "recall_too_late", head=head.hex()),
        ),
        ("refused: key revoked", ack_object("refused", "key_revoked", head=head.hex())),
        ("refused without a reason", ack_object("refused", None, head=head.hex())),
        ("filed with a reason", ack_object("filed", "scan_failed", head=head.hex())),
        ("an unknown reason", ack_object("refused", "because", head=head.hex())),
        ("a recall reason on a refusal", ack_object("refused", "recall_too_late", head=head.hex())),
        (
            "a refusal reason on a recall refusal",
            ack_object("recall_refused", "scan_failed", head=head.hex()),
        ),
        ("a state that means read", ack_object("read", head=head.hex())),
        ("a ref with spaces", ack_object("filed", ref="a b" + "c" * 19, head=head.hex())),
        ("a ref that is not 22 characters", ack_object("filed", ref="short", head=head.hex())),
        ("a clinic_id that is a number", {**ack_object("filed", head=head.hex()), "clinic_id": 5}),
        ("version true", {**ack_object("filed", head=head.hex()), "v": True}),
    ]:
        ack_cases.append({"name": name, "object": value, "expect": check_ack(value) or "accept"})

    # --- recall cases.
    recall = recall_object(head.hex())
    recall_cases = []
    for name, value in [
        ("as built", recall),
        ("a state field added", {**recall, "state": "recalled"}),
        ("a chain_head that is not hex", {**recall, "chain_head": "zz" * 32}),
        ("version 1.0", {**recall, "v": 1.0}),
        ("a clinic_id missing", {k: v for k, v in recall.items() if k != "clinic_id"}),
    ]:
        recall_cases.append(
            {"name": name, "object": value, "expect": check_recall(value) or "accept"}
        )

    # --- recall binding cases (CARLOS: is this recall about THIS message).
    binding_cases = []
    outer_for_binding = json.loads(outer_bytes)
    for name, value in [
        ("as built", recall),
        ("another device_key_id", {**recall, "device_key_id": "other-device"}),
        ("another chain_head", {**recall, "chain_head": "0" * 64}),
        ("another message_id", {**recall, "message_id": OTHER_MESSAGE_ID}),
        ("another clinic_id", {**recall, "clinic_id": "other-clinic"}),
        ("another recipient_id", {**recall, "recipient_id": "other-recipient"}),
    ]:
        binding_cases.append(
            {
                "name": name,
                "recall": value,
                "expect": check_recall_binding(value, outer_for_binding) or "accept",
            }
        )

    # --- inbox key statement cases (checked with a clock).
    now = CREATED_AT
    statement = inbox_key_statement()
    other_key = bytes(range(1, 33))
    inbox_cases = []

    def inbox_case(name, value, at=now, known=None):
        inbox_cases.append(
            {
                "name": name,
                "now": at,
                "known": known,
                "object": value,
                "expect": check_inbox_key(value, at, known=known) or "accept",
            }
        )

    inbox_case("an active statement inside its validity", statement)
    inbox_case("an unknown field", {**statement, "note": "x"})
    inbox_case("a revoked key", inbox_key_statement(status="revoked"))
    inbox_case("not yet valid", inbox_key_statement(not_before=now + 10))
    inbox_case("expired", inbox_key_statement(not_after=now - 1))
    inbox_case("valid for more than 30 days", inbox_key_statement(not_after=now + 31 * 86_400))
    inbox_case(
        "valid for exactly 30 days", inbox_key_statement(not_after=now - 86_400 + 30 * 86_400)
    )
    inbox_case("another clinic's statement", {**statement, "clinic_id": "other-clinic"})
    inbox_case(
        "a serial below the app's high-water mark",
        inbox_key_statement(serial=2),
        known={"serial": 3, "revoked": False},
    )
    inbox_case(
        "the serial the app already holds",
        inbox_key_statement(serial=3),
        known={"serial": 3, "revoked": False},
    )
    inbox_case(
        "a higher serial",
        inbox_key_statement(serial=4),
        known={"serial": 3, "revoked": False},
    )
    inbox_case(
        "active at the same serial as a revocation the app holds",
        inbox_key_statement(serial=3),
        known={"serial": 3, "revoked": True},
    )
    inbox_case(
        "active at a higher serial than a revocation the app holds",
        inbox_key_statement(serial=4),
        known={"serial": 3, "revoked": True},
    )
    inbox_case("a kid that is not the key's hash", {**statement, "kid": inbox_key_kid(other_key)})
    inbox_case("a public key of 31 bytes", {**statement, "public_key": b64u(b"x" * 31)})
    inbox_case("a serial of zero", {**statement, "serial": 0})
    inbox_case("version 2", {**statement, "v": 2})

    # --- the signing inputs: exactly the bytes a signature covers.
    envelope_input = signing_input("envelope", envelope_bytes)
    ack_input = signing_input("ack", canonical_ack)
    recall_bytes = canonical(recall)
    recall_input = signing_input("recall", recall_bytes)
    statement_bytes = canonical(statement)
    statement_input = signing_input("inbox_key", statement_bytes)

    request_hash = lambda method, path, body: digest(  # noqa: E731
        frame(method.encode(), path.encode(), b"", body)
    )

    time_cases = []
    for name, created, expires, clock in [
        ("inside its lifetime", CREATED_AT, EXPIRES_AT, CREATED_AT + 60),
        ("created within the skew ahead", CREATED_AT, EXPIRES_AT, CREATED_AT - 300),
        ("created beyond the skew ahead", CREATED_AT, EXPIRES_AT, CREATED_AT - 301),
        ("already expired", CREATED_AT, EXPIRES_AT, EXPIRES_AT),
        ("expires after more than seven days", CREATED_AT, CREATED_AT + 7 * 86_400 + 1, CREATED_AT),
    ]:
        time_cases.append(
            {
                "name": name,
                "created_at": created,
                "expires_at": expires,
                "now": clock,
                "expect": check_times(created, expires, clock) or "accept",
            }
        )

    text_cases = []
    for name, text, as_name in [
        ("plain text", "FAKE hello", False),
        ("a line feed in a body", "a\nb", False),
        ("a line feed in a name", "a\nb", True),
        ("a decomposed letter", "é", False),
        ("a no-break space inside", "a b", False),
        ("a zero-width joiner", "a‍b", False),
        ("a left-to-right mark", "a‎b", False),
        ("a name with a trailing space", "a.pdf ", True),
    ]:
        text_cases.append(
            {
                "name": name,
                "text": text,
                "as_name": as_name,
                "expect": check_text(text, name=as_name) or "accept",
            }
        )

    worst_envelope, worst_compact, worst_sealed = worst_case_envelope()
    envelope_compact = m["envelope_compact"]

    plain_pieces = {
        "plaintext_a_sha256": digest(m["plain_a"]),
        "plaintext_b_sha256": digest(m["plain_b"]),
    }

    return {
        "description": (
            "FAKE reference vectors for mycarlos-send/1 (patient to clinic), DRAFT for review. "
            "No signature, key, cipher or randomness is used: signing inputs are bytes, and every "
            "hash below is over fixed FAKE bytes. Not a conformance claim for any real component."
        ),
        "format_version": 2,
        "contract": "mycarlos-send/1",
        "canonical_json": (
            "sorted keys, no spaces, UTF-8, strings and integers and null only "
            "(RFC 8785 for these objects)"
        ),
        "frame": "each part preceded by its length as eight bytes, big endian",
        "compact_form": (
            "b64url(payload).b64url(signature), unpadded; the signature covers "
            "signing_input(kind, payload) = frame(domain, payload), never the base64 text; a "
            "verifier requires canonical(parse(payload)) == payload before anything else"
        ),
        "limits": LIMITS,
        "phases": PHASES,
        "refusal_reasons": REFUSAL_REASONS,
        "recall_refusal_reasons": RECALL_REFUSAL_REASONS,
        "ack_states": ACK_STATES,
        "identifiers": {
            "message_id": MESSAGE_ID,
            "attachment_a": ATTACHMENT_A,
            "attachment_b": ATTACHMENT_B,
            "clinic_id": CLINIC_ID,
            "recipient_id": RECIPIENT_ID,
            "other_message_id": OTHER_MESSAGE_ID,
        },
        "signing_domains": {kind: encoded(prefix) for kind, prefix in SIGN_DOMAINS.items()},
        "chain": {
            "definition": {
                "start": (
                    "sha256(frame('mycarlos-send/1 chain-start', message_id16, attachment_id16, "
                    "chunk_count8))"
                ),
                "link": (
                    "sha256(frame('mycarlos-send/1 chain-link', previous32, index8, "
                    "sha256(sealed_chunk)))"
                ),
                "attachment_head": "the link after the last chunk",
                "message_head": (
                    "sha256(frame('mycarlos-send/1 message', message_id16, "
                    "sha256(sealed_envelope), head_of_attachment_0, head_of_attachment_1, ...))"
                ),
                "who_checks": (
                    "the portal recomputes every head from the ciphertext it holds (it can: "
                    "attachment_id is in the outer record), which finds corruption and loss; it "
                    "does NOT protect against the portal, which can recompute anything. The "
                    "protective check is CARLOS's: after opening, the chain heads named inside "
                    "the SIGNED envelope must equal the heads it recomputes from what it fetched"
                ),
            },
            "attachment_a_chunk_sealed_sizes": [len(c) for c in sealed_a],
            "attachment_a_chunk_sha256": [digest(c) for c in sealed_a],
            "attachment_b_chunk_sealed_sizes": [len(c) for c in sealed_b],
            "attachment_b_chunk_sha256": [digest(c) for c in sealed_b],
            "envelope_ciphertext": {"fill": "0xe0", "size": len(envelope_ciphertext)},
            "base": {
                "attachment_a_head": head_a.hex(),
                "attachment_b_head": head_b.hex(),
                "message_head": head.hex(),
            },
            "cases": chain_cases,
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
            "sealed_key": (
                "b64url(enc || ciphertext) of the HPKE seal of the 32-byte content key: 32 + 32 + "
                "16 = 80 bytes, unpadded"
            ),
        },
        "end_to_end": {
            "note": (
                "ONE message in which every size, count, hash, head and descriptor agrees: the "
                "outer record, the envelope and the chunk hashes above describe the same bytes"
            ),
            "plaintext": plain_pieces,
            "envelope": envelope,
            "outer": outer,
            "pair_check": check_pair(outer, envelope) or "accept",
        },
        "envelope": {
            "canonical": encoded(envelope_bytes),
            "signing_input": encoded(envelope_input),
            "signed_by": "the device Ed25519 key",
            "fake_signature_hex": FAKE_DEVICE_SIGNATURE.hex(),
            "sealed_plaintext": {
                "note": (
                    "what the content key seals: ASCII, b64url(canonical payload) + '.' + "
                    "b64url(64-byte signature), unpadded; the sealed envelope is this plus the "
                    "16-byte tag. The signature here is FAKE bytes of the right length"
                ),
                "ascii": envelope_compact.decode("ascii"),
                "size": len(envelope_compact),
                "sha256": digest(envelope_compact),
            },
            "min_sealed_size": min_sealed_envelope_size(),
        },
        "worst_case_envelope": {
            "note": (
                "the largest envelope allowed: 10 attachments each with a 16 KiB manifest, a "
                "body of 8,192 escaped bytes and 120 escaped bytes of name each; it must fit "
                "the budget with headroom, and the envelope checker accepts it"
            ),
            "canonical_size": len(canonical(worst_envelope)),
            "compact_size": len(worst_compact),
            "sealed_size": worst_sealed,
            "budget": LIMITS["envelope_sealed_max"],
            "headroom": LIMITS["envelope_sealed_max"] - worst_sealed,
            "check_envelope": check_envelope(worst_envelope) or "accept",
            "sha256": digest(worst_compact),
        },
        "outer": {
            "canonical": encoded(outer_bytes),
            "create_request_hash": request_hash("POST", "/api/mycarlos/sends", outer_bytes),
            "chunk_request_hash": request_hash(
                "PUT",
                f"/api/mycarlos/sends/{MESSAGE_ID}/attachments/0/chunks/1",
                sealed_a[1],
            ),
        },
        "acks": {
            "signed_by": "a clinic signing key (ECDSA P-256, ES256)",
            "collected": {
                "canonical": encoded(canonical_ack),
                "signing_input": encoded(ack_input),
            },
            "filed": encoded(canonical(ack_object("filed", head=head.hex()))),
            "refused": encoded(canonical(ack_object("refused", "scan_failed", head=head.hex()))),
            "recalled": encoded(canonical(ack_object("recalled", head=head.hex()))),
            "recall_refused": encoded(
                canonical(ack_object("recall_refused", "recall_too_late", head=head.hex()))
            ),
        },
        "recall": {
            "signed_by": "the device Ed25519 key",
            "canonical": encoded(recall_bytes),
            "signing_input": encoded(recall_input),
        },
        "inbox_key": {
            "signed_by": (
                "a clinic signing key (ES256) that the link already pins; the app seals only to a "
                "key named by a statement that verifies, is active and is inside its validity"
            ),
            "canonical": encoded(statement_bytes),
            "signing_input": encoded(statement_input),
            "kid": statement["kid"],
        },
        "compact_cases": compact_cases,
        "outer_cases": outer_cases,
        "envelope_cases": envelope_cases,
        "pair_cases": pair_cases,
        "ack_cases": ack_cases,
        "recall_cases": recall_cases,
        "inbox_key_cases": inbox_cases,
        "recall_binding_cases": binding_cases,
        "time_cases": time_cases,
        "text_cases": text_cases,
        "states": STATES,
        "transitions": TRANSITIONS,
        "rules": RULES,
        "check_order": CHECK_ORDER,
        "routes": ROUTES,
        "idempotency": IDEMPOTENCY,
        "portal_learns": PORTAL_LEARNS,
        "portal_does_not_learn": PORTAL_DOES_NOT_LEARN,
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
