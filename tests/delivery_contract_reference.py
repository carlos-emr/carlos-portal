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

"""Reference implementation of the Send to myCarlos format (docs/architecture/mycarlos-delivery.md).

TEST-ONLY. It writes `tests/fixtures/delivery-contract.json`, the shared vectors that CARLOS
(Java), the portal (Python) and myCarlos (Rust) check. The portal itself never opens a package,
and no runtime module may import this file.

It seals with HPKE (RFC 9180) base mode using a fixed ephemeral key derived from a fixed `ikmE`,
exactly as the RFC's own vectors are made, so its output is reproducible. A real sender must use
a fresh random ephemeral key for every package. All keys here are FAKE test keys.

Regenerate with: `python -m tests.delivery_contract_reference` from the repository root.
"""

import base64
import hashlib
import hmac
import json
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "delivery-contract.json"

# --- Format constants (the spec's section "Constants") ----------------------------------------
FORMAT_VERSION = 1
KEM_ID, KDF_ID, AEAD_ID = 0x0020, 0x0001, 0x0003
HPKE_INFO = b"carlos-emr/mycarlos-delivery/v1"
PLAINTEXT_MAGIC = b"mycarlos-delivery/1"
DEVICE_KEY_ID_LABEL = b"mycarlos-device-key-v1"
MANIFEST_TYPE = "mycarlos-delivery-manifest"
RECEIPT_TYPE = "mycarlos-delivery-receipt"
DEVICE_AUDIENCE = "carlos-patient-portal-device-api"
LINK_AUDIENCE = "carlos-patient-portal-device-link"
RECEIPT_AUDIENCE = "carlos-delivery-receipt"
ASSERTION_HEADER = "X-MyCarlos-Device-Assertion"
ASSERTION_ISSUER = "mycarlos"
ASSERTION_LIFETIME_SECONDS = 60
MAX_ASSERTION_LIFETIME_SECONDS = 120
ASSERTION_CLOCK_SKEW_SECONDS = 30
MAX_DELIVERY_LIFETIME_SECONDS = 7 * 24 * 60 * 60
DEVICE_EXPIRY_SKEW_SECONDS = 24 * 60 * 60
MAX_CIPHERTEXT_BYTES = 20 * 1024 * 1024
LINK_CODE_LIFETIME_SECONDS = 10 * 60
MAX_LINK_CODE_ATTEMPTS = 5
DEVICE_DELIVERIES_PATH = "/api/mycarlos/deliveries"
LINK_PATH = "/api/mycarlos/link"

# --- The fixed scenario -------------------------------------------------------------------------
NOW = 1_792_454_400  # 2026-10-19T12:00:00Z, the "current time" every vector is checked at
CREATED_AT = NOW - 3_600
EXPIRES_AT = CREATED_AT + MAX_DELIVERY_LIFETIME_SECONDS
CLINIC_A = "clinic-a"
CLINIC_B = "clinic-b"
RECIPIENT_ID = "rcp-FAKE0001aaaaaaaaaaaa"
OTHER_RECIPIENT_ID = "rcp-FAKE0002bbbbbbbbbbbb"
DELIVERY_ID = "6f1c2a7e-0b9d-4e53-8a41-2d7c9b0e5f13"
OTHER_DELIVERY_ID = "0d4b8e21-7a3f-4c66-9b12-8e5a1f7c3d90"
SEEN_DELIVERY_ID = "a1e5c9d3-2f47-4b08-8c6e-91d0b3a7e254"
FILED_DELIVERY_ID = "5b2e8d14-9c3a-4f71-a6e0-d47c1b9f8e32"
THIRD_DELIVERY_ID = "c7f3a9b1-4e2d-4a68-9d05-3b8e6f1c2a47"
FAKE_PDF = (
    b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
    b"trailer<</Root 1 0 R>>\n%%EOF\n"
)
VAULT_HEAD = "b5" * 32  # a stand-in vault history head hash (decision L)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def frame(*parts: bytes) -> bytes:
    """8-byte big-endian length before every part: no concatenation is ambiguous."""
    return b"".join(len(part).to_bytes(8, "big") + part for part in parts)


def unframe(data: bytes) -> list[bytes]:
    parts, offset = [], 0
    while offset < len(data):
        if len(data) - offset < 8:
            raise ValueError("truncated length")
        length = int.from_bytes(data[offset : offset + 8], "big")
        offset += 8
        if length > len(data) - offset:
            raise ValueError("truncated part")
        parts.append(data[offset : offset + length])
        offset += length
    return parts


def canonical_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def request_hash(method: str, raw_path: bytes, query_string: bytes, body: bytes) -> str:
    """The same framing as the portal's staff and job request hash."""
    return sha256_hex(frame(method.upper().encode("ascii"), raw_path, query_string, body))


# --- HPKE RFC 9180, base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305 ------
def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


_KEM_SUITE = b"KEM" + _i2osp(KEM_ID, 2)
_HPKE_SUITE = b"HPKE" + _i2osp(KEM_ID, 2) + _i2osp(KDF_ID, 2) + _i2osp(AEAD_ID, 2)


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + suite + label + ikm)


def _labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return _expand(prk, _i2osp(length, 2) + b"HPKE-v1" + suite + label + info, length)


def _raw(public_key: X25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def hpke_derive_key_pair(ikm: bytes) -> tuple[X25519PrivateKey, bytes]:
    prk = _labeled_extract(_KEM_SUITE, b"", b"dkp_prk", ikm)
    private = X25519PrivateKey.from_private_bytes(_labeled_expand(_KEM_SUITE, prk, b"sk", b"", 32))
    return private, _raw(private.public_key())


def _shared_secret(dh: bytes, enc: bytes, pk_r: bytes) -> bytes:
    prk = _labeled_extract(_KEM_SUITE, b"", b"eae_prk", dh)
    return _labeled_expand(_KEM_SUITE, prk, b"shared_secret", enc + pk_r, 32)


def _key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    context = (
        b"\x00"
        + _labeled_extract(_HPKE_SUITE, b"", b"psk_id_hash", b"")
        + _labeled_extract(_HPKE_SUITE, b"", b"info_hash", info)
    )
    secret = _labeled_extract(_HPKE_SUITE, shared_secret, b"secret", b"")
    key = _labeled_expand(_HPKE_SUITE, secret, b"key", context, 32)
    return key, _labeled_expand(_HPKE_SUITE, secret, b"base_nonce", context, 12)


def hpke_seal(pk_r: bytes, info: bytes, aad: bytes, plaintext: bytes, ikm_e: bytes) -> bytes:
    """enc ‖ ciphertext. `ikm_e` fixes the ephemeral key: vectors only, never in a real sender."""
    sk_e, enc = hpke_derive_key_pair(ikm_e)
    dh = sk_e.exchange(X25519PublicKey.from_public_bytes(pk_r))
    key, nonce = _key_schedule(_shared_secret(dh, enc, pk_r), info)
    return enc + ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def hpke_open(sk_r: X25519PrivateKey, info: bytes, aad: bytes, blob: bytes) -> bytes:
    enc, ciphertext = blob[:32], blob[32:]
    dh = sk_r.exchange(X25519PublicKey.from_public_bytes(enc))
    key, nonce = _key_schedule(_shared_secret(dh, enc, _raw(sk_r.public_key())), info)
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


# RFC 9180 Appendix A.2.1 (base mode, this suite), sequence number 0, verbatim.
RFC9180_A21 = {
    "mode": 0,
    "kem_id": KEM_ID,
    "kdf_id": KDF_ID,
    "aead_id": AEAD_ID,
    "info": "4f6465206f6e2061204772656369616e2055726e",
    "ikmE": "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
    "pkEm": "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    "skEm": "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
    "ikmR": "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
    "pkRm": "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
    "skRm": "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
    "enc": "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    "shared_secret": "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
    "key": "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
    "base_nonce": "5c4d98150661b848853b547f",
    "encryptions": [
        {
            "sequence_number": 0,
            "pt": "4265617574792069732074727574682c20747275746820626561757479",
            "aad": "436f756e742d30",
            "nonce": "5c4d98150661b848853b547f",
            "ct": "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db"
            "21993c62ce81883d2dd1b51a28",
        }
    ],
}


# --- Keys ----------------------------------------------------------------------------------------
# Every FAKE private key is derived from readable seed text, so the fixture holds no key material:
# key bytes = SHA-256(UTF-8 seed text). That is the Ed25519 seed or the X25519 private key as is;
# for P-256 the scalar is int(those bytes) mod (n - 1) + 1.
SEED_PREFIX = "FAKE delivery contract test key: "
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def seed_text(label: str) -> str:
    return SEED_PREFIX + label


def _seed(label: str) -> bytes:
    return hashlib.sha256(seed_text(label).encode("utf-8")).digest()


class ClinicKey:
    """A FAKE clinic P-256 signing key (carlos-emr/carlos#4691 in production)."""

    def __init__(self, label: str, clinic_id: str) -> None:
        self.label = label
        scalar = int.from_bytes(_seed(label), "big") % (P256_ORDER - 1) + 1
        self.private = ec.derive_private_key(scalar, ec.SECP256R1())
        self.clinic_id = clinic_id
        self.spki = self.private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.kid = b64url(hashlib.sha256(self.spki).digest())

    def sign(self, message: bytes) -> bytes:
        """ES256 as r ‖ s (32 bytes each), deterministic (RFC 6979) so the fixture reproduces."""
        der = self.private.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def public(self) -> dict[str, str]:
        return {"clinic_id": self.clinic_id, "kid": self.kid, "spki": b64url(self.spki)}

    def described(self) -> dict[str, str]:
        return {**self.public(), "seed_text": seed_text(self.label)}


class DeviceKeys:
    """A FAKE myCarlos device: X25519 to open packages, Ed25519 to sign requests and receipts."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.x25519 = X25519PrivateKey.from_private_bytes(_seed(label + " x25519"))
        self.x25519_public = _raw(self.x25519.public_key())
        self.ed25519 = Ed25519PrivateKey.from_private_bytes(_seed(label + " ed25519"))
        self.ed25519_public = self.ed25519.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.device_key_id = device_key_id(self.x25519_public, self.ed25519_public)

    def public(self) -> dict[str, str]:
        return {
            "device_key_id": self.device_key_id,
            "x25519_public_key": b64url(self.x25519_public),
            "ed25519_public_key": b64url(self.ed25519_public),
        }

    def described(self) -> dict[str, str]:
        return {
            **self.public(),
            "x25519_seed_text": seed_text(self.label + " x25519"),
            "ed25519_seed_text": seed_text(self.label + " ed25519"),
        }


def device_key_id(x25519_public: bytes, ed25519_public: bytes) -> str:
    return b64url(
        hashlib.sha256(DEVICE_KEY_ID_LABEL + frame(x25519_public, ed25519_public)).digest()
    )


def compact_ed25519(key: Ed25519PrivateKey, claims: dict[str, object]) -> str:
    payload = canonical_json(claims)
    return b64url(payload) + "." + b64url(key.sign(payload))


def compact_es256(key: ClinicKey, claims: dict[str, object]) -> str:
    payload = canonical_json(claims)
    return b64url(payload) + "." + b64url(key.sign(payload))


# --- Packages ------------------------------------------------------------------------------
def manifest_claims(
    key: ClinicKey, *, delivery_id: str, recipient_id: str, device: DeviceKeys, pdf: bytes
) -> dict[str, object]:
    return {
        "v": FORMAT_VERSION,
        "typ": MANIFEST_TYPE,
        "delivery_id": delivery_id,
        "recipient_id": recipient_id,
        "device_key_id": device.device_key_id,
        "clinic_id": key.clinic_id,
        "clinic_name": "FAKE Demo Clinic" if key.clinic_id == CLINIC_A else "FAKE Second Clinic",
        "provider_name": "FAKE-Provider, Demo",
        "patient": {"name": "FAKE-Jones, FAKE-Jacky", "birth_date": "1985-06-15"},
        "document": {
            "title": "FAKE chest X-ray report",
            "type": "imaging_report",
            "service_date": "2026-10-18",
            "media_type": "application/pdf",
            "size": len(pdf),
            "sha256": sha256_hex(pdf),
        },
        "created_at": CREATED_AT,
        "expires_at": EXPIRES_AT,
        "kid": key.kid,
    }


def aad_for(delivery_id: str, recipient_id: str, device_key_id_value: str) -> bytes:
    return frame(delivery_id.encode(), recipient_id.encode(), device_key_id_value.encode())


def build_package(
    *,
    manifest: str,
    pdf: bytes,
    device: DeviceKeys,
    outer_delivery_id: str,
    outer_recipient_id: str,
    ikm_label: str,
    padding: bytes | None = None,
    magic: bytes = PLAINTEXT_MAGIC,
    sections: list[bytes] | None = None,
) -> dict[str, object]:
    parts = sections if sections is not None else [magic, manifest.encode("ascii"), pdf]
    if padding is not None:
        parts = [*parts, padding]
    blob = hpke_seal(
        device.x25519_public,
        HPKE_INFO,
        aad_for(outer_delivery_id, outer_recipient_id, device.device_key_id),
        frame(*parts),
        _seed("ephemeral " + ikm_label),
    )
    return {
        "outer": outer_record(blob, outer_delivery_id, outer_recipient_id, device.device_key_id),
        "blob": b64url(blob),
    }


def outer_record(blob: bytes, delivery_id: str, recipient_id: str, dkid: str) -> dict[str, object]:
    return {
        "v": FORMAT_VERSION,
        "suite": {"kem_id": KEM_ID, "kdf_id": KDF_ID, "aead_id": AEAD_ID},
        "delivery_id": delivery_id,
        "recipient_id": recipient_id,
        "device_key_id": dkid,
        "size": len(blob),
        "ciphertext_sha256": sha256_hex(blob),
        "created_at": CREATED_AT,
        "expires_at": EXPIRES_AT,
    }


# --- The receiver's checks, in the spec's order (section "Opening a package") ------------------
class Refused(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _manifest_shape_ok(claims: dict[str, object]) -> bool:
    patient, document = claims["patient"], claims["document"]

    def is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    return (
        all(
            isinstance(claims[name], str)
            for name in (
                "delivery_id",
                "recipient_id",
                "device_key_id",
                "clinic_id",
                "clinic_name",
                "provider_name",
                "kid",
            )
        )
        and is_int(claims["created_at"])
        and is_int(claims["expires_at"])
        and isinstance(patient, dict)
        and set(patient) == {"name", "birth_date"}
        and all(isinstance(value, str) for value in patient.values())
        and isinstance(document, dict)
        and set(document) == {"title", "type", "service_date", "media_type", "size", "sha256"}
        and document["media_type"] == "application/pdf"
        and is_int(document["size"])
        and all(
            isinstance(document[name], str) for name in ("title", "type", "service_date", "sha256")
        )
    )


def open_package(
    package: dict[str, object],
    *,
    device: DeviceKeys,
    link: dict[str, object],
    all_links: list[dict[str, object]],
    filed: dict[str, str],
    now: int,
) -> tuple[str, dict[str, object]]:
    """Returns ("file", claims), or ("already_filed", claims) for a copy filed before.

    `filed` maps each delivery ID the device has filed to that copy's ciphertext hash.
    """
    outer, blob = package["outer"], b64url_decode(package["blob"])
    if outer["v"] != FORMAT_VERSION or outer["suite"] != {
        "kem_id": KEM_ID,
        "kdf_id": KDF_ID,
        "aead_id": AEAD_ID,
    }:
        raise Refused("unsupported_version")
    if outer["size"] != len(blob) or outer["ciphertext_sha256"] != sha256_hex(blob):
        raise Refused("hash_mismatch")
    if outer["recipient_id"] != link["recipient_id"]:
        raise Refused("wrong_recipient")
    if outer["device_key_id"] != device.device_key_id:
        raise Refused("wrong_device")
    aad = aad_for(outer["delivery_id"], outer["recipient_id"], outer["device_key_id"])
    try:
        plaintext = hpke_open(device.x25519, HPKE_INFO, aad, blob)
    except Exception:
        raise Refused("decrypt_failed") from None
    try:
        sections = unframe(plaintext)
    except ValueError:
        raise Refused("bad_package") from None
    if not sections or not sections[0].startswith(b"mycarlos-delivery/"):
        raise Refused("bad_package")
    if sections[0] != PLAINTEXT_MAGIC:
        raise Refused("unsupported_version")
    if len(sections) not in (3, 4):  # magic, manifest, document, optional padding (ignored)
        raise Refused("bad_package")
    manifest_text, pdf = sections[1].decode("ascii", "replace"), sections[2]
    encoded_payload, dot, encoded_signature = manifest_text.partition(".")
    try:
        payload = b64url_decode(encoded_payload)
        claims = json.loads(payload)
        signature = b64url_decode(encoded_signature)
    except Exception:
        raise Refused("bad_manifest") from None
    expected = {
        "v",
        "typ",
        "delivery_id",
        "recipient_id",
        "device_key_id",
        "clinic_id",
        "clinic_name",
        "provider_name",
        "patient",
        "document",
        "created_at",
        "expires_at",
        "kid",
    }
    if not dot or not isinstance(claims, dict) or set(claims) != expected:
        raise Refused("bad_manifest")
    if claims["v"] != FORMAT_VERSION or claims["typ"] != MANIFEST_TYPE:
        raise Refused("bad_manifest")
    if not _manifest_shape_ok(claims):
        raise Refused("bad_manifest")
    pinned = {key["kid"]: key for key in link["clinic_keys"]}
    if claims["kid"] not in pinned:
        other_links = [
            other
            for other in all_links
            if other is not link
            and any(key["kid"] == claims["kid"] for key in other["clinic_keys"])
        ]
        raise Refused("wrong_clinic" if other_links else "unknown_clinic_key")
    if pinned[claims["kid"]]["status"] != "active":
        raise Refused("revoked_clinic_key")
    if claims["clinic_id"] != link["clinic_id"]:
        raise Refused("wrong_clinic")
    public_key = serialization.load_der_public_key(b64url_decode(pinned[claims["kid"]]["spki"]))
    if len(signature) != 64:
        raise Refused("bad_signature")
    try:
        public_key.verify(
            encode_dss_signature(
                int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            ),
            payload,
            ec.ECDSA(hashes.SHA256()),
        )
    except Exception:
        raise Refused("bad_signature") from None
    if (claims["delivery_id"], claims["recipient_id"], claims["device_key_id"]) != (
        outer["delivery_id"],
        outer["recipient_id"],
        outer["device_key_id"],
    ):
        raise Refused("id_mismatch")
    document = claims["document"]
    if document["sha256"] != sha256_hex(pdf) or document["size"] != len(pdf):
        raise Refused("document_hash_mismatch")
    if now > claims["expires_at"] + DEVICE_EXPIRY_SKEW_SECONDS:
        raise Refused("expired")
    if claims["delivery_id"] in filed:
        # The same copy again means the receipt was lost after filing: send it again, file
        # nothing. A different copy under a filed delivery ID is a replay.
        if filed[claims["delivery_id"]] != outer["ciphertext_sha256"]:
            raise Refused("replayed")
        return "already_filed", claims
    return "file", claims


# --- The fixture ---------------------------------------------------------------------------
def build_contract() -> dict[str, object]:
    clinic_a = ClinicKey("clinic-a signing key 1", CLINIC_A)
    clinic_a_revoked = ClinicKey("clinic-a signing key 0 (revoked)", CLINIC_A)
    clinic_b = ClinicKey("clinic-b signing key 1", CLINIC_B)
    unknown = ClinicKey("an unknown signing key", CLINIC_A)
    device = DeviceKeys("device 1")
    other_device = DeviceKeys("device 2")
    third_device = DeviceKeys("device 3")
    new_device = DeviceKeys("device 4")

    def key_entry(key: ClinicKey, status: str) -> dict[str, str]:
        return {**key.public(), "status": status}

    link_a = {
        "name": "link to clinic-a",
        "clinic_id": CLINIC_A,
        "recipient_id": RECIPIENT_ID,
        "clinic_keys": [key_entry(clinic_a, "active"), key_entry(clinic_a_revoked, "revoked")],
    }
    link_b = {
        "name": "link to clinic-b",
        "clinic_id": CLINIC_B,
        "recipient_id": "rcp-FAKE0003cccccccccccc",
        "clinic_keys": [key_entry(clinic_b, "active")],
    }

    def manifest(key: ClinicKey = clinic_a, **changes: object) -> str:
        claims = manifest_claims(
            key, delivery_id=DELIVERY_ID, recipient_id=RECIPIENT_ID, device=device, pdf=FAKE_PDF
        )
        claims.update(changes)
        return compact_es256(key, claims)

    good_claims = manifest_claims(
        clinic_a, delivery_id=DELIVERY_ID, recipient_id=RECIPIENT_ID, device=device, pdf=FAKE_PDF
    )
    good = compact_es256(clinic_a, good_claims)
    assert good == manifest()

    def package(name: str, **overrides: object) -> dict[str, object]:
        args: dict[str, object] = {
            "manifest": good,
            "pdf": FAKE_PDF,
            "device": device,
            "outer_delivery_id": DELIVERY_ID,
            "outer_recipient_id": RECIPIENT_ID,
            "ikm_label": name,
        }
        args.update(overrides)
        return {"name": name, **build_package(**args)}

    filed_again = package(
        "a copy the device filed but never confirmed",
        manifest=manifest(delivery_id=FILED_DELIVERY_ID),
        outer_delivery_id=FILED_DELIVERY_ID,
    )
    filed = {
        SEEN_DELIVERY_ID: sha256_hex(b"FAKE an earlier, different copy"),
        FILED_DELIVERY_ID: filed_again["outer"]["ciphertext_sha256"],
    }
    accepted = [
        {**package("a delivery"), "now": NOW, "expect": "file"},
        {**package("with a padding section", padding=b"\x00" * 64), "now": NOW, "expect": "file"},
        {
            **package("past expiry, within the 24 h device clock skew"),
            "now": EXPIRES_AT + DEVICE_EXPIRY_SKEW_SECONDS - 60,
            "expect": "file",
        },
        {
            **filed_again,
            "now": NOW,
            "expect": "already_filed",
            "note": "the receipt was lost after filing; send it again and file nothing",
        },
    ]

    def refusal(code: str, pkg: dict[str, object], now: int = NOW) -> dict[str, object]:
        return {**pkg, "now": now, "expect": code}

    tampered = package("tampered ciphertext")
    blob = bytearray(b64url_decode(tampered["blob"]))
    blob[-1] ^= 0x01
    tampered["blob"] = b64url(bytes(blob))
    tampered["outer"] = {
        **tampered["outer"],
        "size": len(blob),
        "ciphertext_sha256": sha256_hex(bytes(blob)),
    }
    hash_mismatch = package("outer hash does not match the blob")
    hash_mismatch["outer"] = {**hash_mismatch["outer"], "ciphertext_sha256": "00" * 32}
    future_version = package("outer record version 2")
    future_version["outer"] = {**future_version["outer"], "v": 2}
    payload_text, _, signature_text = good.partition(".")
    edited = json.loads(b64url_decode(payload_text))
    edited["document"] = {**edited["document"], "title": "FAKE edited title"}
    bad_signature = b64url(canonical_json(edited)) + "." + signature_text

    refusals = [
        refusal("unsupported_version", future_version),
        refusal("hash_mismatch", hash_mismatch),
        refusal(
            "wrong_recipient",
            package(
                "sealed for another recipient",
                manifest=manifest(recipient_id=OTHER_RECIPIENT_ID),
                outer_recipient_id=OTHER_RECIPIENT_ID,
            ),
        ),
        {
            **refusal(
                "wrong_device",
                package("sealed for another device", device=other_device),
            ),
            "note": "the outer record names device 2; checked before any decryption",
        },
        refusal("decrypt_failed", tampered),
        refusal(
            "bad_package",
            package("not a delivery plaintext", sections=[b"something else", b"x", b"y"]),
        ),
        refusal(
            "unsupported_version",
            package("plaintext version 2", magic=b"mycarlos-delivery/2"),
        ),
        refusal(
            "bad_manifest",
            package(
                "manifest missing a claim",
                manifest=compact_es256(
                    clinic_a,
                    {
                        key: value
                        for key, value in manifest_claims(
                            clinic_a,
                            delivery_id=DELIVERY_ID,
                            recipient_id=RECIPIENT_ID,
                            device=device,
                            pdf=FAKE_PDF,
                        ).items()
                        if key != "provider_name"
                    },
                ),
            ),
        ),
        refusal(
            "bad_manifest",
            package(
                "a document that is not a PDF",
                manifest=manifest(document={**good_claims["document"], "media_type": "text/html"}),
            ),
        ),
        refusal(
            "unknown_clinic_key",
            package("signed by an unknown key", manifest=manifest(unknown, kid=unknown.kid)),
        ),
        refusal(
            "revoked_clinic_key",
            package(
                "signed by a revoked key",
                manifest=manifest(clinic_a_revoked, kid=clinic_a_revoked.kid),
            ),
        ),
        {
            **refusal(
                "wrong_clinic",
                package(
                    "genuine clinic-b package served through the clinic-a link",
                    manifest=manifest(clinic_b, kid=clinic_b.kid, clinic_id=CLINIC_B),
                ),
            ),
            "note": "clinic-b's key is pinned, but on the device's other link",
        },
        refusal(
            "wrong_clinic",
            package(
                "clinic-a key, manifest naming clinic-b",
                manifest=manifest(clinic_id=CLINIC_B),
            ),
        ),
        refusal("bad_signature", package("manifest edited after signing", manifest=bad_signature)),
        {
            **refusal(
                "id_mismatch",
                package(
                    "a genuine manifest re-sealed under another delivery ID",
                    outer_delivery_id=OTHER_DELIVERY_ID,
                ),
            ),
            "note": "outer record and AAD say one delivery ID, the signed manifest another",
        },
        {
            **refusal(
                "id_mismatch",
                package(
                    "a genuine manifest for device 2 re-sealed to device 1",
                    manifest=compact_es256(
                        clinic_a,
                        manifest_claims(
                            clinic_a,
                            delivery_id=DELIVERY_ID,
                            recipient_id=RECIPIENT_ID,
                            device=other_device,
                            pdf=FAKE_PDF,
                        ),
                    ),
                ),
            ),
            "note": "the portal holds device 1's public key and could seal; the signature stops it",
        },
        refusal(
            "document_hash_mismatch",
            package(
                "document bytes differ from the signed hash",
                pdf=FAKE_PDF + b"% FAKE appended line\n",
            ),
        ),
        refusal(
            "expired",
            package("past expiry and the 24 h skew"),
            now=EXPIRES_AT + DEVICE_EXPIRY_SKEW_SECONDS + 1,
        ),
        refusal(
            "replayed",
            package(
                "a different copy under a delivery ID the device has filed",
                manifest=manifest(delivery_id=SEEN_DELIVERY_ID),
                outer_delivery_id=SEEN_DELIVERY_ID,
            ),
        ),
    ]

    # What the portal decides when CARLOS uploads each package. It never opens one, so it can
    # only refuse what the outer record and the blob's own bytes show.
    upload_refusals = {"outer hash does not match the blob", "outer record version 2"}
    for vector in [*accepted, *refusals]:
        vector["portal_upload"] = (
            "invalid_delivery" if vector["name"] in upload_refusals else "accept"
        )

    # Check every vector against the reference receiver before writing it.
    for vector in accepted:
        outcome, _ = open_package(
            vector,
            device=device,
            link=link_a,
            all_links=[link_a, link_b],
            filed=filed,
            now=vector["now"],
        )
        assert outcome == vector["expect"], (vector["name"], outcome)
    for vector in refusals:
        try:
            open_package(
                vector,
                device=device,
                link=link_a,
                all_links=[link_a, link_b],
                filed=filed,
                now=vector["now"],
            )
        except Refused as refused:
            assert refused.code == vector["expect"], (vector["name"], refused.code)
        else:
            raise AssertionError(f"{vector['name']} was accepted")

    return {
        "description": (
            "Shared vectors for Send to myCarlos (docs/architecture/mycarlos-delivery.md). "
            "Generated by tests/delivery_contract_reference.py; do not edit by hand. "
            "Every key is a FAKE test key derived from its seed text (keys.derivation). "
            "Receivers must accept and refuse exactly as listed. Senders cannot reproduce the "
            "seals (the ephemeral key is fixed here), so they are checked by round trip."
        ),
        "format_version": FORMAT_VERSION,
        "constants": {
            "hpke": {"mode": 0, "kem_id": KEM_ID, "kdf_id": KDF_ID, "aead_id": AEAD_ID},
            "hpke_info": HPKE_INFO.decode(),
            "plaintext_magic": PLAINTEXT_MAGIC.decode(),
            "device_key_id_label": DEVICE_KEY_ID_LABEL.decode(),
            "manifest_typ": MANIFEST_TYPE,
            "receipt_typ": RECEIPT_TYPE,
            "device_audience": DEVICE_AUDIENCE,
            "link_audience": LINK_AUDIENCE,
            "receipt_audience": RECEIPT_AUDIENCE,
            "assertion_header": ASSERTION_HEADER,
            "assertion_issuer": ASSERTION_ISSUER,
            "assertion_lifetime_seconds": ASSERTION_LIFETIME_SECONDS,
            "max_assertion_lifetime_seconds": MAX_ASSERTION_LIFETIME_SECONDS,
            "assertion_clock_skew_seconds": ASSERTION_CLOCK_SKEW_SECONDS,
            "max_delivery_lifetime_seconds": MAX_DELIVERY_LIFETIME_SECONDS,
            "device_expiry_skew_seconds": DEVICE_EXPIRY_SKEW_SECONDS,
            "max_ciphertext_bytes": MAX_CIPHERTEXT_BYTES,
            "link_code_lifetime_seconds": LINK_CODE_LIFETIME_SECONDS,
            "max_link_code_attempts": MAX_LINK_CODE_ATTEMPTS,
        },
        "hpke_rfc9180_a2_1": RFC9180_A21,
        "keys": {
            "derivation": (
                "key bytes = SHA-256(UTF-8 seed_text). Ed25519: the 32-byte seed. X25519: the "
                "32-byte private key. P-256: scalar = int(key bytes, big-endian) mod (n - 1) + 1."
            ),
            "clinic_a": clinic_a.described(),
            "clinic_a_revoked": clinic_a_revoked.described(),
            "clinic_b": clinic_b.described(),
            "unknown_clinic": unknown.described(),
            "device": device.described(),
            "other_device": other_device.described(),
            "third_device": third_device.described(),
            "new_device": new_device.described(),
        },
        "sender": {
            "note": (
                "What CARLOS builds for packages.accept[0]. The manifest is reproducible "
                "(RFC 8785 JSON, RFC 6979 ES256), and so are the plaintext and AAD; the seal is "
                "not, so a sender test seals with a fresh ephemeral key and opens the result "
                "with keys.device."
            ),
            "signing_key": "clinic_a",
            "recipient": "device",
            "document_b64url": b64url(FAKE_PDF),
            "manifest_claims": good_claims,
            "manifest": good,
            "aad_hex": aad_for(DELIVERY_ID, RECIPIENT_ID, device.device_key_id).hex(),
            "plaintext_sha256": sha256_hex(frame(PLAINTEXT_MAGIC, good.encode("ascii"), FAKE_PDF)),
        },
        "receiver": {
            "device": "device",
            "links": [link_a, link_b],
            "package_link": link_a["name"],
            "filed": [
                {"delivery_id": delivery_id, "ciphertext_sha256": ciphertext_sha256}
                for delivery_id, ciphertext_sha256 in filed.items()
            ],
        },
        "packages": {"accept": accepted, "refuse": refusals},
        "portal": portal_vectors(device, other_device, third_device, new_device, accepted[0]),
    }


def _jti(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:mycarlos-delivery-contract:" + name))


def delivery_path(delivery_id: str) -> str:
    return f"{DEVICE_DELIVERIES_PATH}/{delivery_id}"


def receipt_path(delivery_id: str) -> str:
    return f"{DEVICE_DELIVERIES_PATH}/{delivery_id}/receipt"


def portal_vectors(
    device: DeviceKeys,
    other_device: DeviceKeys,
    third_device: DeviceKeys,
    new_device: DeviceKeys,
    delivered: dict[str, object],
) -> dict[str, object]:
    """What the portal checks: device-signed requests, link requests and receipts.

    Each vector runs against a fresh copy of `state`, after the vector named in `after`, if any.
    """
    third_copy = outer_record(
        b"FAKE stand-in ciphertext for device 3",
        THIRD_DELIVERY_ID,
        RECIPIENT_ID,
        third_device.device_key_id,
    )

    def request(
        name: str,
        method: str,
        path: str,
        body: bytes = b"",
        *,
        signer: DeviceKeys = device,
        **changes: object,
    ) -> dict[str, object]:
        claims: dict[str, object] = {
            "aud": DEVICE_AUDIENCE,
            "iss": ASSERTION_ISSUER,
            "kid": device.device_key_id,
            "recipient_id": RECIPIENT_ID,
            "jti": _jti(name),
            "iat": NOW,
            "exp": NOW + ASSERTION_LIFETIME_SECONDS,
            "request_hash": request_hash(method, path.encode(), b"", body),
        }
        claims.update(changes)
        return {
            "name": name,
            "method": method,
            "path": path,
            "query": "",
            "body": body.decode(),
            "assertion": compact_ed25519(signer.ed25519, claims),
        }

    receipt_claims: dict[str, object] = {
        "typ": RECEIPT_TYPE,
        "aud": RECEIPT_AUDIENCE,
        "delivery_id": DELIVERY_ID,
        "recipient_id": RECIPIENT_ID,
        "device_key_id": device.device_key_id,
        "ciphertext_sha256": delivered["outer"]["ciphertext_sha256"],
        "document_sha256": sha256_hex(FAKE_PDF),
        "picked_up_at": NOW,
        "vault_head": VAULT_HEAD,
        "jti": _jti("receipt"),
    }
    receipt = compact_ed25519(device.ed25519, receipt_claims)
    receipt_body = canonical_json({"receipt": receipt})

    def receipt_vector(
        name: str, expect: str, *, route: str = DELIVERY_ID, signer: DeviceKeys = device, **changes
    ) -> dict[str, object]:
        claims = {**receipt_claims, **changes}
        claims = {key: value for key, value in claims.items() if value is not None}
        return {
            "name": name,
            "expect": expect,
            "device": "device",
            "delivery_id": route,
            "receipt": compact_ed25519(signer.ed25519, claims),
        }

    def link_body(link_id: str, code: str, keys: DeviceKeys = new_device, name: str = "") -> bytes:
        return canonical_json(
            {
                "link_id": link_id,
                "code": code,
                "device_name": name or "FAKE Linux laptop",
                "ed25519_public_key": b64url(keys.ed25519_public),
                "x25519_public_key": b64url(keys.x25519_public),
            }
        )

    def link_request(
        name: str,
        expect: str,
        body: bytes,
        *,
        signer: DeviceKeys = new_device,
        signed_body: bytes | None = None,
        **changes: object,
    ) -> dict[str, object]:
        claims: dict[str, object] = {
            "aud": LINK_AUDIENCE,
            "iss": ASSERTION_ISSUER,
            "kid": signer.device_key_id,
            "jti": _jti("link: " + name),
            "iat": NOW,
            "exp": NOW + ASSERTION_LIFETIME_SECONDS,
            "request_hash": request_hash(
                "POST", LINK_PATH.encode(), b"", body if signed_body is None else signed_body
            ),
        }
        claims.update(changes)
        return {
            "name": name,
            "expect": expect,
            "method": "POST",
            "path": LINK_PATH,
            "query": "",
            "body": body.decode(),
            "assertion": compact_ed25519(signer.ed25519, claims),
        }

    codes = {
        "FAKELNK1": "FAKE-7Q2M-4KXP",
        "FAKELNK2": "FAKE-9D3R-HW6T",
        "FAKELNK3": "FAKE-2B8N-QJ5V",
        "FAKELNK4": "FAKE-6C1Z-MR7Y",
        "FAKELNK5": "FAKE-4H9W-TK2D",
        "FAKELNK6": "FAKE-8P3F-XN6S",
    }

    def code_row(link_id: str, account: str, **changes: object) -> dict[str, object]:
        row: dict[str, object] = {
            "link_id": link_id,
            "code": codes[link_id],
            "account": account,
            "session_signed_in": True,
            "status": "unused",
            "expires_at": NOW + 300,
            "wrong_attempts": 0,
        }
        row.update(changes)
        return row

    first = request("list waiting copies", "GET", DEVICE_DELIVERIES_PATH)
    good_link = link_body("FAKELNK1", codes["FAKELNK1"])
    return {
        "state": {
            "now": NOW,
            "accounts": [
                {"account": "account-1", "recipient_id": RECIPIENT_ID, "clinic_id": CLINIC_A},
                {"account": "account-2", "recipient_id": OTHER_RECIPIENT_ID, "clinic_id": CLINIC_A},
            ],
            "devices": [
                {**device.public(), "account": "account-1", "status": "active"},
                {**other_device.public(), "account": "account-1", "status": "removed"},
                {**third_device.public(), "account": "account-1", "status": "active"},
            ],
            "deliveries": [dict(delivered["outer"]), third_copy],
            "link_codes": [
                code_row("FAKELNK1", "account-1"),
                code_row("FAKELNK2", "account-2"),
                code_row("FAKELNK3", "account-1", expires_at=NOW - 1),
                code_row("FAKELNK4", "account-1", status="used"),
                code_row("FAKELNK5", "account-1", session_signed_in=False),
                code_row("FAKELNK6", "account-1", wrong_attempts=MAX_LINK_CODE_ATTEMPTS),
            ],
        },
        "device_requests": [
            {**first, "expect": "accept", "returns": [DELIVERY_ID]},
            {
                **request(
                    "check in with the vault head",
                    "GET",
                    DEVICE_DELIVERIES_PATH,
                    vault_head=VAULT_HEAD,
                ),
                "expect": "accept",
                "returns": [DELIVERY_ID],
            },
            {
                **request("download one copy", "GET", delivery_path(DELIVERY_ID)),
                "expect": "accept",
                "returns": DELIVERY_ID,
            },
            {
                **request("send the receipt", "POST", receipt_path(DELIVERY_ID), receipt_body),
                "expect": "accept",
                "returns": DELIVERY_ID,
            },
            {
                **request(
                    "the same request again",
                    "GET",
                    DEVICE_DELIVERIES_PATH,
                    jti=_jti("list waiting copies"),
                ),
                "expect": "replay",
                "after": first["name"],
            },
            {
                **request("expired", "GET", DEVICE_DELIVERIES_PATH, iat=NOW - 600, exp=NOW - 540),
                "expect": "expired",
            },
            {
                **request(
                    "issued in the future",
                    "GET",
                    DEVICE_DELIVERIES_PATH,
                    iat=NOW + 300,
                    exp=NOW + 360,
                ),
                "expect": "invalid_assertion",
            },
            {
                **request("lifetime over 120 s", "GET", DEVICE_DELIVERIES_PATH, exp=NOW + 600),
                "expect": "invalid_assertion",
            },
            {
                **request(
                    "staff audience",
                    "GET",
                    DEVICE_DELIVERIES_PATH,
                    aud="carlos-patient-portal-internal-api",
                ),
                "expect": "invalid_assertion",
            },
            {
                **request("link audience", "GET", DEVICE_DELIVERIES_PATH, aud=LINK_AUDIENCE),
                "expect": "invalid_assertion",
            },
            {
                **request("an extra claim", "GET", DEVICE_DELIVERIES_PATH, scope="all"),
                "expect": "invalid_assertion",
            },
            {
                **request(
                    "a vault head that is not a SHA-256",
                    "GET",
                    DEVICE_DELIVERIES_PATH,
                    vault_head="not-a-hash",
                ),
                "expect": "invalid_assertion",
            },
            {
                **request(
                    "signed by another device's key",
                    "GET",
                    DEVICE_DELIVERIES_PATH,
                    signer=other_device,
                ),
                "expect": "invalid_assertion",
            },
            {
                **request(
                    "unknown device",
                    "GET",
                    DEVICE_DELIVERIES_PATH,
                    signer=new_device,
                    kid=new_device.device_key_id,
                ),
                "expect": "unknown_device",
            },
            {
                **request(
                    "removed device",
                    "GET",
                    DEVICE_DELIVERIES_PATH,
                    signer=other_device,
                    kid=other_device.device_key_id,
                ),
                "expect": "device_removed",
            },
            {
                **{
                    **request("signed for another path", "GET", DEVICE_DELIVERIES_PATH),
                    "path": delivery_path(DELIVERY_ID),
                },
                "expect": "request_mismatch",
            },
            {
                **{
                    **request(
                        "body changed after signing",
                        "POST",
                        receipt_path(DELIVERY_ID),
                        receipt_body,
                    ),
                    "body": canonical_json({"receipt": receipt + "x"}).decode(),
                },
                "expect": "request_mismatch",
            },
            {
                **request(
                    "another patient's recipient ID",
                    "GET",
                    DEVICE_DELIVERIES_PATH,
                    recipient_id=OTHER_RECIPIENT_ID,
                ),
                "expect": "recipient_mismatch",
            },
            {
                **request(
                    "download another device's copy", "GET", delivery_path(THIRD_DELIVERY_ID)
                ),
                "expect": "delivery_not_found",
            },
            {
                **request("download a copy that is gone", "GET", delivery_path(SEEN_DELIVERY_ID)),
                "expect": "delivery_not_found",
            },
        ],
        "receipts": [
            receipt_vector("the receipt for a picked-up copy", "accept"),
            receipt_vector(
                "ciphertext hash differs from the stored copy",
                "receipt_mismatch",
                ciphertext_sha256="00" * 32,
            ),
            receipt_vector(
                "receipt names another delivery than the route",
                "receipt_mismatch",
                delivery_id=OTHER_DELIVERY_ID,
            ),
            receipt_vector(
                "route names another device's copy",
                "delivery_not_found",
                route=THIRD_DELIVERY_ID,
                delivery_id=THIRD_DELIVERY_ID,
            ),
            receipt_vector("signed by another device", "invalid_receipt", signer=other_device),
            receipt_vector(
                "names another device",
                "invalid_receipt",
                device_key_id=third_device.device_key_id,
            ),
            receipt_vector(
                "another patient's recipient ID",
                "invalid_receipt",
                recipient_id=OTHER_RECIPIENT_ID,
            ),
            receipt_vector("missing the vault head", "invalid_receipt", vault_head=None),
            receipt_vector("device request audience", "invalid_receipt", aud=DEVICE_AUDIENCE),
        ],
        "link_requests": [
            {
                **link_request("link a new device", "accept", good_link),
                "returns": {"account": "account-1", "recipient_id": RECIPIENT_ID},
            },
            {
                **link_request(
                    "a code from another account's link",
                    "link_code_invalid",
                    link_body("FAKELNK2", codes["FAKELNK1"]),
                ),
                "note": "link_id names account-2's pending link; the code is account-1's",
            },
            link_request(
                "an expired code",
                "link_code_invalid",
                link_body("FAKELNK3", codes["FAKELNK3"]),
            ),
            link_request(
                "a used code", "link_code_invalid", link_body("FAKELNK4", codes["FAKELNK4"])
            ),
            link_request(
                "the session that showed the code has signed out",
                "link_code_invalid",
                link_body("FAKELNK5", codes["FAKELNK5"]),
            ),
            link_request(
                "too many wrong codes for this link",
                "link_code_invalid",
                link_body("FAKELNK6", codes["FAKELNK6"]),
            ),
            link_request(
                "an unknown link ID",
                "link_code_invalid",
                link_body("FAKELNK9", codes["FAKELNK1"]),
            ),
            link_request(
                "signed by a key other than the one in the body",
                "invalid_assertion",
                good_link,
                signer=other_device,
                kid=new_device.device_key_id,
            ),
            link_request(
                "kid is not the body keys' fingerprint",
                "invalid_assertion",
                good_link,
                kid=other_device.device_key_id,
            ),
            link_request(
                "device audience on the link route",
                "invalid_assertion",
                good_link,
                aud=DEVICE_AUDIENCE,
            ),
            link_request(
                "device name changed after signing",
                "request_mismatch",
                link_body("FAKELNK1", codes["FAKELNK1"], name="FAKE renamed device"),
                signed_body=good_link,
            ),
            link_request(
                "a device key that is already linked",
                "device_exists",
                link_body("FAKELNK1", codes["FAKELNK1"], keys=device),
                signer=device,
            ),
        ],
    }


def render() -> str:
    return json.dumps(build_contract(), indent=2, sort_keys=False, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE_PATH.write_text(render(), encoding="utf-8")
    print(f"wrote {FIXTURE_PATH}")
