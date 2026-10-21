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

"""Send to myCarlos contract (M0): the shared vectors, and the checks the portal itself makes.

The portal never opens a package. It checks the outer record of each upload, device-signed
requests, link requests and pickup receipts. The checks here are the reference the M2 routes
must match (carlos-emr/carlos-portal#41); those routes will run these same vectors.
"""

import copy
import json
import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from carlos_patient_portal.staff_identity import staff_request_hash
from tests import delivery_contract_reference as ref

CONTRACT = json.loads(ref.FIXTURE_PATH.read_text(encoding="utf-8"))
CONSTANTS = CONTRACT["constants"]
PORTAL = CONTRACT["portal"]
SPEC_PATH = Path(__file__).parents[1] / "docs" / "architecture" / "mycarlos-delivery.md"

HEX64 = re.compile(r"[0-9a-f]{64}")
OPAQUE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
OUTER_FIELDS = {
    "v",
    "suite",
    "delivery_id",
    "recipient_id",
    "device_key_id",
    "size",
    "ciphertext_sha256",
    "created_at",
    "expires_at",
}
DEVICE_CLAIMS = {"aud", "iss", "kid", "recipient_id", "jti", "iat", "exp", "request_hash"}
DEVICE_OPTIONAL_CLAIMS = {"vault_head"}
LINK_CLAIMS = {"aud", "iss", "kid", "jti", "iat", "exp", "request_hash"}
LINK_BODY_FIELDS = {"link_id", "code", "device_name", "x25519_public_key", "ed25519_public_key"}
RECEIPT_CLAIMS = {
    "typ",
    "aud",
    "delivery_id",
    "recipient_id",
    "device_key_id",
    "ciphertext_sha256",
    "document_sha256",
    "picked_up_at",
    "vault_head",
    "jti",
}
MAX_ASSERTION_BYTES = 4096
DELIVERY_ROUTE = re.compile(r"/api/mycarlos/deliveries/([0-9a-f-]{36})(/receipt)?")


class Refusal(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _strict_b64url(value: object, code: str, length: int | None = None) -> bytes:
    """Only the canonical unpadded form, as the staff assertion check requires."""
    if not isinstance(value, str) or not value.isascii():
        raise Refusal(code)
    try:
        decoded = urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        raise Refusal(code) from None
    if _b64url(decoded) != value or (length is not None and len(decoded) != length):
        raise Refusal(code)
    return decoded


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    claims: dict[str, object] = {}
    for name, value in pairs:
        if name in claims:
            raise ValueError("duplicate claim")
        claims[name] = value
    return claims


def _parse_compact(token: object, code: str) -> tuple[bytes, dict[str, object], bytes]:
    if not isinstance(token, str) or not token or len(token.encode()) > MAX_ASSERTION_BYTES:
        raise Refusal(code)
    encoded_payload, dot, encoded_signature = token.partition(".")
    if not dot or not encoded_payload or "." in encoded_signature:
        raise Refusal(code)
    payload = _strict_b64url(encoded_payload, code)
    signature = _strict_b64url(encoded_signature, code, 64)
    try:
        claims = json.loads(payload, object_pairs_hook=_no_duplicates)
    except ValueError:
        raise Refusal(code) from None
    if not isinstance(claims, dict):
        raise Refusal(code)
    return payload, claims, signature


def _is_link_text(value: object, length: int) -> bool:
    """A link ID or code as sent: exactly `length` characters of the link-code alphabet."""
    return (
        isinstance(value, str)
        and len(value) == length
        and set(value) <= set(CONSTANTS["link_code_alphabet"])
    )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        return False


def _check_assertion_shape(
    claims: dict[str, object], audience: str, required: set[str], optional: set[str]
) -> None:
    if not required <= set(claims) <= required | optional:
        raise Refusal("invalid_assertion")
    if claims["aud"] != audience or claims["iss"] != CONSTANTS["assertion_issuer"]:
        raise Refusal("invalid_assertion")
    if not _is_uuid(claims["jti"]) or not _is_int(claims["iat"]) or not _is_int(claims["exp"]):
        raise Refusal("invalid_assertion")
    if not isinstance(claims["kid"], str) or not isinstance(claims["request_hash"], str):
        raise Refusal("invalid_assertion")
    if not HEX64.fullmatch(claims["request_hash"]):
        raise Refusal("invalid_assertion")
    if "vault_head" in claims and not (
        isinstance(claims["vault_head"], str) and HEX64.fullmatch(claims["vault_head"])
    ):
        raise Refusal("invalid_assertion")


def _verify_ed25519(public_key: bytes, signature: bytes, payload: bytes, code: str) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (InvalidSignature, ValueError):
        raise Refusal(code) from None


class ReferencePortal:
    """The portal's checks over the fixture's state. The M2 routes must decide the same way."""

    def __init__(self, state: dict[str, object]) -> None:
        self.state = copy.deepcopy(state)
        self.now: int = self.state["now"]
        self.seen_jtis: set[str] = set()
        # Receipts accepted, as (device_key_id, delivery_id, receipt), held for CARLOS. The portal
        # keeps each one (or its hash) until the copy's expiry, so a retry is answered as done.
        self.held_receipts: list[tuple[str, str, str]] = []

    def _account(self, name: str) -> dict[str, object]:
        return next(row for row in self.state["accounts"] if row["account"] == name)

    def _device_rows(self, device_key_id: object) -> list[dict[str, object]]:
        """Keys are per device, so one device linked to two accounts has a row for each."""
        return [row for row in self.state["devices"] if row["device_key_id"] == device_key_id]

    def _check_times(self, claims: dict[str, object]) -> None:
        issued_at, expires_at = claims["iat"], claims["exp"]
        skew = CONSTANTS["assertion_clock_skew_seconds"]
        if (
            expires_at <= issued_at
            or expires_at - issued_at > CONSTANTS["max_assertion_lifetime_seconds"]
            or issued_at > self.now + skew
        ):
            raise Refusal("invalid_assertion")
        if self.now >= expires_at + skew:
            raise Refusal("expired")

    def _check_request(self, claims: dict[str, object], vector: dict[str, object]) -> None:
        expected = staff_request_hash(
            vector["method"],
            vector["path"].encode(),
            vector["query"].encode(),
            vector["body"].encode(),
        )
        if not compare_digest(claims["request_hash"], expected):
            raise Refusal("request_mismatch")

    def _consume_jti(self, jti: str) -> None:
        if jti in self.seen_jtis:
            raise Refusal("replay")
        self.seen_jtis.add(jti)

    def _copies_for(self, device: dict[str, object]) -> list[dict[str, object]]:
        return [
            row
            for row in self.state["deliveries"]
            if row["device_key_id"] == device["device_key_id"] and row["expires_at"] > self.now
        ]

    def check_upload(self, outer: dict[str, object], blob: bytes, max_bytes: int) -> str:
        suite = {key: CONSTANTS["hpke"][key] for key in ("kem_id", "kdf_id", "aead_id")}
        valid = (
            set(outer) == OUTER_FIELDS
            and outer["v"] == CONTRACT["format_version"]
            and outer["suite"] == suite
            and _is_uuid(outer["delivery_id"])
            and isinstance(outer["recipient_id"], str)
            and OPAQUE_ID.fullmatch(outer["recipient_id"])
            and isinstance(outer["device_key_id"], str)
            and OPAQUE_ID.fullmatch(outer["device_key_id"])
            and _is_int(outer["size"])
            and outer["size"] == len(blob)
            and 32 + 16 < len(blob) <= max_bytes
            and isinstance(outer["ciphertext_sha256"], str)
            and compare_digest(outer["ciphertext_sha256"], sha256(blob).hexdigest())
            and _is_int(outer["created_at"])
            and _is_int(outer["expires_at"])
            and outer["created_at"]
            < outer["expires_at"]
            <= outer["created_at"] + CONSTANTS["max_delivery_lifetime_seconds"]
        )
        return "accept" if valid else "invalid_delivery"

    def device_request(self, vector: dict[str, object]) -> object:
        payload, claims, signature = _parse_compact(vector["assertion"], "invalid_assertion")
        _check_assertion_shape(
            claims, CONSTANTS["device_audience"], DEVICE_CLAIMS, DEVICE_OPTIONAL_CLAIMS
        )
        rows = self._device_rows(claims["kid"])
        if not rows:
            raise Refusal("unknown_device")
        _verify_ed25519(
            _strict_b64url(rows[0]["ed25519_public_key"], "invalid_assertion", 32),
            signature,
            payload,
            "invalid_assertion",
        )
        device = next(
            (
                row
                for row in rows
                if self._account(row["account"])["recipient_id"] == claims["recipient_id"]
            ),
            None,
        )
        if device is None:
            raise Refusal("recipient_mismatch")
        if device["status"] != "active":
            raise Refusal("device_removed")
        self._check_times(claims)
        self._check_request(claims, vector)
        self._consume_jti(claims["jti"])

        if vector["method"] == "GET" and vector["path"] == ref.DEVICE_DELIVERIES_PATH:
            return sorted(row["delivery_id"] for row in self._copies_for(device))
        route = DELIVERY_ROUTE.fullmatch(vector["path"])
        assert route is not None, vector["path"]
        delivery_id, is_receipt = route.group(1), route.group(2) is not None
        if vector["method"] == "GET" and not is_receipt:
            if not any(row["delivery_id"] == delivery_id for row in self._copies_for(device)):
                raise Refusal("delivery_not_found")
            return delivery_id
        assert vector["method"] == "POST" and is_receipt
        return self.receipt(device, delivery_id, json.loads(vector["body"])["receipt"])

    def receipt(self, device: dict[str, object], delivery_id: str, receipt: str) -> str:
        stored = next(
            (row for row in self._copies_for(device) if row["delivery_id"] == delivery_id), None
        )
        if stored is None:
            if (device["device_key_id"], delivery_id, receipt) in self.held_receipts:
                return delivery_id  # the same receipt again: already done
            raise Refusal("delivery_not_found")
        payload, claims, signature = _parse_compact(receipt, "invalid_receipt")
        if (
            set(claims) != RECEIPT_CLAIMS
            or claims["typ"] != CONSTANTS["receipt_typ"]
            or claims["aud"] != CONSTANTS["receipt_audience"]
            or not _is_uuid(claims["jti"])
            or not _is_uuid(claims["delivery_id"])
            or not _is_int(claims["picked_up_at"])
            or not all(
                isinstance(claims[name], str) and HEX64.fullmatch(claims[name])
                for name in ("ciphertext_sha256", "document_sha256", "vault_head")
            )
        ):
            raise Refusal("invalid_receipt")
        _verify_ed25519(
            _strict_b64url(device["ed25519_public_key"], "invalid_receipt", 32),
            signature,
            payload,
            "invalid_receipt",
        )
        if (
            claims["device_key_id"] != device["device_key_id"]
            or claims["recipient_id"] != self._account(device["account"])["recipient_id"]
        ):
            raise Refusal("invalid_receipt")
        if claims["delivery_id"] != delivery_id or not compare_digest(
            claims["ciphertext_sha256"], stored["ciphertext_sha256"]
        ):
            raise Refusal("receipt_mismatch")
        self.state["deliveries"].remove(stored)
        self.held_receipts.append((device["device_key_id"], delivery_id, receipt))
        return delivery_id

    def link_request(self, vector: dict[str, object]) -> dict[str, object]:
        try:
            body = json.loads(vector["body"], object_pairs_hook=_no_duplicates)
        except ValueError:
            raise Refusal("invalid_assertion") from None
        if not isinstance(body, dict) or set(body) != LINK_BODY_FIELDS:
            raise Refusal("invalid_assertion")
        x25519_public = _strict_b64url(body["x25519_public_key"], "invalid_assertion", 32)
        ed25519_public = _strict_b64url(body["ed25519_public_key"], "invalid_assertion", 32)
        name = body["device_name"]
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 64
            or not name.isprintable()
            or not _is_link_text(body["link_id"], CONSTANTS["link_id_length"])
            or not _is_link_text(body["code"], CONSTANTS["link_code_length"])
        ):
            raise Refusal("invalid_assertion")
        payload, claims, signature = _parse_compact(vector["assertion"], "invalid_assertion")
        _check_assertion_shape(claims, CONSTANTS["link_audience"], LINK_CLAIMS, set())
        fingerprint = _b64url(
            sha256(
                CONSTANTS["device_key_id_label"].encode()
                + len(x25519_public).to_bytes(8, "big")
                + x25519_public
                + len(ed25519_public).to_bytes(8, "big")
                + ed25519_public
            ).digest()
        )
        if claims["kid"] != fingerprint:
            raise Refusal("invalid_assertion")
        _verify_ed25519(ed25519_public, signature, payload, "invalid_assertion")
        self._check_times(claims)
        self._check_request(claims, vector)
        self._consume_jti(claims["jti"])

        row = next(
            (code for code in self.state["link_codes"] if code["link_id"] == body["link_id"]),
            None,
        )
        if row is None:
            raise Refusal("link_code_invalid")
        account = self._account(row["account"])
        code_matches = compare_digest(
            sha256(body["code"].encode()).digest(), sha256(row["code"].encode()).digest()
        )
        if not code_matches:
            row["wrong_attempts"] += 1
            account["recent_wrong_codes"] += 1
        if (
            not code_matches
            or row["status"] != "unused"
            or row["expires_at"] <= self.now
            or not row["session_signed_in"]
            or row["wrong_attempts"] >= CONSTANTS["max_link_code_attempts"]
            or account["recent_wrong_codes"] >= CONSTANTS["max_account_wrong_codes"]
        ):
            raise Refusal("link_code_invalid")
        if any(row_["account"] == row["account"] for row_ in self._device_rows(fingerprint)):
            raise Refusal("device_exists")
        row["status"] = "used"
        self.state["devices"].append(
            {
                "device_key_id": fingerprint,
                "x25519_public_key": body["x25519_public_key"],
                "ed25519_public_key": body["ed25519_public_key"],
                "account": row["account"],
                "status": "active",
            }
        )
        return {
            "account": account["account"],
            "recipient_id": account["recipient_id"],
            "device_key_id": fingerprint,
        }


def _outcome(call: object, *args: object) -> tuple[str, object]:
    try:
        return "accept", call(*args)
    except Refusal as refusal:
        return refusal.code, None


def _named(vectors: list[dict[str, object]]) -> list[object]:
    return [pytest.param(vector, id=vector["name"]) for vector in vectors]


def _by_name(vectors: list[dict[str, object]], name: str) -> dict[str, object]:
    return next(vector for vector in vectors if vector["name"] == name)


def test_fixture_is_exactly_what_the_reference_generates():
    assert ref.FIXTURE_PATH.read_text(encoding="utf-8") == ref.render(), (
        "regenerate with: python -m tests.delivery_contract_reference"
    )


def test_hpke_reproduces_rfc9180_appendix_a21():
    vector = CONTRACT["hpke_rfc9180_a2_1"]
    assert {key: vector[key] for key in ("mode", "kem_id", "kdf_id", "aead_id")} == CONSTANTS[
        "hpke"
    ]
    recipient_private, recipient_public = ref.hpke_derive_key_pair(bytes.fromhex(vector["ikmR"]))
    _, ephemeral_public = ref.hpke_derive_key_pair(bytes.fromhex(vector["ikmE"]))
    assert recipient_public.hex() == vector["pkRm"]
    assert ephemeral_public.hex() == vector["pkEm"]
    encryption = vector["encryptions"][0]
    info, aad, plaintext = (
        bytes.fromhex(vector["info"]),
        bytes.fromhex(encryption["aad"]),
        bytes.fromhex(encryption["pt"]),
    )
    blob = ref.hpke_seal(recipient_public, info, aad, plaintext, bytes.fromhex(vector["ikmE"]))
    assert blob[:32].hex() == vector["enc"]
    assert blob[32:].hex() == encryption["ct"]
    assert ref.hpke_open(recipient_private, info, aad, blob) == plaintext


@pytest.mark.parametrize(
    ("method", "path", "query", "body"),
    [
        ("GET", b"/api/mycarlos/deliveries", b"", b""),
        ("post", b"/api/mycarlos/link", b"a=1&b=2", b'{"x":1}'),
        ("POST", b"/api/mycarlos/deliveries/x/receipt", b"", "é".encode()),
    ],
)
def test_reference_request_hash_is_the_portals_framing(method, path, query, body):
    assert ref.request_hash(method, path, query, body) == staff_request_hash(
        method, path, query, body
    )


def test_every_key_follows_from_its_seed_text():
    keys = CONTRACT["keys"]
    for name in ("clinic_a", "clinic_a_revoked", "clinic_b", "unknown_clinic"):
        entry = keys[name]
        material = sha256(entry["seed_text"].encode()).digest()
        scalar = int.from_bytes(material, "big") % (ref.P256_ORDER - 1) + 1
        spki = (
            ec.derive_private_key(scalar, ec.SECP256R1())
            .public_key()
            .public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        assert entry["spki"] == _b64url(spki), name
        assert entry["kid"] == _b64url(sha256(spki).digest()), name
    for name in ("device", "other_device", "third_device", "new_device"):
        entry = keys[name]
        x25519 = X25519PrivateKey.from_private_bytes(
            sha256(entry["x25519_seed_text"].encode()).digest()
        ).public_key()
        ed25519 = Ed25519PrivateKey.from_private_bytes(
            sha256(entry["ed25519_seed_text"].encode()).digest()
        ).public_key()
        raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        assert entry["x25519_public_key"] == _b64url(x25519.public_bytes(*raw)), name
        assert entry["ed25519_public_key"] == _b64url(ed25519.public_bytes(*raw)), name
        assert entry["device_key_id"] == ref.device_key_id(
            x25519.public_bytes(*raw), ed25519.public_bytes(*raw)
        ), name


def test_sender_example_is_the_first_accepted_package():
    sender = CONTRACT["sender"]
    device = ref.DeviceKeys("device 1")
    document = ref.b64url_decode(sender["document_b64url"])
    plaintext = ref.hpke_open(
        device.x25519,
        CONSTANTS["hpke_info"].encode(),
        bytes.fromhex(sender["aad_hex"]),
        ref.b64url_decode(CONTRACT["packages"]["accept"][0]["blob"]),
    )
    assert sha256(plaintext).hexdigest() == sender["plaintext_sha256"]
    assert ref.unframe(plaintext) == [
        CONSTANTS["plaintext_magic"].encode(),
        sender["manifest"].encode(),
        document,
    ]
    payload = ref.b64url_decode(sender["manifest"].partition(".")[0])
    assert json.loads(payload) == sender["manifest_claims"]
    assert payload == ref.canonical_json(sender["manifest_claims"])
    # A fresh seal, as a real sender makes it, still opens to the same plaintext.
    resealed = ref.hpke_seal(
        device.x25519_public,
        CONSTANTS["hpke_info"].encode(),
        bytes.fromhex(sender["aad_hex"]),
        plaintext,
        b"another ephemeral key",
    )
    assert resealed != ref.b64url_decode(CONTRACT["packages"]["accept"][0]["blob"])
    assert (
        ref.hpke_open(
            device.x25519,
            CONSTANTS["hpke_info"].encode(),
            bytes.fromhex(sender["aad_hex"]),
            resealed,
        )
        == plaintext
    )


def _open(vector: dict[str, object]) -> tuple[str, dict[str, object]]:
    receiver = CONTRACT["receiver"]
    links = receiver["links"]
    return ref.open_package(
        vector,
        device=ref.DeviceKeys("device 1"),
        link=_by_name(links, receiver["package_link"]),
        all_links=links,
        filed={row["delivery_id"]: row["ciphertext_sha256"] for row in receiver["filed"]},
        now=vector["now"],
    )


@pytest.mark.parametrize("vector", _named(CONTRACT["packages"]["accept"]))
def test_reference_receiver_accepts(vector):
    outcome, claims = _open(vector)
    assert outcome == vector["expect"]
    assert claims["delivery_id"] == vector["outer"]["delivery_id"]


@pytest.mark.parametrize("vector", _named(CONTRACT["packages"]["refuse"]))
def test_reference_receiver_refuses(vector):
    with pytest.raises(ref.Refused) as refused:
        _open(vector)
    assert refused.value.code == vector["expect"]


@pytest.mark.parametrize(
    "vector", _named([*CONTRACT["packages"]["accept"], *CONTRACT["packages"]["refuse"]])
)
def test_portal_upload_checks_only_the_outer_record(vector):
    portal = ReferencePortal(PORTAL["state"])
    blob = ref.b64url_decode(vector["blob"])
    assert (
        portal.check_upload(vector["outer"], blob, CONSTANTS["max_ciphertext_bytes"])
        == vector["portal_upload"]
    )


def test_portal_upload_refuses_oversized_and_overlong_copies():
    portal = ReferencePortal(PORTAL["state"])
    package = CONTRACT["packages"]["accept"][0]
    outer, blob = package["outer"], ref.b64url_decode(package["blob"])
    assert portal.check_upload(outer, blob, len(blob)) == "accept"
    assert portal.check_upload(outer, blob, len(blob) - 1) == "invalid_delivery"
    week = CONSTANTS["max_delivery_lifetime_seconds"]
    too_long = {**outer, "expires_at": outer["created_at"] + week + 1}
    assert portal.check_upload(too_long, blob, len(blob)) == "invalid_delivery"
    backwards = {**outer, "expires_at": outer["created_at"]}
    assert portal.check_upload(backwards, blob, len(blob)) == "invalid_delivery"
    extra = {**outer, "title": "FAKE title the portal must never store"}
    assert portal.check_upload(extra, blob, len(blob)) == "invalid_delivery"


def _run(vectors: list[dict[str, object]], vector: dict[str, object], call: str) -> tuple:
    portal = ReferencePortal(PORTAL["state"])
    if "after" in vector:
        assert _outcome(getattr(portal, call), _by_name(vectors, vector["after"]))[0] == "accept"
    return portal, _outcome(getattr(portal, call), vector)


@pytest.mark.parametrize("vector", _named(PORTAL["device_requests"]))
def test_portal_device_requests(vector):
    _, (outcome, result) = _run(PORTAL["device_requests"], vector, "device_request")
    assert outcome == vector["expect"]
    if "returns" in vector:
        assert result == vector["returns"]


def test_a_receipt_deletes_the_copy_and_is_held_for_carlos():
    portal = ReferencePortal(PORTAL["state"])
    send = _by_name(PORTAL["device_requests"], "send the receipt")
    assert portal.device_request(send) == ref.DELIVERY_ID
    assert ref.DELIVERY_ID not in [row["delivery_id"] for row in portal.state["deliveries"]]
    assert [receipt for _, _, receipt in portal.held_receipts] == [
        json.loads(send["body"])["receipt"]
    ]
    download = _by_name(PORTAL["device_requests"], "download one copy")
    assert _outcome(portal.device_request, download)[0] == "delivery_not_found"


def _post_receipt(portal: ReferencePortal, vector: dict[str, object]) -> str:
    device = next(
        row
        for row in portal.state["devices"]
        if row["device_key_id"] == CONTRACT["keys"][vector["device"]]["device_key_id"]
    )
    return portal.receipt(device, vector["delivery_id"], vector["receipt"])


@pytest.mark.parametrize("vector", _named(PORTAL["receipts"]))
def test_portal_receipts(vector):
    portal = ReferencePortal(PORTAL["state"])
    if "after" in vector:
        earlier = _by_name(PORTAL["receipts"], vector["after"])
        assert _outcome(_post_receipt, portal, earlier)[0] == "accept"
    outcome, _ = _outcome(_post_receipt, portal, vector)
    assert outcome == vector["expect"]


@pytest.mark.parametrize("vector", _named(PORTAL["link_requests"]))
def test_portal_link_requests(vector):
    portal, (outcome, result) = _run(PORTAL["link_requests"], vector, "link_request")
    assert outcome == vector["expect"]
    if "returns" in vector:
        assert result == vector["returns"]
        added = portal.state["devices"][-1]
        assert added["account"] == vector["returns"]["account"]
        assert added["device_key_id"] == vector["returns"]["device_key_id"]


def test_a_wrong_code_counts_against_the_link_it_names():
    portal = ReferencePortal(PORTAL["state"])
    vector = _by_name(PORTAL["link_requests"], "a code from another account's link")
    assert _outcome(portal.link_request, vector)[0] == "link_code_invalid"
    row = next(code for code in portal.state["link_codes"] if code["link_id"] == "FAKE0002")
    assert row["wrong_attempts"] == 1
    assert row["status"] == "unused"
    account = next(row for row in portal.state["accounts"] if row["account"] == "account-2")
    assert account["recent_wrong_codes"] == 1


def test_a_link_code_works_once():
    portal = ReferencePortal(PORTAL["state"])
    vector = _by_name(PORTAL["link_requests"], "link a new device")
    assert _outcome(portal.link_request, vector)[0] == "accept"
    assert _outcome(portal.link_request, vector)[0] == "replay"
    # Even past the replay check (a portal restarted with an empty jti store), the code is spent.
    restarted = ReferencePortal(portal.state)
    assert _outcome(restarted.link_request, vector)[0] == "link_code_invalid"


@pytest.mark.parametrize(
    "example", [pytest.param(e, id=e["typed"]) for e in PORTAL["link_code_display_examples"]]
)
def test_typed_link_codes_split_as_listed(example):
    if example.get("expect") == "not_a_link_code":
        with pytest.raises(ValueError):
            ref.parse_typed_link_code(example["typed"])
    else:
        assert ref.parse_typed_link_code(example["typed"]) == (example["link_id"], example["code"])


def test_link_codes_meet_the_format():
    alphabet = CONSTANTS["link_code_alphabet"]
    assert len(alphabet) == 32 and len(set(alphabet)) == 32 and not set("ILOU") & set(alphabet)
    assert CONSTANTS["link_code_length"] * 5 >= 50  # at least 50 bits of secret
    for row in PORTAL["state"]["link_codes"]:
        assert _is_link_text(row["link_id"], CONSTANTS["link_id_length"])
        assert _is_link_text(row["code"], CONSTANTS["link_code_length"])
        assert ref.parse_typed_link_code(row["display"]) == (row["link_id"], row["code"])


def test_every_refusal_code_is_in_the_spec():
    spec = SPEC_PATH.read_text(encoding="utf-8")
    groups = (
        CONTRACT["packages"]["accept"],
        CONTRACT["packages"]["refuse"],
        PORTAL["device_requests"],
        PORTAL["receipts"],
        PORTAL["link_requests"],
    )
    codes = {vector["expect"] for group in groups for vector in group}
    codes |= {vector["portal_upload"] for vector in CONTRACT["packages"]["refuse"]}
    codes |= {e.get("expect", "accept") for e in PORTAL["link_code_display_examples"]}
    codes.discard("accept")
    missing = sorted(code for code in codes if f"`{code}`" not in spec)
    assert not missing, missing
