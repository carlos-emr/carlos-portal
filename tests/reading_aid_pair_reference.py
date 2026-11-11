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

"""Reference for the reading-aid pair contract: a clinician-approved AI summary delivered as a
second copy, bound to the original it reads. The rules are in
docs/architecture/mycarlos-delivery.md, section "Reading aids". This module builds the fixture
`tests/fixtures/reading-aid-pair-contract.json` (`python -m tests.reading_aid_pair_reference`) and
holds the reference receiver that every vector is checked against. Every key is FAKE and derived
from its seed text, as in delivery_contract_reference. No runtime code imports this module.
"""

import json
import re
from pathlib import Path

from tests import delivery_contract_reference as ref
from tests.delivery_contract_reference import (
    ClinicKey,
    DeviceKeys,
    Refused,
    aad_for,
    b64url,
    b64url_decode,
    canonical_json,
    compact_es256,
    frame,
    hpke_open,
    reject_duplicates,
    sha256_hex,
    unframe,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "reading-aid-pair-contract.json"

# --- Constants of the reading-aid copy (spec: "Reading aids") -----------------------------------
READING_AID_VERSION = 1
READING_AID_MAGIC = b"mycarlos-reading-aid/1"
READING_AID_MANIFEST_TYPE = "mycarlos-reading-aid-manifest"
READING_AID_TYPE = "mycarlos-reading-aid"
READING_AID_MEDIA_TYPE = "application/vnd.carlos.reading-aid+json"
READING_AID_KIND = "reading-aid/1"  # the outer record's `kind`, and what a device accepts
MAX_READING_AID_BYTES = 64 * 1024  # the canonical JSON inside the seal
MAX_READING_AID_CIPHERTEXT_BYTES = 1024 * 1024  # the sealed copy
MAX_POINTS = 50
MAX_EVIDENCE_PER_POINT = 5
NOTICE_VERSION_EN = "carlos-5537-en-1"
# <scheme>-<language>-<n>: the language is a lower-case primary subtag, with an upper-case
# two-letter region after it when the notice is for a region ("carlos-5537-pt-BR-1").
# Group 1 is the primary subtag.
NOTICE_VERSION_RE = re.compile(r"^[a-z0-9-]+-([a-z]{2,3})(?:-[A-Z]{2})?-[0-9]+$")
KIND_RE = re.compile(
    r"^[a-z0-9-]+/[0-9]+$"
)  # an outer record's `kind` and a pickup's `accept` value
MAX_KIND_LENGTH = 64
MAX_ACCEPT_VALUES = 8
REVIEWER_ROLES = frozenset({"clinician"})
NOTICE_HEADING_EN = "AI-generated reading aid — open the original document"
NOTICE_BODY_EN = (
    "FAKE notice body: this reading aid was produced by software and checked by a clinician. "
    "It is not your medical record. Open the original document for what your clinic recorded."
)
REVIEWER_ROLE = "clinician"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
LANGUAGE_RE = re.compile(r"^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$")

AID_DELIVERY_ID = "3e9d7b52-1c4a-4f08-9a6d-5b2e8c1f7d34"
OTHER_AID_DELIVERY_ID = "b48c2e71-6d5f-4a93-8e2b-1c7d9f3a6e05"
FILED_AID_DELIVERY_ID = "7c1e5a93-0b2d-4f47-9a86-4e3c8d2b1f70"
UNFILED_ORIGINAL_DELIVERY_ID = "e2a7d4c9-5f1b-4e38-8b06-9c3a2d7e4f61"
PAIR_ID = "9a1f4c6e-2b7d-4e35-8c09-6d4b2a7e1f58"
APPROVAL_ID = "apr-FAKE0001-9d2e"
SUMMARY_VERSION = sha256_hex(b"FAKE summary version fingerprint")
GENERATED_AT = ref.CREATED_AT - 600
REVIEWED_AT = ref.CREATED_AT - 120


# --- The reading aid itself: canonical JSON, the clinician-approved text ------------------------
def reading_aid(language: str = "en", **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "v": READING_AID_VERSION,
        "typ": READING_AID_TYPE,
        "language": language,
        "notice": {
            "version": NOTICE_VERSION_EN,
            "heading": NOTICE_HEADING_EN,
            "body": NOTICE_BODY_EN,
        },
        "overview": "FAKE chest X-ray report: the report describes the chest images and a plan.",
        "points": [
            {
                "text": "FAKE: no acute change is described compared with the earlier images.",
                "evidence": ["FAKE no acute change compared with the prior study."],
            },
            {
                "text": "FAKE: a repeat image is planned in three months.",
                "evidence": ["FAKE repeat imaging in 3 months."],
            },
        ],
    }
    value.update(changes)
    return value


def reading_aid_bytes(value: dict[str, object]) -> bytes:
    return canonical_json(value)


# --- The manifest of the reading-aid copy --------------------------------------------------------
def aid_manifest_claims(
    key: ClinicKey,
    *,
    delivery_id: str,
    recipient_id: str,
    device: DeviceKeys,
    original: dict[str, object],
    aid: bytes,
    language: str = "en",
) -> dict[str, object]:
    """`original` is the signed manifest's claims of the original this aid reads."""
    document = original["document"]
    assert isinstance(document, dict)
    return {
        "v": READING_AID_VERSION,
        "typ": READING_AID_MANIFEST_TYPE,
        "delivery_id": delivery_id,
        "recipient_id": recipient_id,
        "device_key_id": device.device_key_id,
        "clinic_id": key.clinic_id,
        "clinic_name": original["clinic_name"],
        "provider_name": original["provider_name"],
        "patient": dict(original["patient"]),  # type: ignore[arg-type]
        "pair": {
            "pair_id": PAIR_ID,
            "original_delivery_id": original["delivery_id"],
            "original_document_sha256": document["sha256"],
        },
        "reading_aid": {
            "media_type": READING_AID_MEDIA_TYPE,
            "size": len(aid),
            "sha256": sha256_hex(aid),
            "language": language,
            "summary_version": SUMMARY_VERSION,
            "generated_at": GENERATED_AT,
            "revised_at": None,
            "notice_version": NOTICE_VERSION_EN,
        },
        "approval": {"id": APPROVAL_ID, "reviewer_role": REVIEWER_ROLE, "reviewed_at": REVIEWED_AT},
        "created_at": original["created_at"],
        "expires_at": original["expires_at"],
        "kid": key.kid,
    }


def build_aid_package(
    *,
    manifest: str,
    aid: bytes,
    device: DeviceKeys,
    outer_delivery_id: str,
    outer_recipient_id: str,
    ikm_label: str,
    padding: bytes | None = None,
    magic: bytes = READING_AID_MAGIC,
    sections: list[bytes] | None = None,
    kind: str | None = READING_AID_KIND,
) -> dict[str, object]:
    package = ref.build_package(
        manifest=manifest,
        pdf=aid,
        device=device,
        outer_delivery_id=outer_delivery_id,
        outer_recipient_id=outer_recipient_id,
        ikm_label=ikm_label,
        padding=padding,
        magic=magic,
        sections=sections,
    )
    outer = dict(package["outer"])  # type: ignore[arg-type]
    if kind is not None:
        outer["kind"] = kind
    return {"outer": outer, "blob": package["blob"]}


# --- What the portal serves to whom (spec: "Who receives a reading aid") -------------------------
def portal_serves(outer: dict[str, object], accepts: list[str]) -> bool:
    """A copy with a `kind` is served only to a pickup that accepts that kind; a copy without one
    (an original) is served to every pickup."""
    kind = outer.get("kind")
    return kind is None or kind in accepts


def kind_ok(kind: object) -> bool:
    """An outer record's optional `kind`: printable ASCII, at most 64 characters, `name/version`."""
    return (
        isinstance(kind, str) and len(kind) <= MAX_KIND_LENGTH and KIND_RE.match(kind) is not None
    )


def accept_ok(accepts: object) -> bool:
    """A pickup's `accept` values, stored and echoed by the portal: at most 8, each a valid kind."""
    return (
        isinstance(accepts, list)
        and len(accepts) <= MAX_ACCEPT_VALUES
        and len(set(accepts)) == len(accepts)
        and all(kind_ok(value) for value in accepts)
    )


# --- The receiver's checks (spec: "Opening a reading aid") ---------------------------------------
EXPECTED_CLAIMS = {
    "v",
    "typ",
    "delivery_id",
    "recipient_id",
    "device_key_id",
    "clinic_id",
    "clinic_name",
    "provider_name",
    "patient",
    "pair",
    "reading_aid",
    "approval",
    "created_at",
    "expires_at",
    "kid",
}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _aid_manifest_shape_ok(claims: dict[str, object]) -> bool:
    patient, pair, aid, approval = (
        claims["patient"],
        claims["pair"],
        claims["reading_aid"],
        claims["approval"],
    )
    strings = (
        "delivery_id",
        "recipient_id",
        "device_key_id",
        "clinic_id",
        "clinic_name",
        "provider_name",
        "kid",
    )
    return (
        all(isinstance(claims[name], str) and claims[name] for name in strings)
        and _is_int(claims["created_at"])
        and _is_int(claims["expires_at"])
        and isinstance(patient, dict)
        and set(patient) == {"name", "birth_date"}
        and all(isinstance(value, str) for value in patient.values())
        and isinstance(pair, dict)
        and set(pair) == {"pair_id", "original_delivery_id", "original_document_sha256"}
        and isinstance(pair["pair_id"], str)
        and UUID_RE.match(pair["pair_id"]) is not None
        and isinstance(pair["original_delivery_id"], str)
        and UUID_RE.match(pair["original_delivery_id"]) is not None
        and pair["original_delivery_id"] != claims["delivery_id"]
        and isinstance(pair["original_document_sha256"], str)
        and HEX64_RE.match(pair["original_document_sha256"]) is not None
        and isinstance(aid, dict)
        and set(aid)
        == {
            "media_type",
            "size",
            "sha256",
            "language",
            "summary_version",
            "generated_at",
            "revised_at",
            "notice_version",
        }
        and aid["media_type"] == READING_AID_MEDIA_TYPE
        and _is_int(aid["size"])
        and 0 < aid["size"] <= MAX_READING_AID_BYTES
        and isinstance(aid["sha256"], str)
        and HEX64_RE.match(aid["sha256"]) is not None
        and isinstance(aid["language"], str)
        and LANGUAGE_RE.match(aid["language"]) is not None
        and isinstance(aid["summary_version"], str)
        and HEX64_RE.match(aid["summary_version"]) is not None
        and _is_int(aid["generated_at"])
        and (aid["revised_at"] is None or _is_int(aid["revised_at"]))
        and isinstance(aid["notice_version"], str)
        and NOTICE_VERSION_RE.match(aid["notice_version"]) is not None
        and NOTICE_VERSION_RE.match(aid["notice_version"]).group(1)
        == aid["language"].split("-", 1)[0]
        and isinstance(approval, dict)
        and set(approval) == {"id", "reviewer_role", "reviewed_at"}
        and isinstance(approval["id"], str)
        and bool(approval["id"])
        and approval["reviewer_role"] in REVIEWER_ROLES
        and _is_int(approval["reviewed_at"])
    )


def _reading_aid_ok(value: object, manifest_aid: dict[str, object]) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "v",
        "typ",
        "language",
        "notice",
        "overview",
        "points",
    }:
        return False
    notice, points = value["notice"], value["points"]
    if value["v"] != READING_AID_VERSION or value["typ"] != READING_AID_TYPE:
        return False
    if value["language"] != manifest_aid["language"]:
        return False
    if (
        not isinstance(notice, dict)
        or set(notice) != {"version", "heading", "body"}
        or not all(isinstance(part, str) and part.strip() for part in notice.values())
        or notice["version"] != manifest_aid["notice_version"]
    ):
        return False
    if not isinstance(value["overview"], str) or not value["overview"].strip():
        return False
    if not isinstance(points, list) or not 1 <= len(points) <= MAX_POINTS:
        return False
    for point in points:
        if not isinstance(point, dict) or set(point) != {"text", "evidence"}:
            return False
        if not isinstance(point["text"], str) or not point["text"].strip():
            return False
        evidence = point["evidence"]
        if not isinstance(evidence, list) or not 1 <= len(evidence) <= MAX_EVIDENCE_PER_POINT:
            return False
        if not all(isinstance(item, str) and item.strip() for item in evidence):
            return False
    return True


def open_reading_aid(
    package: dict[str, object],
    *,
    device: DeviceKeys,
    link: dict[str, object],
    all_links: list[dict[str, object]],
    filed_originals: dict[str, dict[str, object]],
    filed_aids: dict[str, str],
    now: int,
    waiting_aids: dict[str, str] | None = None,
) -> tuple[str, dict[str, object]]:
    """Returns ("file", claims), ("already_filed", claims) or ("waiting_for_original", claims).

    `filed_originals` maps each filed original's delivery ID to its `ciphertext_sha256`,
    `document_sha256`, `created_at` and `expires_at`; `filed_aids` maps each filed reading aid's
    delivery ID to its ciphertext hash; `waiting_aids` maps each aid kept while its original is not
    filed to the ciphertext hash it was kept with. A package whose plaintext is an original
    (`mycarlos-delivery/…`) goes to the v1 receiver.
    """
    waiting_aids = waiting_aids or {}
    outer, blob = package["outer"], b64url_decode(package["blob"])
    if outer["v"] != ref.FORMAT_VERSION or outer["suite"] != {
        "kem_id": ref.KEM_ID,
        "kdf_id": ref.KDF_ID,
        "aead_id": ref.AEAD_ID,
    }:
        raise Refused("unsupported_version")
    # From the listing alone, before any download: a reading aid larger than its limit.
    if outer.get("kind") == READING_AID_KIND and outer["size"] > MAX_READING_AID_CIPHERTEXT_BYTES:
        raise Refused("too_large")
    if outer["size"] != len(blob) or outer["ciphertext_sha256"] != sha256_hex(blob):
        raise Refused("hash_mismatch")
    if outer["recipient_id"] != link["recipient_id"]:
        raise Refused("wrong_recipient")
    if outer["device_key_id"] != device.device_key_id:
        raise Refused("wrong_device")
    aad = aad_for(outer["delivery_id"], outer["recipient_id"], outer["device_key_id"])
    try:
        plaintext = hpke_open(device.x25519, ref.HPKE_INFO, aad, blob)
    except Exception:
        raise Refused("decrypt_failed") from None
    try:
        sections = unframe(plaintext)
    except ValueError:
        raise Refused("bad_package") from None
    if sections and sections[0].startswith(b"mycarlos-delivery/"):
        filed = {key: value["ciphertext_sha256"] for key, value in filed_originals.items()}
        return ref.open_package(
            {"outer": {k: v for k, v in outer.items() if k != "kind"}, "blob": package["blob"]},
            device=device,
            link=link,
            all_links=all_links,
            filed=filed,
            now=now,
        )
    if not sections or not sections[0].startswith(b"mycarlos-reading-aid/"):
        raise Refused("bad_package")
    if sections[0] != READING_AID_MAGIC:
        raise Refused("unsupported_version")
    if len(sections) not in (3, 4):  # magic, manifest, reading aid, optional padding (ignored)
        raise Refused("bad_package")
    manifest_text, aid = sections[1].decode("ascii", "replace"), sections[2]
    encoded_payload, dot, encoded_signature = manifest_text.partition(".")
    try:
        payload = b64url_decode(encoded_payload)
        claims = json.loads(payload, object_pairs_hook=reject_duplicates)
        signature = b64url_decode(encoded_signature)
    except Exception:
        raise Refused("bad_manifest") from None
    if not dot or not isinstance(claims, dict) or set(claims) != EXPECTED_CLAIMS:
        raise Refused("bad_manifest")
    if claims["v"] != READING_AID_VERSION or claims["typ"] != READING_AID_MANIFEST_TYPE:
        raise Refused("bad_manifest")
    if not _aid_manifest_shape_ok(claims):
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
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

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
    manifest_aid = claims["reading_aid"]
    if manifest_aid["sha256"] != sha256_hex(aid) or manifest_aid["size"] != len(aid):
        raise Refused("reading_aid_hash_mismatch")
    try:
        parsed = json.loads(aid.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except Exception:
        raise Refused("bad_reading_aid") from None
    if not _reading_aid_ok(parsed, manifest_aid) or canonical_json(parsed) != aid:
        raise Refused("bad_reading_aid")
    if now > claims["expires_at"] + ref.DEVICE_EXPIRY_SKEW_SECONDS:
        raise Refused("expired")
    # One delivery-ID space: an aid under an original's ID, or a different copy under an ID
    # already filed or kept waiting, is a replay.
    if claims["delivery_id"] in filed_originals:
        raise Refused("replayed")
    if claims["delivery_id"] in filed_aids:
        if filed_aids[claims["delivery_id"]] != outer["ciphertext_sha256"]:
            raise Refused("replayed")
        return "already_filed", claims
    if (
        claims["delivery_id"] in waiting_aids
        and waiting_aids[claims["delivery_id"]] != outer["ciphertext_sha256"]
    ):
        raise Refused("replayed")
    pair = claims["pair"]
    original = filed_originals.get(pair["original_delivery_id"])
    if original is None:
        return "waiting_for_original", claims
    if original["document_sha256"] != pair["original_document_sha256"]:
        raise Refused("pair_mismatch")
    if (original["created_at"], original["expires_at"]) != (
        claims["created_at"],
        claims["expires_at"],
    ):
        raise Refused("pair_mismatch")
    return "file", claims


# --- The fixture ---------------------------------------------------------------------------------
def build_contract() -> dict[str, object]:
    clinic_a = ClinicKey("clinic-a signing key 1", ref.CLINIC_A)
    clinic_a_revoked = ClinicKey("clinic-a signing key 0 (revoked)", ref.CLINIC_A)
    unknown = ClinicKey("an unknown signing key", ref.CLINIC_A)
    device = DeviceKeys("device 1")
    other_device = DeviceKeys("device 2")

    def key_entry(key: ClinicKey, status: str) -> dict[str, str]:
        return {**key.public(), "status": status}

    link_a = {
        "name": "link to clinic-a",
        "device": "device",
        "clinic_id": ref.CLINIC_A,
        "recipient_id": ref.RECIPIENT_ID,
        "clinic_keys": [key_entry(clinic_a, "active"), key_entry(clinic_a_revoked, "revoked")],
        "accepts": [READING_AID_KIND],
    }

    # The original this aid reads: the same claims as the delivery contract's first package.
    original_claims = ref.manifest_claims(
        clinic_a,
        delivery_id=ref.DELIVERY_ID,
        recipient_id=ref.RECIPIENT_ID,
        device=device,
        pdf=ref.FAKE_PDF,
    )
    original_manifest = compact_es256(clinic_a, original_claims)
    original_package = {
        "name": "the original the aid reads",
        **ref.build_package(
            manifest=original_manifest,
            pdf=ref.FAKE_PDF,
            device=device,
            outer_delivery_id=ref.DELIVERY_ID,
            outer_recipient_id=ref.RECIPIENT_ID,
            ikm_label="the original the aid reads",
        ),
    }

    aid_value = reading_aid()
    aid = reading_aid_bytes(aid_value)

    def manifest(
        key: ClinicKey = clinic_a,
        *,
        aid_bytes: bytes = aid,
        language: str = "en",
        **changes: object,
    ) -> str:
        claims = aid_manifest_claims(
            key,
            delivery_id=AID_DELIVERY_ID,
            recipient_id=ref.RECIPIENT_ID,
            device=device,
            original=original_claims,
            aid=aid_bytes,
            language=language,
        )
        for name, value in changes.items():
            if value is None:
                claims.pop(name)
            elif isinstance(value, dict) and isinstance(claims.get(name), dict):
                claims[name] = {**claims[name], **value}  # type: ignore[dict-item]
            else:
                claims[name] = value
        return compact_es256(key, claims)

    good_claims = aid_manifest_claims(
        clinic_a,
        delivery_id=AID_DELIVERY_ID,
        recipient_id=ref.RECIPIENT_ID,
        device=device,
        original=original_claims,
        aid=aid,
    )
    good = compact_es256(clinic_a, good_claims)
    assert good == manifest()

    def package(name: str, **overrides: object) -> dict[str, object]:
        args: dict[str, object] = {
            "manifest": good,
            "aid": aid,
            "device": device,
            "outer_delivery_id": AID_DELIVERY_ID,
            "outer_recipient_id": ref.RECIPIENT_ID,
            "ikm_label": name,
        }
        args.update(overrides)
        return {"name": name, **build_aid_package(**args)}  # type: ignore[arg-type]

    filed_again = package(
        "an aid the device filed but never confirmed",
        manifest=manifest(delivery_id=FILED_AID_DELIVERY_ID),
        outer_delivery_id=FILED_AID_DELIVERY_ID,
    )
    filed_originals = {
        ref.DELIVERY_ID: {
            "ciphertext_sha256": original_package["outer"]["ciphertext_sha256"],
            "document_sha256": sha256_hex(ref.FAKE_PDF),
            "created_at": ref.CREATED_AT,
            "expires_at": ref.EXPIRES_AT,
        },
        ref.OTHER_DELIVERY_ID: {
            "ciphertext_sha256": sha256_hex(b"FAKE another original's sealed copy"),
            "document_sha256": sha256_hex(b"FAKE another original's PDF"),
            "created_at": ref.CREATED_AT,
            "expires_at": ref.EXPIRES_AT,
        },
    }
    waiting_copy = package(
        "an aid kept waiting, seen again in a later listing",
        manifest=manifest(
            delivery_id=OTHER_AID_DELIVERY_ID,
            pair={
                "original_delivery_id": UNFILED_ORIGINAL_DELIVERY_ID,
                "original_document_sha256": sha256_hex(b"FAKE a PDF still on its way"),
            },
        ),
        outer_delivery_id=OTHER_AID_DELIVERY_ID,
    )
    waiting_aids = {OTHER_AID_DELIVERY_ID: waiting_copy["outer"]["ciphertext_sha256"]}
    filed_aids = {
        ref.SEEN_DELIVERY_ID: sha256_hex(b"FAKE an earlier, different aid copy"),
        FILED_AID_DELIVERY_ID: filed_again["outer"]["ciphertext_sha256"],
    }

    def vector(pkg: dict[str, object], expect: str, now: int = ref.NOW, **extra: object) -> dict:
        return {**pkg, "now": now, "expect": expect, **extra}

    def notice_aid(language: str, version: str) -> tuple[bytes, str]:
        """An aid in `language` carrying notice `version`, and a manifest that names the same."""
        notice = {
            "version": version,
            "heading": f"FAKE heading ({language})",
            "body": f"FAKE body ({language})",
        }
        body = reading_aid_bytes(reading_aid(language, notice=notice))
        claimed = manifest(
            aid_bytes=body, language=language, reading_aid={"notice_version": version}
        )
        return body, claimed

    notice_languages = [
        ("fr", "carlos-5537-fr-1"),
        ("es", "carlos-5537-es-1"),
        ("pl", "carlos-5537-pl-1"),
        ("pt-BR", "carlos-5537-pt-BR-1"),
    ]
    accepted = [
        vector(package("a reading aid for a filed original"), "file"),
        vector(package("with a padding section", padding=b"\x00" * 64), "file"),
        vector(
            package("past expiry, within the 24 h device clock skew"),
            "file",
            now=ref.EXPIRES_AT + ref.DEVICE_EXPIRY_SKEW_SECONDS - 60,
        ),
        vector(
            filed_again,
            "already_filed",
            note="the receipt was lost after filing; send it again and file nothing",
        ),
        vector(
            waiting_copy,
            "waiting_for_original",
            note=(
                "the two copies travel on their own, so the aid may be listed first: kept by "
                "delivery ID and ciphertext hash, checked again after each original is filed "
                "until it expires; the same listing hash is not downloaded again"
            ),
        ),
        *[
            vector(
                package(
                    f"a {language} reading aid with its own notice version",
                    manifest=notice_aid(language, version)[1],
                    aid=notice_aid(language, version)[0],
                ),
                "file",
            )
            for language, version in notice_languages
        ],
    ]

    tampered = package("tampered ciphertext")
    blob = bytearray(b64url_decode(tampered["blob"]))
    blob[-1] ^= 0x01
    tampered["blob"] = b64url(bytes(blob))
    tampered["outer"] = {
        **tampered["outer"],
        "size": len(blob),
        "ciphertext_sha256": sha256_hex(bytes(blob)),
    }
    wrong_aid_bytes = reading_aid_bytes(reading_aid(overview="FAKE a different overview."))
    not_canonical = json.dumps(aid_value, indent=1).encode("utf-8")
    refused = [
        vector(
            package(
                "the aid as a v1 original receiver sees it (older myCarlos)",
                magic=READING_AID_MAGIC,
            ),
            "bad_package",
            receiver="v1_original_receiver",
            note="an older build that only knows mycarlos-delivery/1 refuses it and files nothing",
        ),
        vector(tampered, "decrypt_failed"),
        vector(
            package(
                "plaintext labelled as a future reading-aid version",
                sections=[b"mycarlos-reading-aid/2", good.encode("ascii"), aid],
            ),
            "unsupported_version",
        ),
        vector(
            package("two plaintext parts", sections=[READING_AID_MAGIC, good.encode("ascii")]),
            "bad_package",
        ),
        vector(
            package("a manifest of the original's type", manifest=original_manifest, aid=aid),
            "bad_manifest",
        ),
        vector(package("a claim missing", manifest=manifest(approval=None)), "bad_manifest"),
        vector(
            package("an extra claim", manifest=manifest(original_document_id="FAKE-doc-1")),
            "bad_manifest",
        ),
        vector(
            package(
                "the aid names itself as its own original",
                manifest=manifest(pair={"original_delivery_id": AID_DELIVERY_ID}),
            ),
            "bad_manifest",
        ),
        vector(
            package(
                "a reading aid that is not JSON media",
                manifest=manifest(reading_aid={"media_type": "application/pdf"}),
            ),
            "bad_manifest",
        ),
        vector(
            package(
                "a reading aid larger than the limit",
                manifest=manifest(reading_aid={"size": MAX_READING_AID_BYTES + 1}),
            ),
            "bad_manifest",
        ),
        vector(
            package("signed by an unknown clinic key", manifest=manifest(unknown)),
            "unknown_clinic_key",
        ),
        vector(
            package("signed by a revoked clinic key", manifest=manifest(clinic_a_revoked)),
            "revoked_clinic_key",
        ),
        vector(
            package("sealed for another device", device=other_device),
            "wrong_device",
            note="the outer record names device 2; the device checks before decrypting",
        ),
        vector(
            package(
                "signed IDs differ from the outer record",
                manifest=manifest(delivery_id=OTHER_AID_DELIVERY_ID),
            ),
            "id_mismatch",
        ),
        vector(
            package("the sealed aid is not the one the manifest signs", aid=wrong_aid_bytes),
            "reading_aid_hash_mismatch",
        ),
        vector(
            package(
                "the aid JSON is not canonical",
                manifest=manifest(aid_bytes=not_canonical),
                aid=not_canonical,
            ),
            "bad_reading_aid",
        ),
        vector(
            package(
                "the aid's language is not the manifest's",
                manifest=manifest(
                    language="fr", reading_aid={"notice_version": "carlos-5537-fr-1"}
                ),
            ),
            "bad_reading_aid",
        ),
        vector(
            package(
                "an empty evidence list",
                manifest=manifest(
                    aid_bytes=reading_aid_bytes(
                        reading_aid(points=[{"text": "FAKE", "evidence": []}])
                    )
                ),
                aid=reading_aid_bytes(reading_aid(points=[{"text": "FAKE", "evidence": []}])),
            ),
            "bad_reading_aid",
        ),
        vector(
            package("expired, beyond the clock skew"),
            "expired",
            now=ref.EXPIRES_AT + ref.DEVICE_EXPIRY_SKEW_SECONDS + 1,
        ),
        vector(
            package(
                "a different copy under a filed aid's delivery ID",
                manifest=manifest(delivery_id=ref.SEEN_DELIVERY_ID),
                outer_delivery_id=ref.SEEN_DELIVERY_ID,
            ),
            "replayed",
        ),
        vector(
            package(
                "a different copy under a waiting aid's delivery ID",
                manifest=manifest(
                    delivery_id=OTHER_AID_DELIVERY_ID,
                    aid_bytes=wrong_aid_bytes,
                    pair={
                        "original_delivery_id": UNFILED_ORIGINAL_DELIVERY_ID,
                        "original_document_sha256": sha256_hex(b"FAKE a PDF still on its way"),
                    },
                ),
                aid=wrong_aid_bytes,
                outer_delivery_id=OTHER_AID_DELIVERY_ID,
            ),
            "replayed",
        ),
        vector(
            package(
                "an aid under a filed original's delivery ID",
                manifest=manifest(
                    delivery_id=ref.DELIVERY_ID,
                    pair={
                        "original_delivery_id": ref.OTHER_DELIVERY_ID,
                        "original_document_sha256": sha256_hex(b"FAKE another original's PDF"),
                    },
                ),
                outer_delivery_id=ref.DELIVERY_ID,
            ),
            "replayed",
            note="one delivery-ID space across originals and aids",
        ),
        vector(
            package(
                "a reviewer role outside the closed set",
                manifest=manifest(approval={"reviewer_role": "nurse"}),
            ),
            "bad_manifest",
        ),
        vector(
            package(
                "a notice version whose language tag is not the aid's language",
                manifest=manifest(reading_aid={"notice_version": "carlos-5537-fr-1"}),
            ),
            "bad_manifest",
        ),
        vector(
            package(
                "an aid whose lifetime is not its original's",
                manifest=manifest(created_at=ref.CREATED_AT + 1),
            ),
            "pair_mismatch",
            note="created_at and expires_at must equal the filed original's; no receipt is sent",
        ),
        vector(
            package(
                "an aid bound to another PDF than the filed original",
                manifest=manifest(
                    pair={"original_document_sha256": sha256_hex(b"FAKE an edited PDF")}
                ),
            ),
            "pair_mismatch",
            note="the original changed after approval; CARLOS fences both copies, never re-signs",
        ),
        vector(
            package(
                "a pt-BR aid with the Spanish notice version",
                manifest=notice_aid("pt-BR", "carlos-5537-es-1")[1],
                aid=notice_aid("pt-BR", "carlos-5537-es-1")[0],
            ),
            "bad_manifest",
        ),
        vector(
            package(
                "a notice version whose region is not upper case",
                manifest=notice_aid("pt-BR", "carlos-5537-pt-br-1")[1],
                aid=notice_aid("pt-BR", "carlos-5537-pt-br-1")[0],
            ),
            "bad_manifest",
        ),
        vector(
            package(
                "a notice version with a three-letter region",
                manifest=notice_aid("pt-BR", "carlos-5537-pt-BRA-1")[1],
                aid=notice_aid("pt-BR", "carlos-5537-pt-BRA-1")[0],
            ),
            "bad_manifest",
        ),
    ]

    oversize = package("a reading aid listed larger than its limit")
    oversize["outer"] = {**oversize["outer"], "size": MAX_READING_AID_CIPHERTEXT_BYTES + 1}
    refused.insert(
        2,
        vector(
            oversize,
            "too_large",
            note="refused from the listing's outer record, before any download",
        ),
    )
    kind_examples = [
        {"kind": READING_AID_KIND, "ok": True},
        {"kind": "reading-aid/2", "ok": True},
        {"kind": "Reading-Aid/1", "ok": False},
        {"kind": "reading-aid", "ok": False},
        {"kind": "reading-aid/1 ", "ok": False},
        {"kind": "a" * 62 + "/1", "ok": True},
        {"kind": "a" * 63 + "/1", "ok": False},
        {"kind": "", "ok": False},
        {"kind": 1, "ok": False},
    ]
    accept_examples = [
        {"accepts": [READING_AID_KIND], "ok": True},
        {"accepts": [], "ok": True},
        {"accepts": [READING_AID_KIND, "reading-aid/2"], "ok": True},
        {"accepts": [READING_AID_KIND, READING_AID_KIND], "ok": False},
        {"accepts": [f"reading-aid/{n}" for n in range(9)], "ok": False},
        {"accepts": ["Reading-Aid/1"], "ok": False},
    ]
    serve_examples = [
        {"outer_kind": READING_AID_KIND, "accepts": [READING_AID_KIND], "served": True},
        {"outer_kind": READING_AID_KIND, "accepts": [], "served": False},
        {"outer_kind": None, "accepts": [], "served": True},
        {"outer_kind": None, "accepts": [READING_AID_KIND], "served": True},
        {"outer_kind": "reading-aid/2", "accepts": [READING_AID_KIND], "served": False},
    ]

    return {
        "description": (
            "FAKE vectors for the reading-aid pair contract "
            "(docs/architecture/mycarlos-delivery.md, Reading aids). "
            "Regenerate with: python -m tests.reading_aid_pair_reference"
        ),
        "format_version": READING_AID_VERSION,
        "constants": {
            "plaintext_magic": READING_AID_MAGIC.decode(),
            "manifest_typ": READING_AID_MANIFEST_TYPE,
            "reading_aid_typ": READING_AID_TYPE,
            "media_type": READING_AID_MEDIA_TYPE,
            "kind": READING_AID_KIND,
            "hpke_info": ref.HPKE_INFO.decode(),
            "max_reading_aid_bytes": MAX_READING_AID_BYTES,
            "max_ciphertext_bytes": MAX_READING_AID_CIPHERTEXT_BYTES,
            "max_points": MAX_POINTS,
            "max_evidence_per_point": MAX_EVIDENCE_PER_POINT,
            "max_kind_length": MAX_KIND_LENGTH,
            "max_accept_values": MAX_ACCEPT_VALUES,
            "reviewer_roles": sorted(REVIEWER_ROLES),
            "notice_version_en": NOTICE_VERSION_EN,
            "device_expiry_skew_seconds": ref.DEVICE_EXPIRY_SKEW_SECONDS,
        },
        "keys": {
            "derivation": (
                "as tests/fixtures/delivery-contract.json: every key is FAKE, from its seed text"
            ),
            "clinic_a": clinic_a.described(),
            "clinic_a_revoked": clinic_a_revoked.described(),
            "unknown_clinic": unknown.described(),
            "device": device.described(),
            "other_device": other_device.described(),
        },
        "sender": {
            "note": (
                "CARLOS builds the aid JSON (JCS canonical), signs the manifest (JCS plus "
                "RFC 6979), seals with a fresh ephemeral key, and stages the original and the aid "
                "together"
            ),
            "signing_key": "clinic_a",
            "recipient": ref.RECIPIENT_ID,
            "original_manifest_claims": original_claims,
            "original_manifest": original_manifest,
            "reading_aid": aid_value,
            "reading_aid_b64url": b64url(aid),
            "reading_aid_sha256": sha256_hex(aid),
            "manifest_claims": good_claims,
            "manifest": good,
            "aad_hex": aad_for(AID_DELIVERY_ID, ref.RECIPIENT_ID, device.device_key_id).hex(),
            "plaintext_sha256": sha256_hex(frame(READING_AID_MAGIC, good.encode("ascii"), aid)),
        },
        "receiver": {
            "device": "device",
            "links": [link_a],
            "package_link": link_a["name"],
            "filed_originals": filed_originals,
            "filed_aids": filed_aids,
            "waiting_aids": waiting_aids,
        },
        "original_package": original_package,
        "packages": {"accept": accepted, "refuse": refused},
        "portal": {
            "serve": serve_examples,
            "kind": kind_examples,
            "accept": accept_examples,
        },
    }


def render() -> str:
    return json.dumps(build_contract(), indent=2, sort_keys=False, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE_PATH.write_text(render(), encoding="utf-8")
    print(f"wrote {FIXTURE_PATH}")
