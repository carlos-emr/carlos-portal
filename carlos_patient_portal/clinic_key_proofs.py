# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Standard P-256 replacement proofs and complete, immutable clinic-key inventories."""

from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from carlos_patient_portal.device_identity import b64url

REPLACEMENT_DOMAIN = b"mycarlos-clinic-key-replacement-v1\x00"
MAX_CLINIC_KEY_INVENTORY = 16


@dataclass(frozen=True)
class ClinicKeyMaterial:
    kid: str
    spki: bytes
    status: str
    replaces_kid: str | None = None
    replacement_signature: bytes | None = None


class ClinicKeyInventoryError(ValueError):
    def __init__(self, code: str = "invalid_key") -> None:
        super().__init__(code)
        self.code = code


def replacement_statement(clinic_id: str, predecessor_kid: str, successor: ClinicKeyMaterial) -> bytes:
    parts = (
        clinic_id.encode("utf-8"), predecessor_kid.encode("utf-8"),
        successor.kid.encode("utf-8"), successor.spki,
    )
    return REPLACEMENT_DOMAIN + b"".join(len(part).to_bytes(8, "big") + part for part in parts)


def checked_public_key(material: ClinicKeyMaterial) -> ec.EllipticCurvePublicKey:
    try:
        public = serialization.load_der_public_key(material.spki)
    except (TypeError, ValueError) as exc:
        raise ClinicKeyInventoryError() from exc
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
        raise ClinicKeyInventoryError()
    canonical = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if canonical != material.spki or b64url(sha256(canonical).digest()) != material.kid:
        raise ClinicKeyInventoryError()
    return public


def verify_replacement_proof(
    clinic_id: str, predecessor: ClinicKeyMaterial, successor: ClinicKeyMaterial
) -> None:
    old_public = checked_public_key(predecessor)
    checked_public_key(successor)
    signature = successor.replacement_signature
    if successor.replaces_kid != predecessor.kid or signature is None or len(signature) != 64:
        raise ClinicKeyInventoryError()
    # Standard ECDSA verification accepts both valid S representations. The original P1363
    # bytes remain immutable storage values; verification never rewrites a supplied signature.
    der = encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )
    try:
        old_public.verify(
            der, replacement_statement(clinic_id, predecessor.kid, successor), ec.ECDSA(hashes.SHA256())
        )
    except (InvalidSignature, ValueError) as exc:
        raise ClinicKeyInventoryError() from exc


def validate_clinic_key_inventory(
    clinic_id: str,
    incoming: Sequence[ClinicKeyMaterial],
    previous: Sequence[ClinicKeyMaterial] = (),
) -> tuple[str, ...]:
    """Check every binding/proof/edge before the caller stores any update.

    Empty previous state is explicit administrative bootstrap: valid historical chains need
    no prior anchor. An existing inventory additionally requires immutable history and valid
    continuity for new edges. New unsigned roots are allowed by the frozen plain-notice policy;
    return their IDs so a consuming trust store can persist notices with its state transaction.
    The portal publisher retains all-revoked inventories; actual link bootstrap separately
    requires an active key.
    """
    if not 1 <= len(incoming) <= MAX_CLINIC_KEY_INVENTORY:
        raise ClinicKeyInventoryError("invalid_key_list")
    listed = {key.kid: key for key in incoming}
    old = {key.kid: key for key in previous}
    if len(listed) != len(incoming):
        raise ClinicKeyInventoryError("invalid_key_list")
    # Preserve the publisher's established immutable-history refusal codes. No signature can
    # excuse a changed historical binding, and every otherwise admissible proof is verified
    # before any caller may persist the inventory.
    if set(old) - set(listed):
        raise ClinicKeyInventoryError("key_missing")
    for kid, before in old.items():
        after = listed[kid]
        if (before.spki, before.replaces_kid, before.replacement_signature) != (
            after.spki, after.replaces_kid, after.replacement_signature,
        ):
            raise ClinicKeyInventoryError("key_changed")
        if before.status == "revoked" and after.status != "revoked":
            raise ClinicKeyInventoryError("key_revoked")
    successors: dict[str, str] = {}
    for key in incoming:
        checked_public_key(key)
        if key.status not in {"active", "revoked"}:
            raise ClinicKeyInventoryError()
        if (key.replaces_kid is None) != (key.replacement_signature is None):
            raise ClinicKeyInventoryError()
        if key.replaces_kid is not None:
            predecessor = listed.get(key.replaces_kid)
            if predecessor is None or predecessor.kid == key.kid:
                raise ClinicKeyInventoryError()
            verify_replacement_proof(clinic_id, predecessor, key)
            if predecessor.kid in successors:
                raise ClinicKeyInventoryError()
            successors[predecessor.kid] = key.kid
    # Each key has at most one predecessor and successor. Following predecessors from every
    # key detects cycles within the fixed16-key bound without recursion or partial acceptance.
    for key in incoming:
        seen: set[str] = set()
        current: ClinicKeyMaterial | None = key
        while current is not None:
            if current.kid in seen:
                raise ClinicKeyInventoryError()
            seen.add(current.kid)
            current = listed.get(current.replaces_kid) if current.replaces_kid else None
    if not old:
        return ()
    unsigned_roots = tuple(key.kid for key in incoming if key.kid not in old and key.replaces_kid is None)
    for key in incoming:
        if key.kid in old or key.replaces_kid is None:
            continue
        predecessor = listed[key.replaces_kid]
        if predecessor.kid in old and old[predecessor.kid].status == "revoked":
            raise ClinicKeyInventoryError()
        # Find the nearest previously active ancestor, or a new unsigned root. Old historical
        # edges remain valid even when their predecessor was revoked in an earlier snapshot.
        current = predecessor
        while True:
            if current.kid in old and old[current.kid].status == "active":
                break
            if current.kid in unsigned_roots:
                break
            if current.replaces_kid is None:
                raise ClinicKeyInventoryError()
            current = listed[current.replaces_kid]
    return unsigned_roots
