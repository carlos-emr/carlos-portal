"""Consume the one shared fixture using the portal's production proof/authentication code."""

import base64
import json
from pathlib import Path

import pytest

from carlos_patient_portal.clinic_key_proofs import (
    ClinicKeyInventoryError,
    ClinicKeyMaterial,
    validate_clinic_key_inventory,
    verify_replacement_proof,
)
from carlos_patient_portal.device_identity import (
    DeviceRecord,
    DeviceRefusal,
    verify_link_recovery_assertion,
)
from carlos_patient_portal.staff_identity import staff_request_hash

FIXTURE = json.loads((Path(__file__).parent / "fixtures/link-lifecycle-v1.json").read_text())


def decode(value):
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("noncanonical base64url")
    return raw


def material(value):
    return ClinicKeyMaterial(
        value["kid"], decode(value["spki"]), value["status"], value.get("replaces_kid"),
        decode(value["replacement_signature"]) if "replacement_signature" in value else None,
    )


@pytest.mark.parametrize("vector", FIXTURE["proof_vectors"], ids=lambda value: value["name"])
def test_actual_proof_verifier_consumes_shared_bytes(vector):
    valid = False
    try:
        predecessor = ClinicKeyMaterial(vector["replaces_kid"], decode(vector["predecessor_spki"]), "active")
        successor = ClinicKeyMaterial(
            vector["kid"], decode(vector["spki"]), "active", vector["replaces_kid"],
            decode(vector["signature"]),
        )
        verify_replacement_proof(vector["clinic_id"], predecessor, successor)
        valid = True
    except ValueError:
        pass
    assert valid is vector["expect_valid"]


@pytest.mark.parametrize("vector", FIXTURE["inventory_vectors"], ids=lambda value: value["name"])
def test_actual_inventory_validator_consumes_shared_cases(vector):
    incoming = [material(value) for value in vector["incoming"]]
    previous = [material(value) for value in vector["previous"]]
    accepted = False
    try:
        roots = validate_clinic_key_inventory("clinic-a", incoming, previous)
        # The publisher retains all-revoked history. Initial/pending-link bootstrap has the
        # additional active-key requirement enforced by the actual HTTP routes.
        if vector["mode"] == "bootstrap" and not any(key.status == "active" for key in incoming):
            raise ClinicKeyInventoryError()
        if vector["required_notice"] == "unsigned":
            assert roots
        accepted = True
    except ClinicKeyInventoryError:
        pass
    assert accepted is vector["expect_accept"]


@pytest.mark.parametrize("vector", FIXTURE["recovery_vectors"], ids=lambda value: value["name"])
def test_actual_recovery_authentication_primitive(vector):
    device = FIXTURE["device"]
    record = DeviceRecord(
        device_id=1, account_id=1, device_key_id=device["device_key_id"],
        ed25519_public_key=decode(device["ed25519_public_key"]),
        status=vector["device_status"],
        recipient_id="FAKE recipient" if vector["recipient_exists"] else None,
    )
    expected_hash = staff_request_hash(
        vector["method"], bytes.fromhex(vector["raw_path_hex"]),
        bytes.fromhex(vector["raw_query_hex"]), bytes.fromhex(vector["body_hex"]),
    )
    valid_primitive_names = {
        "valid-prefixed-recovery", "valid-original-noncanonical-signed-json", "nonce-replay",
        "fresh-valid-removed", "replayed-removed-is-generic", "missing-account", "missing-recipient",
    }
    try:
        principal = verify_link_recovery_assertion(
            vector["assertion"],
            find_device=lambda kid: record if vector["known_device"] and kid == record.device_key_id else None,
            expected_request_hash=expected_hash, now=vector["now"],
        )
    except DeviceRefusal as refusal:
        assert vector["name"] not in valid_primitive_names
        if vector["name"] in {"wrong-prefix", "wrong-method", "wrong-query", "nonempty-body"}:
            assert refusal.code == "request_mismatch"
    else:
        assert vector["name"] in valid_primitive_names
        assert principal.device_key_id == record.device_key_id
    # Replay, removed status and missing account are deliberately HTTP/transaction checks;
    # this primitive test does not claim those policies passed from a generic404 alone.
