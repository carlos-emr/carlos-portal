# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Consumes the unchanged shared M3 bytes; no private reference implementation imports."""

import json
from base64 import urlsafe_b64encode
from pathlib import Path

import pytest

from carlos_patient_portal.approval_codec import (
    object_claims,
    verify_approval,
    verify_clinic,
    verify_intent,
)
from carlos_patient_portal.mailbox_codec import MailboxRefusal
from carlos_patient_portal.mycarlos_devices import strict_b64url_decode

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures/device-approval-contract-v1.json").read_bytes()
)
SCOPE = {
    "clinic": FIXTURE["clinic_id"],
    "recipient": FIXTURE["recipient_id"],
    "public_base": FIXTURE["public_portal_base_url"],
}


@pytest.mark.parametrize("flow", ["first", "later"])
def test_shared_signed_objects_verify(flow):
    for kind, value in FIXTURE["flows"][flow].items():
        if kind == "intent":
            verified = verify_intent(value["compact"], **SCOPE)
        elif kind == "approval":
            key = FIXTURE["keys"]["predecessor"]
            verified = verify_approval(
                value["compact"],
                predecessor_kid=key["device_key_id"],
                predecessor_ed=strict_b64url_decode(key["ed25519_public_key"]),
                **SCOPE,
            )
        else:
            verified = verify_clinic(
                kind,
                value["compact"],
                spki=strict_b64url_decode(FIXTURE["keys"]["clinic"]["spki"]),
                **SCOPE,
            )
        assert verified == value["claims"]


@pytest.mark.parametrize("bad", [[], {}, True, 1, None])
def test_wrong_kind_type_is_controlled_refusal(bad):
    source = FIXTURE["flows"]["first"]["challenge"]
    claims = dict(source["claims"], approval_kind=bad)
    payload = urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    compact = payload + "." + source["compact"].split(".")[1]
    with pytest.raises(MailboxRefusal) as failure:
        object_claims("challenge", compact, **SCOPE)
    assert failure.value.code == "invalid_approval"


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b"{} {}", b'{"a":NaN}'])
def test_strict_json_refuses_ambiguous_body(raw):
    from carlos_patient_portal.routes.mycarlos_approval import body_object

    with pytest.raises(MailboxRefusal):
        body_object(raw, {"a"})


@pytest.mark.parametrize(
    "vector", FIXTURE["signed_object_vectors"], ids=lambda vector: vector["id"]
)
def test_every_shared_signed_object_vector(vector):
    def verify():
        kind = vector["kind"]
        if kind == "intent":
            value = verify_intent(vector["compact"], **SCOPE)
            if value["iat"] > vector["now"] + 30 or value["exp"] <= vector["now"]:
                raise MailboxRefusal("approval_expired")
        elif kind == "approval":
            key = FIXTURE["keys"]["predecessor"]
            value = verify_approval(
                vector["compact"],
                predecessor_kid=key["device_key_id"],
                predecessor_ed=strict_b64url_decode(key["ed25519_public_key"]),
                **SCOPE,
            )
        else:
            if vector["clinic_key_status"] != "active":
                raise MailboxRefusal("invalid_approval")
            value = verify_clinic(
                kind,
                vector["compact"],
                spki=strict_b64url_decode(FIXTURE["keys"]["clinic"]["spki"]),
                **SCOPE,
            )
            if kind == "challenge" and value["expires_at"] <= vector["now"]:
                raise MailboxRefusal("approval_expired")
        return value

    if vector["valid"]:
        assert verify()
    else:
        with pytest.raises(MailboxRefusal):
            verify()


def test_fixture_holds_no_private_key_and_seed_texts_rebuild_every_key_and_signature():
    # The fixture names each FAKE key by seed text only; the private half is derived at run time.
    import hashlib

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    from tests import delivery_contract_reference as ref

    raw = (Path(__file__).parent / "fixtures/device-approval-contract-v1.json").read_text()
    assert "private" not in raw.lower()
    assert "MC4CAQAw" not in raw and "MIGHAgEA" not in raw  # PKCS#8 headers
    keys, publics = FIXTURE["keys"], {}
    for name, key in keys.items():
        if name == "clinic":
            private = ref.private_key_from_seed_text(key["seed_text"], "p256")
            spki = private.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            assert ref.b64url(spki) == key["spki"]
            assert ref.b64url(hashlib.sha256(spki).digest()) == key["kid"]
            publics[name] = private
            continue
        ed = ref.private_key_from_seed_text(key["ed25519_seed_text"], "ed25519")
        x = ref.private_key_from_seed_text(key["x25519_seed_text"], "x25519")
        ed_public = ed.public_key().public_bytes_raw()
        x_public = x.public_key().public_bytes_raw()
        assert ref.b64url(ed_public) == key["ed25519_public_key"]
        assert ref.b64url(x_public) == key["x25519_public_key"]
        assert ref.device_key_id(x_public, ed_public) == key["device_key_id"]
        publics[name] = ed
    signers = {
        ("first", "intent"): publics["first"],
        ("later", "intent"): publics["candidate"],
        ("later", "approval"): publics["predecessor"],
    }
    resigned = 0
    for flow, objects in FIXTURE["flows"].items():
        for kind, value in objects.items():
            payload_text, signature = value["compact"].split(".")
            payload = ref.b64url_decode(payload_text)
            if kind in {"challenge", "acceptance"}:
                der = publics["clinic"].sign(
                    payload, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
                )
                r, s = decode_dss_signature(der)
                again = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            else:
                again = signers[(flow, kind)].sign(payload)
            assert ref.b64url(again) == signature, (flow, kind)
            resigned += 1
    assert resigned == 7
