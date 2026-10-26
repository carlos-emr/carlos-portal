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
