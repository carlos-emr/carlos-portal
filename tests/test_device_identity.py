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

"""The device-request and link-request checks (M2-b) against every shared vector.

The vectors (`tests/fixtures/delivery-contract.json`) say how the portal decides each request.
These checks are the authentication layer only, so a vector whose answer comes from a later step
(the link code, `device_exists`, a missing copy) must pass here, and every other must be refused
with exactly the vector's code.
"""

import json
from base64 import urlsafe_b64decode
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

import pytest
from alembic import command
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal.device_identity import (
    DEVICE_REFUSAL_CODES,
    DeviceRefusal,
    consume_device_assertion,
    device_key_id,
    find_device_record,
    verify_device_assertion,
    verify_link_request,
)
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosRecipient,
    PatientPortalStaffAssertionUse,
    utc_now,
)
from carlos_patient_portal.staff_identity import staff_request_hash
from tests import delivery_contract_reference as ref
from tests.support import alembic_config_for_tests

CONTRACT = json.loads(
    (Path(__file__).parent / "fixtures" / "delivery-contract.json").read_text(encoding="utf-8")
)
PORTAL = CONTRACT["portal"]
STATE = PORTAL["state"]
NOW = STATE["now"]
# Codes decided after these checks: by the link code, the device key, or the route itself.
LATER_STEP_CODES = {"accept", "link_code_invalid", "device_exists", "delivery_not_found"}


def decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


@pytest.fixture
def portal(tmp_path: Path) -> Iterator[sessionmaker[Session]]:
    """A migrated database holding the vectors' accounts, recipient IDs and devices."""
    database_url = f"sqlite+pysqlite:///{tmp_path / 'device-identity.db'}"
    config = alembic_config_for_tests()
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_engine(database_url)
    session_factory = sessionmaker(engine, expire_on_commit=False)
    with session_factory() as session, session.begin():
        accounts = {}
        for number, row in enumerate(STATE["accounts"], start=1):
            account = PatientPortalAccount(
                clinic_id=row["clinic_id"],
                demographic_no=9000 + number,
                username=f"fake.{row['account']}",
                email=f"{row['account']}@example.test",
                password_hash="FAKE-not-a-real-hash",
                status="active",
            )
            session.add(account)
            session.flush()
            session.add(
                PatientPortalMyCarlosRecipient(
                    account_id=account.id,
                    recipient_id=row["recipient_id"],
                )
            )
            accounts[row["account"]] = account.id
        for row in STATE["devices"]:
            removed = row["status"] == "removed"
            session.add(
                PatientPortalMyCarlosDevice(
                    account_id=accounts[row["account"]],
                    device_key_id=row["device_key_id"],
                    x25519_public_key=decode(row["x25519_public_key"]),
                    ed25519_public_key=decode(row["ed25519_public_key"]),
                    device_name="myCarlos on Linux",
                    status=row["status"],
                    linked_at=utc_now(),
                    removed_at=utc_now() if removed else None,
                    removed_by="patient" if removed else None,
                )
            )
    try:
        yield session_factory
    finally:
        engine.dispose()


def expected_hash(vector: dict[str, object]) -> str:
    return staff_request_hash(
        str(vector["method"]),
        str(vector["path"]).encode(),
        str(vector["query"]).encode(),
        str(vector["body"]).encode(),
    )


def device_outcome(portal: sessionmaker[Session], vector: dict[str, object], now: int = NOW):
    try:
        with portal() as session:
            principal = verify_device_assertion(
                vector["assertion"],
                find_device=lambda kid: find_device_record(session, kid),
                expected_request_hash=expected_hash(vector),
                now=now,
            )
        consume_device_assertion(portal, principal, now=now)
    except DeviceRefusal as refusal:
        return refusal.code, None
    return "accept", principal


def link_outcome(portal: sessionmaker[Session], vector: dict[str, object], now: int = NOW):
    try:
        request = verify_link_request(
            str(vector["body"]).encode(),
            vector["assertion"],
            expected_request_hash=expected_hash(vector),
            now=now,
        )
        consume_device_assertion(portal, request, now=now)
    except DeviceRefusal as refusal:
        return refusal.code, None
    return "accept", request


def by_name(vectors: list[dict[str, object]], name: str) -> dict[str, object]:
    return next(vector for vector in vectors if vector["name"] == name)


def named(vectors: list[dict[str, object]]) -> list[object]:
    return [pytest.param(vector, id=vector["name"]) for vector in vectors]


@pytest.mark.parametrize("vector", named(PORTAL["device_requests"]))
def test_device_requests_are_decided_as_the_vectors_say(portal, vector) -> None:
    if "after" in vector:
        earlier = by_name(PORTAL["device_requests"], vector["after"])
        assert device_outcome(portal, earlier)[0] == "accept"
    outcome, principal = device_outcome(portal, vector)
    expected = vector["expect"] if vector["expect"] not in LATER_STEP_CODES else "accept"
    assert outcome == expected
    if principal is not None:
        assert principal.device_key_id == CONTRACT["keys"]["device"]["device_key_id"]


def test_a_vault_head_anchor_is_handed_to_the_route(portal) -> None:
    vector = by_name(PORTAL["device_requests"], "check in with the vault head anchor")
    outcome, principal = device_outcome(portal, vector)
    assert outcome == "accept"
    claims = json.loads(decode(vector["assertion"].split(".")[0]))
    assert principal.vault_head_link == claims["vault_head_link"]


@pytest.mark.parametrize("vector", named(PORTAL["link_requests"]))
def test_link_requests_pass_or_fail_these_checks_as_the_vectors_say(portal, vector) -> None:
    outcome, request = link_outcome(portal, vector)
    expected = vector["expect"] if vector["expect"] not in LATER_STEP_CODES else "accept"
    assert outcome == expected
    if "returns" in vector:
        assert request.device_key_id == vector["returns"]["device_key_id"]


def test_a_link_request_is_used_once(portal) -> None:
    vector = by_name(PORTAL["link_requests"], "link a new device")
    assert link_outcome(portal, vector)[0] == "accept"
    assert link_outcome(portal, vector)[0] == "replay"


def test_the_link_request_carries_the_new_keys_name_and_code(portal) -> None:
    vector = by_name(PORTAL["link_requests"], "link a new device")
    outcome, request = link_outcome(portal, vector)
    body = json.loads(vector["body"])
    assert outcome == "accept"
    assert (request.link_id, request.code, request.device_name) == (
        body["link_id"],
        body["code"],
        body["device_name"],
    )
    assert request.x25519_public_key == decode(body["x25519_public_key"])
    assert request.ed25519_public_key == decode(body["ed25519_public_key"])


def test_every_fixture_device_key_id_is_computed_the_same_way() -> None:
    for name, key in CONTRACT["keys"].items():
        if "device_key_id" not in key:
            continue
        computed = device_key_id(
            decode(key["x25519_public_key"]), decode(key["ed25519_public_key"])
        )
        assert computed == key["device_key_id"], name


def fake_jti(label: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"FAKE device request {label}"))


def signed_request(**changes: object) -> dict[str, object]:
    """A FAKE device request signed with the fixture's own device 1 (derived from its seed)."""
    device = ref.DeviceKeys("device 1")
    claims: dict[str, object] = {
        "aud": "carlos-patient-portal-device-api",
        "iss": "mycarlos",
        "kid": device.device_key_id,
        "recipient_id": ref.RECIPIENT_ID,
        "jti": fake_jti("first"),
        "iat": NOW,
        "exp": NOW + 60,
        "request_hash": staff_request_hash("GET", ref.DEVICE_DELIVERIES_PATH.encode(), b"", b""),
    }
    claims.update(changes)
    return {
        "method": "GET",
        "path": ref.DEVICE_DELIVERIES_PATH,
        "query": "",
        "body": "",
        "assertion": ref.compact_ed25519(device.ed25519, claims),
    }


def test_an_assertion_passes_through_the_30_second_grace_and_not_after(portal) -> None:
    expires_at = NOW + 60
    assert device_outcome(portal, signed_request(), now=expires_at + 29)[0] == "accept"
    late = signed_request(jti=fake_jti("late"))
    assert device_outcome(portal, late, now=expires_at + 30)[0] == "expired"


def test_the_nonce_is_kept_until_the_grace_ends(portal) -> None:
    outcome, principal = device_outcome(portal, signed_request())
    assert outcome == "accept"
    with portal() as session:
        stored = session.scalar(
            select(PatientPortalStaffAssertionUse).where(
                PatientPortalStaffAssertionUse.assertion_id == principal.assertion_id
            )
        )
    kept_until = stored.expires_at.replace(tzinfo=stored.expires_at.tzinfo or UTC)
    assert kept_until == datetime.fromtimestamp(NOW + 60 + 30, tz=UTC)


def test_a_nonce_used_by_a_device_is_refused_to_another_device_request(portal) -> None:
    first = signed_request()
    assert device_outcome(portal, first)[0] == "accept"
    same_jti_other_path = signed_request(
        request_hash=staff_request_hash("GET", b"/api/mycarlos/deliveries/x", b"", b"")
    )
    same_jti_other_path["path"] = "/api/mycarlos/deliveries/x"
    assert device_outcome(portal, same_jti_other_path)[0] == "replay"


@pytest.mark.parametrize(
    "assertion",
    [None, "", "no-dot", "a.b.c", "x" * 5000, signed_request()["assertion"] + "="],
)
def test_a_malformed_assertion_is_invalid(portal, assertion) -> None:
    vector = {**signed_request(), "assertion": assertion}
    assert device_outcome(portal, vector)[0] == "invalid_assertion"


def test_a_non_integer_time_is_invalid(portal) -> None:
    assert device_outcome(portal, signed_request(iat=True))[0] == "invalid_assertion"
    assert device_outcome(portal, signed_request(exp=float(NOW + 60)))[0] == "invalid_assertion"


def test_a_refusal_code_must_be_one_of_the_specs() -> None:
    with pytest.raises(ValueError, match="unknown device refusal code"):
        DeviceRefusal("made_up")
    vector_codes = {
        vector["expect"] for vector in PORTAL["device_requests"] + PORTAL["link_requests"]
    }
    assert DEVICE_REFUSAL_CODES <= vector_codes
