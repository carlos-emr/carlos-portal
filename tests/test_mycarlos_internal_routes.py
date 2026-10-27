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

"""CARLOS's internal myCarlos routes (carlos-portal#41, M2-d): clinic keys and patient devices."""

import json
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal import internal_routes
from carlos_patient_portal.models import (
    AUDIT_EVENT_JOB_AUTH_REFUSED,
    AUDIT_EVENT_MYCARLOS_CLINIC_KEYS_PUBLISH,
    AUDIT_EVENT_MYCARLOS_DEVICE_LIST,
    AUDIT_EVENT_MYCARLOS_DEVICE_REMOVE,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalClinicKey,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosRecipient,
    utc_now,
)
from carlos_patient_portal.mycarlos_devices import (
    ClinicKeyPublishError,
    ClinicKeySpec,
    b64url,
    clinic_key_id,
    insert_clinic_key,
    publish_clinic_keys,
)
from carlos_patient_portal.system_jobs import JOB_ONLY_PERMISSIONS, SYSTEM_JOBS
from tests import delivery_contract_reference as ref
from tests.support import (
    TEST_JOB_ASSERTION_KEY_IDS,
    TEST_JOB_ASSERTION_PUBLIC_KEYS,
    carlos_job_headers,
    carlos_staff_headers,
)
from tests.test_internal_api import INTERNAL_API_TOKEN, internal_app

CLINIC = "clinic-a"
KEYS_PATH = "/internal/carlos/mycarlos/clinic-keys"
PUBLISH = "portal.mycarlos.clinic_keys.publish"
MANAGE = "portal.mycarlos.device.manage"
# Derived like the other test job keys (support.py), never a literal.
KEY_PUBLISH_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(161, 193)))
KEY_PUBLISH_KID = "key-publish-test-2026"


def raw_public(private_key: Ed25519PrivateKey) -> str:
    return b64url(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )


JOB_KEYRING = json.dumps(
    {
        **{
            job: {TEST_JOB_ASSERTION_KEY_IDS[job]: public_key}
            for job, public_key in TEST_JOB_ASSERTION_PUBLIC_KEYS.items()
        },
        "key-publish": {KEY_PUBLISH_KID: raw_public(KEY_PUBLISH_PRIVATE_KEY)},
    },
    separators=(",", ":"),
    sort_keys=True,
)


def clinic_spki(label: str) -> bytes:
    """A FAKE P-256 clinic key, derived from its label as the delivery fixtures derive theirs."""
    # Any scalar from 1 to 2**255 is below the P-256 group order, so it is a valid private key.
    scalar = int.from_bytes(sha256(f"FAKE clinic key: {label}".encode()).digest()) % 2**255 + 1
    return (
        ec.derive_private_key(scalar, ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def key_entry(label: str, status: str = "active", **changes: object) -> dict[str, object]:
    spki = clinic_spki(label)
    entry: dict[str, object] = {"kid": clinic_key_id(spki), "spki": b64url(spki), "status": status}
    entry.update(changes)
    return entry


def mycarlos_app(**overrides: object):
    return internal_app(
        mycarlos_delivery_enabled=True,
        internal_job_assertion_public_keyring=JOB_KEYRING,
        **overrides,
    )


def publish(client: TestClient, keys: list[dict[str, object]], **header_options: object):
    body = json.dumps({"keys": keys}, separators=(",", ":")).encode()
    options: dict[str, object] = {"key_id": KEY_PUBLISH_KID, "signing_key": KEY_PUBLISH_PRIVATE_KEY}
    options.update(header_options)
    headers = carlos_job_headers(
        "key-publish",
        PUBLISH,
        method="PUT",
        path=KEYS_PATH,
        body=body,
        clinic_id=CLINIC,
        **options,
    )
    return client.put(
        KEYS_PATH,
        content=body,
        headers={**headers, "Content-Type": "application/json"},
    )


def staff(*permissions: str) -> dict[str, str]:
    return carlos_staff_headers(*permissions, clinic_id=CLINIC)


def audit_rows(app, event_type: str) -> list[PatientPortalAuditEvent]:
    with app.state.session_factory() as session:
        return list(
            session.scalars(
                select(PatientPortalAuditEvent)
                .where(PatientPortalAuditEvent.event_type == event_type)
                .order_by(PatientPortalAuditEvent.id)
            )
        )


def seed_patient(app, demographic_no: int, devices: list[tuple[str, str]]) -> int:
    """An account with FAKE devices given as (label, status). Returns the account id."""
    with app.state.session_factory() as session:
        with session.begin():
            account = PatientPortalAccount(
                clinic_id=CLINIC,
                demographic_no=demographic_no,
                username=f"fake.patient{demographic_no}",
                email=f"fake{demographic_no}@example.test",
                password_hash="FAKE-not-a-real-hash",
                status="active",
            )
            session.add(account)
            session.flush()
            session.add(
                PatientPortalMyCarlosRecipient(
                    account_id=account.id,
                    recipient_id=f"rcp-FAKE{demographic_no}",
                )
            )
            for label, status in devices:
                removed = status == "removed"
                session.add(
                    PatientPortalMyCarlosDevice(
                        account_id=account.id,
                        device_key_id=device_key_id(label),
                        x25519_public_key=sha256(f"{label} x25519".encode()).digest(),
                        ed25519_public_key=sha256(f"{label} ed25519".encode()).digest(),
                        device_name="myCarlos on Linux",
                        status=status,
                        linked_at=utc_now(),
                        removed_at=utc_now() if removed else None,
                        removed_by="patient" if removed else None,
                    )
                )
            return account.id


def device_key_id(label: str) -> str:
    return b64url(sha256(f"FAKE device {label}".encode()).digest())


# --------------------------------------------------------------------------------------
# The switch and who may call
# --------------------------------------------------------------------------------------


def test_every_route_is_absent_while_the_switch_is_off() -> None:
    client = TestClient(internal_app(internal_job_assertion_public_keyring=JOB_KEYRING))
    assert publish(client, [key_entry("one")]).status_code == 404
    assert (
        client.get(
            "/internal/carlos/patients/1234/mycarlos/devices", headers=staff(MANAGE)
        ).status_code
        == 404
    )
    paths = {getattr(route, "path", "") for route in client.app.routes}
    assert not any("mycarlos" in path for path in paths)


def test_each_route_names_its_one_caller() -> None:
    app = mycarlos_app()
    policies = {}
    for route in app.routes:
        if (
            isinstance(route, APIRoute)
            and route.path.startswith("/internal/carlos/")
            and ("/mycarlos" in route.path)
        ):
            dependency = next(
                dependency.call
                for dependency in route.dependant.dependencies
                if hasattr(dependency.call, internal_routes.CALLER_POLICY_ATTRIBUTE)
            )
            policy = getattr(dependency, internal_routes.CALLER_POLICY_ATTRIBUTE)
            for method in route.methods:
                policies[(method, route.path)] = (policy.caller, policy.job, policy.permission)
    assert policies == {
        ("PUT", KEYS_PATH): ("job", "key-publish", PUBLISH),
        ("GET", "/internal/carlos/patients/{demographic_no}/mycarlos/devices"): (
            "staff",
            None,
            MANAGE,
        ),
        (
            "POST",
            "/internal/carlos/patients/{demographic_no}/mycarlos/devices/{device_key_id}/remove",
        ): ("staff", None, MANAGE),
    }


def test_the_key_publish_job_holds_only_its_own_right_and_staff_never_holds_it() -> None:
    assert SYSTEM_JOBS["key-publish"].permissions == {PUBLISH}
    assert SYSTEM_JOBS["key-publish"].actor_id == "job:key-publish"
    assert PUBLISH in JOB_ONLY_PERMISSIONS


def test_staff_cannot_publish_clinic_keys_whatever_they_hold() -> None:
    client = TestClient(mycarlos_app())
    body = json.dumps({"keys": [key_entry("one")]}).encode()
    response = client.put(
        KEYS_PATH,
        content=body,
        headers={**staff(PUBLISH, MANAGE), "Content-Type": "application/json"},
    )
    assert response.status_code == 403


def test_another_job_is_refused_on_the_key_route_and_recorded() -> None:
    app = mycarlos_app()
    client = TestClient(app)
    body = json.dumps({"keys": [key_entry("one")]}, separators=(",", ":")).encode()
    headers = carlos_job_headers(
        "booking-sync",
        "portal.booking_prompt.sync",
        method="PUT",
        path=KEYS_PATH,
        body=body,
        clinic_id=CLINIC,
    )
    response = client.put(
        KEYS_PATH, content=body, headers={**headers, "Content-Type": "application/json"}
    )
    assert response.status_code == 404
    (refusal,) = audit_rows(app, AUDIT_EVENT_JOB_AUTH_REFUSED)
    assert (refusal.actor_id, refusal.reason, refusal.resource_id) == (
        "job:booking-sync",
        "route_not_open",
        KEYS_PATH,
    )
    with app.state.session_factory() as session:
        assert session.scalars(select(PatientPortalClinicKey)).first() is None


def test_the_key_publish_job_is_refused_on_a_device_route() -> None:
    app = mycarlos_app()
    path = "/internal/carlos/patients/1234/mycarlos/devices"
    headers = carlos_job_headers(
        "key-publish",
        PUBLISH,
        method="GET",
        path=path,
        clinic_id=CLINIC,
        key_id=KEY_PUBLISH_KID,
        signing_key=KEY_PUBLISH_PRIVATE_KEY,
    )
    assert TestClient(app).get(path, headers=headers).status_code == 404


def test_device_routes_need_the_device_permission() -> None:
    app = mycarlos_app()
    seed_patient(app, 1234, [("phone", "active")])
    client = TestClient(app)
    path = "/internal/carlos/patients/1234/mycarlos/devices"
    assert client.get(path, headers=staff("portal.account.manage")).status_code == 403
    remove = f"{path}/{device_key_id('phone')}/remove"
    assert client.post(remove, headers=staff("portal.account.manage")).status_code == 403


# --------------------------------------------------------------------------------------
# Clinic keys
# --------------------------------------------------------------------------------------


def test_publishing_stores_the_keys_once_and_audits_each_call() -> None:
    app = mycarlos_app()
    client = TestClient(app)
    keys = [key_entry("one")]

    first = publish(client, keys)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["clinic_id"] == CLINIC
    assert body["changed"] is True
    assert [(key["kid"], key["status"]) for key in body["keys"]] == [(keys[0]["kid"], "active")]

    again = publish(client, keys)
    assert again.status_code == 200
    assert again.json()["changed"] is False

    rows = audit_rows(app, AUDIT_EVENT_MYCARLOS_CLINIC_KEYS_PUBLISH)
    assert [row.reason for row in rows] == ["changed", "unchanged"]
    assert {(row.actor_type, row.actor_id, row.assertion_key_id) for row in rows} == {
        ("system", "job:key-publish", KEY_PUBLISH_KID)
    }


def test_a_new_key_with_its_replacement_signature_and_a_revocation() -> None:
    app = mycarlos_app()
    client = TestClient(app)
    fixture = json.loads((Path(__file__).parent / "fixtures/link-lifecycle-v1.json").read_text())
    scenario = next(v for v in fixture["inventory_vectors"] if v["name"] == "signed-replacement")
    old = scenario["previous"][0]
    assert publish(client, [old]).status_code == 200
    new = scenario["incoming"][1]
    signature = new["replacement_signature"]

    rotated = publish(client, [{**old, "status": "revoked"}, new])
    assert rotated.status_code == 200, rotated.text
    by_kid = {key["kid"]: key for key in rotated.json()["keys"]}
    assert by_kid[old["kid"]]["status"] == "revoked"
    assert by_kid[old["kid"]]["revoked_at"] is not None
    assert by_kid[new["kid"]]["replaces_kid"] == old["kid"]
    with app.state.session_factory() as session:
        stored = session.get(PatientPortalClinicKey, new["kid"])
        assert stored.replacement_signature == ref.b64url_decode(signature)


@pytest.mark.parametrize(
    ("second_list", "status_code", "detail"),
    [
        # A published key can't vanish: CARLOS lists it as revoked instead.
        (lambda one, two: [two], 409, "key_missing"),
        (lambda one, two: [{**one, "status": "active"}, two], 409, "key_revoked"),
        (
            lambda one, two: [
                {**one, "status": "revoked"},
                {
                    **two,
                    "replaces_kid": one["kid"],
                    "replacement_signature": b64url(b"\x01" * 64),
                },
            ],
            409,
            "key_changed",
        ),
    ],
)
def test_a_list_that_would_undo_what_is_published_is_refused(
    second_list, status_code: int, detail: str
) -> None:
    app = mycarlos_app()
    client = TestClient(app)
    one = key_entry("one")
    two = key_entry("two")
    assert publish(client, [{**one, "status": "revoked"}, two]).status_code == 200

    response = publish(client, second_list(one, two))
    assert (response.status_code, response.json()["detail"]) == (status_code, detail)
    with app.state.session_factory() as session:
        stored = {key.kid: key.status for key in session.scalars(select(PatientPortalClinicKey))}
    assert stored == {one["kid"]: "revoked", two["kid"]: "active"}


def ed25519_spki() -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def p384_spki() -> bytes:
    return (
        ec.derive_private_key(12345, ec.SECP384R1())
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


@pytest.mark.parametrize(
    "bad_entry",
    [
        # The kid must be the hash of the key it names.
        lambda: {**key_entry("one"), "kid": key_entry("two")["kid"]},
        # Only P-256 keys, in their one DER form.
        lambda: {
            "kid": clinic_key_id(ed25519_spki()),
            "spki": b64url(ed25519_spki()),
            "status": "active",
        },
        lambda: {
            "kid": clinic_key_id(p384_spki()),
            "spki": b64url(p384_spki()),
            "status": "active",
        },
        lambda: {**key_entry("one"), "spki": key_entry("one")["spki"] + "="},
        lambda: {**key_entry("one"), "status": "retired"},
        # A replacement names the key it replaces together with that key's signature.
        lambda: {**key_entry("one"), "replaces_kid": key_entry("two")["kid"]},
        lambda: {**key_entry("one"), "replacement_signature": b64url(b"\x01" * 64)},
        lambda: {**key_entry("one"), "unexpected": True},
    ],
)
def test_a_malformed_key_is_refused_and_nothing_is_stored(bad_entry) -> None:
    app = mycarlos_app()
    response = publish(TestClient(app), [bad_entry()])
    assert response.status_code == 422, response.text
    with app.state.session_factory() as session:
        assert session.scalars(select(PatientPortalClinicKey)).first() is None


def test_a_list_with_a_repeated_key_or_too_many_keys_is_refused() -> None:
    client = TestClient(mycarlos_app())
    one = key_entry("one")
    assert publish(client, [one, one]).status_code == 422
    assert publish(client, [key_entry(f"key {index}") for index in range(17)]).status_code == 422
    assert publish(client, []).status_code == 422


# --------------------------------------------------------------------------------------
# A patient's devices
# --------------------------------------------------------------------------------------


def test_staff_read_the_recipient_id_and_every_device_with_its_public_keys() -> None:
    app = mycarlos_app()
    account_id = seed_patient(app, 1234, [("phone", "active"), ("laptop", "removed")])
    response = TestClient(app).get(
        "/internal/carlos/patients/1234/mycarlos/devices", headers=staff(MANAGE)
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["recipient_id"] == "rcp-FAKE1234"
    assert [(device["device_key_id"], device["status"]) for device in body["devices"]] == [
        (device_key_id("phone"), "active"),
        (device_key_id("laptop"), "removed"),
    ]
    phone = body["devices"][0]
    assert phone["x25519_public_key"] == b64url(sha256(b"phone x25519").digest())
    assert phone["ed25519_public_key"] == b64url(sha256(b"phone ed25519").digest())
    (row,) = audit_rows(app, AUDIT_EVENT_MYCARLOS_DEVICE_LIST)
    assert (row.actor_type, row.demographic_no, row.account_id) == ("staff", 1234, account_id)


def test_an_account_with_no_device_yet_has_no_recipient_id() -> None:
    app = mycarlos_app()
    seed_patient(app, 1234, [])
    with app.state.session_factory() as session:
        with session.begin():
            session.query(PatientPortalMyCarlosRecipient).delete()
    response = TestClient(app).get(
        "/internal/carlos/patients/1234/mycarlos/devices", headers=staff(MANAGE)
    )
    assert response.json() == {"recipient_id": None, "devices": []}


def test_a_patient_without_a_portal_account_is_not_found() -> None:
    response = TestClient(mycarlos_app()).get(
        "/internal/carlos/patients/1234/mycarlos/devices", headers=staff(MANAGE)
    )
    assert response.status_code == 404


def test_staff_remove_a_device_once_and_again_changes_nothing() -> None:
    app = mycarlos_app()
    seed_patient(app, 1234, [("phone", "active"), ("tablet", "active")])
    client = TestClient(app)
    path = f"/internal/carlos/patients/1234/mycarlos/devices/{device_key_id('phone')}/remove"

    first = client.post(path, headers=staff(MANAGE))
    assert first.status_code == 200, first.text
    assert (first.json()["status"], first.json()["removed_by"]) == ("removed", "staff")
    removed_at = first.json()["removed_at"]

    again = client.post(path, headers=staff(MANAGE))
    assert again.status_code == 200
    assert again.json()["removed_at"] == removed_at
    assert [row.reason for row in audit_rows(app, AUDIT_EVENT_MYCARLOS_DEVICE_REMOVE)] == [
        "removed",
        "already_removed",
    ]
    with app.state.session_factory() as session:
        tablet = session.scalar(
            select(PatientPortalMyCarlosDevice).where(
                PatientPortalMyCarlosDevice.device_key_id == device_key_id("tablet")
            )
        )
        assert tablet.status == "active"


def test_another_patients_device_is_not_found_and_stays_linked() -> None:
    app = mycarlos_app()
    seed_patient(app, 1234, [])
    seed_patient(app, 5678, [("theirs", "active")])
    path = f"/internal/carlos/patients/1234/mycarlos/devices/{device_key_id('theirs')}/remove"
    response = TestClient(app).post(path, headers=staff(MANAGE))
    assert (response.status_code, response.json()["detail"]) == (404, "device not found")
    with app.state.session_factory() as session:
        theirs = session.scalar(select(PatientPortalMyCarlosDevice))
        assert theirs.status == "active"


def test_a_malformed_device_key_id_is_refused_before_any_lookup() -> None:
    app = mycarlos_app()
    seed_patient(app, 1234, [])
    path = "/internal/carlos/patients/1234/mycarlos/devices/not-a-key-id/remove"
    assert TestClient(app).post(path, headers=staff(MANAGE)).status_code == 422


def test_the_internal_api_token_is_still_required() -> None:
    app = mycarlos_app()
    headers = staff(MANAGE)
    headers["Authorization"] = "Bearer " + "w" * len(INTERNAL_API_TOKEN)
    response = TestClient(app).get(
        "/internal/carlos/patients/1234/mycarlos/devices", headers=headers
    )
    assert response.status_code == 404


# --------------------------------------------------------------------------------------
# Two first publishes racing on the same kid
# --------------------------------------------------------------------------------------


def test_a_key_a_concurrent_publish_just_stored_is_checked_like_a_published_key() -> None:
    app = mycarlos_app()
    entry = key_entry("raced")
    spec = ClinicKeySpec(
        kid=entry["kid"], spki=clinic_spki("raced"), status="revoked", replaces_kid=None
    )
    # The winner stored the key as active, after the loser had read "no keys yet".
    with app.state.session_factory() as session, session.begin():
        session.add(
            PatientPortalClinicKey(
                kid=entry["kid"],
                clinic_id=CLINIC,
                spki=clinic_spki("raced"),
                status="active",
                published_at=utc_now(),
            )
        )
    with app.state.session_factory() as session, session.begin():
        existing = insert_clinic_key(session, clinic_id=CLINIC, spec=spec, now=utc_now())
        assert existing is not None and existing.status == "active"
    with app.state.session_factory() as session, session.begin():
        result = publish_clinic_keys(session, clinic_id=CLINIC, specs=[spec])
    assert [(key.kid, key.status) for key in result.keys] == [(entry["kid"], "revoked")]


def test_a_raced_key_stored_for_another_clinic_is_refused() -> None:
    app = mycarlos_app()
    entry = key_entry("elsewhere")
    with app.state.session_factory() as session, session.begin():
        session.add(
            PatientPortalClinicKey(
                kid=entry["kid"],
                clinic_id="clinic-b",
                spki=clinic_spki("elsewhere"),
                status="active",
                published_at=utc_now(),
            )
        )
    spec = ClinicKeySpec(kid=entry["kid"], spki=clinic_spki("elsewhere"), status="active")
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(ClinicKeyPublishError, match="invalid_key"):
            insert_clinic_key(session, clinic_id=CLINIC, spec=spec, now=utc_now())
