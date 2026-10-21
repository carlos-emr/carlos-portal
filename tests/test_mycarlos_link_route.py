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

"""`POST /api/mycarlos/link` (carlos-portal#41, M2-c) against every shared link vector, and the
limits: per link, per account, the session, and the switch."""

import json
from base64 import urlsafe_b64decode
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from itertools import count
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from carlos_patient_portal.models import (
    AUDIT_EVENT_MYCARLOS_LINK,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalClinicKey,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosLinkCode,
    PatientPortalMyCarlosLinkFailure,
    PatientPortalMyCarlosRecipient,
    PatientPortalSession,
)
from carlos_patient_portal.mycarlos_links import (
    LinkingPausedError,
    create_link_code,
    display_link_code,
    hash_link_code,
)
from carlos_patient_portal.routes.mycarlos import mycarlos_clock
from carlos_patient_portal.staff_identity import staff_request_hash
from carlos_patient_portal.token_keys import PortalTokenKeys
from tests import delivery_contract_reference as ref
from tests.support import NON_DEVELOPMENT_SESSION_SECRET, migrated_development_app

CONTRACT = json.loads(
    (Path(__file__).parent / "fixtures" / "delivery-contract.json").read_text(encoding="utf-8")
)
PORTAL = CONTRACT["portal"]
STATE = PORTAL["state"]
NOW = STATE["now"]
NOW_AT = datetime.fromtimestamp(NOW, tz=UTC)
LINK_PATH = "/api/mycarlos/link"
LINK_KEY = PortalTokenKeys.derive(NON_DEVELOPMENT_SESSION_SECRET).mycarlos_link
IDLE = timedelta(minutes=10)
SESSION_NUMBERS = count(1)
# The spec's generic answer to a failed assertion, so the API reveals nothing without a key.
ASSERTION_FAILURES = {"invalid_assertion", "expired", "request_mismatch", "replay"}


def decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def link_app(**overrides: object):
    app = migrated_development_app(
        clinic_id="clinic-a",
        clinic_name="Clinic A",
        session_secret=NON_DEVELOPMENT_SESSION_SECRET,
        mycarlos_delivery_enabled=True,
        **overrides,
    )
    app.dependency_overrides[mycarlos_clock] = lambda: NOW
    return app


def seed_vector_state(app) -> dict[str, int]:
    """The vectors' accounts, devices, link codes and recent wrong codes, at the vectors' time."""
    accounts: dict[str, int] = {}
    with app.state.session_factory() as session, session.begin():
        for number, row in enumerate(STATE["accounts"], start=1):
            account = PatientPortalAccount(
                clinic_id=row["clinic_id"],
                demographic_no=7000 + number,
                username=f"fake.{row['account']}",
                email=f"{row['account']}@example.test",
                password_hash="FAKE-not-a-real-hash",
                status="active",
            )
            session.add(account)
            session.flush()
            accounts[row["account"]] = account.id
            session.add(
                PatientPortalMyCarlosRecipient(
                    account_id=account.id, recipient_id=row["recipient_id"]
                )
            )
            for minutes in range(row["recent_wrong_codes"]):
                session.add(
                    PatientPortalMyCarlosLinkFailure(
                        account_id=account.id,
                        link_id="FAKEPAST",
                        failed_at=NOW_AT - timedelta(minutes=30 + minutes),
                    )
                )
        devices: dict[str, int] = {}
        for row in STATE["devices"]:
            removed = row["status"] == "removed"
            device = PatientPortalMyCarlosDevice(
                account_id=accounts[row["account"]],
                device_key_id=row["device_key_id"],
                x25519_public_key=decode(row["x25519_public_key"]),
                ed25519_public_key=decode(row["ed25519_public_key"]),
                device_name="myCarlos on Linux",
                status=row["status"],
                linked_at=NOW_AT - timedelta(days=3),
                removed_at=NOW_AT - timedelta(days=1) if removed else None,
                removed_by="patient" if removed else None,
            )
            session.add(device)
            session.flush()
            devices.setdefault(row["account"], device.id)
        for row in STATE["link_codes"]:
            portal_session = add_session(
                session, accounts[row["account"]], signed_in=row["session_signed_in"]
            )
            expires_at = datetime.fromtimestamp(row["expires_at"], tz=UTC)
            used = row["status"] == "used"
            session.add(
                PatientPortalMyCarlosLinkCode(
                    account_id=accounts[row["account"]],
                    session_id=portal_session.id,
                    link_id=row["link_id"],
                    code_hash=hash_link_code(LINK_KEY, row["link_id"], row["code"]),
                    status="used" if used else "pending",
                    wrong_codes=row["wrong_attempts"],
                    created_at=expires_at - timedelta(minutes=10),
                    expires_at=expires_at,
                    used_at=NOW_AT - timedelta(minutes=1) if used else None,
                    device_id=devices[row["account"]] if used else None,
                )
            )
        for name in ("clinic_a", "clinic_a_revoked"):
            key = CONTRACT["keys"][name]
            revoked = name.endswith("revoked")
            session.add(
                PatientPortalClinicKey(
                    kid=key["kid"],
                    clinic_id=key["clinic_id"],
                    spki=decode(key["spki"]),
                    status="revoked" if revoked else "active",
                    published_at=NOW_AT - timedelta(days=30 if revoked else 1),
                    revoked_at=NOW_AT - timedelta(days=2) if revoked else None,
                )
            )
    return accounts


def add_session(session, account_id: int, *, signed_in: bool = True) -> PatientPortalSession:
    portal_session = PatientPortalSession(
        account_id=account_id,
        token_hash=sha256(f"FAKE session {next(SESSION_NUMBERS)}".encode()).hexdigest(),
        created_at=NOW_AT - timedelta(minutes=2),
        expires_at=NOW_AT + timedelta(hours=1),
        last_seen_at=NOW_AT - timedelta(seconds=10),
        revoked_at=None if signed_in else NOW_AT - timedelta(seconds=30),
        revoked_reason=None if signed_in else "logout",
    )
    session.add(portal_session)
    session.flush()
    return portal_session


def post(client: TestClient, vector: dict[str, object]):
    return client.post(
        str(vector["path"]),
        content=str(vector["body"]).encode(),
        headers={
            "Content-Type": "application/json",
            "X-MyCarlos-Device-Assertion": str(vector["assertion"]),
        },
    )


def named(vectors: list[dict[str, object]]) -> list[object]:
    return [pytest.param(vector, id=vector["name"]) for vector in vectors]


def wrong_code_count(app, account_id: int) -> int:
    with app.state.session_factory() as session:
        return session.scalar(
            select(func.count())
            .select_from(PatientPortalMyCarlosLinkFailure)
            .where(
                PatientPortalMyCarlosLinkFailure.account_id == account_id,
                PatientPortalMyCarlosLinkFailure.failed_at > NOW_AT - timedelta(hours=24),
            )
        )


@pytest.mark.parametrize("vector", named(PORTAL["link_requests"]))
def test_the_link_route_decides_every_vector_as_the_reference_does(vector) -> None:
    app = link_app()
    accounts = seed_vector_state(app)
    response = post(TestClient(app), vector)

    expected = vector["expect"]
    if expected == "accept":
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["recipient_id"] == vector["returns"]["recipient_id"]
        assert body["device_key_id"] == vector["returns"]["device_key_id"]
        assert (body["clinic_id"], body["clinic_name"]) == ("clinic-a", "Clinic A")
        assert {(key["kid"], key["status"]) for key in body["clinic_keys"]} == {
            (CONTRACT["keys"]["clinic_a"]["kid"], "active"),
            (CONTRACT["keys"]["clinic_a_revoked"]["kid"], "revoked"),
        }
        with app.state.session_factory() as session:
            device = session.scalar(
                select(PatientPortalMyCarlosDevice).where(
                    PatientPortalMyCarlosDevice.device_key_id == body["device_key_id"]
                )
            )
            assert device.account_id == accounts[vector["returns"]["account"]]
            assert device.status == "active"
    elif expected in ASSERTION_FAILURES:
        assert (response.status_code, response.json()) == (404, {"detail": "not found"})
    else:
        status_code = {"link_code_invalid": 403, "device_exists": 409}[expected]
        assert (response.status_code, response.json()) == (status_code, {"code": expected})
    for name, expected_count in vector.get("account_wrong_codes_after", {}).items():
        assert wrong_code_count(app, accounts[name]) == expected_count, name


def test_a_link_uses_the_code_once_and_audits_each_attempt() -> None:
    app = link_app()
    accounts = seed_vector_state(app)
    client = TestClient(app)
    vector = next(v for v in PORTAL["link_requests"] if v["name"] == "link a new device")
    assert post(client, vector).status_code == 200
    # The same request again is a replay: the generic 404.
    assert post(client, vector).status_code == 404
    with app.state.session_factory() as session:
        link = session.scalar(
            select(PatientPortalMyCarlosLinkCode).where(
                PatientPortalMyCarlosLinkCode.link_id == "FAKE0001"
            )
        )
        assert link.status == "used" and link.device_id is not None
        rows = list(
            session.scalars(
                select(PatientPortalAuditEvent)
                .where(PatientPortalAuditEvent.event_type == AUDIT_EVENT_MYCARLOS_LINK)
                .order_by(PatientPortalAuditEvent.id)
            )
        )
    assert [(row.outcome, row.reason) for row in rows] == [
        ("success", "linked"),
        ("failure", "replay"),
    ]
    assert rows[0].account_id == accounts["account-1"]
    assert rows[0].actor_id == vector["returns"]["device_key_id"]


# --------------------------------------------------------------------------------------
# Requests built here, signed with fresh FAKE device keys derived from their labels
# --------------------------------------------------------------------------------------


def link_request(
    link_id: str,
    code: str,
    label: str,
    *,
    path: str = LINK_PATH,
    signed_path: str | None = None,
) -> dict[str, object]:
    device = ref.DeviceKeys(f"m2c {label}")
    body = ref.canonical_json(
        {
            "link_id": link_id,
            "code": code,
            "device_name": "myCarlos on Linux",
            "x25519_public_key": ref.b64url(device.x25519_public),
            "ed25519_public_key": ref.b64url(device.ed25519_public),
        }
    )
    claims = {
        "aud": "carlos-patient-portal-device-link",
        "iss": "mycarlos",
        "kid": device.device_key_id,
        "jti": str(uuid5(NAMESPACE_URL, f"FAKE m2c link {label}")),
        "iat": NOW,
        "exp": NOW + 60,
        "request_hash": staff_request_hash("POST", (signed_path or path).encode(), b"", body),
    }
    return {
        "path": path,
        "body": body.decode(),
        "assertion": ref.compact_ed25519(device.ed25519, claims),
    }


def publish_active_clinic_key(app) -> None:
    """The fixture's clinic-a key, published as CARLOS's key-publish job would."""
    key = CONTRACT["keys"]["clinic_a"]
    with app.state.session_factory() as session, session.begin():
        if session.get(PatientPortalClinicKey, key["kid"]) is None:
            session.add(
                PatientPortalClinicKey(
                    kid=key["kid"],
                    clinic_id=key["clinic_id"],
                    spki=decode(key["spki"]),
                    status="active",
                    published_at=NOW_AT - timedelta(days=1),
                )
            )


def fresh_account(
    app, demographic_no: int = 8001, *, with_clinic_key: bool = True
) -> tuple[int, int]:
    """An account with one signed-in session. Returns (account id, session id)."""
    if with_clinic_key:
        publish_active_clinic_key(app)
    with app.state.session_factory() as session, session.begin():
        account = PatientPortalAccount(
            clinic_id="clinic-a",
            demographic_no=demographic_no,
            username=f"fake.link{demographic_no}",
            email=f"link{demographic_no}@example.test",
            password_hash="FAKE-not-a-real-hash",
            status="active",
        )
        session.add(account)
        session.flush()
        portal_session = add_session(session, account.id)
        return account.id, portal_session.id


def new_code(app, account_id: int, session_id: int, *, at: datetime = NOW_AT):
    with app.state.session_factory() as session, session.begin():
        return create_link_code(
            session,
            account_id=account_id,
            session_id=session_id,
            key=LINK_KEY,
            idle_timeout=IDLE,
            now=at,
        )


def wrong(code: str) -> str:
    return ("0" if code[0] != "0" else "1") + code[1:]


def test_a_fresh_code_links_and_makes_the_recipient_id() -> None:
    app = link_app()
    account_id, session_id = fresh_account(app)
    issued = new_code(app, account_id, session_id)
    assert issued.display == display_link_code(issued.link_id, issued.code)
    assert len(issued.link_id) == 8 and len(issued.code) == 10
    response = post(TestClient(app), link_request(issued.link_id, issued.code, "fresh"))
    assert response.status_code == 200, response.text
    recipient_id = response.json()["recipient_id"]
    # 128 random bits as unpadded base64url.
    assert len(recipient_id) == 22 and len(decode(recipient_id)) == 16
    with app.state.session_factory() as session:
        stored = session.get(PatientPortalMyCarlosRecipient, account_id)
        link = session.scalar(select(PatientPortalMyCarlosLinkCode))
    assert stored.recipient_id == recipient_id
    # Never the code itself.
    assert issued.code not in link.code_hash


def test_no_device_links_before_the_clinic_publishes_an_active_key() -> None:
    app = link_app()
    account_id, session_id = fresh_account(app, with_clinic_key=False)
    # Only a revoked key so far: nothing a device could pin and verify with.
    revoked = CONTRACT["keys"]["clinic_a_revoked"]
    with app.state.session_factory() as session, session.begin():
        session.add(
            PatientPortalClinicKey(
                kid=revoked["kid"],
                clinic_id=revoked["clinic_id"],
                spki=decode(revoked["spki"]),
                status="revoked",
                published_at=NOW_AT - timedelta(days=30),
                revoked_at=NOW_AT - timedelta(days=2),
            )
        )
    issued = new_code(app, account_id, session_id)
    client = TestClient(app)

    refused = post(client, link_request(issued.link_id, issued.code, "no key yet"))
    assert (refused.status_code, refused.json()) == (409, {"code": "clinic_keys_missing"})
    # A wrong code gets the same answer and counts nothing: the check comes before the code.
    wrong_first = post(client, link_request(issued.link_id, wrong(issued.code), "no key wrong"))
    assert wrong_first.json() == {"code": "clinic_keys_missing"}
    assert wrong_code_count(app, account_id) == 0
    with app.state.session_factory() as session:
        link = session.scalar(select(PatientPortalMyCarlosLinkCode))
        assert (link.status, link.wrong_codes) == ("pending", 0)
        reasons = list(
            session.scalars(
                select(PatientPortalAuditEvent.reason).where(
                    PatientPortalAuditEvent.event_type == AUDIT_EVENT_MYCARLOS_LINK
                )
            )
        )
    assert reasons == ["clinic_keys_missing", "clinic_keys_missing"]

    # Once CARLOS publishes an active key, the same code links.
    publish_active_clinic_key(app)
    linked = post(client, link_request(issued.link_id, issued.code, "key published"))
    assert linked.status_code == 200, linked.text
    assert [key["status"] for key in linked.json()["clinic_keys"]] == ["revoked", "active"]


def test_five_wrong_codes_end_a_link_and_more_count_nothing() -> None:
    app = link_app()
    account_id, session_id = fresh_account(app)
    issued = new_code(app, account_id, session_id)
    client = TestClient(app)
    for attempt in range(7):
        response = post(
            client, link_request(issued.link_id, wrong(issued.code), f"wrong {attempt}")
        )
        assert response.json() == {"code": "link_code_invalid"}
    assert wrong_code_count(app, account_id) == 5
    # Even the right code no longer works.
    response = post(client, link_request(issued.link_id, issued.code, "right after five"))
    assert response.json() == {"code": "link_code_invalid"}


def test_a_fourth_code_replaces_the_oldest() -> None:
    app = link_app()
    account_id, session_id = fresh_account(app)
    codes = [
        new_code(app, account_id, session_id, at=NOW_AT + timedelta(seconds=n)) for n in range(4)
    ]
    with app.state.session_factory() as session:
        statuses = {
            link.link_id: link.status
            for link in session.scalars(select(PatientPortalMyCarlosLinkCode))
        }
    assert statuses[codes[0].link_id] == "replaced"
    assert [statuses[code.link_id] for code in codes[1:]] == ["pending"] * 3
    client = TestClient(app)
    replaced = post(client, link_request(codes[0].link_id, codes[0].code, "replaced"))
    assert replaced.json() == {"code": "link_code_invalid"}
    # A wrong code for the replaced link counts nothing.
    post(client, link_request(codes[0].link_id, wrong(codes[0].code), "replaced wrong"))
    assert wrong_code_count(app, account_id) == 0


def test_ten_wrong_codes_in_a_day_pause_linking_for_the_account() -> None:
    app = link_app()
    account_id, session_id = fresh_account(app)
    client = TestClient(app)
    for round_number in range(2):
        issued = new_code(app, account_id, session_id)
        for attempt in range(5):
            post(
                client,
                link_request(issued.link_id, wrong(issued.code), f"pause {round_number} {attempt}"),
            )
    assert wrong_code_count(app, account_id) == 10
    with pytest.raises(LinkingPausedError):
        new_code(app, account_id, session_id)
    # A day after the last wrong code, linking works again.
    later = NOW_AT + timedelta(hours=24, minutes=1)
    issued = new_code(app, account_id, session_id, at=later)
    assert issued.link_id


def test_the_pause_lasts_until_24_hours_after_the_last_wrong_code() -> None:
    app = link_app()
    account_id, session_id = fresh_account(app)
    with app.state.session_factory() as session, session.begin():
        # Five early and five late: 10 within 24 hours, the last one at NOW.
        for offset in [timedelta(hours=20)] * 5 + [timedelta(0)] * 5:
            session.add(
                PatientPortalMyCarlosLinkFailure(
                    account_id=account_id, link_id="FAKEPAST", failed_at=NOW_AT - offset
                )
            )
    # Five hours later only five fall in a rolling 24-hour window, yet linking is still paused.
    with pytest.raises(LinkingPausedError):
        new_code(app, account_id, session_id, at=NOW_AT + timedelta(hours=5))
    with pytest.raises(LinkingPausedError):
        new_code(app, account_id, session_id, at=NOW_AT + timedelta(hours=23, minutes=59))
    assert new_code(app, account_id, session_id, at=NOW_AT + timedelta(hours=24, minutes=1))


def test_a_code_stops_working_when_its_session_signs_out() -> None:
    app = link_app()
    account_id, session_id = fresh_account(app)
    issued = new_code(app, account_id, session_id)
    with app.state.session_factory() as session, session.begin():
        portal_session = session.get(PatientPortalSession, session_id)
        portal_session.revoked_at = NOW_AT
        portal_session.revoked_reason = "logout"
    response = post(TestClient(app), link_request(issued.link_id, issued.code, "signed out"))
    assert response.json() == {"code": "link_code_invalid"}
    assert wrong_code_count(app, account_id) == 0


def test_a_code_stops_working_after_ten_minutes() -> None:
    app = link_app()
    account_id, session_id = fresh_account(app)
    issued = new_code(app, account_id, session_id, at=NOW_AT - timedelta(minutes=10))
    response = post(TestClient(app), link_request(issued.link_id, issued.code, "expired"))
    assert response.json() == {"code": "link_code_invalid"}


def test_a_portal_under_a_path_checks_the_path_the_device_signed() -> None:
    app = link_app(public_base_url="https://portal.example.test/patient")
    client = TestClient(app, base_url="https://portal.example.test")
    account_id, session_id = fresh_account(app)
    first = new_code(app, account_id, session_id)
    # The proxy strips /patient; the device signed the public path.
    signed_public = link_request(
        first.link_id, first.code, "under a path", signed_path="/patient/api/mycarlos/link"
    )
    assert post(client, signed_public).status_code == 200
    second = new_code(app, account_id, session_id)
    signed_bare = link_request(second.link_id, second.code, "bare path")
    assert post(client, signed_bare).status_code == 404


def test_an_oversized_body_is_refused_before_it_is_read() -> None:
    app = link_app()
    response = TestClient(app).post(
        LINK_PATH,
        content=b"{" + b" " * 5000 + b"}",
        headers={"Content-Type": "application/json", "X-MyCarlos-Device-Assertion": "x.y"},
    )
    assert response.status_code == 413


def test_no_route_exists_while_the_switch_is_off() -> None:
    app = migrated_development_app(session_secret=NON_DEVELOPMENT_SESSION_SECRET)
    vector = PORTAL["link_requests"][0]
    response = post(TestClient(app), vector)
    assert response.status_code == 404
    assert not any("mycarlos" in getattr(route, "path", "") for route in app.routes)


def test_the_link_route_has_its_own_strict_rate_limit() -> None:
    app = link_app(auth_rate_limit_max_requests=2)
    client = TestClient(app)
    codes = [post(client, PORTAL["link_requests"][-1]).status_code for _ in range(3)]
    assert codes[-1] == 429
    # Another route keeps its own budget.
    assert client.get("/health").status_code == 200
