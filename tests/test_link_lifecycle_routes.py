"""Real signed HTTP recovery/refresh, including a proxy-stripped deployment prefix."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select

from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalClinicKey,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosLinkCode,
    PatientPortalMyCarlosRecipient,
)
from carlos_patient_portal.routes import mycarlos as mycarlos_routes
from carlos_patient_portal.routes.mycarlos import mycarlos_clock
from tests import delivery_contract_reference as ref
from tests.support import migrated_development_app

FIXTURE = json.loads((Path(__file__).parent / "fixtures/link-lifecycle-v1.json").read_text())
NOW = FIXTURE["constants"]["now"]
NOW_AT = datetime.fromtimestamp(NOW, tz=UTC)
PREFIX = "/patients"
RECOVERY = PREFIX + "/api/mycarlos/link"
REFRESH = PREFIX + "/api/mycarlos/clinic-keys"


class StrippingProxy:
    """Model the actual reverse proxy: externally prefixed path, stripped before ASGI app."""

    def __init__(self, app):
        self.app = app
        self.observed_paths = []

    async def __call__(self, scope, receive, send):
        forwarded = dict(scope)
        if scope["type"] == "http":
            assert scope["raw_path"].startswith(PREFIX.encode() + b"/")
            self.observed_paths.append(scope["raw_path"])
            forwarded["path"] = scope["path"][len(PREFIX) :]
            forwarded["raw_path"] = scope["raw_path"][len(PREFIX) :]
        await self.app(forwarded, receive, send)


def native_portal(
    *,
    removed=False,
    recipient=True,
    all_revoked=False,
    database_url="sqlite+pysqlite:///:memory:",
    public_base_url="https://portal.example.test/patients",
    proxy_factory=StrippingProxy,
    **settings_overrides,
):
    app = migrated_development_app(
        mycarlos_delivery_enabled=True,
        clinic_id="clinic-a",
        clinic_name="FAKE independent clinic",
        public_base_url=public_base_url,
        database_url=database_url,
        **settings_overrides,
    )
    app.dependency_overrides[mycarlos_clock] = lambda: NOW
    device = FIXTURE["device"]
    scenario = next(v for v in FIXTURE["inventory_vectors"] if v["name"] == "signed-replacement")
    with app.state.session_factory() as session, session.begin():
        account = PatientPortalAccount(
            clinic_id="clinic-a",
            demographic_no=7001,
            username="fake.lifecycle",
            email="fake.lifecycle@example.test",
            password_hash="FAKE-not-a-password-hash",
            status="active",
        )
        session.add(account)
        session.flush()
        account_id = account.id
        if recipient:
            session.add(
                PatientPortalMyCarlosRecipient(
                    account_id=account_id,
                    recipient_id=ref.RECIPIENT_ID,
                )
            )
        session.add(
            PatientPortalMyCarlosDevice(
                account_id=account_id,
                device_key_id=device["device_key_id"],
                x25519_public_key=ref.b64url_decode(device["x25519_public_key"]),
                ed25519_public_key=ref.b64url_decode(device["ed25519_public_key"]),
                device_name="FAKE lifecycle device",
                status="removed" if removed else "active",
                linked_at=NOW_AT - timedelta(days=1),
                removed_at=NOW_AT if removed else None,
                removed_by="patient" if removed else None,
            )
        )
        for index, value in enumerate(scenario["incoming"]):
            revoked = all_revoked or value["status"] == "revoked"
            session.add(
                PatientPortalClinicKey(
                    kid=value["kid"],
                    clinic_id="clinic-a",
                    spki=ref.b64url_decode(value["spki"]),
                    status="revoked" if revoked else "active",
                    published_at=NOW_AT - timedelta(days=30 - index),
                    revoked_at=NOW_AT if revoked else None,
                    replaces_kid=value.get("replaces_kid"),
                    replacement_signature=ref.b64url_decode(value["replacement_signature"])
                    if "replacement_signature" in value
                    else None,
                )
            )
    proxy = proxy_factory(app)
    return app, TestClient(proxy, base_url="https://portal.example.test"), proxy, account_id


def signed_assertion(
    path, *, recovery=True, signed_method="GET", signed_path=None, recipient_id=ref.RECIPIENT_ID
):
    device = ref.DeviceKeys("lifecycle-v1 registered device")
    assert device.device_key_id == FIXTURE["device"]["device_key_id"]
    claims = {
        "aud": "carlos-patient-portal-device-link-recovery" if recovery else ref.DEVICE_AUDIENCE,
        "iss": "mycarlos",
        "kid": device.device_key_id,
        "jti": str(uuid4()),
        "iat": NOW,
        "exp": NOW + 60,
        "request_hash": ref.request_hash(signed_method, (signed_path or path).encode(), b"", b""),
    }
    if not recovery:
        claims["recipient_id"] = recipient_id
    return ref.compact_ed25519(device.ed25519, claims)


@pytest.mark.parametrize(
    "vector",
    [
        value
        for value in FIXTURE["recovery_vectors"]
        if value["name"] not in {"wrong-method", "wrong-prefix"}
    ],
    ids=lambda value: value["name"],
)
def test_recovery_http_decides_shared_vectors_without_creating_devices_or_codes(
    vector, monkeypatch
):
    replay = vector["nonce_already_consumed"]
    app, client, proxy, account_id = native_portal(
        removed=vector["device_status"] == "removed" and not replay,
        recipient=vector["recipient_exists"],
    )
    if replay:
        first = client.get(RECOVERY, headers={"X-MyCarlos-Device-Assertion": vector["assertion"]})
        assert first.status_code == 200
        if vector["device_status"] == "removed":
            with app.state.session_factory() as session, session.begin():
                device = session.scalar(select(PatientPortalMyCarlosDevice))
                device.status = "removed"
                device.removed_at = NOW_AT
                device.removed_by = "patient"
    deleted_after_authentication = []
    if not vector["account_exists"]:
        original_consume = mycarlos_routes.consume_device_assertion

        def consume_then_delete_owned_account(*args, **kwargs):
            # Keep real signature/freshness/request/nonce checks. Model disappearance
            # AFTER that authenticated snapshot, before the current account lock.
            original_consume(*args, **kwargs)
            with app.state.session_factory() as session, session.begin():
                session.execute(
                    delete(PatientPortalMyCarlosDevice).where(
                        PatientPortalMyCarlosDevice.account_id == account_id
                    )
                )
                session.execute(
                    delete(PatientPortalMyCarlosRecipient).where(
                        PatientPortalMyCarlosRecipient.account_id == account_id
                    )
                )
                session.execute(
                    delete(PatientPortalAccount).where(PatientPortalAccount.id == account_id)
                )
            deleted_after_authentication.append(account_id)

        monkeypatch.setattr(
            mycarlos_routes, "consume_device_assertion", consume_then_delete_owned_account
        )
    query = bytes.fromhex(vector["raw_query_hex"]).decode()
    response = client.request(
        "GET",
        RECOVERY + ("?" + query if query else ""),
        content=bytes.fromhex(vector["body_hex"]),
        headers={"X-MyCarlos-Device-Assertion": vector["assertion"]},
    )
    assert response.status_code == vector["expected_status"], response.text
    assert response.json() == json.loads(bytes.fromhex(vector["expected_response_utf8_hex"]))
    assert response.headers["cache-control"] == "no-store"
    assert proxy.observed_paths[-1] == RECOVERY.encode()
    if not vector["account_exists"]:
        assert deleted_after_authentication == [account_id]
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(PatientPortalMyCarlosLinkCode)) == 0
        assert session.scalar(select(func.count()).select_from(PatientPortalMyCarlosDevice)) == int(
            vector["account_exists"]
        )


@pytest.mark.parametrize(
    "signed_method,signed_path", [("POST", RECOVERY), ("GET", "/api/mycarlos/link")]
)
def test_actual_prefixed_get_refuses_wrong_signed_method_or_missing_signed_prefix(
    signed_method, signed_path
):
    app, client, proxy, _account = native_portal()
    assertion = signed_assertion(RECOVERY, signed_method=signed_method, signed_path=signed_path)
    response = client.get(RECOVERY, headers={"X-MyCarlos-Device-Assertion": assertion})
    assert response.status_code == 404
    assert response.json() == {"detail": "not found"}
    assert proxy.observed_paths == [RECOVERY.encode()]
    with app.state.session_factory() as session:
        assert session.scalar(select(PatientPortalAuditEvent.reason)) == "request_mismatch"


def test_all_revoked_refresh_is_valid_but_recovery_bootstrap_requires_active_key():
    _app, client, _proxy, _account = native_portal(all_revoked=True)
    refreshed = client.get(
        REFRESH, headers={"X-MyCarlos-Device-Assertion": signed_assertion(REFRESH, recovery=False)}
    )
    assert refreshed.status_code == 200
    assert len(refreshed.json()["clinic_keys"]) == 2
    assert all(value["status"] == "revoked" for value in refreshed.json()["clinic_keys"])
    recovered = client.get(
        RECOVERY, headers={"X-MyCarlos-Device-Assertion": signed_assertion(RECOVERY)}
    )
    assert recovered.status_code == 409 and recovered.json() == {"code": "clinic_keys_missing"}


def test_recovery_audience_never_authorizes_refresh_or_the_reverse():
    _app, client, _proxy, _account = native_portal()
    for path, recovery in [(RECOVERY, False), (REFRESH, True)]:
        result = client.get(
            path, headers={"X-MyCarlos-Device-Assertion": signed_assertion(path, recovery=recovery)}
        )
        assert result.status_code == 404 and result.json() == {"detail": "not found"}


@pytest.mark.parametrize(
    "recipient_id,status,code",
    [
        ("rcp-FAKE-wrong-recipient", 403, "recipient_mismatch"),
        ("recipient-é", 404, None),
    ],
)
def test_refresh_preserves_recipient_refusal_without_unicode_comparison_error(
    recipient_id, status, code
):
    _app, client, _proxy, _account = native_portal()
    assertion = signed_assertion(REFRESH, recovery=False, recipient_id=recipient_id)
    response = client.get(REFRESH, headers={"X-MyCarlos-Device-Assertion": assertion})
    assert response.status_code == status
    assert response.json() == ({"code": code} if code else {"detail": "not found"})
