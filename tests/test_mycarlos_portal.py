# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Real browser-form authentication, ownership and secret handling for patient linking."""

import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from starlette.responses import Response

from carlos_patient_portal import web_support
from carlos_patient_portal.auth import create_patient_session
from carlos_patient_portal.config import Settings
from carlos_patient_portal.credentials import hash_password
from carlos_patient_portal.i18n import MYCARLOS_TEXT_CATALOG
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalClinicKey,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosLinkCode,
    PatientPortalSession,
    utc_now,
)
from carlos_patient_portal.mycarlos_links import IssuedLinkCode
from carlos_patient_portal.runtime import auth_policy_from_settings
from carlos_patient_portal.token_keys import PortalTokenKeys
from tests import delivery_contract_reference as ref
from tests.support import (
    MFA_CHALLENGE_TOKEN_PATTERN,
    NON_DEVELOPMENT_SESSION_SECRET,
    STRONG_PASSWORD,
    STRONG_RESET_PASSWORD,
    RecordingPortalSmsSender,
    csrf_token_from_response,
    development_settings,
    get_csrf_token,
    migrated_development_app,
    non_development_settings_values,
)


def make_portal(*, enabled=True, require_mfa=True, session_secret=None):
    sms = RecordingPortalSmsSender()
    app = migrated_development_app(
        sms_sender=sms,
        mycarlos_delivery_enabled=enabled,
        require_mfa=require_mfa,
        public_base_url="https://portal.example.test",
        session_secret=session_secret,
    )
    key = ref.ClinicKey("FAKE portal UI", app.state.settings.clinic_id)
    with app.state.session_factory() as session, session.begin():
        account = PatientPortalAccount(
            clinic_id=app.state.settings.clinic_id,
            demographic_no=7001,
            username="fake.patient",
            email="fake.patient@example.test",
            phone_number="+15555550123",
            preferred_mfa_method="sms",
            password_hash=hash_password(STRONG_PASSWORD),
            status="active",
        )
        session.add(account)
        session.add(
            PatientPortalClinicKey(
                kid=key.kid,
                clinic_id=key.clinic_id,
                spki=key.spki,
                status="active",
                published_at=utc_now(),
            )
        )
        session.flush()
        account_id = account.id
    return app, TestClient(app, base_url="https://portal.example.test"), sms, account_id


def finish_sms(client, sms, page):
    challenge = MFA_CHALLENGE_TOKEN_PATTERN.search(page.text)
    assert challenge is not None
    result = client.post(
        "/auth/mfa/verify",
        data={
            "csrf_token": csrf_token_from_response(page),
            "mfa_challenge_token": challenge.group(1),
            "code": sms.messages[-1]["code"],
        },
        follow_redirects=False,
    )
    assert result.status_code == 303
    return result


def sign_in(client, sms, *, mfa=True):
    page = client.post(
        "/auth/login",
        data={
            "csrf_token": get_csrf_token(client),
            "username": "fake.patient",
            "password": STRONG_PASSWORD,
        },
        follow_redirects=False,
    )
    if mfa:
        assert page.status_code == 200
        finish_sms(client, sms, page)
    else:
        assert page.status_code == 303


def form_token(client):
    page = client.get("/portal/mycarlos")
    assert page.status_code == 200
    return csrf_token_from_response(page)


def code_count(app):
    with app.state.session_factory() as session:
        return session.scalar(select(func.count()).select_from(PatientPortalMyCarlosLinkCode))


def replace_browser_cookie(client, name, value):
    domain = next(
        cookie.domain
        for cookie in client.cookies.jar
        if cookie.name == web_support.PORTAL_SESSION_COOKIE_NAME
    )
    client.cookies.delete(name)
    client.cookies.set(name, value, domain=domain, path="/portal")


def stored_device(app, account_id, label, name="FAKE myCarlos on Windows"):
    keys = ref.DeviceKeys(label)
    with app.state.session_factory() as session, session.begin():
        device = PatientPortalMyCarlosDevice(
            account_id=account_id,
            device_key_id=keys.device_key_id,
            x25519_public_key=keys.x25519_public,
            ed25519_public_key=keys.ed25519_public,
            device_name=name,
            status="active",
            linked_at=utc_now(),
        )
        session.add(device)
    return keys.device_key_id


def test_sms_mfa_code_is_session_bound_hashed_not_cached_or_logged(caplog):
    app, client, sms, account_id = make_portal()
    sign_in(client, sms)
    assert client.cookies.get(web_support.PORTAL_MFA_PROOF_COOKIE_NAME).startswith("sms.")
    csrf = form_token(client)
    assert "https://portal.example.test" in client.get("/portal/mycarlos").text
    csrf = form_token(client)
    assert code_count(app) == 0
    result = client.post("/portal/mycarlos/code", data={"csrf_token": csrf})
    assert result.status_code == 200
    displayed = re.search(
        r"[0-9A-HJKMNP-TV-Z]{8}-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}", result.text
    )
    assert displayed is not None
    link_id, first, second = displayed.group(0).split("-")
    secret = first + second
    assert result.headers["cache-control"] == "no-store"
    assert secret not in str(result.url) and secret not in caplog.text
    with app.state.session_factory() as session:
        row = session.scalar(select(PatientPortalMyCarlosLinkCode))
        assert row.account_id == account_id and row.link_id == link_id
        assert row.code_hash != secret and len(row.code_hash) == 64
        assert row.session_id == session.scalar(select(PatientPortalSession.id))
    assert secret not in repr(IssuedLinkCode(link_id, secret, utc_now()))


def test_password_only_session_must_complete_real_sms_step_up_before_code():
    app, client, sms, _account = make_portal(require_mfa=False)
    sign_in(client, sms, mfa=False)
    csrf = form_token(client)
    refused = client.post("/portal/mycarlos/code", data={"csrf_token": csrf})
    assert refused.status_code == 403 and code_count(app) == 0 and not sms.messages
    step_up = client.post(
        "/portal/mycarlos/mfa", data={"csrf_token": csrf_token_from_response(refused)}
    )
    assert step_up.status_code == 200 and len(sms.messages) == 1
    finish_sms(client, sms, step_up)
    issued = client.post("/portal/mycarlos/code", data={"csrf_token": form_token(client)})
    assert issued.status_code == 200 and code_count(app) == 1


@pytest.mark.parametrize(
    "proof", ["sms." + "0" * 64, "email.bad", "sms." + "a" * 65, "sms.%E2%98%83"]
)
def test_forged_or_malformed_proof_does_not_issue_code(proof):
    app, client, sms, _account = make_portal()
    sign_in(client, sms)
    replace_browser_cookie(client, web_support.PORTAL_MFA_PROOF_COOKIE_NAME, proof)
    result = client.post("/portal/mycarlos/code", data={"csrf_token": form_token(client)})
    assert result.status_code == 403 and code_count(app) == 0


def test_mfa_proof_cannot_be_moved_to_another_valid_session():
    # The development default generates a process-local secret without storing it in settings.
    # Configure this FAKE fixture explicitly so both legitimate sessions use the same real key.
    app, client, sms, account_id = make_portal(session_secret=NON_DEVELOPMENT_SESSION_SECRET)
    sign_in(client, sms)
    settings = app.state.settings
    assert settings.session_secret is not None
    keys = PortalTokenKeys.derive(settings.session_secret.get_secret_value())
    with app.state.session_factory() as session, session.begin():
        replacement = create_patient_session(
            session,
            session.get(PatientPortalAccount, account_id),
            policy=auth_policy_from_settings(settings),
            session_token_secret=keys.session,
            now=utc_now(),
        )
    replace_browser_cookie(client, web_support.PORTAL_SESSION_COOKIE_NAME, replacement)
    result = client.post("/portal/mycarlos/code", data={"csrf_token": form_token(client)})
    assert result.status_code == 403 and code_count(app) == 0


@pytest.mark.parametrize("state", ["expired", "revoked"])
def test_valid_mfa_mac_never_overrides_session_expiry_or_revocation(state):
    app, client, sms, _account = make_portal()
    sign_in(client, sms)
    csrf = form_token(client)
    with app.state.session_factory() as session, session.begin():
        row = session.scalar(select(PatientPortalSession))
        if state == "expired":
            row.created_at = utc_now() - timedelta(hours=2)
            row.expires_at = utc_now() - timedelta(seconds=1)
        else:
            row.revoked_at, row.revoked_reason = utc_now(), "FAKE test revocation"
    result = client.post("/portal/mycarlos/code", data={"csrf_token": csrf}, follow_redirects=False)
    assert result.status_code == 303 and code_count(app) == 0


def test_device_name_is_escaped_and_only_owned_device_can_be_removed():
    app, client, sms, account_id = make_portal()
    sign_in(client, sms)
    key = stored_device(app, account_id, "FAKE owned", "<script>alert(1)</script>")
    page = client.get("/portal/account")
    assert "<script>alert(1)</script>" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    path = f"/portal/account/mycarlos/devices/{key}/remove"
    confirmation = client.get(path)
    assert confirmation.status_code == 200
    with app.state.session_factory() as session:
        assert session.scalar(select(PatientPortalMyCarlosDevice.status)) == "active"
    assert client.post(path).status_code == 403
    for _attempt in range(2):
        result = client.post(
            path,
            data={"csrf_token": csrf_token_from_response(confirmation)},
            follow_redirects=False,
        )
        assert result.status_code == 303
    with app.state.session_factory() as session:
        device = session.scalar(select(PatientPortalMyCarlosDevice))
        assert (device.status, device.removed_by) == ("removed", "patient")
        assert device.removed_at is not None
    other = stored_device(app, account_id, "FAKE moved to another account")
    with app.state.session_factory() as session, session.begin():
        second = PatientPortalAccount(
            clinic_id=app.state.settings.clinic_id,
            demographic_no=7002,
            username="fake.other",
            email="other@example.test",
            password_hash="FAKE-not-used",
            status="active",
        )
        session.add(second)
        session.flush()
        row = session.scalar(
            select(PatientPortalMyCarlosDevice).where(
                PatientPortalMyCarlosDevice.device_key_id == other
            )
        )
        row.account_id = second.id
    other_path = f"/portal/account/mycarlos/devices/{other}/remove"
    assert client.get(other_path).status_code == 404
    assert client.post(other_path, data={"csrf_token": form_token(client)}).status_code == 404


def test_get_and_invalid_csrf_or_client_supplied_account_never_create_code():
    app, client, sms, _account = make_portal()
    sign_in(client, sms)
    for _ in range(2):
        form_token(client)
    assert code_count(app) == 0
    assert client.post("/portal/mycarlos/code", data={"csrf_token": "bad"}).status_code == 403
    assert (
        client.post(
            "/portal/mycarlos/code", data={"csrf_token": form_token(client), "account_id": "7002"}
        ).status_code
        == 400
    )
    assert code_count(app) == 0


def test_off_switch_hides_routes_navigation_and_does_not_issue_new_auth_cookie():
    app, client, sms, _account = make_portal(enabled=False)
    sign_in(client, sms)
    assert client.cookies.get(web_support.PORTAL_MFA_PROOF_COOKIE_NAME) is None
    assert client.get("/portal/mycarlos").status_code == 404
    assert client.post("/portal/mycarlos/code").status_code == 404
    assert "Link myCarlos" not in client.get("/portal").text
    assert code_count(app) == 0


def test_password_replacement_and_logout_clear_mfa_proof():
    _app, client, sms, _account = make_portal()
    sign_in(client, sms)
    account = client.get("/portal/account")
    result = client.post(
        "/portal/account/password",
        data={
            "csrf_token": csrf_token_from_response(account),
            "current_password": STRONG_PASSWORD,
            "new_password": STRONG_RESET_PASSWORD,
            "new_password_confirmation": STRONG_RESET_PASSWORD,
        },
        follow_redirects=False,
    )
    assert result.status_code == 303
    assert client.cookies.get(web_support.PORTAL_MFA_PROOF_COOKIE_NAME) is None
    assert (
        client.post("/portal/mycarlos/code", data={"csrf_token": form_token(client)}).status_code
        == 403
    )
    # A leftover or forged tag must also be cleared by the ordinary logout handler.
    replace_browser_cookie(client, web_support.PORTAL_MFA_PROOF_COOKIE_NAME, "sms." + "a" * 64)
    account = client.get("/portal/account")
    logout = client.post(
        "/portal/logout",
        data={"csrf_token": csrf_token_from_response(account)},
        follow_redirects=False,
    )
    assert logout.status_code == 303
    assert client.cookies.get(web_support.PORTAL_MFA_PROOF_COOKIE_NAME) is None


@pytest.mark.parametrize("locale", ["en", "fr", "es", "pl", "pt-BR"])
def test_linking_uses_real_locale_copy(locale):
    _app, client, sms, _account = make_portal()
    sign_in(client, sms)
    client.cookies.set("portal_locale", locale)
    result = client.get("/portal/mycarlos")
    assert result.status_code == 200
    assert MYCARLOS_TEXT_CATALOG[locale]["mycarlos_link"] in result.text
    assert MYCARLOS_TEXT_CATALOG[locale]["mycarlos_create"] in result.text


def test_email_proof_is_environment_bound_and_cookie_is_scoped_secure_and_cleared():
    settings = development_settings(
        mycarlos_delivery_enabled=True, public_base_url="https://portal.example.test/patients"
    )
    keys = PortalTokenKeys.derive("FAKE-session-secret" * 3)
    token = "a" * 43
    response = Response()
    web_support.set_portal_mfa_proof_cookie(
        response,
        token,
        delivery_method="email",
        proof_secret=keys.mycarlos_mfa_proof,
        settings=settings,
    )
    header = response.headers["set-cookie"]
    proof = header.split(";", 1)[0].split("=", 1)[1]
    assert (
        "HttpOnly" in header and "SameSite=strict" in header and "Path=/patients/portal" in header
    )
    assert web_support.is_valid_portal_mfa_proof(
        proof, token, proof_secret=keys.mycarlos_mfa_proof, allow_email=True
    )
    assert not web_support.is_valid_portal_mfa_proof(
        proof, token, proof_secret=keys.mycarlos_mfa_proof, allow_email=False
    )
    nondevelopment = non_development_settings_values("staging")
    nondevelopment["public_base_url"] = "https://portal.example.test/patients"
    secure_settings = Settings(**nondevelopment, mycarlos_delivery_enabled=True)
    secure_response = Response()
    web_support.set_portal_mfa_proof_cookie(
        secure_response,
        token,
        delivery_method="sms",
        proof_secret=keys.mycarlos_mfa_proof,
        settings=secure_settings,
    )
    assert "Secure" in secure_response.headers["set-cookie"]
    with pytest.raises(ValueError, match="not an independent production"):
        web_support.set_portal_mfa_proof_cookie(
            Response(),
            token,
            delivery_method="email",
            proof_secret=keys.mycarlos_mfa_proof,
            settings=secure_settings,
        )
    cleared = Response()
    web_support.set_portal_session_cookie(cleared, "b" * 43, settings=settings)
    assert any(
        web_support.PORTAL_MFA_PROOF_COOKIE_NAME in value and "Max-Age=0" in value
        for value in cleared.headers.getlist("set-cookie")
    )
