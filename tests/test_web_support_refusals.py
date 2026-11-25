# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Refusals in `web_support.py` that no other test drove: the MFA proof cookie and its check, the
date and forwarded-address parsers, and the request readers that say 415 or a validation error for
a body that is not what the route takes. FAKE values only; nothing needs a database."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from datetime import date
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request
from starlette.responses import Response

from carlos_patient_portal import web_support as ws
from carlos_patient_portal.models import MFA_DELIVERY_METHOD_EMAIL, MFA_DELIVERY_METHOD_SMS

SECRET = "FAKE csrf and proof secret, long enough for the tests, 40+ characters"
SESSION_TOKEN = "S" * 43
PROOF_SECRET = "FAKE mfa proof secret, long enough for the tests, 40+ characters"


def settings(*, development: bool = True, mycarlos: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        is_development=development,
        session_ttl_seconds=3600,
        root_path="",
        mycarlos_delivery_enabled=mycarlos,
    )


def request_for(
    body: bytes = b"",
    *,
    content_type: str | None = None,
    cookies: dict[str, str] | None = None,
) -> Request:
    headers = []
    if content_type is not None:
        headers.append((b"content-type", content_type.encode()))
    if cookies:
        headers.append((b"cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()).encode()))
    sent = {"done": False}

    async def receive() -> dict[str, object]:
        if sent["done"]:
            return {"type": "http.disconnect"}
        sent["done"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "headers": headers,
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 1234),
    }
    return Request(scope, receive)


def run(awaitable: Awaitable[object]) -> object:
    return asyncio.run(awaitable)  # type: ignore[arg-type]


def form(fields: dict[str, str], *, good_csrf: bool = True) -> Request:
    token = ws.create_csrf_token(SECRET)
    body = urlencode({**fields, ws.CSRF_FORM_FIELD: token})
    cookies = {ws.CSRF_COOKIE_NAME: token if good_csrf else ws.create_csrf_token(SECRET)}
    return request_for(
        body.encode(), content_type="application/x-www-form-urlencoded", cookies=cookies
    )


# --- the MFA proof cookie ----------------------------------------------------------------------


def test_a_proof_cookie_is_made_only_for_a_known_factor_and_a_real_session_token() -> None:
    response = Response()
    for method in ("totp", "", "SMS"):
        with pytest.raises(ValueError, match="unsupported MFA proof factor"):
            ws.set_portal_mfa_proof_cookie(
                response,
                SESSION_TOKEN,
                delivery_method=method,
                proof_secret=PROOF_SECRET,
                settings=settings(),
            )
    for token in ("short", SESSION_TOKEN + "x", "S" * 42 + "!"):
        with pytest.raises(ValueError, match="invalid session token"):
            ws.set_portal_mfa_proof_cookie(
                response,
                token,
                delivery_method=MFA_DELIVERY_METHOD_SMS,
                proof_secret=PROOF_SECRET,
                settings=settings(),
            )
    assert "set-cookie" not in response.headers


def test_email_is_not_an_independent_proof_outside_development() -> None:
    response = Response()
    with pytest.raises(ValueError, match="not an independent production MFA factor"):
        ws.set_portal_mfa_proof_cookie(
            response,
            SESSION_TOKEN,
            delivery_method=MFA_DELIVERY_METHOD_EMAIL,
            proof_secret=PROOF_SECRET,
            settings=settings(development=False),
        )
    assert "set-cookie" not in response.headers
    # In development an email proof is made, and sms is made anywhere.
    for development, method in ((True, "email"), (False, "sms")):
        ok = Response()
        ws.set_portal_mfa_proof_cookie(
            ok,
            SESSION_TOKEN,
            delivery_method=method,
            proof_secret=PROOF_SECRET,
            settings=settings(development=development),
        )
        assert ok.headers["set-cookie"].startswith(f"{ws.PORTAL_MFA_PROOF_COOKIE_NAME}={method}.")


def _proof(method: str = "sms") -> str:
    response = Response()
    ws.set_portal_mfa_proof_cookie(
        response,
        SESSION_TOKEN,
        delivery_method=method,
        proof_secret=PROOF_SECRET,
        settings=settings(),
    )
    value = response.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    return value


@pytest.mark.parametrize(
    ("proof", "session_token"),
    [
        (None, SESSION_TOKEN),
        ("x" * 71, SESSION_TOKEN),
        ("sms.not-hex", SESSION_TOKEN),
        ("tel." + "0" * 64, SESSION_TOKEN),
        ("sms." + "0" * 64, SESSION_TOKEN),  # well formed, wrong tag
        (None, None),
    ],
)
def test_a_proof_that_is_missing_malformed_or_wrong_proves_nothing(
    proof: str | None, session_token: str | None
) -> None:
    assert not ws.is_valid_portal_mfa_proof(
        proof, session_token, proof_secret=PROOF_SECRET, allow_email=True
    )


def test_a_proof_proves_only_for_its_own_session_and_an_allowed_factor() -> None:
    sms = _proof("sms")
    assert ws.is_valid_portal_mfa_proof(
        sms, SESSION_TOKEN, proof_secret=PROOF_SECRET, allow_email=False
    )
    # No session token, a malformed one, or another session's.
    for token in (None, "short", "T" * 43):
        assert not ws.is_valid_portal_mfa_proof(
            sms, token, proof_secret=PROOF_SECRET, allow_email=True
        )
    # Another secret.
    assert not ws.is_valid_portal_mfa_proof(
        sms, SESSION_TOKEN, proof_secret=PROOF_SECRET + "x", allow_email=True
    )
    # Email counts only where it is allowed.
    email = _proof("email")
    assert ws.is_valid_portal_mfa_proof(
        email, SESSION_TOKEN, proof_secret=PROOF_SECRET, allow_email=True
    )
    assert not ws.is_valid_portal_mfa_proof(
        email, SESSION_TOKEN, proof_secret=PROOF_SECRET, allow_email=False
    )


def test_logging_out_without_a_session_token_does_nothing() -> None:
    from datetime import timedelta

    ws.logout_browser_session_cookie_token(
        None,  # type: ignore[arg-type]
        session_token=None,
        session_token_secret=SECRET,
        idle_timeout=timedelta(minutes=5),
    )


def test_the_login_payload_carries_the_session_token_only_when_there_is_one() -> None:
    plain = SimpleNamespace(status="authenticated", session_token=None, mfa_challenge=None)
    assert ws.login_response_payload(plain, settings=settings()) == {"status": "authenticated"}
    kept = SimpleNamespace(status="authenticated", session_token="FAKE-token", mfa_challenge=None)
    assert ws.login_response_payload(kept, settings=settings()) == {
        "status": "authenticated",
        "session_token": "FAKE-token",
    }


# --- date and address parsers ------------------------------------------------------------------


def test_the_optional_date_takes_one_iso_form_only() -> None:
    assert ws.parse_optional_email_password_date(None) is None
    assert ws.parse_optional_email_password_date("   ") is None
    assert ws.parse_optional_email_password_date(" 2026-11-24 ") == date(2026, 11, 24)
    for value in ("2026-1-4", "20261124", "11/24/2026", "2026-W48-2", "2026-11-244", "x" * 10):
        with pytest.raises(ValueError):
            ws.parse_optional_email_password_date(value)


@pytest.mark.parametrize(
    ("header", "peer", "cidrs", "expected"),
    [
        ("203.0.113.9, 10.0.0.2", "10.0.0.1", "10.0.0.0/8", "203.0.113.9"),
        # A client may put its own claim first: the address nearest the proxy chain is believed.
        ("198.51.100.7, 203.0.113.9, 10.0.0.2", "10.0.0.1", "10.0.0.0/8", "203.0.113.9"),
        # Every address is a trusted proxy: the first one is the client.
        ("10.0.0.5, 10.0.0.2", "10.0.0.1", "10.0.0.0/8", "10.0.0.5"),
        # A peer that is not a trusted proxy cannot name the client.
        ("203.0.113.9", "198.51.100.1", "10.0.0.0/8", None),
        ("not an address", "10.0.0.1", "10.0.0.0/8", None),
        (",", "10.0.0.1", "10.0.0.0/8", None),
        ("203.0.113.9", "10.0.0.1", "not a cidr", None),
        ("203.0.113.9", None, "10.0.0.0/8", None),
        (None, "10.0.0.1", "10.0.0.0/8", None),
    ],
)
def test_the_forwarded_address_is_believed_only_from_a_trusted_proxy(
    header: str | None, peer: str | None, cidrs: str, expected: str | None
) -> None:
    assert (
        ws.parse_trusted_client_ip_header(
            "x-forwarded-for", header, peer_address=peer, trusted_proxy_cidrs=cidrs
        )
        == expected
    )


def test_a_kept_activation_form_ignores_a_date_it_cannot_read() -> None:
    kept = ws.activation_form_values_to_keep({"date_of_birth": ["not a date"], "email": ["a@b.c"]})
    assert kept == {"email": "a@b.c"}
    iso = ws.activation_form_values_to_keep({"date_of_birth": ["1980-05-02"]})
    assert iso == {
        "date_of_birth_day": "2",
        "date_of_birth_month": "5",
        "date_of_birth_year": "1980",
    }


# --- requests that are not what the route takes ------------------------------------------------


def test_activation_takes_only_json() -> None:
    request = request_for(b"invite_code=x", content_type="application/x-www-form-urlencoded")
    with pytest.raises(HTTPException) as raised:
        run(ws.get_activation_request(request))
    assert raised.value.status_code == 415


@pytest.mark.parametrize(
    "reader",
    [
        ws.get_mfa_verify_request_from_request,
        ws.get_mfa_resend_request_from_request,
        ws.get_login_request_from_request,
    ],
)
def test_a_body_that_is_neither_json_nor_a_form_is_415(reader) -> None:  # noqa: ANN001
    request = request_for(b"<x/>", content_type="text/xml")
    with pytest.raises(HTTPException) as raised:
        run(reader(request, SECRET))
    assert raised.value.status_code == 415
    assert "application/json or form" in raised.value.detail


@pytest.mark.parametrize(
    "reader",
    [
        ws.get_mfa_verify_request_from_request,
        ws.get_mfa_resend_request_from_request,
        ws.get_login_request_from_request,
        ws.get_password_reset_request_from_request,
    ],
)
def test_a_form_without_its_csrf_proof_is_refused_before_its_fields_are_read(
    reader,  # noqa: ANN001
) -> None:
    request = form({"code": "123456"}, good_csrf=False)
    with pytest.raises(HTTPException) as raised:
        run(reader(request, SECRET))
    assert raised.value.status_code == 403


@pytest.mark.parametrize(
    "reader",
    [
        ws.get_mfa_verify_request_from_request,
        ws.get_mfa_resend_request_from_request,
        ws.get_login_request_from_request,
        ws.get_password_reset_request_from_request,
    ],
)
def test_a_form_with_a_good_csrf_proof_and_bad_fields_is_a_validation_error(
    reader,  # noqa: ANN001
) -> None:
    with pytest.raises(RequestValidationError):
        run(reader(form({}), SECRET))


def test_a_reset_completion_form_that_does_not_match_or_is_not_valid_is_a_form_error() -> None:
    mismatch = form({"new_password": "a", "new_password_confirmation": "b", "reset_token": "t"})
    with pytest.raises(ws.BrowserFormValidationError) as raised:
        run(ws.get_password_reset_complete_request_from_request(mismatch, SECRET))
    assert str(raised.value) == "password_mismatch"
    # Matching, but the model refuses: with a token it is the password (empty) that is wrong,
    # without a token it is the whole form.
    for token, password, message in (
        ("tok", "", "invalid_password"),
        ("", "a", "invalid_reset_form"),
    ):
        bad = form(
            {"new_password": password, "new_password_confirmation": password, "reset_token": token}
        )
        with pytest.raises(ws.BrowserFormValidationError) as raised:
            run(ws.get_password_reset_complete_request_from_request(bad, SECRET))
        assert str(raised.value) == message
