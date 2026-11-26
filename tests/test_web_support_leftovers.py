# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""The web helpers' remaining refusals: the MyCarlos proof cookie and its check, a login payload, a
date that is not an ISO date, a request body of the wrong type or that fails its model (the form
requests), the activation form's kept date, and the client address behind a trusted proxy.
FAKE tokens and addresses only.
"""

import asyncio
from datetime import timedelta
from urllib.parse import urlencode

import pytest
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request
from starlette.responses import Response

from carlos_patient_portal import web_support as web
from carlos_patient_portal.auth import LoginResult
from carlos_patient_portal.models import MFA_DELIVERY_METHOD_EMAIL, MFA_DELIVERY_METHOD_SMS
from tests.support import development_settings, production_settings

SECRET = "p" * 32
TOKEN = "A" * 43  # the shape of a session token: 43 URL-safe characters


def make_request(
    *,
    content_type: str | None = None,
    body: bytes = b"",
    cookie: str | None = None,
) -> Request:
    headers = []
    if content_type is not None:
        headers.append((b"content-type", content_type.encode()))
    if cookie is not None:
        headers.append((b"cookie", cookie.encode()))

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/x",
            "headers": headers,
            "query_string": b"",
            "client": ("192.0.2.10", 5000),
            "server": ("testserver", 80),
            "scheme": "http",
            "http_version": "1.1",
        },
        receive,
    )


def form_request(fields: dict[str, str], *, csrf: bool = True, secret: str = SECRET) -> Request:
    token = web.create_csrf_token(secret)
    values = {**fields, **({web.CSRF_FORM_FIELD: token} if csrf else {})}
    return make_request(
        content_type="application/x-www-form-urlencoded",
        body=urlencode(values).encode(),
        cookie=f"{web.CSRF_COOKIE_NAME}={token}",
    )


# --------------------------------------------------------------------------------------------
# The MyCarlos proof cookie
# --------------------------------------------------------------------------------------------


def proof_cookie(response: Response) -> str:
    header = next(
        value.decode()
        for name, value in response.raw_headers
        if name == b"set-cookie" and web.PORTAL_MFA_PROOF_COOKIE_NAME.encode() in value
    )
    return header.split(";")[0].split("=", 1)[1]


def test_a_proof_is_issued_for_a_real_factor_and_session_and_never_by_email_in_production() -> None:
    development = development_settings()
    for factor in (MFA_DELIVERY_METHOD_SMS, MFA_DELIVERY_METHOD_EMAIL):
        response = Response()
        web.set_portal_mfa_proof_cookie(
            response, TOKEN, delivery_method=factor, proof_secret=SECRET, settings=development
        )
        assert proof_cookie(response).startswith(f"{factor}.")
    for refused, message in (
        ({"delivery_method": "pigeon"}, "unsupported MFA proof factor"),
        ({"delivery_method": "sms", "session_token": "short"}, "invalid session token"),
        ({"delivery_method": "sms", "session_token": TOKEN + "!"}, "invalid session token"),
    ):
        values = {"session_token": TOKEN, **refused}
        with pytest.raises(ValueError, match=message):
            web.set_portal_mfa_proof_cookie(
                Response(),
                values.pop("session_token"),
                proof_secret=SECRET,
                settings=development,
                **values,
            )
    with pytest.raises(ValueError, match="email is not an independent production MFA factor"):
        web.set_portal_mfa_proof_cookie(
            Response(),
            TOKEN,
            delivery_method="email",
            proof_secret=SECRET,
            settings=production_settings(),
        )
    response = Response()  # sms is fine in production, and the cookie is then Secure
    web.set_portal_mfa_proof_cookie(
        response, TOKEN, delivery_method="sms", proof_secret=SECRET, settings=production_settings()
    )
    assert "Secure" in str(response.raw_headers)


def test_a_proof_is_valid_only_with_the_session_it_was_made_for() -> None:
    def make(factor="sms", token=TOKEN, secret=SECRET) -> str:
        response = Response()
        web.set_portal_mfa_proof_cookie(
            response,
            token,
            delivery_method=factor,
            proof_secret=secret,
            settings=development_settings(),
        )
        return proof_cookie(response)

    def check(proof, token=TOKEN, *, allow_email=True, secret=SECRET) -> bool:
        return web.is_valid_portal_mfa_proof(
            proof, token, proof_secret=secret, allow_email=allow_email
        )

    sms, email = make("sms"), make("email")
    assert check(sms) and check(email)
    # A correct tag for a token that is not the shape of a session token is still refused.
    odd = "short"
    forged = f"sms.{web.hash_auth_token(SECRET, 'mycarlos-mfa-session-v1:sms', odd)}"
    assert not check(forged, odd)
    assert not check(email, allow_email=False) and check(sms, allow_email=False)
    # Another session, another secret, a missing or malformed token, a missing or malformed proof.
    assert not check(sms, "B" * 43) and not check(sms, secret="q" * 32)
    assert not check(sms, None) and not check(sms, "short")  # type: ignore[arg-type]
    assert not check(None) and not check("x" * 71) and not check("sms.nothex")
    assert not check("pigeon." + sms.split(".")[1])
    assert not check(
        sms.replace("sms", "email", 1)
    )  # a tag made for one factor, claimed as another


# --------------------------------------------------------------------------------------------
# A login payload, dates, a kept date
# --------------------------------------------------------------------------------------------


def test_a_login_payload_carries_a_session_token_only_when_there_is_one() -> None:
    settings = development_settings()
    signed_in = LoginResult(status="signed_in", account=None, session_token="the-token")  # type: ignore[arg-type]
    assert web.login_response_payload(signed_in, settings=settings) == {
        "status": "signed_in",
        "session_token": "the-token",
    }
    needs_code = LoginResult(status="mfa_required", account=None)  # type: ignore[arg-type]
    assert web.login_response_payload(needs_code, settings=settings) == {"status": "mfa_required"}


def test_an_optional_date_is_empty_or_exactly_year_month_day() -> None:
    assert web.parse_optional_email_password_date(None) is None
    assert web.parse_optional_email_password_date("   ") is None
    assert str(web.parse_optional_email_password_date(" 1980-05-20 ")) == "1980-05-20"
    for bad in ("1980-5-20", "19800520", "May 20 1980", "1980-05-2"):  # not ten characters
        with pytest.raises(ValueError, match="YYYY-MM-DD"):
            web.parse_optional_email_password_date(bad)
    # Ten characters that Python reads as a date (an ISO week date), but not as year-month-day.
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        web.parse_optional_email_password_date("1980-W20-1")
    for bad in ("1980/05/20", "1980-13-45"):  # ten characters that are not a date at all
        with pytest.raises(ValueError):
            web.parse_optional_email_password_date(bad)


def test_an_activation_form_made_before_the_three_date_boxes_shows_its_date_in_them() -> None:
    keep = web.activation_form_values_to_keep
    assert keep({"date_of_birth": ["1980-05-20"]}) == {
        "date_of_birth_day": "20",
        "date_of_birth_month": "5",
        "date_of_birth_year": "1980",
    }
    # A date that cannot be read is dropped, not shown or crashed on; so is one beside the boxes.
    assert keep({"date_of_birth": ["not a date"]}) == {}
    assert keep({"date_of_birth": ["1980-05-20"], "date_of_birth_year": ["1975"]}) == {
        "date_of_birth_year": "1975"
    }
    # Passwords are never kept.
    assert keep({"password": ["secret"], "username": ["fake.user"]}) == {"username": "fake.user"}


def test_a_logout_with_no_session_cookie_does_nothing_and_a_bad_one_is_not_an_error() -> None:
    class Untouched:
        def __getattr__(self, name):
            raise AssertionError("the database must not be used")

    web.logout_browser_session_cookie_token(
        Untouched(),
        session_token=None,
        session_token_secret=SECRET,
        idle_timeout=timedelta(minutes=30),
    )


# --------------------------------------------------------------------------------------------
# Request bodies: the wrong type, and a body its model refuses
# --------------------------------------------------------------------------------------------


def run(coroutine):
    return asyncio.run(coroutine)


def refused_with(status_code: int, coroutine) -> HTTPException:
    with pytest.raises(HTTPException) as refused:
        run(coroutine)
    assert refused.value.status_code == status_code
    return refused.value


def test_an_activation_that_is_not_json_is_refused_as_the_wrong_media_type() -> None:
    for content_type in (None, "text/plain", "application/x-www-form-urlencoded"):
        refused = refused_with(
            415, web.get_activation_request(make_request(content_type=content_type, body=b"{}"))
        )
        assert "application/json" in refused.detail


@pytest.mark.parametrize(
    ("function", "message"),
    [
        (web.get_mfa_verify_request_from_request, "MFA verification requires"),
        (web.get_mfa_resend_request_from_request, "MFA resend requires"),
        (web.get_login_request_from_request, "login requires"),
    ],
)
def test_a_form_route_takes_json_or_a_form_and_nothing_else(function, message) -> None:
    for content_type in (None, "text/plain", "multipart/form-data; boundary=x"):
        refused = refused_with(
            415, function(make_request(content_type=content_type, body=b"x=1"), SECRET)
        )
        assert message in refused.detail and "application/json or form" in refused.detail


@pytest.mark.parametrize(
    "function",
    [
        web.get_mfa_verify_request_from_request,
        web.get_mfa_resend_request_from_request,
        web.get_password_reset_request_from_request,
        web.get_login_request_from_request,
    ],
)
def test_a_form_that_fails_its_model_is_a_validation_error_not_a_crash(function) -> None:
    with pytest.raises(RequestValidationError) as refused:
        run(function(form_request({"unrelated": "1"}), SECRET))
    assert refused.value.errors()  # it says which fields, and nothing about their values


def test_a_password_reset_form_that_fails_its_model_names_the_reason_without_the_password() -> None:
    def submit(fields):
        return run(
            web.get_password_reset_complete_request_from_request(form_request(fields), SECRET)
        )

    with pytest.raises(web.BrowserFormValidationError) as with_token:
        submit(
            {
                "reset_token": "t" * 43,
                "new_password": "",
                "new_password_confirmation": "",
            }
        )
    assert str(with_token.value) == "invalid_password"
    assert with_token.value.safe_form_values == {"reset_token": "t" * 43}
    with pytest.raises(web.BrowserFormValidationError) as no_token:
        submit({"new_password": "", "new_password_confirmation": ""})
    assert str(no_token.value) == "invalid_reset_form"
    with pytest.raises(web.BrowserFormValidationError) as mismatch:
        submit({"reset_token": "t", "new_password": "a", "new_password_confirmation": "b"})
    assert str(mismatch.value) == "password_mismatch"
    assert "new_password" not in mismatch.value.safe_form_values


# --------------------------------------------------------------------------------------------
# The client address behind a proxy
# --------------------------------------------------------------------------------------------


def test_forwarded_addresses_are_read_from_the_right_and_only_from_a_trusted_peer() -> None:
    def parse(value, *, peer="10.0.0.1", cidrs="10.0.0.0/8", header="x-forwarded-for"):
        return web.parse_trusted_client_ip_header(
            header, value, peer_address=peer, trusted_proxy_cidrs=cidrs
        )

    assert parse("203.0.113.9") == "203.0.113.9"
    # The rightmost address that is not one of the trusted proxies is the client.
    assert parse("198.51.100.7, 203.0.113.9, 10.1.2.3") == "203.0.113.9"
    # Every address a proxy: the leftmost is the best answer there is.
    assert parse("10.9.9.9, 10.1.2.3") == "10.9.9.9"
    assert parse("203.0.113.9", peer="192.0.2.1") is None  # peer not trusted
    assert parse("not-an-ip") is None and parse(" , ") is None and parse("") is None
    assert parse("203.0.113.9", peer="not-an-ip") is None
    assert parse("203.0.113.9", cidrs="not-a-network") is None
    assert parse("203.0.113.9", header="x-real-ip") == "203.0.113.9"
    assert parse("203.0.113.9, 198.51.100.1", header="x-real-ip") is None
