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

"""Shared HTTP plumbing for the portal's route modules.

CSRF tokens and cookies, session cookies, request-body parsing and size limits, path and
content-type predicates, response payload shapes, and the Jinja template environment with the
context builders each public page needs.

Extracted from `main.py` so the route modules can depend on this without importing the application
module that composes them, which would be circular. Nothing here registers a route, opens a
database session, or performs I/O beyond rendering a template.
"""

import json
import re
from collections.abc import Callable, Mapping
from datetime import date, timedelta
from hashlib import sha256
from hmac import new as new_hmac
from ipaddress import ip_address, ip_network
from pathlib import Path as FilePath
from secrets import compare_digest, token_urlsafe
from time import time
from typing import TypeVar
from urllib.parse import parse_qs, urlsplit

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session
from starlette.responses import Response
from starlette.routing import Match, Mount

from carlos_patient_portal.audit import UNKNOWN_CLIENT_REFERENCE
from carlos_patient_portal.auth import (
    AuthenticatedPortalSession,
    LoginResult,
    MfaChallengeDelivery,
    PortalSessionInvalidError,
    hash_auth_token,
    logout_patient_session,
)
from carlos_patient_portal.config import DEFAULT_SERVICE_NAME, Settings
from carlos_patient_portal.i18n import (
    LOCALE_COOKIE_MAX_AGE_SECONDS,
    LOCALE_COOKIE_NAME,
    plural_text,
    portal_text,
    resolve_locale,
    supported_locale_options,
)
from carlos_patient_portal.interop import build_fhir_r4_operation_outcome
from carlos_patient_portal.models import (
    MFA_DELIVERY_METHOD_EMAIL,
    MFA_DELIVERY_METHOD_SMS,
    PatientPortalAccount,
    PatientPortalInvite,
    PatientPortalUnlockSecret,
)
from carlos_patient_portal.routes.fhir import fhir_json_response
from carlos_patient_portal.schemas import (
    ActivationRequest,
    InviteCreateRequest,
    LoginRequest,
    MfaResendRequest,
    MfaVerifyRequest,
    PasswordResetCompleteRequest,
    PasswordResetRequest,
)
from carlos_patient_portal.view_models import (
    EmailPasswordDashboardViewModel,
    MessagesViewModel,
    MyCarlosViewModel,
)

PACKAGE_DIR = FilePath(__file__).resolve().parent


RequestModel = TypeVar("RequestModel", bound=BaseModel)


# Semgrep's direct-use-of-jinja2 rule targets Flask, where it advises render_template() over a
# hand-built Environment because Flask's own default is autoescape=False. This is Starlette's
# Jinja2Templates — the framework-supplied renderer — and autoescape is set explicitly, so the
# escaping the rule protects is on. Marked inline on both lines because the rule is Semgrep PRO
# and cannot be run locally to confirm which line the match anchors to.
templates = Jinja2Templates(  # nosemgrep: direct-use-of-jinja2 -- see comment above
    env=Environment(  # nosemgrep: direct-use-of-jinja2 -- see comment above
        loader=FileSystemLoader(str(PACKAGE_DIR / "templates")),
        autoescape=True,
    )
)


CONTENT_SECURITY_POLICY = (
    "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
    "object-src 'none'"
)


FHIR_PATH_PREFIX = "/fhir/"


PORTAL_ROOT_PATH = "/portal"
JSON_MEDIA_TYPE = "application/json"


SERVICE_UNAVAILABLE_DETAIL = "service temporarily unavailable"


AUTHENTICATION_REQUIRED_DETAIL = "authentication required"


# Shared by login, resend, and activation so every JSON surface stays equally generic; the browser
# equivalents come from the locale catalog.
MFA_DELIVERY_UNAVAILABLE_DETAIL = "MFA delivery method is unavailable"


NOT_FOUND_DETAIL = "not found"


INVALID_CSRF_DETAIL = "invalid CSRF token"


ACCOUNT_LOCKED_DETAIL = "account access is locked; contact the clinic for help"


MFA_VERIFICATION_FAILED_DETAIL = "MFA could not be verified"


PASSWORD_RESET_COMPLETE_TEMPLATE = "password_reset_complete.jinja"


EMAIL_CHANGE_TEMPLATE = "email_change_complete.jinja"


ACTIVATION_TEMPLATE = "activate.jinja"


AUTH_LOGOUT_RESPONSES = {
    status.HTTP_401_UNAUTHORIZED: {"description": "Authentication is required."},
}


PORTAL_LOGOUT_RESPONSES = {
    status.HTTP_403_FORBIDDEN: {"description": "The CSRF token is invalid."},
}


DEV_ADMIN_COMMON_RESPONSES = {
    status.HTTP_400_BAD_REQUEST: {"description": "The staff actor is invalid."},
    status.HTTP_404_NOT_FOUND: {
        "description": "The endpoint is unavailable or the resource was not found."
    },
}


DEV_ADMIN_CONFLICT_RESPONSES = {
    **DEV_ADMIN_COMMON_RESPONSES,
    status.HTTP_409_CONFLICT: {"description": "The requested state transition conflicts."},
}


SECURITY_HEADERS = {
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


NO_STORE_PATHS = {"/"}


MAX_FORM_BODY_BYTES = 16 * 1024


MAX_JSON_BODY_BYTES = 16 * 1024


MAX_FORM_FIELD_COUNT = 20


DEV_ADMIN_ACTOR_HEADER = "X-CARLOS-Staff-Actor"


CSRF_COOKIE_NAME = "carlos_portal_csrf"


CSRF_COOKIE_PATH = "/auth"


CSRF_FORM_FIELD = "csrf_token"


CSRF_TOKEN_TTL_SECONDS = 60 * 60


CSRF_FUTURE_SKEW_SECONDS = 60


PORTAL_SESSION_COOKIE_NAME = "carlos_portal_session"
PORTAL_MFA_PROOF_COOKIE_NAME = "carlos_portal_mfa_proof"


PORTAL_SESSION_COOKIE_PATH = PORTAL_ROOT_PATH


PORTAL_MODULES = (
    {"slug": "dashboard", "label_key": "dashboard", "route_name": "portal_dashboard"},
    {"slug": "account", "label_key": "account", "route_name": "portal_account"},
    {
        "slug": "email-passwords",
        "label_key": "email_passwords",
        "route_name": "portal_email_passwords",
    },
    {"slug": "messages", "label_key": "messages", "route_name": "portal_messages"},
    {"slug": "help", "label_key": "help", "route_name": "portal_help"},
)


ACCOUNT_NOTICE_MESSAGE_KEYS = {
    "mycarlos-device-removed": "mycarlos_removed",
    "contact-confirmation-required": "account_status_contact_confirmation_required",
    "contact-updated": "account_status_contact_updated",
    "contact-updated-notice-failed": "account_status_contact_notice_failed",
    "email-confirmation-required": "account_status_email_confirmation_required",
    "email-confirmation-notice-failed": "account_status_email_confirmation_notice_failed",
    "phone-confirmation-required": "account_status_phone_confirmation_required",
    "phone-confirmation-invalid": "account_status_phone_confirmation_invalid",
    "phone-confirmation-notice-failed": "account_status_phone_confirmation_notice_failed",
    "phone-confirmation-rate-limited": "account_status_phone_confirmation_rate_limited",
    "mfa-updated": "account_status_mfa_updated",
    "no-change": "account_status_no_change",
    "password-updated": "account_status_password_updated",
}


VALIDATION_ERROR_PRIVATE_FIELDS = {"ctx", "input"}


# Backslash plus everything at or below U+0020 and the C1 range. Browsers strip TAB/LF/CR while
# parsing a URL and fold backslashes to slashes, so any of these can turn a path that looks local
# into an authority once the browser is done with it.
UNSAFE_REDIRECT_CHARACTER_PATTERN = re.compile(r"[\\\x00-\x20\x7f-\x9f]")


class BrowserFormValidationError(Exception):
    """Raised when a browser form cannot be validated without exposing field details."""

    def __init__(
        self,
        message: str,
        *,
        safe_form_values: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.safe_form_values = safe_form_values or {}


def wants_html_response(path: str) -> bool:
    """Whether `path` is a patient-facing path, whose errors may be a page rather than JSON.

    The path half of `wants_html_error_page`, which also looks at what the caller sent and asked
    for. Machine surfaces keep their JSON/FHIR shapes: an API client parsing `{"detail": ...}`
    must not start receiving HTML.
    """
    return not (
        path.startswith("/api/")
        or path.startswith(FHIR_PATH_PREFIX)
        or path.startswith("/internal/")
        or path.startswith("/dev/admin/")
    )


def wants_html_error_page(request: Request) -> bool:
    """Whether an error answering this request should be a page rather than a JSON body.

    Path alone is the wrong discriminator: /auth/activate serves a browser form *and* accepts a
    JSON body, and /auth/session and /auth/logout serve bearer clients. A caller that sent JSON,
    asked only for JSON, or authenticated with a bearer token gets JSON back; a browser form post
    or a navigation gets the page. HEAD has no body to read either way.
    """
    headers = request.headers
    declared_json = JSON_MEDIA_TYPE in (headers.get("content-type") or "").lower()
    accept = (headers.get("accept") or "").lower()
    asked_for_json = JSON_MEDIA_TYPE in accept and "text/html" not in accept
    bearer_client = (headers.get("authorization") or "").lower().startswith("bearer ")
    return (
        wants_html_response(request.url.path)
        and not (declared_json or asked_for_json or bearer_client)
        and request.method != "HEAD"
    )


def service_notice_response(
    request: Request,
    *,
    settings: Settings,
    status_code: int,
    heading_key: str,
    message_key: str,
    retry_after_seconds: int | None,
) -> Response:
    """Render the browser-facing page for a failed request or a throttled or unavailable portal."""
    locale = request_locale(request)
    text = portal_text(locale)
    return templates.TemplateResponse(
        request=request,
        name="service_notice.jinja",
        context={
            "clinic_name": settings.clinic_name,
            "service_name": displayed_service_name(settings, text),
            "source_code_url": settings.source_code_url,
            "locale": locale,
            "locale_switch_target": locale_switch_targets(request),
            "supported_locales": supported_locale_options(locale),
            "text": text,
            "notice_heading": text[heading_key],
            "notice_message": text[message_key],
        },
        status_code=status_code,
        headers=(
            {"Retry-After": str(retry_after_seconds)} if retry_after_seconds is not None else None
        ),
    )


def is_safe_local_redirect(destination: str) -> bool:
    """Whether `destination` is a same-origin path this app may redirect a patient to.

    Deliberately an allowlist of shape rather than a blocklist of known-bad prefixes. An earlier
    version here checked only for a leading `//` after folding backslashes, which let
    `/<TAB>/evil.example` through: browsers strip TAB, LF, and CR while parsing a URL, so that
    value reaches the network stack as `//evil.example` and leaves the origin. A leading space
    behaves the same way in some parsers.

    So: the value must start with a single `/`, contain no backslash and no character at or below
    U+0020 or in the C1 range, and `urlsplit` must see neither a scheme nor an authority. Paths
    this application generates never contain any of those, so nothing legitimate is lost.
    """
    if not destination.startswith("/") or destination.startswith("//"):
        return False
    if UNSAFE_REDIRECT_CHARACTER_PATTERN.search(destination) is not None:
        return False
    parsed_destination = urlsplit(destination)
    return not parsed_destination.scheme and not parsed_destination.netloc


# Where a route that changes the language mid-request (the MFA page's language form) records the
# new choice, so the page it renders is already in that language: the cookie it sets only arrives
# with the next request.
REQUEST_LOCALE_STATE_ATTRIBUTE = "portal_locale"


def request_locale(request: Request) -> str:
    """The locale to render this request in."""
    chosen_this_request = getattr(
        getattr(request, "state", None), REQUEST_LOCALE_STATE_ATTRIBUTE, None
    )
    if chosen_this_request is not None:
        return chosen_this_request
    return resolve_locale(
        cookie_value=request.cookies.get(LOCALE_COOKIE_NAME),
        accept_language=request.headers.get("Accept-Language"),
    )


def set_locale_cookie(response: Response, locale: str, *, settings: Settings) -> None:
    """Remember a display-language choice for a year.

    HttpOnly even though this is only a display preference: nothing on the page reads it from
    script, so withholding it from JavaScript costs nothing and keeps every cookie the portal sets
    consistent.
    """
    response.set_cookie(
        LOCALE_COOKIE_NAME,
        locale,
        max_age=LOCALE_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=not settings.is_development,
        path="/",
    )


def displayed_service_name(settings: Settings, text: Mapping[str, str]) -> str:
    """The product name a page shows: translated when it is the default, else as configured.

    A name the clinic configured is its own and is never translated; only the stock
    "CARLOS Patient Portal" follows the patient's language.
    """
    if settings.service_name == DEFAULT_SERVICE_NAME:
        return text["service_name_default"]
    return settings.service_name


# GET pages that only work with the token from an emailed link, which rides in the URL fragment and
# never reaches the server. A page answering the form they post must not send the patient back to
# them: without the token they are an empty form that cannot succeed.
LINK_TOKEN_PAGE_ROUTE_NAMES = frozenset(
    {"password_reset_complete_page", "email_change_confirm_page"}
)


def _get_route_name_for_path(request: Request) -> str | None:
    """The name of the page route that answers a GET at this request's path, or None.

    A mount (the static files) matches every path under its prefix, but a missing file there is
    a 404, not a page to come back to, so mounts do not count.
    """
    scope = getattr(request, "scope", None) or {}
    app = scope.get("app")
    if app is None:
        return None
    # Matched as the application sees the path: inside the static mount, root_path has grown by
    # the mount's own prefix, which would let another route match the rest of the path.
    app_root_path = scope.get("app_root_path", scope.get("root_path", ""))
    get_scope = {**scope, "method": "GET", "root_path": app_root_path}
    for route in app.router.routes:
        if isinstance(route, Mount):
            continue
        if route.matches(get_scope)[0] is Match.FULL:
            return getattr(route, "name", None) or ""
    return None


def locale_switch_targets(request: Request, *, get_fallback: str | None = None) -> str:
    """The path a language button should return the patient to.

    Query string included so a filtered dashboard survives a language change, but never the
    fragment — reset tokens live there and must not travel in a redirect target.

    The language link redirects with a GET, and not every page is reachable that way at its own
    path: a failed sign-in is rendered at POST /auth/login, a password change at POST
    /portal/account/password, and a 404 or 405 page at a path with no GET page. Those return the
    patient to `get_fallback` (a signed-in page passes its module's own page), else to the front
    page. So does a page answering the form of an emailed-link page (LINK_TOKEN_PAGE_ROUTE_NAMES).
    The MFA page has its own POST form instead; see /auth/mfa/language.
    """
    scope = getattr(request, "scope", {})
    # Inside a mount (a 404 under /static/) root_path includes the mount; app_root_path does not.
    root_path = scope.get("app_root_path", scope.get("root_path", "")).rstrip("/")
    is_get = getattr(request, "method", "GET") in ("GET", "HEAD")
    get_route_name = _get_route_name_for_path(request)
    if get_route_name is None or (not is_get and get_route_name in LINK_TOKEN_PAGE_ROUTE_NAMES):
        destination = get_fallback or f"{root_path}/"
    else:
        destination = f"{root_path}{request.url.path}"
        if request.url.query and is_get:
            destination = f"{destination}?{request.url.query}"
    return destination if is_safe_local_redirect(destination) else "/"


def create_csrf_token(secret: str) -> str:
    issued_at = str(int(time()))
    nonce = token_urlsafe(24)
    message = f"{issued_at}.{nonce}"
    signature = sign_csrf_token(message, secret)
    return f"{message}.{signature}"


def sign_csrf_token(message: str, secret: str) -> str:
    # The same session secret also keys session tokens, MFA codes, and reset tokens, so the signed
    # message carries a purpose prefix exactly like hash_auth_token/hash_mfa_code. Without it, the
    # domain separation between the secret's four roles would rest on the input formats happening
    # never to collide rather than on anything structural.
    return new_hmac(
        secret.encode("utf-8"),
        f"csrf_token:{message}".encode(),
        sha256,
    ).hexdigest()


def constant_time_text_equals(left: str, right: str) -> bool:
    """Compare header/form text without `compare_digest` rejecting non-ASCII input."""
    return compare_digest(
        left.encode("utf-8", "surrogateescape"),
        right.encode("utf-8", "surrogateescape"),
    )


def is_valid_csrf_token(token: str | None, secret: str) -> bool:
    if token is None:
        return False

    issued_at_value, separator, signed_part = token.partition(".")
    nonce, separator_2, supplied_signature = signed_part.partition(".")
    if not separator or not separator_2 or not nonce or not supplied_signature:
        return False

    try:
        issued_at = int(issued_at_value)
    except ValueError:
        return False

    current_time = int(time())
    if issued_at > current_time + CSRF_FUTURE_SKEW_SECONDS:
        return False
    if current_time - issued_at > CSRF_TOKEN_TTL_SECONDS:
        return False

    expected_signature = sign_csrf_token(f"{issued_at_value}.{nonce}", secret)
    return constant_time_text_equals(supplied_signature, expected_signature)


def is_valid_csrf_submission(
    form_token: str | None,
    cookie_token: str | None,
    secret: str,
) -> bool:
    if form_token is None or cookie_token is None:
        return False
    if not constant_time_text_equals(form_token, cookie_token):
        return False
    return is_valid_csrf_token(form_token, secret)


def set_csrf_cookie(
    response: Response,
    csrf_token: str,
    *,
    settings: Settings,
    path: str,
) -> None:
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf_token,
        httponly=True,
        max_age=CSRF_TOKEN_TTL_SECONDS,
        path=deployment_cookie_path(settings, path),
        samesite="strict",
        secure=not settings.is_development,
    )


def set_portal_session_cookie(
    response: Response,
    session_cookie_value: str,
    *,
    settings: Settings,
) -> None:
    # set_cookie appends rather than replaces, so this composes with the CSRF cookie written on the
    # same response; there is no need to build the header by hand.
    response.set_cookie(
        PORTAL_SESSION_COOKIE_NAME,
        session_cookie_value,
        httponly=True,
        max_age=settings.session_ttl_seconds,
        path=deployment_cookie_path(settings, PORTAL_SESSION_COOKIE_PATH),
        samesite="strict",
        secure=not settings.is_development,
    )
    if settings.mycarlos_delivery_enabled:
        clear_portal_mfa_proof_cookie(response, settings=settings)


def set_portal_mfa_proof_cookie(
    response: Response,
    session_token: str,
    *,
    delivery_method: str,
    proof_secret: str,
    settings: Settings,
) -> None:
    """Called only after the browser's actual MFA verification succeeded."""
    if delivery_method not in {MFA_DELIVERY_METHOD_SMS, MFA_DELIVERY_METHOD_EMAIL}:
        raise ValueError("unsupported MFA proof factor")
    if delivery_method == MFA_DELIVERY_METHOD_EMAIL and not settings.is_development:
        raise ValueError("email is not an independent production MFA factor")
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", session_token) is None:
        raise ValueError("invalid session token for MFA proof")
    tag = hash_auth_token(proof_secret, f"mycarlos-mfa-session-v1:{delivery_method}", session_token)
    response.set_cookie(
        PORTAL_MFA_PROOF_COOKIE_NAME,
        f"{delivery_method}.{tag}",
        httponly=True,
        max_age=settings.session_ttl_seconds,
        path=deployment_cookie_path(settings, PORTAL_SESSION_COOKIE_PATH),
        samesite="strict",
        secure=not settings.is_development,
    )


def is_valid_portal_mfa_proof(
    proof: str | None,
    session_token: str | None,
    *,
    proof_secret: str,
    allow_email: bool,
) -> bool:
    """A proof alone never authenticates: the caller must also check the live session."""
    if session_token is None or re.fullmatch(r"[A-Za-z0-9_-]{43}", session_token) is None:
        return False
    if proof is None or len(proof) > 70:
        return False
    match = re.fullmatch(r"(sms|email)\.([0-9a-f]{64})", proof)
    if match is None or (match[1] == MFA_DELIVERY_METHOD_EMAIL and not allow_email):
        return False
    expected = hash_auth_token(proof_secret, f"mycarlos-mfa-session-v1:{match[1]}", session_token)
    return compare_digest(match[2], expected)


def clear_portal_mfa_proof_cookie(response: Response, *, settings: Settings) -> None:
    response.delete_cookie(
        PORTAL_MFA_PROOF_COOKIE_NAME,
        path=deployment_cookie_path(settings, PORTAL_SESSION_COOKIE_PATH),
        secure=not settings.is_development,
        httponly=True,
        samesite="strict",
    )


def clear_portal_session_cookie(response: Response, *, settings: Settings) -> None:
    response.delete_cookie(
        PORTAL_SESSION_COOKIE_NAME,
        path=deployment_cookie_path(settings, PORTAL_SESSION_COOKIE_PATH),
        secure=not settings.is_development,
        httponly=True,
        samesite="strict",
    )
    if settings.mycarlos_delivery_enabled:
        clear_portal_mfa_proof_cookie(response, settings=settings)


def deployment_cookie_path(settings: Settings, application_path: str) -> str:
    """Translate an application route path to the browser-visible deployment path."""
    deployment_path = f"{settings.root_path}{application_path}"
    return deployment_path or "/"


def logout_browser_session_cookie_token(
    session: Session,
    *,
    session_token: str | None,
    session_token_secret: str,
    idle_timeout: timedelta,
) -> None:
    if session_token is None:
        return
    try:
        logout_patient_session(
            session,
            session_token=session_token,
            session_token_secret=session_token_secret,
            idle_timeout=idle_timeout,
        )
    except (PortalSessionInvalidError, ValueError):
        return


def is_portal_path(path: str) -> bool:
    return path == PORTAL_SESSION_COOKIE_PATH or path.startswith(f"{PORTAL_SESSION_COOKIE_PATH}/")


MYCARLOS_API_PREFIX = "/api/mycarlos/"
MYCARLOS_LINK_PATH = "/api/mycarlos/link"


def is_patient_runtime_path(path: str) -> bool:
    return (
        path == "/"
        or path.startswith("/auth/")
        or path.startswith("/api/patient/")
        or path.startswith(FHIR_PATH_PREFIX)
        or is_portal_path(path)
    )


def is_rate_limited_path(path: str) -> bool:
    # /internal/carlos/** is throttled because every failed request there writes an audit row in its
    # own session, so an unauthenticated caller can force unbounded inserts into a table with a
    # 25-year retention floor and bury the real staff-action failures. The reference proxy restricts
    # the prefix by source address, but the application must not depend on the edge being configured
    # correctly for that.
    #
    # The probe endpoints (/internal/health/db, /internal/readiness, /internal/metrics) are
    # deliberately excluded: they are polled on a fixed interval by orchestrators and throttling
    # them would turn a healthy service into a failing liveness check.
    #
    # /api/mycarlos/** is the myCarlos device API (carlos-portal#41). It answers callers with no
    # browser session, and its link route takes a guessable one-time code.
    return (
        is_patient_runtime_path(path)
        or path.startswith("/internal/carlos/")
        or path.startswith(MYCARLOS_API_PREFIX)
    )


def is_maintenance_exempt_path(path: str) -> bool:
    return path in {
        "/health",
        "/internal/health/db",
        "/internal/readiness",
        "/internal/metrics",
    }


def is_json_request(request: Request) -> bool:
    return request.headers.get("content-type", "").partition(";")[0].strip().lower() == (
        JSON_MEDIA_TYPE
    )


def is_urlencoded_form_request(request: Request) -> bool:
    return request.headers.get("content-type", "").partition(";")[0].strip().lower() == (
        "application/x-www-form-urlencoded"
    )


def sanitized_validation_errors(exc: RequestValidationError) -> list[dict[str, object]]:
    return [
        {
            field_name: field_value
            for field_name, field_value in error.items()
            if field_name not in VALIDATION_ERROR_PRIVATE_FIELDS
        }
        for error in exc.errors()
    ]


def invite_response_payload(
    invite: PatientPortalInvite,
    invite_token: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": invite.id,
        "clinic_id": invite.clinic_id,
        "demographic_no": invite.demographic_no,
        "status": invite.status,
        "created_by": invite.created_by,
        "created_at": invite.created_at,
        "updated_at": invite.updated_at,
        "issued_count": invite.sent_count,
        "last_issued_at": invite.last_sent_at,
        "last_issued_by": invite.last_sent_by,
        "expires_at": invite.expires_at,
        "revoked_at": invite.revoked_at,
        "revoked_by": invite.revoked_by,
        "has_identity_proof": all(
            (
                invite.proof_email_hash,
                invite.proof_date_of_birth_hash,
                invite.proof_health_card_hash,
                invite.proof_salt,
                invite.proof_hash_version,
            )
        ),
        "accepted_at": invite.accepted_at,
        "accepted_account_id": invite.accepted_account_id,
        "supersedes_invite_id": invite.supersedes_invite_id,
    }
    if invite_token is not None:
        payload["invite_token"] = invite_token
    return payload


def account_admin_response_payload(account: PatientPortalAccount) -> dict[str, object]:
    return {
        "id": account.id,
        "clinic_id": account.clinic_id,
        "demographic_no": account.demographic_no,
        "username": account.username,
        "email": account.email,
        "locked_at": account.locked_at,
        "force_password_reset": account.force_password_reset,
        "failed_login_count": account.failed_login_count,
    }


def email_password_record_response_payload(
    unlock_secret: PatientPortalUnlockSecret,
) -> dict[str, object]:
    return {
        "id": unlock_secret.id,
        "label": unlock_secret.label,
        "source_reference": unlock_secret.source_reference,
        "created_at": unlock_secret.created_at,
        "updated_at": unlock_secret.updated_at,
        "last_viewed_at": unlock_secret.last_viewed_at,
    }


def email_password_secret_response_payload(
    unlock_secret: PatientPortalUnlockSecret,
    *,
    passphrase: str,
) -> dict[str, object]:
    return {
        **email_password_record_response_payload(unlock_secret),
        "passphrase": passphrase,
    }


def fhir_operation_outcome_response(
    *,
    status_code: int,
    code: str,
    diagnostics: str,
) -> JSONResponse:
    return fhir_json_response(
        build_fhir_r4_operation_outcome(code=code, diagnostics=diagnostics),
        status_code=status_code,
    )


def mfa_challenge_response_payload(
    delivery: MfaChallengeDelivery,
    *,
    settings: Settings,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": "mfa_required",
        "mfa_challenge_token": delivery.challenge_token,
        "mfa_delivery_method": delivery.delivery_method,
    }
    if settings.is_development:
        payload["development_mfa_code"] = delivery.code
    return payload


def login_response_payload(
    result: LoginResult,
    *,
    settings: Settings,
) -> dict[str, object]:
    payload: dict[str, object] = {"status": result.status}
    if result.session_token is not None:
        payload["session_token"] = result.session_token
    if result.mfa_challenge is not None:
        payload.update(mfa_challenge_response_payload(result.mfa_challenge, settings=settings))
    return payload


def password_reset_request_response_payload(
    reset_token: str | None,
    *,
    settings: Settings,
) -> dict[str, object]:
    payload: dict[str, object] = {"status": "reset_requested"}
    if settings.is_development and reset_token is not None:
        payload["development_reset_token"] = reset_token
    return payload


def auth_error_response(
    *,
    is_browser_form: bool,
    request: Request,
    render_index_response: Callable[..., Response],
    status_code: int,
    browser_message: str,
    json_content: dict[str, object],
    headers: dict[str, str] | None = None,
) -> Response:
    if is_browser_form:
        response = render_index_response(
            request,
            status_code=status_code,
            error_message=browser_message,
        )
        if headers:
            response.headers.update(headers)
        return response
    return JSONResponse(status_code=status_code, content=json_content, headers=headers)


def index_template_context(
    request: Request,
    *,
    settings: Settings,
    csrf_token: str,
    error_message: str | None = None,
) -> dict[str, object]:
    locale = request_locale(request)
    text = portal_text(locale)
    return {
        "request": request,
        "locale": locale,
        "clinic_name": settings.clinic_name,
        "csrf_token": csrf_token,
        "error_message": error_message,
        "service_name": displayed_service_name(settings, text),
        "source_code_url": settings.source_code_url,
        "supported_locales": supported_locale_options(locale),
        "locale_switch_target": locale_switch_targets(request),
        "text": text,
    }


def public_auth_template_context(
    request: Request,
    *,
    settings: Settings,
    csrf_token: str,
    error_message: str | None = None,
    notice_message: str | None = None,
    form_values: dict[str, str] | None = None,
    sms_mfa_available: bool | None = None,
    email_mfa_available: bool | None = None,
    reset_token: str | None = None,
    development_reset_url: str | None = None,
    result_heading: str | None = None,
    result_message: str | None = None,
) -> dict[str, object]:
    # Declared explicitly rather than as **extra_context: these five keys are read by individual
    # public templates, and a kwargs bag let a caller typo one into silence.
    locale = request_locale(request)
    text = portal_text(locale)
    return {
        "request": request,
        "locale": locale,
        "clinic_name": settings.clinic_name,
        "csrf_token": csrf_token,
        "error_message": error_message,
        "form_values": form_values or {},
        "notice_message": notice_message,
        "service_name": displayed_service_name(settings, text),
        "source_code_url": settings.source_code_url,
        "supported_locales": supported_locale_options(locale),
        "locale_switch_target": locale_switch_targets(request),
        "text": text,
        "sms_mfa_available": sms_mfa_available,
        "email_mfa_available": (
            settings.is_development if email_mfa_available is None else email_mfa_available
        ),
        "reset_token": reset_token,
        "development_reset_url": development_reset_url,
        "result_heading": result_heading,
        "result_message": result_message,
    }


def render_public_auth_template(
    request: Request,
    *,
    settings: Settings,
    csrf_secret: str,
    template_name: str,
    status_code: int = status.HTTP_200_OK,
    error_message: str | None = None,
    notice_message: str | None = None,
    form_values: dict[str, str] | None = None,
    sms_mfa_available: bool | None = None,
    reset_token: str | None = None,
    development_reset_url: str | None = None,
    result_heading: str | None = None,
    result_message: str | None = None,
) -> Response:
    csrf_token = create_csrf_token(csrf_secret)
    response = templates.TemplateResponse(
        request=request,
        name=template_name,
        context=public_auth_template_context(
            request,
            settings=settings,
            csrf_token=csrf_token,
            error_message=error_message,
            notice_message=notice_message,
            form_values=form_values,
            sms_mfa_available=sms_mfa_available,
            reset_token=reset_token,
            development_reset_url=development_reset_url,
            result_heading=result_heading,
            result_message=result_message,
        ),
        status_code=status_code,
    )
    set_csrf_cookie(response, csrf_token, settings=settings, path=CSRF_COOKIE_PATH)
    return response


def mfa_template_context(
    request: Request,
    *,
    settings: Settings,
    delivery: MfaChallengeDelivery,
    csrf_token: str,
    error_message: str | None = None,
    notice_message: str | None = None,
) -> dict[str, object]:
    is_email = delivery.delivery_method == MFA_DELIVERY_METHOD_EMAIL
    locale = request_locale(request)
    text = portal_text(locale)
    return {
        "request": request,
        "locale": locale,
        "clinic_name": settings.clinic_name,
        "csrf_token": csrf_token,
        "development_mfa_code": (
            delivery.code if settings.is_development and delivery.code else None
        ),
        "error_message": error_message,
        "notice_message": notice_message,
        "mfa_code_sent_message": mfa_code_sent_message(delivery, text),
        "mfa_challenge_token": delivery.challenge_token,
        "mfa_email_available": (MFA_DELIVERY_METHOD_EMAIL in delivery.available_delivery_methods),
        "mfa_email_selected": is_email,
        "mfa_rate_limit_message": (text["email_codes_rate"] if is_email else text["mfa_sms_rate"]),
        "mfa_sms_available": (MFA_DELIVERY_METHOD_SMS in delivery.available_delivery_methods),
        "mfa_sms_selected": not is_email,
        "service_name": displayed_service_name(settings, text),
        "source_code_url": settings.source_code_url,
        # The MFA page is only ever rendered in answer to a POST and its challenge token lives in
        # the form, so its language buttons are small POST forms to /auth/mfa/language rather
        # than the GET links the other pages use; a GET link would drop the sign-in.
        "supported_locales": supported_locale_options(locale),
        "text": text,
    }


def mask_mfa_destination(delivery: MfaChallengeDelivery) -> str | None:
    """The code's destination with most of it hidden, or None when it cannot be masked safely."""
    if delivery.delivery_method == MFA_DELIVERY_METHOD_EMAIL:
        local_part, separator, domain = delivery.destination.partition("@")
        if not separator:
            return None
        visible_prefix = local_part[:2] if len(local_part) > 1 else local_part[:1]
        return visible_prefix + "***@" + domain

    digits = "".join(character for character in delivery.destination if character.isdigit())
    if len(digits) < 4:
        return None
    return f"***-***-{digits[-4:]}"


def mfa_code_sent_message(delivery: MfaChallengeDelivery, text: Mapping[str, str]) -> str:
    """The MFA page's "Code sent to … by …" line: one translated sentence per delivery method.

    One key per method (and an unmasked variant) rather than a method code spliced into a
    shared sentence, because "by email" and "by SMS" are grammar, not a word to substitute.
    """
    method = "email" if delivery.delivery_method == MFA_DELIVERY_METHOD_EMAIL else "sms"
    masked_destination = mask_mfa_destination(delivery)
    if masked_destination is None:
        return text[f"mfa_code_sent_{method}_unmasked"]
    return text[f"mfa_code_sent_{method}"].format(destination=masked_destination)


def portal_modules(
    request: Request,
    active_module: str,
    text: dict[str, str],
    *,
    mycarlos_enabled: bool = False,
) -> tuple[dict[str, object], ...]:
    modules = PORTAL_MODULES
    if mycarlos_enabled:
        modules += (
            {"slug": "mycarlos", "label_key": "mycarlos_link", "route_name": "portal_mycarlos"},
        )
    return tuple(
        {
            **module,
            "href": request.url_for(str(module["route_name"])).path,
            "label": text[module["label_key"]],
            "is_active": module["slug"] == active_module,
        }
        for module in modules
    )


def portal_template_context(
    request: Request,
    *,
    authenticated_session: AuthenticatedPortalSession,
    settings: Settings,
    active_module: str,
    csrf_token: str,
    sms_mfa_available: bool,
    account_notice: str | None = None,
    account_error: str | None = None,
    email_passwords: EmailPasswordDashboardViewModel | None = None,
    messages: MessagesViewModel | None = None,
    new_message_count: int = 0,
    mycarlos: MyCarlosViewModel | None = None,
) -> dict[str, object]:
    account = authenticated_session.account
    locale = request_locale(request)
    text = portal_text(locale)
    modules = portal_modules(
        request, active_module, text, mycarlos_enabled=settings.mycarlos_delivery_enabled
    )
    # A page answering a form POST (a password change, a revealed email password) switches
    # language back to its module's own page, never to the POST-only path it was rendered at.
    active_module_href = next(
        (str(module["href"]) for module in modules if module["is_active"]),
        None,
    )
    context: dict[str, object] = {
        "request": request,
        "locale": locale,
        "service_name": displayed_service_name(settings, text),
        "clinic_name": settings.clinic_name,
        "source_code_url": settings.source_code_url,
        "supported_locales": supported_locale_options(locale),
        "locale_switch_target": locale_switch_targets(request, get_fallback=active_module_href),
        "account": account,
        "password_updated_date": account.password_updated_at.date().isoformat(),
        "active_module": active_module,
        "modules": modules,
        "csrf_token": csrf_token,
        "account_notice": account_notice,
        "account_error": account_error,
        "sms_mfa_available": sms_mfa_available and account.phone_number is not None,
        "email_mfa_available": settings.is_development,
        "text": text,
    }
    # Modules with their own view state; typed so a rename is a type error, not a blank page.
    context["email_passwords"] = email_passwords
    context["messages"] = messages
    context["new_message_count"] = new_message_count
    context["new_messages_label"] = plural_text(
        text, "messages_new_count", new_message_count, locale
    ).format(count=new_message_count)
    context["mycarlos_enabled"] = settings.mycarlos_delivery_enabled
    context["mycarlos"] = mycarlos
    return context


def parse_optional_email_password_date(value: str | None) -> date | None:
    if value is None:
        return None
    normalized_value = value.strip()
    if not normalized_value:
        return None
    if len(normalized_value) != 10:
        raise ValueError("date must use YYYY-MM-DD format")
    parsed_date = date.fromisoformat(normalized_value)
    if parsed_date.isoformat() != normalized_value:
        raise ValueError("date must use YYYY-MM-DD format")
    return parsed_date


async def read_limited_request_body(request: Request, max_bytes: int) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="request body too large",
            )
        body.extend(chunk)
    return bytes(body)


async def get_urlencoded_form_values(
    request: Request,
    max_body_bytes: int,
    max_fields: int,
) -> dict[str, list[str]]:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        return {}

    try:
        body = (await read_limited_request_body(request, max_body_bytes)).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid form body",
        ) from exc
    try:
        return parse_qs(
            body,
            keep_blank_values=True,
            max_num_fields=max_fields,
            strict_parsing=True,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid form body",
        ) from exc


async def get_csrf_urlencoded_form_values(
    request: Request,
    csrf_secret: str,
    *,
    unsupported_media_type_detail: str,
) -> dict[str, list[str]]:
    if not is_urlencoded_form_request(request):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=unsupported_media_type_detail,
        )
    form_values = await get_urlencoded_form_values(
        request,
        MAX_FORM_BODY_BYTES,
        MAX_FORM_FIELD_COUNT,
    )
    if not is_valid_csrf_submission(
        first_form_value(form_values, CSRF_FORM_FIELD),
        request.cookies.get(CSRF_COOKIE_NAME),
        csrf_secret,
    ):
        # This helper is shared by routes that document their own browser/API responses.
        raise HTTPException(status_code=403, detail=INVALID_CSRF_DETAIL)  # NOSONAR
    return form_values


async def get_activation_request(request: Request) -> ActivationRequest:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if content_type != JSON_MEDIA_TYPE:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="activation requires an application/json request body",
        )
    body = await read_limited_request_body(request, MAX_JSON_BODY_BYTES)
    invite_code = ""
    try:
        raw_payload = json.loads(body)
        if isinstance(raw_payload, dict) and isinstance(raw_payload.get("invite_code"), str):
            invite_code = raw_payload["invite_code"]
    # Malformed input like any other, refused below, never a 500. ValueError covers decode errors
    # (JSONDecodeError, UnicodeDecodeError) and a number past Python's int-conversion digit limit;
    # RecursionError is JSON nested deeply enough, inside the size cap, to exhaust the decoder.
    except (ValueError, RecursionError):
        pass
    try:
        return ActivationRequest.model_validate_json(body)
    except ValidationError as exc:
        raise RequestValidationError(
            exc.errors(),
            body={"invite_code": invite_code},
        ) from exc


async def get_activation_request_from_request(
    request: Request,
    csrf_secret: str,
) -> ActivationRequest:
    if is_json_request(request):
        return await get_activation_request(request)

    form_values = await get_csrf_urlencoded_form_values(
        request,
        csrf_secret,
        unsupported_media_type_detail=(
            "activation requires an application/json or form request body"
        ),
    )
    # Every way activation can fail re-shows the form with these; the body cannot be read again.
    request.state.activation_form_values = activation_form_values_to_keep(form_values)
    password = first_form_value_or_empty(form_values, "password")
    if password != first_form_value_or_empty(form_values, "password_confirmation"):
        raise BrowserFormValidationError(
            "password confirmation does not match",
            # Only the invite code is read from this (to charge the rate limit); the entries the
            # page shows again come from request.state.
            safe_form_values={"invite_code": first_form_value_or_empty(form_values, "invite_code")},
        )
    try:
        return ActivationRequest.model_validate(
            {
                "invite_code": first_form_value(form_values, "invite_code"),
                "email": first_form_value(form_values, "email"),
                "date_of_birth": date_of_birth_from_form(form_values),
                "health_card_number": first_form_value(form_values, "health_card_number"),
                "username": first_form_value(form_values, "username"),
                "password": password,
                "mfa_delivery_method": first_form_value_or_empty(
                    form_values,
                    "mfa_delivery_method",
                )
                or MFA_DELIVERY_METHOD_EMAIL,
                "phone_number": first_form_value(form_values, "phone_number"),
            }
        )
    except ValidationError as exc:
        raise RequestValidationError(
            exc.errors(),
            body={"invite_code": first_form_value_or_empty(form_values, "invite_code")},
        ) from exc


async def get_mfa_verify_request(request: Request) -> MfaVerifyRequest:
    return await get_json_request_model(
        request,
        MfaVerifyRequest,
        "MFA verification requires an application/json request body",
    )


async def get_mfa_verify_request_from_request(
    request: Request,
    csrf_secret: str,
) -> MfaVerifyRequest:
    if is_json_request(request):
        return await get_mfa_verify_request(request)

    if not is_urlencoded_form_request(request):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="MFA verification requires an application/json or form request body",
        )

    form_values = await get_urlencoded_form_values(
        request,
        MAX_FORM_BODY_BYTES,
        MAX_FORM_FIELD_COUNT,
    )
    csrf_token = first_form_value(form_values, CSRF_FORM_FIELD)
    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
    if not is_valid_csrf_submission(csrf_token, csrf_cookie, csrf_secret):
        # This helper is shared by routes that document their own browser/API responses.
        raise HTTPException(status_code=403, detail=INVALID_CSRF_DETAIL)  # NOSONAR

    try:
        return MfaVerifyRequest.model_validate(
            {
                "mfa_challenge_token": first_form_value(
                    form_values,
                    "mfa_challenge_token",
                ),
                "code": first_form_value(form_values, "code"),
            }
        )
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


async def get_mfa_resend_request(request: Request) -> MfaResendRequest:
    return await get_json_request_model(
        request,
        MfaResendRequest,
        "MFA resend requires an application/json request body",
    )


async def get_mfa_resend_request_from_request(
    request: Request,
    csrf_secret: str,
) -> MfaResendRequest:
    if is_json_request(request):
        return await get_mfa_resend_request(request)

    if not is_urlencoded_form_request(request):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="MFA resend requires an application/json or form request body",
        )

    form_values = await get_urlencoded_form_values(
        request,
        MAX_FORM_BODY_BYTES,
        MAX_FORM_FIELD_COUNT,
    )
    csrf_token = first_form_value(form_values, CSRF_FORM_FIELD)
    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
    if not is_valid_csrf_submission(csrf_token, csrf_cookie, csrf_secret):
        # This helper is shared by routes that document their own browser/API responses.
        raise HTTPException(status_code=403, detail=INVALID_CSRF_DETAIL)  # NOSONAR

    try:
        return MfaResendRequest.model_validate(
            {
                "mfa_challenge_token": first_form_value(
                    form_values,
                    "mfa_challenge_token",
                ),
                "mfa_delivery_method": first_form_value(
                    form_values,
                    "mfa_delivery_method",
                ),
            }
        )
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


async def get_password_reset_request(request: Request) -> PasswordResetRequest:
    return await get_json_request_model(
        request,
        PasswordResetRequest,
        "password reset request requires an application/json request body",
    )


async def get_password_reset_request_from_request(
    request: Request,
    csrf_secret: str,
) -> PasswordResetRequest:
    if is_json_request(request):
        return await get_password_reset_request(request)

    form_values = await get_csrf_urlencoded_form_values(
        request,
        csrf_secret,
        unsupported_media_type_detail=(
            "password reset request requires an application/json or form request body"
        ),
    )
    try:
        return PasswordResetRequest.model_validate(
            {
                "username": first_form_value(form_values, "username"),
                "email": first_form_value(form_values, "email"),
            }
        )
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


async def get_password_reset_complete_request(request: Request) -> PasswordResetCompleteRequest:
    return await get_json_request_model(
        request,
        PasswordResetCompleteRequest,
        "password reset completion requires an application/json request body",
    )


async def get_password_reset_complete_request_from_request(
    request: Request,
    csrf_secret: str,
) -> PasswordResetCompleteRequest:
    if is_json_request(request):
        return await get_password_reset_complete_request(request)

    form_values = await get_csrf_urlencoded_form_values(
        request,
        csrf_secret,
        unsupported_media_type_detail=(
            "password reset completion requires an application/json or form request body"
        ),
    )
    new_password = first_form_value_or_empty(form_values, "new_password")
    reset_token = first_form_value_or_empty(form_values, "reset_token")
    if new_password != first_form_value_or_empty(
        form_values,
        "new_password_confirmation",
    ):
        raise BrowserFormValidationError(
            "password_mismatch",
            safe_form_values={"reset_token": reset_token},
        )
    try:
        return PasswordResetCompleteRequest.model_validate(
            {
                "reset_token": reset_token,
                "new_password": new_password,
            }
        )
    except ValidationError as exc:
        raise BrowserFormValidationError(
            "invalid_password" if reset_token else "invalid_reset_form",
            safe_form_values={"reset_token": reset_token},
        ) from exc


async def get_invite_create_request(request: Request) -> InviteCreateRequest:
    return await get_json_request_model(
        request,
        InviteCreateRequest,
        "invite creation requires an application/json request body",
    )


# PEP 695 function syntax requires Python 3.12; the portal supports Python 3.11.
async def get_json_request_model(  # NOSONAR
    request: Request,
    model_type: type[RequestModel],
    unsupported_media_type_detail: str,
) -> RequestModel:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if content_type != JSON_MEDIA_TYPE:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=unsupported_media_type_detail,
        )

    body = await read_limited_request_body(request, MAX_JSON_BODY_BYTES)
    try:
        return model_type.model_validate_json(body)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


def first_form_value(form_values: dict[str, list[str]], field_name: str) -> str | None:
    values = form_values.get(field_name)
    if not values:
        return None
    return values[0]


def first_form_value_or_empty(form_values: dict[str, list[str]], field_name: str) -> str:
    return first_form_value(form_values, field_name) or ""


# Not a date, so the request model refuses it as a date of birth (and the form says so).
UNREADABLE_DATE_OF_BIRTH = "unreadable"

# What a failed activation shows again, so the patient fixes one detail rather than retyping
# them all. Never the two password boxes. Each value is capped: it is only a typing aid.
ACTIVATION_KEPT_FIELDS = (
    "invite_code",
    "email",
    "date_of_birth_day",
    "date_of_birth_month",
    "date_of_birth_year",
    "health_card_number",
    "username",
    "mfa_delivery_method",
    "phone_number",
)
MAX_KEPT_ACTIVATION_VALUE_LENGTH = 256


def activation_form_values_to_keep(form_values: dict[str, list[str]]) -> dict[str, str]:
    """The activation form's entries to show again after a failure, passwords excluded."""
    kept = {
        field_name: value[:MAX_KEPT_ACTIVATION_VALUE_LENGTH]
        for field_name in ACTIVATION_KEPT_FIELDS
        if (value := first_form_value_or_empty(form_values, field_name))
    }
    single_date_of_birth = first_form_value_or_empty(form_values, "date_of_birth")
    if single_date_of_birth and not any(
        field_name.startswith("date_of_birth_") for field_name in kept
    ):
        # A page opened before the three boxes: show its ISO date in them.
        try:
            parsed = date.fromisoformat(single_date_of_birth)
        except ValueError:
            pass
        else:
            kept["date_of_birth_day"] = str(parsed.day)
            kept["date_of_birth_month"] = str(parsed.month)
            kept["date_of_birth_year"] = f"{parsed.year:04d}"
    return kept


def kept_activation_form_values(request: Request) -> dict[str, str]:
    """The entries a failed browser activation shows again (none for a JSON request)."""
    return dict(getattr(request.state, "activation_form_values", {}))


def date_of_birth_from_form(form_values: dict[str, list[str]]) -> str | None:
    """The activation form's day, month and year boxes as one ISO date.

    Parts that are missing, not digits, or no real date (31 February) give a value the request
    model refuses as a date of birth; the range check is the model's. A form that sends a single
    ISO ``date_of_birth`` (a page opened before the boxes) is read as before.
    """
    parts = [
        first_form_value_or_empty(form_values, field_name).strip()
        for field_name in ("date_of_birth_day", "date_of_birth_month", "date_of_birth_year")
    ]
    if not any(parts):
        return first_form_value(form_values, "date_of_birth")
    day, month, year = parts
    if not (
        re.fullmatch(r"[0-9]{1,2}", day)
        and re.fullmatch(r"[0-9]{1,2}", month)
        and re.fullmatch(r"[0-9]{4}", year)
    ):
        return UNREADABLE_DATE_OF_BIRTH
    try:
        return date(int(year), int(month), int(day)).isoformat()
    except ValueError:
        return UNREADABLE_DATE_OF_BIRTH


async def get_login_request_from_request(request: Request, csrf_secret: str) -> LoginRequest:
    if is_json_request(request):
        return await get_json_request_model(
            request,
            LoginRequest,
            "login requires an application/json request body",
        )

    if not is_urlencoded_form_request(request):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="login requires an application/json or form request body",
        )

    form_values = await get_urlencoded_form_values(
        request,
        MAX_FORM_BODY_BYTES,
        MAX_FORM_FIELD_COUNT,
    )
    csrf_token = first_form_value(form_values, CSRF_FORM_FIELD)
    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
    if not is_valid_csrf_submission(csrf_token, csrf_cookie, csrf_secret):
        # This helper is shared by routes that document their own browser/API responses.
        raise HTTPException(status_code=403, detail=INVALID_CSRF_DETAIL)  # NOSONAR

    try:
        return LoginRequest.model_validate(
            {
                "username": first_form_value(form_values, "username"),
                "password": first_form_value(form_values, "password"),
                "mfa_delivery_method": first_form_value(form_values, "mfa_delivery_method"),
            }
        )
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


def parse_trusted_client_ip_header(
    header_name: str,
    header_value: str | None,
    *,
    peer_address: str | None,
    trusted_proxy_cidrs: str | None,
) -> str | None:
    if not header_value or not peer_address or not trusted_proxy_cidrs:
        return None

    try:
        peer_ip = ip_address(peer_address)
        trusted_networks = tuple(
            ip_network(value.strip(), strict=False)
            for value in trusted_proxy_cidrs.split(",")
            if value.strip()
        )
    except ValueError:
        return None
    if not any(peer_ip in network for network in trusted_networks):
        return None

    try:
        if header_name != "x-forwarded-for":
            return str(ip_address(header_value.strip()))
        forwarded_ips = tuple(
            ip_address(value.strip()) for value in header_value.split(",") if value.strip()
        )
    except ValueError:
        return None
    if not forwarded_ips:
        return None

    for candidate in reversed(forwarded_ips):
        if not any(candidate in network for network in trusted_networks):
            return str(candidate)
    return str(forwarded_ips[0])


def get_request_client_reference(request: Request, settings: Settings) -> str:
    if settings.trusted_client_ip_header is not None:
        trusted_client_reference = parse_trusted_client_ip_header(
            settings.trusted_client_ip_header,
            request.headers.get(settings.trusted_client_ip_header),
            peer_address=request.client.host if request.client is not None else None,
            trusted_proxy_cidrs=settings.trusted_proxy_cidrs,
        )
        if trusted_client_reference is not None:
            return trusted_client_reference

    if request.client is None or not request.client.host:
        return UNKNOWN_CLIENT_REFERENCE
    return request.client.host
