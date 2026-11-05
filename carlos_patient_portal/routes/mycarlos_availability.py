# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""A linked myCarlos device enrolls, lists and revokes its availability destinations (P1, P4).

Registered only while both PATIENT_PORTAL_MYCARLOS_DELIVERY_ENABLED and
PATIENT_PORTAL_MYCARLOS_AVAILABILITY_ENABLED are on. Every request carries the device's signed
assertion, checked and used once exactly as the mailbox routes do. Enrolling stores what the
device reports: the platform, an opaque destination id, the remote switch, remote consent v1
and an OS permission it observed. A revocation names the device's own destination id and is
answered only once its tombstone is committed, so the device may then drop it from its queue
(P4). Nothing here sends; the dispatch worker (P2) does, and only with credentials.
Responses carry the device's own subscription ids and settings, nothing about the patient.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from time import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from carlos_patient_portal.device_identity import (
    DEVICE_ASSERTION_HEADER,
    DevicePrincipal,
    DeviceRefusal,
    consume_device_assertion,
    find_device_record,
    verify_device_assertion,
)
from carlos_patient_portal.models import PatientPortalMyCarlosAvailabilitySubscription
from carlos_patient_portal.mycarlos_availability import AvailabilityError, Owner
from carlos_patient_portal.mycarlos_availability_store import (
    EnrollmentRefusal,
    EnrollmentRequest,
    RevocationRequest,
    acknowledge_revocation,
    enroll,
    revoke,
    subscriptions_for_owner,
)
from carlos_patient_portal.routes.mycarlos import signed_path
from carlos_patient_portal.runtime import PortalRuntime
from carlos_patient_portal.staff_identity import staff_request_hash

SUBSCRIPTIONS_PATH = "/api/mycarlos/availability/subscriptions"
REVOCATIONS_PATH = "/api/mycarlos/availability/revocations"
MAX_ENROLLMENT_BODY = 1024
MAX_REVOCATION_BODY = 1024
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
ENROLLMENT_FIELDS = frozenset(
    {
        "platform",
        "destination_id",
        "remote_enabled",
        "remote_consent_version",
        "permission_observed",
    }
)
REVOCATION_FIELDS = frozenset({"platform", "destination_id"})
REFUSAL_STATUS = {
    "invalid_enrollment": 400,
    "invalid_platform": 400,
    "invalid_destination": 400,
    "consent_required": 422,
    "destination_revoked": 409,
    "destination_taken": 409,
    "destination_capacity": 409,
    "device_inactive": 403,
    "not_found": 404,
}


class _TooLarge(Exception):
    pass


def _response(content: dict[str, object], status: int = 200) -> JSONResponse:
    return JSONResponse(content=content, status_code=status, headers=NO_STORE)


def _refused(code: str) -> JSONResponse:
    status = REFUSAL_STATUS.get(code, 400)
    if status == 404:
        return _response({"detail": "not found"}, 404)
    return _response({"code": code}, status)


def _enrolled_at(value: datetime) -> str:
    return value.isoformat()


def subscription_record(row: PatientPortalMyCarlosAvailabilitySubscription) -> dict[str, object]:
    """What the device is told about one of its subscriptions: its own ids and settings."""
    return {
        "subscription_id": row.subscription_id,
        "epoch": row.epoch,
        "destination_id": row.destination_id,
        "platform": row.platform,
        "remote_enabled": bool(row.remote_enabled),
        "remote_consent_version": row.remote_consent_version,
        "permission_observed": bool(row.permission_observed),
        "enrolled_at": _enrolled_at(row.created_at),
        "revoked": row.revoked_at is not None,
    }


def parse_enrollment(body: bytes) -> EnrollmentRequest:
    """The exact five fields, with their exact types; anything else is refused."""
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise EnrollmentRefusal("invalid_enrollment") from None
    if not isinstance(value, dict) or set(value) != ENROLLMENT_FIELDS:
        raise EnrollmentRefusal("invalid_enrollment")
    if (
        type(value["platform"]) is not str
        or type(value["destination_id"]) is not str
        or type(value["remote_enabled"]) is not bool
        or type(value["remote_consent_version"]) is not int
        or type(value["permission_observed"]) is not bool
    ):
        raise EnrollmentRefusal("invalid_enrollment")
    return EnrollmentRequest(
        platform=value["platform"],
        destination_id=value["destination_id"],
        remote_enabled=value["remote_enabled"],
        remote_consent_version=value["remote_consent_version"],
        permission_observed=value["permission_observed"],
    )


def parse_revocation(body: bytes) -> RevocationRequest:
    """The exact two fields, both strings; anything else is refused."""
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise EnrollmentRefusal("invalid_enrollment") from None
    if not isinstance(value, dict) or set(value) != REVOCATION_FIELDS:
        raise EnrollmentRefusal("invalid_enrollment")
    if type(value["platform"]) is not str or type(value["destination_id"]) is not str:
        raise EnrollmentRefusal("invalid_enrollment")
    return RevocationRequest(platform=value["platform"], destination_id=value["destination_id"])


async def _bounded_body(request: Request, maximum: int) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum:
            raise _TooLarge
        body.extend(chunk)
    return bytes(body)


def register_mycarlos_availability_routes(app: FastAPI, runtime: PortalRuntime) -> None:
    def execute(
        request: Request,
        body: bytes,
        operation: Callable[[Session, Owner], Response],
    ) -> Response:
        assertion = request.headers.get(DEVICE_ASSERTION_HEADER)
        request_hash = staff_request_hash(
            request.method,
            signed_path(runtime, request),
            request.scope.get("query_string", b""),
            body,
        )
        try:
            with runtime.session_factory() as lookup:
                principal: DevicePrincipal = verify_device_assertion(
                    assertion,
                    find_device=lambda kid: find_device_record(lookup, kid),
                    expected_request_hash=request_hash,
                    now=int(time()),
                )
            consume_device_assertion(runtime.session_factory, principal, now=int(time()))
        except DeviceRefusal as exc:
            if exc.code in {"device_removed", "recipient_mismatch"}:
                return _response({"code": exc.code}, 403)
            return _response({"detail": "not found"}, 404)
        owner = Owner(principal.account_id, principal.device_id)
        try:
            with runtime.session_factory() as session, session.begin():
                content = operation(session, owner)
            return content  # Context exited/COMMIT succeeded before exposing success.
        except EnrollmentRefusal as exc:
            return _refused(exc.code)
        except AvailabilityError:
            return _refused("invalid_enrollment")

    async def call(
        request: Request,
        maximum: int,
        operation: Callable[[Session, Owner, bytes], Response],
    ) -> Response:
        try:
            body = await _bounded_body(request, maximum)
        except _TooLarge:
            return _response({"detail": "request too large"}, 413)
        if request.scope.get("query_string", b""):
            return _response({"detail": "not found"}, 404)
        return await run_in_threadpool(
            execute,
            request,
            body,
            lambda session, owner: operation(session, owner, body),
        )

    @app.get(SUBSCRIPTIONS_PATH, include_in_schema=runtime.settings.is_development)
    async def list_subscriptions(request: Request) -> Response:
        def operation(session: Session, owner: Owner, body: bytes) -> Response:
            if body:
                raise EnrollmentRefusal("invalid_enrollment")
            rows = subscriptions_for_owner(session, owner, include_revoked=True)
            return _response({"subscriptions": [subscription_record(row) for row in rows]})

        return await call(request, 0, operation)

    @app.post(SUBSCRIPTIONS_PATH, include_in_schema=runtime.settings.is_development)
    async def enroll_subscription(request: Request) -> Response:
        def operation(session: Session, owner: Owner, body: bytes) -> Response:
            row, created = enroll(session, owner, parse_enrollment(body))
            return _response(subscription_record(row), 201 if created else 200)

        return await call(request, MAX_ENROLLMENT_BODY, operation)

    @app.delete(
        SUBSCRIPTIONS_PATH + "/{subscription_id}",
        include_in_schema=runtime.settings.is_development,
    )
    async def revoke_subscription(request: Request, subscription_id: str) -> Response:
        def operation(session: Session, owner: Owner, body: bytes) -> Response:
            if body:
                raise EnrollmentRefusal("invalid_enrollment")
            row = revoke(session, owner, subscription_id, by="device")
            return _response(subscription_record(row))

        return await call(request, 0, operation)

    @app.post(REVOCATIONS_PATH, include_in_schema=runtime.settings.is_development)
    async def acknowledge_device_revocation(request: Request) -> Response:
        # The answer names only the destination the device sent: a tombstone the portal had to
        # create was never enrolled, so it has no enrollment to report.
        def operation(session: Session, owner: Owner, body: bytes) -> Response:
            row = acknowledge_revocation(session, owner, parse_revocation(body))
            return _response({"destination_id": row.destination_id, "revoked": True})

        return await call(request, MAX_REVOCATION_BODY, operation)
