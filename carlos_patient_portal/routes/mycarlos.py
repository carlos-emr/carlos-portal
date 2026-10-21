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

"""The myCarlos device API (carlos-portal#41): `POST /api/mycarlos/link` for now.

Registered only while PATIENT_PORTAL_MYCARLOS_DELIVERY_ENABLED is on. The device has no browser
session; it proves itself with `X-MyCarlos-Device-Assertion` (device_identity.py). Answers follow
the spec's "Response codes": a failed assertion is the same generic 404 as the job routes, a
refused code is 403 `link_code_invalid`, and a key that is already linked is 409 `device_exists`.
Every attempt is audited as `mycarlos.link` with its code, never its content.
"""

from datetime import UTC, datetime, timedelta
from time import time
from typing import Annotated

from fastapi import Depends, FastAPI, Request, status
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from carlos_patient_portal.audit import hash_sensitive_reference, record_audit_event
from carlos_patient_portal.device_identity import (
    DEVICE_ASSERTION_HEADER,
    DeviceRefusal,
    LinkRequest,
    consume_device_assertion,
    verify_link_request,
)
from carlos_patient_portal.models import (
    AUDIT_ACTOR_TYPE_PATIENT,
    AUDIT_EVENT_MYCARLOS_LINK,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_SUCCESS,
    PatientPortalAccount,
)
from carlos_patient_portal.mycarlos_links import (
    LINK_RESULT_CODE_INVALID,
    LINK_RESULT_DEVICE_EXISTS,
    LINK_RESULT_LINKED,
    clinic_key_list,
    link_device,
)
from carlos_patient_portal.runtime import PortalRuntime
from carlos_patient_portal.staff_identity import staff_request_hash
from carlos_patient_portal.web_support import MYCARLOS_LINK_PATH, get_request_client_reference

# The body is five short fields; anything larger is refused before it is read in full.
MAX_LINK_BODY_BYTES = 4096
GENERIC_NOT_FOUND = {"detail": "not found"}
LINK_STATUS = {
    LINK_RESULT_CODE_INVALID: status.HTTP_403_FORBIDDEN,
    LINK_RESULT_DEVICE_EXISTS: status.HTTP_409_CONFLICT,
}


def mycarlos_clock() -> int:
    """The current Unix time. A dependency, so tests can check requests at the vectors' time."""
    return int(time())


def signed_path(runtime: PortalRuntime, request: Request) -> bytes:
    """The path the device signed: the public base URL's path, then the route.

    A deployment under a prefix (PATIENT_PORTAL_PUBLIC_BASE_URL=https://host/patient) has the
    prefix stripped by the proxy, so the device's signed path is the root path plus what arrives.
    """
    raw_path = request.scope.get("raw_path") or request.url.path.encode("utf-8")
    return runtime.settings.root_path.encode("utf-8") + raw_path


def register_mycarlos_device_routes(app: FastAPI, runtime: PortalRuntime) -> None:
    settings = runtime.settings
    idle_timeout = timedelta(seconds=settings.session_idle_timeout_seconds)

    def record_link_attempt(
        *,
        outcome: str,
        reason: str,
        client_reference_hash: str,
        device_key_id: str | None = None,
        account: PatientPortalAccount | None = None,
        device_id: int | None = None,
        session=None,  # noqa: ANN001 - an open Session, or None to write in a new one
    ) -> None:
        values = {
            "event_type": AUDIT_EVENT_MYCARLOS_LINK,
            "outcome": outcome,
            "actor_type": AUDIT_ACTOR_TYPE_PATIENT,
            "actor_id": device_key_id,
            "clinic_id": account.clinic_id if account is not None else settings.clinic_id,
            "demographic_no": account.demographic_no if account is not None else None,
            "account_id": account.id if account is not None else None,
            "resource_type": "mycarlos_device",
            "resource_id": str(device_id) if device_id is not None else None,
            "reason": reason,
            "client_reference_hash": client_reference_hash,
        }
        if session is not None:
            record_audit_event(session, **values)
            return
        with runtime.session_factory() as audit_session, audit_session.begin():
            record_audit_event(audit_session, **values)

    def link(
        body: bytes,
        assertion: str | None,
        expected_request_hash: str,
        client_reference_hash: str,
        now: int,
    ) -> JSONResponse:
        try:
            request: LinkRequest = verify_link_request(
                body,
                assertion,
                expected_request_hash=expected_request_hash,
                now=now,
            )
            consume_device_assertion(runtime.session_factory, request, now=now)
        except DeviceRefusal as refusal:
            record_link_attempt(
                outcome=AUDIT_OUTCOME_FAILURE,
                reason=refusal.code,
                client_reference_hash=client_reference_hash,
            )
            return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content=GENERIC_NOT_FOUND)

        with runtime.session_factory() as session, session.begin():
            result = link_device(
                session,
                request,
                key=runtime.token_keys.mycarlos_link,
                idle_timeout=idle_timeout,
                now=datetime.fromtimestamp(now, tz=UTC),
            )
            account = (
                session.get(PatientPortalAccount, result.account_id)
                if result.account_id is not None
                else None
            )
            linked = result.code == LINK_RESULT_LINKED
            # Written in the same transaction as the wrong-code count, so both or neither land.
            record_link_attempt(
                outcome=AUDIT_OUTCOME_SUCCESS if linked else AUDIT_OUTCOME_FAILURE,
                reason=result.code,
                client_reference_hash=client_reference_hash,
                device_key_id=request.device_key_id,
                account=account,
                device_id=result.device.id if result.device is not None else None,
                session=session,
            )
            if linked and account is not None:
                content = {
                    "recipient_id": result.recipient_id,
                    "device_key_id": request.device_key_id,
                    "clinic_id": account.clinic_id,
                    "clinic_name": settings.clinic_name,
                    "clinic_keys": clinic_key_list(session, account.clinic_id),
                }
        if not linked:
            return JSONResponse(status_code=LINK_STATUS[result.code], content={"code": result.code})
        return JSONResponse(status_code=status.HTTP_200_OK, content=content)

    @app.post(MYCARLOS_LINK_PATH, include_in_schema=settings.is_development)
    async def link_mycarlos_device(
        request: Request,
        now: Annotated[int, Depends(mycarlos_clock)],
    ) -> JSONResponse:
        """Link a myCarlos device with a one-time code (spec "Linking a device")."""
        declared_length = request.headers.get("content-length", "")
        if declared_length.isdigit() and int(declared_length) > MAX_LINK_BODY_BYTES:
            return JSONResponse(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                content={"detail": "request too large"},
            )
        body = await request.body()
        if len(body) > MAX_LINK_BODY_BYTES:
            return JSONResponse(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                content={"detail": "request too large"},
            )
        expected_request_hash = staff_request_hash(
            request.method,
            signed_path(runtime, request),
            request.scope.get("query_string", b""),
            body,
        )
        client_reference_hash = hash_sensitive_reference(
            runtime.audit_hash_secret,
            "portal_client",
            get_request_client_reference(request, settings),
        )
        return await run_in_threadpool(
            link,
            body,
            request.headers.get(DEVICE_ASSERTION_HEADER),
            expected_request_hash,
            client_reference_hash,
            now,
        )
