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
refused code is 403 `link_code_invalid`, a key that is already linked is 409 `device_exists`, and
linking before the clinic has published an active signing key is 409 `clinic_keys_missing`.
Every attempt is audited as `mycarlos.link` with its code, never its content.
"""

from datetime import UTC, datetime, timedelta
from time import time
from typing import Annotated

from fastapi import Depends, FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from carlos_patient_portal.audit import hash_sensitive_reference, record_audit_event
from carlos_patient_portal.device_identity import (
    DEVICE_ASSERTION_HEADER,
    DeviceRefusal,
    LinkRequest,
    REFUSAL_DEVICE_REMOVED,
    consume_device_assertion,
    find_device_record,
    verify_device_assertion,
    verify_link_recovery_assertion,
    verify_link_request,
)
from carlos_patient_portal.models import (
    AUDIT_ACTOR_TYPE_PATIENT,
    AUDIT_EVENT_MYCARLOS_LINK,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_SUCCESS,
    PatientPortalAccount,
    PatientPortalMyCarlosDevice,
    MYCARLOS_DEVICE_STATUS_ACTIVE,
)
from carlos_patient_portal.mycarlos_links import (
    LINK_RESULT_CLINIC_KEYS_MISSING,
    LINK_RESULT_CODE_INVALID,
    LINK_RESULT_DEVICE_EXISTS,
    LINK_RESULT_LINKED,
    clinic_key_list,
    link_device,
)
from carlos_patient_portal.mycarlos_devices import recipient_id_for_account
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
            # Spec check 5: no device links before the clinic has a key to give it. Checked for
            # the whole clinic before any link is looked up, so the code stays pending, nothing
            # is counted, and the answer says nothing about the link the request names.
            published_keys = clinic_key_list(session, settings.clinic_id)
            if not any(key["status"] == "active" for key in published_keys):
                record_link_attempt(
                    outcome=AUDIT_OUTCOME_FAILURE,
                    reason=LINK_RESULT_CLINIC_KEYS_MISSING,
                    client_reference_hash=client_reference_hash,
                    device_key_id=request.device_key_id,
                    session=session,
                )
                return JSONResponse(
                    status_code=status.HTTP_409_CONFLICT,
                    content={"code": LINK_RESULT_CLINIC_KEYS_MISSING},
                )
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
                    # One source for the clinic and its keys: the device pins these keys under
                    # this clinic ID, and every manifest it later checks must name the same one.
                    "clinic_id": settings.clinic_id,
                    "clinic_name": settings.clinic_name,
                    "clinic_keys": published_keys,
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

    def inventory_response(content: dict[str, object], status_code: int = 200) -> JSONResponse:
        return JSONResponse(
            content=content, status_code=status_code,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    def read_inventory(
        assertion: str | None, expected_request_hash: str, client_reference_hash: str,
        now: int, recovery: bool,
    ) -> JSONResponse:
        verifier = verify_link_recovery_assertion if recovery else verify_device_assertion
        try:
            with runtime.session_factory() as lookup_session:
                principal = verifier(
                    assertion,
                    find_device=lambda kid: find_device_record(lookup_session, kid),
                    expected_request_hash=expected_request_hash, now=now,
                )
            # Recovery must validate freshness, exact request binding AND shared replay policy
            # before any removed-device distinction. This commit precedes account/device locks.
            consume_device_assertion(runtime.session_factory, principal, now=now)
        except DeviceRefusal as refusal:
            record_link_attempt(
                outcome=AUDIT_OUTCOME_FAILURE, reason=refusal.code,
                client_reference_hash=client_reference_hash,
            )
            if not recovery and refusal.code == REFUSAL_DEVICE_REMOVED:
                return inventory_response({"code": REFUSAL_DEVICE_REMOVED}, 403)
            return inventory_response(GENERIC_NOT_FOUND, 404)
        with runtime.session_factory() as session, session.begin():
            account = session.scalar(
                select(PatientPortalAccount).where(
                    PatientPortalAccount.id == principal.account_id,
                    PatientPortalAccount.clinic_id == settings.clinic_id,
                ).with_for_update().execution_options(populate_existing=True)
            )
            device = session.scalar(
                select(PatientPortalMyCarlosDevice).where(
                    PatientPortalMyCarlosDevice.id == principal.device_id,
                    PatientPortalMyCarlosDevice.account_id == principal.account_id,
                    PatientPortalMyCarlosDevice.device_key_id == principal.device_key_id,
                ).with_for_update().execution_options(populate_existing=True)
            ) if account is not None else None
            recipient = recipient_id_for_account(session, principal.account_id) if account else None
            if account is None or device is None or recipient is None:
                record_link_attempt(
                    outcome=AUDIT_OUTCOME_FAILURE, reason="unknown_device",
                    client_reference_hash=client_reference_hash,
                    device_key_id=principal.device_key_id, session=session,
                )
                return inventory_response(GENERIC_NOT_FOUND, 404)
            if device.status != MYCARLOS_DEVICE_STATUS_ACTIVE:
                record_link_attempt(
                    outcome=AUDIT_OUTCOME_FAILURE, reason=REFUSAL_DEVICE_REMOVED,
                    client_reference_hash=client_reference_hash,
                    device_key_id=principal.device_key_id, account=account,
                    device_id=device.id, session=session,
                )
                return inventory_response({"code": REFUSAL_DEVICE_REMOVED}, 403)
            # One statement sees the publisher's complete committed inventory. Bootstrap still
            # needs an active key; a completed link may refresh to an all-revoked inventory.
            published_keys = clinic_key_list(session, settings.clinic_id)
            if not published_keys or (recovery and not any(key["status"] == "active" for key in published_keys)):
                record_link_attempt(
                    outcome=AUDIT_OUTCOME_FAILURE, reason=LINK_RESULT_CLINIC_KEYS_MISSING,
                    client_reference_hash=client_reference_hash,
                    device_key_id=principal.device_key_id, account=account,
                    device_id=device.id, session=session,
                )
                return inventory_response({"code": LINK_RESULT_CLINIC_KEYS_MISSING}, 409)
            record_link_attempt(
                outcome=AUDIT_OUTCOME_SUCCESS, reason="recovered" if recovery else "keys_refreshed",
                client_reference_hash=client_reference_hash,
                device_key_id=principal.device_key_id, account=account,
                device_id=device.id, session=session,
            )
            return inventory_response({
                "recipient_id": recipient, "device_key_id": device.device_key_id,
                "clinic_id": settings.clinic_id, "clinic_name": settings.clinic_name,
                "clinic_keys": published_keys,
            })

    async def inventory_request(request: Request, now: int, *, recovery: bool) -> JSONResponse:
        # Both signed GETs have an empty body. Stop at the first nonempty chunk rather than
        # buffering an attacker-controlled body merely to reject it.
        async for chunk in request.stream():
            if chunk:
                return inventory_response(GENERIC_NOT_FOUND, 404)
        expected_request_hash = staff_request_hash(
            request.method, signed_path(runtime, request),
            request.scope.get("query_string", b""), b"",
        )
        client_reference_hash = hash_sensitive_reference(
            runtime.audit_hash_secret, "portal_client", get_request_client_reference(request, settings)
        )
        return await run_in_threadpool(
            read_inventory, request.headers.get(DEVICE_ASSERTION_HEADER),
            expected_request_hash, client_reference_hash, now, recovery,
        )

    @app.get(MYCARLOS_LINK_PATH, include_in_schema=settings.is_development)
    async def recover_mycarlos_link(
        request: Request, now: Annotated[int, Depends(mycarlos_clock)],
    ) -> JSONResponse:
        return await inventory_request(request, now, recovery=True)

    @app.get("/api/mycarlos/clinic-keys", include_in_schema=settings.is_development)
    async def refresh_mycarlos_clinic_keys(
        request: Request, now: Annotated[int, Depends(mycarlos_clock)],
    ) -> JSONResponse:
        return await inventory_request(request, now, recovery=False)
