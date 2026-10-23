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

"""Default-off M4 routes; exact frozen v1 bytes, no server-provided URLs or PHI."""

from time import time
from typing import Annotated

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from carlos_patient_portal.device_identity import (
    DEVICE_ASSERTION_HEADER, DeviceRefusal, consume_device_assertion,
    find_device_record, verify_device_assertion,
)
from carlos_patient_portal.mailbox import (
    MailboxLimits, accept_receipt, acknowledge_events, admit_upload, clinic_lock,
    copy_lock, events_page, mailbox_lock, outer_record, rate, record_request_anchor,
)
from carlos_patient_portal.mailbox_codec import (
    MAX_UPLOAD, MailboxRefusal, cursor, json_bytes, parse_ack, parse_receipt_body, parse_upload,
)
from carlos_patient_portal.mailbox_models import MailboxAnchor, MailboxBlob, MailboxCopy, MailboxProof
from carlos_patient_portal.models import PatientPortalAccount
from carlos_patient_portal.routes.mycarlos import signed_path
from carlos_patient_portal.staff_identity import staff_request_hash
from carlos_patient_portal.system_jobs import (
    JOB_DELIVERY_SYNC, PERMISSION_DELIVERY_EVENTS_ACK,
    PERMISSION_DELIVERY_EVENTS_READ, PERMISSION_DELIVERY_UPLOAD,
)

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def limits_from_settings(settings) -> MailboxLimits:
    return MailboxLimits(**{name: getattr(settings, "mycarlos_mailbox_" + name)
                            for name in MailboxLimits.__dataclass_fields__})


def response(content, status=200):
    return JSONResponse(content=content, status_code=status, headers=NO_STORE)


def refusal_response(exc: MailboxRefusal):
    if exc.status == 404 and exc.code == "invalid_assertion":
        return response({"detail": "not found"}, 404)
    headers = NO_STORE | ({"Retry-After": "60"} if exc.status == 429 else {})
    if exc.status == 413:
        return JSONResponse(content={"detail": "request too large"}, status_code=413, headers=headers)
    return JSONResponse(content={"code": exc.code}, status_code=exc.status, headers=headers)


async def bounded_body(request: Request, maximum: int) -> bytes:
    # Read at most maximum+one incoming ASGI chunk; never an unbounded request.body().
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum:
            raise MailboxRefusal("invalid_delivery", 413)
        body.extend(chunk)
    return bytes(body)


def query_values(request: Request, allowed: set[str], *, maximum: int, default: int):
    values = {}
    try:
        raw = request.scope.get("query_string", b"").decode("ascii")
    except UnicodeError as exc:
        raise MailboxRefusal("invalid_cursor") from exc
    for part in raw.split("&") if raw else []:
        key, separator, value = part.partition("=")
        if not separator:
            raise MailboxRefusal("invalid_cursor")
        if key not in allowed or key in values:
            raise MailboxRefusal("invalid_cursor")
        values[key] = value
    after = cursor(values.get("after", "0"))
    limit = cursor(values.get("limit", str(default)))
    if not 1 <= limit <= maximum:
        raise MailboxRefusal("invalid_cursor")
    return after, limit, values


def register_device_mailbox_routes(app: FastAPI, runtime) -> None:
    settings = runtime.settings
    limits = limits_from_settings(settings)

    def execute(request: Request, body: bytes, operation):
        assertion = request.headers.get(DEVICE_ASSERTION_HEADER)
        request_hash = staff_request_hash(request.method, signed_path(runtime, request),
            request.scope.get("query_string", b""), body)
        try:
            with runtime.session_factory() as lookup:
                principal = verify_device_assertion(assertion,
                    find_device=lambda kid: find_device_record(lookup, kid),
                    expected_request_hash=request_hash, now=int(time()))
            consume_device_assertion(runtime.session_factory, principal, now=int(time()))
        except DeviceRefusal as exc:
            if exc.code in {"device_removed", "recipient_mismatch"}:
                return response({"code": exc.code}, 403)
            return response({"detail": "not found"}, 404)
        try:
            with runtime.session_factory() as session, session.begin():
                m = mailbox_lock(session, account_id=principal.account_id,
                    device_key_id=principal.device_key_id, clinic_id=settings.clinic_id)
                content = operation(session, m, principal, assertion)
            return content  # Context exited/COMMIT succeeded before exposing success.
        except MailboxRefusal as exc:
            return refusal_response(exc)

    async def call(request, maximum, operation):
        try:
            if request.method == "GET":
                async for chunk in request.stream():
                    if chunk:
                        raise MailboxRefusal("invalid_assertion", 404)
                body = b""
            else:
                body = await bounded_body(request, maximum)
        except MailboxRefusal as exc:
            return refusal_response(exc)
        return await run_in_threadpool(execute, request, body,
            lambda session, m, principal, assertion: operation(session, m, principal, assertion, body))

    @app.get("/api/mycarlos/deliveries")
    async def deliveries(request: Request):
        def operation(session, m, principal, assertion, _body):
            after, limit, values = query_values(request, {"after", "through", "limit"}, maximum=100, default=50)
            through = cursor(values["through"]) if "through" in values else m.device_quota.delivery_sequence
            if after > through or through > m.device_quota.delivery_sequence:
                raise MailboxRefusal("invalid_cursor")
            now = int(time())
            rate(session, m.clinic, f"list:{m.device.id}", now=now, maximum=limits.device_lists_per_minute)
            anchored = record_request_anchor(session, m, compact=assertion, anchor=principal.vault_head_link, now=now, limits=limits)
            rows = list(session.scalars(select(MailboxCopy).where(MailboxCopy.device_id == m.device.id,
                MailboxCopy.sequence > after, MailboxCopy.sequence <= through,
                MailboxCopy.status == "waiting", MailboxCopy.expires_at > now)
                .order_by(MailboxCopy.sequence).limit(limit + 1)))
            selected = rows[:limit]
            content = {"deliveries": [outer_record(row) for row in selected], "through": str(through),
                "next_cursor": str(selected[-1].sequence) if len(rows) > limit else None,
                "anchor_recorded": anchored}
            if len(json_bytes(content)) > 524288:
                raise RuntimeError("Bounded mailbox list exceeded frozen byte limit")
            return response(content)
        return await call(request, 0, operation)

    @app.get("/api/mycarlos/deliveries/{delivery_id}")
    async def download(request: Request, delivery_id: str):
        def operation(session, m, principal, assertion, _body):
            copy = copy_lock(session, m, delivery_id)
            now = int(time())
            if copy is None or copy.status != "waiting" or copy.expires_at <= now:
                raise MailboxRefusal("delivery_not_found", 404)
            rate(session, m.clinic, f"download:{m.device.id}", now=now, maximum=limits.device_downloads_per_minute)
            blob = session.get(MailboxBlob, copy.id)
            if blob is None or len(blob.sealed) != copy.size:
                raise RuntimeError("Missing primary mailbox blob")
            record_request_anchor(session, m, compact=assertion, anchor=principal.vault_head_link, now=now, limits=limits)
            return Response(content=blob.sealed, media_type="application/octet-stream", headers=NO_STORE)
        return await call(request, 0, operation)

    @app.post("/api/mycarlos/deliveries/{delivery_id}/receipt")
    async def receipt(request: Request, delivery_id: str):
        def operation(session, m, principal, assertion, body):
            compact = parse_receipt_body(body)
            rate(session, m.clinic, f"receipt:{m.device.id}", now=int(time()), maximum=limits.device_receipts_per_minute)
            return response(accept_receipt(session, m, delivery_id=delivery_id, compact=compact,
                request_assertion=assertion, request_anchor=principal.vault_head_link, limits=limits))
        return await call(request, 8192, operation)

    @app.get("/api/mycarlos/anchors")
    async def anchors(request: Request):
        def operation(session, m, principal, assertion, _body):
            after, limit, _values = query_values(request, {"after", "limit"}, maximum=100, default=50)
            if after > m.device_quota.anchor_sequence:
                raise MailboxRefusal("invalid_cursor")
            now = int(time())
            rate(session, m.clinic, f"anchors:{m.device.id}", now=now, maximum=limits.device_lists_per_minute)
            record_request_anchor(session, m, compact=assertion, anchor=principal.vault_head_link, now=now, limits=limits)
            rows = list(session.scalars(select(MailboxAnchor).where(MailboxAnchor.device_key_id == m.device.device_key_id,
                MailboxAnchor.sequence > after).order_by(MailboxAnchor.sequence).limit(limit + 1)))
            content = {"anchors": [{"sequence": str(row.sequence), "vault_head_link": row.vault_head_link,
                "recorded_at": row.recorded_at, "proof_kind": row.proof_kind,
                "compact_proof": session.get(MailboxProof, row.proof_id).compact.decode("ascii")}
                for row in rows[:limit]], "next_cursor": str(rows[limit - 1].sequence) if len(rows) > limit else None}
            if len(json_bytes(content)) > 1048576:
                raise RuntimeError("Bounded anchor page exceeded frozen byte limit")
            return response(content)
        return await call(request, 0, operation)


def register_internal_mailbox_routes(app: FastAPI, runtime, deps) -> None:
    """Reuse existing registered job dependencies and refusal/audit policies."""
    limits = limits_from_settings(runtime.settings)

    def body_guard(maximum):
        async def prepare(request: Request):
            try:
                raw = await bounded_body(request, maximum)
            except MailboxRefusal as exc:
                from fastapi import HTTPException
                raise HTTPException(status_code=exc.status, detail="request too large") from exc
            # Existing authentication's request.body() reads this exact bounded raw body.
            request._body = raw
        return prepare

    @app.post("/internal/carlos/patients/{demographic_no}/mycarlos/deliveries",
              dependencies=[Depends(body_guard(MAX_UPLOAD))])
    async def upload(request: Request, demographic_no: int,
        principal: Annotated[object, Depends(deps.job_principal_requiring(JOB_DELIVERY_SYNC, PERMISSION_DELIVERY_UPLOAD))]):
        body = await request.body()
        def operation():
            try:
                if not 1 <= demographic_no <= 2147483647 or request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/octet-stream":
                    raise MailboxRefusal("invalid_delivery")
                value = parse_upload(body)
                with runtime.session_factory() as session, session.begin():
                    account_id = session.scalar(select(PatientPortalAccount.id).where(PatientPortalAccount.clinic_id == principal.clinic_id,
                        PatientPortalAccount.demographic_no == demographic_no))
                    if account_id is None:
                        raise MailboxRefusal("delivery_not_found", 404)
                    m = mailbox_lock(session, account_id=account_id, device_key_id=value.outer["device_key_id"],
                        clinic_id=principal.clinic_id, removed_status=409)
                    content, status = admit_upload(session, m, value, now=int(time()), limits=limits)
                return response(content, status)
            except MailboxRefusal as exc:
                return refusal_response(exc)
        return await run_in_threadpool(operation)

    @app.get("/internal/carlos/mycarlos/delivery-events", dependencies=[Depends(body_guard(0))])
    def events(request: Request,
        principal: Annotated[object, Depends(deps.job_principal_requiring(JOB_DELIVERY_SYNC, PERMISSION_DELIVERY_EVENTS_READ))]):
        try:
            after, limit, _values = query_values(request, {"after", "limit"}, maximum=50, default=25)
            with runtime.session_factory() as session, session.begin():
                clinic = clinic_lock(session, principal.clinic_id)
                content = events_page(session, clinic, after=after, limit=limit, now=int(time()), limits=limits)
            return response(content)
        except MailboxRefusal as exc:
            return refusal_response(exc)

    @app.post("/internal/carlos/mycarlos/delivery-events/ack", dependencies=[Depends(body_guard(1024))])
    async def ack(request: Request,
        principal: Annotated[object, Depends(deps.job_principal_requiring(JOB_DELIVERY_SYNC, PERMISSION_DELIVERY_EVENTS_ACK))]):
        body = await request.body()
        def operation():
            try:
                through = parse_ack(body)
                with runtime.session_factory() as session, session.begin():
                    clinic = clinic_lock(session, principal.clinic_id)
                    content = acknowledge_events(session, clinic, through=through)
                return response(content)
            except MailboxRefusal as exc:
                return refusal_response(exc)
        return await run_in_threadpool(operation)
