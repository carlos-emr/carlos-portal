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

"""Default-off frozen M3 HTTP adapter using existing device/job authentication."""

from collections.abc import Callable
from time import time
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import and_, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from carlos_patient_portal.approval_codec import (
    CONTRACT_VERSIONS,
    compact_hash,
    invalid,
    verify_approval,
)
from carlos_patient_portal.approval_models import ApprovalCode, ApprovalRequest
from carlos_patient_portal.approvals import (
    MAX_CODE_ATTEMPTS,
    approval_clinic,
    candidate_request,
    consume_code,
    erase_stale_codes,
    publish_challenge,
    publish_decision,
    request_row,
    scope,
    status_payload,
    submit_code,
    valid_code_r,
)
from carlos_patient_portal.device_identity import (
    DEVICE_ASSERTION_HEADER,
    DeviceRecord,
    DeviceRefusal,
    consume_device_assertion,
    find_device_record,
    verify_device_assertion,
)
from carlos_patient_portal.internal_routes import InternalRouteDependencies, InternalRuntime
from carlos_patient_portal.job_identity import JobPrincipal
from carlos_patient_portal.mailbox import (
    LockedMailbox,
    clinic_lock,
    mailbox_lock,
    next_sequence,
    record_request_anchor,
)
from carlos_patient_portal.mailbox_codec import (
    MailboxRefusal,
    canonical_key,
    strict_object,
    uuid_text,
)
from carlos_patient_portal.public_portal_base import normalize_portal
from carlos_patient_portal.routes.mycarlos import signed_path
from carlos_patient_portal.routes.mycarlos_mailbox import (
    bounded_body,
    limits_from_settings,
    query_values,
    refusal_response,
    response,
)
from carlos_patient_portal.runtime import PortalRuntime
from carlos_patient_portal.staff_identity import staff_request_hash
from carlos_patient_portal.system_jobs import (
    JOB_DEVICE_APPROVAL_SYNC,
    PERMISSION_APPROVAL_CHALLENGES_PUBLISH,
    PERMISSION_APPROVAL_CODES_CONSUME,
    PERMISSION_APPROVAL_CODES_READ,
    PERMISSION_APPROVAL_DECISIONS_PUBLISH,
    PERMISSION_APPROVAL_PROOFS_READ,
    PERMISSION_APPROVAL_REQUESTS_READ,
)

# Clinic code v1 (mycarlos#141): the device's body is exactly {"code_r": "<6 digits>"}.
CODE_BODY_LIMIT = 256
CODE_ATTEMPT_TEXT = frozenset(str(n) for n in range(1, MAX_CODE_ATTEMPTS + 1))


def body_object(raw: bytes, fields: set[str], limit: int = 32768) -> dict:
    value = strict_object(raw, limit=limit, code="invalid_approval")
    if set(value) != fields:
        raise invalid()
    return value


def register_device_approval_routes(app: FastAPI, runtime: PortalRuntime) -> None:
    settings = runtime.settings
    limits = limits_from_settings(settings)
    public_base = normalize_portal(settings.public_base_url)
    if public_base is None:
        raise ValueError("myCarlos approval requires a configured public base URL")

    def execute(request: Request, body: bytes, operation: Callable) -> Response:
        assertion = request.headers.get(DEVICE_ASSERTION_HEADER)
        request_hash = staff_request_hash(
            request.method,
            signed_path(runtime, request),
            request.scope.get("query_string", b""),
            body,
        )
        try:
            with runtime.session_factory() as lookup:
                verified_recipient: str | None = None

                def find_record(kid: str) -> DeviceRecord | None:
                    nonlocal verified_recipient
                    record = find_device_record(lookup, kid)
                    if record is not None:
                        verified_recipient = record.recipient_id
                    return record

                principal = verify_device_assertion(
                    assertion,
                    find_device=find_record,
                    expected_request_hash=request_hash,
                    now=int(time()),
                )
            consume_device_assertion(runtime.session_factory, principal, now=int(time()))
        except DeviceRefusal as exc:
            if exc.code in {"device_removed", "recipient_mismatch"}:
                return response({"code": exc.code}, 403)
            return response({"detail": "not found"}, 404)
        try:
            with runtime.session_factory() as session, session.begin():
                m = mailbox_lock(
                    session,
                    account_id=principal.account_id,
                    device_key_id=principal.device_key_id,
                    clinic_id=settings.clinic_id,
                )
                if m.recipient != verified_recipient or m.account.status != "active":
                    raise invalid("recipient_mismatch", 403)
                result = operation(session, m, body)
                record_request_anchor(
                    session,
                    m,
                    compact=assertion,
                    anchor=principal.vault_head_link,
                    now=int(time()),
                    limits=limits,
                )
            return result
        except MailboxRefusal as exc:
            return refusal_response(exc)

    async def call(request: Request, maximum: int, operation: Callable) -> Response:
        try:
            body = await bounded_body(request, maximum)
            if request.method == "GET" and body:
                raise invalid("invalid_assertion", 404)
        except MailboxRefusal as exc:
            return refusal_response(exc)
        return await run_in_threadpool(execute, request, body, operation)

    @app.post("/api/mycarlos/device-approval-requests")
    async def candidate(request: Request) -> Response:
        def operation(session: Session, m: LockedMailbox, raw: bytes) -> Response:
            if request.scope.get("query_string", b""):
                raise invalid()
            value = body_object(raw, {"intent"})
            content, status = candidate_request(
                session,
                m,
                intent=value["intent"],
                body=raw,
                public_base=public_base,
                now=int(time()),
            )
            return response(content, status)

        return await call(request, 32768, operation)

    @app.get("/api/mycarlos/device-approval-requests/{request_id}")
    async def status(request: Request, request_id: str) -> Response:
        def operation(session: Session, m: LockedMailbox, raw: bytes) -> Response:
            if request.scope.get("query_string", b"") or not uuid_text(request_id, version4=True):
                raise invalid("approval_not_found", 404)
            row = request_row(session, m, request_id)
            if row.device_id != m.device.id:
                raise invalid("approval_not_found", 404)
            return response(status_payload(row))

        return await call(request, 0, operation)

    # The device approval contract versions this portal takes (myCarlos #144). An app that
    # finds no such route (an older portal answers 404) signs v1.
    @app.get("/api/mycarlos/device-approval-versions")
    async def versions(request: Request) -> Response:
        def operation(session: Session, m: LockedMailbox, raw: bytes) -> Response:
            if request.scope.get("query_string", b""):
                raise invalid()
            return response({"versions": list(CONTRACT_VERSIONS)})

        return await call(request, 0, operation)

    @app.get("/api/mycarlos/device-approvals")
    async def approver_list(request: Request) -> Response:
        def operation(session: Session, m: LockedMailbox, raw: bytes) -> Response:
            after, limit, _ = query_values(request, {"after", "limit"}, maximum=20, default=10)
            rows = list(
                session.scalars(
                    select(ApprovalRequest)
                    .where(
                        ApprovalRequest.clinic_id == settings.clinic_id,
                        ApprovalRequest.account_id == m.account.id,
                        ApprovalRequest.predecessor_kid == m.device.device_key_id,
                        ApprovalRequest.challenge.is_not(None),
                        ApprovalRequest.challenge_sequence > after,
                        ApprovalRequest.status == "challenge_ready",
                        ApprovalRequest.expires_at > int(time()),
                    )
                    .order_by(ApprovalRequest.challenge_sequence)
                    .limit(limit + 1)
                )
            )
            more = len(rows) > limit
            rows = rows[:limit]
            last = rows[-1].challenge_sequence if rows else after
            return response(
                {
                    "requests": [
                        {
                            "sequence": str(row.challenge_sequence),
                            "request_id": row.request_id,
                            "intent": row.intent,
                            "challenge": row.challenge,
                        }
                        for row in rows
                    ],
                    "last_sequence": str(last),
                    "next_cursor": str(last) if more else None,
                }
            )

        return await call(request, 0, operation)

    @app.post("/api/mycarlos/device-approvals/{challenge_id}")
    async def approve(request: Request, challenge_id: str) -> Response:
        def operation(session: Session, m: LockedMailbox, raw: bytes) -> Response:
            if request.scope.get("query_string", b"") or not canonical_key(challenge_id):
                raise invalid()
            value = body_object(raw, {"approval"}, 16384)
            row = session.scalar(
                select(ApprovalRequest)
                .where(
                    ApprovalRequest.clinic_id == settings.clinic_id,
                    ApprovalRequest.account_id == m.account.id,
                    ApprovalRequest.challenge_id == challenge_id,
                )
                .with_for_update()
            )
            if row is None or row.predecessor_kid != m.device.device_key_id:
                raise invalid("approval_not_found", 404)
            if row.approval is not None:
                if row.approval != value["approval"]:
                    raise invalid("approval_conflict", 409)
                return response({"status": "received"})
            if row.status != "challenge_ready" or row.expires_at <= int(time()):
                raise invalid("approval_expired", 410)
            from carlos_patient_portal.approval_codec import compact_parts

            proof = verify_approval(
                value["approval"],
                predecessor_kid=m.device.device_key_id,
                predecessor_ed=m.device.ed25519_public_key,
                **scope(m, public_base),
            )
            challenge, _, _ = compact_parts(row.challenge)
            for field in (
                "v",
                "challenge_id",
                "candidate_intent_sha256",
                "candidate_device_key_id",
                "candidate_x25519_public_key",
                "candidate_ed25519_public_key",
                "predecessor_device_key_id",
                "predecessor_version",
            ):
                if proof[field] != challenge[field]:
                    raise invalid("approval_conflict", 409)
            if proof["challenge_sha256"] != compact_hash(row.challenge):
                raise invalid("approval_conflict", 409)
            row.approval = value["approval"]
            row.approval_sequence = next_sequence(
                approval_clinic(session, settings.clinic_id), "approval_sequence"
            )
            return response({"status": "received"})

        return await call(request, 16384, operation)

    @app.post("/api/mycarlos/device-approvals/{request_id}/code")
    async def submit(request: Request, request_id: str) -> Response:
        """Clinic code v1: store the code the patient entered, for CARLOS to compare."""

        def operation(session: Session, m: LockedMailbox, raw: bytes) -> Response:
            if request.scope.get("query_string", b""):
                raise invalid()
            value = body_object(raw, {"code_r"}, CODE_BODY_LIMIT)
            if not valid_code_r(value["code_r"]):
                raise invalid()
            if not uuid_text(request_id, version4=True):
                raise invalid("approval_not_found", 404)
            row = request_row(session, m, request_id)
            submit_code(session, m, row, code_r=value["code_r"], now=int(time()))
            return response({"status": "submitted"}, 202)

        return await call(request, CODE_BODY_LIMIT, operation)


def register_internal_approval_routes(
    app: FastAPI, runtime: InternalRuntime, deps: InternalRouteDependencies
) -> None:
    public_base = normalize_portal(runtime.settings.public_base_url)
    if public_base is None:
        raise ValueError("myCarlos approval requires a configured public base URL")

    def guard(maximum: int) -> Callable:
        async def prepare(request: Request) -> None:
            try:
                request._body = await bounded_body(request, maximum)
            except MailboxRefusal as exc:
                raise HTTPException(status_code=exc.status, detail="request too large") from exc

        return prepare

    def listing(request: Request, principal: JobPrincipal, proofs: bool) -> Response:
        try:
            after, limit, _ = query_values(request, {"after", "limit"}, maximum=20, default=10)
            with runtime.session_factory() as session, session.begin():
                clinic_lock(session, principal.clinic_id)
                clinic = approval_clinic(session, principal.clinic_id)
                column = (
                    ApprovalRequest.approval_sequence
                    if proofs
                    else ApprovalRequest.request_sequence
                )
                latest = clinic.approval_sequence if proofs else clinic.request_sequence
                if after > latest:
                    raise invalid("invalid_cursor")
                rows = list(
                    session.scalars(
                        select(ApprovalRequest)
                        .where(ApprovalRequest.clinic_id == principal.clinic_id, column > after)
                        .order_by(column)
                        .limit(limit + 1)
                    )
                )
                more = len(rows) > limit
                rows = rows[:limit]
                last = (
                    (rows[-1].approval_sequence if proofs else rows[-1].request_sequence)
                    if rows
                    else after
                )
                if proofs:
                    records = [
                        {
                            "sequence": str(row.approval_sequence),
                            "request_id": row.request_id,
                            "challenge_id": row.challenge_id,
                            "approval": row.approval,
                        }
                        for row in rows
                    ]
                else:
                    records = [
                        {
                            "sequence": str(row.request_sequence),
                            "demographic_no": row.demographic_no,
                            "intent": row.intent,
                        }
                        for row in rows
                    ]
                content = {
                    "approvals" if proofs else "requests": records,
                    "last_sequence": str(last),
                    "next_cursor": str(last) if more else None,
                }
            return response(content)
        except MailboxRefusal as exc:
            return refusal_response(exc)

    @app.get("/internal/carlos/mycarlos/device-approval-requests", dependencies=[Depends(guard(0))])
    def requests(
        request: Request,
        principal: Annotated[
            JobPrincipal,
            Depends(
                deps.job_principal_requiring(
                    JOB_DEVICE_APPROVAL_SYNC, PERMISSION_APPROVAL_REQUESTS_READ
                )
            ),
        ],
    ) -> Response:
        return listing(request, principal, False)

    @app.get("/internal/carlos/mycarlos/device-approvals", dependencies=[Depends(guard(0))])
    def approvals(
        request: Request,
        principal: Annotated[
            JobPrincipal,
            Depends(
                deps.job_principal_requiring(
                    JOB_DEVICE_APPROVAL_SYNC, PERMISSION_APPROVAL_PROOFS_READ
                )
            ),
        ],
    ) -> Response:
        return listing(request, principal, True)

    def publish(
        request: Request, principal: JobPrincipal, request_id: str, raw: bytes, challenge: bool
    ) -> Response:
        try:
            if not uuid_text(request_id, version4=True) or request.scope.get("query_string", b""):
                raise invalid()
            value = body_object(
                raw,
                {"intent", "challenge"}
                if challenge
                else {"challenge_id", "status", "acceptance", "reason"},
                32768 if challenge else 16384,
            )
            with runtime.session_factory() as lookup:
                target = lookup.get(ApprovalRequest, (principal.clinic_id, request_id))
                if target is None:
                    raise invalid("approval_not_found", 404)
                account, kid = target.account_id, target.candidate_kid
            with runtime.session_factory() as session, session.begin():
                m = mailbox_lock(
                    session,
                    account_id=account,
                    device_key_id=kid,
                    clinic_id=principal.clinic_id,
                    allow_removed=not challenge,
                )
                row = request_row(session, m, request_id)
                if challenge:
                    publish_challenge(
                        session,
                        m,
                        row,
                        intent=value["intent"],
                        challenge=value["challenge"],
                        public_base=public_base,
                        now=int(time()),
                    )
                else:
                    if m.device.status != "active" and row.decision_body_hash is None:
                        raise invalid("device_removed", 403)
                    publish_decision(
                        session, m, row, value=value, body=raw, public_base=public_base
                    )
            return response({"status": "stored"})
        except MailboxRefusal as exc:
            return refusal_response(exc)

    @app.get("/internal/carlos/mycarlos/device-approval-codes", dependencies=[Depends(guard(0))])
    def codes(
        request: Request,
        principal: Annotated[
            JobPrincipal,
            Depends(
                deps.job_principal_requiring(
                    JOB_DEVICE_APPROVAL_SYNC, PERMISSION_APPROVAL_CODES_READ
                )
            ),
        ],
    ) -> Response:
        """Clinic code v1: submitted codes after a per-clinic cursor, for CARLOS to compare."""
        try:
            after, limit, _ = query_values(request, {"after", "limit"}, maximum=20, default=10)
            with runtime.session_factory() as session, session.begin():
                clinic_lock(session, principal.clinic_id)
                if after > approval_clinic(session, principal.clinic_id).code_sequence:
                    raise invalid("invalid_cursor")
                erase_stale_codes(session, principal.clinic_id, int(time()))
                rows = list(
                    session.execute(
                        select(ApprovalCode, ApprovalRequest.challenge_id)
                        .join(
                            ApprovalRequest,
                            and_(
                                ApprovalRequest.clinic_id == ApprovalCode.clinic_id,
                                ApprovalRequest.request_id == ApprovalCode.request_id,
                            ),
                        )
                        .where(
                            ApprovalCode.clinic_id == principal.clinic_id,
                            ApprovalCode.code_sequence > after,
                        )
                        .order_by(ApprovalCode.code_sequence)
                        .limit(limit + 1)
                    )
                )
                more = len(rows) > limit
                rows = rows[:limit]
                last = rows[-1][0].code_sequence if rows else after
                content = {
                    "codes": [
                        {
                            "sequence": str(code.code_sequence),
                            "request_id": code.request_id,
                            "challenge_id": challenge_id,
                            "attempt": code.attempt,
                            "code_r": code.code_r,
                            "submitted_at": code.submitted_at,
                        }
                        for code, challenge_id in rows
                    ],
                    "last_sequence": str(last),
                    "next_cursor": str(last) if more else None,
                }
            return response(content)
        except MailboxRefusal as exc:
            return refusal_response(exc)

    @app.put(
        "/internal/carlos/mycarlos/device-approval-requests/{request_id}/codes/{attempt}/consumed",
        dependencies=[Depends(guard(0))],
    )
    def consumed(
        request: Request,
        request_id: str,
        attempt: str,
        principal: Annotated[
            JobPrincipal,
            Depends(
                deps.job_principal_requiring(
                    JOB_DEVICE_APPROVAL_SYNC, PERMISSION_APPROVAL_CODES_CONSUME
                )
            ),
        ],
    ) -> Response:
        """Clinic code v1: CARLOS has compared this code; erase it (idempotent)."""
        try:
            if request.scope.get("query_string", b""):
                raise invalid()
            if not uuid_text(request_id, version4=True) or attempt not in CODE_ATTEMPT_TEXT:
                raise invalid("approval_not_found", 404)
            with runtime.session_factory() as session, session.begin():
                consume_code(session, principal.clinic_id, request_id, int(attempt), int(time()))
            return response({"status": "consumed"})
        except MailboxRefusal as exc:
            return refusal_response(exc)

    @app.put(
        "/internal/carlos/mycarlos/device-approval-requests/{request_id}/challenge",
        dependencies=[Depends(guard(32768))],
    )
    async def challenge(
        request: Request,
        request_id: str,
        principal: Annotated[
            JobPrincipal,
            Depends(
                deps.job_principal_requiring(
                    JOB_DEVICE_APPROVAL_SYNC, PERMISSION_APPROVAL_CHALLENGES_PUBLISH
                )
            ),
        ],
    ) -> Response:
        return await run_in_threadpool(
            publish, request, principal, request_id, await request.body(), True
        )

    @app.put(
        "/internal/carlos/mycarlos/device-approval-requests/{request_id}/decision",
        dependencies=[Depends(guard(16384))],
    )
    async def decision(
        request: Request,
        request_id: str,
        principal: Annotated[
            JobPrincipal,
            Depends(
                deps.job_principal_requiring(
                    JOB_DEVICE_APPROVAL_SYNC, PERMISSION_APPROVAL_DECISIONS_PUBLISH
                )
            ),
        ],
    ) -> Response:
        return await run_in_threadpool(
            publish, request, principal, request_id, await request.body(), False
        )
