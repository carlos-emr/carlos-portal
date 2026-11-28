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

"""The internal API CARLOS uses for payment requests (billing through the portal, Phase 0).

CARLOS calls the portal. Staff routes require `portal.payment.manage`. Only the signed settlement
job may call the hourly reporting route. A request holds an opaque invoice
reference, the amount due now in cents with its tax portion, a category from a closed vocabulary,
how the patient is told to pay, a due date and a status: no description, no patient name, no free
text. The refusals' `detail` texts are part of the contract and carry no request detail.

- `POST   /internal/carlos/patients/{demographic_no}/payment-requests`   create (idempotent)
- `GET    /internal/carlos/patients/{demographic_no}/payment-requests`   list the patient's latest
- `POST   /internal/carlos/payment-requests/{id}/withdraw`               withdraw (idempotent)
- `POST   /internal/carlos/payment-requests/{id}/paid`                   CARLOS recorded the payment
"""

from datetime import date, datetime, timedelta
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Path, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from carlos_patient_portal.internal_routes import (
    COMMON_INTERNAL_RESPONSES,
    INTERNAL_ACCOUNT_NOT_FOUND_DETAIL,
    INTERNAL_CONFLICT_RESPONSES,
    MAX_DEMOGRAPHIC_NO,
    InternalRouteDependencies,
    InternalRuntime,
    StaffPrincipal,
)
from carlos_patient_portal.job_identity import JobPrincipal
from carlos_patient_portal.models import (
    MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH,
    MAX_PAYMENT_AMOUNT_CENTS,
    MAX_PAYMENT_INVOICE_REF_LENGTH,
    MIN_PAYMENT_AMOUNT_CENTS,
    PatientPortalPaymentRequest,
)
from carlos_patient_portal.payment_requests import (
    PaymentRequestAccountUnavailableError,
    PaymentRequestNotFoundError,
    PaymentRequestOperationConflictError,
    PaymentRequestPastDueError,
    PaymentRequestStateConflictError,
    create_payment_request,
    list_payment_requests,
    mark_payment_request_paid,
    payment_request_state,
    report_paid_operation,
    withdraw_payment_request,
)
from carlos_patient_portal.runtime import MAX_DATABASE_ID
from carlos_patient_portal.system_jobs import JOB_PAYMENT_SETTLEMENT, PERMISSION_REPORT_PAID

# The staff assertion permission for staff routes here, like `portal.booking_prompt.manage`.
PERMISSION_PAYMENT_REQUEST_MANAGE = "portal.payment.manage"

# `detail` texts CARLOS tells outcomes apart by. None carries a request's content.
PAYMENT_REQUEST_NOT_FOUND_DETAIL = "payment request not found"
PAYMENT_REQUEST_OPERATION_CONFLICT_DETAIL = (
    "operation id or invoice reference was used for a different payment request"
)
PAYMENT_REQUEST_STATE_CONFLICT_DETAIL = "payment request is in a state this cannot apply to"
PAYMENT_REQUEST_INVALID_DETAIL = "payment request is invalid"
PAYMENT_REQUEST_PAST_DUE_DETAIL = "payment operation absent after its due date"

PaymentRequestStateName = Literal["sent", "read", "paid", "withdrawn", "expired"]


class PaymentOperationReferences(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    operation_id: str = Field(
        min_length=1,
        max_length=MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    # An opaque random reference CARLOS maps to its own invoice: never the invoice number, never
    # text. Letters, digits, dashes and underscores only.
    invoice_ref: str = Field(
        min_length=1,
        max_length=MAX_PAYMENT_INVOICE_REF_LENGTH,
        pattern=r"^[A-Za-z0-9_-]+$",
    )


class InternalSettlementReport(PaymentOperationReferences):
    request_id: int | None = Field(default=None, strict=True, gt=0, le=MAX_DATABASE_ID)


class InternalSettlementReceipt(PaymentOperationReferences):
    request_id: int
    demographic_no: int
    state: Literal["paid", "withdrawn"]


class InternalPaymentRequestRequest(PaymentOperationReferences):
    category: Literal["uninsured_service", "form_or_note", "missed_appointment", "other"]
    # How the patient is told to pay. A closed vocabulary: a processor's hosted page would be a
    # later value.
    payment_method: Literal["clinic_instructions"] = "clinic_instructions"
    currency: Literal["CAD"] = "CAD"
    # The amount due NOW, in cents, and the tax portion of it: integers, so nothing is rounded here.
    amount_cents: int = Field(ge=MIN_PAYMENT_AMOUNT_CENTS, le=MAX_PAYMENT_AMOUNT_CENTS, strict=True)
    tax_cents: int = Field(ge=0, le=MAX_PAYMENT_AMOUNT_CENTS, strict=True)
    due_on: date
    lookup_only: bool = Field(default=False, strict=True)


class InternalPaymentRequestResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    demographic_no: int
    invoice_ref: str
    category: str
    payment_method: str
    currency: str
    amount_cents: int
    tax_cents: int
    due_on: date
    state: PaymentRequestStateName
    created_by: str
    created_at: datetime
    expires_at: datetime
    read_at: datetime | None
    paid_at: datetime | None
    withdrawn_at: datetime | None
    withdrawn_by: str | None


class InternalPaymentRequestCreateResponse(InternalPaymentRequestResponse):
    created: bool


def payment_request_payload(request: PatientPortalPaymentRequest) -> dict[str, object]:
    return {
        "id": request.id,
        "demographic_no": request.demographic_no,
        "invoice_ref": request.invoice_ref,
        "category": request.category,
        "payment_method": request.payment_method,
        "currency": request.currency,
        "amount_cents": request.amount_cents,
        "tax_cents": request.tax_cents,
        "due_on": request.due_on,
        "state": payment_request_state(request),
        "created_by": request.created_by,
        "created_at": request.created_at,
        "expires_at": request.expires_at,
        "read_at": request.read_at,
        "paid_at": request.paid_at,
        "withdrawn_at": request.withdrawn_at,
        "withdrawn_by": request.withdrawn_by,
    }


def register_internal_payment_request_routes(
    app: FastAPI,
    runtime: InternalRuntime,
    deps: InternalRouteDependencies,
) -> None:
    """Register the staff routes and the job-only settlement report."""

    @app.post(
        "/internal/carlos/patients/{demographic_no}/payment-requests",
        status_code=status.HTTP_201_CREATED,
        response_model=InternalPaymentRequestCreateResponse,
        responses=INTERNAL_CONFLICT_RESPONSES,
    )
    def internal_create_payment_request(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        payload: InternalPaymentRequestRequest,
        principal: Annotated[
            StaffPrincipal,
            Depends(deps.staff_principal_requiring(PERMISSION_PAYMENT_REQUEST_MANAGE)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        try:
            result = create_payment_request(
                session,
                clinic_id=principal.clinic_id,
                demographic_no=demographic_no,
                operation_id=payload.operation_id,
                invoice_ref=payload.invoice_ref,
                category=payload.category,
                payment_method=payload.payment_method,
                currency=payload.currency,
                amount_cents=payload.amount_cents,
                tax_cents=payload.tax_cents,
                due_on=payload.due_on,
                created_by=principal.display_name,
                created_by_id=principal.provider_id,
                ttl=timedelta(days=runtime.settings.payment_request_ttl_days),
                timezone_name=runtime.settings.clinic_timezone,
                lookup_only=payload.lookup_only,
            )
        except PaymentRequestNotFoundError as exc:
            raise HTTPException(status_code=404, detail=PAYMENT_REQUEST_NOT_FOUND_DETAIL) from exc
        except PaymentRequestPastDueError as exc:
            raise HTTPException(status_code=422, detail=PAYMENT_REQUEST_PAST_DUE_DETAIL) from exc
        except PaymentRequestAccountUnavailableError as exc:
            # CARLOS tells staff to contact the patient another way; nothing was stored.
            raise HTTPException(status_code=404, detail=INTERNAL_ACCOUNT_NOT_FOUND_DETAIL) from exc
        except PaymentRequestOperationConflictError as exc:
            raise HTTPException(
                status_code=409, detail=PAYMENT_REQUEST_OPERATION_CONFLICT_DETAIL
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=PAYMENT_REQUEST_INVALID_DETAIL,
            ) from exc
        return {**payment_request_payload(result.request), "created": result.created}

    @app.get(
        "/internal/carlos/patients/{demographic_no}/payment-requests",
        response_model=list[InternalPaymentRequestResponse],
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_list_payment_requests(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        principal: Annotated[
            StaffPrincipal,
            Depends(deps.staff_principal_requiring(PERMISSION_PAYMENT_REQUEST_MANAGE)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> list[dict[str, object]]:
        requests = list_payment_requests(
            session,
            clinic_id=principal.clinic_id,
            demographic_no=demographic_no,
            actor=principal.display_name,
            actor_id=principal.provider_id,
        )
        return [payment_request_payload(request) for request in requests]

    @app.post(
        "/internal/carlos/payment-requests/{request_id}/withdraw",
        response_model=InternalPaymentRequestResponse,
        responses=INTERNAL_CONFLICT_RESPONSES,
    )
    def internal_withdraw_payment_request(
        request_id: Annotated[int, Path(gt=0, le=MAX_DATABASE_ID)],
        principal: Annotated[
            StaffPrincipal,
            Depends(deps.staff_principal_requiring(PERMISSION_PAYMENT_REQUEST_MANAGE)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        try:
            request = withdraw_payment_request(
                session,
                request_id,
                clinic_id=principal.clinic_id,
                withdrawn_by=principal.display_name,
                withdrawn_by_id=principal.provider_id,
            )
        except PaymentRequestNotFoundError as exc:
            raise HTTPException(status_code=404, detail=PAYMENT_REQUEST_NOT_FOUND_DETAIL) from exc
        except PaymentRequestStateConflictError as exc:
            raise HTTPException(
                status_code=409, detail=PAYMENT_REQUEST_STATE_CONFLICT_DETAIL
            ) from exc
        return payment_request_payload(request)

    @app.post(
        "/internal/carlos/payment-requests/{request_id}/paid",
        response_model=InternalPaymentRequestResponse,
        responses=INTERNAL_CONFLICT_RESPONSES,
    )
    def internal_mark_payment_request_paid(
        request_id: Annotated[int, Path(gt=0, le=MAX_DATABASE_ID)],
        principal: Annotated[
            StaffPrincipal,
            Depends(deps.staff_principal_requiring(PERMISSION_PAYMENT_REQUEST_MANAGE)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        try:
            request = mark_payment_request_paid(
                session,
                request_id,
                clinic_id=principal.clinic_id,
                paid_by=principal.display_name,
                paid_by_id=principal.provider_id,
            )
        except PaymentRequestNotFoundError as exc:
            raise HTTPException(status_code=404, detail=PAYMENT_REQUEST_NOT_FOUND_DETAIL) from exc
        except PaymentRequestStateConflictError as exc:
            raise HTTPException(
                status_code=409, detail=PAYMENT_REQUEST_STATE_CONFLICT_DETAIL
            ) from exc
        return payment_request_payload(request)

    @app.post(
        "/internal/carlos/patients/{demographic_no}/payment-settlements",
        response_model=InternalSettlementReceipt,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_report_paid_operation(
        demographic_no: Annotated[int, Path(gt=0, le=MAX_DEMOGRAPHIC_NO)],
        payload: InternalSettlementReport,
        principal: Annotated[
            JobPrincipal,
            Depends(deps.job_principal_requiring(JOB_PAYMENT_SETTLEMENT, PERMISSION_REPORT_PAID)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        try:
            request = report_paid_operation(
                session,
                principal,
                demographic_no=demographic_no,
                operation_id=payload.operation_id,
                invoice_ref=payload.invoice_ref,
                request_id=payload.request_id,
            )
        except PaymentRequestNotFoundError as exc:
            raise HTTPException(status_code=404, detail=PAYMENT_REQUEST_NOT_FOUND_DETAIL) from exc
        return {
            "request_id": request.id,
            "demographic_no": request.demographic_no,
            "operation_id": request.operation_id,
            "invoice_ref": request.invoice_ref,
            "state": request.status,
        }
