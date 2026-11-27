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

"""Payment requests: a clinic asks a patient to pay an amount it recorded in CARLOS (Phase 0).

CARLOS creates a request through the internal API; the patient reads it after signing in, with the
clinic's own instructions for how to pay. The portal takes no payment and holds no card data: staff
record the payment in CARLOS, which then tells the portal the request is paid. A request is built
from a closed vocabulary and integers, never from staff text: an opaque invoice reference, the
amount due now in cents with its tax portion, a category, a due date and a status. What a payment
was for would tell a reader about the care, so it is not here.
"""

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from carlos_patient_portal.audit import record_audit_event
from carlos_patient_portal.booking_offers import as_utc
from carlos_patient_portal.invites import (
    normalize_clinic_id,
    normalize_staff_actor,
    normalize_staff_actor_id,
    validate_demographic_no,
)
from carlos_patient_portal.models import (
    ACCOUNT_STATUS_ACTIVE,
    AUDIT_ACTOR_TYPE_PATIENT,
    AUDIT_ACTOR_TYPE_STAFF,
    AUDIT_EVENT_PAYMENT_REQUEST_CREATE,
    AUDIT_EVENT_PAYMENT_REQUEST_LIST,
    AUDIT_EVENT_PAYMENT_REQUEST_PAID,
    AUDIT_EVENT_PAYMENT_REQUEST_READ,
    AUDIT_EVENT_PAYMENT_REQUEST_WITHDRAW,
    AUDIT_OUTCOME_SUCCESS,
    MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH,
    MAX_PAYMENT_AMOUNT_CENTS,
    MAX_PAYMENT_INVOICE_REF_LENGTH,
    MIN_PAYMENT_AMOUNT_CENTS,
    PAYMENT_REQUEST_CATEGORIES,
    PAYMENT_REQUEST_CURRENCY,
    PAYMENT_REQUEST_METHODS,
    PAYMENT_REQUEST_STATE_EXPIRED,
    PAYMENT_REQUEST_STATUS_PAID,
    PAYMENT_REQUEST_STATUS_READ,
    PAYMENT_REQUEST_STATUS_SENT,
    PAYMENT_REQUEST_STATUS_WITHDRAWN,
    PatientPortalAccount,
    PatientPortalPaymentRequest,
    utc_now,
)

# The staff list and the patient's messages are capped rather than paginated, as for booking
# prompts.
MAX_STAFF_PAYMENT_REQUEST_LIST = 100
MAX_PATIENT_PAYMENT_REQUEST_LIST = 50
# A due date is a plain date a person reads: today up to a year ahead.
MAX_DUE_DAYS_AHEAD = 365


class PaymentRequestNotFoundError(Exception):
    """Raised when a request does not exist in the caller's scope."""


class PaymentRequestPastDueError(ValueError):
    """No matching operation exists, and the clinic date precludes a later create."""


class PaymentRequestAccountUnavailableError(Exception):
    """Raised when the patient has no active portal account to receive a request."""


class PaymentRequestOperationConflictError(Exception):
    """Raised when an operation id or invoice reference is reused for a different request."""


class PaymentRequestStateConflictError(Exception):
    """Raised when a request's state cannot take the change (for example paying a withdrawn one)."""


@dataclass(frozen=True, slots=True)
class CreatedPaymentRequest:
    request: PatientPortalPaymentRequest
    created: bool


# Statuses that expiry does not override: a request that was paid or withdrawn stays so.
_STATUSES_THAT_DO_NOT_EXPIRE = frozenset(
    {PAYMENT_REQUEST_STATUS_PAID, PAYMENT_REQUEST_STATUS_WITHDRAWN}
)


def payment_request_state(
    request: PatientPortalPaymentRequest, *, now: datetime | None = None
) -> str:
    """The state CARLOS and the patient see: sent, read, paid, withdrawn, or expired.

    Expired is not stored: it is a sent or read request past its expiry.
    """
    if request.status in _STATUSES_THAT_DO_NOT_EXPIRE:
        return request.status
    if as_utc(request.expires_at) <= (now or utc_now()):
        return PAYMENT_REQUEST_STATE_EXPIRED
    return request.status


def _normalize_operation_id(operation_id: str) -> str:
    normalized = operation_id.strip()
    if not normalized or len(normalized) > MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH:
        raise ValueError(
            f"operation_id must be 1 to {MAX_BOOKING_PROMPT_OPERATION_ID_LENGTH} characters"
        )
    return normalized


def _normalize_invoice_ref(invoice_ref: str) -> str:
    """An opaque reference: letters, digits, dashes and underscores only, never free text."""
    normalized = invoice_ref.strip()
    if (
        not normalized
        or len(normalized) > MAX_PAYMENT_INVOICE_REF_LENGTH
        or not all(char.isascii() and (char.isalnum() or char in "-_") for char in normalized)
    ):
        raise ValueError("invoice_ref must be an opaque reference of letters, digits, - and _")
    return normalized


@dataclass(frozen=True, slots=True)
class _RequestValues:
    demographic_no: int
    invoice_ref: str
    category: str
    payment_method: str
    amount_cents: int
    tax_cents: int
    due_on: date

    def matches(self, request: PatientPortalPaymentRequest) -> bool:
        return (
            request.demographic_no == self.demographic_no
            and request.invoice_ref == self.invoice_ref
            and request.category == self.category
            and request.payment_method == self.payment_method
            and request.amount_cents == self.amount_cents
            and request.tax_cents == self.tax_cents
            and request.due_on == self.due_on
        )


def _request_for_operation(
    session: Session, *, clinic_id: str, operation_id: str
) -> PatientPortalPaymentRequest | None:
    return session.scalar(
        select(PatientPortalPaymentRequest)
        .where(
            PatientPortalPaymentRequest.clinic_id == clinic_id,
            PatientPortalPaymentRequest.operation_id == operation_id,
        )
        .with_for_update()
    )


def _request_for_invoice(
    session: Session, *, clinic_id: str, invoice_ref: str
) -> PatientPortalPaymentRequest | None:
    return session.scalar(
        select(PatientPortalPaymentRequest).where(
            PatientPortalPaymentRequest.clinic_id == clinic_id,
            PatientPortalPaymentRequest.invoice_ref == invoice_ref,
        )
    )


def _retry_result(
    request: PatientPortalPaymentRequest, values: _RequestValues
) -> CreatedPaymentRequest:
    """A repeated operation returns its request; the same id for a different request is refused."""
    if not values.matches(request):
        raise PaymentRequestOperationConflictError()
    return CreatedPaymentRequest(request=request, created=False)


def payment_account_conditions(
    clinic_id: str, demographic_no: int
) -> tuple[ColumnElement[bool], ...]:
    """Which account can receive a payment request: the patient's active account in this clinic."""
    return (
        PatientPortalAccount.clinic_id == clinic_id,
        PatientPortalAccount.demographic_no == demographic_no,
        PatientPortalAccount.status == ACCOUNT_STATUS_ACTIVE,
    )


def create_payment_request(
    session: Session,
    *,
    clinic_id: str,
    demographic_no: int,
    operation_id: str,
    invoice_ref: str,
    category: str,
    payment_method: str,
    currency: str,
    amount_cents: int,
    tax_cents: int,
    due_on: date,
    created_by: str,
    created_by_id: str | None,
    ttl: timedelta,
    timezone_name: str = "UTC",
    lookup_only: bool = False,
    today: date | None = None,
    now: datetime | None = None,
) -> CreatedPaymentRequest:
    """Create a request in one transaction.

    Retrying the same operation returns the same request and writes nothing more. The same
    operation, or the same invoice reference, with different values is refused. A patient without
    an active account gets nothing stored, so CARLOS can tell staff to contact them another way.

    "Today" for the due date is the date in the clinic's time zone (``timezone_name``), not UTC:
    after about 19:00 in Ontario the UTC date is already tomorrow, and a due date of today must
    still be accepted then. ``today`` and ``now`` exist so a test can fix the clock.
    """
    validate_demographic_no(demographic_no)
    if category not in PAYMENT_REQUEST_CATEGORIES:
        raise ValueError("category is not supported")
    if payment_method not in PAYMENT_REQUEST_METHODS:
        raise ValueError("payment_method is not supported")
    if currency != PAYMENT_REQUEST_CURRENCY:
        raise ValueError("currency is not supported")
    if isinstance(amount_cents, bool) or not isinstance(amount_cents, int):
        raise ValueError("amount_cents must be an integer")
    if isinstance(tax_cents, bool) or not isinstance(tax_cents, int):
        raise ValueError("tax_cents must be an integer")
    if not MIN_PAYMENT_AMOUNT_CENTS <= amount_cents <= MAX_PAYMENT_AMOUNT_CENTS:
        raise ValueError("amount_cents is out of range")
    if not 0 <= tax_cents <= amount_cents:
        raise ValueError("tax_cents must be between 0 and amount_cents")
    if ttl <= timedelta(0):
        raise ValueError("ttl must be positive")
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    normalized_operation_id = _normalize_operation_id(operation_id)
    normalized_invoice_ref = _normalize_invoice_ref(invoice_ref)
    normalized_created_by = normalize_staff_actor(created_by)
    normalized_created_by_id = normalize_staff_actor_id(created_by_id, normalized_created_by)
    values = _RequestValues(
        demographic_no=demographic_no,
        invoice_ref=normalized_invoice_ref,
        category=category,
        payment_method=payment_method,
        amount_cents=amount_cents,
        tax_cents=tax_cents,
        due_on=due_on,
    )

    # Serialize same-patient creates and probes before reading the operation and clinic clock.
    # A probe that reports a past-due miss must see any earlier writer's committed operation.
    account = session.scalar(
        select(PatientPortalAccount)
        .where(*payment_account_conditions(normalized_clinic_id, demographic_no))
        .with_for_update()
    )
    existing = _request_for_operation(
        session, clinic_id=normalized_clinic_id, operation_id=normalized_operation_id
    )
    if existing is not None:
        return _retry_result(existing, values)
    now = now or utc_now()
    first_day = today or as_utc(now).astimezone(ZoneInfo(timezone_name)).date()
    if due_on < first_day:
        raise PaymentRequestPastDueError("due_on is before today")
    if lookup_only:
        raise PaymentRequestNotFoundError()
    if due_on > first_day + timedelta(days=MAX_DUE_DAYS_AHEAD):
        raise ValueError("due_on must be from today to a year ahead")
    # One request per invoice reference: a different operation for the same reference is a second
    # request for the same invoice, which staff withdraw and resend rather than stack.
    if (
        _request_for_invoice(
            session, clinic_id=normalized_clinic_id, invoice_ref=normalized_invoice_ref
        )
        is not None
    ):
        raise PaymentRequestOperationConflictError()

    if account is None:
        raise PaymentRequestAccountUnavailableError()

    request = PatientPortalPaymentRequest(
        clinic_id=normalized_clinic_id,
        demographic_no=demographic_no,
        account_id=account.id,
        operation_id=normalized_operation_id,
        invoice_ref=normalized_invoice_ref,
        category=category,
        payment_method=payment_method,
        currency=currency,
        amount_cents=amount_cents,
        tax_cents=tax_cents,
        status=PAYMENT_REQUEST_STATUS_SENT,
        created_by=normalized_created_by,
        created_by_id=normalized_created_by_id,
        created_at=now,
        due_on=due_on,
        expires_at=now + ttl,
    )
    try:
        with session.begin_nested():
            session.add(request)
            session.flush()
    except IntegrityError:
        # A retry sent while the first request was in flight loses the insert; it returns the
        # request the first one created. A clash on the invoice reference alone is a conflict.
        raced = _request_for_operation(
            session, clinic_id=normalized_clinic_id, operation_id=normalized_operation_id
        )
        if raced is None:
            raise PaymentRequestOperationConflictError() from None
        return _retry_result(raced, values)

    record_audit_event(
        session,
        event_type=AUDIT_EVENT_PAYMENT_REQUEST_CREATE,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor=normalized_created_by,
        actor_id=normalized_created_by_id,
        clinic_id=normalized_clinic_id,
        demographic_no=demographic_no,
        account_id=account.id,
        resource_type="payment_request",
        resource_id=str(request.id),
    )
    return CreatedPaymentRequest(request=request, created=True)


def list_payment_requests(
    session: Session,
    *,
    clinic_id: str,
    demographic_no: int,
    actor: str,
    actor_id: str | None,
) -> list[PatientPortalPaymentRequest]:
    """The patient's requests, newest first, for staff; the listing itself is audited."""
    validate_demographic_no(demographic_no)
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    normalized_actor = normalize_staff_actor(actor)
    requests = list(
        session.scalars(
            select(PatientPortalPaymentRequest)
            .where(
                PatientPortalPaymentRequest.clinic_id == normalized_clinic_id,
                PatientPortalPaymentRequest.demographic_no == demographic_no,
            )
            .order_by(
                PatientPortalPaymentRequest.created_at.desc(),
                PatientPortalPaymentRequest.id.desc(),
            )
            .limit(MAX_STAFF_PAYMENT_REQUEST_LIST)
        )
    )
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_PAYMENT_REQUEST_LIST,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor=normalized_actor,
        actor_id=normalize_staff_actor_id(actor_id, normalized_actor),
        clinic_id=normalized_clinic_id,
        demographic_no=demographic_no,
        resource_type="payment_request",
    )
    return requests


def _locked_request(
    session: Session, request_id: int, clinic_id: str
) -> PatientPortalPaymentRequest:
    request = session.scalar(
        select(PatientPortalPaymentRequest)
        .where(
            PatientPortalPaymentRequest.id == request_id,
            PatientPortalPaymentRequest.clinic_id == clinic_id,
        )
        .with_for_update()
    )
    if request is None:
        raise PaymentRequestNotFoundError()
    return request


def withdraw_payment_request(
    session: Session,
    request_id: int,
    *,
    clinic_id: str,
    withdrawn_by: str,
    withdrawn_by_id: str | None,
) -> PatientPortalPaymentRequest:
    """Withdraw a request, for example once the invoice changed. Withdrawing again is a no-op.

    A paid request cannot be withdrawn: the money is recorded, so it stays as a record of payment.
    """
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    normalized_actor = normalize_staff_actor(withdrawn_by)
    normalized_actor_id = normalize_staff_actor_id(withdrawn_by_id, normalized_actor)
    request = _locked_request(session, request_id, normalized_clinic_id)
    if request.status == PAYMENT_REQUEST_STATUS_WITHDRAWN:
        return request
    if request.status == PAYMENT_REQUEST_STATUS_PAID:
        raise PaymentRequestStateConflictError()
    request.status = PAYMENT_REQUEST_STATUS_WITHDRAWN
    request.withdrawn_at = utc_now()
    request.withdrawn_by = normalized_actor
    request.withdrawn_by_id = normalized_actor_id
    session.flush()
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_PAYMENT_REQUEST_WITHDRAW,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor=normalized_actor,
        actor_id=normalized_actor_id,
        clinic_id=normalized_clinic_id,
        demographic_no=request.demographic_no,
        account_id=request.account_id,
        resource_type="payment_request",
        resource_id=str(request.id),
    )
    return request


def mark_payment_request_paid(
    session: Session,
    request_id: int,
    *,
    clinic_id: str,
    paid_by: str,
    paid_by_id: str | None,
) -> PatientPortalPaymentRequest:
    """Record that CARLOS recorded the payment. Paying again is a no-op, so a retry is safe.

    A withdrawn request cannot be paid: staff withdrew it, so the payment belongs to a request the
    patient no longer sees; CARLOS must resend one. An expired but unpaid request can still be
    paid (the clinic took the money), and shows as paid.
    """
    normalized_clinic_id = normalize_clinic_id(clinic_id)
    normalized_actor = normalize_staff_actor(paid_by)
    normalized_actor_id = normalize_staff_actor_id(paid_by_id, normalized_actor)
    request = _locked_request(session, request_id, normalized_clinic_id)
    if request.status == PAYMENT_REQUEST_STATUS_PAID:
        return request
    if request.status == PAYMENT_REQUEST_STATUS_WITHDRAWN:
        raise PaymentRequestStateConflictError()
    request.status = PAYMENT_REQUEST_STATUS_PAID
    request.paid_at = utc_now()
    session.flush()
    record_audit_event(
        session,
        event_type=AUDIT_EVENT_PAYMENT_REQUEST_PAID,
        outcome=AUDIT_OUTCOME_SUCCESS,
        actor_type=AUDIT_ACTOR_TYPE_STAFF,
        actor=normalized_actor,
        actor_id=normalized_actor_id,
        clinic_id=normalized_clinic_id,
        demographic_no=request.demographic_no,
        account_id=request.account_id,
        resource_type="payment_request",
        resource_id=str(request.id),
    )
    return request


def _visible_to_account(account_id: int, now: datetime) -> tuple[ColumnElement[bool], ...]:
    """Which of an account's requests the patient sees.

    A sent or read request before its expiry, and a paid one (for a record of payment) for as long
    as the portal keeps it; a withdrawn or expired unpaid one drops out.
    """
    return (
        PatientPortalPaymentRequest.account_id == account_id,
        (PatientPortalPaymentRequest.status == PAYMENT_REQUEST_STATUS_PAID)
        | (
            PatientPortalPaymentRequest.status.in_(
                (PAYMENT_REQUEST_STATUS_SENT, PAYMENT_REQUEST_STATUS_READ)
            )
            & (PatientPortalPaymentRequest.expires_at > now)
        ),
    )


def list_visible_requests_for_account(
    session: Session, account_id: int
) -> list[PatientPortalPaymentRequest]:
    """The patient's requests, newest first."""
    return list(
        session.scalars(
            select(PatientPortalPaymentRequest)
            .where(*_visible_to_account(account_id, utc_now()))
            .order_by(
                PatientPortalPaymentRequest.created_at.desc(),
                PatientPortalPaymentRequest.id.desc(),
            )
            .limit(MAX_PATIENT_PAYMENT_REQUEST_LIST)
        )
    )


def count_unread_requests_for_account(session: Session, account_id: int) -> int:
    return (
        session.scalar(
            select(func.count(PatientPortalPaymentRequest.id)).where(
                *_visible_to_account(account_id, utc_now()),
                PatientPortalPaymentRequest.status == PAYMENT_REQUEST_STATUS_SENT,
            )
        )
        or 0
    )


def open_payment_request(
    session: Session,
    request_id: int,
    *,
    account: PatientPortalAccount,
) -> PatientPortalPaymentRequest:
    """Show one of the patient's requests, recording the first time they open it."""
    request = session.scalar(
        select(PatientPortalPaymentRequest)
        .where(
            PatientPortalPaymentRequest.id == request_id,
            PatientPortalPaymentRequest.clinic_id == account.clinic_id,
            *_visible_to_account(account.id, utc_now()),
        )
        .with_for_update()
    )
    if request is None:
        raise PaymentRequestNotFoundError()
    if request.status == PAYMENT_REQUEST_STATUS_SENT:
        request.status = PAYMENT_REQUEST_STATUS_READ
        request.read_at = utc_now()
        session.flush()
        record_audit_event(
            session,
            event_type=AUDIT_EVENT_PAYMENT_REQUEST_READ,
            outcome=AUDIT_OUTCOME_SUCCESS,
            actor_type=AUDIT_ACTOR_TYPE_PATIENT,
            actor=account.username,
            actor_id=str(account.id),
            clinic_id=account.clinic_id,
            demographic_no=account.demographic_no,
            account_id=account.id,
            resource_type="payment_request",
            resource_id=str(request.id),
        )
    return request
