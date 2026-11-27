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

"""Payment requests (billing through the portal, Phase 0): CARLOS asks, the patient reads.

The portal takes no payment. A request carries an amount due now, its tax portion, a category, an
opaque invoice reference and a due date; the patient reads it in Messages and CARLOS marks it paid.
"""

from datetime import date, timedelta

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal.i18n import (
    SUPPORTED_LOCALES,
    format_cad,
    format_portal_date,
    portal_text,
)
from carlos_patient_portal.models import (
    AUDIT_EVENT_PAYMENT_REQUEST_CREATE,
    AUDIT_EVENT_PAYMENT_REQUEST_LIST,
    AUDIT_EVENT_PAYMENT_REQUEST_PAID,
    AUDIT_EVENT_PAYMENT_REQUEST_READ,
    AUDIT_EVENT_PAYMENT_REQUEST_WITHDRAW,
    PatientPortalAuditEvent,
    PatientPortalPaymentRequest,
    utc_now,
)
from tests.support import (
    INTERNAL_API_TOKEN,
    OUTBOX_ENCRYPTION_SECRET,
    activate_seeded_patient_account,
    alembic_config_for_tests,
    browser_sign_in_seeded_patient,
    carlos_staff_headers,
    migrated_development_app,
)
from tests.test_mycarlos_availability_store import migrated  # noqa: F401

PATH = "/internal/carlos/patients/1234/payment-requests"
PERMISSION = "portal.payment.manage"


def payment_app(**overrides: object):
    return migrated_development_app(
        **{
            "clinic_id": "clinic-a",
            "clinic_name": "Example Clinic",
            "internal_api_token": INTERNAL_API_TOKEN,
            "outbox_encryption_secret": OUTBOX_ENCRYPTION_SECRET,
            **overrides,
        }
    )


def headers(
    clinic_id: str = "clinic-a",
    permission: str = PERMISSION,
    provider_name: str = "Front Desk",
) -> dict[str, str]:
    return carlos_staff_headers(
        permission,
        clinic_id=clinic_id,
        token=INTERNAL_API_TOKEN,
        provider_name=provider_name,
    )


def request_body(**overrides: object) -> dict[str, object]:
    return {
        "operation_id": "pay-operation-1",
        "invoice_ref": "inv-7f3a9c",
        "category": "uninsured_service",
        "payment_method": "clinic_instructions",
        "currency": "CAD",
        "amount_cents": 4500,
        "tax_cents": 518,
        "due_on": (date.today() + timedelta(days=14)).isoformat(),
        **overrides,
    }


def audit_events(app, event_type: str) -> list[PatientPortalAuditEvent]:
    with app.state.session_factory() as session:
        return list(
            session.scalars(
                select(PatientPortalAuditEvent)
                .where(PatientPortalAuditEvent.event_type == event_type)
                .order_by(PatientPortalAuditEvent.id)
            )
        )


def stored_requests(app) -> list[PatientPortalPaymentRequest]:
    with app.state.session_factory() as session:
        return list(session.scalars(select(PatientPortalPaymentRequest)))


# --- creating ----------------------------------------------------------------------------------


def test_creating_a_request_stores_only_the_closed_fields_and_audits_it() -> None:
    app = payment_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)

    response = client.post(PATH, headers=headers(), json=request_body())

    assert response.status_code == 201
    body = response.json()
    assert body["created"] is True
    assert body["state"] == "sent"
    assert (body["amount_cents"], body["tax_cents"], body["currency"]) == (4500, 518, "CAD")
    assert body["invoice_ref"] == "inv-7f3a9c"
    assert body["created_by"] == "Front Desk"
    assert set(body) == {
        "id",
        "demographic_no",
        "invoice_ref",
        "category",
        "payment_method",
        "currency",
        "amount_cents",
        "tax_cents",
        "due_on",
        "state",
        "created_by",
        "created_at",
        "expires_at",
        "read_at",
        "paid_at",
        "withdrawn_at",
        "withdrawn_by",
        "created",
    }
    events = audit_events(app, AUDIT_EVENT_PAYMENT_REQUEST_CREATE)
    assert len(events) == 1
    assert events[0].demographic_no == 1234
    assert events[0].actor == "Front Desk"


def test_a_repeated_operation_returns_the_same_request_without_a_second_row() -> None:
    app = payment_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)

    first = client.post(PATH, headers=headers(), json=request_body()).json()
    second = client.post(PATH, headers=headers(), json=request_body()).json()

    assert second["id"] == first["id"]
    assert second["created"] is False
    assert len(stored_requests(app)) == 1


def test_an_operation_or_invoice_reused_with_other_values_is_a_409() -> None:
    app = payment_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    client.post(PATH, headers=headers(), json=request_body())

    other_amount = client.post(PATH, headers=headers(), json=request_body(amount_cents=9900))
    other_operation = client.post(PATH, headers=headers(), json=request_body(operation_id="second"))

    assert other_amount.status_code == 409
    assert other_operation.status_code == 409
    assert len(stored_requests(app)) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"amount_cents": 0},
        {"amount_cents": -5},
        {"amount_cents": 10_000_001},
        {"amount_cents": 12.5},
        {"amount_cents": "4500"},
        {"tax_cents": -1},
        {"category": "free text about a diagnosis"},
        {"payment_method": "credit_card"},
        {"currency": "USD"},
        {"invoice_ref": "has space"},
        {"invoice_ref": "x" * 65},
        {"invoice_ref": ""},
        {"operation_id": ""},
        {"due_on": "not-a-date"},
        {"description": "Dr. note for John Smith"},
    ],
)
def test_an_invalid_request_is_refused_and_stores_nothing(overrides: dict[str, object]) -> None:
    app = payment_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)

    response = client.post(PATH, headers=headers(), json=request_body(**overrides))

    assert response.status_code == 422
    assert stored_requests(app) == []


def test_tax_above_the_amount_is_refused() -> None:
    app = payment_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)

    response = client.post(
        PATH, headers=headers(), json=request_body(amount_cents=100, tax_cents=101)
    )

    assert response.status_code == 422
    assert stored_requests(app) == []


def test_a_patient_without_a_portal_account_is_a_404_and_nothing_is_stored() -> None:
    app = payment_app()
    client = TestClient(app)

    response = client.post(PATH, headers=headers(), json=request_body())

    assert response.status_code == 404
    assert stored_requests(app) == []


def test_staff_without_the_permission_or_of_another_clinic_are_refused() -> None:
    app = payment_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)

    no_permission = client.post(
        PATH, headers=headers(permission="portal.booking_prompt.manage"), json=request_body()
    )
    other_clinic = client.post(PATH, headers=headers(clinic_id="clinic-b"), json=request_body())
    anonymous = client.post(PATH, json=request_body())

    assert no_permission.status_code == 403
    assert other_clinic.status_code == 404
    # An unsigned caller is not told the internal API exists.
    assert anonymous.status_code == 404
    assert stored_requests(app) == []


# --- listing, withdrawing, paid ----------------------------------------------------------------


def test_listing_shows_newest_first_and_is_audited() -> None:
    app = payment_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    client.post(PATH, headers=headers(), json=request_body())
    client.post(
        PATH,
        headers=headers(),
        json=request_body(operation_id="second", invoice_ref="inv-second"),
    )

    listed = client.get(PATH, headers=headers())

    assert listed.status_code == 200
    assert [item["invoice_ref"] for item in listed.json()] == ["inv-second", "inv-7f3a9c"]
    assert len(audit_events(app, AUDIT_EVENT_PAYMENT_REQUEST_LIST)) == 1


def test_withdrawing_is_idempotent_and_a_paid_request_cannot_be_withdrawn() -> None:
    app = payment_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    first = client.post(PATH, headers=headers(), json=request_body()).json()["id"]
    second = client.post(
        PATH, headers=headers(), json=request_body(operation_id="b", invoice_ref="inv-b")
    ).json()["id"]

    withdraw_path = f"/internal/carlos/payment-requests/{first}/withdraw"
    withdrawn = client.post(withdraw_path, headers=headers())
    again = client.post(withdraw_path, headers=headers())
    paid = client.post(f"/internal/carlos/payment-requests/{second}/paid", headers=headers())
    refused = client.post(f"/internal/carlos/payment-requests/{second}/withdraw", headers=headers())

    assert withdrawn.status_code == 200
    assert withdrawn.json()["state"] == "withdrawn"
    assert again.status_code == 200
    assert paid.status_code == 200
    assert paid.json()["state"] == "paid"
    assert refused.status_code == 409
    assert len(audit_events(app, AUDIT_EVENT_PAYMENT_REQUEST_WITHDRAW)) == 1
    assert len(audit_events(app, AUDIT_EVENT_PAYMENT_REQUEST_PAID)) == 1


def test_a_withdrawn_request_cannot_be_marked_paid_and_paying_twice_is_a_no_op() -> None:
    app = payment_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    request_id = client.post(PATH, headers=headers(), json=request_body()).json()["id"]
    client.post(f"/internal/carlos/payment-requests/{request_id}/withdraw", headers=headers())

    refused = client.post(f"/internal/carlos/payment-requests/{request_id}/paid", headers=headers())

    assert refused.status_code == 409
    assert refused.json() == {"detail": "payment request is in a state this cannot apply to"}


def test_marking_paid_twice_is_a_no_op() -> None:
    app = payment_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    request_id = client.post(PATH, headers=headers(), json=request_body()).json()["id"]

    first = client.post(f"/internal/carlos/payment-requests/{request_id}/paid", headers=headers())
    second = client.post(f"/internal/carlos/payment-requests/{request_id}/paid", headers=headers())

    assert first.status_code == second.status_code == 200
    # SQLite hands the stored time back without its "Z"; the instant is what must not move.
    assert second.json()["paid_at"].rstrip("Z") == first.json()["paid_at"].rstrip("Z")
    assert len(audit_events(app, AUDIT_EVENT_PAYMENT_REQUEST_PAID)) == 1


def test_an_unknown_or_other_clinic_request_is_a_404() -> None:
    app = payment_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    request_id = client.post(PATH, headers=headers(), json=request_body()).json()["id"]

    unknown = client.post("/internal/carlos/payment-requests/999/withdraw", headers=headers())
    elsewhere = client.post(
        f"/internal/carlos/payment-requests/{request_id}/paid",
        headers=headers(clinic_id="clinic-b"),
    )

    assert unknown.status_code == 404
    assert unknown.json() == {"detail": "payment request not found"}
    assert elsewhere.status_code == 404
    assert stored_requests(app)[0].status == "sent"


# --- what the patient sees ---------------------------------------------------------------------


def test_the_patient_reads_the_amount_tax_and_due_date_and_opening_marks_it_read() -> None:
    app = payment_app(payment_instructions="Pay at the front desk or call 555-0100.")
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    staff = TestClient(app)
    request_id = staff.post(PATH, headers=headers(), json=request_body()).json()["id"]

    dashboard = client.get("/portal")
    messages = client.get("/portal/messages")
    opened = client.get(f"/portal/messages/payment/{request_id}")
    listed = staff.get(PATH, headers=headers()).json()

    assert "1 new" in dashboard.text
    assert messages.status_code == 200
    assert "A payment is requested for an uninsured service" in messages.text
    assert "45.00 CAD" in messages.text
    assert opened.status_code == 200
    assert "45.00 CAD" in opened.text
    assert "Includes 5.18 CAD in tax" in opened.text
    assert "Pay at the front desk or call 555-0100." in opened.text
    assert "You cannot pay on this site" in opened.text
    assert "<form" not in opened.text.split('class="message-detail payment-request-detail"')[1]
    assert listed[0]["state"] == "read"
    assert listed[0]["read_at"] is not None
    assert len(audit_events(app, AUDIT_EVENT_PAYMENT_REQUEST_READ)) == 1
    # Reopening does not record a second first-read.
    client.get(f"/portal/messages/payment/{request_id}")
    assert len(audit_events(app, AUDIT_EVENT_PAYMENT_REQUEST_READ)) == 1


def test_without_clinic_instructions_the_patient_is_told_to_contact_the_clinic() -> None:
    app = payment_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    request_id = TestClient(app).post(PATH, headers=headers(), json=request_body()).json()["id"]

    opened = client.get(f"/portal/messages/payment/{request_id}")

    assert "Please contact Example Clinic to arrange payment." in opened.text


def test_a_paid_request_shows_thanks_and_no_how_to_pay() -> None:
    app = payment_app(payment_instructions="Pay at the front desk.")
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    staff = TestClient(app)
    request_id = staff.post(PATH, headers=headers(), json=request_body()).json()["id"]
    staff.post(f"/internal/carlos/payment-requests/{request_id}/paid", headers=headers())

    opened = client.get(f"/portal/messages/payment/{request_id}")
    messages = client.get("/portal/messages")

    assert "Payment received. Thank you." in opened.text
    assert "Pay at the front desk." not in opened.text
    assert "How to pay" not in opened.text
    assert "Payment received. Thank you." in messages.text


def test_a_withdrawn_or_unknown_request_is_a_404_for_the_patient() -> None:
    app = payment_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    staff = TestClient(app)
    withdrawn = staff.post(PATH, headers=headers(), json=request_body()).json()["id"]
    staff.post(f"/internal/carlos/payment-requests/{withdrawn}/withdraw", headers=headers())

    gone = client.get(f"/portal/messages/payment/{withdrawn}")
    messages = client.get("/portal/messages")

    assert gone.status_code == 404
    assert "message-row" not in messages.text
    assert "You have no messages from your clinic." in messages.text
    assert client.get("/portal/messages/payment/99999").status_code == 404


def test_an_expired_unpaid_request_leaves_the_patients_messages_but_can_still_be_paid() -> None:
    app = payment_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    staff = TestClient(app)
    request_id = staff.post(PATH, headers=headers(), json=request_body()).json()["id"]
    with app.state.session_factory() as session:
        row = session.get(PatientPortalPaymentRequest, request_id)
        # The database requires expiry after creation, so age the request, not just its expiry.
        row.created_at = utc_now() - timedelta(days=2)
        row.expires_at = utc_now() - timedelta(minutes=1)
        session.commit()

    messages = client.get("/portal/messages")
    gone = client.get(f"/portal/messages/payment/{request_id}")
    listed = staff.get(PATH, headers=headers()).json()
    paid = staff.post(f"/internal/carlos/payment-requests/{request_id}/paid", headers=headers())

    assert "A payment is requested" not in messages.text
    assert gone.status_code == 404
    assert listed[0]["state"] == "expired"
    assert paid.status_code == 200
    assert paid.json()["state"] == "paid"


def test_the_signed_out_patient_is_redirected_not_shown_the_request() -> None:
    app = payment_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    request_id = TestClient(app).post(PATH, headers=headers(), json=request_body()).json()["id"]

    response = client.get(f"/portal/messages/payment/{request_id}", follow_redirects=False)

    assert response.status_code in {302, 303}
    assert "CAD" not in response.text


def test_the_invoice_reference_and_internal_ids_are_never_shown_to_the_patient() -> None:
    app = payment_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    request_id = TestClient(app).post(PATH, headers=headers(), json=request_body()).json()["id"]

    opened = client.get(f"/portal/messages/payment/{request_id}")

    assert "inv-7f3a9c" not in opened.text
    assert "pay-operation-1" not in opened.text


# --- wording and money -------------------------------------------------------------------------


def test_money_is_written_from_integer_cents_with_the_languages_decimal_mark() -> None:
    assert format_cad(4500) == "45.00 CAD"
    assert format_cad(5) == "0.05 CAD"
    assert format_cad(10_000_000) == "100000.00 CAD"
    assert format_cad(1250, "fr") == "12,50 CAD"
    assert format_cad(1250, "pt-BR") == "12,50 CAD"
    assert format_cad(1250, "zh-CN") == "12.50 CAD"


def test_dates_are_numbers_only_in_every_language() -> None:
    day = date(2026, 12, 9)

    assert format_portal_date(day, "en") == "2026-12-09"
    assert format_portal_date(day, "es") == "09/12/2026"
    assert format_portal_date(day, "zh-TW") == "2026年12月9日"


PAYMENT_KEYS = (
    "payment_request_amount",
    "payment_request_contact",
    "payment_request_due",
    "payment_request_how_to_pay",
    "payment_request_includes_tax",
    "payment_request_no_online",
    "payment_request_status_open",
    "payment_request_status_paid",
    "payment_request_form_or_note_title",
    "payment_request_missed_appointment_title",
    "payment_request_other_title",
    "payment_request_uninsured_service_title",
)


@pytest.mark.parametrize("code", [option.code for option in SUPPORTED_LOCALES])
def test_every_language_has_every_payment_string_with_its_placeholders(code: str) -> None:
    text = portal_text(code)
    english = portal_text("en")

    for key in PAYMENT_KEYS:
        assert text[key].strip(), key
        for placeholder in ("{tax}", "{due}", "{clinic_name}"):
            assert (placeholder in text[key]) == (placeholder in english[key]), (code, key)
    if code != "en":
        assert text["payment_request_other_title"] != english["payment_request_other_title"]


# --- the migration -----------------------------------------------------------------------------


def test_payment_requests_are_the_one_line_head_after_the_mfa_outcome() -> None:
    script = ScriptDirectory.from_config(alembic_config_for_tests())
    (head,) = script.get_heads()
    revision = script.get_revision("0028_payment_requests")

    # Whichever of this and the portal's older 0027/0028 pair merges second renumbers; this pin
    # makes that a visible test change rather than a silent second head.
    assert head == "0028_payment_requests"
    assert revision is not None
    assert revision.down_revision == "0027_mfa_resumed_outcome"


def test_the_database_refuses_a_request_that_breaks_the_amount_or_vocabulary_rules() -> None:
    app = payment_app()
    client = TestClient(app)
    account_id = activate_seeded_patient_account(app, client)

    def row(**overrides: object) -> PatientPortalPaymentRequest:
        values = {
            "clinic_id": "clinic-a",
            "demographic_no": 1234,
            "account_id": account_id,
            "operation_id": "op",
            "invoice_ref": "inv",
            "category": "other",
            "payment_method": "clinic_instructions",
            "currency": "CAD",
            "amount_cents": 100,
            "tax_cents": 0,
            "status": "sent",
            "created_by": "Front Desk",
            "created_at": utc_now(),
            "due_on": date.today(),
            "expires_at": utc_now() + timedelta(days=1),
            **overrides,
        }
        return PatientPortalPaymentRequest(**values)

    for bad in (
        {"amount_cents": 0},
        {"tax_cents": 101},
        {"category": "anything"},
        {"currency": "USD"},
        {"status": "refunded"},
    ):
        with app.state.session_factory() as session:
            session.add(row(**bad))
            with pytest.raises(IntegrityError):
                session.commit()
    assert stored_requests(app) == []


def test_downgrade_refuses_while_payment_audit_events_exist_and_then_works(migrated) -> None:  # noqa: F811
    engine, config = migrated
    with Session(engine) as session, session.begin():
        session.add(
            PatientPortalAuditEvent(
                event_type=AUDIT_EVENT_PAYMENT_REQUEST_LIST,
                outcome="success",
                actor_type="staff",
                created_at=utc_now(),
            )
        )

    with pytest.raises(RuntimeError, match="payment"):
        command.downgrade(config, "0027_mfa_resumed_outcome")
    with Session(engine) as session, session.begin():
        session.query(PatientPortalAuditEvent).delete()
    command.downgrade(config, "0027_mfa_resumed_outcome")
    command.upgrade(config, "head")
