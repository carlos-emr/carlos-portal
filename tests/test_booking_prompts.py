"""Booking prompts: CARLOS asks a patient to book, the patient reads it, nothing is booked."""

import logging
from datetime import timedelta
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect, select, text

from carlos_patient_portal.delivery_outbox import (
    OUTBOX_FAILURE_BOOKING_PROMPT_NOT_NEEDED,
    process_one_delivery,
)
from carlos_patient_portal.internal_routes import _booking_prompt_sign_in_url
from carlos_patient_portal.maintenance import cleanup_transient_auth_rows
from carlos_patient_portal.models import (
    AUDIT_EVENT_BOOKING_PROMPT_CREATE,
    AUDIT_EVENT_BOOKING_PROMPT_DELIVERY,
    AUDIT_EVENT_BOOKING_PROMPT_LIST,
    AUDIT_EVENT_BOOKING_PROMPT_READ,
    AUDIT_EVENT_BOOKING_PROMPT_WITHDRAW,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_SUCCESS,
    OUTBOX_KIND_BOOKING_PROMPT,
    OUTBOX_STATUS_DELIVERED,
    OUTBOX_STATUS_FAILED,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalBookingPrompt,
    PatientPortalOutboundDelivery,
    utc_now,
)
from carlos_patient_portal.outbound_messages import booking_prompt_email_message
from tests.support import (
    INTERNAL_API_TOKEN,
    OUTBOX_ENCRYPTION_SECRET,
    RecordingPortalEmailSender,
    activate_seeded_patient_account,
    browser_sign_in_seeded_patient,
    carlos_staff_headers,
    development_settings,
    migrated_development_app,
)

PATH = "/internal/carlos/patients/1234/booking-prompts"
PERMISSION = "portal.booking_prompt.manage"


def booking_app(**overrides: object):
    return migrated_development_app(
        **{
            "clinic_id": "clinic-a",
            "clinic_name": "Maple Clinic",
            "internal_api_token": INTERNAL_API_TOKEN,
            "outbox_encryption_secret": OUTBOX_ENCRYPTION_SECRET,
            **overrides,
        }
    )


def headers(clinic_id: str = "clinic-a", provider_name: str = "Front Desk") -> dict[str, str]:
    return carlos_staff_headers(
        PERMISSION,
        clinic_id=clinic_id,
        token=INTERNAL_API_TOKEN,
        provider_name=provider_name,
    )


def prompt_request(**overrides: object) -> dict[str, object]:
    return {
        "operation_id": "prompt-operation-1",
        "urgency": "as_soon_as_possible",
        "appointment_type": "follow_up",
        "suggested_by": "Dr. Singh",
        **overrides,
    }


def deliver_next(app, sender: RecordingPortalEmailSender):
    return process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        max_attempts=3,
        lease_seconds=60,
    )


def audit_events(app, event_type: str) -> list[PatientPortalAuditEvent]:
    with app.state.session_factory() as session:
        return list(
            session.scalars(
                select(PatientPortalAuditEvent)
                .where(PatientPortalAuditEvent.event_type == event_type)
                .order_by(PatientPortalAuditEvent.id)
            )
        )


def test_prompt_is_created_once_and_a_retry_returns_it_without_a_second_email() -> None:
    app = booking_app()
    client = TestClient(app)
    account_id = activate_seeded_patient_account(app, client)

    created = client.post(PATH, headers=headers(), json=prompt_request())
    repeated = client.post(PATH, headers=headers(), json=prompt_request())

    assert created.status_code == 201
    assert created.json()["created"] is True
    assert created.json()["state"] == "sent"
    assert created.json()["suggested_by"] == "Dr. Singh"
    assert created.json()["created_by"] == "Front Desk"
    assert repeated.status_code == 201
    assert repeated.json()["created"] is False
    assert repeated.json()["id"] == created.json()["id"]
    with app.state.session_factory() as session:
        prompts = list(session.scalars(select(PatientPortalBookingPrompt)))
        notices = list(
            session.scalars(
                select(PatientPortalOutboundDelivery).where(
                    PatientPortalOutboundDelivery.kind == OUTBOX_KIND_BOOKING_PROMPT
                )
            )
        )
    assert [prompt.account_id for prompt in prompts] == [account_id]
    assert [notice.booking_prompt_id for notice in notices] == [created.json()["id"]]
    events = audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_CREATE)
    assert [(event.actor, event.resource_id) for event in events] == [
        ("Front Desk", str(created.json()["id"]))
    ]


def test_reusing_an_operation_for_a_different_prompt_is_refused() -> None:
    app = booking_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    assert client.post(PATH, headers=headers(), json=prompt_request()).status_code == 201

    changed = client.post(PATH, headers=headers(), json=prompt_request(urgency="routine"))
    other_patient = client.post(
        "/internal/carlos/patients/5678/booking-prompts",
        headers=headers(),
        json=prompt_request(),
    )

    assert changed.status_code == 409
    assert changed.json() == {"detail": "operation id was used for a different booking prompt"}
    assert other_patient.status_code == 409


@pytest.mark.parametrize("account_state", ["none", "disabled"])
def test_patient_without_an_active_account_gets_a_404_and_nothing_is_stored(account_state) -> None:
    app = booking_app()
    client = TestClient(app)
    if account_state == "disabled":
        activate_seeded_patient_account(app, client)
        disabled = client.post(
            "/internal/carlos/patients/1234/portal-account/access",
            headers=carlos_staff_headers(
                "portal.account.manage", clinic_id="clinic-a", token=INTERNAL_API_TOKEN
            ),
            json={"enabled": False, "reason": "patient_requested"},
        )
        assert disabled.status_code == 200

    response = client.post(PATH, headers=headers(), json=prompt_request())

    assert response.status_code == 404
    assert response.json() == {"detail": "portal account not found"}
    with app.state.session_factory() as session:
        assert list(session.scalars(select(PatientPortalBookingPrompt))) == []
        assert list(session.scalars(select(PatientPortalOutboundDelivery))) == []


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(prompt_request(urgency="whenever"), id="unknown-urgency"),
        pytest.param(prompt_request(appointment_type="surgery"), id="unknown-type"),
        pytest.param(prompt_request(operation_id="has space"), id="operation-id-format"),
        pytest.param(prompt_request(suggested_by="Dr.\x00Singh"), id="suggested-by-control"),
        pytest.param({**prompt_request(), "note": "free text"}, id="free-text-field"),
    ],
)
def test_prompt_accepts_only_its_fixed_vocabulary(body) -> None:
    app = booking_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)

    response = client.post(PATH, headers=headers(), json=body)

    assert response.status_code == 422
    with app.state.session_factory() as session:
        assert list(session.scalars(select(PatientPortalBookingPrompt))) == []


def test_another_clinic_cannot_create_list_or_withdraw_prompts() -> None:
    app = booking_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    created_elsewhere = client.post(
        PATH, headers=headers(clinic_id="clinic-b"), json=prompt_request(operation_id="other")
    )
    with app.state.session_factory() as session:
        assert list(session.scalars(select(PatientPortalBookingPrompt))) == []
        assert list(session.scalars(select(PatientPortalOutboundDelivery))) == []
    prompt_id = client.post(PATH, headers=headers(), json=prompt_request()).json()["id"]

    listed = client.get(PATH, headers=headers(clinic_id="clinic-b"))
    withdrawn = client.post(
        f"/internal/carlos/booking-prompts/{prompt_id}/withdraw",
        headers=headers(clinic_id="clinic-b"),
    )

    # A portal serves one clinic, so another clinic's staff are refused before any lookup.
    assert created_elsewhere.status_code == 404
    assert listed.status_code == 404
    assert withdrawn.status_code == 404
    with app.state.session_factory() as session:
        assert session.get(PatientPortalBookingPrompt, prompt_id).status == "sent"


def test_withdrawing_an_unknown_prompt_is_a_404() -> None:
    app = booking_app()
    client = TestClient(app)

    response = client.post("/internal/carlos/booking-prompts/999/withdraw", headers=headers())

    assert response.status_code == 404
    assert response.json() == {"detail": "booking prompt not found"}


def test_notice_says_only_that_a_message_is_waiting_and_is_recorded() -> None:
    app = booking_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    prompt_id = client.post(PATH, headers=headers(), json=prompt_request()).json()["id"]
    sender = RecordingPortalEmailSender()

    result = deliver_next(app, sender)

    assert result is not None
    assert result.status == OUTBOX_STATUS_DELIVERED
    assert sender.messages[-1]["type"] == "booking_prompt_notice"
    assert sender.messages[-1]["recipient"] == "example.patient@example.com"
    # Development without a public URL falls back to the request's own origin.
    assert sender.messages[-1]["sign_in_url"] == "http://testserver/"
    listed = client.get(PATH, headers=headers()).json()
    assert listed[0]["notified_at"] is not None
    delivery_events = audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_DELIVERY)
    assert [(event.outcome, event.resource_id) for event in delivery_events] == [
        (AUDIT_OUTCOME_SUCCESS, str(prompt_id))
    ]


def test_notice_email_carries_no_provider_type_or_urgency() -> None:
    message = booking_prompt_email_message(
        service_name="CARLOS Patient Portal",
        clinic_name="Maple Clinic",
        sign_in_url="https://portal.example.test/",
    )
    text = (message.subject + "\n" + message.body).casefold()

    for leaked in ("singh", "follow", "annual", "lab", "urgent", "soon", "possible", "book"):
        assert leaked not in text, leaked
    assert "https://portal.example.test/" in message.body


@pytest.mark.parametrize("change", ["withdrawn", "read", "expired"])
def test_notice_is_not_sent_once_it_would_lead_nowhere(change, caplog) -> None:
    app = booking_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    prompt_id = client.post(PATH, headers=headers(), json=prompt_request()).json()["id"]
    with app.state.session_factory.begin() as session:
        prompt = session.get(PatientPortalBookingPrompt, prompt_id)
        if change == "withdrawn":
            prompt.status = "withdrawn"
            prompt.withdrawn_at = utc_now()
            prompt.withdrawn_by = "Front Desk"
        elif change == "read":
            prompt.status = "read"
            prompt.read_at = utc_now()
        else:
            prompt.created_at = utc_now() - timedelta(days=100)
            prompt.expires_at = utc_now() - timedelta(seconds=1)
    sender = RecordingPortalEmailSender()

    with caplog.at_level(logging.INFO, logger="carlos_patient_portal.delivery_outbox"):
        result = deliver_next(app, sender)

    assert result is not None
    assert result.status == OUTBOX_STATUS_FAILED
    assert sender.messages == []
    with app.state.session_factory() as session:
        notice = session.scalar(select(PatientPortalOutboundDelivery))
        assert notice.last_failure_code == OUTBOX_FAILURE_BOOKING_PROMPT_NOT_NEEDED
    # Not an outage: nothing is logged as an error, and no delivery outcome is invented.
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_DELIVERY) == []


@pytest.mark.parametrize("change", ["disabled", "staff-locked"])
def test_notice_is_not_sent_once_staff_stop_the_account(change) -> None:
    # A disabled account can mean its mailbox is not the patient's; even "you have a message"
    # would tell that mailbox the patient attends the clinic.
    app = booking_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    assert client.post(PATH, headers=headers(), json=prompt_request()).status_code == 201
    if change == "disabled":
        disabled = client.post(
            "/internal/carlos/patients/1234/portal-account/access",
            headers=carlos_staff_headers(
                "portal.account.manage", clinic_id="clinic-a", token=INTERNAL_API_TOKEN
            ),
            json={"enabled": False, "reason": "not_the_patients_mailbox"},
        )
        assert disabled.status_code == 200
    else:
        with app.state.session_factory.begin() as session:
            account = session.scalar(select(PatientPortalAccount))
            account.locked_at = utc_now()
            account.locked_by = "Front Desk"
    sender = RecordingPortalEmailSender()

    result = deliver_next(app, sender)

    assert result is not None
    assert result.status == OUTBOX_STATUS_FAILED
    assert sender.messages == []


def test_notice_goes_to_the_accounts_current_email() -> None:
    app = booking_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    assert client.post(PATH, headers=headers(), json=prompt_request()).status_code == 201
    with app.state.session_factory.begin() as session:
        session.scalar(select(PatientPortalAccount)).email = "new.address@example.com"
    sender = RecordingPortalEmailSender()

    result = deliver_next(app, sender)

    assert result is not None
    assert result.status == OUTBOX_STATUS_DELIVERED
    assert [message["recipient"] for message in sender.messages] == ["new.address@example.com"]


def test_notice_that_keeps_failing_is_recorded_against_its_prompt() -> None:
    app = booking_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    prompt_id = client.post(PATH, headers=headers(), json=prompt_request()).json()["id"]
    sender = RecordingPortalEmailSender()
    sender.fail = True

    for _ in range(3):
        with app.state.session_factory.begin() as session:
            session.scalar(select(PatientPortalOutboundDelivery)).available_at = utc_now()
        result = deliver_next(app, sender)

    assert result is not None
    assert result.status == OUTBOX_STATUS_FAILED
    events = audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_DELIVERY)
    assert [(event.outcome, event.resource_id) for event in events] == [
        (AUDIT_OUTCOME_FAILURE, str(prompt_id))
    ]
    # The prompt itself still waits in the patient's messages.
    assert client.get(PATH, headers=headers()).json()[0]["state"] == "sent"


def test_patient_reads_the_prompt_and_staff_can_see_it_was_read() -> None:
    app = booking_app(clinic_booking_phone="555-123-4567")
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    staff = TestClient(app)
    prompt_id = staff.post(PATH, headers=headers(), json=prompt_request()).json()["id"]

    dashboard = client.get("/portal")
    messages = client.get("/portal/messages")
    opened = client.get(f"/portal/messages/{prompt_id}")
    reopened = client.get(f"/portal/messages/{prompt_id}")
    listed = staff.get(PATH, headers=headers()).json()

    assert "1 new" in dashboard.text
    assert messages.status_code == 200
    assert "Book a follow-up appointment" in messages.text
    assert "message-badge" in messages.text
    assert opened.status_code == 200
    assert "Dr. Singh suggested this appointment." in opened.text
    assert "Please book as soon as possible." in opened.text
    assert "To book, call Maple Clinic at 555-123-4567." in opened.text
    assert "Appointments cannot be booked in this portal." in opened.text
    assert reopened.status_code == 200
    assert listed[0]["state"] == "read"
    assert listed[0]["read_at"] is not None
    # One read, however many times it is opened.
    assert len(audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_READ)) == 1
    assert "message-badge" not in client.get("/portal/messages").text
    assert "1 new" not in client.get("/portal").text
    assert len(audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_LIST)) == 1


def test_prompt_without_a_booking_phone_says_to_contact_the_clinic() -> None:
    app = booking_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    prompt_id = TestClient(app).post(
        PATH, headers=headers(), json=prompt_request(suggested_by=None, urgency="routine")
    ).json()["id"]

    opened = client.get(f"/portal/messages/{prompt_id}")

    assert "To book, contact Maple Clinic." in opened.text
    assert "Your clinic suggested this appointment." in opened.text
    assert "Please book at a time that suits you." in opened.text


def test_a_prompt_beyond_the_listed_newest_still_opens() -> None:
    app = booking_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    staff = TestClient(app)
    oldest = staff.post(
        PATH, headers=headers(), json=prompt_request(operation_id="oldest")
    ).json()["id"]
    for index in range(50):
        assert staff.post(
            PATH, headers=headers(), json=prompt_request(operation_id=f"newer-{index}")
        ).status_code == 201

    opened = client.get(f"/portal/messages/{oldest}")

    # The list shows the newest 50; the opened one is shown whether or not it is among them.
    assert opened.status_code == 200
    assert 'id="message-title"' in opened.text
    assert f'href="/portal/messages/{oldest}"' not in opened.text


def test_withdrawn_and_expired_prompts_leave_the_patients_messages() -> None:
    app = booking_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    staff = TestClient(app)
    withdrawn_id = staff.post(
        PATH, headers=headers(), json=prompt_request(operation_id="to-withdraw")
    ).json()["id"]
    expired_id = staff.post(
        PATH,
        headers=headers(),
        json=prompt_request(operation_id="to-expire", appointment_type="lab_review"),
    ).json()["id"]

    withdrawn = staff.post(
        f"/internal/carlos/booking-prompts/{withdrawn_id}/withdraw", headers=headers()
    )
    withdrawn_again = staff.post(
        f"/internal/carlos/booking-prompts/{withdrawn_id}/withdraw", headers=headers()
    )
    with app.state.session_factory.begin() as session:
        prompt = session.get(PatientPortalBookingPrompt, expired_id)
        prompt.created_at = utc_now() - timedelta(days=100)
        prompt.expires_at = utc_now() - timedelta(seconds=1)

    assert withdrawn.json()["state"] == "withdrawn"
    assert withdrawn.json()["withdrawn_by"] == "Front Desk"
    assert withdrawn_again.status_code == 200
    assert len(audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_WITHDRAW)) == 1
    assert "You have no messages from your clinic." in client.get("/portal/messages").text
    for prompt_id in (withdrawn_id, expired_id):
        response = client.get(f"/portal/messages/{prompt_id}")
        assert response.status_code == 404
        assert "That message is no longer available." in response.text
    states = {prompt["id"]: prompt["state"] for prompt in staff.get(PATH, headers=headers()).json()}
    assert states == {withdrawn_id: "withdrawn", expired_id: "expired"}


def test_patient_cannot_open_another_patients_prompt() -> None:
    app = booking_app()
    client = TestClient(app)
    other = TestClient(app)
    activate_seeded_patient_account(
        app,
        other,
        username="other.patient",
        demographic_no=5678,
        email="other.patient@example.com",
        health_card_number="ZYXW 9876-5432",
    )
    browser_sign_in_seeded_patient(app, client)
    others_prompt = TestClient(app).post(
        "/internal/carlos/patients/5678/booking-prompts",
        headers=headers(),
        json=prompt_request(),
    )

    response = client.get(f"/portal/messages/{others_prompt.json()['id']}")

    assert others_prompt.status_code == 201
    assert response.status_code == 404
    assert audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_READ) == []


def test_messages_require_a_signed_in_patient() -> None:
    client = TestClient(booking_app())

    listed = client.get("/portal/messages", follow_redirects=False)
    opened = client.get("/portal/messages/1", follow_redirects=False)

    assert listed.status_code == 303
    assert opened.status_code == 303


def test_cleanup_removes_an_expired_prompt_only_after_its_notice_is_settled() -> None:
    app = booking_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    prompt_id = client.post(PATH, headers=headers(), json=prompt_request()).json()["id"]
    long_ago = utc_now() - timedelta(days=200)
    with app.state.session_factory.begin() as session:
        prompt = session.get(PatientPortalBookingPrompt, prompt_id)
        prompt.created_at = long_ago
        prompt.expires_at = long_ago + timedelta(days=90)
        session.scalar(select(PatientPortalOutboundDelivery)).created_at = long_ago
    before = utc_now() - timedelta(days=30)

    with app.state.session_factory.begin() as session:
        waiting = cleanup_transient_auth_rows(session, before=before)
    deliver_next(app, RecordingPortalEmailSender())
    with app.state.session_factory.begin() as session:
        dry_run = cleanup_transient_auth_rows(session, before=before, dry_run=True)
    with app.state.session_factory.begin() as session:
        removed = cleanup_transient_auth_rows(session, before=before)

    # A queued notice keeps its prompt, even an expired one.
    assert waiting.booking_prompts == 0
    assert dry_run.booking_prompts == 1
    assert removed.booking_prompts == 1
    assert removed.outbound_deliveries == 1
    with app.state.session_factory() as session:
        assert session.get(PatientPortalBookingPrompt, prompt_id) is None
    # The record of it stays.
    assert len(audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_CREATE)) == 1


def test_prompt_expiry_follows_the_configured_lifetime() -> None:
    app = booking_app(booking_prompt_ttl_days=7)
    client = TestClient(app)
    activate_seeded_patient_account(app, client)

    created = client.post(PATH, headers=headers(), json=prompt_request()).json()

    with app.state.session_factory() as session:
        prompt = session.get(PatientPortalBookingPrompt, created["id"])
        lifetime = prompt.expires_at - prompt.created_at
    assert lifetime == timedelta(days=7)


def test_notice_links_to_the_public_portal_and_refuses_to_guess_outside_development() -> None:
    request = SimpleNamespace(base_url="http://internal-api.local/")

    public = _booking_prompt_sign_in_url(
        request,
        development_settings(public_base_url="https://portal.example.test/"),
    )
    with pytest.raises(HTTPException) as unconfigured:
        _booking_prompt_sign_in_url(request, SimpleNamespace(
            public_base_url=None, is_development=False
        ))

    assert public == "https://portal.example.test/"
    assert unconfigured.value.status_code == 503


def test_booking_prompt_migration_keeps_its_audit_record_on_downgrade(tmp_path) -> None:
    config = Config()
    config.set_main_option("script_location", "carlos_patient_portal:migrations")
    database_url = f"sqlite+pysqlite:///{tmp_path / 'booking-prompts.db'}"
    config.set_main_option("sqlalchemy.url", database_url)
    assert (
        ScriptDirectory.from_config(config).get_revision("0014_booking_prompts").down_revision
        == "0013_drop_redundant_pending_idx"
    )
    command.upgrade(config, "0014_booking_prompts")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "insert into patient_portal_audit_events "
                    "(event_type, outcome, actor_type, created_at) "
                    "values ('booking_prompt.create', 'success', 'staff', :now)"
                ),
                {"now": utc_now()},
            )
        # The old event-type constraint cannot hold these rows, and deleting audit evidence to
        # make room is not the migration's call.
        with pytest.raises(RuntimeError, match="booking prompt audit events exist"):
            command.downgrade(config, "0013_drop_redundant_pending_idx")
        with engine.begin() as connection:
            connection.execute(text("delete from patient_portal_audit_events"))
        command.downgrade(config, "0013_drop_redundant_pending_idx")
        assert "patient_portal_booking_prompts" not in inspect(engine).get_table_names()
        assert "booking_prompt_id" not in {
            column["name"]
            for column in inspect(engine).get_columns("patient_portal_outbound_deliveries")
        }
        command.upgrade(config, "head")
        assert "patient_portal_booking_prompts" in inspect(engine).get_table_names()
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "value",
    [
        "555-123-4567",
        "(416) 555-0100",
        "+1 (416) 555-0100 ext. 22",
        "416.555.0100 x3",
        "  555 123 4567  ",
    ],
)
def test_clinic_booking_phone_accepts_phone_numbers(value) -> None:
    assert development_settings(clinic_booking_phone=value).clinic_booking_phone == value.strip()


@pytest.mark.parametrize("value", ["call the clinic", "555<b>1234</b>", "5" * 30, "x123"])
def test_clinic_booking_phone_refuses_anything_else(value) -> None:
    with pytest.raises(ValidationError, match="CLINIC_BOOKING_PHONE"):
        development_settings(clinic_booking_phone=value)


def test_clinic_booking_phone_is_optional() -> None:
    assert development_settings(clinic_booking_phone="   ").clinic_booking_phone is None
