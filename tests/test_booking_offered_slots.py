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

"""Offered times: CARLOS offers slots, the patient picks one, CARLOS reports the result."""

import re
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, func, inspect, select, text

from carlos_patient_portal import delivery_outbox, i18n
from carlos_patient_portal.booking_choices import (
    choose_offered_slot,
    close_lapsed_choices,
    list_pending_choices,
)
from carlos_patient_portal.booking_offers import OfferedSlotSpec
from carlos_patient_portal.booking_prompts import (
    BookingPromptNotFoundError,
    BookingPromptNotice,
    create_booking_prompt,
)
from carlos_patient_portal.delivery_outbox import (
    OUTBOX_FAILURE_BOOKING_PROMPT_NOT_NEEDED,
    process_one_delivery,
)
from carlos_patient_portal.maintenance import cleanup_transient_auth_rows
from carlos_patient_portal.models import (
    AUDIT_EVENT_BOOKING_PROMPT_CHOICE,
    AUDIT_EVENT_BOOKING_PROMPT_CREATE,
    AUDIT_EVENT_BOOKING_PROMPT_DECLINE,
    AUDIT_EVENT_BOOKING_PROMPT_DELIVERY,
    AUDIT_EVENT_BOOKING_PROMPT_OFFER,
    AUDIT_EVENT_BOOKING_PROMPT_RESULT,
    AUDIT_EVENT_STAFF_ACTION,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_SUCCESS,
    OUTBOX_KIND_BOOKING_PROMPT,
    OUTBOX_KIND_BOOKING_PROMPT_UPDATE,
    OUTBOX_STATUS_DELIVERED,
    OUTBOX_STATUS_FAILED,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalBookingChoice,
    PatientPortalBookingOfferedSlot,
    PatientPortalBookingPrompt,
    PatientPortalOutboundDelivery,
    utc_now,
)
from carlos_patient_portal.outbound_messages import booking_prompt_update_email_message
from tests.support import (
    INTERNAL_API_TOKEN,
    OUTBOX_ENCRYPTION_SECRET,
    RecordingPortalEmailSender,
    activate_seeded_patient_account,
    browser_sign_in_seeded_patient,
    carlos_staff_headers,
    csrf_token_from_response,
    development_settings,
    migrated_development_app,
)
from tests.test_internal_api import INTERNAL_ROUTE_PERMISSIONS

PROMPTS_PATH = "/internal/carlos/patients/1234/booking-prompts"
CHOICES_PATH = "/internal/carlos/booking-prompts/choices?state=pending"
MANAGE = "portal.booking_prompt.manage"
SYNC = "portal.booking_prompt.sync"
CLINIC_TIMEZONE = ZoneInfo("America/Toronto")
LOCATIONS = "main=Main Street Office,east=East Office"
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
MONTHS = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)
SLOT_RADIO_PATTERN = re.compile(r'name="slot" value="(\d+)"')


def booking_app(**overrides: object):
    return migrated_development_app(
        **{
            "clinic_id": "clinic-a",
            "clinic_name": "Example Clinic",
            "clinic_timezone": "America/Toronto",
            "booking_locations": LOCATIONS,
            "internal_api_token": INTERNAL_API_TOKEN,
            "outbox_encryption_secret": OUTBOX_ENCRYPTION_SECRET,
            **overrides,
        }
    )


def staff_headers(*permissions: str, clinic_id: str = "clinic-a") -> dict[str, str]:
    return carlos_staff_headers(
        *(permissions or (MANAGE,)),
        clinic_id=clinic_id,
        token=INTERNAL_API_TOKEN,
        provider_name="Front Desk",
    )


def sync_headers(clinic_id: str = "clinic-a") -> dict[str, str]:
    # The polling job's own principal: a non-login system provider with only this permission.
    return carlos_staff_headers(
        SYNC,
        clinic_id=clinic_id,
        token=INTERNAL_API_TOKEN,
        provider_id="carlos-booking-sync",
        provider_name="CARLOS booking sync",
    )


def local_time(days_ahead: int, hour: int, minute: int = 0) -> datetime:
    day = datetime.now(CLINIC_TIMEZONE).date() + timedelta(days=days_ahead)
    return datetime.combine(day, time(hour, minute), tzinfo=CLINIC_TIMEZONE)


def expected_when(value: datetime) -> str:
    local = value.astimezone(CLINIC_TIMEZONE)
    return f"{WEEKDAYS[local.weekday()]} {local.day} {MONTHS[local.month - 1]} at {local:%H:%M}"


def slot(slot_id: str, starts_at: datetime, **overrides: object) -> dict[str, object]:
    return {
        "slot_id": slot_id,
        "starts_at": starts_at.isoformat(),
        "duration_minutes": 30,
        "visit_mode": "in_person",
        "location_code": "main",
        **overrides,
    }


FIRST = local_time(7, 10, 30)
SECOND = local_time(8, 14, 0)
THIRD = local_time(9, 9, 15)


def default_slots() -> list[dict[str, object]]:
    return [
        slot("carlos:slot:1", FIRST),
        slot("carlos:slot:2", SECOND, visit_mode="phone", location_code=None, duration_minutes=45),
        slot("carlos:slot:3", THIRD, visit_mode="video", location_code="east"),
    ]


def prompt_request(**overrides: object) -> dict[str, object]:
    return {
        "operation_id": "offer-operation-1",
        "urgency": "soon",
        "appointment_type": "follow_up",
        "offered_slots": default_slots(),
        **overrides,
    }


def create_prompt(app, **overrides: object) -> int:
    response = TestClient(app).post(
        PROMPTS_PATH, headers=staff_headers(), json=prompt_request(**overrides)
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def patient_with_offer(**app_overrides: object):
    app = booking_app(**app_overrides)
    patient = TestClient(app)
    browser_sign_in_seeded_patient(app, patient)
    prompt_id = create_prompt(app)
    return app, patient, prompt_id


def open_message(patient: TestClient, prompt_id: int):
    response = patient.get(f"/portal/messages/{prompt_id}")
    assert response.status_code == 200, response.text
    return response


def slot_row_ids(app, prompt_id: int) -> dict[str, int]:
    with app.state.session_factory() as session:
        return {
            row.slot_id: row.id
            for row in session.scalars(
                select(PatientPortalBookingOfferedSlot).where(
                    PatientPortalBookingOfferedSlot.prompt_id == prompt_id
                )
            )
        }


def choose(patient: TestClient, prompt_id: int, slot_row_id: int | str | None):
    page = patient.get(f"/portal/messages/{prompt_id}")
    data = {"csrf_token": csrf_token_from_response(page)}
    if slot_row_id is not None:
        data["slot"] = str(slot_row_id)
    return patient.post(
        f"/portal/messages/{prompt_id}/choice", data=data, follow_redirects=False
    )


def pick(app, patient: TestClient, prompt_id: int, slot_id: str = "carlos:slot:1"):
    return choose(patient, prompt_id, slot_row_ids(app, prompt_id)[slot_id])


def decline(patient: TestClient, prompt_id: int):
    page = patient.get(f"/portal/messages/{prompt_id}")
    return patient.post(
        f"/portal/messages/{prompt_id}/decline",
        data={"csrf_token": csrf_token_from_response(page)},
        follow_redirects=False,
    )


def pending_choices(app, headers: dict[str, str] | None = None):
    return TestClient(app).get(CHOICES_PATH, headers=headers or sync_headers())


def report(app, prompt_id: int, choice_id: int, result: str, **extra: object):
    return TestClient(app).post(
        f"/internal/carlos/booking-prompts/{prompt_id}/choice-result",
        headers=sync_headers(),
        json={"choice_id": choice_id, "result": result, **extra},
    )


def only_choice(app) -> PatientPortalBookingChoice:
    with app.state.session_factory() as session:
        return session.scalar(
            select(PatientPortalBookingChoice).order_by(PatientPortalBookingChoice.id.desc())
        )


def prompt_state(app, prompt_id: int) -> str:
    listed = TestClient(app).get(PROMPTS_PATH, headers=staff_headers()).json()
    return {prompt["id"]: prompt["state"] for prompt in listed}[prompt_id]


def audit_events(app, event_type: str) -> list[PatientPortalAuditEvent]:
    with app.state.session_factory() as session:
        return list(
            session.scalars(
                select(PatientPortalAuditEvent)
                .where(PatientPortalAuditEvent.event_type == event_type)
                .order_by(PatientPortalAuditEvent.id)
            )
        )


def update_notices(app) -> list[PatientPortalOutboundDelivery]:
    with app.state.session_factory() as session:
        return list(
            session.scalars(
                select(PatientPortalOutboundDelivery).where(
                    PatientPortalOutboundDelivery.kind == OUTBOX_KIND_BOOKING_PROMPT_UPDATE
                )
            )
        )


def deliver_all(app, sender: RecordingPortalEmailSender) -> None:
    while process_one_delivery(
        app.state.session_factory,
        email_sender=sender,
        encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        max_attempts=3,
        lease_seconds=60,
    ):
        pass


def move_prompt_expiry(app, prompt_id: int, *, expires_at: datetime) -> None:
    with app.state.session_factory.begin() as session:
        prompt = session.get(PatientPortalBookingPrompt, prompt_id)
        prompt.created_at = expires_at - timedelta(days=90)
        prompt.expires_at = expires_at


# --------------------------------------------------------------------------------------
# Creating a prompt with offered times
# --------------------------------------------------------------------------------------


def test_offered_times_are_stored_in_order_and_the_offer_is_audited_by_count() -> None:
    app = booking_app()
    activate_seeded_patient_account(app, TestClient(app))

    response = TestClient(app).post(PROMPTS_PATH, headers=staff_headers(), json=prompt_request())

    assert response.status_code == 201
    assert response.json()["state"] == "sent"
    prompt_id = response.json()["id"]
    with app.state.session_factory() as session:
        rows = list(
            session.scalars(
                select(PatientPortalBookingOfferedSlot).order_by(
                    PatientPortalBookingOfferedSlot.position
                )
            )
        )
        prompt = session.get(PatientPortalBookingPrompt, prompt_id)
        assert prompt.offer_digest is not None and len(prompt.offer_digest) == 64
    assert [(row.position, row.slot_id) for row in rows] == [
        (0, "carlos:slot:1"),
        (1, "carlos:slot:2"),
        (2, "carlos:slot:3"),
    ]
    stored_first = rows[0].starts_at.replace(tzinfo=UTC)
    assert stored_first == FIRST.astimezone(UTC)
    assert [(row.duration_minutes, row.visit_mode, row.location_code) for row in rows] == [
        (30, "in_person", "main"),
        (45, "phone", None),
        (30, "video", "east"),
    ]
    offers = audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_OFFER)
    assert [(event.actor, event.resource_id, event.reason) for event in offers] == [
        ("Front Desk", str(prompt_id), "initial:3")
    ]
    assert len(audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_CREATE)) == 1


def test_a_prompt_without_offered_times_behaves_as_before() -> None:
    app = booking_app()
    patient = TestClient(app)
    browser_sign_in_seeded_patient(app, patient)
    prompt_id = create_prompt(app, offered_slots=None)

    opened = open_message(patient, prompt_id)

    assert "Appointments cannot be booked in this portal." in opened.text
    assert "To book, contact Example Clinic." in opened.text
    assert 'name="slot"' not in opened.text
    assert audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_OFFER) == []
    with app.state.session_factory() as session:
        assert session.get(PatientPortalBookingPrompt, prompt_id).offer_digest is None


def _invalid_offer(**changes: object) -> list[dict[str, object]]:
    return [{**slot("carlos:slot:1", FIRST), **changes}]


@pytest.mark.parametrize(
    "offered_slots",
    [
        pytest.param(_invalid_offer(slot_id="has space"), id="slot-id-format"),
        pytest.param(_invalid_offer(slot_id=""), id="slot-id-empty"),
        pytest.param(_invalid_offer(slot_id="s" * 65), id="slot-id-too-long"),
        pytest.param(_invalid_offer(starts_at="2030-10-14T10:30:00"), id="naive-start"),
        pytest.param(_invalid_offer(starts_at=1_900_000_000), id="numeric-start"),
        pytest.param(_invalid_offer(starts_at="1900000000"), id="numeric-text-start"),
        pytest.param(_invalid_offer(starts_at="next tuesday"), id="unparseable-start"),
        pytest.param(
            _invalid_offer(starts_at=(utc_now() - timedelta(minutes=1)).isoformat()),
            id="past-start",
        ),
        pytest.param(_invalid_offer(duration_minutes=4), id="duration-too-short"),
        pytest.param(_invalid_offer(duration_minutes=481), id="duration-too-long"),
        pytest.param(_invalid_offer(duration_minutes="30"), id="duration-as-text"),
        pytest.param(_invalid_offer(duration_minutes=30.5), id="duration-fraction"),
        pytest.param(_invalid_offer(visit_mode="home"), id="visit-mode"),
        pytest.param(_invalid_offer(location_code="north"), id="location-not-configured"),
        pytest.param(_invalid_offer(location_code="MAIN"), id="location-format"),
        pytest.param(_invalid_offer(provider="Dr. Example"), id="provider-field"),
        pytest.param(_invalid_offer(reason="free text"), id="free-text-field"),
        pytest.param(
            [slot("carlos:slot:1", FIRST), slot("carlos:slot:1", SECOND)],
            id="duplicate-slot-id",
        ),
        pytest.param(
            [slot(f"carlos:slot:{index}", local_time(3, 9 + index)) for index in range(9)],
            id="more-than-eight",
        ),
    ],
)
def test_offered_times_accept_only_their_fixed_shape(offered_slots) -> None:
    app = booking_app()
    activate_seeded_patient_account(app, TestClient(app))

    response = TestClient(app).post(
        PROMPTS_PATH, headers=staff_headers(), json=prompt_request(offered_slots=offered_slots)
    )

    assert response.status_code == 422
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count(PatientPortalBookingPrompt.id))) == 0
        assert session.scalar(select(func.count(PatientPortalBookingOfferedSlot.id))) == 0
        assert session.scalar(select(func.count(PatientPortalOutboundDelivery.id))) == 0


def test_eight_offered_times_are_accepted() -> None:
    app = booking_app()
    activate_seeded_patient_account(app, TestClient(app))
    eight = [slot(f"carlos:slot:{index}", local_time(3, 9 + index)) for index in range(8)]

    response = TestClient(app).post(
        PROMPTS_PATH, headers=staff_headers(), json=prompt_request(offered_slots=eight)
    )

    assert response.status_code == 201
    assert len(slot_row_ids(app, response.json()["id"])) == 8


def test_a_location_code_is_refused_when_no_locations_are_configured() -> None:
    app = booking_app(booking_locations=None)
    activate_seeded_patient_account(app, TestClient(app))
    staff = TestClient(app)

    with_location = staff.post(
        PROMPTS_PATH,
        headers=staff_headers(),
        json=prompt_request(offered_slots=[slot("carlos:slot:1", FIRST)]),
    )
    without_location = staff.post(
        PROMPTS_PATH,
        headers=staff_headers(),
        json=prompt_request(offered_slots=[slot("carlos:slot:1", FIRST, location_code=None)]),
    )

    assert with_location.status_code == 422
    assert without_location.status_code == 201


def test_a_retry_matches_on_its_offered_times() -> None:
    app = booking_app()
    patient = TestClient(app)
    browser_sign_in_seeded_patient(app, patient)
    staff = TestClient(app)
    created = staff.post(PROMPTS_PATH, headers=staff_headers(), json=prompt_request())
    prompt_id = created.json()["id"]
    # The retry must still match after the patient has picked, which changes the stored times.
    assert pick(app, patient, prompt_id).status_code == 303

    same = staff.post(PROMPTS_PATH, headers=staff_headers(), json=prompt_request())
    same_in_utc = staff.post(
        PROMPTS_PATH,
        headers=staff_headers(),
        json=prompt_request(
            offered_slots=[
                {**entry, "starts_at": datetime.fromisoformat(entry["starts_at"]).astimezone(UTC)
                 .isoformat()}
                for entry in default_slots()
            ]
        ),
    )
    moved = staff.post(
        PROMPTS_PATH,
        headers=staff_headers(),
        json=prompt_request(
            offered_slots=[
                slot("carlos:slot:1", FIRST + timedelta(minutes=15)),
                *default_slots()[1:],
            ]
        ),
    )
    reordered = staff.post(
        PROMPTS_PATH,
        headers=staff_headers(),
        json=prompt_request(offered_slots=list(reversed(default_slots()))),
    )
    without = staff.post(
        PROMPTS_PATH, headers=staff_headers(), json=prompt_request(offered_slots=None)
    )

    assert same.status_code == 201
    assert same.json()["created"] is False
    assert same.json()["id"] == prompt_id
    assert same_in_utc.status_code == 201
    assert same_in_utc.json()["created"] is False
    for conflict in (moved, reordered, without):
        assert conflict.status_code == 409
        assert conflict.json() == {"detail": "operation id was used for a different booking prompt"}
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count(PatientPortalBookingPrompt.id))) == 1
        notices = session.scalar(
            select(func.count(PatientPortalOutboundDelivery.id)).where(
                PatientPortalOutboundDelivery.kind == OUTBOX_KIND_BOOKING_PROMPT
            )
        )
        assert notices == 1


def test_a_prompt_created_without_times_does_not_match_a_retry_with_times() -> None:
    app = booking_app()
    activate_seeded_patient_account(app, TestClient(app))
    staff = TestClient(app)
    assert staff.post(
        PROMPTS_PATH, headers=staff_headers(), json=prompt_request(offered_slots=[])
    ).status_code == 201

    retried = staff.post(PROMPTS_PATH, headers=staff_headers(), json=prompt_request())

    assert retried.status_code == 409


def test_offering_times_needs_the_digest_key() -> None:
    app = booking_app()
    account_id = activate_seeded_patient_account(app, TestClient(app))
    assert account_id

    with app.state.session_factory() as session, pytest.raises(ValueError, match="digest"):
        create_booking_prompt(
            session,
            clinic_id="clinic-a",
            demographic_no=1234,
            operation_id="no-digest-key",
            urgency="soon",
            appointment_type="follow_up",
            suggested_by=None,
            created_by="Front Desk",
            created_by_id="front-desk",
            ttl=timedelta(days=90),
            notice=BookingPromptNotice(
                sign_in_url="https://portal.example.test/",
                encryption_secret=OUTBOX_ENCRYPTION_SECRET,
                encryption_key_id="primary",
            ),
            offered_slots=[
                OfferedSlotSpec(
                    slot_id="carlos:slot:1",
                    starts_at=FIRST,
                    duration_minutes=30,
                    visit_mode="in_person",
                )
            ],
        )


# --------------------------------------------------------------------------------------
# What the patient sees
# --------------------------------------------------------------------------------------


def test_patient_sees_the_offered_times_in_the_clinic_time_zone() -> None:
    app, patient, prompt_id = patient_with_offer()

    opened = open_message(patient, prompt_id)

    assert "<fieldset" in opened.text and "<legend>Available times</legend>" in opened.text
    assert opened.text.count('type="radio" name="slot"') == 3
    assert expected_when(FIRST) in opened.text
    assert "30 minutes · In person · Main Street Office" in opened.text
    assert expected_when(SECOND) in opened.text
    assert "45 minutes · By phone" in opened.text
    assert "30 minutes · By video · East Office" in opened.text
    assert ">Choose this time</button>" in opened.text
    assert ">None of these work</button>" in opened.text
    assert "Appointments cannot be booked in this portal." not in opened.text
    # CARLOS's slot ids stay out of the browser; the radio values are the portal's row ids.
    assert "carlos:slot" not in opened.text
    assert set(SLOT_RADIO_PATTERN.findall(opened.text)) == {
        str(row_id) for row_id in slot_row_ids(app, prompt_id).values()
    }
    # No inline script or style: the page keeps the strict CSP.
    assert "<script>" not in opened.text and "style=" not in opened.text


def test_a_time_sent_in_utc_is_shown_in_clinic_time() -> None:
    app = booking_app()
    patient = TestClient(app)
    browser_sign_in_seeded_patient(app, patient)
    utc_start = datetime.combine(
        datetime.now(UTC).date() + timedelta(days=10), time(15, 45), tzinfo=UTC
    )
    prompt_id = create_prompt(app, offered_slots=[slot("carlos:slot:utc", utc_start)])

    opened = open_message(patient, prompt_id)

    assert expected_when(utc_start) in opened.text
    assert f"at {utc_start:%H:%M}" not in opened.text


def test_offered_times_follow_the_patients_language(monkeypatch) -> None:
    app, patient, prompt_id = patient_with_offer()
    local_first = FIRST.astimezone(CLINIC_TIMEZONE)
    monkeypatch.setitem(
        i18n.TEXT_CATALOG,
        "fr",
        {
            f"booking_weekday_{local_first.weekday()}": "Jourdetest",
            "booking_choose": "Choisir cette heure",
        },
    )

    opened = patient.get(f"/portal/messages/{prompt_id}", cookies={"portal_locale": "fr"})

    assert "Jourdetest" in opened.text
    assert "Choisir cette heure" in opened.text


def test_a_time_that_has_started_is_no_longer_offered() -> None:
    app, patient, prompt_id = patient_with_offer()
    row_ids = slot_row_ids(app, prompt_id)
    with app.state.session_factory.begin() as session:
        session.get(PatientPortalBookingOfferedSlot, row_ids["carlos:slot:1"]).starts_at = (
            utc_now() - timedelta(minutes=1)
        )

    opened = open_message(patient, prompt_id)
    chosen = choose(patient, prompt_id, row_ids["carlos:slot:1"])

    assert opened.text.count('type="radio" name="slot"') == 2
    assert chosen.status_code == 409
    assert only_choice(app) is None


# --------------------------------------------------------------------------------------
# Choosing a time
# --------------------------------------------------------------------------------------


def test_choosing_a_time_waits_for_the_clinic_and_is_visible_to_the_polling_job() -> None:
    app, patient, prompt_id = patient_with_offer()
    row_ids = slot_row_ids(app, prompt_id)

    chosen = choose(patient, prompt_id, row_ids["carlos:slot:2"])

    assert chosen.status_code == 303
    assert chosen.headers["location"] == f"/portal/messages/{prompt_id}"
    page = open_message(patient, prompt_id)
    assert "We are confirming your time with the clinic." in page.text
    assert expected_when(SECOND) in page.text
    assert 'name="slot"' not in page.text
    assert prompt_state(app, prompt_id) == "choice_pending"
    choice = only_choice(app)
    assert choice.state == "pending"
    assert choice.slot_id == "carlos:slot:2"
    assert choice.clinic_id == "clinic-a"
    polled = pending_choices(app)
    assert polled.status_code == 200
    assert polled.json() == {
        "items": [
            {
                "prompt_id": prompt_id,
                "choice_id": choice.id,
                "demographic_no": 1234,
                "slot_id": "carlos:slot:2",
                "chosen_at": polled.json()["items"][0]["chosen_at"],
            }
        ],
        "has_more": False,
    }
    events = audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_CHOICE)
    assert [(event.actor_type, event.resource_type, event.resource_id) for event in events] == [
        ("patient", "booking_choice", str(choice.id))
    ]
    assert events[0].reason is None


def test_only_one_choice_can_wait_at_a_time() -> None:
    app, patient, prompt_id = patient_with_offer()
    row_ids = slot_row_ids(app, prompt_id)
    assert choose(patient, prompt_id, row_ids["carlos:slot:1"]).status_code == 303

    page = patient.get(f"/portal/messages/{prompt_id}")
    second = patient.post(
        f"/portal/messages/{prompt_id}/choice",
        data={"csrf_token": csrf_token_from_response(page), "slot": row_ids["carlos:slot:3"]},
        follow_redirects=False,
    )

    assert second.status_code == 409
    assert "That time could not be chosen." in second.text
    assert "We are confirming your time with the clinic." in second.text
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count(PatientPortalBookingChoice.id))) == 1
    refusals = [
        event.reason
        for event in audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_CHOICE)
        if event.outcome == AUDIT_OUTCOME_FAILURE
    ]
    assert refusals == ["prompt_closed"]


def test_a_choice_needs_a_valid_csrf_token() -> None:
    app, patient, prompt_id = patient_with_offer()
    row_id = slot_row_ids(app, prompt_id)["carlos:slot:1"]
    open_message(patient, prompt_id)

    missing = patient.post(
        f"/portal/messages/{prompt_id}/choice", data={"slot": row_id}, follow_redirects=False
    )
    forged = patient.post(
        f"/portal/messages/{prompt_id}/choice",
        data={"slot": row_id, "csrf_token": "forged"},
        follow_redirects=False,
    )
    decline_missing = patient.post(f"/portal/messages/{prompt_id}/decline", follow_redirects=False)

    assert missing.status_code == 403
    assert forged.status_code == 403
    assert decline_missing.status_code == 403
    assert only_choice(app) is None
    assert prompt_state(app, prompt_id) == "read"


def test_a_signed_out_choice_goes_to_sign_in() -> None:
    app, patient, prompt_id = patient_with_offer()
    page = patient.get(f"/portal/messages/{prompt_id}")
    token = csrf_token_from_response(page)
    patient.cookies.delete("carlos_patient_portal_session", path="/portal")
    for name in list(patient.cookies.keys()):
        if "session" in name:
            patient.cookies.delete(name)

    response = patient.post(
        f"/portal/messages/{prompt_id}/choice",
        data={"csrf_token": token, "slot": "1"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert only_choice(app) is None


def test_a_patient_cannot_choose_on_another_patients_prompt() -> None:
    app = booking_app()
    other = TestClient(app)
    activate_seeded_patient_account(
        app,
        other,
        username="other.patient",
        demographic_no=5678,
        email="other.patient@example.com",
        health_card_number="ZYXW 9876-5432",
    )
    patient = TestClient(app)
    browser_sign_in_seeded_patient(app, patient)
    others_prompt = TestClient(app).post(
        "/internal/carlos/patients/5678/booking-prompts",
        headers=staff_headers(),
        json=prompt_request(),
    ).json()["id"]
    own_prompt = create_prompt(app, operation_id="own-offer")
    others_slot = slot_row_ids(app, others_prompt)["carlos:slot:1"]

    page = patient.get(f"/portal/messages/{own_prompt}")
    token = csrf_token_from_response(page)
    on_their_prompt = patient.post(
        f"/portal/messages/{others_prompt}/choice",
        data={"csrf_token": token, "slot": others_slot},
        follow_redirects=False,
    )
    their_slot_on_own_prompt = patient.post(
        f"/portal/messages/{own_prompt}/choice",
        data={"csrf_token": csrf_token_from_response(on_their_prompt), "slot": others_slot},
        follow_redirects=False,
    )
    declined = patient.post(
        f"/portal/messages/{others_prompt}/decline",
        data={"csrf_token": csrf_token_from_response(their_slot_on_own_prompt)},
        follow_redirects=False,
    )

    # Not found, exactly as opening it: nothing says the prompt exists.
    assert on_their_prompt.status_code == 404
    assert "That message is no longer available." in on_their_prompt.text
    assert "Front Desk" not in on_their_prompt.text
    assert their_slot_on_own_prompt.status_code == 409
    assert declined.status_code == 404
    assert only_choice(app) is None
    assert prompt_state(app, own_prompt) == "read"
    with app.state.session_factory() as session:
        assert session.get(PatientPortalBookingPrompt, others_prompt).status == "sent"


@pytest.mark.parametrize("closed_by", ["withdrawn", "expired"])
def test_a_withdrawn_or_expired_prompt_takes_no_choice(closed_by) -> None:
    app, patient, prompt_id = patient_with_offer()
    row_id = slot_row_ids(app, prompt_id)["carlos:slot:1"]
    page = open_message(patient, prompt_id)
    if closed_by == "withdrawn":
        assert TestClient(app).post(
            f"/internal/carlos/booking-prompts/{prompt_id}/withdraw", headers=staff_headers()
        ).status_code == 200
    else:
        move_prompt_expiry(app, prompt_id, expires_at=utc_now() - timedelta(seconds=1))

    response = patient.post(
        f"/portal/messages/{prompt_id}/choice",
        data={"csrf_token": csrf_token_from_response(page), "slot": row_id},
        follow_redirects=False,
    )

    assert response.status_code == 404
    assert only_choice(app) is None


@pytest.mark.parametrize("closed_by", ["booked", "declined"])
def test_a_booked_or_declined_prompt_takes_no_choice(closed_by) -> None:
    app, patient, prompt_id = patient_with_offer()
    row_ids = slot_row_ids(app, prompt_id)
    if closed_by == "booked":
        assert choose(patient, prompt_id, row_ids["carlos:slot:1"]).status_code == 303
        assert report(app, prompt_id, only_choice(app).id, "booked").status_code == 200
    else:
        assert decline(patient, prompt_id).status_code == 303
    before = only_choice(app)

    response = choose(patient, prompt_id, row_ids["carlos:slot:2"])

    assert response.status_code == 409
    after = only_choice(app)
    assert (after.id if after else None) == (before.id if before else None)


def test_submitting_without_picking_a_time_is_a_400() -> None:
    app, patient, prompt_id = patient_with_offer()

    missing = choose(patient, prompt_id, None)
    garbage = choose(patient, prompt_id, "one")

    assert missing.status_code == 400
    assert garbage.status_code == 400
    assert "That time could not be chosen." in missing.text
    assert only_choice(app) is None


def test_a_patient_waiting_past_the_configured_time_is_told_to_call_if_urgent() -> None:
    app, patient, prompt_id = patient_with_offer(booking_choice_wait_minutes=5)
    assert pick(app, patient, prompt_id).status_code == 303
    assert "We are confirming your time with the clinic." in open_message(patient, prompt_id).text

    with app.state.session_factory.begin() as session:
        choice = session.scalar(select(PatientPortalBookingChoice))
        choice.chosen_at = utc_now() - timedelta(minutes=4)
    still_waiting = open_message(patient, prompt_id)
    with app.state.session_factory.begin() as session:
        choice = session.scalar(select(PatientPortalBookingChoice))
        choice.chosen_at = utc_now() - timedelta(minutes=6)
    overdue = open_message(patient, prompt_id)

    assert "We are confirming your time with the clinic." in still_waiting.text
    remaining_ms = int(re.search(r'data-booking-wait-ms="(\d+)"', still_waiting.text).group(1))
    assert 0 < remaining_ms <= 60_000
    assert 'data-booking-wait-ms=' not in overdue.text
    assert (
        "The clinic will confirm your time. If it is urgent, call the clinic." in overdue.text
    )
    assert "We are confirming your time" not in overdue.text


def test_a_pending_choice_outlives_the_prompts_expiry() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    move_prompt_expiry(app, prompt_id, expires_at=utc_now() - timedelta(minutes=1))

    # The patient chose while it was live: they keep seeing the wait, and CARLOS keeps seeing it.
    # The pick is moments old, inside the configured wait.
    assert "We are confirming your time with the clinic." in open_message(patient, prompt_id).text
    assert prompt_state(app, prompt_id) == "choice_pending"
    assert len(pending_choices(app).json()["items"]) == 1


# --------------------------------------------------------------------------------------
# None of these work
# --------------------------------------------------------------------------------------


def test_none_of_these_work_records_declined_all_and_shows_the_contact_message() -> None:
    app, patient, prompt_id = patient_with_offer()

    declined = decline(patient, prompt_id)

    assert declined.status_code == 303
    assert declined.headers["location"] == f"/portal/messages/{prompt_id}"
    page = open_message(patient, prompt_id)
    assert "To book, contact Example Clinic." in page.text
    assert 'name="slot"' not in page.text
    # Times were offered, so the page does not claim the portal cannot book.
    assert "Appointments cannot be booked in this portal." not in page.text
    assert prompt_state(app, prompt_id) == "declined_all"
    assert slot_row_ids(app, prompt_id) == {}
    events = audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_DECLINE)
    assert [(event.outcome, event.resource_id, event.reason) for event in events] == [
        (AUDIT_OUTCOME_SUCCESS, str(prompt_id), "offered:3")
    ]
    assert pending_choices(app).json()["items"] == []


def test_none_of_these_work_is_refused_while_a_choice_waits_or_nothing_is_offered() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    no_offer = create_prompt(app, operation_id="no-offer", offered_slots=None)

    while_waiting = decline(patient, prompt_id)
    nothing_offered = decline(patient, no_offer)

    assert while_waiting.status_code == 409
    assert nothing_offered.status_code == 409
    assert prompt_state(app, prompt_id) == "choice_pending"
    assert prompt_state(app, no_offer) == "sent" or prompt_state(app, no_offer) == "read"


# --------------------------------------------------------------------------------------
# The polling job's list
# --------------------------------------------------------------------------------------


def test_the_polling_list_has_only_pending_choices_for_its_clinic_oldest_first() -> None:
    app = booking_app()
    patient = TestClient(app)
    browser_sign_in_seeded_patient(app, patient)
    older = create_prompt(app, operation_id="older")
    newer = create_prompt(app, operation_id="newer")
    resolved = create_prompt(app, operation_id="resolved")
    for prompt_id in (newer, older, resolved):
        assert pick(app, patient, prompt_id).status_code == 303
    with app.state.session_factory.begin() as session:
        choices = {
            choice.prompt_id: choice
            for choice in session.scalars(select(PatientPortalBookingChoice))
        }
        choices[older].chosen_at = utc_now() - timedelta(minutes=10)
        choices[newer].chosen_at = utc_now() - timedelta(minutes=5)
        resolved_choice_id = choices[resolved].id
        # Another clinic's pending pick in the same database is never listed to this one.
        foreign_account = session.scalar(select(PatientPortalAccount))
        foreign = PatientPortalBookingPrompt(
            clinic_id="clinic-b",
            demographic_no=1234,
            account_id=foreign_account.id,
            operation_id="foreign",
            urgency="soon",
            appointment_type="follow_up",
            status="choice_pending",
            created_by="Other Desk",
            created_at=utc_now() - timedelta(hours=1),
            expires_at=utc_now() + timedelta(days=1),
            read_at=utc_now() - timedelta(hours=1),
        )
        session.add(foreign)
        session.flush()
        session.add(
            PatientPortalBookingChoice(
                prompt_id=foreign.id,
                clinic_id="clinic-b",
                slot_id="foreign:slot",
                starts_at=FIRST,
                duration_minutes=30,
                visit_mode="phone",
                state="pending",
                chosen_at=utc_now() - timedelta(hours=1),
            )
        )
    assert report(app, resolved, resolved_choice_id, "booked").status_code == 200

    listed = pending_choices(app)
    limited = TestClient(app).get(f"{CHOICES_PATH}&limit=1", headers=sync_headers())
    other_clinic = pending_choices(app, sync_headers(clinic_id="clinic-b"))

    assert listed.status_code == 200
    assert [item["prompt_id"] for item in listed.json()["items"]] == [older, newer]
    assert listed.json()["has_more"] is False
    assert [item["prompt_id"] for item in limited.json()["items"]] == [older]
    assert limited.json()["has_more"] is True
    # A portal serves one clinic: another clinic's assertion is refused before any lookup.
    assert other_clinic.status_code == 404


def test_turning_an_account_off_cancels_its_waiting_pick_for_good() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id

    def set_access(enabled: bool):
        # A fresh assertion each time: every one is single-use.
        return TestClient(app).post(
            "/internal/carlos/patients/1234/portal-account/access",
            headers=staff_headers("portal.account.manage"),
            json={"enabled": enabled, "reason": "staff_action"},
        )

    disabled = set_access(False)
    while_disabled = pending_choices(app)
    enabled = set_access(True)
    after = pending_choices(app)

    # Turning the account off cancels the pick; turning it back on does not revive it, so CARLOS
    # never books a time the patient may not have chosen.
    assert disabled.status_code == 200
    assert while_disabled.json()["items"] == []
    assert enabled.status_code == 200
    assert after.json()["items"] == []
    choice = only_choice(app)
    assert (choice.state, choice.slot_id, choice.starts_at) == ("withdrawn", None, None)
    assert prompt_state(app, prompt_id) == "read"
    late = report(app, prompt_id, choice_id, "booked")
    assert (late.status_code, late.json()["detail"]) == (409, "booking choice was withdrawn")
    cancelled = [
        event
        for event in audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_RESULT)
        if event.reason == "withdrawn_account_disabled"
    ]
    assert [(event.actor_type, event.resource_id) for event in cancelled] == [
        ("staff", str(choice_id))
    ]


def test_the_polling_list_needs_the_pending_state_and_audits_only_what_it_discloses() -> None:
    app, patient, prompt_id = patient_with_offer()

    empty = pending_choices(app)
    no_state = TestClient(app).get(
        "/internal/carlos/booking-prompts/choices", headers=sync_headers()
    )
    other_state = TestClient(app).get(
        "/internal/carlos/booking-prompts/choices?state=booked", headers=sync_headers()
    )
    assert pick(app, patient, prompt_id).status_code == 303
    one = pending_choices(app)

    assert empty.json() == {"items": [], "has_more": False}
    assert no_state.status_code == 422
    assert other_state.status_code == 422
    assert len(one.json()["items"]) == 1
    listings = [
        (event.actor, event.actor_id, event.resource_type, event.resource_id, event.reason)
        for event in audit_events(app, AUDIT_EVENT_STAFF_ACTION)
        if event.outcome == AUDIT_OUTCOME_SUCCESS
    ]
    assert listings == [
        (
            "CARLOS booking sync",
            "carlos-booking-sync",
            "booking_choice",
            "count:1",
            "pending_choices_listed",
        )
    ]


# --------------------------------------------------------------------------------------
# CARLOS reports the result
# --------------------------------------------------------------------------------------


def test_a_booked_result_confirms_the_time_and_deletes_the_offer() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id

    reported = report(app, prompt_id, choice_id, "booked")

    assert reported.status_code == 200
    assert reported.json() == {
        "prompt_id": prompt_id,
        "choice_id": choice_id,
        "result": "booked",
        "state": "booked",
        "recorded": True,
        "offered_slot_count": 0,
    }
    page = open_message(patient, prompt_id)
    local_first = FIRST.astimezone(CLINIC_TIMEZONE)
    assert (
        f"Booked for {WEEKDAYS[local_first.weekday()]} {local_first.day} "
        f"{MONTHS[local_first.month - 1]} at {local_first:%H:%M}." in page.text
    )
    assert "30 minutes · In person · Main Street Office" in page.text
    assert 'name="slot"' not in page.text
    assert slot_row_ids(app, prompt_id) == {}
    assert prompt_state(app, prompt_id) == "booked"
    assert pending_choices(app).json()["items"] == []
    # The copy of the booked time survives the offer's deletion, for the confirmation.
    assert only_choice(app).starts_at is not None
    results = audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_RESULT)
    assert [(event.actor_id, event.resource_id, event.reason) for event in results] == [
        ("carlos-booking-sync", str(choice_id), "booked")
    ]
    assert len(update_notices(app)) == 1


def test_repeating_a_result_changes_nothing_and_sends_no_second_notice() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id
    assert report(app, prompt_id, choice_id, "booked").json()["recorded"] is True

    repeated = report(app, prompt_id, choice_id, "booked")
    conflicting = report(app, prompt_id, choice_id, "slot_unavailable")

    assert repeated.status_code == 200
    assert repeated.json()["recorded"] is False
    assert repeated.json()["state"] == "booked"
    assert conflicting.status_code == 409
    assert conflicting.json() == {"detail": "booking choice already has a different result"}
    assert len(update_notices(app)) == 1
    assert len(audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_RESULT)) == 1
    assert prompt_state(app, prompt_id) == "booked"


def test_a_slot_unavailable_repeat_is_idempotent_too() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id
    assert report(app, prompt_id, choice_id, "slot_unavailable").status_code == 200

    repeated = report(
        app,
        prompt_id,
        choice_id,
        "slot_unavailable",
        offered_slots=[slot("carlos:slot:9", local_time(12, 11))],
    )
    conflicting = report(app, prompt_id, choice_id, "booked")

    assert repeated.status_code == 200
    assert repeated.json()["recorded"] is False
    # A repeat changes nothing, so replacements sent with it are not added either.
    assert "carlos:slot:9" not in slot_row_ids(app, prompt_id)
    assert conflicting.status_code == 409
    assert len(update_notices(app)) == 1


def test_a_result_must_name_the_prompts_pending_choice() -> None:
    app, patient, prompt_id = patient_with_offer()
    other_prompt = create_prompt(app, operation_id="other-offer")
    assert pick(app, patient, prompt_id).status_code == 303
    assert pick(app, patient, other_prompt).status_code == 303
    with app.state.session_factory() as session:
        choice_ids = {
            choice.prompt_id: choice.id
            for choice in session.scalars(select(PatientPortalBookingChoice))
        }

    unknown_choice = report(app, prompt_id, 999_999, "booked")
    other_prompts_choice = report(app, prompt_id, choice_ids[other_prompt], "booked")
    unknown_prompt = report(app, 999_999, choice_ids[prompt_id], "booked")
    booked_with_replacements = report(
        app,
        prompt_id,
        choice_ids[prompt_id],
        "booked",
        offered_slots=[slot("carlos:slot:9", local_time(12, 11))],
    )
    unknown_result = report(app, prompt_id, choice_ids[prompt_id], "maybe")

    assert unknown_choice.status_code == 409
    assert unknown_choice.json() == {"detail": "booking choice is not pending"}
    assert other_prompts_choice.status_code == 409
    assert unknown_prompt.status_code == 404
    assert unknown_prompt.json() == {"detail": "booking prompt not found"}
    assert booked_with_replacements.status_code == 422
    assert unknown_result.status_code == 422
    assert len(pending_choices(app).json()["items"]) == 2
    assert update_notices(app) == []


def test_slot_unavailable_lets_the_patient_pick_again_from_the_rest() -> None:
    app, patient, prompt_id = patient_with_offer()
    row_ids = slot_row_ids(app, prompt_id)
    assert choose(patient, prompt_id, row_ids["carlos:slot:1"]).status_code == 303
    first_choice_id = only_choice(app).id

    reported = report(app, prompt_id, first_choice_id, "slot_unavailable")

    assert reported.status_code == 200
    assert reported.json()["state"] == "read"
    assert reported.json()["offered_slot_count"] == 2
    page = open_message(patient, prompt_id)
    assert "That time was just taken. Please pick another." in page.text
    assert expected_when(FIRST) not in page.text
    assert expected_when(SECOND) in page.text and expected_when(THIRD) in page.text
    assert set(slot_row_ids(app, prompt_id)) == {"carlos:slot:2", "carlos:slot:3"}
    # The taken time is not kept: the choice no longer says which one it was.
    with app.state.session_factory() as session:
        first = session.get(PatientPortalBookingChoice, first_choice_id)
        assert (first.state, first.slot_id, first.starts_at) == ("slot_unavailable", None, None)

    again = choose(patient, prompt_id, row_ids["carlos:slot:3"])

    assert again.status_code == 303
    assert "We are confirming your time with the clinic." in open_message(patient, prompt_id).text
    assert [item["slot_id"] for item in pending_choices(app).json()["items"]] == ["carlos:slot:3"]


def test_slot_unavailable_can_bring_replacement_times() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id
    replacement = local_time(10, 16, 20)

    reported = report(
        app,
        prompt_id,
        choice_id,
        "slot_unavailable",
        offered_slots=[slot("carlos:slot:4", replacement, visit_mode="phone", location_code=None)],
    )

    assert reported.status_code == 200
    assert reported.json()["offered_slot_count"] == 3
    page = open_message(patient, prompt_id)
    assert expected_when(replacement) in page.text
    with app.state.session_factory() as session:
        positions = [
            (row.slot_id, row.position)
            for row in session.scalars(
                select(PatientPortalBookingOfferedSlot).order_by(
                    PatientPortalBookingOfferedSlot.position
                )
            )
        ]
    assert positions == [("carlos:slot:2", 1), ("carlos:slot:3", 2), ("carlos:slot:4", 3)]
    offers = audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_OFFER)
    assert [event.reason for event in offers] == ["initial:3", "replacement:1"]


@pytest.mark.parametrize(
    "replacements",
    [
        pytest.param(
            [slot("carlos:slot:9", utc_now() - timedelta(minutes=1))], id="in-the-past"
        ),
        pytest.param([slot("carlos:slot:2", local_time(12, 11))], id="already-offered"),
        pytest.param([slot("carlos:slot:1", local_time(12, 11))], id="the-taken-time"),
        pytest.param(
            [slot(f"carlos:slot:{index + 10}", local_time(12, 8 + index)) for index in range(7)],
            id="over-the-cap",
        ),
        pytest.param([slot("carlos:slot:9", local_time(12, 11), location_code="north")],
                     id="unknown-location"),
        pytest.param(
            [slot("carlos:slot:9", local_time(12, 11)), slot("carlos:slot:9", local_time(13, 11))],
            id="duplicates",
        ),
    ],
)
def test_invalid_replacement_times_leave_the_choice_pending(replacements) -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id

    reported = report(app, prompt_id, choice_id, "slot_unavailable", offered_slots=replacements)

    assert reported.status_code == 422
    assert only_choice(app).state == "pending"
    assert set(slot_row_ids(app, prompt_id)) == {"carlos:slot:1", "carlos:slot:2", "carlos:slot:3"}
    assert update_notices(app) == []
    assert audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_RESULT) == []


def test_slot_unavailable_with_nothing_left_shows_the_contact_message() -> None:
    app = booking_app()
    patient = TestClient(app)
    browser_sign_in_seeded_patient(app, patient)
    prompt_id = create_prompt(app, offered_slots=[slot("carlos:slot:1", FIRST)])
    assert pick(app, patient, prompt_id).status_code == 303

    assert report(app, prompt_id, only_choice(app).id, "slot_unavailable").status_code == 200

    page = open_message(patient, prompt_id)
    assert "That time was just taken. Please contact the clinic." in page.text
    assert "To book, contact Example Clinic." in page.text
    assert 'name="slot"' not in page.text


def test_replacements_for_an_expired_prompt_are_not_stored() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    move_prompt_expiry(app, prompt_id, expires_at=utc_now() - timedelta(minutes=1))

    reported = report(
        app,
        prompt_id,
        only_choice(app).id,
        "slot_unavailable",
        offered_slots=[slot("carlos:slot:9", local_time(12, 11))],
    )

    assert reported.status_code == 200
    assert reported.json()["state"] == "expired"
    assert reported.json()["offered_slot_count"] == 0
    assert "carlos:slot:9" not in slot_row_ids(app, prompt_id)


def test_a_booked_prompt_stays_booked_after_it_expires_until_a_day_after_the_visit() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    assert report(app, prompt_id, only_choice(app).id, "booked").status_code == 200
    move_prompt_expiry(app, prompt_id, expires_at=utc_now() - timedelta(days=1))

    assert prompt_state(app, prompt_id) == "booked"
    assert "Booked for" in open_message(patient, prompt_id).text

    with app.state.session_factory.begin() as session:
        session.scalar(select(PatientPortalBookingChoice)).starts_at = utc_now() - timedelta(
            hours=25
        )
    assert patient.get(f"/portal/messages/{prompt_id}").status_code == 404
    assert "Book a follow-up appointment" not in patient.get("/portal/messages").text


# --------------------------------------------------------------------------------------
# Who may call the sync endpoints
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "permission"),
    [route for route in INTERNAL_ROUTE_PERMISSIONS if route[2] != SYNC],
)
def test_the_sync_principal_is_refused_by_every_other_internal_route(
    method, path, permission
) -> None:
    app = booking_app()

    response = TestClient(app).request(method, path, headers=sync_headers())

    assert response.status_code == 403, f"{method} {path} accepted the sync permission"
    assert response.json() == {"detail": "permission denied"}


def test_the_sync_principal_cannot_create_read_accounts_or_manage_invites() -> None:
    app = booking_app()
    activate_seeded_patient_account(app, TestClient(app))
    client = TestClient(app)

    created = client.post(PROMPTS_PATH, headers=sync_headers(), json=prompt_request())
    account = client.get(
        "/internal/carlos/patients/1234/portal-account", headers=sync_headers()
    )
    invites = client.get("/internal/carlos/patients/1234/invites", headers=sync_headers())

    assert [created.status_code, account.status_code, invites.status_code] == [403, 403, 403]
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count(PatientPortalBookingPrompt.id))) == 0


def test_the_sync_endpoints_require_the_sync_permission_not_manage() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    client = TestClient(app)

    listed = client.get(CHOICES_PATH, headers=staff_headers(MANAGE))
    reported = client.post(
        f"/internal/carlos/booking-prompts/{prompt_id}/choice-result",
        headers=staff_headers(MANAGE),
        json={"choice_id": only_choice(app).id, "result": "booked"},
    )

    assert listed.status_code == 403
    assert reported.status_code == 403
    assert only_choice(app).state == "pending"


# --------------------------------------------------------------------------------------
# Notices
# --------------------------------------------------------------------------------------


def test_the_update_email_carries_no_appointment_details() -> None:
    message = booking_prompt_update_email_message(
        service_name="CARLOS Patient Portal",
        clinic_name="Example Clinic",
        sign_in_url="https://portal.example.test/",
    )
    text = (message.subject + "\n" + message.body).casefold()

    assert "https://portal.example.test/" in message.body
    for leaked in (
        *(day.casefold() for day in WEEKDAYS),
        *(month.casefold() for month in MONTHS),
        "10:30", "minutes", "phone", "video", "in person", "main street", "office",
        "dr.", "follow", "booked", "taken", "slot", "time",
    ):
        assert leaked not in text, leaked


@pytest.mark.parametrize("result", ["booked", "slot_unavailable"])
def test_the_result_notice_says_only_that_there_is_an_update(result) -> None:
    app, patient, prompt_id = patient_with_offer()
    sender = RecordingPortalEmailSender()
    deliver_all(app, sender)
    assert [message["type"] for message in sender.messages] == ["booking_prompt_notice"]
    listed = TestClient(app).get(PROMPTS_PATH, headers=staff_headers()).json()
    notified_at = listed[0]["notified_at"]
    assert pick(app, patient, prompt_id).status_code == 303
    assert report(app, prompt_id, only_choice(app).id, result).status_code == 200

    (notice,) = update_notices(app)
    payload = delivery_outbox._decrypt_payload(notice, encryption_secret=OUTBOX_ENCRYPTION_SECRET)
    deliver_all(app, sender)

    # Nothing about the time or the result, and no address: it goes to the account's email.
    assert payload == {"sign_in_url": "http://testserver/"}
    assert sender.messages[-1] == {
        "recipient": "example.patient@example.com",
        "sign_in_url": "http://testserver/",
        "type": "booking_prompt_update_notice",
        "message_id": sender.messages[-1]["message_id"],
    }
    listed = TestClient(app).get(PROMPTS_PATH, headers=staff_headers()).json()[0]
    # `notified_at` is about the prompt's own notice; an update does not move it.
    assert listed["notified_at"] == notified_at
    deliveries = [
        (event.outcome, event.reason)
        for event in audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_DELIVERY)
    ]
    assert deliveries == [(AUDIT_OUTCOME_SUCCESS, None), (AUDIT_OUTCOME_SUCCESS, "update_notice")]


def test_the_update_notice_is_not_sent_once_the_prompt_is_withdrawn() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    assert report(app, prompt_id, only_choice(app).id, "booked").status_code == 200
    assert TestClient(app).post(
        f"/internal/carlos/booking-prompts/{prompt_id}/withdraw", headers=staff_headers()
    ).status_code == 200
    sender = RecordingPortalEmailSender()

    deliver_all(app, sender)

    assert "booking_prompt_update_notice" not in [message["type"] for message in sender.messages]
    (notice,) = update_notices(app)
    assert notice.status == OUTBOX_STATUS_FAILED
    assert notice.last_failure_code == OUTBOX_FAILURE_BOOKING_PROMPT_NOT_NEEDED


def test_the_update_notice_goes_to_a_booked_prompt_even_after_its_expiry() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    move_prompt_expiry(app, prompt_id, expires_at=utc_now() - timedelta(minutes=1))
    assert report(app, prompt_id, only_choice(app).id, "booked").status_code == 200
    sender = RecordingPortalEmailSender()

    deliver_all(app, sender)

    (notice,) = update_notices(app)
    assert notice.status == OUTBOX_STATUS_DELIVERED


# --------------------------------------------------------------------------------------
# Withdrawal and retention
# --------------------------------------------------------------------------------------


def test_withdrawing_deletes_the_offer_and_closes_a_waiting_choice() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id

    withdrawn = TestClient(app).post(
        f"/internal/carlos/booking-prompts/{prompt_id}/withdraw", headers=staff_headers()
    )

    assert withdrawn.json()["state"] == "withdrawn"
    assert slot_row_ids(app, prompt_id) == {}
    choice = only_choice(app)
    assert (choice.state, choice.slot_id, choice.starts_at) == ("withdrawn", None, None)
    assert choice.result_at is not None
    assert pending_choices(app).json()["items"] == []
    late_result = report(app, prompt_id, choice_id, "booked")
    assert late_result.status_code == 409
    assert late_result.json() == {"detail": "booking choice was withdrawn"}
    assert patient.get(f"/portal/messages/{prompt_id}").status_code == 404


def test_withdrawing_a_booked_prompt_forgets_the_booked_time() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id
    assert report(app, prompt_id, choice_id, "booked").status_code == 200

    TestClient(app).post(
        f"/internal/carlos/booking-prompts/{prompt_id}/withdraw", headers=staff_headers()
    )

    assert only_choice(app).starts_at is None
    # A late repeat of the result CARLOS already reported is still answered idempotently.
    assert report(app, prompt_id, choice_id, "booked").json()["recorded"] is False


def test_cleanup_deletes_times_as_soon_as_they_cannot_be_picked() -> None:
    app = booking_app()
    patient = TestClient(app)
    browser_sign_in_seeded_patient(app, patient)
    expired = create_prompt(app, operation_id="expired")
    started = create_prompt(app, operation_id="started")
    live = create_prompt(app, operation_id="live")
    move_prompt_expiry(app, expired, expires_at=utc_now() - timedelta(minutes=1))
    with app.state.session_factory.begin() as session:
        session.get(
            PatientPortalBookingOfferedSlot, slot_row_ids(app, started)["carlos:slot:1"]
        ).starts_at = utc_now() - timedelta(minutes=1)
    retention_cutoff = utc_now() - timedelta(days=30)

    with app.state.session_factory.begin() as session:
        dry_run = cleanup_transient_auth_rows(session, before=retention_cutoff, dry_run=True)
    with app.state.session_factory.begin() as session:
        removed = cleanup_transient_auth_rows(session, before=retention_cutoff)

    # Not after the 30-day retention window: at the first run after expiry.
    assert dry_run.offered_slots == 4
    assert removed.offered_slots == 4
    assert removed.booking_prompts == 0
    assert slot_row_ids(app, expired) == {}
    assert set(slot_row_ids(app, started)) == {"carlos:slot:2", "carlos:slot:3"}
    assert len(slot_row_ids(app, live)) == 3


def test_cleanup_clears_a_booked_time_a_day_after_the_appointment() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    assert report(app, prompt_id, only_choice(app).id, "booked").status_code == 200
    long_ago = utc_now() - timedelta(days=200)
    move_prompt_expiry(app, prompt_id, expires_at=long_ago)
    with app.state.session_factory.begin() as session:
        for notice in session.scalars(select(PatientPortalOutboundDelivery)):
            notice.status = OUTBOX_STATUS_FAILED
            notice.created_at = long_ago
        session.scalar(select(PatientPortalBookingChoice)).starts_at = utc_now() - timedelta(
            hours=23
        )
    retention_cutoff = utc_now() - timedelta(days=30)

    with app.state.session_factory.begin() as session:
        within_the_day = cleanup_transient_auth_rows(session, before=retention_cutoff)
    kept = only_choice(app)
    with app.state.session_factory.begin() as session:
        session.scalar(select(PatientPortalBookingChoice)).starts_at = utc_now() - timedelta(
            hours=25
        )
    with app.state.session_factory.begin() as session:
        dry_run = cleanup_transient_auth_rows(session, before=retention_cutoff, dry_run=True)
    with app.state.session_factory.begin() as session:
        after_the_day = cleanup_transient_auth_rows(session, before=retention_cutoff)

    # The booked appointment keeps its prompt, long expired, until a day after it starts.
    assert within_the_day.booking_choice_times == 0
    assert within_the_day.booking_prompts == 0
    assert kept.starts_at is not None
    assert dry_run.booking_choice_times == 1
    assert after_the_day.booking_choice_times == 1
    assert after_the_day.booking_prompts == 1
    with app.state.session_factory() as session:
        assert session.get(PatientPortalBookingPrompt, prompt_id) is None
        assert session.scalar(select(func.count(PatientPortalBookingChoice.id))) == 0
    # The record of what happened stays.
    assert len(audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_RESULT)) == 1


def test_cleanup_clears_a_booked_time_on_a_prompt_that_is_kept() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    assert report(app, prompt_id, only_choice(app).id, "booked").status_code == 200
    with app.state.session_factory.begin() as session:
        session.scalar(select(PatientPortalBookingChoice)).starts_at = utc_now() - timedelta(
            hours=25
        )

    with app.state.session_factory.begin() as session:
        cleared = cleanup_transient_auth_rows(session, before=utc_now() - timedelta(days=30))

    assert cleared.booking_choice_times == 1
    choice = only_choice(app)
    assert (choice.state, choice.slot_id, choice.starts_at, choice.visit_mode) == (
        "booked",
        None,
        None,
        None,
    )
    assert prompt_state(app, prompt_id) == "booked"


# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------


def test_booking_locations_parse_in_order() -> None:
    settings = development_settings(
        booking_locations=" main = Main Street Office ,east=East Office"
    )

    assert list(settings.resolved_booking_locations.items()) == [
        ("main", "Main Street Office"),
        ("east", "East Office"),
    ]
    assert development_settings(booking_locations="  ").resolved_booking_locations == {}
    assert development_settings().resolved_booking_locations == {}


@pytest.mark.parametrize(
    "value",
    [
        "Main=Main Street",
        "main",
        "main=",
        "=Main Street",
        "main=Main Street,main=Other",
        "main=" + "x" * 65,
        "main=Main‮Street",
        "main=Main\tStreet",
        "m" * 33 + "=Main Street",
    ],
)
def test_booking_locations_refuse_anything_else(value) -> None:
    with pytest.raises(ValidationError, match="BOOKING_LOCATIONS"):
        development_settings(booking_locations=value)


@pytest.mark.parametrize("value", [0, 24 * 60 + 1])
def test_booking_choice_wait_minutes_is_bounded(value) -> None:
    with pytest.raises(ValidationError):
        development_settings(booking_choice_wait_minutes=value)
    assert development_settings().booking_choice_wait_minutes == 15


# --------------------------------------------------------------------------------------
# Migration
# --------------------------------------------------------------------------------------


def test_offered_slot_migration_downgrades_only_without_new_records(tmp_path) -> None:
    config = Config()
    config.set_main_option("script_location", "carlos_patient_portal:migrations")
    database_url = f"sqlite+pysqlite:///{tmp_path / 'offered-slots.db'}"
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0015_booking_offered_slots")
    engine = create_engine(database_url)
    now = utc_now()
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "insert into patient_portal_accounts (id, clinic_id, demographic_no, "
                    "username, email, preferred_mfa_method, password_hash, status, "
                    "failed_login_count, force_password_reset, created_at, updated_at, "
                    "password_updated_at, failed_mfa_count) values (1, 'default', 1234, "
                    "'patient.user', 'patient@example.test', 'email', 'stored-hash', 'active', "
                    "0, false, :now, :now, :now, 0)"
                ),
                {"now": now},
            )
            connection.execute(
                text(
                    "insert into patient_portal_booking_prompts (id, clinic_id, demographic_no, "
                    "account_id, operation_id, urgency, appointment_type, status, created_by, "
                    "created_at, expires_at, read_at) values (1, 'default', 1234, 1, 'op', "
                    "'soon', 'follow_up', 'booked', 'Front Desk', :now, :later, :now)"
                ),
                {"now": now, "later": now + timedelta(days=1)},
            )
            connection.execute(
                text(
                    "insert into patient_portal_audit_events "
                    "(event_type, outcome, actor_type, created_at) "
                    "values ('booking_prompt.choice', 'success', 'patient', :now)"
                ),
                {"now": now},
            )
        with pytest.raises(RuntimeError, match="offered-time audit events exist"):
            command.downgrade(config, "0014_booking_prompts")
        with engine.begin() as connection:
            connection.execute(text("delete from patient_portal_audit_events"))
        # Folding a booked prompt back to "read" would rewrite what happened.
        with pytest.raises(RuntimeError, match="choice_pending, booked or declined_all"):
            command.downgrade(config, "0014_booking_prompts")
        with engine.begin() as connection:
            connection.execute(
                text("update patient_portal_booking_prompts set status = 'read'")
            )
        command.downgrade(config, "0014_booking_prompts")
        tables = inspect(engine).get_table_names()
        assert "patient_portal_booking_offered_slots" not in tables
        assert "patient_portal_booking_choices" not in tables
        assert "offer_digest" not in {
            column["name"]
            for column in inspect(engine).get_columns("patient_portal_booking_prompts")
        }
        command.upgrade(config, "head")
        assert "patient_portal_booking_choices" in inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_a_second_pending_choice_is_refused_by_the_database() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303

    with pytest.raises(Exception, match="(?i)unique"):
        with app.state.session_factory.begin() as session:
            session.add(
                PatientPortalBookingChoice(
                    prompt_id=prompt_id,
                    clinic_id="clinic-a",
                    slot_id="carlos:slot:2",
                    starts_at=SECOND,
                    duration_minutes=30,
                    visit_mode="phone",
                    state="pending",
                    chosen_at=utc_now(),
                )
            )


@pytest.mark.parametrize("dry_run", [True, False])
def test_cleanup_preserves_unanswered_choices_after_retention(dry_run) -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id
    long_ago = utc_now() - timedelta(days=200)
    move_prompt_expiry(app, prompt_id, expires_at=long_ago)
    with app.state.session_factory.begin() as session:
        for notice in session.scalars(select(PatientPortalOutboundDelivery)):
            notice.status = OUTBOX_STATUS_FAILED
            notice.created_at = long_ago
    with app.state.session_factory.begin() as session:
        cleaned = cleanup_transient_auth_rows(
            session, before=utc_now() - timedelta(days=30), dry_run=dry_run
        )
    assert cleaned.booking_prompts == 0
    assert cleaned.booking_choice_times == 0
    assert only_choice(app).state == "pending"
    assert pending_choices(app).json()["items"][0]["choice_id"] == choice_id
    assert open_message(patient, prompt_id).status_code == 200
    assert report(app, prompt_id, choice_id, "booked").status_code == 200


@pytest.mark.parametrize("clear_copy", [False, True])
def test_delayed_notice_is_suppressed_after_booked_confirmation_disappears(clear_copy) -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    assert report(app, prompt_id, only_choice(app).id, "booked").status_code == 200
    with app.state.session_factory.begin() as session:
        session.scalar(select(PatientPortalBookingChoice)).starts_at = utc_now() - timedelta(days=2)
    if clear_copy:
        with app.state.session_factory.begin() as session:
            cleanup_transient_auth_rows(session, before=utc_now() - timedelta(days=30))
    assert patient.get(f"/portal/messages/{prompt_id}").status_code == 404
    sender = RecordingPortalEmailSender()
    deliver_all(app, sender)
    assert not sender.messages
    (notice,) = update_notices(app)
    assert notice.last_failure_code == OUTBOX_FAILURE_BOOKING_PROMPT_NOT_NEEDED


def test_stale_form_cannot_select_a_replacement_after_all_original_slots_are_deleted() -> None:
    app = booking_app()
    patient = TestClient(app)
    browser_sign_in_seeded_patient(app, patient)
    prompt_id = create_prompt(app, offered_slots=[default_slots()[0]])
    stale_id = slot_row_ids(app, prompt_id)["carlos:slot:1"]
    assert choose(patient, prompt_id, stale_id).status_code == 303
    assert report(
        app, prompt_id, only_choice(app).id, "slot_unavailable",
        offered_slots=[slot("replacement", SECOND)],
    ).status_code == 200
    assert slot_row_ids(app, prompt_id)["replacement"] != stale_id
    assert choose(patient, prompt_id, stale_id).status_code == 409
    assert pending_choices(app).json()["items"] == []


def test_last_taken_slot_tells_patient_to_contact_clinic() -> None:
    app = booking_app()
    patient = TestClient(app)
    browser_sign_in_seeded_patient(app, patient)
    prompt_id = create_prompt(app, offered_slots=[default_slots()[0]])
    assert pick(app, patient, prompt_id).status_code == 303
    assert report(app, prompt_id, only_choice(app).id, "slot_unavailable").status_code == 200
    page = open_message(patient, prompt_id)
    assert "That time was just taken. Please contact the clinic." in page.text
    assert "Please pick another" not in page.text


# --------------------------------------------------------------------------------------
# Review fixes: late answers, repeated submissions, stored ids, bounds, and the sync principal
# --------------------------------------------------------------------------------------


def delete_prompt_notices(app) -> None:
    """Drop the prompt's emails, which on their own keep a prompt from cleanup until they age
    out."""
    with app.state.session_factory.begin() as session:
        for notice in session.scalars(
            select(PatientPortalOutboundDelivery).where(
                PatientPortalOutboundDelivery.kind.in_(
                    (OUTBOX_KIND_BOOKING_PROMPT, OUTBOX_KIND_BOOKING_PROMPT_UPDATE)
                )
            )
        ):
            session.delete(notice)


def test_a_pick_taken_after_the_prompt_expired_is_still_shown_and_emailed() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice = only_choice(app)
    move_prompt_expiry(app, prompt_id, expires_at=utc_now() - timedelta(minutes=1))

    assert report(app, prompt_id, choice.id, "slot_unavailable").status_code == 200

    # The patient was waiting on that pick: they learn it fell through, and cannot pick again.
    page = open_message(patient, prompt_id)
    assert "That time was just taken. Please contact the clinic." in page.text
    assert 'name="slot"' not in page.text
    assert f"/portal/messages/{prompt_id}" in patient.get("/portal/messages").text
    deliver_all(app, RecordingPortalEmailSender())
    assert [notice.status for notice in update_notices(app)] == [OUTBOX_STATUS_DELIVERED]
    assert prompt_state(app, prompt_id) == "expired"


def test_the_taken_notice_after_expiry_lasts_a_week_and_cleanup_keeps_it_until_then() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice = only_choice(app)
    move_prompt_expiry(app, prompt_id, expires_at=utc_now() - timedelta(days=40))
    assert report(app, prompt_id, choice.id, "slot_unavailable").status_code == 200
    delete_prompt_notices(app)
    retention_cutoff = utc_now() - timedelta(days=30)

    with app.state.session_factory.begin() as session:
        kept = cleanup_transient_auth_rows(session, before=retention_cutoff)
    assert kept.booking_prompts == 0
    open_message(patient, prompt_id)

    with app.state.session_factory.begin() as session:
        session.get(PatientPortalBookingChoice, choice.id).result_at = utc_now() - timedelta(days=8)
    assert patient.get(f"/portal/messages/{prompt_id}").status_code == 404
    with app.state.session_factory.begin() as session:
        removed = cleanup_transient_auth_rows(session, before=retention_cutoff)
    assert removed.booking_prompts == 1


def test_a_pick_taken_before_the_prompt_expired_ends_with_the_prompt() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id
    assert report(app, prompt_id, choice_id, "slot_unavailable").status_code == 200
    with app.state.session_factory.begin() as session:
        session.get(PatientPortalBookingChoice, choice_id).result_at = utc_now() - timedelta(
            minutes=10
        )
    move_prompt_expiry(app, prompt_id, expires_at=utc_now() - timedelta(minutes=1))

    # Taken while the patient could still pick again: the prompt then expires as usual.
    assert patient.get(f"/portal/messages/{prompt_id}").status_code == 404


def test_choosing_the_same_time_twice_is_not_an_error() -> None:
    app, patient, prompt_id = patient_with_offer()
    rows = slot_row_ids(app, prompt_id)
    page = patient.get(f"/portal/messages/{prompt_id}")
    data = {"csrf_token": csrf_token_from_response(page), "slot": str(rows["carlos:slot:1"])}

    first = patient.post(f"/portal/messages/{prompt_id}/choice", data=data, follow_redirects=False)
    second = patient.post(f"/portal/messages/{prompt_id}/choice", data=data, follow_redirects=False)

    assert (first.status_code, second.status_code) == (303, 303)
    assert "could not be chosen" not in open_message(patient, prompt_id).text
    assert len(pending_choices(app).json()["items"]) == 1
    picks = [
        event
        for event in audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_CHOICE)
        if event.outcome == AUDIT_OUTCOME_SUCCESS
    ]
    assert len(picks) == 1
    # A different time while one is pending is still refused.
    assert choose(patient, prompt_id, rows["carlos:slot:2"]).status_code == 409


def test_declining_twice_is_not_an_error() -> None:
    app, patient, prompt_id = patient_with_offer()
    page = patient.get(f"/portal/messages/{prompt_id}")
    data = {"csrf_token": csrf_token_from_response(page)}
    path = f"/portal/messages/{prompt_id}/decline"

    first = patient.post(path, data=data, follow_redirects=False)
    second = patient.post(path, data=data, follow_redirects=False)

    assert (first.status_code, second.status_code) == (303, 303)
    declines = [
        event
        for event in audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_DECLINE)
        if event.outcome == AUDIT_OUTCOME_SUCCESS
    ]
    assert len(declines) == 1


def test_a_booked_pick_keeps_its_time_but_not_the_carlos_slot_id() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id

    assert report(app, prompt_id, choice_id, "booked").status_code == 200

    booked = only_choice(app)
    assert booked.slot_id is None
    assert booked.starts_at is not None
    assert "Booked for" in open_message(patient, prompt_id).text
    repeat = report(app, prompt_id, choice_id, "booked")
    assert repeat.status_code == 200
    assert repeat.json()["recorded"] is False


@pytest.mark.parametrize(
    "starts_at",
    ["9999-12-31T23:00:00-05:00", "0001-01-01T00:30:00+01:00"],
)
def test_a_start_out_of_range_is_refused_rather_than_failing(starts_at: str) -> None:
    app = booking_app()
    offered = [{**slot("carlos:slot:1", FIRST), "starts_at": starts_at}]

    response = TestClient(app).post(
        PROMPTS_PATH, headers=staff_headers(), json=prompt_request(offered_slots=offered)
    )

    assert response.status_code == 422


def test_a_time_more_than_a_year_ahead_is_refused() -> None:
    app, _patient, _prompt_id = patient_with_offer()
    offered = [slot("carlos:slot:1", datetime.now(UTC) + timedelta(days=400))]

    response = TestClient(app).post(
        PROMPTS_PATH,
        headers=staff_headers(),
        json=prompt_request(operation_id="far-ahead", offered_slots=offered),
    )

    assert response.status_code == 422


def test_a_result_for_a_withdrawn_pick_says_so() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id
    assert TestClient(app).post(
        f"/internal/carlos/booking-prompts/{prompt_id}/withdraw", headers=staff_headers()
    ).status_code == 200

    withdrawn = report(app, prompt_id, choice_id, "booked")
    unknown = report(app, prompt_id, choice_id + 100, "booked")

    assert (withdrawn.status_code, withdrawn.json()["detail"]) == (
        409,
        "booking choice was withdrawn",
    )
    assert (unknown.status_code, unknown.json()["detail"]) == (409, "booking choice is not pending")


def combined_sync_headers() -> dict[str, str]:
    return carlos_staff_headers(
        SYNC,
        MANAGE,
        clinic_id="clinic-a",
        token=INTERNAL_API_TOKEN,
        provider_id="carlos-booking-sync",
        provider_name="CARLOS booking sync",
    )


def test_the_sync_permission_is_only_accepted_on_its_own() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id
    client = TestClient(app)

    assert client.get(CHOICES_PATH, headers=combined_sync_headers()).status_code == 403
    assert client.post(
        f"/internal/carlos/booking-prompts/{prompt_id}/choice-result",
        headers=combined_sync_headers(),
        json={"choice_id": choice_id, "result": "booked"},
    ).status_code == 403
    assert client.get(PROMPTS_PATH, headers=combined_sync_headers()).status_code == 403
    # Nothing changed, and the sync principal on its own still works.
    assert prompt_state(app, prompt_id) == "choice_pending"
    assert len(pending_choices(app).json()["items"]) == 1


def test_the_polling_job_is_audited_as_the_system() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    assert len(pending_choices(app).json()["items"]) == 1
    assert report(app, prompt_id, only_choice(app).id, "booked").status_code == 200

    listed = [
        event
        for event in audit_events(app, AUDIT_EVENT_STAFF_ACTION)
        if event.reason == "pending_choices_listed"
    ]
    results = audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_RESULT)
    assert [event.actor_type for event in listed + results] == ["system", "system"]


# --------------------------------------------------------------------------------------
# A pick whose time starts before CARLOS answers, and the clinic's number while waiting
# --------------------------------------------------------------------------------------


def start_the_picked_time(app, prompt_id: int, *, slot_id: str = "carlos:slot:1") -> None:
    """Move the picked time (and its offered row) into the past, as if it started unanswered."""
    started = utc_now() - timedelta(minutes=1)
    with app.state.session_factory.begin() as session:
        session.get(
            PatientPortalBookingOfferedSlot, slot_row_ids(app, prompt_id)[slot_id]
        ).starts_at = started
        choice = session.scalar(
            select(PatientPortalBookingChoice).where(PatientPortalBookingChoice.state == "pending")
        )
        choice.starts_at = started


def test_a_pick_whose_time_starts_unanswered_is_closed_and_the_patient_can_pick_again() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    start_the_picked_time(app, prompt_id)

    # Not polled yet: the patient is already told it did not go through.
    waiting = open_message(patient, prompt_id).text
    assert (
        "That time passed before the clinic could confirm it. Please contact the clinic." in waiting
    )

    # The next poll closes it instead of listing it, and the patient gets the update email.
    assert pending_choices(app).json()["items"] == []
    choice = only_choice(app)
    assert (choice.state, choice.slot_id, choice.starts_at) == ("expired", None, None)
    assert prompt_state(app, prompt_id) == "read"
    deliver_all(app, RecordingPortalEmailSender())
    assert [notice.status for notice in update_notices(app)] == [OUTBOX_STATUS_DELIVERED]
    closed = [
        event
        for event in audit_events(app, AUDIT_EVENT_BOOKING_PROMPT_RESULT)
        if event.reason == "expired"
    ]
    assert [(event.actor_type, event.actor) for event in closed] == [("system", "portal")]

    page = open_message(patient, prompt_id).text
    assert "That time passed before the clinic could confirm it. Please pick another." in page
    assert set(slot_row_ids(app, prompt_id)) == {"carlos:slot:2", "carlos:slot:3"}
    assert pick(app, patient, prompt_id, "carlos:slot:2").status_code == 303


def test_a_late_result_for_a_pick_whose_time_started_is_refused() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    choice_id = only_choice(app).id
    start_the_picked_time(app, prompt_id)

    before_closing = report(app, prompt_id, choice_id, "booked")
    assert (before_closing.status_code, before_closing.json()["detail"]) == (
        409,
        "booking choice expired",
    )
    assert pending_choices(app).json()["items"] == []
    after_closing = report(app, prompt_id, choice_id, "booked")
    assert (after_closing.status_code, after_closing.json()["detail"]) == (
        409,
        "booking choice expired",
    )
    assert prompt_state(app, prompt_id) == "read"


def test_cleanup_closes_a_started_pick_when_carlos_has_stopped_polling() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    start_the_picked_time(app, prompt_id)
    retention_cutoff = utc_now() - timedelta(days=30)

    with app.state.session_factory.begin() as session:
        dry_run = cleanup_transient_auth_rows(session, before=retention_cutoff, dry_run=True)
    assert only_choice(app).state == "pending"
    with app.state.session_factory.begin() as session:
        removed = cleanup_transient_auth_rows(session, before=retention_cutoff)

    assert (dry_run.lapsed_booking_choices, removed.lapsed_booking_choices) == (1, 1)
    # The started time is left to the offered-time pass, so a dry run reports what a live run does.
    assert (dry_run.offered_slots, removed.offered_slots) == (1, 1)
    assert only_choice(app).state == "expired"
    # Cleanup has no request to build a sign-in link from: the portal message is the notice.
    assert update_notices(app) == []


def test_a_pick_that_lapses_after_the_prompt_expired_is_still_shown_briefly() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    move_prompt_expiry(app, prompt_id, expires_at=utc_now() - timedelta(minutes=5))
    start_the_picked_time(app, prompt_id)

    assert pending_choices(app).json()["items"] == []

    page = open_message(patient, prompt_id).text
    assert "That time passed before the clinic could confirm it. Please contact the clinic." in page
    assert 'name="slot"' not in page
    assert slot_row_ids(app, prompt_id) == {}
    assert prompt_state(app, prompt_id) == "expired"
    deliver_all(app, RecordingPortalEmailSender())
    assert [notice.status for notice in update_notices(app)] == [OUTBOX_STATUS_DELIVERED]


def test_the_waiting_message_gives_the_clinics_number_when_one_is_set() -> None:
    app, patient, prompt_id = patient_with_offer(clinic_booking_phone="555-123-4567")
    assert pick(app, patient, prompt_id).status_code == 303
    with app.state.session_factory.begin() as session:
        session.scalar(select(PatientPortalBookingChoice)).chosen_at = utc_now() - timedelta(
            minutes=20
        )

    page = open_message(patient, prompt_id).text

    assert (
        "The clinic will confirm your time. If it is urgent, call the clinic at 555-123-4567."
        in page
    )


def test_the_poll_never_lists_a_pick_whose_time_has_started_even_before_it_is_closed() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    start_the_picked_time(app, prompt_id)

    # The listing on its own, as when the closing pass skipped a prompt another writer held.
    with app.state.session_factory.begin() as session:
        page = list_pending_choices(
            session, clinic_id="clinic-a", actor="CARLOS booking sync", actor_id="sync"
        )

    assert page.choices == ()
    assert only_choice(app).state == "pending"


def test_closing_started_picks_stays_within_the_clinic() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    start_the_picked_time(app, prompt_id)

    with app.state.session_factory.begin() as session:
        closed = close_lapsed_choices(session, clinic_id="clinic-b")

    assert closed == 0
    assert only_choice(app).state == "pending"


def test_turning_an_account_off_clears_the_offer_of_an_expired_prompt() -> None:
    app, patient, prompt_id = patient_with_offer()
    assert pick(app, patient, prompt_id).status_code == 303
    move_prompt_expiry(app, prompt_id, expires_at=utc_now() - timedelta(minutes=1))

    assert TestClient(app).post(
        "/internal/carlos/patients/1234/portal-account/access",
        headers=staff_headers("portal.account.manage"),
        json={"enabled": False, "reason": "staff_action"},
    ).status_code == 200

    assert only_choice(app).state == "withdrawn"
    assert slot_row_ids(app, prompt_id) == {}


def test_a_pick_is_refused_once_the_account_is_off() -> None:
    app, patient, prompt_id = patient_with_offer()
    row_id = slot_row_ids(app, prompt_id)["carlos:slot:1"]
    with app.state.session_factory.begin() as session:
        account = session.scalar(select(PatientPortalAccount))
        account.status = "disabled"
        account.disabled_at = utc_now()
        account.disabled_by = "Synthetic Staff"
    with app.state.session_factory.begin() as session:
        account = session.scalar(select(PatientPortalAccount))
        with pytest.raises(BookingPromptNotFoundError):
            choose_offered_slot(session, prompt_id, row_id, account=account)

    assert pending_choices(app).json()["items"] == []
