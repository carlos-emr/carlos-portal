"""Seed the isolated development database used by the Playwright CI smoke test.

Run without arguments to seed. `choice-result booked|slot_unavailable` stands in for the CARLOS
polling job: it reports a result for the patient's pending pick on the seeded offer, through the
same service function the internal API uses. The browser run has no CARLOS and no internal API
token, so the Playwright script calls this instead.
"""

import json
import os
import sys
import tempfile
from datetime import date, datetime, time, timedelta
from pathlib import Path
from secrets import token_urlsafe
from zoneinfo import ZoneInfo

from sqlalchemy import select

from carlos_patient_portal.accounts import ActivationRateLimit, activate_patient_account
from carlos_patient_portal.auth import request_password_reset
from carlos_patient_portal.booking_choices import record_choice_result
from carlos_patient_portal.booking_offers import OfferedSlotSpec, add_offered_slots, offer_digest
from carlos_patient_portal.booking_prompts import BookingPromptNotice
from carlos_patient_portal.config import Settings, get_settings
from carlos_patient_portal.database import create_portal_engine, create_session_factory
from carlos_patient_portal.identity import IdentityProof
from carlos_patient_portal.invites import create_invite
from carlos_patient_portal.models import (
    BOOKING_CHOICE_STATE_PENDING,
    BOOKING_PROMPT_STATUS_SENT,
    PatientPortalBookingChoice,
    PatientPortalBookingPrompt,
    utc_now,
)
from carlos_patient_portal.runtime import auth_policy_from_settings
from carlos_patient_portal.token_keys import PortalTokenKeys
from carlos_patient_portal.unlock_secrets import create_unlock_secret

DEVELOPMENT_PASSWORD = "-".join(("Nectar", "Sparrow", "Quartz", "87!"))
ACTIVATION_PASSWORD = "-".join(("Cedar", "River", "Comet", "62!"))
ACTIVATION_EMAIL = "activation.patient@example.com"
ACTIVATION_DATE_OF_BIRTH = date(1975, 9, 14)
ACTIVATION_HEALTH_CARD_NUMBER = "EFGH 9876-5432"
ACTIVATION_USERNAME = "PlaywrightActivate"
RESET_OLD_PASSWORD = "-".join(("Willow", "Harbour", "Flint", "38!"))
RESET_NEW_PASSWORD = "-".join(("Maple", "Voyage", "Star", "74!"))
RESET_EMAIL = "reset.patient@example.com"
RESET_DATE_OF_BIRTH = date(1968, 2, 29)
RESET_HEALTH_CARD_NUMBER = "IJKL 2468-1357"
RESET_USERNAME = "PlaywrightReset"
OFFER_OPERATION_ID = "ci-booking-offer-1"


def _clinic_time(settings: Settings, days_ahead: int, hour: int, minute: int) -> datetime:
    clinic_zone = ZoneInfo(settings.clinic_timezone)
    day = datetime.now(clinic_zone).date() + timedelta(days=days_ahead)
    return datetime.combine(day, time(hour, minute), tzinfo=clinic_zone)


def browser_offered_slots(settings: Settings) -> tuple[OfferedSlotSpec, ...]:
    return (
        OfferedSlotSpec("ci-slot-1", _clinic_time(settings, 7, 10, 30), 30, "in_person"),
        OfferedSlotSpec("ci-slot-2", _clinic_time(settings, 8, 14, 0), 45, "phone"),
        OfferedSlotSpec("ci-slot-3", _clinic_time(settings, 9, 9, 15), 30, "video"),
    )


def browser_replacement_slots(settings: Settings) -> tuple[OfferedSlotSpec, ...]:
    return (OfferedSlotSpec("ci-slot-4", _clinic_time(settings, 10, 16, 20), 30, "phone"),)


def main() -> None:
    settings = get_settings()
    if settings.session_secret is None:
        raise RuntimeError(
            "PATIENT_PORTAL_SESSION_SECRET is required to seed browser reset fixtures"
        )
    token_keys = PortalTokenKeys.derive(settings.session_secret.get_secret_value())
    keyring = settings.resolved_unlock_secret_keyring
    encryption_secret = keyring[settings.unlock_secret_active_key_id]
    engine = create_portal_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    fixture_path = Path(
        os.environ.get(
            "PORTAL_BROWSER_FIXTURE_FILE",
            str(Path(tempfile.gettempdir()) / "patient-portal-browser-fixtures.json"),
        )
    )
    try:
        with session_factory() as session:
            with session.begin():
                _, invite_token = create_invite(
                    session,
                    1234,
                    "CI seed",
                    clinic_id=settings.clinic_id,
                    actor_id="ci-seed",
                    identity_proof=IdentityProof(
                        email="example.patient@example.com",
                        date_of_birth=date(1980, 5, 20),
                        health_card_number="ABCD 1234-5678",
                    ),
                    proof_secret=settings.identity_proof_secret.get_secret_value(),
                )
                account = activate_patient_account(
                    session,
                    invite_code=invite_token,
                    identity_proof=IdentityProof(
                        email="example.patient@example.com",
                        date_of_birth=date(1980, 5, 20),
                        health_card_number="ABCD 1234-5678",
                    ),
                    username="CarlosPatient",
                    password=DEVELOPMENT_PASSWORD,
                    proof_secret=settings.identity_proof_secret.get_secret_value(),
                    client_reference_hash="0" * 64,
                    rate_limit=ActivationRateLimit(
                        failure_window=timedelta(hours=1),
                        max_failures_per_invite=10,
                        max_failures_per_client=50,
                    ),
                    expected_clinic_id=settings.clinic_id,
                )
                for index, label in enumerate(
                    (
                        "Care plan password",
                        "Referral package password",
                        "Lab results password",
                        "Imaging report password",
                        "Consultation note password",
                        "Medication summary password",
                        "Discharge summary password",
                        "Specialist letter password",
                        "Appointment package password",
                        "Insurance form password",
                        "Vaccination record password",
                        "Treatment plan password",
                    ),
                    start=1,
                ):
                    create_unlock_secret(
                        session,
                        clinic_id=settings.clinic_id,
                        demographic_no=account.demographic_no,
                        account_id=account.id,
                        created_by="CarlosDoc",
                        created_by_id="provider-42",
                        encryption_secret=encryption_secret,
                        encryption_key_id=settings.unlock_secret_active_key_id,
                        label=label,
                        source_reference=f"ci-message-{index}",
                    )
                # One unread booking prompt for the Messages check. Inserted directly: the browser
                # run has no outbox worker, and the prompt is what the patient reads.
                seeded_at = utc_now()
                session.add(
                    PatientPortalBookingPrompt(
                        clinic_id=settings.clinic_id,
                        demographic_no=account.demographic_no,
                        account_id=account.id,
                        operation_id="ci-booking-prompt-1",
                        urgency="soon",
                        appointment_type="follow_up",
                        suggested_by="Dr. Singh",
                        status=BOOKING_PROMPT_STATUS_SENT,
                        created_by="CarlosDoc",
                        created_by_id="provider-42",
                        created_at=seeded_at,
                        expires_at=seeded_at + timedelta(days=90),
                    )
                )
                # A second prompt offering times, for the pick, confirm, and pick-again check.
                offered_slots = browser_offered_slots(settings)
                offer_prompt = PatientPortalBookingPrompt(
                    clinic_id=settings.clinic_id,
                    demographic_no=account.demographic_no,
                    account_id=account.id,
                    operation_id=OFFER_OPERATION_ID,
                    urgency="routine",
                    appointment_type="annual_exam",
                    suggested_by=None,
                    status=BOOKING_PROMPT_STATUS_SENT,
                    created_by="CarlosDoc",
                    created_by_id="provider-42",
                    created_at=seeded_at,
                    expires_at=seeded_at + timedelta(days=90),
                    offer_digest=offer_digest(
                        offered_slots,
                        secret=(
                            settings.audit_hash_secret.get_secret_value()
                            if settings.audit_hash_secret is not None
                            else token_urlsafe(32)
                        ),
                    ),
                )
                session.add(offer_prompt)
                session.flush()
                add_offered_slots(session, offer_prompt.id, offered_slots)
                _, activation_invite_token = create_invite(
                    session,
                    5678,
                    "CI browser activation",
                    clinic_id=settings.clinic_id,
                    actor_id="ci-seed",
                    identity_proof=IdentityProof(
                        email=ACTIVATION_EMAIL,
                        date_of_birth=ACTIVATION_DATE_OF_BIRTH,
                        health_card_number=ACTIVATION_HEALTH_CARD_NUMBER,
                    ),
                    proof_secret=settings.identity_proof_secret.get_secret_value(),
                )
                _, reset_invite_token = create_invite(
                    session,
                    9012,
                    "CI browser password reset",
                    clinic_id=settings.clinic_id,
                    actor_id="ci-seed",
                    identity_proof=IdentityProof(
                        email=RESET_EMAIL,
                        date_of_birth=RESET_DATE_OF_BIRTH,
                        health_card_number=RESET_HEALTH_CARD_NUMBER,
                    ),
                    proof_secret=settings.identity_proof_secret.get_secret_value(),
                )
                activate_patient_account(
                    session,
                    invite_code=reset_invite_token,
                    identity_proof=IdentityProof(
                        email=RESET_EMAIL,
                        date_of_birth=RESET_DATE_OF_BIRTH,
                        health_card_number=RESET_HEALTH_CARD_NUMBER,
                    ),
                    username=RESET_USERNAME,
                    password=RESET_OLD_PASSWORD,
                    proof_secret=settings.identity_proof_secret.get_secret_value(),
                    client_reference_hash="1" * 64,
                    rate_limit=ActivationRateLimit(
                        failure_window=timedelta(hours=1),
                        max_failures_per_invite=10,
                        max_failures_per_client=50,
                    ),
                    expected_clinic_id=settings.clinic_id,
                )
                reset_result = request_password_reset(
                    session,
                    username=RESET_USERNAME,
                    email=RESET_EMAIL,
                    client_reference_hash="2" * 64,
                    policy=auth_policy_from_settings(settings),
                    reset_token_secret=token_keys.password_reset,
                    clinic_id=settings.clinic_id,
                )
                if reset_result.reset_token is None:
                    raise RuntimeError("browser password-reset token was not created")
        fixture_path.parent.mkdir(parents=True, exist_ok=True)
        fixture_payload = json.dumps(
            {
                "activation": {
                    "inviteCode": activation_invite_token,
                    "email": ACTIVATION_EMAIL,
                    "dateOfBirth": ACTIVATION_DATE_OF_BIRTH.isoformat(),
                    "healthCardNumber": ACTIVATION_HEALTH_CARD_NUMBER,
                    "username": ACTIVATION_USERNAME,
                    "password": ACTIVATION_PASSWORD,
                },
                "passwordReset": {
                    "email": RESET_EMAIL,
                    "username": RESET_USERNAME,
                    "oldPassword": RESET_OLD_PASSWORD,
                    "newPassword": RESET_NEW_PASSWORD,
                    "token": reset_result.reset_token,
                },
            }
        )
        # The fixture contains one-time invite/reset tokens and test passwords. Write it under a
        # random 0600 name and atomically replace the predictable path, avoiding both symlink
        # following and a brief readable window if an old path had permissive mode bits.
        descriptor, temporary_name = tempfile.mkstemp(
            dir=fixture_path.parent,
            prefix=f".{fixture_path.name}.",
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as fixture_file:
                fixture_file.write(fixture_payload)
            os.replace(temporary_path, fixture_path)
        except BaseException:
            temporary_path.unlink(missing_ok=True)
            raise
    finally:
        engine.dispose()


def report_choice_result(result: str) -> None:
    """Answer the patient's pending pick on the seeded offer, as the CARLOS polling job would."""
    settings = get_settings()
    outbox_keys = settings.resolved_outbox_keyring
    engine = create_portal_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    try:
        with session_factory() as session:
            with session.begin():
                pending = session.execute(
                    select(PatientPortalBookingChoice.id, PatientPortalBookingPrompt.id)
                    .join(
                        PatientPortalBookingPrompt,
                        PatientPortalBookingPrompt.id == PatientPortalBookingChoice.prompt_id,
                    )
                    .where(
                        PatientPortalBookingPrompt.clinic_id == settings.clinic_id,
                        PatientPortalBookingPrompt.operation_id == OFFER_OPERATION_ID,
                        PatientPortalBookingChoice.state == BOOKING_CHOICE_STATE_PENDING,
                    )
                ).one_or_none()
                if pending is None:
                    raise RuntimeError("the seeded offer has no pending choice to answer")
                choice_id, prompt_id = pending
                record_choice_result(
                    session,
                    prompt_id,
                    clinic_id=settings.clinic_id,
                    choice_id=choice_id,
                    result=result,
                    replacement_slots=(
                        browser_replacement_slots(settings)
                        if result == "slot_unavailable"
                        else ()
                    ),
                    actor="CARLOS booking sync",
                    actor_id="carlos-booking-sync",
                    # The browser run has no outbox worker; the queued notice is never sent.
                    notice=BookingPromptNotice(
                        sign_in_url=(settings.public_base_url or "http://127.0.0.1:8090") + "/",
                        encryption_secret=outbox_keys.get(
                            settings.outbox_active_key_id, token_urlsafe(32)
                        ),
                        encryption_key_id=settings.outbox_active_key_id,
                    ),
                )
    finally:
        engine.dispose()


if __name__ == "__main__":
    if sys.argv[1:2] == ["choice-result"] and len(sys.argv) == 3:
        report_choice_result(sys.argv[2])
    elif len(sys.argv) == 1:
        main()
    else:
        raise SystemExit("usage: seed_browser.py [choice-result booked|slot_unavailable]")
