# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Seed the fixtures for scripts/patient-portal-account-playwright-checks.js.

Kept apart from tests/seed_browser.py, which seeds the main browser check, so neither check's
fixtures can disturb the other's. It may run against the same database as that seed: its accounts,
demographic numbers and booking operation IDs are its own. Every fixture is still single-use (a
confirmation token, a removed device, a locked account), so recreate the database before each run.

Everything is FAKE: example.com addresses, passwords generated here at run time, and a clinic key
and device keys derived from readable seed text by tests/delivery_contract_reference.py, exactly
as tests/test_mycarlos_portal.py builds them.

Run it with the same environment as the server it seeds for: the email-change token is keyed by the
session secret, and the fixture records the server's lockout, rate-limit and cooldown settings so
the check can plan around them. See the run recipe at the top of the check script.
"""

import json
import os
import re
import sys
import tempfile
from datetime import datetime, time, timedelta
from pathlib import Path
from secrets import token_urlsafe
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from carlos_patient_portal.account_settings import (
    CONTACT_UPDATE_OUTCOME_CONFIRMATION_REQUIRED,
    update_account_contact,
)
from carlos_patient_portal.booking_offers import OfferedSlotSpec, add_offered_slots, offer_digest
from carlos_patient_portal.config import Settings, get_settings
from carlos_patient_portal.credentials import hash_password, validate_password, validate_username
from carlos_patient_portal.database import create_portal_engine, create_session_factory
from carlos_patient_portal.i18n import DEFAULT_LOCALE, portal_text
from carlos_patient_portal.models import (
    ACCOUNT_STATUS_ACTIVE,
    BOOKING_PROMPT_STATUS_SENT,
    CLINIC_KEY_STATUS_ACTIVE,
    MFA_DELIVERY_METHOD_EMAIL,
    MYCARLOS_DEVICE_STATUS_ACTIVE,
    MYCARLOS_LINK_CODE_LENGTH,
    MYCARLOS_LINK_ID_LENGTH,
    PatientPortalAccount,
    PatientPortalBookingPrompt,
    PatientPortalClinicKey,
    PatientPortalMyCarlosDevice,
    utc_now,
)
from carlos_patient_portal.mycarlos_links import LINK_CODE_ALPHABET
from carlos_patient_portal.token_keys import PortalTokenKeys
from carlos_patient_portal.web_support import (
    PORTAL_MFA_PROOF_COOKIE_NAME,
    PORTAL_SESSION_COOKIE_NAME,
)
from tests import delivery_contract_reference as ref

DEFAULT_FIXTURE_NAME = "patient-portal-account-fixtures.json"

EMAIL_CHANGE_USERNAME = "fake-email-change"
EMAIL_CHANGE_OLD_EMAIL = "fake.email.change@old.example.com"
EMAIL_CHANGE_NEW_EMAIL = "fake.email.change@new.example.com"
EMAIL_CHANGE_DEMOGRAPHIC_NO = 7101

LINK_USERNAME = "fake-mycarlos-link"
LINK_EMAIL = "fake.mycarlos.link@example.com"
LINK_DEMOGRAPHIC_NO = 7102
CLINIC_KEY_LABEL = "FAKE account browser check clinic"
# The first name carries markup: the page must show it as text, never as an element.
DEVICES = (
    ("FAKE account browser check device A", "FAKE <b>Kitchen</b> tablet & co", False),
    ("FAKE account browser check device B", "FAKE myCarlos on Windows", True),
)
DECLINE_OPERATION_ID = "fake-account-check-decline-offer-1"
DECLINE_APPOINTMENT_TYPE = "lab_review"
DECLINE_URGENCY = "routine"

LOCK_USERNAME = "fake-lock-account"
LOCK_EMAIL = "fake.lock.account@example.com"
LOCK_DEMOGRAPHIC_NO = 7103

# Every string the check asserts, read from the portal's own English catalog so a copy edit there
# cannot leave the check asserting stale text.
TEXT_KEYS = (
    "account",
    "account_change_error",
    "account_status_mfa_updated",
    "back_to_sign_in",
    "booking_choice_error",
    "booking_choose",
    "booking_decline",
    "booking_slots_legend",
    "clinic_help",
    "dashboard_greeting",
    "email",
    "email_change_complete_error",
    "email_change_complete_heading",
    "email_change_confirm",
    "email_change_success",
    "email_change_success_heading",
    "incorrect_username_or_password",
    "logout",
    "message_back",
    "messages",
    "mfa_heading",
    "mfa_verify",
    "mycarlos_another",
    "mycarlos_approval",
    "mycarlos_code_label",
    "mycarlos_create",
    "mycarlos_devices",
    "mycarlos_keep",
    "mycarlos_lifetime",
    "mycarlos_link",
    "mycarlos_mfa_required",
    "mycarlos_not_seen",
    "mycarlos_portal_address",
    "mycarlos_qr_alt",
    "mycarlos_qr_label",
    "mycarlos_remove",
    "mycarlos_remove_effect",
    "mycarlos_remove_question",
    "mycarlos_removed",
    "mycarlos_unavailable",
    "mycarlos_verify",
    "request_failed_heading",
    "session_locked_details",
    "session_locked_heading",
    "sign_in_button",
    "sign_in_heading",
    "update_contact",
    "update_mfa",
    "update_password",
)


def generated_password(*context_values: str) -> str:
    """A fresh password that passes the portal's own policy; never a literal in the source."""
    for _attempt in range(20):
        password = token_urlsafe(18)
        try:
            return validate_password(password, context_values=context_values)
        except ValueError:
            continue
    raise RuntimeError("could not generate a policy-compliant test password")


def clinic_time(settings: Settings, days_ahead: int, hour: int, minute: int) -> datetime:
    # Same rule as tests/seed_browser.py: a wall-clock time in the clinic's own zone.
    clinic_zone = ZoneInfo(settings.clinic_timezone)
    day = datetime.now(clinic_zone).date() + timedelta(days=days_ahead)
    return datetime.combine(day, time(hour, minute), tzinfo=clinic_zone)


def link_code_pattern() -> str:
    """The displayed code, `<link_id>-<first 5>-<rest>` (mycarlos_links.display_link_code)."""
    character = "[" + re.escape(LINK_CODE_ALPHABET) + "]"
    return (
        f"^{character}{{{MYCARLOS_LINK_ID_LENGTH}}}-{character}{{5}}"
        f"-{character}{{{MYCARLOS_LINK_CODE_LENGTH - 5}}}$"
    )


def audit_hash_secret(settings: Settings) -> str:
    """The secret the portal recomputes offer digests with; require_browser_settings checked it."""
    assert settings.audit_hash_secret is not None
    return settings.audit_hash_secret.get_secret_value()


def require_browser_settings(settings: Settings) -> str:
    """Refuse a configuration the check cannot pass on; return the session secret."""
    problems = []
    if not settings.is_development:
        problems.append("PATIENT_PORTAL_ENVIRONMENT=development (development MFA codes)")
    if settings.session_secret is None:
        problems.append("PATIENT_PORTAL_SESSION_SECRET (keys the email-change token)")
    if not settings.mycarlos_delivery_enabled:
        problems.append("PATIENT_PORTAL_MYCARLOS_DELIVERY_ENABLED=true (Link myCarlos pages)")
    if settings.public_base_url is None or not settings.public_base_url.startswith("https://"):
        problems.append("an https:// PATIENT_PORTAL_PUBLIC_BASE_URL (the link QR needs one)")
    if settings.audit_hash_secret is None:
        problems.append("PATIENT_PORTAL_AUDIT_HASH_SECRET (keys the offered-times digest)")
    if problems:
        raise RuntimeError("the account browser check needs " + "; ".join(problems))
    assert settings.session_secret is not None
    return settings.session_secret.get_secret_value()


def add_account(
    session: Session,
    settings: Settings,
    *,
    demographic_no: int,
    username: str,
    email: str,
    password: str,
) -> PatientPortalAccount:
    # Inserted directly, as tests/test_mycarlos_portal.py does: these accounts exist only to be
    # driven by the browser, and none of the checked flows depends on how the account was made.
    account = PatientPortalAccount(
        clinic_id=settings.clinic_id,
        demographic_no=demographic_no,
        username=validate_username(username),
        email=email,
        phone_number=None,
        preferred_mfa_method=MFA_DELIVERY_METHOD_EMAIL,
        password_hash=hash_password(password),
        status=ACCOUNT_STATUS_ACTIVE,
    )
    session.add(account)
    session.flush()
    return account


def refuse_reused_database(session: Session, settings: Settings) -> None:
    existing = session.scalars(
        select(PatientPortalAccount.username).where(
            PatientPortalAccount.clinic_id == settings.clinic_id,
            PatientPortalAccount.username.in_(
                (EMAIL_CHANGE_USERNAME, LINK_USERNAME, LOCK_USERNAME)
            ),
        )
    ).all()
    if existing:
        raise RuntimeError(
            "account browser fixtures already exist in this database; they are single-use, so "
            "recreate the database (alembic upgrade head on an empty file) and seed again"
        )


def write_fixture(fixture_path: Path, payload: dict[str, object]) -> None:
    # The fixture holds test passwords and a one-time token. Same pattern as tests/seed_browser.py:
    # mkstemp creates the file 0600 under a random name, which then atomically replaces the
    # predictable path, so there is no symlink to follow and no window with looser mode bits.
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=fixture_path.parent,
        prefix=f".{fixture_path.name}.",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as fixture_file:
            fixture_file.write(json.dumps(payload))
        os.replace(temporary_path, fixture_path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def main() -> None:
    settings = get_settings()
    token_keys = PortalTokenKeys.derive(require_browser_settings(settings))
    english = portal_text(DEFAULT_LOCALE)
    text = {key: english[key] for key in TEXT_KEYS}
    fixture_path = Path(
        os.environ.get(
            "PORTAL_ACCOUNT_FIXTURE_FILE",
            str(Path(tempfile.gettempdir()) / DEFAULT_FIXTURE_NAME),
        )
    )
    email_change_password = generated_password(
        EMAIL_CHANGE_USERNAME, EMAIL_CHANGE_OLD_EMAIL, EMAIL_CHANGE_NEW_EMAIL, settings.clinic_id
    )
    link_password = generated_password(LINK_USERNAME, LINK_EMAIL, settings.clinic_id)
    lock_password = generated_password(LOCK_USERNAME, LOCK_EMAIL, settings.clinic_id)
    engine = create_portal_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    try:
        with session_factory() as session:
            with session.begin():
                refuse_reused_database(session, settings)
                now = utc_now()

                # 1. Email change: a pending change minted by the same service function the
                # account page's contact form calls. The browser never sees the confirmation mail,
                # so the token travels in the fixture instead of a mailbox.
                email_account = add_account(
                    session,
                    settings,
                    demographic_no=EMAIL_CHANGE_DEMOGRAPHIC_NO,
                    username=EMAIL_CHANGE_USERNAME,
                    email=EMAIL_CHANGE_OLD_EMAIL,
                    password=email_change_password,
                )
                contact_update = update_account_contact(
                    session,
                    email_account,
                    current_password=email_change_password,
                    email=EMAIL_CHANGE_NEW_EMAIL,
                    phone_number=None,
                    max_failed_password_attempts=settings.auth_max_failed_password_attempts,
                    email_change_token_secret=token_keys.email_change,
                    email_change_token_ttl=timedelta(
                        seconds=settings.email_change_token_ttl_seconds
                    ),
                    phone_change_code_ttl=timedelta(seconds=settings.phone_change_code_ttl_seconds),
                )
                if (
                    contact_update.outcome != CONTACT_UPDATE_OUTCOME_CONFIRMATION_REQUIRED
                    or not contact_update.confirmation_token
                ):
                    raise RuntimeError("the pending email change was not created")

                # 2-3, 5. Link myCarlos, linked devices and the offered-times decline share one
                # account. An active clinic key is what lets the portal issue a link code at all.
                link_account = add_account(
                    session,
                    settings,
                    demographic_no=LINK_DEMOGRAPHIC_NO,
                    username=LINK_USERNAME,
                    email=LINK_EMAIL,
                    password=link_password,
                )
                clinic_key = ref.ClinicKey(CLINIC_KEY_LABEL, settings.clinic_id)
                session.add(
                    PatientPortalClinicKey(
                        kid=clinic_key.kid,
                        clinic_id=clinic_key.clinic_id,
                        spki=clinic_key.spki,
                        status=CLINIC_KEY_STATUS_ACTIVE,
                        published_at=now,
                    )
                )
                devices = []
                for index, (label, name, seen) in enumerate(DEVICES):
                    keys = ref.DeviceKeys(label)
                    session.add(
                        PatientPortalMyCarlosDevice(
                            account_id=link_account.id,
                            device_key_id=keys.device_key_id,
                            x25519_public_key=keys.x25519_public,
                            ed25519_public_key=keys.ed25519_public,
                            device_name=name,
                            status=MYCARLOS_DEVICE_STATUS_ACTIVE,
                            # Distinct, ordered link times so the list order is stable.
                            linked_at=now - timedelta(days=len(DEVICES) - index),
                            last_seen_at=now - timedelta(hours=1) if seen else None,
                        )
                    )
                    devices.append({"name": name, "deviceKeyId": keys.device_key_id, "seen": seen})
                offered_slots = (
                    OfferedSlotSpec(
                        "fake-decline-slot-1", clinic_time(settings, 6, 11, 0), 30, "in_person"
                    ),
                    OfferedSlotSpec(
                        "fake-decline-slot-2", clinic_time(settings, 11, 15, 30), 45, "video"
                    ),
                )
                decline_prompt = PatientPortalBookingPrompt(
                    clinic_id=settings.clinic_id,
                    demographic_no=link_account.demographic_no,
                    account_id=link_account.id,
                    operation_id=DECLINE_OPERATION_ID,
                    urgency=DECLINE_URGENCY,
                    appointment_type=DECLINE_APPOINTMENT_TYPE,
                    suggested_by=None,
                    status=BOOKING_PROMPT_STATUS_SENT,
                    created_by="FAKE clinic seed",
                    created_by_id="fake-provider-1",
                    created_at=now,
                    expires_at=now + timedelta(days=90),
                    offer_digest=offer_digest(offered_slots, secret=audit_hash_secret(settings)),
                )
                session.add(decline_prompt)
                session.flush()
                add_offered_slots(session, decline_prompt.id, offered_slots)

                # 4. A dedicated account to lock, so no other fixture is ever locked.
                add_account(
                    session,
                    settings,
                    demographic_no=LOCK_DEMOGRAPHIC_NO,
                    username=LOCK_USERNAME,
                    email=LOCK_EMAIL,
                    password=lock_password,
                )

        # What the patient is told after declining: the prompt's contact line, built exactly as
        # presenters._booking_prompt_view builds it.
        if settings.clinic_booking_phone:
            decline_contact_text = english["booking_prompt_contact_phone"].format(
                clinic_name=settings.clinic_name,
                phone=settings.clinic_booking_phone,
            )
        else:
            decline_contact_text = english["booking_prompt_contact"].format(
                clinic_name=settings.clinic_name
            )
        write_fixture(
            fixture_path,
            {
                "settings": {
                    "publicBaseUrl": settings.public_base_url,
                    "lockThreshold": settings.auth_max_failed_password_attempts,
                    "authRateLimitMaxRequests": settings.auth_rate_limit_max_requests,
                    "authRateLimitWindowSeconds": settings.auth_rate_limit_window_seconds,
                    "mfaEmailCooldownSeconds": settings.mfa_email_resend_cooldown_seconds,
                    # The step-up route sends its code by email only when a mail sender exists
                    # (routes/mycarlos_portal.py start_step_up); without one it answers 409.
                    "stepUpEmailAvailable": settings.smtp_host is not None,
                    "proofCookieName": PORTAL_MFA_PROOF_COOKIE_NAME,
                    "sessionCookieName": PORTAL_SESSION_COOKIE_NAME,
                    "linkCodePattern": link_code_pattern(),
                },
                "text": text,
                "emailChange": {
                    "username": validate_username(EMAIL_CHANGE_USERNAME),
                    "password": email_change_password,
                    "oldEmail": EMAIL_CHANGE_OLD_EMAIL,
                    "newEmail": EMAIL_CHANGE_NEW_EMAIL,
                    "token": contact_update.confirmation_token,
                },
                "mycarlos": {
                    "username": validate_username(LINK_USERNAME),
                    "password": link_password,
                    "email": LINK_EMAIL,
                    "devices": devices,
                    "decline": {
                        "title": english[f"booking_prompt_title_{DECLINE_APPOINTMENT_TYPE}"],
                        "slotCount": len(offered_slots),
                        "contactText": decline_contact_text,
                    },
                },
                "lock": {
                    "username": validate_username(LOCK_USERNAME),
                    "password": lock_password,
                    "email": LOCK_EMAIL,
                },
            },
        )
    finally:
        engine.dispose()


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("usage: seed_browser_account.py")
    main()
