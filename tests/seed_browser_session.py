# SPDX-License-Identifier: AGPL-3.0-or-later
"""Seed the fixtures for scripts/patient-portal-session-playwright-checks.js.

Five accounts for the sign-in and session flows the other browser checks do not drive: an
account that receives its sign-in code by SMS, one that changes its phone number, one that
walks the signed-in pages in every locale, one that is thrown at the sign-in throttle, and one
that sits idle until its session expires. Passwords are generated here, never literals. The
check runs against a throwaway portal only (the throttle and the idle expiry are stateful), so
recreate the database before each run. Locales and their catalogs are exported as the portal
defines them, so a new locale is checked as soon as it exists.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from secrets import token_urlsafe

from sqlalchemy.orm import Session

from carlos_patient_portal.auth import SESSION_LAST_SEEN_UPDATE_INTERVAL
from carlos_patient_portal.config import Settings, get_settings
from carlos_patient_portal.credentials import hash_password, validate_password, validate_username
from carlos_patient_portal.database import create_portal_engine, create_session_factory
from carlos_patient_portal.i18n import (
    DEFAULT_LOCALE,
    LOCALE_COOKIE_NAME,
    SUPPORTED_LOCALES,
    portal_text,
)
from carlos_patient_portal.models import (
    ACCOUNT_STATUS_ACTIVE,
    MFA_DELIVERY_METHOD_EMAIL,
    MFA_DELIVERY_METHOD_SMS,
    PatientPortalAccount,
)
from carlos_patient_portal.web_support import (
    PORTAL_MFA_PROOF_COOKIE_NAME,
    PORTAL_SESSION_COOKIE_NAME,
)

DEFAULT_FIXTURE_NAME = "patient-portal-session-fixtures.json"

# 555-01xx numbers are reserved for fiction; nothing can receive them.
ACCOUNTS = {
    "sms": (
        "fake-session-sms",
        "fake.session.sms@example.com",
        7201,
        "+15555550141",
        MFA_DELIVERY_METHOD_SMS,
    ),
    "phone": (
        "fake-session-phone",
        "fake.session.phone@example.com",
        7202,
        None,
        MFA_DELIVERY_METHOD_EMAIL,
    ),
    "locale": (
        "fake-session-locale",
        "fake.session.locale@example.com",
        7203,
        None,
        MFA_DELIVERY_METHOD_EMAIL,
    ),
    "throttle": (
        "fake-session-throttle",
        "fake.session.throttle@example.com",
        7204,
        None,
        MFA_DELIVERY_METHOD_EMAIL,
    ),
    "idle": (
        "fake-session-idle",
        "fake.session.idle@example.com",
        7205,
        None,
        MFA_DELIVERY_METHOD_EMAIL,
    ),
}
NEW_PHONE = "+15555550142"


def generated_password(*context_values: str) -> str:
    """A fresh password that passes the portal's own policy; never a literal in the source."""
    for _attempt in range(20):
        password = token_urlsafe(18)
        try:
            return validate_password(password, context_values=context_values)
        except ValueError:
            continue
    raise RuntimeError("could not generate a policy-compliant test password")


def require_browser_settings(settings: Settings) -> None:
    """Refuse a configuration the check cannot pass on."""
    problems = []
    if not settings.is_development:
        problems.append("PATIENT_PORTAL_ENVIRONMENT=development (development MFA codes)")
    if settings.sms_webhook_url is None or settings.sms_webhook_token is None:
        problems.append("PATIENT_PORTAL_SMS_WEBHOOK_URL and _TOKEN (the capture webhook)")
    if problems:
        raise RuntimeError("the session browser check needs " + "; ".join(problems))


def add_account(
    session: Session,
    settings: Settings,
    *,
    demographic_no: int,
    username: str,
    email: str,
    phone: str | None,
    method: str,
    password: str,
) -> PatientPortalAccount:
    # Inserted directly, as tests/test_mycarlos_portal.py does: these accounts exist only to be
    # driven by the browser, and none of the checked flows depends on how the account was made.
    account = PatientPortalAccount(
        clinic_id=settings.clinic_id,
        demographic_no=demographic_no,
        username=validate_username(username),
        email=email,
        phone_number=phone,
        preferred_mfa_method=method,
        password_hash=hash_password(password),
        status=ACCOUNT_STATUS_ACTIVE,
    )
    session.add(account)
    session.flush()
    return account


def write_fixture(fixture_path: Path, payload: dict[str, object]) -> None:
    # The fixture holds test passwords: mkstemp creates it 0600 under a random name, which then
    # atomically replaces the predictable path (same pattern as tests/seed_browser.py).
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=fixture_path.parent, prefix=f".{fixture_path.name}."
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
    require_browser_settings(settings)
    fixture_path = Path(
        os.environ.get(
            "PORTAL_SESSION_FIXTURE_FILE", str(Path(tempfile.gettempdir()) / DEFAULT_FIXTURE_NAME)
        )
    )
    engine = create_portal_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    accounts: dict[str, dict[str, object]] = {}
    try:
        with session_factory() as session:
            with session.begin():
                for role, (username, email, demographic_no, phone, method) in ACCOUNTS.items():
                    password = generated_password(username, email, settings.clinic_id)
                    add_account(
                        session,
                        settings,
                        demographic_no=demographic_no,
                        username=username,
                        email=email,
                        phone=phone,
                        method=method,
                        password=password,
                    )
                    accounts[role] = {
                        "username": username,
                        "password": password,
                        "email": email,
                        "phone": phone,
                    }
    finally:
        engine.dispose()
    payload = {
        "settings": {
            "sessionCookieName": PORTAL_SESSION_COOKIE_NAME,
            "proofCookieName": PORTAL_MFA_PROOF_COOKIE_NAME,
            "localeCookieName": LOCALE_COOKIE_NAME,
            "mfaEmailCooldownSeconds": settings.mfa_email_resend_cooldown_seconds,
            "mfaSmsCooldownSeconds": settings.mfa_sms_resend_cooldown_seconds,
            "idleTimeoutSeconds": settings.session_idle_timeout_seconds,
            "lastSeenUpdateIntervalSeconds": int(SESSION_LAST_SEEN_UPDATE_INTERVAL.total_seconds()),
            "authRateLimitMaxRequests": settings.auth_rate_limit_max_requests,
            "authRateLimitWindowSeconds": settings.auth_rate_limit_window_seconds,
            "smsSenderId": settings.sms_sender_id,
            "defaultLocale": DEFAULT_LOCALE,
        },
        "text": portal_text(DEFAULT_LOCALE),
        "locales": [
            {
                "code": option.code,
                "label": option.label,
                "shortLabel": option.short_label,
                "text": portal_text(option.code),
            }
            for option in SUPPORTED_LOCALES
        ],
        "accounts": accounts,
        "newPhone": NEW_PHONE,
    }
    write_fixture(fixture_path, payload)
    print(f"seeded {len(accounts)} session accounts; fixture at {fixture_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
