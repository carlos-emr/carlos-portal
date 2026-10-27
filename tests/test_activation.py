"""Invite activation: turning an invite plus identity proof into a portal account."""

import html
import json
import re
from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal import credentials, identity, web_support
from carlos_patient_portal.audit import hash_sensitive_reference
from carlos_patient_portal.models import (
    AUDIT_EVENT_ACTIVATION,
    AUDIT_EVENT_INVITE_CREATE,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_SUCCESS,
    AUDIT_OUTCOME_THROTTLED,
    INVITE_STATUS_ACCEPTED,
    INVITE_STATUS_PENDING,
    MAX_DEMOGRAPHIC_NO,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalInvite,
    utc_now,
)
from carlos_patient_portal.staff_identity import staff_request_hash
from tests.support import (
    AUDIT_HASH_SECRET,
    NON_DEVELOPMENT_SESSION_SECRET,
    SEEDED_INVITE_DOB,
    SEEDED_INVITE_EMAIL,
    SEEDED_INVITE_HCN,
    STRONG_PASSWORD,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    activation_request,
    carlos_staff_headers,
    csrf_token_from_response,
    dev_admin_headers,
    migrated_development_app,
    migrated_staging_app,
    seeded_invite_request,
)

# SEEDED_INVITE_DOB (1980-05-20) as the activation form's three boxes send it.
SEEDED_INVITE_DOB_PARTS = {
    "date_of_birth_day": "20",
    "date_of_birth_month": "5",
    "date_of_birth_year": "1980",
}


def test_browser_activation_form_creates_account_without_repopulating_proof_values() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    invite_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )
    activation_page = client.get("/auth/activate")

    assert activation_page.status_code == 200
    assert 'type="date"' not in activation_page.text
    assert "Activate your account" in activation_page.text

    activation_response = client.post(
        "/auth/activate",
        data={
            "csrf_token": csrf_token_from_response(activation_page),
            "invite_code": invite_response.json()["invite_token"],
            "email": SEEDED_INVITE_EMAIL,
            **SEEDED_INVITE_DOB_PARTS,
            "health_card_number": SEEDED_INVITE_HCN,
            "username": "browser.patient",
            "password": STRONG_PASSWORD,
            "password_confirmation": STRONG_PASSWORD,
        },
    )

    assert activation_response.status_code == 201
    assert "Account activated" in activation_response.text
    assert SEEDED_INVITE_HCN not in activation_response.text
    assert invite_response.json()["invite_token"] not in activation_response.text
    with app.state.session_factory() as session:
        account = session.scalar(
            select(PatientPortalAccount).where(PatientPortalAccount.username == "browser.patient")
        )
        assert account is not None


def browser_activation_entries(invite_code: str, **overrides: str) -> dict[str, str]:
    """Everything the activation form posts, as a patient would type it."""
    entries = {
        "invite_code": invite_code,
        "email": SEEDED_INVITE_EMAIL,
        **SEEDED_INVITE_DOB_PARTS,
        "health_card_number": SEEDED_INVITE_HCN,
        "username": "browser.patient",
        "mfa_delivery_method": "email",
        "phone_number": "+16135550199",
        "password": STRONG_PASSWORD,
        "password_confirmation": STRONG_PASSWORD,
    }
    entries.update(overrides)
    return entries


def post_browser_activation(client: TestClient, entries: dict[str, str]):
    activation_page = client.get("/auth/activate")
    return client.post(
        "/auth/activate",
        data={"csrf_token": csrf_token_from_response(activation_page), **entries},
    )


def assert_entries_kept_but_not_passwords(response, entries: dict[str, str]) -> None:
    text = response.text
    # The kept entries must not sit in a cache.
    assert response.headers["cache-control"] == "no-store"
    assert "enter your password again" in text
    for field_name in (
        "invite_code",
        "email",
        "date_of_birth_day",
        "date_of_birth_year",
        "health_card_number",
        "username",
        "phone_number",
    ):
        expected = re.escape(html.escape(entries[field_name]))
        assert re.search(rf'name="{field_name}"\s+value="{expected}"', text), field_name
    month = entries["date_of_birth_month"]
    assert re.search(rf'<option value="{month}" selected>', text)
    if entries["mfa_delivery_method"] == "email":
        assert '<option value="email" selected>' in text
    else:
        # SMS chosen on a portal that cannot send it: the option stays disabled, never selected.
        assert re.search(r'<option value="sms" disabled>', text)
    for field_name in ("password", "password_confirmation"):
        tag = re.search(rf'<input[^>]*name="{field_name}"[^>]*>', text)
        assert tag is not None and "value=" not in tag.group(0), field_name
    assert entries["password"] not in text
    assert entries["password_confirmation"] not in text


def create_browser_invite(client: TestClient) -> str:
    return client.post(
        "/dev/admin/invites", headers=dev_admin_headers(), json=seeded_invite_request()
    ).json()["invite_token"]


def test_browser_activation_keeps_entries_when_the_details_could_not_be_verified() -> None:
    client = TestClient(migrated_development_app())
    entries = browser_activation_entries(create_browser_invite(client), date_of_birth_day="21")

    response = post_browser_activation(client, entries)

    assert response.status_code == 400
    assert "The activation details could not be verified." in response.text
    assert_entries_kept_but_not_passwords(response, entries)


def test_browser_activation_keeps_entries_when_the_date_of_birth_is_no_real_date() -> None:
    client = TestClient(migrated_development_app())
    entries = browser_activation_entries(
        create_browser_invite(client), date_of_birth_day="31", date_of_birth_month="2"
    )

    response = post_browser_activation(client, entries)

    assert response.status_code == 400
    assert "Check the date of birth: enter a real date" in response.text
    # What was typed comes back as typed, so the patient can see what to fix.
    assert_entries_kept_but_not_passwords(response, entries)


def test_browser_activation_keeps_entries_when_the_passwords_differ() -> None:
    client = TestClient(migrated_development_app())
    entries = browser_activation_entries(
        create_browser_invite(client),
        password_confirmation="Different1!word",  # ggignore
    )

    response = post_browser_activation(client, entries)

    assert response.status_code == 400
    assert "password confirmation does not match" in response.text.lower()
    assert_entries_kept_but_not_passwords(response, entries)


def test_browser_activation_keeps_entries_when_the_password_is_too_weak() -> None:
    client = TestClient(migrated_development_app())
    entries = browser_activation_entries(
        create_browser_invite(client),
        password="password1234",  # ggignore
        password_confirmation="password1234",  # ggignore
    )

    response = post_browser_activation(client, entries)

    assert response.status_code == 400
    assert "Choose a different password" in response.text
    assert_entries_kept_but_not_passwords(response, entries)


def test_browser_activation_keeps_entries_when_sms_cannot_be_sent() -> None:
    client = TestClient(migrated_development_app())
    entries = browser_activation_entries(create_browser_invite(client), mfa_delivery_method="sms")

    response = post_browser_activation(client, entries)

    assert response.status_code == 400
    # SMS is not offered by this portal, so the form falls back to email.
    assert_entries_kept_but_not_passwords(response, entries)


def test_browser_activation_keeps_entries_when_attempts_are_rate_limited() -> None:
    client = TestClient(
        migrated_development_app(
            session_secret=NON_DEVELOPMENT_SESSION_SECRET,
            activation_max_failures_per_invite=1,
            activation_max_failures_per_client=50,
        )
    )
    entries = browser_activation_entries(
        create_browser_invite(client), health_card_number="WRONG1234"
    )
    assert post_browser_activation(client, entries).status_code == 400

    response = post_browser_activation(client, entries)

    assert response.status_code == 429
    assert_entries_kept_but_not_passwords(response, entries)


@pytest.mark.parametrize(
    ("day", "month", "year"),
    [
        ("31", "2", "1985"),  # no such day
        ("15", "13", "1985"),  # no such month
        ("15", "6", "85"),  # a two-digit year
        ("15", "6", "0615"),  # a real date, but 1,400 years ago
        ("", "6", "1985"),  # a box left empty
        ("1x", "6", "1985"),  # not digits
        # Later than any real birth date (the server allows one day for time zones).
        tuple(
            str(part)
            for part in (
                (utc_now().date() + timedelta(days=2)).day,
                (utc_now().date() + timedelta(days=2)).month,
                (utc_now().date() + timedelta(days=2)).year,
            )
        ),
    ],
)
def test_browser_activation_names_the_date_of_birth_when_it_is_no_real_date(
    day: str, month: str, year: str
) -> None:
    app = migrated_development_app()
    client = TestClient(app)
    invite_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )
    activation_page = client.get("/auth/activate")

    response = client.post(
        "/auth/activate",
        data={
            "csrf_token": csrf_token_from_response(activation_page),
            "invite_code": invite_response.json()["invite_token"],
            "email": SEEDED_INVITE_EMAIL,
            "date_of_birth_day": day,
            "date_of_birth_month": month,
            "date_of_birth_year": year,
            "health_card_number": SEEDED_INVITE_HCN,
            "username": "browser.patient",
            "password": STRONG_PASSWORD,
            "password_confirmation": STRONG_PASSWORD,
        },
    )

    assert response.status_code == 400
    assert "Check the date of birth: enter a real date" in response.text
    assert "could not be verified" not in response.text
    assert STRONG_PASSWORD not in response.text


def test_browser_activation_keeps_a_wrong_but_real_date_of_birth_generic() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    invite_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )
    activation_page = client.get("/auth/activate")

    response = client.post(
        "/auth/activate",
        data={
            "csrf_token": csrf_token_from_response(activation_page),
            "invite_code": invite_response.json()["invite_token"],
            "email": SEEDED_INVITE_EMAIL,
            # A real date in range, but not the invited patient's: never say which detail failed.
            "date_of_birth_day": "21",
            "date_of_birth_month": "5",
            "date_of_birth_year": "1980",
            "health_card_number": SEEDED_INVITE_HCN,
            "username": "browser.patient",
            "password": STRONG_PASSWORD,
            "password_confirmation": STRONG_PASSWORD,
        },
    )

    assert response.status_code == 400
    assert "The activation details could not be verified." in response.text
    assert "Check the date of birth" not in response.text


def test_activation_page_asks_for_the_date_of_birth_as_day_month_and_year() -> None:
    page = TestClient(migrated_development_app()).get("/auth/activate")

    assert page.status_code == 200
    text = page.text
    assert '<fieldset class="date-of-birth" aria-describedby="date-of-birth-hint">' in text
    assert "<legend>Date of birth</legend>" in text
    assert '<small id="date-of-birth-hint">For example, 15 June 1985.</small>' in text
    assert 'name="date_of_birth_day"' in text and 'autocomplete="bday-day"' in text
    assert 'name="date_of_birth_year"' in text and 'autocomplete="bday-year"' in text
    assert '<select name="date_of_birth_month" autocomplete="bday-month" required>' in text
    assert '<option value="1">January</option>' in text
    assert '<option value="12">December</option>' in text
    assert 'name="date_of_birth"' not in text


def test_browser_activation_still_reads_a_single_date_of_birth_field() -> None:
    # A page opened before the three boxes posts one ISO date; it must keep working.
    app = migrated_development_app()
    client = TestClient(app)
    invite_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )
    activation_page = client.get("/auth/activate")

    response = client.post(
        "/auth/activate",
        data={
            "csrf_token": csrf_token_from_response(activation_page),
            "invite_code": invite_response.json()["invite_token"],
            "email": SEEDED_INVITE_EMAIL,
            "date_of_birth": SEEDED_INVITE_DOB,
            "health_card_number": SEEDED_INVITE_HCN,
            "username": "browser.patient",
            "password": STRONG_PASSWORD,
            "password_confirmation": STRONG_PASSWORD,
        },
    )

    assert response.status_code == 201


def test_browser_activation_keeps_entries_when_the_username_is_taken() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    first_token = create_browser_invite(client)
    second_token = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(
            demographic_no=5678,
            email="second.patient@example.com",
            health_card_number="ZXCV 1234",
        ),
    ).json()["invite_token"]
    assert client.post("/auth/activate", json=activation_request(first_token)).status_code == 201
    entries = browser_activation_entries(
        second_token,
        email="second.patient@example.com",
        health_card_number="ZXCV-1234",
        username=str(activation_request(first_token)["username"]),
    )

    response = post_browser_activation(client, entries)

    assert response.status_code == 409
    assert_entries_kept_but_not_passwords(response, entries)


@pytest.mark.parametrize(
    ("today", "earliest", "latest"),
    [
        (date(2026, 10, 15), date(1900, 10, 15), date(2026, 10, 16)),
        # No February 29 in 1902: the anniversary falls back to February 28.
        (date(2028, 2, 29), date(1902, 2, 28), date(2028, 3, 1)),
    ],
)
def test_date_of_birth_bounds_follow_the_server_rule(
    today: date, earliest: date, latest: date
) -> None:
    assert identity.date_of_birth_bounds(today) == (earliest, latest)


def test_activation_accepts_the_health_card_with_its_version_code() -> None:
    # The clinic stores the number without its version code; the patient types the whole card.
    client = TestClient(migrated_development_app())
    invite_code = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(health_card_number="1234567890"),
    ).json()["invite_token"]

    response = client.post(
        "/auth/activate",
        json=activation_request(invite_code, health_card_number="1234-567-890-AB"),
    )

    assert response.status_code == 201


def test_password_holding_the_card_number_is_refused_when_typed_with_its_version_code() -> None:
    client = TestClient(migrated_development_app())
    invite_code = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(health_card_number="1234567890"),
    ).json()["invite_token"]

    response = client.post(
        "/auth/activate",
        json=activation_request(
            invite_code,
            health_card_number="1234-567-890-AB",
            password="Orbit1234567890Lantern!",  # ggignore
        ),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "password does not meet the password rules"


def test_patient_activation_creates_account_from_seeded_invite() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    create_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )

    assert create_response.status_code == 201
    created_invite = create_response.json()
    invite_id = created_invite["id"]
    invite_token = created_invite["invite_token"]
    assert created_invite["has_identity_proof"] is True

    with app.state.session_factory() as session:
        persisted_invite = session.get(PatientPortalInvite, invite_id)
        assert persisted_invite is not None
        assert persisted_invite.proof_email_hash is not None
        assert persisted_invite.proof_date_of_birth_hash is not None
        assert persisted_invite.proof_health_card_hash is not None
        assert persisted_invite.proof_salt is not None
        assert persisted_invite.proof_email_hash != SEEDED_INVITE_EMAIL
        assert persisted_invite.proof_health_card_hash != SEEDED_INVITE_HCN

    activation_response = client.post(
        "/auth/activate",
        json=activation_request(invite_token),
    )

    assert activation_response.status_code == 201
    assert activation_response.json() == {"status": "activated", "username": "patient.user"}
    assert activation_response.headers["cache-control"] == "no-store"

    with app.state.session_factory() as session:
        account = session.scalar(
            select(PatientPortalAccount).where(PatientPortalAccount.username == "patient.user")
        )
        accepted_invite = session.get(PatientPortalInvite, invite_id)

        assert account is not None
        assert account.clinic_id == "default"
        assert account.demographic_no == 1234
        assert account.email == SEEDED_INVITE_EMAIL
        assert account.password_hash.startswith("$argon2id$")
        assert account.password_hash != STRONG_PASSWORD
        assert accepted_invite is not None
        assert accepted_invite.status == INVITE_STATUS_ACCEPTED
        assert accepted_invite.accepted_account_id == account.id
        assert accepted_invite.accepted_at is not None
        audit_events = list(
            session.scalars(select(PatientPortalAuditEvent).order_by(PatientPortalAuditEvent.id))
        )
        assert [(event.event_type, event.outcome) for event in audit_events] == [
            (AUDIT_EVENT_INVITE_CREATE, AUDIT_OUTCOME_SUCCESS),
            (AUDIT_EVENT_ACTIVATION, AUDIT_OUTCOME_SUCCESS),
        ]
        assert audit_events[-1].account_id == account.id
        assert audit_events[-1].invite_id == invite_id

    second_activation_response = client.post(
        "/auth/activate",
        json=activation_request(invite_token, username="another.patient"),
    )

    assert second_activation_response.status_code == 400
    assert second_activation_response.json()["detail"] == (
        "activation details could not be verified"
    )


def test_patient_activation_can_enroll_sms_mfa_when_sender_is_configured() -> None:
    sms_sender = RecordingPortalSmsSender()
    app = migrated_development_app(sms_sender=sms_sender)
    client = TestClient(app)
    create_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )

    activated = client.post(
        "/auth/activate",
        json=activation_request(
            create_response.json()["invite_token"],
            mfa_delivery_method="sms",
            phone_number="+1 613 555 0199",
        ),
    )
    login = client.post(
        "/auth/login",
        json={"username": "patient.user", "password": STRONG_PASSWORD},
    )

    assert activated.status_code == 201
    assert login.status_code == 200
    assert login.json()["mfa_delivery_method"] == "sms"
    assert sms_sender.messages[-1]["recipient"] == "+16135550199"
    with app.state.session_factory() as session:
        account = session.scalar(select(PatientPortalAccount))
        assert account is not None
        assert account.preferred_mfa_method == "sms"
        assert account.phone_number == "+16135550199"


def test_non_development_requires_sms_for_activation_and_login_mfa() -> None:
    sms_sender = RecordingPortalSmsSender()
    app = migrated_staging_app(
        email_sender=RecordingPortalEmailSender(),
        sms_sender=sms_sender,
        outbox_encryption_secret="o" * 32,
    )
    client = TestClient(app, base_url="https://portal.example.test")
    invite_path = "/internal/carlos/patients/1234/invites"
    invite_body = json.dumps(seeded_invite_request(), separators=(",", ":")).encode()
    invite = client.post(
        invite_path,
        headers={
            **carlos_staff_headers(
                "portal.invite.manage",
                request_hash=staff_request_hash("POST", invite_path.encode(), b"", invite_body),
            ),
            "Content-Type": "application/json",
        },
        content=invite_body,
    )
    assert invite.status_code == 201, invite.text
    invite_token = invite.json()["invite_token"]

    rejected_email_activation = client.post(
        "/auth/activate",
        json=activation_request(invite_token, mfa_delivery_method="email"),
    )
    sms_activation = client.post(
        "/auth/activate",
        json=activation_request(
            invite_token,
            mfa_delivery_method="sms",
            phone_number="+16135550199",
        ),
    )

    assert rejected_email_activation.status_code == 400
    assert rejected_email_activation.json()["detail"] == "MFA delivery method is unavailable"
    assert sms_activation.status_code == 201

    rejected_email_login = client.post(
        "/auth/login",
        json={
            "username": "patient.user",
            "password": STRONG_PASSWORD,
            "mfa_delivery_method": "email",
        },
    )
    sms_login = client.post(
        "/auth/login",
        json={"username": "patient.user", "password": STRONG_PASSWORD},
    )

    assert rejected_email_login.status_code == 400
    assert rejected_email_login.json()["detail"] == "MFA delivery method is unavailable"
    assert sms_login.status_code == 200
    assert sms_login.json()["mfa_delivery_method"] == "sms"
    assert sms_sender.messages[-1]["recipient"] == "+16135550199"


def test_patient_activation_rejects_sms_when_sender_is_unavailable() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    create_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )

    response = client.post(
        "/auth/activate",
        json=activation_request(
            create_response.json()["invite_token"],
            mfa_delivery_method="sms",
            phone_number="+16135550199",
        ),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "MFA delivery method is unavailable"
    with app.state.session_factory() as session:
        event = session.scalar(
            select(PatientPortalAuditEvent)
            .where(PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACTIVATION)
            .order_by(PatientPortalAuditEvent.id.desc())
        )
        assert event is not None
        assert event.outcome == AUDIT_OUTCOME_FAILURE


def test_patient_activation_rejects_identity_mismatch_without_account_leak() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    create_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )
    invite_token = create_response.json()["invite_token"]

    activation_response = client.post(
        "/auth/activate",
        json=activation_request(invite_token, health_card_number="WRONG1234"),
    )

    assert activation_response.status_code == 400
    assert activation_response.json()["detail"] == "activation details could not be verified"

    with app.state.session_factory() as session:
        assert session.scalar(select(PatientPortalAccount.id)) is None
        invite = session.scalar(select(PatientPortalInvite))
        audit_event = session.scalar(
            select(PatientPortalAuditEvent).where(
                PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACTIVATION
            )
        )
        assert invite is not None
        assert invite.status == INVITE_STATUS_PENDING
        assert audit_event is not None
        assert audit_event.outcome == AUDIT_OUTCOME_FAILURE
        assert audit_event.reason == "invalid_details"


def test_throttled_activation_skips_expensive_password_strength_analysis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The password is judged before the invite, so the rate limit (checked first) is what bounds
    # the strength analysis: once a client is throttled it must not run at all.
    app = migrated_development_app(
        session_secret=NON_DEVELOPMENT_SESSION_SECRET,
        activation_max_failures_per_invite=50,
        activation_max_failures_per_client=1,
    )
    client = TestClient(app)
    assert client.post(
        "/auth/activate", json=activation_request("forged-invite-token")
    ).status_code == 400

    def fail_if_called(*_args: object, **_kwargs: object) -> dict[str, object]:
        pytest.fail("password strength analysis ran for a throttled activation")

    monkeypatch.setattr(credentials, "zxcvbn", fail_if_called)
    response = client.post("/auth/activate", json=activation_request("another-forged-token"))

    assert response.status_code == 429


def test_password_rejection_names_the_password_whether_or_not_the_identity_matches() -> None:
    client = TestClient(migrated_development_app())
    invite_code = create_browser_invite(client)
    weak = {"password": "password1234", "password_confirmation": "password1234"}  # ggignore

    right_identity = post_browser_activation(
        client, browser_activation_entries(invite_code, **weak)
    )
    wrong_identity = post_browser_activation(
        client,
        browser_activation_entries(invite_code, health_card_number="WRONG1234", **weak),
    )

    # Same status and the same message either way: the password message is no identity oracle.
    for response in (right_identity, wrong_identity):
        assert response.status_code == 400
        assert "Choose a different password: use at least 12 characters" in response.text
        assert "could not be verified" not in response.text


def invite_in_every_state(app, client: TestClient) -> dict[str, tuple[str, dict[str, str]]]:
    """An invite code, and any changed entries, for every state an invite can be in."""
    valid = create_browser_invite(client)
    expired = client.post(
        "/dev/admin/invites", headers=dev_admin_headers(), json=seeded_invite_request()
    ).json()
    with app.state.session_factory() as session:
        row = session.get(PatientPortalInvite, expired["id"])
        row.created_at = utc_now() - timedelta(days=8)
        row.expires_at = utc_now() - timedelta(days=1)
        session.commit()
    used = create_browser_invite(client)
    assert client.post("/auth/activate", json=activation_request(used)).status_code == 201
    return {
        "forged": ("forged-invite-token", {}),
        "right identity": (valid, {}),
        "wrong identity": (valid, {"health_card_number": "WRONG1234"}),
        "expired": (expired["invite_token"], {}),
        "used": (used, {"username": "other.patient"}),
    }


def test_weak_password_page_is_the_same_for_every_invite_state() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    weak = {"password": "password1234", "password_confirmation": "password1234"}  # ggignore
    seen = {}
    for state, (invite_code, changes) in invite_in_every_state(app, client).items():
        response = post_browser_activation(
            client, browser_activation_entries(invite_code, **weak, **changes)
        )
        alert = re.search(r'role="alert">(.*?)</p>', response.text, re.S)
        assert alert is not None, state
        seen[state] = (response.status_code, alert.group(1), response.headers["cache-control"])

    # One status, one complete alert and one cache policy, whatever the invite or identity.
    assert len(set(seen.values())) == 1, seen
    assert "Choose a different password" in next(iter(seen.values()))[1]


def test_weak_password_json_is_the_same_for_every_invite_state() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    seen = {}
    for state, (invite_code, changes) in invite_in_every_state(app, client).items():
        body = activation_request(invite_code, password="password1234")  # ggignore
        body.update(changes)
        response = client.post("/auth/activate", json=body)
        seen[state] = (response.status_code, response.text)

    assert len(set(seen.values())) == 1, seen


def test_weak_password_attempt_counts_toward_the_invite_limit() -> None:
    app = migrated_development_app(
        session_secret=NON_DEVELOPMENT_SESSION_SECRET,
        activation_max_failures_per_invite=1,
        activation_max_failures_per_client=50,
    )
    client = TestClient(app)
    invite_code = create_browser_invite(client)
    weak = activation_request(invite_code, password="password1234")  # ggignore

    assert client.post("/auth/activate", json=weak).status_code == 400
    assert client.post("/auth/activate", json=activation_request(invite_code)).status_code == 429


def test_the_whole_password_alert_is_in_the_patients_language() -> None:
    client = TestClient(migrated_development_app())
    client.cookies.set("portal_locale", "fr")
    entries = browser_activation_entries(
        create_browser_invite(client),
        password="password1234",  # ggignore
        password_confirmation="password1234",  # ggignore
    )

    response = post_browser_activation(client, entries)

    alert = html.unescape(re.search(r'role="alert">(.*?)</p>', response.text, re.S).group(1))
    assert alert.startswith("Choisissez un autre mot de passe")
    assert alert.endswith("saisissez de nouveau votre mot de passe.")


def test_date_of_birth_form_and_its_error_are_in_the_patients_language() -> None:
    client = TestClient(migrated_development_app())
    client.cookies.set("portal_locale", "fr")

    page = html.unescape(client.get("/auth/activate").text)
    entries = browser_activation_entries(
        create_browser_invite(client), date_of_birth_day="31", date_of_birth_month="2"
    )
    response = post_browser_activation(client, entries)

    assert "<legend>Date de naissance</legend>" in page
    assert "Par exemple, 15 juin 1985." in page
    for label in ("Jour", "Mois", "Année"):
        assert f"<span>{label}</span>" in page
    assert '<option value="6">Juin</option>' in page
    alert = html.unescape(re.search(r'role="alert">(.*?)</p>', response.text, re.S).group(1))
    assert alert == (
        "Vérifiez la date de naissance : entrez une date réelle, par exemple 15 juin 1985. "
        "Vos autres renseignements sont conservés : saisissez de nouveau votre mot de passe."
    )


def test_good_password_with_the_wrong_identity_stays_generic() -> None:
    client = TestClient(migrated_development_app())
    entries = browser_activation_entries(
        create_browser_invite(client), health_card_number="WRONG1234"
    )

    response = post_browser_activation(client, entries)

    assert response.status_code == 400
    assert "The activation details could not be verified." in response.text
    assert "Choose a different password" not in response.text


def test_password_rejection_is_shown_in_the_patients_language() -> None:
    client = TestClient(migrated_development_app())
    client.cookies.set("portal_locale", "fr")
    entries = browser_activation_entries(
        create_browser_invite(client),
        password="password1234",  # ggignore
        password_confirmation="password1234",  # ggignore
    )

    response = post_browser_activation(client, entries)

    assert response.status_code == 400
    assert "Choisissez un autre mot de passe" in html.unescape(response.text)


def test_password_rejection_from_a_forged_invite_still_names_the_password() -> None:
    # Judged before the invite lookup, so a weak password does not reveal the invite is unknown.
    client = TestClient(migrated_development_app())

    response = client.post(
        "/auth/activate",
        json=activation_request("forged-invite-token", password="password1234"),  # ggignore
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "password does not meet the password rules"


def test_patient_activation_rejects_expired_invite() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    create_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )
    created_invite = create_response.json()
    invite_token = created_invite["invite_token"]

    with app.state.session_factory() as session:
        invite = session.get(PatientPortalInvite, created_invite["id"])
        assert invite is not None
        invite.created_at = utc_now() - timedelta(days=8)
        invite.expires_at = utc_now() - timedelta(days=1)
        session.commit()

    activation_response = client.post(
        "/auth/activate",
        json=activation_request(invite_token),
    )

    assert activation_response.status_code == 400
    assert activation_response.json()["detail"] == "activation details could not be verified"


def test_patient_activation_rejects_unavailable_username() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    first_create_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )
    first_token = first_create_response.json()["invite_token"]
    second_create_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(
            demographic_no=5678,
            email="second.patient@example.com",
            health_card_number="ZXCV 1234",
        ),
    )
    second_token = second_create_response.json()["invite_token"]

    assert client.post("/auth/activate", json=activation_request(first_token)).status_code == 201

    activation_response = client.post(
        "/auth/activate",
        json=activation_request(
            second_token,
            email="second.patient@example.com",
            health_card_number="ZXCV-1234",
        ),
    )

    assert activation_response.status_code == 409
    assert activation_response.json()["detail"] == "username unavailable"


def test_patient_activation_rejects_weak_password() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    create_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )

    activation_response = client.post(
        "/auth/activate",
        json=activation_request(create_response.json()["invite_token"], password="weak"),
    )

    assert activation_response.status_code == 400
    assert activation_response.json()["detail"] == "password does not meet the password rules"
    assert "weak" not in activation_response.text


def test_patient_activation_rejects_oversized_json_body() -> None:
    app = migrated_development_app()
    oversized_body = (
        b'{"invite_code":"'
        + b"x" * web_support.MAX_JSON_BODY_BYTES
        + b'","email":"example.patient@example.com"}'
    )

    response = TestClient(app).post(
        "/auth/activate",
        content=oversized_body,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "request body too large"


def test_patient_activation_refuses_deeply_nested_json_without_a_500() -> None:
    """Nested deeply enough, inside the size cap, the JSON decoder runs out of recursion depth."""
    app = migrated_development_app()
    nested_body = b"[" * 15000
    assert len(nested_body) <= web_support.MAX_JSON_BODY_BYTES

    response = TestClient(app, raise_server_exceptions=False).post(
        "/auth/activate",
        content=nested_body,
        headers={"Content-Type": "application/json"},
    )

    # A malformed body like any other: refused as invalid input, never a server error.
    assert response.status_code == 400


def test_patient_activation_refuses_an_oversized_json_number_without_a_500() -> None:
    """A number past Python's 4,300-digit int-conversion limit, inside the size cap."""
    app = migrated_development_app()
    body = b'{"invite_code": ' + b"9" * 5000 + b"}"
    assert len(body) <= web_support.MAX_JSON_BODY_BYTES

    response = TestClient(app, raise_server_exceptions=False).post(
        "/auth/activate",
        content=body,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 400


def test_patient_activation_requires_json_body() -> None:
    app = migrated_development_app()
    response = TestClient(app).post(
        "/auth/activate",
        data={"invite_code": "unused"},
    )

    # A urlencoded post is a browser form submission, so the rejection renders the portal's
    # page rather than a raw JSON body.
    assert response.status_code == 403
    assert response.headers["content-type"].startswith("text/html")
    assert "Request could not be completed" in response.text


def test_patient_activation_validation_does_not_echo_health_card_number() -> None:
    app = migrated_development_app()
    invalid_health_card_number = "bad card ?"

    response = TestClient(app).post(
        "/auth/activate",
        json=activation_request("unused", health_card_number=invalid_health_card_number),
    )

    assert response.status_code == 400
    assert invalid_health_card_number not in response.text


def test_patient_activation_rejects_too_short_health_card_number() -> None:
    app = migrated_development_app()
    response = TestClient(app).post(
        "/auth/activate",
        json=activation_request("unused", health_card_number="A1"),
    )

    assert response.status_code == 400


def test_activation_schema_failures_consume_the_failure_budget() -> None:
    app = migrated_development_app(
        activation_max_failures_per_invite=2,
        activation_max_failures_per_client=50,
    )
    client = TestClient(app)
    malformed = activation_request("", health_card_number="A1")

    responses = [client.post("/auth/activate", json=malformed) for _ in range(3)]

    assert [response.status_code for response in responses] == [400, 400, 429]
    with app.state.session_factory() as session:
        outcomes = list(
            session.scalars(
                select(PatientPortalAuditEvent.outcome)
                .where(PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACTIVATION)
                .order_by(PatientPortalAuditEvent.id)
            )
        )
    assert outcomes == [AUDIT_OUTCOME_FAILURE, AUDIT_OUTCOME_FAILURE, AUDIT_OUTCOME_THROTTLED]


def test_patient_activation_rate_limits_failed_attempts() -> None:
    app = migrated_development_app(
        session_secret=NON_DEVELOPMENT_SESSION_SECRET,
        activation_max_failures_per_invite=2,
        activation_max_failures_per_client=50,
    )
    client = TestClient(app)
    create_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )
    invite_token = create_response.json()["invite_token"]

    for _ in range(2):
        response = client.post(
            "/auth/activate",
            json=activation_request(invite_token, health_card_number="WRONG1234"),
        )
        assert response.status_code == 400

    throttled_response = client.post(
        "/auth/activate",
        json=activation_request(invite_token, health_card_number="WRONG1234"),
    )

    assert throttled_response.status_code == 429
    assert throttled_response.headers["retry-after"] == "3600"
    expected_client_hash = hash_sensitive_reference(
        AUDIT_HASH_SECRET,
        "activation_client",
        "testclient",
    )
    with app.state.session_factory() as session:
        audit_events = list(
            session.scalars(
                select(PatientPortalAuditEvent)
                .where(PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACTIVATION)
                .order_by(PatientPortalAuditEvent.id)
            )
        )

        assert [event.outcome for event in audit_events] == [
            AUDIT_OUTCOME_FAILURE,
            AUDIT_OUTCOME_FAILURE,
            AUDIT_OUTCOME_THROTTLED,
        ]
        assert all(event.client_reference_hash == expected_client_hash for event in audit_events)


def test_patient_activation_rate_limit_ignores_header_from_untrusted_peer() -> None:
    app = migrated_development_app(
        session_secret=NON_DEVELOPMENT_SESSION_SECRET,
        trusted_client_ip_header="x-forwarded-for",
        trusted_proxy_cidrs="10.0.0.0/8",
    )
    client = TestClient(app)
    create_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )
    invite_token = create_response.json()["invite_token"]
    response = client.post(
        "/auth/activate",
        headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.10"},
        json=activation_request(invite_token, health_card_number="WRONG1234"),
    )

    assert response.status_code == 400
    expected_client_hash = hash_sensitive_reference(
        AUDIT_HASH_SECRET,
        "activation_client",
        "testclient",
    )
    with app.state.session_factory() as session:
        audit_event = session.scalar(
            select(PatientPortalAuditEvent).where(
                PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACTIVATION
            )
        )
        assert audit_event is not None
        assert audit_event.client_reference_hash == expected_client_hash


def test_patient_activation_rate_limit_window_expires() -> None:
    app = migrated_development_app(
        activation_failure_window_seconds=60,
        activation_max_failures_per_invite=1,
        activation_max_failures_per_client=50,
    )
    client = TestClient(app)
    create_response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(),
    )
    invite_token = create_response.json()["invite_token"]
    failed_response = client.post(
        "/auth/activate",
        json=activation_request(invite_token, health_card_number="WRONG1234"),
    )
    assert failed_response.status_code == 400

    with app.state.session_factory() as session:
        audit_event = session.scalar(
            select(PatientPortalAuditEvent).where(
                PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACTIVATION
            )
        )
        assert audit_event is not None
        audit_event.created_at = utc_now() - timedelta(minutes=2)
        session.commit()

    activation_response = client.post("/auth/activate", json=activation_request(invite_token))

    assert activation_response.status_code == 201


def test_dev_admin_invite_list_refuses_a_patient_number_beyond_32_bits() -> None:
    app = migrated_development_app()
    response = TestClient(app).get(
        f"/dev/admin/invites?demographic_no={MAX_DEMOGRAPHIC_NO + 1}", headers=dev_admin_headers()
    )

    assert response.status_code == 422
