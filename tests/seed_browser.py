"""Seed the isolated development database used by the Playwright CI smoke test."""

import json
import os
import tempfile
from datetime import date, timedelta
from pathlib import Path

from carlos_patient_portal.accounts import ActivationRateLimit, activate_patient_account
from carlos_patient_portal.config import get_settings
from carlos_patient_portal.database import create_portal_engine, create_session_factory
from carlos_patient_portal.identity import IdentityProof
from carlos_patient_portal.invites import create_invite
from carlos_patient_portal.unlock_secrets import create_unlock_secret

DEVELOPMENT_PASSWORD = "-".join(("Nectar", "Sparrow", "Quartz", "87!"))
ACTIVATION_PASSWORD = "-".join(("Cedar", "River", "Comet", "62!"))
ACTIVATION_EMAIL = "activation.patient@example.com"
ACTIVATION_DATE_OF_BIRTH = date(1975, 9, 14)
ACTIVATION_HEALTH_CARD_NUMBER = "EFGH 9876-5432"
ACTIVATION_USERNAME = "PlaywrightActivate"


def main() -> None:
    settings = get_settings()
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
                }
            }
        )
        # The fixture contains a one-time invite and test password. Write it under a random 0600
        # name and atomically replace the predictable path, avoiding both symlink following and a
        # brief readable window if an old path was created with permissive mode bits.
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


if __name__ == "__main__":
    main()
