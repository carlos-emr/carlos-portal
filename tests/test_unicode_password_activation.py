from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal import credentials
from carlos_patient_portal.models import PatientPortalAccount
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    activation_request,
    dev_admin_headers,
    migrated_development_app,
    seeded_invite_request,
)


def test_activation_accepts_a_strong_non_latin_password_and_stores_a_verifiable_hash():
    password = "松雲海竹星河雨石山鳥風林月湖雪花"
    # The actual configured strength screen approves this fixture; no estimator or
    # validator is mocked, and acceptance must not require an ASCII character class.
    strength = credentials.zxcvbn(password)["score"]
    assert strength >= credentials.MIN_PASSWORD_STRENGTH_SCORE
    weak_password = "松" * len(password)
    assert credentials.zxcvbn(weak_password)["score"] < credentials.MIN_PASSWORD_STRENGTH_SCORE
    app = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    with TestClient(app) as client:
        invitation = client.post(
            "/dev/admin/invites",
            headers=dev_admin_headers(),
            json=seeded_invite_request(),
        )
        assert invitation.status_code == 201
        invite_token = invitation.json()["invite_token"]
        rejected = client.post(
            "/auth/activate",
            json=activation_request(invite_token, password=weak_password),
        )
        assert rejected.status_code == 400
        assert rejected.json()["detail"] == "password does not meet the password rules"
        activated = client.post(
            "/auth/activate",
            json=activation_request(invite_token, password=password),
        )

        assert activated.status_code == 201
        assert activated.json() == {"status": "activated", "username": "patient.user"}
        assert password not in activated.text
        with app.state.session_factory() as session:
            account = session.scalar(
                select(PatientPortalAccount).where(PatientPortalAccount.username == "patient.user")
            )
            assert account is not None
            assert account.password_hash.startswith("$argon2id$")
            assert account.password_hash != password
            assert credentials.verify_password(account.password_hash, password) is True
