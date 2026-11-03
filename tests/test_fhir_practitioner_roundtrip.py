from fastapi.testclient import TestClient
from fhir.resources.bundle import Bundle
from fhir.resources.operationoutcome import OperationOutcome
from fhir.resources.practitioner import Practitioner

from carlos_patient_portal.interop import build_fhir_practitioner_id
from carlos_patient_portal.unlock_secrets import create_unlock_secret
from tests.support import (
    UNLOCK_SECRET_ENCRYPTION_SECRET,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    activate_seeded_patient_account,
    bearer_headers,
    migrated_development_app,
    sign_in_patient_api_session,
)


def test_practitioner_id_from_a_later_search_page_round_trips_within_patient_scope() -> None:
    app = migrated_development_app(
        public_base_url="https://portal.example.test",
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    with TestClient(app, base_url="https://portal.example.test") as client:
        activate_seeded_patient_account(app, client)
        headers = bearer_headers(sign_in_patient_api_session(client))
        with app.state.session_factory() as session, session.begin():
            for index in range(102):
                foreign = index == 101
                create_unlock_secret(
                    session,
                    clinic_id="default",
                    demographic_no=5678 if foreign else 1234,
                    created_by=f"FAKE provider {index:03d}",
                    created_by_id=f"FAKE-provider-{index:03d}",
                    encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                    secret="FAKE private passphrase",
                    source_reference=f"FAKE-provider-page-{index:03d}",
                )

        first = client.get("/fhir/Practitioner", params={"_count": 100}, headers=headers)
        assert first.status_code == 200
        first_payload = first.json()
        Bundle(first_payload)
        assert first_payload["total"] == 101
        first_ids = {entry["resource"]["id"] for entry in first_payload["entry"]}
        assert len(first_ids) == 100
        next_link = next(
            link["url"] for link in first_payload["link"] if link["relation"] == "next"
        )

        later = client.get(next_link, headers=headers)
        assert later.status_code == 200
        later_payload = later.json()
        Bundle(later_payload)
        assert later_payload["total"] == 101
        assert len(later_payload["entry"]) == 1
        resource = later_payload["entry"][0]["resource"]
        assert resource["id"] not in first_ids
        assert resource["name"][0]["text"].startswith("FAKE provider ")

        read = client.get(f"/fhir/Practitioner/{resource['id']}", headers=headers)
        assert read.status_code == 200
        assert read.json() == resource
        Practitioner(read.json())
        selected = client.get("/fhir/Practitioner", params={"_id": resource["id"]}, headers=headers)
        assert selected.status_code == 200
        selected_payload = selected.json()
        Bundle(selected_payload)
        assert selected_payload["total"] == 1
        assert [entry["resource"] for entry in selected_payload["entry"]] == [resource]

        foreign_id = build_fhir_practitioner_id(
            clinic_id="default", name="FAKE provider 101", provider_id="FAKE-provider-101"
        )
        foreign = client.get(f"/fhir/Practitioner/{foreign_id}", headers=headers)
        assert foreign.status_code == 404
        OperationOutcome(foreign.json())
        for response in (first, later, read, selected, foreign):
            assert "FAKE private passphrase" not in response.text
