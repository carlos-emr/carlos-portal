from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
from fhir.resources.bundle import Bundle

from carlos_patient_portal.interop import build_fhir_patient_id
from carlos_patient_portal.models import UNLOCK_SECRET_STATUS_ACTIVE, UNLOCK_SECRET_STATUS_PENDING
from carlos_patient_portal.unlock_secrets import (
    create_unlock_secret,
    publish_unlock_secret,
    revoke_unlock_secret,
)
from tests.support import (
    UNLOCK_SECRET_ENCRYPTION_SECRET,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    activate_seeded_patient_account,
    bearer_headers,
    migrated_development_app,
    sign_in_patient_api_session,
)


def test_document_id_search_preserves_compartment_visibility_and_single_result_paging() -> None:
    app = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    with TestClient(app) as client:
        activate_seeded_patient_account(app, client)
        headers = bearer_headers(sign_in_patient_api_session(client))
        ids = {}
        with app.state.session_factory() as session, session.begin():
            for name, clinic, patient, kind, status in [
                ("chosen", "default", 1234, "email", UNLOCK_SECRET_STATUS_ACTIVE),
                ("other-owned", "default", 1234, "email", UNLOCK_SECRET_STATUS_ACTIVE),
                ("pending", "default", 1234, "email", UNLOCK_SECRET_STATUS_PENDING),
                ("revoked", "default", 1234, "email", UNLOCK_SECRET_STATUS_ACTIVE),
                ("other-patient", "default", 5678, "email", UNLOCK_SECRET_STATUS_ACTIVE),
                ("other-clinic", "FAKE-other-clinic", 1234, "email", UNLOCK_SECRET_STATUS_ACTIVE),
                ("pdf", "default", 1234, "pdf", UNLOCK_SECRET_STATUS_ACTIVE),
            ]:
                record = create_unlock_secret(
                    session,
                    clinic_id=clinic,
                    demographic_no=patient,
                    secret_type=kind,
                    initial_status=status,
                    created_by="FAKE provider",
                    encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                    secret="FAKE private document passphrase",
                    label=f"FAKE {name}",
                    source_reference=f"FAKE-id-search-{name}",
                ).unlock_secret
                ids[name] = record.id
            revoke_unlock_secret(
                session,
                ids["revoked"],
                clinic_id="default",
                demographic_no=1234,
                revoked_by="FAKE provider",
            )

        def search(record_id, **parameters):
            response = client.get(
                "/fhir/DocumentReference",
                params={"_id": str(record_id), **parameters},
                headers=headers,
            )
            assert response.status_code == 200
            payload = response.json()
            assert payload["resourceType"] == "Bundle"
            Bundle(payload)
            assert "FAKE private document passphrase" not in response.text
            return payload

        chosen = search(ids["chosen"])
        assert chosen["total"] == 1
        assert [entry["resource"]["id"] for entry in chosen["entry"]] == [str(ids["chosen"])]
        assert chosen["entry"][0]["resource"]["description"] == "FAKE chosen"

        for selector in [
            ids["pending"],
            ids["revoked"],
            ids["other-patient"],
            ids["other-clinic"],
            ids["pdf"],
            max(ids.values()) + 100,
            "FAKE-not-numeric",
        ]:
            hidden = search(selector)
            assert hidden["total"] == 0
            assert hidden.get("entry", []) == []

        wrong_subject = "Patient/" + build_fhir_patient_id("default", 5678)
        mismatched = search(ids["chosen"], subject=wrong_subject)
        assert mismatched["total"] == 0
        assert mismatched.get("entry", []) == []

        beyond_only_result = search(ids["chosen"], _count=1, _offset=1)
        assert beyond_only_result["total"] == 1
        assert beyond_only_result.get("entry", []) == []
        links = {link["relation"]: link["url"] for link in beyond_only_result["link"]}
        assert "next" not in links
        assert parse_qs(urlsplit(links["previous"]).query) == {
            "_id": [str(ids["chosen"])],
            "_count": ["1"],
            "_offset": ["0"],
        }

        with app.state.session_factory() as session, session.begin():
            publish_unlock_secret(
                session,
                ids["pending"],
                clinic_id="default",
                demographic_no=1234,
                published_by="FAKE provider",
            )
        published = search(ids["pending"])
        assert published["total"] == 1
        assert [entry["resource"]["id"] for entry in published["entry"]] == [str(ids["pending"])]
