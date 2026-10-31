from uuid import uuid4

import pytest

from carlos_patient_portal import main
from tests import delivery_contract_reference as ref
from tests.support import RecordingPortalEmailSender, RecordingPortalSmsSender
from tests.test_mycarlos_mailbox_http import (
    DEVICE,
    LIST_PATH,
    OUTER,
    UPLOAD_PATH,
    device_headers,
    http_mailbox,  # noqa: F401 -- request owned fixture after explicit provider injection
    job_headers,
)


def test_mailbox_list_watermark_excludes_uploads_committed_between_pages(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        main, "build_portal_email_sender", lambda settings: RecordingPortalEmailSender()
    )
    monkeypatch.setattr(
        main, "build_portal_sms_sender", lambda settings: RecordingPortalSmsSender()
    )
    app, client, _proxy = request.getfixturevalue("http_mailbox")
    clinic = ref.ClinicKey("FAKE pagination clinic signing key", "clinic-a")
    copies = []
    try:
        for index in range(3):
            delivery_id = str(uuid4())
            manifest = ref.manifest_claims(
                clinic,
                delivery_id=delivery_id,
                recipient_id=OUTER["recipient_id"],
                device=DEVICE,
                pdf=ref.FAKE_PDF,
            )
            package = ref.build_package(
                manifest=ref.compact_es256(clinic, manifest),
                pdf=ref.FAKE_PDF,
                device=DEVICE,
                outer_delivery_id=delivery_id,
                outer_recipient_id=OUTER["recipient_id"],
                ikm_label=f"FAKE pagination copy {index}",
            )
            body = ref.frame(
                ref.canonical_json(package["outer"]), ref.b64url_decode(package["blob"])
            )
            copies.append((package["outer"], body))

        for _outer, body in copies[:2]:
            uploaded = client.post(UPLOAD_PATH, content=body, headers=job_headers(body=body))
            assert uploaded.status_code == 201

        path = LIST_PATH + "?limit=1"
        first = client.get(path, headers=device_headers(path))
        assert first.status_code == 200
        page = first.json()
        assert page["deliveries"] == [copies[0][0]]
        assert page["next_cursor"] is not None
        through = page["through"]

        # A real signed upload commits after discovery of this scan's upper bound.
        body = copies[2][1]
        assert (
            client.post(UPLOAD_PATH, content=body, headers=job_headers(body=body)).status_code
            == 201
        )
        path = LIST_PATH + f"?after={page['next_cursor']}&through={through}&limit=1"
        second = client.get(path, headers=device_headers(path))
        assert second.status_code == 200
        assert second.json()["deliveries"] == [copies[1][0]]
        assert second.json()["through"] == through
        assert second.json()["next_cursor"] is None

        # A new scan from the old watermark must discover the later upload.
        path = LIST_PATH + f"?after={through}&limit=1"
        later = client.get(path, headers=device_headers(path))
        assert later.status_code == 200
        assert later.json()["deliveries"] == [copies[2][0]]
        assert int(later.json()["through"]) > int(through)
        assert later.json()["next_cursor"] is None
    finally:
        # The imported client is deliberately not entered, so no lifespan worker starts.
        client.close()
        app.state.database_engine.dispose()
