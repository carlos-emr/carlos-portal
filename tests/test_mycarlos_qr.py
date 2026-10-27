"""QR producer/privacy checks; actual decoder/native scan evidence is a separate gate."""

import base64
import json
import re
from pathlib import Path

import pytest

from carlos_patient_portal.models import utc_now
from carlos_patient_portal.mycarlos_links import IssuedLinkCode
from carlos_patient_portal.mycarlos_qr import link_qr_data_uri, link_qr_payload
from carlos_patient_portal.view_models import MyCarlosViewModel
from carlos_patient_portal.web_support import CONTENT_SECURITY_POLICY
from tests.test_mycarlos_portal import form_token, make_portal, sign_in

FIXTURE = json.loads((Path(__file__).parent / "fixtures/qr-link-v1.json").read_text())


@pytest.mark.parametrize(
    "vector",
    [value for value in FIXTURE["vectors"] if value["expect_accept"]],
    ids=lambda value: value["name"],
)
def test_producer_matches_shared_original_utf8_bytes(vector):
    expected = bytes.fromhex(vector["payload_hex"])
    values = json.loads(expected)
    issued = IssuedLinkCode(values["link_id"], values["code"], utc_now())
    assert link_qr_payload(issued, values["portal_url"]) == expected
    image = link_qr_data_uri(issued, values["portal_url"])
    assert image.startswith("data:image/png;base64,")
    assert base64.b64decode(image.partition(",")[2], validate=True).startswith(b"\x89PNG\r\n\x1a\n")
    assert values["code"] not in repr(
        MyCarlosViewModel(code_display=values["code"], qr_png_data_uri=image)
    )


def test_qr_only_appears_in_no_store_creation_post_with_full_response_csp(caplog):
    app, client, sms, _account = make_portal()
    sign_in(client, sms)
    initial = client.get("/portal/mycarlos")
    assert "data:image/png" not in initial.text
    assert initial.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    response = client.post("/portal/mycarlos/code", data={"csrf_token": form_token(client)})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert (
        response.headers["content-security-policy"]
        == CONTENT_SECURITY_POLICY + "; img-src 'self' data:"
    )
    image = re.search(r'src="(data:image/png;base64,[A-Za-z0-9+/=]+)"', response.text)
    assert image is not None
    assert image.group(1) not in caplog.text
    assert "data:image/png" not in client.get("/portal/mycarlos").text
    assert "data:image/png" not in str(response.url)


def test_development_http_does_not_create_a_production_qr_target():
    issued = IssuedLinkCode("FAKE0001", "FAKE7Q2M4K", utc_now())
    assert link_qr_data_uri(issued, "http://127.0.0.1:8090") is None
    assert link_qr_data_uri(issued, None) is None
