"""Static assets retain their delivery and security across deployment topologies."""

import pytest
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.routing import Mount

from carlos_patient_portal.web_support import PACKAGE_DIR
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    migrated_development_app,
)
from tests.test_public_device_path import SplitProxy


@pytest.mark.parametrize(
    ("configured_prefix", "wire_prefix", "outer_mount"),
    [
        ("", "", False),
        ("/patient", "/patient", False),
        ("/患者", "/%E6%82%A3%E8%80%85", False),
        ("/patient", "/patient", True),
    ],
    ids=["root", "ascii", "unicode", "outer-mount"],
)
def test_static_assets_keep_delivery_and_security_across_deployment_topologies(
    configured_prefix, wire_prefix, outer_mount
):
    app = migrated_development_app(
        public_base_url="https://portal.example.test" + configured_prefix,
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    proxy = (
        Starlette(routes=[Mount(configured_prefix, app=app)])
        if outer_mount
        else SplitProxy(app, configured_prefix, wire_prefix)
    )
    with TestClient(proxy, base_url="https://portal.example.test") as client:
        for name, content_type in [("portal.js", "javascript"), ("styles.css", "text/css")]:
            target = wire_prefix + "/static/" + name
            response = client.get(target)
            assert response.status_code == 200
            assert content_type in response.headers["content-type"]
            assert response.content == (PACKAGE_DIR / "static" / name).read_bytes()
            head = client.head(target)
            assert head.status_code == 200
            assert head.content == b""
            assert head.headers["content-length"] == response.headers["content-length"]
            assert (
                client.get(target, headers={"If-None-Match": response.headers["etag"]}).status_code
                == 304
            )
            assert client.post(target).status_code == 405

        for target in ["/static/fhir/FAKE-missing-boundary", "/static/%2e%2e/main.py"]:
            missing = client.get(wire_prefix + target)
            assert missing.status_code == 404
            assert missing.headers["content-type"].startswith("text/html")
            assert "OperationOutcome" not in missing.text
