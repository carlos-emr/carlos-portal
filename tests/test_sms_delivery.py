import json
from http.client import HTTPException
from types import SimpleNamespace

import pytest

from carlos_patient_portal.config import Settings
from carlos_patient_portal.sms_delivery import (
    MAX_SMS_GATEWAY_RESPONSE_BYTES,
    PortalSmsDeliveryError,
    WebhookPortalSmsSender,
)

SMS_TOKEN = "sms-webhook-token-value-32-characters"


class FakeResponse:
    status = 202

    def read(self, _: int | None = None) -> bytes:
        return b""


def sms_settings() -> Settings:
    return Settings(
        environment="development",
        sms_webhook_url="https://sms.example.test/messages",
        sms_webhook_token=SMS_TOKEN,
    )


def test_sms_webhook_sends_bearer_authenticated_json(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class FakeConnection:
        def __init__(self, host, port, **kwargs):
            captured["host"] = host
            captured["port"] = port
            captured["kwargs"] = kwargs

        def request(self, method, path, *, body, headers):
            captured["method"] = method
            captured["path"] = path
            captured["body"] = body
            captured["headers"] = headers

        def getresponse(self):
            return FakeResponse()

        def close(self):
            captured["closed"] = True

    monkeypatch.setattr("carlos_patient_portal.sms_delivery.HTTPSConnection", FakeConnection)
    sender = WebhookPortalSmsSender(sms_settings())

    sender.send_code(
        recipient="+15550105555",
        code="123456",
        expires_in_seconds=600,
    )

    payload = json.loads(captured["body"])
    assert captured["host"] == "sms.example.test"
    assert captured["path"] == "/messages"
    assert captured["headers"]["Authorization"] == f"Bearer {SMS_TOKEN}"
    assert payload["to"] == "+15550105555"
    assert "123456" in payload["message"]
    assert captured["kwargs"]["timeout"] == 10
    assert captured["closed"] is True


def test_sms_webhook_failure_does_not_expose_recipient(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingConnection:
        def __init__(self, *_: object, **__: object):
            pass

        def request(self, *_: object, **__: object):
            raise OSError("gateway rejected +15550105555")

        def close(self):
            pass

    monkeypatch.setattr("carlos_patient_portal.sms_delivery.HTTPSConnection", FailingConnection)
    sender = WebhookPortalSmsSender(sms_settings())

    with pytest.raises(PortalSmsDeliveryError) as raised_error:
        sender.send_code(
            recipient="+15550105555",
            code="123456",
            expires_in_seconds=600,
        )

    assert "+15550105555" not in str(raised_error.value)
    assert raised_error.value.__cause__ is None
    assert raised_error.value.__context__ is not None
    assert raised_error.value.__suppress_context__


def test_sms_webhook_rejects_oversized_gateway_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class OversizedResponse:
        status = 202

        def read(self, amount: int) -> bytes:
            return b"x" * amount

    class OversizedConnection:
        def __init__(self, *_: object, **__: object):
            pass

        def request(self, *_: object, **__: object):
            pass

        def getresponse(self):
            return OversizedResponse()

        def close(self):
            pass

    monkeypatch.setattr(
        "carlos_patient_portal.sms_delivery.HTTPSConnection",
        OversizedConnection,
    )
    sender = WebhookPortalSmsSender(sms_settings())

    with pytest.raises(PortalSmsDeliveryError):
        sender.send_code(
            recipient="+15550105555",
            code="123456",
            expires_in_seconds=600,
        )


@pytest.fixture
def recording_gateway(monkeypatch):
    state = SimpleNamespace(status=202, body=b"", read_error=None, closed=0)

    class GatewayResponse:
        @property
        def status(self):
            return state.status

        def read(self, amount):
            if state.read_error is not None:
                raise state.read_error
            return state.body[:amount]

    class GatewayConnection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return GatewayResponse()

        def close(self):
            state.closed += 1

    monkeypatch.setattr("carlos_patient_portal.sms_delivery.HTTPSConnection", GatewayConnection)
    return state


@pytest.mark.parametrize(
    ("status", "accepted"),
    [(200, True), (204, True), (299, True), (300, False), (429, False), (503, False)],
)
def test_sms_gateway_status_controls_delivery_without_echoing_its_body(
    recording_gateway, status, accepted
):
    recording_gateway.status = status
    recording_gateway.body = b"FAKE private gateway body: +15550105555 code 123456"
    sender = WebhookPortalSmsSender(sms_settings())

    if accepted:
        sender.send_code(recipient="+15550105555", code="123456", expires_in_seconds=600)
    else:
        with pytest.raises(PortalSmsDeliveryError) as error:
            sender.send_code(recipient="+15550105555", code="123456", expires_in_seconds=600)
        assert str(error.value) == "portal SMS delivery failed"

    assert recording_gateway.closed == 1


def test_sms_gateway_response_at_the_byte_limit_is_accepted(recording_gateway):
    recording_gateway.body = b"x" * MAX_SMS_GATEWAY_RESPONSE_BYTES
    sender = WebhookPortalSmsSender(sms_settings())

    sender.send_code(recipient="+15550105555", code="123456", expires_in_seconds=600)

    assert recording_gateway.closed == 1


def test_sms_gateway_protocol_read_failure_is_redacted_and_closes_the_connection(recording_gateway):
    recording_gateway.read_error = HTTPException(
        "FAKE private gateway failure: +15550105555 code 123456"
    )
    sender = WebhookPortalSmsSender(sms_settings())

    with pytest.raises(PortalSmsDeliveryError) as error:
        sender.send_code(recipient="+15550105555", code="123456", expires_in_seconds=600)

    assert str(error.value) == "portal SMS delivery failed"
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__ is True
    assert recording_gateway.closed == 1
