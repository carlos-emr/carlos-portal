"""Guards in the push-provider adapters that decide before anything is sent, or without trusting
what came back.

A destination handle is a URL (WNS) or a token the portal will send to, so one that cannot be read
as a URL is an invalid destination, never an exception that stops the whole batch. A provider
answer that is not a plain status is a bug in the HTTP client, reported as one. The configuration
objects refuse a malformed identity so a deployment mistake shows at start-up, not at the first
patient notice. FAKE ids and no network: every transport here is a recording double.
"""

from pathlib import Path
from uuid import UUID

import pytest

from carlos_patient_portal import notification_transports as nt
from carlos_patient_portal.mycarlos_availability import (
    GenericNotice,
    NoticeKeys,
    PushPlatform,
    ReadyHint,
    notice_token,
)
from tests import notification_transports_support as sup

DESTINATION = UUID("00000000-0000-4000-8000-0000000000d1")
HINT = ReadyHint(
    UUID("00000000-0000-4000-8000-0000000000a1"),
    UUID("00000000-0000-4000-8000-0000000000e1"),
    42,
)
NOTICE = GenericNotice(notice_token(NoticeKeys(b"k" * 32), HINT))
WNS = nt.WnsConfig("ms-app://S-1-15-2-1-2-3-4-5-6-7", "fake-client-secret")


def wns_send(handle: str, *responses: int):
    transport = sup.RecordingWnsTransport(
        WNS, sup.FixedHandles({DESTINATION: handle}), *responses
    )
    result = transport.send(
        destination_id=DESTINATION,
        platform=PushPlatform.WINDOWS_WNS,
        notice=NOTICE,
        ttl_seconds=600,
        collapse_key="c" * 64,
    )
    return result, transport.requests


@pytest.mark.parametrize(
    "handle",
    [
        # urlsplit refuses these as malformed (an unclosed or invalid IPv6 host): the handle is
        # an invalid destination and nothing is sent, not a ValueError out of the sender.
        "https://[db5.notify.windows.com/x",
        "https://[::1/x",
        "https://[fe80::1%25eth0]x.notify.windows.com/",
    ],
)
def test_a_wns_channel_that_cannot_be_read_as_a_url_is_an_invalid_destination(
    handle: str,
) -> None:
    result, requests = wns_send(handle, 200)

    assert result is nt.ProviderResult.INVALID_DESTINATION
    assert requests == []


def test_a_wns_channel_on_a_microsoft_host_is_still_sent_to() -> None:
    # The unreadable-handle guard must not turn a good channel into a refusal.
    result, requests = wns_send("https://db5.notify.windows.com/?token=FAKECHANNEL", 200)

    assert result is nt.ProviderResult.ACCEPTED
    assert len(requests) == 1


class AnswersWithTheWrongThing:
    """An HTTP client that returns something other than the `HttpResponse` it promises."""

    def __init__(self, answer: object) -> None:
        self._answer = answer

    def send(self, request: nt.HttpRequest, *, timeout: float) -> object:
        return self._answer


@pytest.mark.parametrize(
    "answer",
    [200, None, {"status": 200}, nt.HttpResponse("200")],  # type: ignore[arg-type]
    ids=["a bare number", "nothing", "a mapping", "a status that is text"],
)
def test_a_client_that_does_not_return_a_plain_status_is_reported_as_a_bug(
    answer: object,
) -> None:
    request = nt.HttpRequest(method="POST", url="https://example.invalid/", headers={}, body=b"")

    with pytest.raises(TypeError, match="invalid_http_response"):
        nt._post(AnswersWithTheWrongThing(answer), request)  # type: ignore[arg-type]


def test_a_provider_answer_prints_only_its_status() -> None:
    # Provider bodies and headers never enter a decision, and never a log line through repr.
    assert repr(nt.HttpResponse(503)) == "HttpResponse[503]"


@pytest.mark.parametrize(
    "overrides",
    [
        {"key_path": "/nonexistent/fake.p8"},  # a string, not a Path
        {"key_path": None},
        {"sandbox": "yes"},  # not a bool
        {"sandbox": 1},
    ],
    ids=["key path as text", "no key path", "sandbox as text", "sandbox as number"],
)
def test_an_apns_config_with_a_wrong_kind_of_key_path_or_sandbox_flag_is_refused(
    overrides: dict[str, object],
) -> None:
    values = {
        "team_id": "FAKETEAM01",
        "key_id": "FAKEKEYID1",
        "key_path": Path("/nonexistent/fake.p8"),
        "bundle_id": "ca.example.fake",
        **overrides,
    }

    with pytest.raises(ValueError, match="invalid_apns_config"):
        nt.ApnsConfig(**values)  # type: ignore[arg-type]


def test_an_apns_config_with_valid_fields_is_accepted() -> None:
    config = nt.ApnsConfig(
        "FAKETEAM01", "FAKEKEYID1", Path("/nonexistent/fake.p8"), "ca.example.fake", sandbox=True
    )

    assert config.sandbox is True
