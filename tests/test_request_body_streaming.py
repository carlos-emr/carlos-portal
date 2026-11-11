"""Bound request bodies while consuming real ASGI messages, before parsing their contents."""

import asyncio
import json

import pytest
from fastapi import HTTPException, Request
from pydantic import BaseModel

from carlos_patient_portal.web_support import (
    MAX_FORM_FIELD_COUNT,
    MAX_JSON_BODY_BYTES,
    get_json_request_model,
    get_urlencoded_form_values,
)


class SyntheticPayload(BaseModel):
    label: str


def streamed_request(chunks, *, content_type, content_length=None):
    received = []
    headers = [(b"content-type", content_type.encode("ascii"))]
    if content_length is not None:
        headers.append((b"content-length", content_length.encode("ascii")))

    async def receive():
        index = len(received)
        assert index < len(chunks), "the parser read beyond the final ASGI body message"
        received.append(chunks[index])
        return {
            "type": "http.request",
            "body": chunks[index],
            "more_body": index < len(chunks) - 1,
        }

    return Request({"type": "http", "headers": headers}, receive), received


def test_json_at_the_byte_limit_survives_a_split_utf8_character_and_empty_chunk():
    payload = json.dumps({"label": "FAKE Żółć"}, ensure_ascii=False).encode("utf-8")
    body = payload + b" " * (MAX_JSON_BODY_BYTES - len(payload))
    split = body.index("Ż".encode()) + 1
    chunks = [body[:split], b"", body[split:]]
    request, received = streamed_request(chunks, content_type="Application/JSON; charset=utf-8")

    parsed = asyncio.run(get_json_request_model(request, SyntheticPayload, "JSON required"))

    assert parsed.label == "FAKE Żółć"
    assert received == chunks


@pytest.mark.parametrize(
    ("segmented", "content_length", "expected_reads"),
    [(False, None, 1), (True, "1", 2)],
)
def test_oversized_json_stops_reading_at_the_first_over_limit_chunk(
    segmented, content_length, expected_reads
):
    if segmented:
        chunks = [b"x" * MAX_JSON_BODY_BYTES, b"!", b"FAKE unread tail"]
    else:
        chunks = [b"x" * (MAX_JSON_BODY_BYTES + 1), b"FAKE unread tail"]
    request, received = streamed_request(
        chunks, content_type="application/json", content_length=content_length
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(get_json_request_model(request, SyntheticPayload, "JSON required"))

    assert error.value.status_code == 413
    assert error.value.detail == "request body too large"
    assert len(received) == expected_reads
    assert received[-1] != b"FAKE unread tail"


def test_form_at_both_limits_preserves_blank_repeated_and_unicode_values():
    fields = ["name=FAKE+Żółć", "tag=first", "tag="] + [
        f"field{index}=FAKE" for index in range(MAX_FORM_FIELD_COUNT - 3)
    ]
    body = "&".join(fields).encode("utf-8")
    split = body.index("Ż".encode()) + 1
    chunks = [body[:split], body[split:]]
    request, received = streamed_request(
        chunks, content_type="application/x-www-form-urlencoded; charset=utf-8"
    )

    parsed = asyncio.run(get_urlencoded_form_values(request, len(body), MAX_FORM_FIELD_COUNT))

    assert parsed["name"] == ["FAKE Żółć"]
    assert parsed["tag"] == ["first", ""]
    assert sum(len(values) for values in parsed.values()) == MAX_FORM_FIELD_COUNT
    assert received == chunks


def test_form_byte_limit_counts_utf8_bytes_instead_of_decoded_characters():
    body = "name=FAKE+Żółć".encode()
    request, received = streamed_request(
        [body[:-1], body[-1:], b"FAKE unread tail"],
        content_type="application/x-www-form-urlencoded",
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(get_urlencoded_form_values(request, len(body) - 1, MAX_FORM_FIELD_COUNT))

    assert error.value.status_code == 413
    assert error.value.detail == "request body too large"
    assert len(received) == 2


def test_unsupported_json_media_type_is_rejected_without_consuming_the_body():
    request, received = streamed_request([b"FAKE unread body"], content_type="text/plain")

    with pytest.raises(HTTPException) as error:
        asyncio.run(get_json_request_model(request, SyntheticPayload, "JSON required"))

    assert error.value.status_code == 415
    assert error.value.detail == "JSON required"
    assert received == []


def test_non_form_media_type_does_not_consume_or_parse_the_body():
    request, received = streamed_request([b"FAKE unread body"], content_type="application/json")

    assert asyncio.run(get_urlencoded_form_values(request, 1, 1)) == {}
    assert received == []
