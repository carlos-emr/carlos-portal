# ruff: noqa: F811  (the signed-HTTP fixture is imported from test_mycarlos_mailbox_http)
"""What the mailbox routes refuse: bad cursors, bodies that are too large or malformed, and
unknown deliveries, on both the device side and the clinic's internal side.

Synthetic keys and bytes only; it reuses the signed-HTTP harness of test_mycarlos_mailbox_http.
"""

import pytest
from sqlalchemy import func, select
from starlette.requests import Request

from carlos_patient_portal.mailbox_codec import MAX_UPLOAD, MailboxRefusal
from carlos_patient_portal.mailbox_models import (
    MailboxBlob,
    MailboxClinic,
    MailboxCopy,
    MailboxEvent,
)
from carlos_patient_portal.routes import mycarlos_mailbox
from tests.support import carlos_job_headers
from tests.test_mycarlos_mailbox_http import (  # noqa: F401  (http_mailbox is a fixture)
    BODY,
    COPY_PATH,
    JOB,
    JOB_KID,
    LIST_PATH,
    M0,
    NOW,
    PREFIX,
    UPLOAD_PATH,
    device_headers,
    http_mailbox,
    job_headers,
)

EVENTS_PATH = "/internal/carlos/mycarlos/delivery-events"
ACK_PATH = EVENTS_PATH + "/ack"
ANCHORS_PATH = PREFIX + "/api/mycarlos/anchors"


def internal_headers(method, path, permission, *, query=b"", body=b""):
    return carlos_job_headers(
        "delivery-sync",
        permission,
        method=method,
        path=path,
        query=query,
        body=body,
        clinic_id="clinic-a",
        key_id=JOB_KID,
        signing_key=JOB.ed25519,
    ) | {"Content-Type": "application/octet-stream"}


def stored(app):
    """What the mailbox holds: copies by status, blobs, events, and the clinic's counters."""
    with app.state.session_factory() as session:
        clinic = session.scalar(select(MailboxClinic))
        return {
            "copies": sorted(session.scalars(select(MailboxCopy.status))),
            "blobs": session.scalar(select(func.count()).select_from(MailboxBlob)),
            "events": session.scalar(select(func.count()).select_from(MailboxEvent)),
            "event_sequence": clinic.event_sequence if clinic else None,
            "acked_through": clinic.acked_through if clinic else None,
        }


def upload(client):
    assert client.post(UPLOAD_PATH, content=BODY, headers=job_headers()).status_code == 201


def pick_up(client, monkeypatch):
    """Upload, then take the copy up with the fixture receipt: the clinic now has an event."""
    import json

    from carlos_patient_portal import mailbox

    upload(client)
    original = mailbox.accept_receipt
    monkeypatch.setattr(
        mycarlos_mailbox,
        "accept_receipt",
        lambda *args, **kwargs: original(*args, **kwargs, clock=lambda: NOW),
    )
    receipt = next(
        value["receipt"] for value in M0["portal"]["receipts"] if value["expect"] == "accept"
    )
    body = json.dumps({"receipt": receipt}, separators=(",", ":")).encode()
    path = COPY_PATH + "/receipt"
    picked = client.post(path, content=body, headers=device_headers(path, method="POST", body=body))
    assert picked.status_code == 200


def still_waiting_and_downloadable(app, client):
    assert stored(app)["copies"] == ["waiting"]
    downloaded = client.get(COPY_PATH, headers=device_headers(COPY_PATH))
    assert downloaded.status_code == 200
    assert stored(app)["copies"] == ["waiting"]


def test_a_device_get_that_carries_a_body_is_not_found(http_mailbox):
    _app, client, _proxy = http_mailbox
    for path in (LIST_PATH, COPY_PATH, ANCHORS_PATH):
        refused = client.request(
            "GET", path, content=b"unexpected", headers=device_headers(path, body=b"unexpected")
        )
        assert refused.status_code == 404, path
        assert refused.json() == {"detail": "not found"}, path
        assert refused.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "query",
    [
        "after=1",  # past what has been delivered to this device
        "after=0&through=1",  # a window beyond the device's own sequence
        "limit=0",
        "limit=101",
        "limit=-1",
        "after=01",  # not canonical
        "after=99999999999999999999",  # past a signed 64-bit counter
        "after=0&after=0",  # repeated
        "after",  # no value
        "colour=blue",  # unknown key
        "after=%C3%A9",  # percent-encoded non-digits (the raw non-ASCII branch is tested below)
        "accept=",  # an empty list of kinds
        "accept=Reading-Aid/1",  # a kind name must be lower case
        "accept=reading-aid/1,reading-aid/1",  # a repeated kind
    ],
)
def test_a_delivery_listing_refuses_a_cursor_it_did_not_issue(http_mailbox, query):
    _app, client, _proxy = http_mailbox
    path = LIST_PATH + "?" + query
    refused = client.get(path, headers=device_headers(path))
    assert refused.status_code == 400, query
    assert refused.json() == {"code": "invalid_cursor"}, query
    assert refused.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("query", ["after=1", "limit=0", "limit=101", "colour=blue"])
def test_an_anchor_listing_refuses_a_cursor_it_did_not_issue(http_mailbox, query):
    _app, client, _proxy = http_mailbox
    path = ANCHORS_PATH + "?" + query
    refused = client.get(path, headers=device_headers(path))
    assert refused.status_code == 400, query
    assert refused.json() == {"code": "invalid_cursor"}, query


def test_a_delivery_nobody_uploaded_is_not_found_for_download_and_receipt(http_mailbox):
    _app, client, _proxy = http_mailbox
    path = LIST_PATH + "/00000000-0000-4000-8000-000000000000"
    missing = client.get(path, headers=device_headers(path))
    assert missing.status_code == 404
    assert missing.json() == {"code": "delivery_not_found"}
    # The receipt half: a well-formed receipt body for a delivery nobody uploaded.
    body = b'{"receipt":"a.b"}'
    receipt = path + "/receipt"
    refused = client.post(
        receipt, content=body, headers=device_headers(receipt, method="POST", body=body)
    )
    assert refused.status_code == 404
    assert refused.json() == {"code": "delivery_not_found"}


def test_a_receipt_body_that_is_too_large_is_refused_before_it_is_read_in_full(http_mailbox):
    app, client, _proxy = http_mailbox
    upload(client)
    path = COPY_PATH + "/receipt"
    body = b"x" * 9000
    refused = client.post(
        path, content=body, headers=device_headers(path, method="POST", body=body)
    )
    assert refused.status_code == 413
    assert refused.json() == {"detail": "request too large"}
    still_waiting_and_downloadable(app, client)


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"{}",
        b'{"receipt":""}',
        b'{"receipt":1}',
        b'{"receipt":"a.b","extra":1}',
        '{"receipt":"café"}'.encode(),
    ],
)
def test_a_receipt_that_is_not_one_ascii_string_is_refused(http_mailbox, body):
    app, client, _proxy = http_mailbox
    upload(client)
    path = COPY_PATH + "/receipt"
    refused = client.post(
        path, content=body, headers=device_headers(path, method="POST", body=body)
    )
    assert refused.status_code == 400, body
    assert refused.json() == {"code": "invalid_receipt"}, body
    still_waiting_and_downloadable(app, client)


def nothing_stored(app):
    held = stored(app)
    assert (held["copies"], held["blobs"], held["events"]) == ([], 0, 0)


def test_an_upload_that_is_not_octet_stream_or_not_for_a_real_patient_is_refused(http_mailbox):
    app, client, _proxy = http_mailbox
    wrong_type = job_headers() | {"Content-Type": "application/json"}
    refused = client.post(UPLOAD_PATH, content=BODY, headers=wrong_type)
    assert refused.status_code == 400
    assert refused.json() == {"code": "invalid_delivery"}
    for number in ("0", "2147483648"):
        path = f"/internal/carlos/patients/{number}/mycarlos/deliveries"
        refused = client.post(path, content=BODY, headers=job_headers(path))
        assert refused.status_code == 400, number
        assert refused.json() == {"code": "invalid_delivery"}, number
    nothing_stored(app)


def test_an_upload_for_a_patient_with_no_account_is_not_found(http_mailbox):
    app, client, _proxy = http_mailbox
    path = "/internal/carlos/patients/987654/mycarlos/deliveries"
    refused = client.post(path, content=BODY, headers=job_headers(path))
    assert refused.status_code == 404
    assert refused.json() == {"code": "delivery_not_found"}
    nothing_stored(app)


def test_an_upload_larger_than_the_frozen_limit_is_refused_as_too_large(http_mailbox):
    app, client, _proxy = http_mailbox
    body = b"\0" * (MAX_UPLOAD + 1)
    refused = client.post(UPLOAD_PATH, content=body, headers=job_headers(body=body))
    assert refused.status_code == 413
    assert refused.json() == {"detail": "request too large"}
    nothing_stored(app)


@pytest.mark.parametrize(
    "query", [b"after=x", b"limit=0", b"limit=51", b"after=1&after=1", b"colour=blue", b"after"]
)
def test_the_clinics_event_listing_refuses_a_cursor_it_did_not_issue(http_mailbox, query):
    _app, client, _proxy = http_mailbox
    headers = internal_headers(
        "GET", EVENTS_PATH, "portal.mycarlos.delivery.events.read", query=query
    )
    refused = client.get(EVENTS_PATH + "?" + query.decode(), headers=headers)
    assert refused.status_code == 400, query
    assert refused.json() == {"code": "invalid_cursor"}, query


def test_the_clinics_event_listing_refuses_a_cursor_past_the_last_event_it_issued(
    http_mailbox, monkeypatch
):
    app, client, _proxy = http_mailbox
    pick_up(client, monkeypatch)
    last = stored(app)["event_sequence"]
    assert last >= 1

    def listing(after):
        query = f"after={after}".encode()
        headers = internal_headers(
            "GET", EVENTS_PATH, "portal.mycarlos.delivery.events.read", query=query
        )
        return client.get(EVENTS_PATH + "?" + query.decode(), headers=headers)

    refused = listing(last + 1)
    assert refused.status_code == 400
    assert refused.json() == {"code": "invalid_cursor"}
    # The last event's own sequence is a cursor the portal did issue.
    assert listing(last).status_code == 200


def test_the_clinics_event_listing_takes_no_body(http_mailbox):
    _app, client, _proxy = http_mailbox
    body = b"unexpected"
    headers = internal_headers(
        "GET", EVENTS_PATH, "portal.mycarlos.delivery.events.read", body=body
    )
    refused = client.request("GET", EVENTS_PATH, content=body, headers=headers)
    assert refused.status_code == 413
    assert refused.json() == {"detail": "request too large"}


def acknowledge(client, body):
    headers = internal_headers("POST", ACK_PATH, "portal.mycarlos.delivery.events.ack", body=body)
    return client.post(ACK_PATH, content=body, headers=headers)


@pytest.mark.parametrize(
    "body",
    [b"not json", b"{}", b'{"through":1}', b'{"through":"x"}', b'{"through":"1","more":"1"}'],
)
def test_an_event_acknowledgement_must_be_one_canonical_cursor(http_mailbox, body):
    app, client, _proxy = http_mailbox
    upload(client)
    before = stored(app)
    refused = acknowledge(client, body)
    assert refused.status_code == 400, body
    assert refused.json() == {"code": "invalid_cursor"}, body
    assert stored(app) == before


def test_an_event_acknowledgement_cannot_pass_the_last_event_issued(http_mailbox, monkeypatch):
    app, client, _proxy = http_mailbox
    pick_up(client, monkeypatch)
    before = stored(app)
    last = before["event_sequence"]
    refused = acknowledge(client, f'{{"through":"{last + 1}"}}'.encode())
    assert refused.status_code == 400
    assert refused.json() == {"code": "invalid_cursor"}
    assert stored(app) == before
    assert before["acked_through"] == 0
    # Up to the last event is allowed, and is what moves the counter.
    accepted = acknowledge(client, f'{{"through":"{last}"}}'.encode())
    assert accepted.status_code == 200
    assert accepted.json() == {"acked_through": str(last)}
    assert stored(app)["acked_through"] == last


def test_an_event_acknowledgement_that_is_too_large_is_refused(http_mailbox):
    app, client, _proxy = http_mailbox
    upload(client)
    before = stored(app)
    refused = acknowledge(client, b'{"through":"' + b"1" * 2000 + b'"}')
    assert refused.status_code == 413
    assert refused.json() == {"detail": "request too large"}
    assert stored(app) == before


def test_a_query_that_is_not_ascii_is_refused_as_an_invalid_cursor():
    # httpx percent-encodes a client's query, so the raw bytes are given to the route directly.
    request = Request({"type": "http", "query_string": b"after=\xc3\xa9", "headers": []})
    with pytest.raises(MailboxRefusal) as refused:
        mycarlos_mailbox.query_values(request, {"after"}, maximum=100, default=50)
    assert (refused.value.code, refused.value.status) == ("invalid_cursor", 400)
