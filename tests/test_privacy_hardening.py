# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""What the portal must not keep, echo or read in full (privacy audit, L1, L2, L5 and L6).

- An HL7 validation failure names the kind of failure, never the value that failed (a patient's
  name, birth date, health card number).
- A FHIR access row stores an id the client typed only when it has the shape of an id this portal
  issues; a name pasted into the URL or `_id` never reaches the audit trail.
- The staff and job API, and the device-link route, count the body as it arrives and stop at their
  limit, whether or not the request says how long it is.

FAKE names and ids only. The body tests drive the ASGI app directly so that every chunk the
application asks for is counted.
"""

import json
from datetime import UTC, datetime

import anyio
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal import body_limit
from carlos_patient_portal.body_limit import (
    INTERNAL_BODY_LIMIT,
    BodyLimitMiddleware,
    internal_body_limit,
)
from carlos_patient_portal.interop import (
    Hl7ConformanceProfileError,
    PortalPatientInteroperabilityIdentity,
    build_fhir_patient_id,
    build_hl7_v251_patient_registration,
    validate_hl7_v251_patient_registration_profile,
)
from carlos_patient_portal.mailbox_codec import MAX_UPLOAD
from carlos_patient_portal.models import PatientPortalAuditEvent
from carlos_patient_portal.routes.fhir import (
    ISSUED_FHIR_ID,
    UNRECOGNIZED_AUDIT_RESOURCE_ID,
)
from tests.support import (
    activate_seeded_patient_account,
    bearer_headers,
    migrated_development_app,
    sign_in_patient_api_session,
)
from tests.test_internal_api import internal_app
from tests.test_mycarlos_link_route import LINK_PATH, link_app

# --------------------------------------------------------------------------------------------
# L1: an HL7 validation error says what failed, not the value
# --------------------------------------------------------------------------------------------

IDENTITY = PortalPatientInteroperabilityIdentity(
    clinic_id="default",
    demographic_no=1234,
    email="fake.patient@example.test",
    date_of_birth=datetime(1980, 1, 2).date(),
    health_card_number="ABCD12345678",
    family_name="Patient",
    given_name="Example",
)
MESSAGE = build_hl7_v251_patient_registration(
    IDENTITY,
    message_time=datetime(2026, 7, 23, 12, 0, tzinfo=UTC),
    message_control_id="MSG0001",
)
FAKE_NAME = "FAKELOVELACE"


@pytest.mark.parametrize(
    "damaged",
    [
        # A name where the birth date goes: HL7apy raises a plain ValueError that quotes it.
        MESSAGE.replace("19800102", FAKE_NAME),
        # A name in a sequence-number field.
        MESSAGE.replace("PID|", f"PID|{FAKE_NAME}^^^|", 1),
        # A name in the encoding characters: an HL7apy error of its own kind.
        MESSAGE.replace("MSH|", f"MSH|{FAKE_NAME}", 1),
    ],
)
def test_a_value_in_a_bad_field_is_not_in_the_validation_error(damaged: str) -> None:
    with pytest.raises(Hl7ConformanceProfileError) as failure:
        validate_hl7_v251_patient_registration_profile(damaged)

    assert FAKE_NAME not in str(failure.value)
    assert str(failure.value).startswith("HL7 v2.5.1 validation failed (")
    # The original is dropped, so a traceback cannot print it either.
    assert failure.value.__cause__ is None
    assert failure.value.__suppress_context__ is True
    assert FAKE_NAME not in "".join(__import__("traceback").format_exception(failure.value))


# --------------------------------------------------------------------------------------------
# L2: a FHIR audit row never stores what the client typed, unless it is an id this portal issues
# --------------------------------------------------------------------------------------------


def fhir_read_ids(app) -> list[str | None]:
    with app.state.session_factory() as session:
        rows = session.scalars(
            select(PatientPortalAuditEvent)
            .where(PatientPortalAuditEvent.event_type.like("fhir.%"))
            .order_by(PatientPortalAuditEvent.id)
        )
        return [row.resource_id for row in rows]


def test_a_name_pasted_into_a_fhir_url_or_search_never_reaches_the_audit_row() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    headers = bearer_headers(sign_in_patient_api_session(client))

    typed = [
        "Jane-Fake-Doe",
        "ABCD12345678",  # shaped like a health card number
        "portal-Jane-Fake-Doe",  # starts like an issued id
        "portal-" + "G" * 56,  # the right length, not hex
        "007",  # a number with a leading zero is not a number this portal issues
        "9" * 20,  # one digit too many
    ]
    for value in typed:
        for path in (
            f"/fhir/Patient/{value}",
            f"/fhir/Practitioner/{value}",
            f"/fhir/Organization/{value}",
            f"/fhir/DocumentReference/{value}",
            f"/fhir/Patient?_id={value}",
            f"/fhir/DocumentReference?_id={value}",
        ):
            client.get(path, headers=headers)

    stored = fhir_read_ids(app)
    assert UNRECOGNIZED_AUDIT_RESOURCE_ID in stored, "the probes must have left their trace"
    # Every row is the marker or an id the portal itself issued (a search that found the
    # patient's own record names it), never what was typed.
    assert all(
        row == UNRECOGNIZED_AUDIT_RESOURCE_ID or ISSUED_FHIR_ID.fullmatch(row or "")
        for row in stored
    ), set(stored)
    for value in typed:
        assert all(value not in (row or "") for row in stored)


def test_an_id_this_portal_issues_is_still_stored_as_it_was_asked_for() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    activate_seeded_patient_account(app, client)
    headers = bearer_headers(sign_in_patient_api_session(client))
    patient_id = build_fhir_patient_id("default", 1234)

    client.get(f"/fhir/Patient?_id={patient_id}", headers=headers)
    client.get("/fhir/DocumentReference/999999", headers=headers)  # a number nobody holds

    assert fhir_read_ids(app) == [patient_id, "999999"]


# --------------------------------------------------------------------------------------------
# L5 and L6: the body is counted as it arrives
# --------------------------------------------------------------------------------------------


class Exchange:
    """One request driven straight into an ASGI app, counting the chunks it asks the client for."""

    def __init__(self, status: int | None, headers: dict[str, str], body: bytes, served: int):
        self.status = status
        self.headers = headers
        self.body = body
        self.served = served


def call(
    app,
    path: str,
    *,
    chunk_sizes,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    declare: bool = False,
) -> Exchange:
    """POST `path` with chunks of the given sizes. `declare` also sends the total as its length."""
    chunks = [b"x" * size for size in chunk_sizes]
    request_headers = {"host": "testserver", **(headers or {})}
    if declare:
        request_headers["content-length"] = str(sum(chunk_sizes))
    state = {"served": 0, "status": None, "headers": {}, "body": b""}

    async def run() -> None:
        index = 0
        finished = anyio.Event()

        async def receive():
            nonlocal index
            if index < len(chunks):
                chunk = chunks[index]
                index += 1
                state["served"] += 1
                return {"type": "http.request", "body": chunk, "more_body": True}
            if index == len(chunks):
                index += 1
                return {"type": "http.request", "body": b"", "more_body": False}
            await finished.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.start":
                state["status"] = message["status"]
                state["headers"] = {
                    key.decode().lower(): value.decode() for key, value in message["headers"]
                }
            elif message["type"] == "http.response.body":
                state["body"] += message.get("body", b"")
                if not message.get("more_body", False):
                    finished.set()

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": [(k.encode(), v.encode()) for k, v in request_headers.items()],
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 80),
        }
        await app(scope, receive, send)

    anyio.run(run)
    return Exchange(state["status"], state["headers"], state["body"], state["served"])


KIB = 1024
INTERNAL_PATH = "/internal/carlos/patients/1234/invites/prepare"
DELIVERY_PATH = "/internal/carlos/patients/1234/mycarlos/deliveries"


def test_the_limit_is_chosen_from_the_largest_real_staff_or_job_request() -> None:
    from carlos_patient_portal.internal_routes import (
        MAX_CLINIC_KEY_TEXT_LENGTH,
        MAX_PUBLISHED_CLINIC_KEYS,
    )

    entry = {
        "kid": "k" * 43,
        "spki": "s" * MAX_CLINIC_KEY_TEXT_LENGTH,
        "status": "revoked",
        "replaces_kid": "r" * 43,
        "replacement_signature": "g" * MAX_CLINIC_KEY_TEXT_LENGTH,
    }
    largest = len(
        json.dumps({"keys": [entry] * MAX_PUBLISHED_CLINIC_KEYS}, separators=(",", ":")).encode()
    )
    # It fits with room to spare, and is not so large that it stops being a limit.
    assert largest < INTERNAL_BODY_LIMIT <= 4 * largest


def test_only_the_staff_and_job_api_is_capped_and_a_sealed_delivery_has_its_own_limit() -> None:
    assert internal_body_limit("/portal/messages") is None
    assert internal_body_limit("/api/mycarlos/link") is None
    assert internal_body_limit(INTERNAL_PATH) == INTERNAL_BODY_LIMIT
    assert internal_body_limit("/internal/carlos/patients/1234/invites") == INTERNAL_BODY_LIMIT
    assert internal_body_limit(DELIVERY_PATH) == MAX_UPLOAD
    # Only that one route: neighbours and prefixes of it keep the ordinary limit.
    assert internal_body_limit(DELIVERY_PATH + "/extra") == INTERNAL_BODY_LIMIT
    assert internal_body_limit("/internal/carlos/patients/1234/mycarlos") == INTERNAL_BODY_LIMIT


def test_an_unauthenticated_body_over_the_limit_is_refused_after_reading_only_the_limit() -> None:
    app = internal_app()
    chunk = 8 * KIB
    # 1000 chunks of 8 KiB (8 MiB, the most nginx lets through), no declared length.
    result = call(app, INTERNAL_PATH, chunk_sizes=[chunk] * 1000)

    assert result.status == 413
    assert json.loads(result.body) == {"detail": "request too large"}
    # Counted as it arrived: the application was given the first chunks and then nothing.
    assert result.served <= INTERNAL_BODY_LIMIT // chunk + 1
    # It passed through the security headers like any other answer.
    assert result.headers["cache-control"] == "no-store"
    assert "x-request-id" in result.headers


def test_a_declared_length_over_the_limit_is_refused_without_reading_any_of_it() -> None:
    app = internal_app()
    result = call(app, INTERNAL_PATH, chunk_sizes=[8 * KIB] * 100, declare=True)

    assert result.status == 413
    assert result.served == 0


def test_a_body_of_exactly_the_limit_is_read_and_one_byte_more_is_not() -> None:
    app = internal_app()
    exactly = call(app, INTERNAL_PATH, chunk_sizes=[INTERNAL_BODY_LIMIT])
    exactly_declared = call(app, INTERNAL_PATH, chunk_sizes=[INTERNAL_BODY_LIMIT], declare=True)
    one_more = call(app, INTERNAL_PATH, chunk_sizes=[INTERNAL_BODY_LIMIT, 1])
    one_more_declared = call(
        app, INTERNAL_PATH, chunk_sizes=[INTERNAL_BODY_LIMIT + 1], declare=True
    )

    # Within the limit it reaches the route, which refuses an unknown caller as it always did.
    assert exactly.status == exactly_declared.status == 404
    assert one_more.status == one_more_declared.status == 413


def test_a_sealed_delivery_may_be_far_larger_than_the_ordinary_limit() -> None:
    app = link_app()  # the sealed-delivery routes exist only with the delivery switch on
    result = call(app, DELIVERY_PATH, chunk_sizes=[64 * KIB] * 4, declare=True)

    # Four times the ordinary limit still reaches the route (and its caller's authentication).
    assert result.status == 404


def test_a_chunked_device_link_body_stops_being_read_at_its_limit() -> None:
    from carlos_patient_portal.routes.mycarlos import MAX_LINK_BODY_BYTES

    app = link_app()
    headers = {"content-type": "application/json", "x-mycarlos-device-assertion": "x.y"}
    chunk = KIB
    result = call(app, LINK_PATH, chunk_sizes=[chunk] * 1000, headers=headers)

    assert result.status == 413
    assert json.loads(result.body) == {"detail": "request too large"}
    assert result.served <= MAX_LINK_BODY_BYTES // chunk + 1


def test_a_device_link_body_of_exactly_its_limit_is_read_and_one_byte_more_is_not() -> None:
    from carlos_patient_portal.routes.mycarlos import MAX_LINK_BODY_BYTES

    app = link_app()
    headers = {"content-type": "application/json", "x-mycarlos-device-assertion": "x.y"}
    exactly = call(app, LINK_PATH, chunk_sizes=[MAX_LINK_BODY_BYTES], headers=headers)
    one_more = call(app, LINK_PATH, chunk_sizes=[MAX_LINK_BODY_BYTES, 1], headers=headers)

    assert exactly.status != 413
    assert one_more.status == 413


def test_the_middleware_ignores_anything_that_is_not_an_http_request() -> None:
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    middleware = BodyLimitMiddleware(app)
    anyio.run(middleware, {"type": "lifespan"}, None, None)

    assert seen == ["lifespan"]
    assert body_limit.INTERNAL_PATH_PREFIX == "/internal/"
