import asyncio
import json
import logging

import h11
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from uvicorn.protocols.http.flow_control import FlowControl
from uvicorn.protocols.http.h11_impl import RequestResponseCycle

from carlos_patient_portal.web_support import SERVICE_UNAVAILABLE_DETAIL
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    migrated_development_app,
)


class MemoryTransport(asyncio.Transport):
    def __init__(self):
        super().__init__()
        self.output = []
        self.closed = False

    def write(self, data):
        self.output.append(data)

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed


@pytest.mark.parametrize(
    ("fault", "expected_status", "exception_type"),
    [("integrity", 500, IntegrityError), ("operational", 503, OperationalError)],
)
def test_database_error_details_stay_out_of_uvicorn_logs_after_safe_application_response(
    fault, expected_status, exception_type, caplog: pytest.LogCaptureFixture
) -> None:
    app = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    engine = app.state.database_engine
    marker = "FAKE-private-database-binding-9e1f"
    failures = []
    path = "/FAKE/database-error"
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE fake_log_source (value TEXT UNIQUE NOT NULL)"))
        connection.execute(
            text("INSERT INTO fake_log_source (value) VALUES (:value)"), {"value": marker}
        )

    @app.get(path, include_in_schema=False)
    def private_fixture_fault():
        try:
            with app.state.session_factory() as session, session.begin():
                statement = (
                    "INSERT INTO fake_log_source (value) VALUES (:value)"
                    if fault == "integrity"
                    else "SELECT value FROM fake_missing_source WHERE value = :value"
                )
                session.execute(text(statement), {"value": marker})
        except SQLAlchemyError as exc:
            assert isinstance(exc, exception_type)
            assert marker in str(exc)
            failures.append(type(exc).__name__)
            raise

    async def request_over_memory():
        client_protocol = h11.Connection(h11.CLIENT)
        request = h11.Request(
            method=b"GET", target=path.encode(), headers=[(b"host", b"testserver")]
        )
        wire = client_protocol.send(request) + client_protocol.send(h11.EndOfMessage())
        server_protocol = h11.Connection(h11.SERVER)
        server_protocol.receive_data(wire)
        assert isinstance(server_protocol.next_event(), h11.Request)
        assert isinstance(server_protocol.next_event(), h11.EndOfMessage)
        transport = MemoryTransport()
        message_event = asyncio.Event()
        cycle = RequestResponseCycle(
            scope={
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.3"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": path,
                "raw_path": path.encode(),
                "root_path": "",
                "query_string": b"",
                "headers": [(b"host", b"testserver")],
                "client": ("127.0.0.1", 12345),
                "server": ("testserver", 80),
                "state": {},
            },
            conn=server_protocol,
            transport=transport,
            flow=FlowControl(transport),
            logger=logging.getLogger("uvicorn.error"),
            access_logger=logging.getLogger("uvicorn.access"),
            access_log=False,
            default_headers=[],
            message_event=message_event,
            on_response=lambda: None,
        )
        cycle.more_body = False
        message_event.set()
        await asyncio.wait_for(cycle.run_asgi(app), timeout=10)
        assert cycle.response_started and cycle.response_complete
        client_protocol.receive_data(b"".join(transport.output))
        response = client_protocol.next_event()
        assert isinstance(response, h11.Response)
        body = bytearray()
        while True:
            event = client_protocol.next_event()
            if isinstance(event, h11.EndOfMessage):
                break
            assert isinstance(event, h11.Data)
            body.extend(event.data)
        return response.status_code, dict(response.headers), bytes(body)

    caplog.set_level(logging.WARNING)
    try:
        response_status, response_headers, body = asyncio.run(request_over_memory())
        assert failures == [exception_type.__name__]
        assert response_status == expected_status
        assert json.loads(body) == {
            "detail": "the request could not be completed"
            if fault == "integrity"
            else SERVICE_UNAVAILABLE_DETAIL
        }
        assert marker not in body.decode()
        if fault == "operational":
            assert response_headers[b"retry-after"] == b"1"
        failure_signal = "unhandled_exception" if fault == "integrity" else "database"
        assert app.state.operational_metrics.snapshot()["failures"][failure_signal] == 1
        app_logs = [
            record for record in caplog.records if record.name == "carlos_patient_portal.main"
        ]
        assert any(exception_type.__name__ in record.getMessage() for record in app_logs)
        assert all(record.exc_info is None for record in app_logs)
        assert marker not in caplog.text
    finally:
        engine.dispose()
