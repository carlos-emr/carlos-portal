# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The iPhone push settings and the wiring from them to the outbox worker (piece 7): the settings
validator, `availability_dispatch_for`, the start-up refusal in `create_app`, and the 403 reaction.
Every key here is made by the test and FAKE; nothing touches the network."""

from __future__ import annotations

import logging
import os
from base64 import urlsafe_b64encode
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import sessionmaker

from carlos_patient_portal import mycarlos_apns_wiring as wiring
from carlos_patient_portal.apns_provider import ApnsKeyError, ApnsProviderJwtSigner
from carlos_patient_portal.config import Settings
from carlos_patient_portal.main import create_app
from carlos_patient_portal.mycarlos_availability import GenericNotice, ProviderResult, PushPlatform
from carlos_patient_portal.mycarlos_availability_dispatch import AvailabilityDispatch
from tests.notification_transports_support import RecordingHttpClient
from tests.test_apns_provider import KEY_ID, NOW, TEAM, TOKEN, write_key

DESTINATION = UUID(int=0xB7)
NOTICE = GenericNotice("B" * 22)
OUTBOX_SECRET = "FAKE outbox secret for the push wiring tests, 40+ characters long"
NOTICE_KEY = urlsafe_b64encode(b"\x07" * 32).decode()


def push_settings(key_path: Path | None, **changes: object) -> Settings:
    values: dict[str, object] = {
        "environment": "development",
        "clinic_id": "clinic-a",
        "clinic_name": "Clinic A",
        "database_url": "sqlite+pysqlite:///:memory:",
        "public_base_url": "https://portal.example.test",
        "mycarlos_delivery_enabled": True,
        "mycarlos_mailbox_enabled": True,
        "mycarlos_availability_enabled": True,
        "mycarlos_apns_enabled": True,
        "mycarlos_apns_team_id": TEAM,
        "mycarlos_apns_key_id": KEY_ID,
        "mycarlos_apns_key_path": key_path,
        "mycarlos_apns_bundle_id": "ca.example.fake",
        "mycarlos_notice_token_key": NOTICE_KEY,
        "outbox_encryption_secret": OUTBOX_SECRET,
        **changes,
    }
    return Settings(**values)


def good_key(tmp_path: Path) -> Path:
    return write_key(tmp_path / "AuthKey_FAKEKEYID1.p8")


def sessions() -> sessionmaker:
    return sessionmaker()


# --- the settings validator ---------------------------------------------------------------------


def test_push_off_needs_none_of_the_settings() -> None:
    settings = push_settings(None, mycarlos_apns_enabled=False, mycarlos_apns_team_id=None)
    assert settings.mycarlos_apns_enabled is False


def test_push_on_with_everything_present_is_accepted(tmp_path: Path) -> None:
    assert push_settings(good_key(tmp_path)).mycarlos_apns_enabled is True


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"mycarlos_apns_team_id": None}, "TEAM_ID is required"),
        ({"mycarlos_apns_key_id": None}, "KEY_ID is required"),
        ({"mycarlos_apns_bundle_id": None}, "BUNDLE_ID is required"),
        ({"mycarlos_apns_team_id": ""}, "TEAM_ID is required"),
        ({"mycarlos_apns_key_path": Path("relative/AuthKey.p8")}, "absolute path"),
        ({"mycarlos_apns_key_path": None}, "absolute path"),
        ({"outbox_encryption_secret": None}, "outbox encryption"),
        ({"mycarlos_notice_token_key": None}, "NOTICE_TOKEN_KEY"),
        ({"mycarlos_notice_token_key": urlsafe_b64encode(b"\x01" * 31).decode()}, "32 bytes"),
        ({"mycarlos_notice_token_key": "not base64 !!"}, "32 bytes"),
        ({"mycarlos_delivery_enabled": False}, "delivery, mailbox and availability"),
        ({"mycarlos_mailbox_enabled": False}, "delivery, mailbox and availability"),
        ({"mycarlos_availability_enabled": False}, "delivery, mailbox and availability"),
    ],
)
def test_push_on_refuses_what_is_missing_or_malformed(
    tmp_path: Path, changes: dict[str, object], message: str
) -> None:
    key = changes.pop("_key", good_key(tmp_path))
    if "mycarlos_apns_key_path" not in changes:
        changes["mycarlos_apns_key_path"] = key
    with pytest.raises((ValidationError, ValueError)) as raised:
        push_settings(None, **changes)
    assert message in str(raised.value)
    # The error names the setting, never a value.
    assert OUTBOX_SECRET not in str(raised.value)
    assert NOTICE_KEY not in str(raised.value)


# --- availability_dispatch_for ------------------------------------------------------------------


def test_off_gives_no_dispatch(tmp_path: Path) -> None:
    settings = push_settings(good_key(tmp_path), mycarlos_apns_enabled=False)
    assert wiring.availability_dispatch_for(settings, sessions(), RecordingHttpClient()) is None


def test_on_without_an_http_client_refuses_with_a_fixed_code(tmp_path: Path) -> None:
    with pytest.raises(ApnsKeyError) as raised:
        wiring.availability_dispatch_for(push_settings(good_key(tmp_path)), sessions(), None)
    assert raised.value.code == "apns_http_client_unavailable"


def test_on_with_a_key_anyone_can_read_refuses(tmp_path: Path) -> None:
    key = write_key(tmp_path / "AuthKey_FAKEKEYID1.p8", mode=0o644)
    with pytest.raises(ApnsKeyError) as raised:
        wiring.availability_dispatch_for(push_settings(key), sessions(), RecordingHttpClient())
    assert raised.value.code == "apns_key_permissions_too_open"
    assert str(key) not in repr(raised.value)


def test_on_with_a_good_key_and_a_client_gives_an_iphone_dispatch(tmp_path: Path) -> None:
    dispatch = wiring.availability_dispatch_for(
        push_settings(good_key(tmp_path)), sessions(), RecordingHttpClient(), clock=lambda: NOW
    )
    assert isinstance(dispatch, AvailabilityDispatch)
    assert set(dispatch.transports) == {PushPlatform.IOS_APNS}
    assert "FAKE" not in repr(dispatch)


def test_create_app_with_push_on_and_no_http_client_stops_at_startup(tmp_path: Path) -> None:
    with pytest.raises(ApnsKeyError) as raised:
        create_app(push_settings(good_key(tmp_path)), apns_http_client=None)
    assert raised.value.code == "apns_http_client_unavailable"


# --- a 403 from Apple ---------------------------------------------------------------------------


class _Handles:
    """Stands in for the SQL lookup: one destination, one token, sandbox."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def handle_for(self, destination_id: UUID) -> str | None:
        return TOKEN if destination_id == DESTINATION else None

    def environment_for(self, destination_id: UUID) -> str | None:
        return "sandbox" if destination_id == DESTINATION else None


def _send(transport, http: RecordingHttpClient) -> ProviderResult:  # noqa: ANN001
    return transport.send(
        destination_id=DESTINATION,
        platform=PushPlatform.IOS_APNS,
        notice=NOTICE,
        ttl_seconds=3600,
        collapse_key="c" * 20,
    )


def test_a_403_is_a_permanent_failure_that_is_reported_and_drops_the_cached_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(wiring, "SqlDestinationHandles", _Handles)
    clock_now = [NOW]
    http = RecordingHttpClient(403, 200)
    failures: list[str] = []
    dispatch = wiring.availability_dispatch_for(
        push_settings(good_key(tmp_path)),
        sessions(),
        http,
        clock=lambda: clock_now[0],
        record_failure=failures.append,
    )
    transport = dispatch.transports[PushPlatform.IOS_APNS]
    with caplog.at_level(logging.ERROR, logger="carlos_patient_portal.mycarlos_apns_wiring"):
        assert _send(transport, http) is ProviderResult.PERMANENT_FAILURE
    # Visible to operations as one class-only category, in the log and the failure counters.
    assert failures == ["apns_auth_rejected"]
    assert "apns_auth_rejected" in caplog.text
    assert TOKEN not in caplog.text
    assert TEAM not in caplog.text
    assert KEY_ID not in caplog.text
    # The next push signs a fresh provider token even though the first is well inside 45 minutes
    # (the clock moved one second, so a cached token would be the same text).
    clock_now[0] += 1
    assert _send(transport, http) is ProviderResult.ACCEPTED
    first, second = (r.headers["authorization"] for r in http.requests)
    assert first != second
    assert failures == ["apns_auth_rejected"]


def test_invalidate_makes_the_signer_sign_again(tmp_path: Path) -> None:
    from carlos_patient_portal.notification_transports import ApnsConfig

    config = ApnsConfig(TEAM, KEY_ID, good_key(tmp_path), "ca.example.fake")
    signed: list[int] = []
    signer = ApnsProviderJwtSigner(config, lambda: NOW)
    original = signer._sign

    def counting(issued_at: int) -> str:
        signed.append(issued_at)
        return original(issued_at)

    signer._sign = counting  # type: ignore[method-assign]
    signer.provider_token()
    signer.provider_token()
    assert len(signed) == 1
    signer.invalidate()
    signer.provider_token()
    assert len(signed) == 2


def test_other_4xx_answers_are_permanent_and_are_not_reported_as_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(wiring, "SqlDestinationHandles", _Handles)
    failures: list[str] = []
    http = RecordingHttpClient(400)
    dispatch = wiring.availability_dispatch_for(
        push_settings(good_key(tmp_path)),
        sessions(),
        http,
        clock=lambda: NOW,
        record_failure=failures.append,
    )
    transport = dispatch.transports[PushPlatform.IOS_APNS]
    assert _send(transport, http) is ProviderResult.PERMANENT_FAILURE
    assert failures == []


def test_a_clock_that_returns_a_float_still_gives_an_integer_iat(tmp_path: Path) -> None:
    import base64
    import json

    from carlos_patient_portal.notification_transports import ApnsConfig

    config = ApnsConfig(TEAM, KEY_ID, good_key(tmp_path), "ca.example.fake")
    token = ApnsProviderJwtSigner(config, lambda: float(NOW) + 0.75).provider_token()  # type: ignore[arg-type,return-value]
    claims = token.split(".")[1]
    decoded = json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))
    assert decoded["iat"] == NOW
    assert type(decoded["iat"]) is int


# --- the key file is opened as the file that was checked ----------------------------------------


def test_a_link_to_the_key_is_refused_even_when_the_target_is_a_good_key(tmp_path: Path) -> None:
    from carlos_patient_portal.notification_transports import ApnsConfig

    target = write_key(tmp_path / "real.p8")
    link = tmp_path / "AuthKey_FAKEKEYID1.p8"
    link.symlink_to(target)
    with pytest.raises(ApnsKeyError) as raised:
        ApnsProviderJwtSigner(ApnsConfig(TEAM, KEY_ID, link, "ca.example.fake"), lambda: NOW)
    assert raised.value.code == "apns_key_not_a_regular_file"


def test_a_key_owned_by_someone_else_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from carlos_patient_portal import apns_provider
    from carlos_patient_portal.notification_transports import ApnsConfig

    key = good_key(tmp_path)
    real_uid = os.geteuid()
    monkeypatch.setattr(apns_provider.os, "geteuid", lambda: real_uid + 1)
    with pytest.raises(ApnsKeyError) as raised:
        apns_provider.check_apns_key_file(ApnsConfig(TEAM, KEY_ID, key, "ca.example.fake"))
    assert raised.value.code == "apns_key_wrong_owner"


def _code_within_seconds(path: Path) -> str:
    """The start-up check on a path that could block, on a thread, so a regression fails."""
    import threading

    from carlos_patient_portal.notification_transports import ApnsConfig

    outcome: list[str] = []

    def run() -> None:
        try:
            ApnsProviderJwtSigner(ApnsConfig(TEAM, KEY_ID, path, "ca.example.fake"), lambda: NOW)
        except ApnsKeyError as error:
            outcome.append(error.code)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive(), "the key check blocked on a special file"
    return outcome[0]


def test_a_fifo_with_no_writer_is_refused_and_does_not_hang_start_up(tmp_path: Path) -> None:
    fifo = tmp_path / "AuthKey_FAKEKEYID1.p8"
    os.mkfifo(fifo, 0o600)
    assert _code_within_seconds(fifo) == "apns_key_not_a_regular_file"


def test_a_character_device_is_refused_as_not_a_regular_file() -> None:
    assert _code_within_seconds(Path("/dev/null")) == "apns_key_not_a_regular_file"


def test_a_key_read_in_short_pieces_is_still_read_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from carlos_patient_portal import apns_provider
    from carlos_patient_portal.notification_transports import ApnsConfig

    key = good_key(tmp_path)
    real_read = os.read
    monkeypatch.setattr(apns_provider.os, "read", lambda fd, n: real_read(fd, min(n, 37)))
    ApnsProviderJwtSigner(ApnsConfig(TEAM, KEY_ID, key, "ca.example.fake"), lambda: NOW)
