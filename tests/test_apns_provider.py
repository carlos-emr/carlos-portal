# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The Apple key behind the iPhone push: the start-up check, the ES256 signer, the host by
environment and the status rules (iPhone push, piece 7). Every key here is made by the test and
is FAKE; nothing touches the network."""

from __future__ import annotations

import base64
import json
import threading
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from carlos_patient_portal import apns_provider as ap
from carlos_patient_portal.mycarlos_availability import (
    GenericNotice,
    ProviderResult,
    PushPlatform,
    TransportFailure,
)
from carlos_patient_portal.notification_transports import (
    APNS_PRODUCTION_HOST,
    APNS_SANDBOX_HOST,
    ApnsConfig,
    ApnsTokenTransport,
)
from tests.notification_transports_support import FixedHandles, FixedToken, RecordingHttpClient

TEAM = "FAKETEAM01"
KEY_ID = "FAKEKEYID1"
NOW = 1_793_900_000
DESTINATION = UUID(int=0xA5)
TOKEN = "ab" * 32
NOTICE = GenericNotice("A" * 22)


def write_key(path: Path, key=None, *, mode: int = 0o600) -> Path:  # noqa: ANN001
    key = key or ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(mode)
    return path


def config(path: Path, *, team: str = TEAM, key_id: str = KEY_ID) -> ApnsConfig:
    return ApnsConfig(team, key_id, path, "ca.example.fake")


def code_of(path: Path, **changes: str) -> str:
    with pytest.raises(ap.ApnsKeyError) as raised:
        ap.check_apns_key_file(config(path, **changes))
    # Only the fixed code: never the path, a value or key bytes.
    assert str(raised.value) == raised.value.code
    assert str(path) not in repr(raised.value)
    return raised.value.code


# --- the start-up check --------------------------------------------------------------------------


def test_a_private_p256_key_only_its_owner_can_read_passes(tmp_path: Path) -> None:
    ap.check_apns_key_file(config(write_key(tmp_path / "AuthKey.p8")))


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660, 0o666, 0o707])
def test_a_key_others_can_read_or_write_is_refused(tmp_path: Path, mode: int) -> None:
    assert code_of(write_key(tmp_path / "k.p8", mode=mode)) == "apns_key_permissions_too_open"


def test_a_missing_key_a_folder_a_link_and_an_empty_or_huge_file_are_refused(
    tmp_path: Path,
) -> None:
    assert code_of(tmp_path / "absent.p8") == "apns_key_missing"
    assert code_of(tmp_path) == "apns_key_not_a_regular_file"
    real = write_key(tmp_path / "real.p8")
    link = tmp_path / "link.p8"
    link.symlink_to(real)
    assert code_of(link) == "apns_key_not_a_regular_file"
    empty = tmp_path / "empty.p8"
    empty.write_bytes(b"")
    empty.chmod(0o600)
    assert code_of(empty) == "apns_key_size"
    huge = tmp_path / "huge.p8"
    huge.write_bytes(b"x" * (ap.MAX_KEY_FILE_BYTES + 1))
    huge.chmod(0o600)
    assert code_of(huge) == "apns_key_size"


def test_a_file_that_is_not_an_ec_p256_private_key_is_refused(tmp_path: Path) -> None:
    garbage = tmp_path / "garbage.p8"
    garbage.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n")
    garbage.chmod(0o600)
    assert code_of(garbage) == "apns_key_invalid"
    assert code_of(write_key(tmp_path / "rsa.p8", rsa.generate_private_key(65537, 2048))) == (
        "apns_key_invalid"
    )
    assert code_of(write_key(tmp_path / "p384.p8", ec.generate_private_key(ec.SECP384R1()))) == (
        "apns_key_invalid"
    )
    # A public key is not a private key.
    public = tmp_path / "public.p8"
    public.write_bytes(
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    public.chmod(0o600)
    assert code_of(public) == "apns_key_invalid"
    # An encrypted key cannot be read without a password and is not accepted.
    encrypted = tmp_path / "encrypted.p8"
    encrypted.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"FAKE password"),
        )
    )
    encrypted.chmod(0o600)
    assert code_of(encrypted) == "apns_key_invalid"


@pytest.mark.parametrize("team", ["faketeam01", "SHORT", "FAKETEAM012", "FAKETEAM-1", "FAKE.TEAM1"])
def test_a_team_id_that_is_not_ten_apple_characters_is_refused(tmp_path: Path, team: str) -> None:
    assert code_of(write_key(tmp_path / "k.p8"), team=team) == "apns_team_id_invalid"


@pytest.mark.parametrize(
    "key_id", ["fakekeyid1", "SHORT", "FAKEKEYID12", "FAKEKEYID_", "FAKE-KEYID"]
)
def test_a_key_id_that_is_not_ten_apple_characters_is_refused(tmp_path: Path, key_id: str) -> None:
    assert code_of(write_key(tmp_path / "k.p8"), key_id=key_id) == "apns_key_id_invalid"


def test_ids_with_spaces_blanks_or_symbols_never_reach_the_check(tmp_path: Path) -> None:
    # `ApnsConfig` itself refuses them, before any file is looked at.
    for bad in ("FAKE TEAM1", "", "FAKETEAM0!", "T" * 200):
        with pytest.raises(ValueError, match="invalid_apns_config"):
            config(tmp_path / "k.p8", team=bad)


# --- the signer ----------------------------------------------------------------------------------


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class Clock:
    def __init__(self, now: int = NOW) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


def test_the_token_is_an_es256_jwt_that_verifies_under_the_public_key(tmp_path: Path) -> None:
    private = ec.generate_private_key(ec.SECP256R1())
    signer = ap.ApnsProviderJwtSigner(config(write_key(tmp_path / "k.p8", private)), Clock())
    token = signer.provider_token()
    header, claims, signature = token.split(".")
    assert json.loads(b64url_decode(header)) == {"alg": "ES256", "kid": KEY_ID}
    assert json.loads(b64url_decode(claims)) == {"iss": TEAM, "iat": NOW}
    assert "=" not in token
    raw = b64url_decode(signature)
    assert len(raw) == 64  # JOSE: raw r || s, not DER
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    private.public_key().verify(der, f"{header}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))


def test_the_token_is_reused_for_45_minutes_and_then_made_again(tmp_path: Path) -> None:
    clock = Clock()
    signer = ap.ApnsProviderJwtSigner(config(write_key(tmp_path / "k.p8")), clock)
    first = signer.provider_token()
    clock.now = NOW + ap.TOKEN_REUSE_SECONDS - 1
    assert signer.provider_token() == first
    clock.now = NOW + ap.TOKEN_REUSE_SECONDS
    second = signer.provider_token()
    assert second != first
    assert json.loads(b64url_decode(second.split(".")[1]))["iat"] == NOW + ap.TOKEN_REUSE_SECONDS
    # Apple wants a token refreshed no more often than every 20 minutes and never older than 60.
    assert 20 * 60 < ap.TOKEN_REUSE_SECONDS < 60 * 60
    # A clock that went backwards does not keep an old token.
    clock.now = NOW
    assert json.loads(b64url_decode(signer.provider_token().split(".")[1]))["iat"] == NOW


def test_many_threads_get_the_same_token(tmp_path: Path) -> None:
    signer = ap.ApnsProviderJwtSigner(config(write_key(tmp_path / "k.p8")), Clock())
    results: list[str] = []
    threads = [
        threading.Thread(target=lambda: results.append(signer.provider_token())) for _ in range(16)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 16
    assert len(set(results)) == 1


def test_a_bad_key_stops_the_signer_at_construction_not_at_the_first_push(tmp_path: Path) -> None:
    with pytest.raises(ap.ApnsKeyError):
        ap.ApnsProviderJwtSigner(config(tmp_path / "absent.p8"), Clock())
    with pytest.raises(ap.ApnsKeyError):
        ap.ApnsProviderJwtSigner(config(write_key(tmp_path / "open.p8", mode=0o644)), Clock())


def test_the_signer_never_shows_its_key(tmp_path: Path) -> None:
    signer = ap.ApnsProviderJwtSigner(config(write_key(tmp_path / "k.p8")), Clock())
    assert repr(signer) == "ApnsProviderJwtSigner[REDACTED]"
    assert "PRIVATE" not in repr(signer) and str(tmp_path) not in repr(signer)


# --- the host follows the destination's environment ----------------------------------------------


class Environments:
    def __init__(self, table: dict[UUID, str]) -> None:
        self._table = table

    def environment_for(self, destination_id: UUID) -> str | None:
        return self._table.get(destination_id)


def transport(environments, *responses: int) -> tuple[ApnsTokenTransport, RecordingHttpClient]:  # noqa: ANN001
    http = RecordingHttpClient(*responses)
    return (
        ApnsTokenTransport(
            ApnsConfig(TEAM, KEY_ID, Path("/nonexistent/fake.p8"), "ca.example.fake"),
            http,
            FixedHandles({DESTINATION: TOKEN}),
            FixedToken(),
            lambda: NOW,
            environments,
        ),
        http,
    )


def send(t: ApnsTokenTransport) -> ProviderResult:
    return t.send(
        destination_id=DESTINATION,
        platform=PushPlatform.IOS_APNS,
        notice=NOTICE,
        ttl_seconds=600,
        collapse_key="c" * 22,
    )


@pytest.mark.parametrize(
    ("environment", "host"),
    [("sandbox", APNS_SANDBOX_HOST), ("production", APNS_PRODUCTION_HOST)],
)
def test_a_token_goes_to_the_host_of_its_own_environment(environment: str, host: str) -> None:
    t, http = transport(Environments({DESTINATION: environment}), 200)
    assert send(t) is ProviderResult.ACCEPTED
    (request,) = http.requests
    assert request.url == f"{host}/3/device/{TOKEN}"


def test_an_unknown_environment_is_a_gone_destination_and_nothing_is_sent() -> None:
    for table in ({}, {DESTINATION: "staging"}, {DESTINATION: ""}):
        t, http = transport(Environments(table), 200)
        assert send(t) is ProviderResult.INVALID_DESTINATION
        assert http.requests == []


def test_without_an_environment_source_the_configured_host_is_used() -> None:
    t, http = transport(None, 200)
    send(t)
    assert http.requests[0].url.startswith(f"{APNS_PRODUCTION_HOST}/3/device/")


def test_the_alert_is_a_loc_key_and_the_opaque_token_only_with_the_fixed_headers() -> None:
    t, http = transport(Environments({DESTINATION: "sandbox"}), 200)
    send(t)
    (request,) = http.requests
    assert json.loads(request.body) == {
        "aps": {"alert": {"loc-key": "native-notice-arrival"}},
        "n": NOTICE.token,
    }
    headers = dict(request.headers)
    assert headers["apns-push-type"] == "alert"
    assert headers["apns-priority"] == "10"
    assert headers["apns-collapse-id"] == "c" * 22
    assert headers["apns-topic"] == "ca.example.fake"
    assert headers["apns-expiration"] == str(NOW + 600)
    assert b"myCarlos" not in request.body


@pytest.mark.parametrize(
    ("status", "result"),
    [
        (200, ProviderResult.ACCEPTED),
        (410, ProviderResult.INVALID_DESTINATION),
        (400, ProviderResult.PERMANENT_FAILURE),  # BadDeviceToken, DeviceTokenNotForTopic, ...
        (403, ProviderResult.PERMANENT_FAILURE),  # an expired or wrong provider token
        (404, ProviderResult.PERMANENT_FAILURE),
        (413, ProviderResult.PERMANENT_FAILURE),
    ],
)
def test_apns_statuses_map_to_the_portals_outcomes(status: int, result: ProviderResult) -> None:
    t, _http = transport(Environments({DESTINATION: "sandbox"}), status)
    assert send(t) is result


@pytest.mark.parametrize("status", [429, 500, 503])
def test_throttling_and_server_trouble_are_retried(status: int) -> None:
    t, _http = transport(Environments({DESTINATION: "sandbox"}), status)
    with pytest.raises(TransportFailure):
        send(t)
