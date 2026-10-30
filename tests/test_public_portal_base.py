# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
import pytest

from carlos_patient_portal.public_portal_base import normalize_portal


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://EXAMPLE.com:443/clinic/", "https://example.com/clinic"),
        ("https://bücher.example/a/%2e%2e/clinic", "https://xn--bcher-kva.example/clinic"),
        ("https://portal.example/é", "https://portal.example/%C3%A9"),
        ("https://portal.example", "https://portal.example"),
    ],
)
def test_matches_native_url_canonicalization(raw, expected):
    assert normalize_portal(raw) == expected
    assert normalize_portal(expected) == expected


@pytest.mark.parametrize(
    "raw",
    [
        " https://example.com",
        "http://example.com",
        "https://example.com/?",
        "https://u@example.com",
        "https://example.com/#x",
        "https://example.com/\\x",
        "https://example.com/" + "é" * 200,
    ],
)
def test_refuses_unsafe_or_expanded_portal_base(raw):
    with pytest.raises(ValueError):
        normalize_portal(raw)


def test_shared_qr_url_normalization_bytes_are_unchanged():
    import json
    from pathlib import Path

    fixture = json.loads((Path(__file__).parent / "fixtures/qr-link-v1.json").read_bytes())
    for vector in fixture["vectors"]:
        if "normalized_portal_url" not in vector:
            continue
        raw = json.loads(bytes.fromhex(vector["payload_hex"]))["portal_url"]
        assert normalize_portal(raw) == vector["normalized_portal_url"], vector["name"]


@pytest.mark.parametrize(
    "raw",
    [
        "https://portal.example/" + "/" * 1100,
        "https://portal.example\\clinic",
        " https://portal.example/",
    ],
)
def test_raw_configured_m3_base_is_validated_before_legacy_normalization(raw):
    from carlos_patient_portal.config import Settings

    with pytest.raises(ValueError):
        Settings(
            environment="development",
            mycarlos_delivery_enabled=True,
            mycarlos_mailbox_enabled=True,
            mycarlos_approval_enabled=True,
            public_base_url=raw,
        )
