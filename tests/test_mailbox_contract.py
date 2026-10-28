# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Affero General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

"""Shared M4 bytes against the real transport parser; no database/HPKE completion claim."""

import hashlib
import json
from pathlib import Path

import pytest

from carlos_patient_portal.mailbox_codec import (
    MAX_SEALED,
    MAX_UPLOAD,
    MailboxRefusal,
    cursor,
    json_bytes,
    parse_ack,
    parse_upload,
)
from carlos_patient_portal.staff_identity import staff_request_hash

FIXTURE = json.loads((Path(__file__).parent / "fixtures/mailbox-contract-v1.json").read_bytes())


def test_frozen_source_contract_and_unchanged_m0_fixture():
    assert (
        FIXTURE["frozen_contract_sha256"]
        == "d01777267371530ea49654eb183a5c845c503ea5bf2259c42f7de43c4e9c1148"
    )
    assert (
        hashlib.sha256(
            (Path(__file__).parent / "fixtures/delivery-contract.json").read_bytes()
        ).hexdigest()
        == FIXTURE["m0_sha256"]
    )


@pytest.mark.parametrize("vector", FIXTURE["uploads"], ids=lambda value: value["name"])
def test_exact_shared_upload_bytes(vector):
    body = bytes.fromhex(vector["body"]["hex"])
    assert hashlib.sha256(body).hexdigest() == vector["body"]["sha256"]
    if vector["expect"] == "accept":
        parsed = parse_upload(body)
        assert parsed.outer == vector["outer"]
        assert parsed.body_sha256 == vector["body"]["sha256"]
    else:
        with pytest.raises(MailboxRefusal) as failure:
            parse_upload(body)
        assert failure.value.code == vector["expect"]


@pytest.mark.parametrize("vector", FIXTURE["request_hashes"], ids=lambda value: value["name"])
def test_full_binary_body_and_external_raw_path_query_are_bound(vector):
    assert (
        staff_request_hash(
            vector["method"],
            bytes.fromhex(vector["raw_path_hex"]),
            bytes.fromhex(vector["raw_query_hex"]),
            bytes.fromhex(vector["body"]["hex"]),
        )
        == vector["request_hash"]
    )


@pytest.mark.parametrize("vector", FIXTURE["cursors"])
def test_shared_cursor_primitive_types(vector):
    if vector["expect"] == "accept":
        assert str(cursor(vector["text"])) == vector["text"]
    else:
        with pytest.raises(MailboxRefusal, match="invalid_cursor"):
            cursor(vector["text"])


@pytest.mark.parametrize("vector", FIXTURE["ack_bodies"])
def test_shared_ack_original_bytes(vector):
    body = bytes.fromhex(vector["body"]["hex"])
    if vector["expect"] == "accept":
        assert parse_ack(body) == 7
    else:
        with pytest.raises(MailboxRefusal, match="invalid_cursor"):
            parse_ack(body)


def test_actual_maximum_sealed_and_outer_byte_bounds():
    outer = dict(FIXTURE["uploads"][0]["outer"])
    sealed = b"\xa5" * MAX_SEALED
    outer.update(size=len(sealed), ciphertext_sha256=hashlib.sha256(sealed).hexdigest())
    raw = json_bytes(outer)
    raw += b" " * (4096 - len(raw))
    body = len(raw).to_bytes(8, "big") + raw + len(sealed).to_bytes(8, "big") + sealed
    assert len(body) == MAX_UPLOAD
    parsed = parse_upload(body)
    assert len(parsed.sealed) == MAX_SEALED and parsed.outer == outer
    with pytest.raises(MailboxRefusal) as failure:
        parse_upload(body + b"x")
    assert failure.value.status == 413
    bad_outer = (4097).to_bytes(8, "big") + raw + b" " + len(sealed).to_bytes(8, "big") + sealed
    with pytest.raises(MailboxRefusal):
        parse_upload(bad_outer)
