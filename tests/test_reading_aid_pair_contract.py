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

"""The reading-aid pair contract (docs/architecture/mycarlos-delivery.md, "Reading aids"): every
vector in tests/fixtures/reading-aid-pair-contract.json gets exactly the listed outcome from the
reference receiver, an older (v1-only) receiver refuses an aid without filing it, the aid's manifest
has exactly the documented claims, and the portal's serve rule and CARLOS's staging rule follow the
link's accepted kinds. No runtime code is exercised: the portal has no reading-aid code yet."""

import json
from hashlib import sha256

import pytest

from tests import delivery_contract_reference as ref
from tests import reading_aid_pair_reference as aid

CONTRACT = json.loads(aid.FIXTURE_PATH.read_text(encoding="utf-8"))
DELIVERY = json.loads(ref.FIXTURE_PATH.read_text(encoding="utf-8"))
DEVICE = aid.DeviceKeys("device 1")
LINKS = CONTRACT["receiver"]["links"]
LINK = next(link for link in LINKS if link["name"] == CONTRACT["receiver"]["package_link"])


def _named(vectors: list[dict]) -> list:
    return [pytest.param(vector, id=vector["name"]) for vector in vectors]


def _open(vector: dict):
    if vector.get("receiver") == "v1_original_receiver":
        filed = {
            k: v["ciphertext_sha256"] for k, v in CONTRACT["receiver"]["filed_originals"].items()
        }
        outer = {k: v for k, v in vector["outer"].items() if k != "kind"}
        return ref.open_package(
            {"outer": outer, "blob": vector["blob"]},
            device=DEVICE,
            link=LINK,
            all_links=LINKS,
            filed=filed,
            now=vector["now"],
        )
    return aid.open_reading_aid(
        vector,
        device=DEVICE,
        link=LINK,
        all_links=LINKS,
        filed_originals=CONTRACT["receiver"]["filed_originals"],
        filed_aids=CONTRACT["receiver"]["filed_aids"],
        now=vector["now"],
        waiting_aids=CONTRACT["receiver"]["waiting_aids"],
    )


def test_fixture_is_exactly_what_the_reference_generates():
    assert aid.FIXTURE_PATH.read_text(encoding="utf-8") == aid.render(), (
        "regenerate with: python -m tests.reading_aid_pair_reference"
    )


def test_keys_are_the_delivery_contracts_keys():
    # Same seed texts, same FAKE keys: a device that passes the delivery vectors needs no new key.
    for name in ("clinic_a", "clinic_a_revoked", "unknown_clinic", "device", "other_device"):
        assert CONTRACT["keys"][name] == DELIVERY["keys"][name]
    assert CONTRACT["constants"]["hpke_info"] == DELIVERY["constants"]["hpke_info"]


def test_the_original_is_the_delivery_contracts_sender_example():
    sender = CONTRACT["sender"]
    assert sender["original_manifest_claims"] == DELIVERY["sender"]["manifest_claims"]
    assert sender["original_manifest"] == DELIVERY["sender"]["manifest"]
    assert (
        sender["manifest_claims"]["pair"]["original_delivery_id"]
        == DELIVERY["sender"]["manifest_claims"]["delivery_id"]
    )
    assert (
        sender["manifest_claims"]["pair"]["original_document_sha256"]
        == DELIVERY["sender"]["manifest_claims"]["document"]["sha256"]
    )


def test_aid_manifest_has_exactly_the_documented_claims():
    claims = CONTRACT["sender"]["manifest_claims"]
    assert set(claims) == aid.EXPECTED_CLAIMS
    assert claims["typ"] == aid.READING_AID_MANIFEST_TYPE and claims["v"] == 1
    assert set(claims["pair"]) == {"pair_id", "original_delivery_id", "original_document_sha256"}
    assert set(claims["reading_aid"]) == {
        "media_type",
        "size",
        "sha256",
        "language",
        "summary_version",
        "generated_at",
        "revised_at",
        "notice_version",
    }
    assert set(claims["approval"]) == {"id", "reviewer_role", "reviewed_at"}
    assert claims["reading_aid"]["media_type"] == aid.READING_AID_MEDIA_TYPE
    # The manifest never names a reviewer, a model or a patient identifier beyond the chart name.
    assert "reviewer_name" not in json.dumps(claims) and "model" not in claims["reading_aid"]
    assert claims["created_at"] == claims["expires_at"] - ref.MAX_DELIVERY_LIFETIME_SECONDS


def test_sender_example_is_the_first_accepted_package():
    sender = CONTRACT["sender"]
    aid_bytes = ref.b64url_decode(sender["reading_aid_b64url"])
    assert aid_bytes == ref.canonical_json(sender["reading_aid"])
    assert (
        sha256(aid_bytes).hexdigest()
        == sender["reading_aid_sha256"]
        == sender["manifest_claims"]["reading_aid"]["sha256"]
    )
    assert (
        len(aid_bytes)
        == sender["manifest_claims"]["reading_aid"]["size"]
        <= aid.MAX_READING_AID_BYTES
    )
    clinic = aid.ClinicKey("clinic-a signing key 1", ref.CLINIC_A)
    assert aid.compact_es256(clinic, sender["manifest_claims"]) == sender["manifest"]
    first = CONTRACT["packages"]["accept"][0]
    outcome, claims = _open(first)
    assert outcome == "file" and claims == sender["manifest_claims"]
    assert first["outer"]["kind"] == aid.READING_AID_KIND
    assert first["outer"]["size"] <= aid.MAX_READING_AID_CIPHERTEXT_BYTES


@pytest.mark.parametrize("vector", _named(CONTRACT["packages"]["accept"]))
def test_reference_receiver_accepts(vector):
    outcome, claims = _open(vector)
    assert outcome == vector["expect"]
    assert claims["delivery_id"] == vector["outer"]["delivery_id"]


@pytest.mark.parametrize("vector", _named(CONTRACT["packages"]["refuse"]))
def test_reference_receiver_refuses(vector):
    with pytest.raises(ref.Refused) as refused:
        _open(vector)
    assert refused.value.code == vector["expect"]


def test_an_older_receiver_refuses_every_reading_aid_copy_without_filing():
    # Every accepted aid, fed to the v1 original receiver, is bad_package: no document, no receipt.
    filed = {k: v["ciphertext_sha256"] for k, v in CONTRACT["receiver"]["filed_originals"].items()}
    for vector in CONTRACT["packages"]["accept"]:
        outer = {k: v for k, v in vector["outer"].items() if k != "kind"}
        with pytest.raises(ref.Refused) as refused:
            ref.open_package(
                {"outer": outer, "blob": vector["blob"]},
                device=DEVICE,
                link=LINK,
                all_links=LINKS,
                filed=filed,
                now=vector["now"],
            )
        assert refused.value.code == "bad_package"


def test_the_reference_receiver_still_files_an_original():
    original = CONTRACT["original_package"]
    outcome, claims = aid.open_reading_aid(
        original,
        device=DEVICE,
        link=LINK,
        all_links=LINKS,
        filed_originals={},
        filed_aids={},
        now=ref.NOW,
    )
    assert outcome == "file" and claims == CONTRACT["sender"]["original_manifest_claims"]


def test_waiting_aid_files_once_its_original_is_filed():
    waiting = next(
        v for v in CONTRACT["packages"]["accept"] if v["expect"] == "waiting_for_original"
    )
    outcome, claims = _open(waiting)
    assert outcome == "waiting_for_original"
    filed_now = {
        **CONTRACT["receiver"]["filed_originals"],
        claims["pair"]["original_delivery_id"]: {
            "ciphertext_sha256": sha256(b"FAKE the late original's copy").hexdigest(),
            "document_sha256": claims["pair"]["original_document_sha256"],
            "created_at": claims["created_at"],
            "expires_at": claims["expires_at"],
        },
    }
    outcome, _ = aid.open_reading_aid(
        waiting,
        device=DEVICE,
        link=LINK,
        all_links=LINKS,
        filed_originals=filed_now,
        filed_aids={},
        now=waiting["now"],
    )
    assert outcome == "file"


@pytest.mark.parametrize("example", CONTRACT["portal"]["serve"])
def test_portal_serves_a_kind_only_to_a_pickup_that_accepts_it(example):
    outer = {} if example["outer_kind"] is None else {"kind": example["outer_kind"]}
    assert aid.portal_serves(outer, example["accepts"]) is example["served"]


@pytest.mark.parametrize("example", CONTRACT["portal"]["kind"])
def test_portal_bounds_the_outer_records_kind(example):
    assert aid.kind_ok(example["kind"]) is example["ok"]


@pytest.mark.parametrize("example", CONTRACT["portal"]["accept"])
def test_portal_bounds_the_pickups_accept_values(example):
    assert aid.accept_ok(example["accepts"]) is example["ok"]


def test_the_notice_tag_may_carry_a_region_and_its_primary_subtag_names_the_language():
    for version, tag in [
        ("carlos-5537-en-1", "en"),
        ("carlos-5537-fr-1", "fr"),
        ("carlos-5537-es-1", "es"),
        ("carlos-5537-pl-1", "pl"),
        ("carlos-5537-pt-BR-1", "pt"),
        # A lower-case "br" is a language of its own, not a region: with the scheme it is
        # "carlos-5537-pt" and the tag "br", which never equals an aid in pt-BR's "pt".
        ("carlos-5537-pt-br-1", "br"),
        ("scheme-2-fil-12", "fil"),
    ]:
        match = aid.NOTICE_VERSION_RE.match(version)
        assert match is not None and match.group(1) == tag, version
    for version in [
        "carlos-5537-pt-BRA-1",  # two letters only
        "carlos-5537-pt-B-1",
        "carlos-5537-PT-1",  # the language is lower case
        "carlos-5537-p-1",
        "carlos-5537-1",
        "carlos-5537-pt-BR",
        "carlos-5537-pt-BR-x",
    ]:
        assert aid.NOTICE_VERSION_RE.match(version) is None, version


def test_the_reviewer_role_set_is_closed_and_the_notice_tag_names_the_language():
    claims = CONTRACT["sender"]["manifest_claims"]
    assert (
        claims["approval"]["reviewer_role"]
        in CONTRACT["constants"]["reviewer_roles"]
        == ["clinician"]
    )
    assert (
        aid.NOTICE_VERSION_RE.match(claims["reading_aid"]["notice_version"]).group(1)
        == claims["reading_aid"]["language"]
    )


def test_the_delivery_contract_fixture_is_untouched():
    # This addendum adds a second copy kind; the v1 original contract must not change with it.
    assert ref.FIXTURE_PATH.read_text(encoding="utf-8") == ref.render()
