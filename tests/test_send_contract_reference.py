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

"""The `mycarlos-send/1` contract draft: the fixture is reproducible and matches the document.

Contract only: no server code exists. The reference validators in the generator are the contract in
code; these tests re-run them over the fixture's lists and check the properties the document claims.
"""

import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).parent
FIXTURE_PATH = HERE / "fixtures/send-contract-v1.json"
DOC = (HERE.parent / "docs/architecture/mycarlos-send.md").read_text(encoding="utf-8")

_spec = importlib.util.spec_from_file_location(
    "send_contract_reference", HERE / "send_contract_reference.py"
)
reference = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reference)
FIXTURE = json.loads(FIXTURE_PATH.read_bytes())


def test_the_fixture_is_exactly_what_the_generator_makes():
    made = json.dumps(reference.build(), indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    assert FIXTURE_PATH.read_bytes() == made


def test_every_listed_case_gives_its_expected_answer_from_the_reference_validators():
    for item in FIXTURE["outer_cases"]:
        assert (reference.check_outer(item["object"]) or "accept") == item["expect"], item["name"]
    for item in FIXTURE["envelope_cases"]:
        working = (
            reference.PHASES["phase2_video"]
            if item["name"] == "video in phase 2"
            else reference.PHASES["phase1"]
        )
        assert (reference.check_envelope(item["object"], working) or "accept") == item["expect"], (
            item["name"]
        )
    for item in FIXTURE["ack_cases"]:
        assert (reference.check_ack(item["object"]) or "accept") == item["expect"], item["name"]


def test_the_object_as_built_is_accepted_and_every_mutation_is_refused_with_a_reason():
    for key in ("outer_cases", "envelope_cases"):
        built, *mutated = FIXTURE[key]
        assert built["expect"] == "accept"
        refused = [case for case in mutated if case["expect"] != "accept"]
        assert len(refused) >= len(mutated) - 2  # only the documented accept-cases stay accepted
        for case in refused:
            assert case["expect"].replace("_", "").isalpha()


def test_the_chain_binds_order_count_content_message_and_attachment():
    cases = {case["name"]: case for case in FIXTURE["chain"]["cases"]}
    base = FIXTURE["chain"]["base"]["attachment_head"]
    assert cases["the base chain"]["head"] == base
    for name, case in cases.items():
        if name == "the base chain":
            continue
        reference_head = (
            base if "message head" not in name else FIXTURE["chain"]["base"]["message_head"]
        )
        assert case["head"] != reference_head, name
    heads = [case["head"] for case in cases.values()]
    assert len(set(heads)) == len(heads)


def test_no_delivery_state_says_read_and_the_machine_is_closed():
    states = FIXTURE["states"]
    assert not {"read", "seen", "reviewed", "delivered_to_clinician"} & set(states)
    for state, meaning in states.items():
        assert meaning["never_means"], state
    transitions = FIXTURE["transitions"]
    known = set(states) | {"cancelled"}
    for source, targets in transitions.items():
        assert source in known
        assert set(targets) <= known
    for final in ("refused", "expired", "recalled", "cancelled"):
        assert transitions[final] == []
    # An acknowledgement of "filed" is reachable only from "collected", and "collected" only from
    # "received": the app cannot be told it was filed before it was received.
    assert "filed" in transitions["collected"] and "filed" not in transitions["received"]
    assert transitions["filed"] == ["recalled"]


def test_the_acknowledgement_states_and_reasons_are_the_documented_ones():
    reasons = FIXTURE["refusal_reasons"]
    assert len(reasons) == len(set(reasons))
    for reason in reasons:
        assert f"`{reason}`" in DOC, reason
    for state in ("collected", "filed", "refused"):
        assert state in FIXTURE["acks"]["payloads"]


def test_the_document_carries_the_limits_and_the_defaults_the_fixture_has():
    limits = FIXTURE["limits"]
    assert limits["body_max_bytes"] == 8192 and "8,192" in DOC
    assert limits["chunk_plain_max"] == 4 * 1024 * 1024 and "4 MiB" in DOC
    assert limits["attachments_max"] == 10 and "at most **10**" in DOC
    assert limits["chunks_per_attachment_max"] == 128 and "128 chunks" in DOC
    assert limits["lifetime_max_seconds"] == 7 * 24 * 3600 and "7 days" in DOC
    for phase in ("phase1", "phase2_video"):
        assert phase in FIXTURE["phases"] and phase in DOC
    assert "Ben may change any" in DOC
    for question in range(1, 13):
        assert f"| Q{question} |" in DOC, question


def test_every_route_in_the_fixture_is_in_the_document_and_idempotency_is_complete():
    for method, path, _auth, _answers in FIXTURE["routes"]:
        assert f"`{method} {path.split('?')[0]}`" in DOC or path in DOC, (method, path)
    statuses = {row[2] for row in FIXTURE["idempotency"]}
    assert {200, 201, 409, 422} <= statuses


def test_the_aead_bytes_are_unique_per_place():
    aead = FIXTURE["aead"]
    nonces = {
        aead[key]["hex"] for key in ("envelope_nonce", "chunk_nonce_a0_n0", "chunk_nonce_a1_n2")
    }
    assert len(nonces) == 3
    assert all(
        len(bytes.fromhex(aead[key]["hex"])) == 12
        for key in ("envelope_nonce", "chunk_nonce_a0_n0", "chunk_nonce_a1_n2")
    )
