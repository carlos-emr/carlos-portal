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
code; these tests re-run them over the fixture's lists, pin EXACTLY which cases are accepted, and
check the one end-to-end vector and the properties the document claims.
"""

import hashlib
import importlib.util
import json
import re
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


def accepted(cases):
    return {case["name"] for case in cases if case["expect"] == "accept"}


def test_the_fixture_is_exactly_what_the_generator_makes():
    made = json.dumps(reference.build(), indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    assert FIXTURE_PATH.read_bytes() == made


def test_every_listed_case_gives_its_expected_answer_from_the_reference_validators():
    for item in FIXTURE["outer_cases"]:
        assert (reference.check_outer(item["object"], now=item["now"]) or "accept") == item[
            "expect"
        ], item["name"]
    for item in FIXTURE["envelope_cases"]:
        working = reference.PHASES[item["phase"]]
        assert (reference.check_envelope(item["object"], working) or "accept") == item["expect"], (
            item["name"]
        )
    for item in FIXTURE["ack_cases"]:
        assert (reference.check_ack(item["object"]) or "accept") == item["expect"], item["name"]
    for item in FIXTURE["recall_cases"]:
        assert (reference.check_recall(item["object"]) or "accept") == item["expect"], item["name"]
    for item in FIXTURE["inbox_key_cases"]:
        result = reference.check_inbox_key(item["object"], item["now"], known=item["known"])
        assert (result or "accept") == item["expect"], item["name"]
    for item in FIXTURE["recall_binding_cases"]:
        outer = FIXTURE["end_to_end"]["outer"]
        result = reference.check_recall_binding(item["recall"], outer)
        assert (result or "accept") == item["expect"], item["name"]
    for item in FIXTURE["time_cases"]:
        result = reference.check_times(item["created_at"], item["expires_at"], item["now"])
        assert (result or "accept") == item["expect"], item["name"]
    for item in FIXTURE["text_cases"]:
        result = reference.check_text(item["text"], name=item["as_name"])
        assert (result or "accept") == item["expect"], item["name"]
    for item in FIXTURE["compact_cases"]:
        _value, reason = reference.check_compact_payload(item["payload_b64url"])
        assert (reason or "accept") == item["expect"], item["name"]


def test_exactly_these_cases_are_accepted_and_every_other_is_refused_with_a_reason():
    # No allowance for "a few more": the accepted set is pinned by name.
    assert accepted(FIXTURE["outer_cases"]) == {
        "exactly as built",
        "with a clock inside its lifetime",
        "created_at ahead of the clock within the skew",
    }
    assert accepted(FIXTURE["envelope_cases"]) == {
        "exactly as built",
        "a line feed in the body is allowed",
        "text and no attachment",
        "video in phase 2",
    }
    assert accepted(FIXTURE["ack_cases"]) == {
        "collected",
        "filed",
        "refused with a reason",
        "refused: key revoked",
        "recalled",
        "recall refused with a reason",
    }
    assert accepted(FIXTURE["recall_cases"]) == {"as built"}
    assert accepted(FIXTURE["inbox_key_cases"]) == {
        "an active statement inside its validity",
        "valid for exactly 30 days",
        "the serial the app already holds",
        "a higher serial",
        "active at a higher serial than a revocation the app holds",
    }
    assert accepted(FIXTURE["recall_binding_cases"]) == {"as built"}
    assert accepted(FIXTURE["pair_cases"]) == {"as built"}
    assert accepted(FIXTURE["compact_cases"]) == {
        "the canonical payload",
        "the largest safe integer 2^53-1",
    }
    for key in (
        "outer_cases",
        "envelope_cases",
        "ack_cases",
        "recall_cases",
        "inbox_key_cases",
        "recall_binding_cases",
        "pair_cases",
        "compact_cases",
        "time_cases",
        "text_cases",
    ):
        for case in FIXTURE[key]:
            assert case["expect"] == "accept" or re.fullmatch(r"[a-z0-9_]+", case["expect"]), case


def test_the_version_is_exactly_the_integer_one_everywhere():
    for key in ("outer_cases", "envelope_cases"):
        by_name = {case["name"]: case for case in FIXTURE[key]}
        for label in ("2", "as text", "true", "1.0", "null"):
            assert by_name[f"version {label}"]["expect"] == "unsupported_version", (key, label)
    for key in ("ack_cases", "recall_cases"):
        for case in FIXTURE[key]:
            if case["name"].startswith("version"):
                assert case["expect"] == "unsupported_version"
    for bad in (True, 1.0, "1", None, 2):
        assert reference.version_ok({"v": bad}) is False
    assert reference.version_ok({"v": 1}) is True
    assert reference.version_ok({}) is False


def test_the_end_to_end_message_agrees_with_itself():
    end = FIXTURE["end_to_end"]
    outer, envelope = end["outer"], end["envelope"]
    chain = FIXTURE["chain"]
    assert end["pair_check"] == "accept"
    assert reference.check_outer(outer) is None
    assert reference.check_envelope(envelope) is None
    assert reference.check_pair(outer, envelope) is None
    hashes = {
        reference.ATTACHMENT_A: chain["attachment_a_chunk_sha256"],
        reference.ATTACHMENT_B: chain["attachment_b_chunk_sha256"],
    }
    sizes = {
        reference.ATTACHMENT_A: chain["attachment_a_chunk_sealed_sizes"],
        reference.ATTACHMENT_B: chain["attachment_b_chunk_sealed_sizes"],
    }
    heads = []
    for visible, described in zip(outer["attachments"], envelope["attachments"], strict=True):
        attachment_id = described["attachment_id"]
        chunk_hashes = [bytes.fromhex(h) for h in hashes[attachment_id]]
        recomputed = reference.head_from_hashes(
            envelope["message_id"], attachment_id, chunk_hashes
        ).hex()
        # The portal's recomputation, the signed envelope's head and the outer record all agree.
        assert visible["chain_head"] == recomputed == described["chain_head"]
        assert visible["chunk_count"] == len(chunk_hashes) == described["chunk_count"]
        assert (
            visible["size"] == sum(sizes[attachment_id]) == reference.sealed_size(described["size"])
        )
        assert described["chunk_count"] == -(-described["size"] // described["chunk_size"])
        heads.append(bytes.fromhex(recomputed))
    envelope_ciphertext_size = chain["envelope_ciphertext"]["size"]
    assert outer["envelope_size"] == envelope_ciphertext_size
    # The sealed plaintext is the ASCII compact signed form, not the bare canonical JSON.
    sealed = FIXTURE["envelope"]["sealed_plaintext"]
    assert outer["envelope_size"] == sealed["size"] + 16
    payload, signature = sealed["ascii"].split(".")
    assert payload == reference.b64u(reference.canonical(envelope))
    assert len(reference.base64.urlsafe_b64decode(signature + "==")) == 64
    assert sealed["size"] == len(sealed["ascii"]) and sealed["ascii"].isascii()
    assert outer["envelope_size"] >= FIXTURE["envelope"]["min_sealed_size"]
    assert outer["total_size"] == outer["envelope_size"] + sum(
        i["size"] for i in outer["attachments"]
    )
    assert outer["chunk_total"] == sum(i["chunk_count"] for i in outer["attachments"])
    message = hashlib.sha256(
        reference.frame(
            b"mycarlos-send/1 message",
            reference.uuid_bytes(outer["message_id"]),
            bytes.fromhex(outer["envelope_sha256"]),
            *heads,
        )
    ).hexdigest()
    assert message == outer["chain_head"] == chain["base"]["message_head"]
    # The plaintext hashes in the signed envelope are those of the plaintext it stands for.
    assert envelope["attachments"][0]["sha256"] == end["plaintext"]["plaintext_a_sha256"]
    assert envelope["attachments"][1]["sha256"] == end["plaintext"]["plaintext_b_sha256"]
    assert (
        FIXTURE["envelope"]["canonical"]["sha256"]
        == hashlib.sha256(reference.canonical(envelope)).hexdigest()
    )
    assert (
        FIXTURE["outer"]["canonical"]["sha256"]
        == hashlib.sha256(reference.canonical(outer)).hexdigest()
    )


def test_the_chain_binds_order_count_content_message_attachment_and_envelope():
    cases = {case["name"]: case for case in FIXTURE["chain"]["cases"]}
    base = FIXTURE["chain"]["base"]
    assert cases["the base chain"]["head"] == base["attachment_a_head"]
    for name, case in cases.items():
        if name == "the base chain":
            continue
        reference_head = (
            base["message_head"] if "message head" in name else base["attachment_a_head"]
        )
        assert case["head"] != reference_head, name
    heads = [case["head"] for case in cases.values()]
    assert len(set(heads)) == len(heads)


def test_a_signature_covers_a_domain_and_the_canonical_bytes_never_the_payload_alone():
    kinds = {
        "envelope": FIXTURE["envelope"],
        "ack": FIXTURE["acks"]["collected"],
        "recall": FIXTURE["recall"],
        "inbox_key": FIXTURE["inbox_key"],
    }
    inputs = set()
    for kind, item in kinds.items():
        payload = bytes.fromhex(item["canonical"]["hex"])
        expected = reference.signing_input(kind, payload)
        assert bytes.fromhex(item["signing_input"]["hex"]) == expected
        assert expected != payload
        assert expected.startswith((len(reference.SIGN_DOMAINS[kind])).to_bytes(8, "big"))
        inputs.add(expected)
    assert len(inputs) == 4
    # The same payload under two domains gives two different inputs: no cross-purpose replay.
    same = b"{}"
    assert len({reference.signing_input(kind, same) for kind in reference.SIGN_DOMAINS}) == 4
    assert FIXTURE["compact_form"].count("canonical(parse(payload)) == payload") == 1


def test_no_delivery_state_says_read_and_the_machine_is_closed():
    states = FIXTURE["states"]
    assert not {"read", "seen", "reviewed", "delivered_to_clinician"} & set(states)
    for state, meaning in states.items():
        assert meaning["never_means"] and meaning["by"], state
    transitions = FIXTURE["transitions"]
    known = set(states)
    for source, targets in transitions.items():
        assert source in known and set(targets) <= known
    for final in ("refused", "expired", "recalled", "cancelled"):
        assert transitions[final] == []
    # "filed" is reachable only from "collected", "collected" only from "received", and the portal's
    # own expiry cannot end a collected message.
    assert "filed" in transitions["collected"] and "filed" not in transitions["received"]
    assert "expired" not in transitions["collected"] and "expired" not in transitions["filed"]
    assert transitions["filed"] == ["recalled"]
    # Who makes each claim true: the clinic's states are signed, the portal's are labelled.
    assert states["collected"]["by"] == states["filed"]["by"] == "clinic-signed"
    assert states["received"]["by"] == "portal-claim"
    for rule in ("after_a_signed_collected", "cancel_vs_complete", "recall_vs_accept", "recall"):
        assert FIXTURE["rules"][rule]
    assert "NEW message_id" in FIXTURE["rules"]["interrupted_send"]


def test_the_acknowledgement_states_and_reasons_are_the_documented_ones():
    for name in ("refusal_reasons", "recall_refusal_reasons"):
        reasons = FIXTURE[name]
        assert len(reasons) == len(set(reasons))
        for reason in reasons:
            assert f"`{reason}`" in DOC, reason
    assert FIXTURE["ack_states"] == ["collected", "filed", "refused", "recalled", "recall_refused"]
    for state in FIXTURE["ack_states"]:
        assert f"`{state}`" in DOC, state


def test_the_document_carries_the_limits_and_the_defaults_the_fixture_has():
    limits = FIXTURE["limits"]
    assert limits["body_max_bytes"] == 8192 and "8,192" in DOC
    assert limits["chunk_plain_max"] == 4 * 1024 * 1024 and "4 MiB" in DOC
    assert limits["attachments_max"] == 10 and "at most **10**" in DOC
    assert limits["chunks_per_attachment_max"] == 128 and "128 chunks" in DOC
    assert limits["lifetime_max_seconds"] == 7 * 24 * 3600 and "7 days" in DOC
    assert limits["sealed_key_bytes"] == 80 and "exactly 80" in DOC
    assert limits["envelope_sealed_max"] == 256 * 1024 and "256 KiB" in DOC
    assert limits["created_skew_seconds"] == 300 and "300 s" in DOC
    # Ten manifests at the manifest limit, as text, fit the envelope budget with the rest.
    manifest_text = -(-limits["manifest_max_bytes"] * 4 // 3)
    assert 10 * manifest_text + 40 * 1024 < limits["envelope_sealed_max"]
    for phase in ("phase1", "phase2_video"):
        assert phase in FIXTURE["phases"] and phase in DOC
    assert "Ben may change any" in DOC
    for question in range(1, 13):
        assert f"| Q{question} |" in DOC, question


def test_every_route_in_the_fixture_is_in_the_document_and_no_route_parameter_has_a_slash():
    for method, path, _auth, _answers in FIXTURE["routes"]:
        assert f"`{method} {path.split('?')[0]}`" in DOC or path in DOC, (method, path)
        # `{a}/chunks/{n}` is three segments; no single parameter such as {part} holds a slash.
        assert "{part}" not in path
    statuses = {row[2] for row in FIXTURE["idempotency"]}
    assert {200, 201, 404, 409, 410, 422} <= statuses
    texts = " ".join(row[1] for row in FIXTURE["idempotency"])
    assert "tombstone" in texts and "300 s" in texts and "another device" in texts
    assert "(device, message_id, chain_head)" in " ".join(row[1] for row in FIXTURE["idempotency"])


def test_what_the_portal_learns_is_stated_and_the_aead_bytes_are_unique_per_place():
    assert FIXTURE["portal_learns"] and FIXTURE["portal_does_not_learn"]
    for line in ("size buckets", "Padding"):
        assert line in DOC
    aead = FIXTURE["aead"]
    names = ("envelope_nonce", "chunk_nonce_a0_n0", "chunk_nonce_a1_n2")
    assert len({aead[key]["hex"] for key in names}) == 3
    assert all(len(bytes.fromhex(aead[key]["hex"])) == 12 for key in names)


def test_the_worst_case_envelope_fits_the_budget_with_headroom_and_is_accepted():
    worst = FIXTURE["worst_case_envelope"]
    envelope, compact, sealed = reference.worst_case_envelope()
    assert worst["sealed_size"] == sealed == len(compact) + 16
    assert worst["check_envelope"] == "accept" == (reference.check_envelope(envelope) or "accept")
    assert sealed <= reference.LIMITS["envelope_sealed_max"]
    assert worst["headroom"] == reference.LIMITS["envelope_sealed_max"] - sealed
    assert 8 * 1024 <= worst["headroom"] <= 16 * 1024  # about 9 KB of headroom, pinned
    assert len(envelope["attachments"]) == 10


def test_canonical_bytes_are_i_json_and_the_text_unassigned_rule_is_stated():
    for bad in (1.0, float("nan"), 2**53, -1, True):
        assert reference.is_int(bad) is False
    assert reference.is_int(2**53 - 1) and reference.is_int(0)
    for line in ("RFC 8785", "Gson", "2^53-1", "lone surrogate", "Unicode 16.0"):
        assert line in DOC, line
    for step in FIXTURE["check_order"]:
        assert step
    assert [step[0] for step in FIXTURE["check_order"]] == ["1", "2", "3", "4", "5"]
