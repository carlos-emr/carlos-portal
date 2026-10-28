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

"""Owned SQLite state/rollback proofs; PostgreSQL races remain separately required."""

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select

from carlos_patient_portal.database import Base
from carlos_patient_portal.mailbox import (
    MailboxLimits,
    accept_receipt,
    acknowledge_events,
    admit_upload,
    clinic_lock,
    events_page,
    expire_batch,
    mailbox_lock,
    prune_collected_events,
    prune_terminal_copies,
    record_request_anchor,
    terminate,
)
from carlos_patient_portal.mailbox_codec import MailboxRefusal, parse_upload
from carlos_patient_portal.mailbox_models import (
    MailboxAccount,
    MailboxAnchor,
    MailboxBase,
    MailboxBlob,
    MailboxClinic,
    MailboxCopy,
    MailboxDevice,
    MailboxEvent,
    MailboxProof,
    MailboxRate,
)
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosRecipient,
)
from carlos_patient_portal.mycarlos_devices import remove_device
from tests import delivery_contract_reference as ref
from tests.test_device_identity import portal  # noqa: F401 -- reused owned migrated fixture

FIXTURE = json.loads((Path(__file__).parent / "fixtures/mailbox-contract-v1.json").read_bytes())
M0 = json.loads((Path(__file__).parent / "fixtures/delivery-contract.json").read_bytes())
NOW = M0["portal"]["state"]["now"]
UPLOAD = bytes.fromhex(FIXTURE["uploads"][0]["body"]["hex"])
VALUE = parse_upload(UPLOAD)
RECEIPT = next(
    value["receipt"] for value in M0["portal"]["receipts"] if value["expect"] == "accept"
)
ASSERTION = next(
    value["assertion"]
    for value in M0["portal"]["device_requests"]
    if value["name"] == "send the receipt"
)
LIMITS = MailboxLimits()


@pytest.fixture
def mailbox_factory(request):
    # Source-only test setup: a future authorized run creates NEW tables only in the
    # existing fixture's owned disposable SQLite database, never via a deployment migration.
    factory = request.getfixturevalue("portal")
    with factory() as session:
        engine = session.get_bind()
    MailboxBase.metadata.create_all(engine)
    return factory


def target(session):
    account_id = session.scalar(
        select(PatientPortalMyCarlosDevice.account_id).where(
            PatientPortalMyCarlosDevice.device_key_id == VALUE.outer["device_key_id"]
        )
    )
    return mailbox_lock(
        session,
        account_id=account_id,
        device_key_id=VALUE.outer["device_key_id"],
        clinic_id="clinic-a",
    )


def count(session, model):
    return session.scalar(select(func.count()).select_from(model))


def store(factory, *, limits=LIMITS):
    with factory() as session, session.begin():
        return admit_upload(session, target(session), VALUE, now=NOW, limits=limits)


def test_rollback_exposes_no_blob_counter_or_identity(mailbox_factory):
    with pytest.raises(RuntimeError, match="FAKE crash before commit"):
        with mailbox_factory() as session, session.begin():
            admit_upload(session, target(session), VALUE, now=NOW, limits=LIMITS)
            raise RuntimeError("FAKE crash before commit")
    with mailbox_factory() as session:
        assert count(session, MailboxBlob) == count(session, MailboxCopy) == 0
        assert count(session, MailboxClinic) == 0


def test_same_body_retry_precedes_quota_and_expiry_and_never_resurrects(mailbox_factory):
    assert store(mailbox_factory, limits=replace(LIMITS, device_copies=1))[1] == 201
    after_expiry = VALUE.outer["expires_at"] + 1
    assert expire_batch(mailbox_factory, clock=lambda: after_expiry) == 1
    with mailbox_factory() as session, session.begin():
        result, status = admit_upload(
            session,
            target(session),
            VALUE,
            now=after_expiry,
            limits=replace(LIMITS, device_copies=1),
        )
        assert status == 200 and result["status"] == "expired"
    with mailbox_factory() as session:
        assert count(session, MailboxBlob) == 0
        assert session.scalar(select(MailboxClinic.waiting_count)) == 0
        assert count(session, MailboxEvent) == 1


def test_same_identity_different_valid_framed_bytes_conflict_preserves_old(mailbox_factory):
    store(mailbox_factory)
    other = parse_upload(bytes.fromhex(FIXTURE["uploads"][1]["body"]["hex"]))
    with pytest.raises(MailboxRefusal, match="delivery_conflict"):
        with mailbox_factory() as session, session.begin():
            admit_upload(session, target(session), other, now=NOW, limits=LIMITS)
    with mailbox_factory() as session:
        assert count(session, MailboxCopy) == count(session, MailboxBlob) == 1
        assert session.scalar(select(MailboxCopy.body_sha256)) == VALUE.body_sha256


def test_valid_receipt_atomically_deletes_blob_preserves_proofs_even_at_ordinary_cap(
    mailbox_factory,
):
    store(mailbox_factory)
    with mailbox_factory() as session, session.begin():
        result = accept_receipt(
            session,
            target(session),
            delivery_id=VALUE.outer["delivery_id"],
            compact=RECEIPT,
            request_assertion=ASSERTION,
            request_anchor=None,
            clock=lambda: NOW,
            limits=replace(LIMITS, ordinary_event_bytes=0),
        )
        assert result == {"status": "picked_up"}
    with mailbox_factory() as session, session.begin():
        clinic = clinic_lock(session, "clinic-a")
        page = events_page(session, clinic, after=0, limit=25, now=NOW, limits=LIMITS)
        assert len(page["events"]) == 1
        assert page["events"][0]["payload"]["receipt"] == RECEIPT
        assert page["events"][0]["payload"]["request_assertion"] == ASSERTION
        assert count(session, MailboxBlob) == 0
        assert clinic.waiting_count == clinic.waiting_bytes == clinic.reserved_terminal_bytes == 0
        assert clinic.terminal_event_bytes <= 16384
        assert acknowledge_events(session, clinic, through=1) == {"acked_through": "1"}
        assert clinic.terminal_event_bytes == 0
        assert acknowledge_events(session, clinic, through=0) == {"acked_through": "1"}
        assert clinic.terminal_event_bytes == 0
        assert acknowledge_events(session, clinic, through=1) == {"acked_through": "1"}
        assert clinic.terminal_event_bytes == 0
        assert prune_collected_events(session, clinic) == 1
        assert clinic.terminal_event_bytes == 0
    with mailbox_factory() as session, session.begin():
        assert count(session, MailboxAnchor) == 1
        assert count(session, MailboxProof) == 2
        # Exact old receipt/hash remains after event pruning AND original expiry.
        assert accept_receipt(
            session,
            target(session),
            delivery_id=VALUE.outer["delivery_id"],
            compact=RECEIPT,
            request_assertion=ASSERTION,
            request_anchor=None,
            clock=lambda: VALUE.outer["expires_at"] + 100,
            limits=LIMITS,
        ) == {"status": "picked_up"}
    with pytest.raises(MailboxRefusal, match="delivery_not_found"):
        with mailbox_factory() as session, session.begin():
            accept_receipt(
                session,
                target(session),
                delivery_id=VALUE.outer["delivery_id"],
                compact=RECEIPT + "x",
                request_assertion=ASSERTION,
                request_anchor=None,
                clock=lambda: NOW,
                limits=LIMITS,
            )


def test_receipt_rollback_leaves_primary_blob_and_no_false_pickup(mailbox_factory):
    store(mailbox_factory)
    with pytest.raises(RuntimeError, match="FAKE receipt crash"):
        with mailbox_factory() as session, session.begin():
            accept_receipt(
                session,
                target(session),
                delivery_id=VALUE.outer["delivery_id"],
                compact=RECEIPT,
                request_assertion=ASSERTION,
                request_anchor=None,
                clock=lambda: NOW,
                limits=LIMITS,
            )
            raise RuntimeError("FAKE receipt crash")
    with mailbox_factory() as session:
        assert count(session, MailboxBlob) == 1
        assert session.scalar(select(MailboxCopy.status)) == "waiting"
        assert (
            count(session, MailboxEvent)
            == count(session, MailboxAnchor)
            == count(session, MailboxProof)
            == 0
        )


def test_ack_rollback_releases_no_budget_or_checkpoint(mailbox_factory):
    store(mailbox_factory)
    with mailbox_factory() as session, session.begin():
        accept_receipt(
            session,
            target(session),
            delivery_id=VALUE.outer["delivery_id"],
            compact=RECEIPT,
            request_assertion=ASSERTION,
            request_anchor=None,
            clock=lambda: NOW,
            limits=LIMITS,
        )
    with mailbox_factory() as session:
        clinic = session.scalar(select(MailboxClinic))
        before = (
            clinic.acked_through,
            clinic.ordinary_event_bytes,
            clinic.terminal_event_bytes,
            clinic.reserved_terminal_bytes,
        )
        assert before[0] == 0 and before[2] > 0
    with pytest.raises(RuntimeError, match="FAKE ack crash before commit"):
        with mailbox_factory() as session, session.begin():
            clinic = clinic_lock(session, "clinic-a")
            acknowledge_events(session, clinic, through=1)
            assert clinic.acked_through == 1 and clinic.terminal_event_bytes == 0
            raise RuntimeError("FAKE ack crash before commit")
    with mailbox_factory() as session:
        clinic = session.scalar(select(MailboxClinic))
        assert (
            clinic.acked_through,
            clinic.ordinary_event_bytes,
            clinic.terminal_event_bytes,
            clinic.reserved_terminal_bytes,
        ) == before
        assert count(session, MailboxEvent) == 1


def test_removed_device_has_one_control_then_copy_event_and_no_late_receipt(mailbox_factory):
    store(mailbox_factory)
    for expected in (True, False):
        with mailbox_factory() as session, session.begin():
            m = target(session) if expected else None
            if m is not None:
                account_id = m.account.id
            result = remove_device(
                session,
                account_id=account_id,
                device_key_id=VALUE.outer["device_key_id"],
                removed_by="patient",
                now=datetime.fromtimestamp(NOW, tz=UTC),
                mailbox_enabled=True,
            )
            assert result[1] is expected
    with mailbox_factory() as session:
        assert count(session, MailboxBlob) == 0
        assert list(session.scalars(select(MailboxEvent.kind).order_by(MailboxEvent.sequence))) == [
            "device_removed",
            "removed",
        ]
        assert session.scalar(select(MailboxClinic.waiting_count)) == 0
    with pytest.raises(MailboxRefusal, match="device_removed"):
        with mailbox_factory() as session, session.begin():
            target(session)


def test_receipt_samples_fresh_time_after_signature_validation(mailbox_factory):
    store(mailbox_factory)
    readings = iter((NOW, VALUE.outer["expires_at"]))
    with pytest.raises(MailboxRefusal, match="delivery_not_found"):
        with mailbox_factory() as session, session.begin():
            accept_receipt(
                session,
                target(session),
                delivery_id=VALUE.outer["delivery_id"],
                compact=RECEIPT,
                request_assertion=ASSERTION,
                request_anchor=None,
                clock=lambda: next(readings),
                limits=LIMITS,
            )
    with mailbox_factory() as session:
        assert count(session, MailboxBlob) == 1
        assert count(session, MailboxEvent) == 0


def test_repeated_pickups_fill_finite_event_budget_and_collection_reopens_admission(
    mailbox_factory,
):
    """Waiting bytes returning to zero must NOT allow an unbounded uncollected feed."""
    limits = replace(LIMITS, ordinary_event_bytes=32768, clinic_copies=1)
    device = ref.DeviceKeys("device 1")
    base_claims = json.loads(ref.b64url_decode(RECEIPT.split(".")[0]))
    blocked = None
    accepted = 0
    for _index in range(100):
        outer = dict(VALUE.outer, delivery_id=str(uuid4()))
        upload = parse_upload(ref.frame(ref.canonical_json(outer), VALUE.sealed))
        try:
            with mailbox_factory() as session, session.begin():
                admit_upload(session, target(session), upload, now=NOW, limits=limits)
        except MailboxRefusal as exc:
            assert exc.code == "mailbox_quota_exceeded" and exc.status == 429
            blocked = upload
            break
        claims = dict(base_claims, delivery_id=outer["delivery_id"], jti=str(uuid4()))
        receipt = ref.compact_ed25519(device.ed25519, claims)
        body = ref.canonical_json({"receipt": receipt})
        request = ref.compact_ed25519(
            device.ed25519,
            {
                "aud": ref.DEVICE_AUDIENCE,
                "iss": "mycarlos",
                "kid": device.device_key_id,
                "recipient_id": outer["recipient_id"],
                "jti": str(uuid4()),
                "iat": NOW,
                "exp": NOW + 60,
                "request_hash": ref.request_hash(
                    "POST",
                    (
                        "/patients/api/mycarlos/deliveries/" + outer["delivery_id"] + "/receipt"
                    ).encode(),
                    b"",
                    body,
                ),
            },
        )
        with mailbox_factory() as session, session.begin():
            assert accept_receipt(
                session,
                target(session),
                delivery_id=outer["delivery_id"],
                compact=receipt,
                request_assertion=request,
                request_anchor=None,
                clock=lambda: NOW,
                limits=limits,
            ) == {"status": "picked_up"}
        accepted += 1
    assert blocked is not None and 1 <= accepted < 100
    with mailbox_factory() as session:
        assert count(session, MailboxBlob) == 0
        assert count(session, MailboxCopy) == accepted  # refused upload creates no tombstone/charge
        clinic = session.scalar(select(MailboxClinic))
        assert clinic.waiting_count == clinic.reserved_terminal_bytes == 0
        assert clinic.ordinary_event_bytes == 0
        assert clinic.terminal_event_bytes <= limits.ordinary_event_bytes + 16384

    # Ordinary anchored check-ins also have to respect the combined terminal envelope,
    # even when their own ordinary-only allowance has plenty of capacity remaining.
    anchor_refused = False
    for _index in range(50):
        assertion = ref.compact_ed25519(
            device.ed25519,
            {
                "aud": ref.DEVICE_AUDIENCE,
                "iss": "mycarlos",
                "kid": device.device_key_id,
                "recipient_id": VALUE.outer["recipient_id"],
                "jti": str(uuid4()),
                "iat": NOW,
                "exp": NOW + 60,
                "request_hash": ref.request_hash(
                    "GET", b"/patients/api/mycarlos/deliveries", b"", b""
                ),
                "vault_head_link": "11" * 32,
            },
        )
        with mailbox_factory() as session:
            before = (
                count(session, MailboxAnchor),
                count(session, MailboxProof),
                count(session, MailboxEvent),
            )
        try:
            with mailbox_factory() as session, session.begin():
                record_request_anchor(
                    session,
                    target(session),
                    compact=assertion,
                    anchor="11" * 32,
                    now=NOW,
                    limits=limits,
                )
        except MailboxRefusal as exc:
            assert exc.code == "mailbox_quota_exceeded"
            with mailbox_factory() as session:
                assert (
                    count(session, MailboxAnchor),
                    count(session, MailboxProof),
                    count(session, MailboxEvent),
                ) == before
                assert (
                    session.scalar(select(MailboxClinic.ordinary_event_bytes))
                    < limits.ordinary_event_bytes // 2
                )
            anchor_refused = True
            break
    assert anchor_refused
    with mailbox_factory() as session, session.begin():
        clinic = clinic_lock(session, "clinic-a")
        acknowledge_events(session, clinic, through=clinic.event_sequence)
        assert clinic.ordinary_event_bytes == clinic.terminal_event_bytes == 0
    with mailbox_factory() as session, session.begin():
        # ACK ALONE reopens admission before any physical event pruning sweep.
        assert admit_upload(session, target(session), blocked, now=NOW, limits=limits)[1] == 201
    with mailbox_factory() as session, session.begin():
        clinic = clinic_lock(session, "clinic-a")
        assert prune_collected_events(session, clinic, limit=100) > 0
        assert clinic.ordinary_event_bytes == clinic.terminal_event_bytes == 0


def _retention_snapshot(factory, *, include_copies=False):
    models = (
        MailboxAccount,
        MailboxAnchor,
        MailboxBlob,
        MailboxClinic,
        MailboxDevice,
        MailboxEvent,
        MailboxProof,
        MailboxRate,
        PatientPortalAccount,
        PatientPortalMyCarlosDevice,
        PatientPortalMyCarlosRecipient,
    )
    if include_copies:
        models += (MailboxCopy,)
    with factory() as session:
        return {
            model.__tablename__: session.execute(
                select(model.__table__).order_by(*model.__table__.primary_key.columns)
            ).all()
            for model in models
        }


def _picked_up_for_retention(factory, *, prune=True, acknowledge=True):
    store(factory)
    with factory() as session, session.begin():
        accept_receipt(
            session,
            target(session),
            delivery_id=VALUE.outer["delivery_id"],
            compact=RECEIPT,
            request_assertion=ASSERTION,
            request_anchor=None,
            clock=lambda: NOW,
            limits=LIMITS,
        )
        clinic = clinic_lock(session, "clinic-a")
        if acknowledge:
            acknowledge_events(session, clinic, through=clinic.event_sequence)
        if prune:
            assert prune_collected_events(session, clinic) == 1


@pytest.mark.parametrize("retention_days", [1, 14])
@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_terminal_retention_requires_both_original_expiry_and_audit_horizon(
    mailbox_factory, retention_days, offset
):
    _picked_up_for_retention(mailbox_factory)
    before = _retention_snapshot(mailbox_factory)
    eligible_at = max(VALUE.outer["expires_at"], NOW + retention_days * 86400)
    assert prune_terminal_copies(
        mailbox_factory, retention_days=retention_days, clock=lambda: eligible_at + offset
    ) == int(offset >= 0)
    assert _retention_snapshot(mailbox_factory) == before
    with mailbox_factory() as session:
        assert count(session, MailboxCopy) == int(offset < 0)
    assert (
        prune_terminal_copies(
            mailbox_factory, retention_days=retention_days, clock=lambda: eligible_at + offset
        )
        == 0
    )


@pytest.mark.parametrize("acknowledged", [False, True])
def test_terminal_retention_any_retained_event_keeps_tombstone_and_exact_proofs(
    mailbox_factory, acknowledged
):
    _picked_up_for_retention(mailbox_factory, prune=False, acknowledge=acknowledged)
    before = _retention_snapshot(mailbox_factory, include_copies=True)
    far_future = NOW + 30 * 86400
    assert prune_terminal_copies(mailbox_factory, retention_days=14, clock=lambda: far_future) == 0
    assert _retention_snapshot(mailbox_factory, include_copies=True) == before
    with mailbox_factory() as session, session.begin():
        clinic = clinic_lock(session, "clinic-a")
        assert clinic.acked_through == int(acknowledged)
        acknowledge_events(session, clinic, through=clinic.event_sequence)
        assert prune_collected_events(session, clinic) == 1
    retained = _retention_snapshot(mailbox_factory)
    with mailbox_factory() as session:
        assert count(session, MailboxProof) == 2
        assert count(session, MailboxAnchor) == 1
        assert session.scalar(select(MailboxCopy.receipt_sha256)) is not None
    assert prune_terminal_copies(mailbox_factory, retention_days=14, clock=lambda: far_future) == 1
    assert _retention_snapshot(mailbox_factory) == retained


def test_terminal_retention_never_expires_waiting_copy_or_touches_its_blob(mailbox_factory):
    store(mailbox_factory)
    before = _retention_snapshot(mailbox_factory, include_copies=True)
    assert (
        prune_terminal_copies(mailbox_factory, retention_days=1, clock=lambda: NOW + 30 * 86400)
        == 0
    )
    assert _retention_snapshot(mailbox_factory, include_copies=True) == before
    with mailbox_factory() as session:
        assert session.scalar(select(MailboxCopy.status)) == "waiting"
        assert session.scalar(select(MailboxBlob.sealed)) == VALUE.sealed


def test_terminal_retention_refuses_inconsistent_primary_blob_without_mutation(mailbox_factory):
    _picked_up_for_retention(mailbox_factory)
    with mailbox_factory() as session, session.begin():
        copy_id = session.scalar(select(MailboxCopy.id))
        session.add(MailboxBlob(copy_id=copy_id, sealed=VALUE.sealed))
    before = _retention_snapshot(mailbox_factory, include_copies=True)
    with pytest.raises(RuntimeError, match="Terminal copy retains primary ciphertext"):
        prune_terminal_copies(mailbox_factory, retention_days=1, clock=lambda: NOW + 30 * 86400)
    assert _retention_snapshot(mailbox_factory, include_copies=True) == before


@pytest.mark.parametrize("missing", [MailboxClinic, MailboxAccount, MailboxDevice])
def test_terminal_retention_never_initializes_missing_quota_rows(mailbox_factory, missing):
    _picked_up_for_retention(mailbox_factory)
    with mailbox_factory() as session, session.begin():
        session.execute(delete(missing))
    before = _retention_snapshot(mailbox_factory, include_copies=True)
    with pytest.raises(RuntimeError, match="Terminal copy lacks its existing quota counters"):
        prune_terminal_copies(mailbox_factory, retention_days=1, clock=lambda: NOW + 30 * 86400)
    assert _retention_snapshot(mailbox_factory, include_copies=True) == before


def test_terminal_retention_default_batch_never_exceeds_one_hundred(mailbox_factory):
    preparation_limits = replace(LIMITS, clinic_uploads_per_minute=200)
    for _index in range(101):
        upload = parse_upload(
            ref.frame(ref.canonical_json(dict(VALUE.outer, delivery_id=str(uuid4()))), VALUE.sealed)
        )
        with mailbox_factory() as session, session.begin():
            m = target(session)
            admit_upload(session, m, upload, now=NOW, limits=preparation_limits)
            copy = session.scalar(
                select(MailboxCopy).where(MailboxCopy.delivery_id == upload.outer["delivery_id"])
            )
            terminate(session, m, copy, status="expired", now=VALUE.outer["expires_at"])
    with mailbox_factory() as session, session.begin():
        clinic = clinic_lock(session, "clinic-a")
        acknowledge_events(session, clinic, through=clinic.event_sequence)
        assert prune_collected_events(session, clinic) == 100
        assert prune_collected_events(session, clinic) == 1
    before = _retention_snapshot(mailbox_factory)

    def clock():
        return VALUE.outer["expires_at"] + 86400

    assert prune_terminal_copies(mailbox_factory, retention_days=1, clock=clock) == 100
    with mailbox_factory() as session:
        assert count(session, MailboxCopy) == 1
    assert prune_terminal_copies(mailbox_factory, retention_days=1, clock=clock) == 1
    assert prune_terminal_copies(mailbox_factory, retention_days=1, clock=clock) == 0
    assert _retention_snapshot(mailbox_factory) == before


@pytest.mark.parametrize("limit", [0, 101, True, 1.5])
def test_terminal_retention_rejects_unbounded_or_noninteger_limit(mailbox_factory, limit):
    before = _retention_snapshot(mailbox_factory, include_copies=True)
    with pytest.raises(ValueError, match="limit must be an integer between 1 and 100"):
        prune_terminal_copies(mailbox_factory, retention_days=1, limit=limit)
    assert _retention_snapshot(mailbox_factory, include_copies=True) == before


def test_proposed_mailbox_metadata_keeps_deployed_schema_and_domain_foreign_keys():
    proposed = MailboxBase.metadata
    expected = {
        "patient_portal_mycarlos_mailbox_clinics",
        "patient_portal_mycarlos_mailbox_accounts",
        "patient_portal_mycarlos_mailbox_devices",
        "patient_portal_mycarlos_mailbox_copies",
        "patient_portal_mycarlos_mailbox_blobs",
        "patient_portal_mycarlos_mailbox_proofs",
        "patient_portal_mycarlos_mailbox_anchors",
        "patient_portal_mycarlos_mailbox_events",
        "patient_portal_mycarlos_mailbox_rates",
    }
    assert set(proposed.tables) == expected
    assert proposed is not Base.metadata
    assert expected.isdisjoint(Base.metadata.tables)
    domain = {"patient_portal_accounts", "patient_portal_mycarlos_devices"}
    external = []
    for table in proposed.tables.values():
        for foreign in table.foreign_keys:
            assert foreign.ondelete == "RESTRICT"
            target = foreign.column
            if target.table.name in domain:
                assert target is Base.metadata.tables[target.table.name].c.id
                external.append(foreign)
            else:
                assert target.table.metadata is proposed
    assert len(external) == 4
