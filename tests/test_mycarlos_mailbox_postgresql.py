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

"""Proposed-table tests in owned migrated PG schemas; NOT executed or rollout DDL."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from threading import Event
from time import monotonic, sleep

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import sessionmaker

from carlos_patient_portal.mailbox import (
    MailboxLimits,
    admit_upload,
    mailbox_lock,
    record_request_anchor,
)
from carlos_patient_portal.mailbox_codec import MailboxRefusal
from carlos_patient_portal.mailbox_models import (
    MailboxBase,
    MailboxBlob,
    MailboxClinic,
    MailboxCopy,
    MailboxEvent,
)
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosRecipient,
)
from carlos_patient_portal.mycarlos_devices import remove_device
from tests import delivery_contract_reference as ref
from tests.test_mycarlos_mailbox import NOW, VALUE
from tests.test_mycarlos_postgresql import migrated_postgresql_engine  # noqa: F401
from tests.test_postgresql_integration import POSTGRES_URL

pytestmark = pytest.mark.skipif(POSTGRES_URL is None, reason="owned PostgreSQL URL required")
LIMITS = MailboxLimits()


@pytest.fixture
def pg_mailboxes(request):
    engine = request.getfixturevalue("migrated_postgresql_engine")
    with engine.connect() as connection:
        assert connection.scalar(text("select current_schema()")).startswith("mycarlos_test_")
    # Future separately authorized PG runtime ONLY. No protected/versioned migration here.
    MailboxBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    targets = []
    for index in range(2):
        device = ref.DeviceKeys("device 1" if index == 0 else "FAKE M4 PG other account")
        recipient = VALUE.outer["recipient_id"] if index == 0 else "FAKE_m4_pg_second_recipient"
        with factory() as session, session.begin():
            account = PatientPortalAccount(
                clinic_id="clinic-a",
                demographic_no=6001 + index,
                username=f"fake.m4.pg.{index}",
                email=f"fake.m4.pg.{index}@example.test",
                password_hash="FAKE-unused",
                status="active",
            )
            session.add(account)
            session.flush()
            session.add(
                PatientPortalMyCarlosRecipient(account_id=account.id, recipient_id=recipient)
            )
            session.add(
                PatientPortalMyCarlosDevice(
                    account_id=account.id,
                    device_key_id=device.device_key_id,
                    x25519_public_key=device.x25519_public,
                    ed25519_public_key=device.ed25519_public,
                    device_name="FAKE PG M4 device",
                    status="active",
                    linked_at=datetime.fromtimestamp(NOW, tz=UTC),
                )
            )
            targets.append((account.id, device))
    return engine, factory, targets


def observe_block(engine, holder_pid, request_pid, completed):
    deadline = monotonic() + 5
    while monotonic() < deadline:
        with engine.connect() as observer:
            blocked = observer.scalar(
                text("select :holder = any(pg_blocking_pids(:request))"),
                {"holder": holder_pid, "request": request_pid},
            )
        if blocked:
            return
        assert not completed.done(), "request completed before actual required lock wait"
        sleep(0.02)
    pytest.fail("request never actually waited on the held transaction")


def test_first_clinic_quota_and_counter_mutex_serializes_different_accounts(pg_mailboxes):
    engine, factory, targets = pg_mailboxes
    connected = Event()
    request_pid = []
    first_account, first_device = targets[0]
    second_account, second_device = targets[1]

    def second_writer():
        try:
            with factory() as session, session.begin():
                request_pid.append(session.scalar(text("select pg_backend_pid()")))
                connected.set()
                m = mailbox_lock(
                    session, account_id=second_account, device_key_id=second_device.device_key_id
                )
                from carlos_patient_portal.mailbox_codec import json_bytes, parse_upload

                outer = json_bytes(
                    dict(
                        VALUE.outer,
                        device_key_id=second_device.device_key_id,
                        recipient_id=m.recipient,
                    )
                )
                other = parse_upload(ref.frame(outer, VALUE.sealed))
                admit_upload(session, m, other, now=NOW, limits=replace(LIMITS, clinic_copies=1))
        except MailboxRefusal as exc:
            return exc.code
        return "stored"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as holder, holder.begin():
            m = mailbox_lock(
                holder, account_id=first_account, device_key_id=first_device.device_key_id
            )
            holder_pid = holder.scalar(text("select pg_backend_pid()"))
            admit_upload(holder, m, VALUE, now=NOW, limits=replace(LIMITS, clinic_copies=1))
            pending = pool.submit(second_writer)
            assert connected.wait(5)
            observe_block(engine, holder_pid, request_pid[0], pending)
        assert pending.result(timeout=5) == "mailbox_quota_exceeded"
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(MailboxCopy)) == 1
        assert session.scalar(select(func.count()).select_from(MailboxBlob)) == 1
        assert session.scalar(select(MailboxClinic.waiting_count)) == 1


def test_event_counter_has_no_published_prefix_past_an_uncommitted_lower_writer(pg_mailboxes):
    engine, factory, targets = pg_mailboxes
    connected = Event()
    upper_written = Event()
    release_upper = Event()
    request_pid = []

    def anchor_writer(index, *, pause=False):
        account_id, device = targets[index]
        with factory() as session, session.begin():
            request_pid.append(session.scalar(text("select pg_backend_pid()")))
            connected.set()
            m = mailbox_lock(session, account_id=account_id, device_key_id=device.device_key_id)
            # Bytes are test-only retained compact stand-ins; real route verifies before service.
            record_request_anchor(
                session, m, compact=f"FAKE.PGProof{index}", anchor="11" * 32, now=NOW, limits=LIMITS
            )
            session.flush()
            if pause:
                upper_written.set()
                assert release_upper.wait(5)

    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            with factory() as holder, holder.begin():
                first_account, first_device = targets[0]
                m = mailbox_lock(
                    holder, account_id=first_account, device_key_id=first_device.device_key_id
                )
                holder_pid = holder.scalar(text("select pg_backend_pid()"))
                record_request_anchor(
                    holder, m, compact="FAKE.PGProof0", anchor="11" * 32, now=NOW, limits=LIMITS
                )
                holder.flush()
                pending = pool.submit(anchor_writer, 1, pause=True)
                assert connected.wait(5)
                observe_block(engine, holder_pid, request_pid[0], pending)
                with engine.connect() as observer:
                    assert observer.scalar(select(func.count()).select_from(MailboxEvent)) == 0
            assert upper_written.wait(5)
            with engine.connect() as observer:
                assert list(
                    observer.scalars(select(MailboxEvent.sequence).order_by(MailboxEvent.sequence))
                ) == [1]
        finally:
            release_upper.set()
        pending.result(timeout=5)
    with factory() as session:
        assert list(
            session.scalars(select(MailboxEvent.sequence).order_by(MailboxEvent.sequence))
        ) == [1, 2]


def test_removal_commits_before_waiting_upload_cannot_create_or_resurrect_blob(pg_mailboxes):
    engine, factory, targets = pg_mailboxes
    account_id, device = targets[0]
    connected = Event()
    request_pid = []

    def late_upload():
        try:
            with factory() as session, session.begin():
                request_pid.append(session.scalar(text("select pg_backend_pid()")))
                connected.set()
                m = mailbox_lock(
                    session,
                    account_id=account_id,
                    device_key_id=device.device_key_id,
                    removed_status=409,
                )
                admit_upload(session, m, VALUE, now=NOW, limits=LIMITS)
        except MailboxRefusal as exc:
            return exc.code, exc.status
        return "stored", 201

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as holder, holder.begin():
            m = mailbox_lock(holder, account_id=account_id, device_key_id=device.device_key_id)
            holder_pid = holder.scalar(text("select pg_backend_pid()"))
            admit_upload(holder, m, VALUE, now=NOW, limits=LIMITS)
            remove_device(
                holder,
                account_id=account_id,
                device_key_id=device.device_key_id,
                removed_by="staff",
                now=datetime.fromtimestamp(NOW, tz=UTC),
                mailbox_enabled=True,
            )
            pending = pool.submit(late_upload)
            assert connected.wait(5)
            observe_block(engine, holder_pid, request_pid[0], pending)
        assert pending.result(timeout=5) == ("device_removed", 409)
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(MailboxBlob)) == 0
        assert session.scalar(select(MailboxCopy.status)) == "removed"
        assert list(session.scalars(select(MailboxEvent.kind).order_by(MailboxEvent.sequence))) == [
            "device_removed",
            "removed",
        ]
