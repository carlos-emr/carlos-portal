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

"""Linking a myCarlos device under concurrent requests, on PostgreSQL (carlos-portal#41, M2-c).

The limits hold because checking a code locks the account row and then the link row: one code
links one device however many requests race, and concurrent wrong codes never count past 5 per
link or 10 per account.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from hashlib import sha256
from itertools import count
from threading import Barrier

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from carlos_patient_portal.database import create_portal_engine
from carlos_patient_portal.device_identity import LinkRequest
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosLinkCode,
    PatientPortalMyCarlosLinkFailure,
    PatientPortalSession,
    utc_now,
)
from carlos_patient_portal.mycarlos_links import create_link_code, link_device
from carlos_patient_portal.token_keys import PortalTokenKeys
from tests import delivery_contract_reference as ref
from tests.test_postgresql_integration import POSTGRES_URL, clean_postgresql_database

pytestmark = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="PORTAL_TEST_POSTGRES_URL is required for PostgreSQL integration tests",
)

LINK_KEY = PortalTokenKeys.derive("p" * 32).mycarlos_link
IDLE = timedelta(minutes=10)
SESSION_NUMBERS = count(1)


def account_with_session(session_factory: sessionmaker) -> tuple[int, int]:
    now = utc_now()
    with session_factory() as session, session.begin():
        account = PatientPortalAccount(
            clinic_id="postgres-clinic",
            demographic_no=6001,
            username="fake.postgres.link",
            email="postgres.link@example.test",
            password_hash="FAKE-not-a-real-hash",
            status="active",
        )
        session.add(account)
        session.flush()
        portal_session = PatientPortalSession(
            account_id=account.id,
            token_hash=sha256(f"FAKE session {next(SESSION_NUMBERS)}".encode()).hexdigest(),
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_seen_at=now,
        )
        session.add(portal_session)
        session.flush()
        return account.id, portal_session.id


def new_code(session_factory: sessionmaker, account_id: int, session_id: int):
    with session_factory() as session, session.begin():
        return create_link_code(
            session,
            account_id=account_id,
            session_id=session_id,
            key=LINK_KEY,
            idle_timeout=IDLE,
        )


def request_for(link_id: str, code: str, label: str) -> LinkRequest:
    device = ref.DeviceKeys(f"postgres {label}")
    return LinkRequest(
        link_id=link_id,
        code=code,
        device_name="myCarlos on Linux",
        x25519_public_key=device.x25519_public,
        ed25519_public_key=device.ed25519_public,
        device_key_id=device.device_key_id,
        assertion_id="not-used-here",
        assertion_expires_at=0,
    )


def wrong(code: str) -> str:
    return ("0" if code[0] != "0" else "1") + code[1:]


def race(session_factory: sessionmaker, requests: list[LinkRequest]) -> list[str]:
    barrier = Barrier(len(requests))

    def attempt(request: LinkRequest) -> str:
        barrier.wait(timeout=10)
        with session_factory() as session, session.begin():
            return link_device(session, request, key=LINK_KEY, idle_timeout=IDLE).code

    with ThreadPoolExecutor(max_workers=len(requests)) as executor:
        return sorted(executor.map(attempt, requests))


def test_postgresql_one_code_links_one_device_when_two_requests_race() -> None:
    assert POSTGRES_URL is not None
    clean_postgresql_database()
    engine = create_portal_engine(POSTGRES_URL)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        account_id, session_id = account_with_session(session_factory)
        issued = new_code(session_factory, account_id, session_id)
        results = race(
            session_factory,
            [request_for(issued.link_id, issued.code, label) for label in ("first", "second")],
        )
        with session_factory() as session:
            devices = session.scalar(select(func.count()).select_from(PatientPortalMyCarlosDevice))
            link = session.scalar(select(PatientPortalMyCarlosLinkCode))
        assert results == ["link_code_invalid", "linked"]
        assert devices == 1
        assert link.status == "used"
    finally:
        engine.dispose()


def test_postgresql_concurrent_wrong_codes_stop_at_five_for_a_link() -> None:
    assert POSTGRES_URL is not None
    clean_postgresql_database()
    engine = create_portal_engine(POSTGRES_URL)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        account_id, session_id = account_with_session(session_factory)
        issued = new_code(session_factory, account_id, session_id)
        results = race(
            session_factory,
            [request_for(issued.link_id, wrong(issued.code), f"wrong {n}") for n in range(8)],
        )
        with session_factory() as session:
            failures = session.scalar(
                select(func.count()).select_from(PatientPortalMyCarlosLinkFailure)
            )
            link = session.scalar(select(PatientPortalMyCarlosLinkCode))
        assert results == ["link_code_invalid"] * 8
        assert (failures, link.wrong_codes) == (5, 5)
    finally:
        engine.dispose()


def test_postgresql_concurrent_wrong_codes_stop_at_ten_for_an_account() -> None:
    assert POSTGRES_URL is not None
    clean_postgresql_database()
    engine = create_portal_engine(POSTGRES_URL)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        account_id, session_id = account_with_session(session_factory)
        codes = [new_code(session_factory, account_id, session_id) for _ in range(3)]
        requests = [
            request_for(issued.link_id, wrong(issued.code), f"account {issued.link_id} {n}")
            for issued in codes
            for n in range(5)
        ]
        results = race(session_factory, requests)
        with session_factory() as session:
            failures = session.scalar(
                select(func.count()).select_from(PatientPortalMyCarlosLinkFailure)
            )
        assert results == ["link_code_invalid"] * 15
        assert failures == 10
    finally:
        engine.dispose()
