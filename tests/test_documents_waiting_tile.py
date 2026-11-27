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

"""The dashboard's Documents tile: a live count of deliveries waiting for the patient's devices.

Only a number is ever shown: no document name, kind or clinic detail. A removed device's copies and
another patient's copies are never counted. Synthetic accounts and values only.
"""

import re
from datetime import UTC, datetime, timedelta
from itertools import count

import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal.i18n import (
    LOCALE_COOKIE_NAME,
    SUPPORTED_LOCALES,
    plural_text,
    portal_text,
)
from carlos_patient_portal.mailbox_models import MailboxCopy
from carlos_patient_portal.models import PatientPortalAccount, PatientPortalMyCarlosDevice
from carlos_patient_portal.mycarlos_waiting import (
    count_waiting_for_account,
    has_active_device,
    waiting_copy_conditions,
)
from tests.support import browser_sign_in_seeded_patient, migrated_development_app

NOW = datetime.now(UTC)
SEQUENCES = count(1)
KEY_NUMBERS = count(1)
TILE_TEXT = re.compile(r'<p id="tile-documents-description">([^<]*)</p>')


def tile_app(**overrides: object):
    return migrated_development_app(
        mycarlos_delivery_enabled=True,
        mycarlos_mailbox_enabled=True,
        **overrides,
    )


def signed_in(app) -> tuple[TestClient, int]:
    client = TestClient(app)
    return client, browser_sign_in_seeded_patient(app, client)


def add_account(app, number: int) -> int:
    with app.state.session_factory() as session, session.begin():
        account = PatientPortalAccount(
            clinic_id="clinic-a",
            demographic_no=7000 + number,
            username=f"fake.other{number}",
            email=f"other{number}@example.test",
            password_hash="FAKE-not-a-real-hash",
            status="active",
        )
        session.add(account)
        session.flush()
        return account.id


def add_device(app, account_id: int, *, removed: bool = False) -> int:
    number = next(KEY_NUMBERS)
    with app.state.session_factory() as session, session.begin():
        device = PatientPortalMyCarlosDevice(
            account_id=account_id,
            device_key_id=f"FAKE{number:039d}",
            x25519_public_key=bytes([number % 251]) * 32,
            ed25519_public_key=bytes([(number + 1) % 251]) * 32,
            device_name="myCarlos on Linux",
            status="removed" if removed else "active",
            linked_at=NOW - timedelta(days=3),
            removed_at=NOW - timedelta(days=1) if removed else None,
            removed_by="patient" if removed else None,
        )
        session.add(device)
        session.flush()
        return device.id


def add_copy(
    app,
    device_id: int,
    *,
    account_id: int | None = None,
    expires_in: int = 3600,
    status: str = "waiting",
    clinic_id: str = "clinic-a",
) -> None:
    sequence = next(SEQUENCES)
    with app.state.session_factory() as session, session.begin():
        device = session.get(PatientPortalMyCarlosDevice, device_id)
        terminal = status != "waiting"
        session.add(
            MailboxCopy(
                account_id=device.account_id if account_id is None else account_id,
                device_id=device_id,
                clinic_id=clinic_id,
                recipient_id="FAKE-recipient",
                device_key_id=device.device_key_id,
                delivery_id=f"00000000-0000-4000-8000-{sequence:012d}",
                sequence=sequence,
                size=49,
                ciphertext_sha256="c" * 64,
                body_sha256="b" * 64,
                created_at=int(NOW.timestamp()) - 60,
                expires_at=int(NOW.timestamp()) + expires_in,
                status=status,
                terminal_at=int(NOW.timestamp()) - 30 if terminal else None,
                receipt_sha256="d" * 64 if status == "picked_up" else None,
            )
        )


def tile(client: TestClient) -> str:
    page = client.get("/portal").text
    match = TILE_TEXT.search(page)
    assert match is not None, "no live Documents tile on the dashboard"
    return match.group(1)


# --- The tile's states ------------------------------------------------------------------------


def test_with_no_linked_device_the_tile_links_to_the_link_page() -> None:
    app = tile_app()
    client, _ = signed_in(app)
    page = client.get("/portal").text
    assert tile(client) == "Link myCarlos to receive your documents on your device."
    link = re.search(
        r'<a class="module-tile" href="([^"]*)" aria-labelledby="tile-documents-title"', page
    )
    assert link is not None and link.group(1).endswith("/portal/mycarlos")
    assert "waiting" not in tile(client)


def test_a_device_with_nothing_waiting_says_so() -> None:
    app = tile_app()
    client, account_id = signed_in(app)
    add_device(app, account_id)
    assert tile(client) == "Nothing is waiting."


def test_one_waiting_document_uses_the_singular() -> None:
    app = tile_app()
    client, account_id = signed_in(app)
    add_copy(app, add_device(app, account_id))
    assert tile(client) == "1 document is waiting for you. Open myCarlos to receive it."


def test_many_waiting_documents_use_the_plural_across_all_active_devices() -> None:
    app = tile_app()
    client, account_id = signed_in(app)
    first, second = add_device(app, account_id), add_device(app, account_id)
    add_copy(app, first)
    add_copy(app, first)
    add_copy(app, second)
    assert tile(client) == "3 documents are waiting for you. Open myCarlos to receive them."


def test_the_tile_is_a_link_with_an_accessible_name_and_description() -> None:
    app = tile_app()
    client, account_id = signed_in(app)
    add_copy(app, add_device(app, account_id))
    page = client.get("/portal").text
    assert re.search(
        r'<a class="module-tile" href="[^"]*/portal/mycarlos" '
        r'aria-labelledby="tile-documents-title" aria-describedby="tile-documents-description">',
        page,
    )
    assert '<h2 id="tile-documents-title">Documents</h2>' in page
    assert 'id="tile-documents-description"' in page
    # No longer the greyed "Future" tile.
    assert "Documents may be available in a future release." not in page
    assert "module-tile disabled" not in page.split('id="tile-documents-title"')[0][-200:]


# --- Who and what is counted -----------------------------------------------------------------


def test_a_removed_devices_copies_are_not_counted() -> None:
    app = tile_app()
    client, account_id = signed_in(app)
    active, removed = add_device(app, account_id), add_device(app, account_id, removed=True)
    add_copy(app, active)
    add_copy(app, removed)
    add_copy(app, removed)
    assert tile(client) == "1 document is waiting for you. Open myCarlos to receive it."


def test_only_removed_devices_means_no_device_and_the_link_text() -> None:
    app = tile_app()
    client, account_id = signed_in(app)
    add_copy(app, add_device(app, account_id, removed=True))
    assert tile(client) == "Link myCarlos to receive your documents on your device."


def test_another_patients_copies_are_never_counted() -> None:
    app = tile_app()
    client, account_id = signed_in(app)
    mine = add_device(app, account_id)
    other_account = add_account(app, 1)
    theirs = add_device(app, other_account)
    add_copy(app, theirs)
    add_copy(app, theirs)
    # Even a copy that names this account but sits on the other patient's device is not counted.
    add_copy(app, theirs, account_id=account_id)
    assert tile(client) == "Nothing is waiting."
    add_copy(app, mine)
    assert tile(client) == "1 document is waiting for you. Open myCarlos to receive it."


def test_expired_and_already_received_copies_are_not_counted() -> None:
    app = tile_app()
    client, account_id = signed_in(app)
    device = add_device(app, account_id)
    add_copy(app, device, expires_in=-1)
    add_copy(app, device, status="picked_up")
    add_copy(app, device, status="removed")
    add_copy(app, device, status="expired")
    assert tile(client) == "Nothing is waiting."
    add_copy(app, device)
    assert tile(client) == "1 document is waiting for you. Open myCarlos to receive it."


def test_the_page_shows_only_a_number_never_a_name_a_kind_or_a_clinic() -> None:
    app = tile_app(clinic_name="FAKE Clinic Alpha")
    client, account_id = signed_in(app)
    device = add_device(app, account_id)
    add_copy(app, device, clinic_id="FAKE-secret-clinic-id")
    page = client.get("/portal").text
    for private in (
        "FAKE-secret-clinic-id",
        "FAKE-recipient",
        "00000000-0000-4000-8000",
        "ciphertext",
    ):
        assert private not in page
    assert tile(client) == "1 document is waiting for you. Open myCarlos to receive it."


# --- When the feature is off -----------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"mycarlos_delivery_enabled": False, "mycarlos_mailbox_enabled": False},
        {"mycarlos_delivery_enabled": True, "mycarlos_mailbox_enabled": False},
    ],
)
def test_with_delivery_or_the_mailbox_off_the_greyed_future_tile_stays(overrides) -> None:
    app = migrated_development_app(**overrides)
    client, _ = signed_in(app)
    page = client.get("/portal").text
    assert "tile-documents-title" not in page
    assert "Documents may be available in a future release." in page
    assert "<span>Future</span>" in page


def test_the_count_is_only_read_for_the_dashboard() -> None:
    app = tile_app()
    client, account_id = signed_in(app)
    add_copy(app, add_device(app, account_id))
    assert "tile-documents-title" not in client.get("/portal/help").text
    assert "tile-documents-title" in client.get("/portal").text


# --- Every language, every plural form -------------------------------------------------------


@pytest.mark.parametrize("option", SUPPORTED_LOCALES, ids=lambda option: option.code)
@pytest.mark.parametrize("waiting", [0, 1, 2, 5, 22])
def test_the_sentence_is_right_in_every_language_and_plural_form(option, waiting: int) -> None:
    app = tile_app()
    client, account_id = signed_in(app)
    device = add_device(app, account_id)
    for _ in range(waiting):
        add_copy(app, device)
    client.cookies.set(LOCALE_COOKIE_NAME, option.code)
    text = portal_text(option.code)
    if waiting == 0:
        expected = text["documents_nothing_waiting"]
    else:
        expected = plural_text(text, "documents_waiting", waiting, option.code).format(
            count=waiting
        )
    assert tile(client) == expected.replace("’", "&#39;") or tile(client) == expected
    assert str(waiting) in expected or waiting == 0
    assert text["documents_link_mycarlos"].strip()


def test_the_polish_forms_are_one_few_and_many() -> None:
    text = portal_text("pl")
    one = plural_text(text, "documents_waiting", 1, "pl")
    few = plural_text(text, "documents_waiting", 3, "pl")
    many = plural_text(text, "documents_waiting", 7, "pl")
    assert len({one, few, many}) == 3
    assert "dokumenty" in few and "dokumentów" in many


# --- The query itself ------------------------------------------------------------------------


def test_the_waiting_definition_is_shared_and_expiry_is_exclusive() -> None:
    app = tile_app()
    _, account_id = signed_in(app)
    device = add_device(app, account_id)
    add_copy(app, device, expires_in=0)
    expiry = datetime.fromtimestamp(int(NOW.timestamp()), tz=UTC)
    with app.state.session_factory() as session:
        # A copy expiring this very second is no longer waiting, as in the waiting answer.
        assert count_waiting_for_account(session, account_id, now=expiry) == 0
        assert (
            count_waiting_for_account(session, account_id, now=expiry - timedelta(seconds=1)) == 1
        )
    status_condition, expiry_condition = waiting_copy_conditions(expiry)
    assert status_condition.right.value == "waiting"
    assert expiry_condition.right.value == int(expiry.timestamp())


def test_has_active_device_ignores_removed_and_other_accounts() -> None:
    app = tile_app()
    _, account_id = signed_in(app)
    other = add_account(app, 2)
    add_device(app, other)
    add_device(app, account_id, removed=True)
    with app.state.session_factory() as session:
        assert has_active_device(session, account_id) is False
        assert has_active_device(session, other) is True
    add_device(app, account_id)
    with app.state.session_factory() as session:
        assert has_active_device(session, account_id) is True
