# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""The clinic key refresh when the device also sends its vault head link (the mailbox anchor).

Test-only. Real signed HTTP against the shared lifecycle portal (FAKE account, device and keys;
an in-memory database; no network). Pinned: a refresh signed with a `vault_head_link` records one
anchor event for that device and still returns the key list; a refresh the mailbox's byte quota
refuses answers 429 `mailbox_quota_exceeded` with `Retry-After: 60` and leaves the mailbox exactly
as it was (nothing half-written); and with the mailbox disabled the claim is ignored.
"""

from uuid import uuid4

from sqlalchemy import func, select

from carlos_patient_portal.mailbox_models import MailboxClinic, MailboxEvent, MailboxProof
from tests import delivery_contract_reference as ref
from tests.test_link_lifecycle_routes import FIXTURE, NOW, REFRESH, native_portal

ANCHOR = "ab" * 32


def anchored_refresh_headers(anchor=ANCHOR):
    device = ref.DeviceKeys("lifecycle-v1 registered device")
    assert device.device_key_id == FIXTURE["device"]["device_key_id"]
    claims = {
        "aud": ref.DEVICE_AUDIENCE,
        "iss": "mycarlos",
        "kid": device.device_key_id,
        "recipient_id": ref.RECIPIENT_ID,
        "jti": str(uuid4()),
        "iat": NOW,
        "exp": NOW + 60,
        "request_hash": ref.request_hash("GET", REFRESH.encode(), b"", b""),
        "vault_head_link": anchor,
    }
    return {"X-MyCarlos-Device-Assertion": ref.compact_ed25519(device.ed25519, claims)}


def counts(app):
    with app.state.session_factory() as session:
        return tuple(
            session.scalar(select(func.count()).select_from(model))
            for model in (MailboxEvent, MailboxProof)
        )


def test_a_refresh_with_a_vault_head_link_records_one_anchor_and_still_returns_the_keys():
    app, client, _proxy, _account = native_portal(mycarlos_mailbox_enabled=True)

    result = client.get(REFRESH, headers=anchored_refresh_headers())

    assert result.status_code == 200, result.text
    assert len(result.json()["clinic_keys"]) == 2
    with app.state.session_factory() as session:
        events = list(session.scalars(select(MailboxEvent)))
    assert [event.kind for event in events] == ["anchor"]
    assert events[0].device_key_id == FIXTURE["device"]["device_key_id"]
    assert counts(app)[1] == 1


def test_a_refresh_the_mailbox_quota_refuses_is_a_429_and_changes_nothing():
    app, client, _proxy, _account = native_portal(mycarlos_mailbox_enabled=True)
    assert client.get(REFRESH, headers=anchored_refresh_headers()).status_code == 200
    before = counts(app)
    with app.state.session_factory() as session, session.begin():
        clinic = session.scalar(select(MailboxClinic))
        clinic.ordinary_event_bytes = 536870912  # the whole default budget is already used

    result = client.get(REFRESH, headers=anchored_refresh_headers("cd" * 32))

    assert result.status_code == 429, result.text
    assert result.json() == {"code": "mailbox_quota_exceeded"}
    assert result.headers["retry-after"] == "60"
    assert counts(app) == before


def test_the_vault_head_link_is_ignored_while_the_mailbox_is_disabled():
    app, client, _proxy, _account = native_portal(mycarlos_mailbox_enabled=False)

    result = client.get(REFRESH, headers=anchored_refresh_headers())

    assert result.status_code == 200, result.text
    assert counts(app) == (0, 0)
