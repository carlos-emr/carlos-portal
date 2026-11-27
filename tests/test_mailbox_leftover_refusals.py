"""The mailbox's small refusals that no test drove: a counter at its limit, a delivery id that is
not a version 4 UUID, an assertion of the wrong size, a cursor behind what is retained, a
per-minute window that rolls over, and the terminal-copy pruner's argument checks.

Each is a function of plain values (or of one small SQLite row), so none needs the signed-HTTP
harness. Synthetic ids and keys only.
"""

from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from carlos_patient_portal import mailbox
from carlos_patient_portal.mailbox_codec import LONG_MAX, MailboxRefusal
from carlos_patient_portal.mailbox_models import MailboxBase, MailboxClinic, MailboxRate


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    MailboxBase.metadata.create_all(engine)
    with Session(engine) as opened:
        yield opened
    engine.dispose()


def refusal_of(callable_, *args, **kwargs):
    with pytest.raises(MailboxRefusal) as caught:
        callable_(*args, **kwargs)
    return caught.value


def test_a_sequence_counter_at_its_limit_refuses_and_stays_put():
    # The last value a signed 64-bit counter can hold is handed out; the next request is refused.
    row = SimpleNamespace(event_sequence=LONG_MAX - 1)
    assert mailbox.next_sequence(row, "event_sequence") == LONG_MAX
    assert row.event_sequence == LONG_MAX
    refused = refusal_of(mailbox.next_sequence, row, "event_sequence")
    assert (refused.code, refused.status) == ("mailbox_quota_exceeded", 429)
    assert row.event_sequence == LONG_MAX, "a refused request must not move the counter"


@pytest.mark.parametrize(
    "delivery_id",
    [
        "",
        "not-a-uuid",
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",  # a version 1 UUID: well formed, wrong kind
        "6BA7B810-9DAD-41D1-80B4-00C04FD430C8",  # not in canonical (lower case) form
        "6ba7b8109dad41d180b400c04fd430c8",  # no hyphens
        None,
        7,
    ],
)
def test_a_delivery_id_that_is_not_a_canonical_version_4_uuid_finds_nothing(delivery_id):
    # It is refused before any row is read, so no session is needed.
    refused = refusal_of(mailbox.copy_lock, None, SimpleNamespace(), delivery_id)
    assert (refused.code, refused.status) == ("delivery_not_found", 404)


@pytest.mark.parametrize("size", [0, 4097, 10_000])
def test_a_request_assertion_of_the_wrong_size_is_not_retained(size):
    m = SimpleNamespace(device=SimpleNamespace(device_key_id="FAKE-device-key"))
    refused = refusal_of(mailbox.retain_proof, None, m, "a" * size, 0)
    assert (refused.code, refused.status) == ("invalid_assertion", 404)


def test_a_cursor_behind_what_the_clinic_retains_is_too_old_and_one_ahead_is_invalid():
    clinic = MailboxClinic(
        clinic_id="FAKE-clinic", event_sequence=9, acked_through=5, retained_floor=5
    )
    # Neither refusal reads a row or counts against the page rate, so there is no session.
    too_old = refusal_of(
        mailbox.events_page, None, clinic, after=4, limit=10, now=0, limits=SimpleNamespace()
    )
    assert (too_old.code, too_old.status) == ("cursor_too_old", 409)
    ahead = refusal_of(
        mailbox.events_page, None, clinic, after=10, limit=10, now=0, limits=SimpleNamespace()
    )
    assert (ahead.code, ahead.status) == ("invalid_cursor", 400)


def test_a_cursor_exactly_at_the_floor_or_at_the_last_event_is_a_valid_empty_page(session):
    clinic = MailboxClinic(
        clinic_id="FAKE-clinic", event_sequence=9, acked_through=5, retained_floor=5
    )
    session.add(clinic)
    session.flush()
    limits = SimpleNamespace(clinic_sync_pages_per_minute=10)
    # The floor itself is the oldest cursor still served, and the last sequence is the newest one a
    # caller can hold: neither is refused, and there is nothing past them in this empty mailbox.
    for cursor in (5, 9):
        page = mailbox.events_page(session, clinic, after=cursor, limit=10, now=0, limits=limits)
        assert page == {"events": [], "last_sequence": str(cursor), "next_cursor": None}


def test_a_per_minute_window_counts_refuses_at_its_maximum_and_starts_over_next_minute(session):
    clinic = MailboxClinic(clinic_id="FAKE-clinic")
    session.add(clinic)
    session.flush()
    window = {"maximum": 2}
    mailbox.rate(session, clinic, "events", now=120, **window)
    mailbox.rate(session, clinic, "events", now=179, **window)
    refused = refusal_of(mailbox.rate, session, clinic, "events", now=179, **window)
    assert (refused.code, refused.status) == ("mailbox_quota_exceeded", 429)
    row = session.get(MailboxRate, ("FAKE-clinic", "events"))
    assert (row.minute, row.count) == (2, 2), "a refusal must not add to the count"
    # The next minute is a fresh window: the count and the bytes go back to zero first.
    mailbox.rate(session, clinic, "events", now=180, **window)
    row = session.get(MailboxRate, ("FAKE-clinic", "events"), populate_existing=True)
    assert (row.minute, row.count, row.bytes) == (3, 1, 0)


def test_a_window_of_bytes_refuses_what_would_pass_its_maximum_and_rolls_over_too(session):
    clinic = MailboxClinic(clinic_id="FAKE-clinic")
    session.add(clinic)
    session.flush()
    mailbox.rate(session, clinic, "uploads", now=0, maximum=10, byte_count=60, maximum_bytes=100)
    refused = refusal_of(
        mailbox.rate, session, clinic, "uploads", now=59, maximum=10, byte_count=41,
        maximum_bytes=100,
    )  # fmt: skip
    assert refused.code == "mailbox_quota_exceeded"
    # Exactly at the maximum is allowed, and the next minute starts with no bytes counted.
    mailbox.rate(session, clinic, "uploads", now=59, maximum=10, byte_count=40, maximum_bytes=100)
    mailbox.rate(session, clinic, "uploads", now=60, maximum=10, byte_count=100, maximum_bytes=100)
    row = session.get(MailboxRate, ("FAKE-clinic", "uploads"), populate_existing=True)
    assert (row.minute, row.count, row.bytes) == (1, 1, 100)


@pytest.mark.parametrize("retention_days", [0, -1, 1.5, "7", None, True])
def test_the_terminal_copy_pruner_refuses_a_retention_that_is_not_a_positive_integer(
    retention_days,
):
    with pytest.raises(ValueError, match="retention_days must be a positive integer"):
        mailbox.prune_terminal_copies(None, retention_days=retention_days)


@pytest.mark.parametrize("limit", [0, 101, -5, 1.5, "10", True])
def test_the_terminal_copy_pruner_refuses_a_limit_outside_one_to_one_hundred(limit):
    with pytest.raises(ValueError, match="limit must be an integer between 1 and 100"):
        mailbox.prune_terminal_copies(None, retention_days=1, limit=limit)
