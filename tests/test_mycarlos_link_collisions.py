"""Link codes and recipient ids that clash with a stored one, and a link whose account is gone.

The ids are random, so a clash is rare: these tests make it certain by fixing the random source, and
check what a caller can rely on. A clash is redrawn; a clash every time is an error and stores
nothing; a link that cannot be tied to its account is refused as "invalid" with nothing counted.
FAKE and synthetic values only; the migrated development app's in-memory database.
"""

from datetime import UTC, datetime, timedelta
from itertools import chain, repeat

import pytest
from sqlalchemy import func, select

from carlos_patient_portal import mycarlos_links as links
from carlos_patient_portal.device_identity import LinkRequest, b64url
from carlos_patient_portal.models import (
    MYCARLOS_LINK_CODE_LENGTH,
    MYCARLOS_LINK_ID_LENGTH,
    PatientPortalAccount,
    PatientPortalMyCarlosLinkCode,
    PatientPortalMyCarlosLinkFailure,
    PatientPortalMyCarlosRecipient,
    PatientPortalSession,
)
from tests.support import migrated_development_app

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)
IDLE = timedelta(minutes=30)
KEY = "k" * 32


def make_account(session, number: int) -> int:
    account = PatientPortalAccount(
        clinic_id="FAKE-clinic",
        demographic_no=7000 + number,
        username=f"fake.link.{number}",
        email=f"fake.link.{number}@example.test",
        password_hash="FAKE-unused-password-hash",
        status="active",
    )
    session.add(account)
    session.flush()
    return account.id


def make_session(session, account_id: int) -> int:
    row = PatientPortalSession(
        account_id=account_id,
        token_hash=f"{account_id}" * 64,
        created_at=NOW - timedelta(minutes=5),
        last_seen_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
    )
    session.add(row)
    session.flush()
    return row.id


def link_count(session) -> int:
    return session.scalar(select(func.count()).select_from(PatientPortalMyCarlosLinkCode))


def fixed_ids(monkeypatch, ids):
    """Every link id drawn comes from `ids` (then the last again); a code is always one value."""
    source = chain(ids, repeat(ids[-1]))

    def draw(length: int) -> str:
        if length == MYCARLOS_LINK_ID_LENGTH:
            return next(source)
        assert length == MYCARLOS_LINK_CODE_LENGTH
        return "Z" * length

    monkeypatch.setattr(links, "random_link_text", draw)


def issue(session, account_id: int, session_id: int):
    return links.create_link_code(
        session,
        account_id=account_id,
        session_id=session_id,
        key=KEY,
        idle_timeout=IDLE,
        now=NOW,
    )


def test_a_link_id_that_clashes_is_drawn_again_and_the_clash_stores_nothing(monkeypatch) -> None:
    app = migrated_development_app(session_secret="t" * 32)
    with app.state.session_factory() as session, session.begin():
        account_id = make_account(session, 1)
        session_id = make_session(session, account_id)
        fixed_ids(monkeypatch, ["AAAAAAAA"])
        assert issue(session, account_id, session_id).link_id == "AAAAAAAA"

    with app.state.session_factory() as session, session.begin():
        # The first draw is the stored id again, the second is free.
        fixed_ids(monkeypatch, ["AAAAAAAA", "BBBBBBBB"])
        second = issue(session, 1, 1)
        assert second.link_id == "BBBBBBBB"
        ids = sorted(session.scalars(select(PatientPortalMyCarlosLinkCode.link_id)))
        assert ids == ["AAAAAAAA", "BBBBBBBB"]


def test_a_link_id_that_clashes_every_time_is_an_error_and_makes_no_link(monkeypatch) -> None:
    app = migrated_development_app(session_secret="t" * 32)
    with app.state.session_factory() as session, session.begin():
        account_id = make_account(session, 1)
        session_id = make_session(session, account_id)
        fixed_ids(monkeypatch, ["AAAAAAAA"])
        issue(session, account_id, session_id)

    with app.state.session_factory() as session:
        # The next code would be "AAAAAAAA" on every one of the attempts there are.
        fixed_ids(monkeypatch, ["AAAAAAAA"])
        with pytest.raises(RuntimeError, match="could not find a free link_id"):
            with session.begin():
                issue(session, 1, 1)

    with app.state.session_factory() as session:
        assert link_count(session) == 1


def recipient_bytes(monkeypatch, values):
    source = chain(values, repeat(values[-1]))
    monkeypatch.setattr(links.secrets, "token_bytes", lambda count: next(source))


def test_a_recipient_id_that_clashes_is_drawn_again_and_an_account_keeps_its_own(
    monkeypatch,
) -> None:
    app = migrated_development_app(session_secret="t" * 32)
    first_bytes, second_bytes = b"\x01" * 16, b"\x02" * 16
    with app.state.session_factory() as session, session.begin():
        first_account, second_account = make_account(session, 1), make_account(session, 2)
        recipient_bytes(monkeypatch, [first_bytes])
        first = links.recipient_id_for(session, first_account)
        assert first == b64url(first_bytes)
        # The second account's first draw is the first account's id: a clash, drawn again.
        recipient_bytes(monkeypatch, [first_bytes, second_bytes])
        second = links.recipient_id_for(session, second_account)
        assert second == b64url(second_bytes) != first
        # Asked again, each gets what it has, and nothing is drawn.
        recipient_bytes(monkeypatch, [b"\x09" * 16])
        assert links.recipient_id_for(session, first_account) == first
        assert links.recipient_id_for(session, second_account) == second
        owners = sorted(session.scalars(select(PatientPortalMyCarlosRecipient.account_id)))
        assert owners == sorted([first_account, second_account])


def test_a_recipient_id_that_clashes_every_time_is_an_error_and_makes_none(monkeypatch) -> None:
    app = migrated_development_app(session_secret="t" * 32)
    with app.state.session_factory() as session, session.begin():
        first_account, second_account = make_account(session, 1), make_account(session, 2)
        recipient_bytes(monkeypatch, [b"\x01" * 16])
        links.recipient_id_for(session, first_account)
        with pytest.raises(RuntimeError, match="could not make a recipient ID"):
            links.recipient_id_for(session, second_account)
        owners = list(session.scalars(select(PatientPortalMyCarlosRecipient.account_id)))
        assert owners == [first_account]


def link_request(link_id: str, code: str = "Z" * MYCARLOS_LINK_CODE_LENGTH) -> LinkRequest:
    return LinkRequest(
        link_id=link_id,
        code=code,
        device_name="FAKE device",
        x25519_public_key=b"\x03" * 32,
        ed25519_public_key=b"\x04" * 32,
        device_key_id="FAKE-device-key-id",
        assertion_id="FAKE-assertion",
        assertion_expires_at=1_900_000_000,
    )


@pytest.mark.parametrize("lock", ["no account", "another account"])
def test_a_link_that_cannot_be_tied_to_its_account_is_invalid_and_counts_nothing(
    monkeypatch, lock
) -> None:
    app = migrated_development_app(session_secret="t" * 32)
    with app.state.session_factory() as session, session.begin():
        account_id = make_account(session, 1)
        other_id = make_account(session, 2)
        session_id = make_session(session, account_id)
        fixed_ids(monkeypatch, ["AAAAAAAA"])
        issue(session, account_id, session_id)

    with app.state.session_factory() as session, session.begin():
        # The code exists, but the account it names is not the one that is locked for the link:
        # gone between the two reads (no account), or a different row (another account).
        if lock == "no account":
            monkeypatch.setattr(links, "_lock_account", lambda session, account_id: None)
        else:
            monkeypatch.setattr(
                links,
                "_lock_account",
                lambda session, account_id: session.get(PatientPortalAccount, other_id),
            )
        result = links.link_device(
            session, link_request("AAAAAAAA"), key=KEY, idle_timeout=IDLE, now=NOW
        )
        assert result.code == links.LINK_RESULT_CODE_INVALID
        assert result.account_id is None and result.device is None
        # Nothing about this was counted against anyone: no wrong code, no failure row.
        assert session.scalar(select(func.count(PatientPortalMyCarlosLinkFailure.id))) == 0
        assert session.scalar(select(PatientPortalMyCarlosLinkCode.wrong_codes)) == 0
