# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""The unlock-secret service's refusals: a damaged word list, a secret that is not text, a scope
that does not match, and every input check. FAKE data only.

Nothing here prints or returns a stored secret: a refusal carries a fixed sentence about what was
wrong with the input, never the input.
"""

import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from carlos_patient_portal import unlock_secrets
from carlos_patient_portal.models import PatientPortalUnlockSecret
from carlos_patient_portal.unlock_secrets import (
    ENCRYPTION_ALGORITHM,
    ENCRYPTION_ALGORITHM_V1,
    MAX_UNLOCK_SECRET_PLAINTEXT_BYTES,
    UnlockSecretDecryptionError,
    UnlockSecretNotFoundError,
    build_associated_data,
    create_unlock_secret,
    decrypt_unlock_secret_payload,
    derive_unlock_secret_key,
    get_scoped_unlock_secret,
    load_unlock_secret_words,
    normalize_account_id,
    normalize_actor_type,
    normalize_demographic_no,
    normalize_optional_text,
    normalize_required_text,
    normalize_unlock_secret_type,
    resolve_account_id,
    validate_plaintext_secret,
)
from tests.support import MIN_PRODUCTION_SECRET_LENGTH, upgrade_to_head

SECRET = "s" * MIN_PRODUCTION_SECRET_LENGTH


# --------------------------------------------------------------------------------------------
# The word list
# --------------------------------------------------------------------------------------------


@pytest.fixture
def wordlist(monkeypatch, tmp_path):
    """A word list file of the test's own, read in place of the shipped one."""

    def use(text: str) -> None:
        path = tmp_path / "words.txt"
        path.write_text(text, encoding="utf-8")
        # An absolute path replaces the package directory in `Path(...) / resource`.
        monkeypatch.setattr(unlock_secrets, "UNLOCK_SECRET_WORDLIST_RESOURCE", str(path))
        load_unlock_secret_words.cache_clear()

    yield use
    load_unlock_secret_words.cache_clear()


def test_a_word_list_row_out_of_order_or_not_a_numbered_word_is_refused(wordlist) -> None:
    for text in (
        "0001\tapple\n",  # the first row must be 0000
        "0000\tapple\n0002\tberry\n",  # a number skipped
        "apple\n",  # not "number<TAB>word"
        "0000 apple\n",  # a space, not a tab
        "00000\tapple\n",
    ):
        wordlist(text)
        with pytest.raises(RuntimeError, match="invalid row"):
            load_unlock_secret_words()


def test_a_word_that_is_not_lower_case_letters_is_refused_before_it_is_used(
    wordlist, monkeypatch
) -> None:
    # The row pattern already requires letters, so the word check is the second guard: it is
    # reached through a row pattern that lets one through.
    monkeypatch.setattr(
        unlock_secrets, "UNLOCK_SECRET_WORDLIST_ROW_PATTERN", re.compile(r"^(\d{4})\t(.+)$")
    )
    wordlist("0000\tApple9\n")
    with pytest.raises(RuntimeError, match="invalid word"):
        load_unlock_secret_words()


def numbered_word(number: int) -> str:
    """A four-letter lower-case word for `number` (base 26), so all 4096 are different."""
    return "".join(chr(ord("a") + (number // 26**place) % 26) for place in range(4))


def test_a_word_list_of_the_right_size_with_a_repeated_word_is_refused(wordlist) -> None:
    rows = [f"{number:04d}\t{numbered_word(number)}" for number in range(4096)]
    wordlist("\n".join(rows) + "\n")
    assert len(set(load_unlock_secret_words())) == 4096  # the control: all different is accepted
    # Row 5 repeats row 4's word: still 4096 well-formed rows, but fewer than 4096 different words,
    # which would lower the entropy of every generated secret.
    rows[5] = f"0005\t{numbered_word(4)}"
    wordlist("\n".join(rows) + "\n")
    with pytest.raises(RuntimeError, match="must contain 4096 unique words"):
        load_unlock_secret_words()


def test_comments_and_blank_lines_are_skipped_and_the_wrong_size_is_refused(wordlist) -> None:
    wordlist("# a comment\n\n0000\tapple\n")
    with pytest.raises(RuntimeError, match="must contain 4096 unique words"):
        load_unlock_secret_words()


def test_the_shipped_word_list_is_the_right_size_and_all_lower_case_letters() -> None:
    load_unlock_secret_words.cache_clear()
    words = load_unlock_secret_words()
    assert len(words) == 4096 and len(set(words)) == 4096
    assert all(word.isalpha() and word.islower() for word in words)


# --------------------------------------------------------------------------------------------
# Decrypting
# --------------------------------------------------------------------------------------------


def stored(plaintext: bytes, *, context: str | None) -> PatientPortalUnlockSecret:
    """A secret as the table holds it, made the way the service makes one, from `plaintext`."""
    nonce = b"n" * 12
    data = build_associated_data(
        clinic_id="default",
        demographic_no=7,
        secret_type="email",
        encryption_key_id="primary",
        encryption_context=context,
    )
    return PatientPortalUnlockSecret(
        clinic_id="default",
        demographic_no=7,
        secret_type="email",
        encryption_key_id="primary",
        encryption_context=context,
        encryption_algorithm=ENCRYPTION_ALGORITHM if context else ENCRYPTION_ALGORITHM_V1,
        encryption_nonce=nonce,
        encrypted_secret=AESGCM(derive_unlock_secret_key(SECRET)).encrypt(nonce, plaintext, data),
    )


@pytest.mark.parametrize("context", [str(uuid.uuid4()), None])
def test_a_secret_that_decrypts_but_is_not_utf8_text_is_a_decryption_error(context) -> None:
    row = stored(b"\xff\xfe\xfa", context=context)
    with pytest.raises(UnlockSecretDecryptionError, match="not valid UTF-8"):
        decrypt_unlock_secret_payload(row, encryption_secret=SECRET)
    # The same row with text in it reads back (so it was the bytes, not the setup).
    ok = stored(b"fake secret", context=context)
    assert decrypt_unlock_secret_payload(ok, encryption_secret=SECRET) == "fake secret"


def test_the_associated_data_names_the_scope_and_a_bad_context_is_refused() -> None:
    first = build_associated_data(
        clinic_id="default", demographic_no=7, secret_type="email", encryption_key_id="primary"
    )
    assert first == b"carlos-patient-portal.unlock-secret.v1|default|7|email|primary"
    context = str(uuid.uuid4())
    second = build_associated_data(
        clinic_id="default",
        demographic_no=7,
        secret_type="EMAIL",
        encryption_key_id="primary",
        encryption_context=context,
    )
    assert (
        second
        == f"carlos-patient-portal.unlock-secret.v2|default|7|email|primary|{context}".encode()
    )
    for bad in ("short", "x" * 35, " " + "x" * 35):
        with pytest.raises(UnlockSecretDecryptionError, match="encryption context is invalid"):
            build_associated_data(
                clinic_id="default",
                demographic_no=7,
                secret_type="email",
                encryption_key_id="primary",
                encryption_context=bad,
            )


def test_an_encryption_secret_that_is_too_short_is_refused() -> None:
    derive_unlock_secret_key.cache_clear()
    with pytest.raises(ValueError, match="at least"):
        derive_unlock_secret_key("short")
    assert len(derive_unlock_secret_key(SECRET)) == 32


# --------------------------------------------------------------------------------------------
# What may be asked for
# --------------------------------------------------------------------------------------------


def test_a_secret_must_have_text_within_its_size_limit() -> None:
    assert validate_plaintext_secret("ok") == "ok"
    for blank in ("", "   ", "\n\t"):
        with pytest.raises(ValueError, match="must not be blank"):
            validate_plaintext_secret(blank)
    with pytest.raises(ValueError, match=f"{MAX_UNLOCK_SECRET_PLAINTEXT_BYTES} bytes or fewer"):
        validate_plaintext_secret("é" * (MAX_UNLOCK_SECRET_PLAINTEXT_BYTES // 2 + 1))
    # The limit is in bytes, not characters.
    assert validate_plaintext_secret("é" * (MAX_UNLOCK_SECRET_PLAINTEXT_BYTES // 2))


def test_the_small_normalizers_refuse_what_is_not_theirs() -> None:
    assert normalize_unlock_secret_type(" PDF ") == "pdf"
    with pytest.raises(ValueError, match="secret_type must be email or pdf"):
        normalize_unlock_secret_type("sms")
    assert normalize_actor_type(" Staff ") == "staff"
    with pytest.raises(ValueError, match="actor_type must be patient or staff"):
        normalize_actor_type("system")
    for number in (0, -1, 10**12):
        with pytest.raises(ValueError, match="demographic_no must be between"):
            normalize_demographic_no(number)
    with pytest.raises(ValueError, match="account_id must be positive"):
        normalize_account_id(0)
    assert normalize_account_id(3) == 3


def test_required_and_optional_text_are_trimmed_bounded_and_named() -> None:
    assert normalize_required_text(" a ", field_name="x", max_length=3) == "a"
    with pytest.raises(ValueError, match="x must not be blank"):
        normalize_required_text("  ", field_name="x", max_length=3)
    with pytest.raises(ValueError, match="x must be 3 characters or fewer"):
        normalize_required_text("abcd", field_name="x", max_length=3)
    assert normalize_optional_text(None, field_name="x", max_length=3) is None
    assert normalize_optional_text("   ", field_name="x", max_length=3) is None
    assert normalize_optional_text(" ab ", field_name="x", max_length=3) == "ab"
    with pytest.raises(ValueError, match="x must be 3 characters or fewer"):
        normalize_optional_text("abcd", field_name="x", max_length=3)


def test_a_date_range_that_ends_before_it_starts_is_refused() -> None:
    now = datetime(2026, 7, 1, tzinfo=UTC)
    statement = unlock_secrets._filtered_unlock_secret_statement
    assert (
        statement(
            clinic_id="default",
            demographic_no=7,
            created_from=now,
            created_before=now + timedelta(days=1),
        )
        is not None
    )
    for before in (now, now - timedelta(days=1)):
        with pytest.raises(ValueError, match="created_from must be earlier than created_before"):
            statement(
                clinic_id="default", demographic_no=7, created_from=now, created_before=before
            )


def test_a_secret_with_an_unknown_initial_status_is_refused_before_anything_is_stored() -> None:
    engine = create_engine("sqlite://", poolclass=StaticPool)
    with Session(engine) as session:
        with pytest.raises(ValueError, match="initial_status must be pending or available"):
            create_unlock_secret(
                session,
                clinic_id="default",
                demographic_no=7,
                created_by="Front Desk",
                encryption_secret=SECRET,
                secret="fake-secret",
                initial_status="revoked",
            )


def test_a_non_positive_id_is_not_found_and_an_account_must_match_its_patient() -> None:
    engine = create_engine("sqlite://", poolclass=StaticPool)
    upgrade_to_head(engine)
    with Session(engine) as session:
        for bad_id in (0, -5):
            with pytest.raises(UnlockSecretNotFoundError):
                get_scoped_unlock_secret(session, bad_id, clinic_id="default")
        # No account exists: naming one is a mismatch, naming none is just "no account".
        with pytest.raises(ValueError, match="account_id does not match"):
            resolve_account_id(session, clinic_id="default", demographic_no=7, account_id=5)
        assert (
            resolve_account_id(session, clinic_id="default", demographic_no=7, account_id=None)
            is None
        )
