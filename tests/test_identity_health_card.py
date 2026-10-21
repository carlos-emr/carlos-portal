"""Health card matching at activation: a trailing version code is not part of the number (#23)."""

from datetime import date

import pytest

from carlos_patient_portal.identity import (
    IdentityProof,
    build_identity_hashes,
    health_card_number_candidates,
    verify_identity_proof,
)

SECRET = "test-identity-proof-secret-0000000001"
SALT = "test-salt"


def stored_hashes(health_card_number: str) -> dict[str, str]:
    return build_identity_hashes(
        IdentityProof(
            email="patient@example.com",
            date_of_birth=date(1985, 6, 15),
            health_card_number=health_card_number,
        ),
        SECRET,
        SALT,
    )


def matches(typed: str, stored: str) -> bool:
    hashes = stored_hashes(stored)
    return verify_identity_proof(
        IdentityProof(
            email="patient@example.com",
            date_of_birth=date(1985, 6, 15),
            health_card_number=typed,
        ),
        SECRET,
        salt=SALT,
        email_hash=hashes["proof_email_hash"],
        date_of_birth_hash=hashes["proof_date_of_birth_hash"],
        health_card_hash=hashes["proof_health_card_hash"],
    )


@pytest.mark.parametrize(
    "typed",
    ["1234567890", "1234-567-890", "1234-567-890-AB", "1234 567 890 ab", "1234567890A"],
)
def test_health_card_matches_with_or_without_its_version_code(typed: str) -> None:
    assert matches(typed, "1234567890")


@pytest.mark.parametrize(
    "typed",
    [
        "1234567891",  # a different number
        "12345678901",  # an extra digit
        "12345678901AB",  # an extra digit before the code
        "1234567890ABC",  # three letters is not a version code
        "123456789AB0",  # letters inside the number
        "AB1234567890",  # letters in front
    ],
)
def test_health_card_still_refuses_another_number(typed: str) -> None:
    assert not matches(typed, "1234567890")


def test_a_stored_number_with_its_version_code_still_matches_as_typed() -> None:
    assert matches("1234-567-890-AB", "1234567890AB")


def test_a_number_that_is_only_letters_and_digits_keeps_its_own_ending() -> None:
    # A number that does not end in letters after a digit has only itself as a candidate.
    assert health_card_number_candidates("ABCD12345678") == ("ABCD12345678",)
    assert health_card_number_candidates("1234567890AB") == ("1234567890AB", "1234567890")
