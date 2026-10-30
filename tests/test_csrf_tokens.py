"""CSRF lifetime and double-submit checks must hold even for otherwise authentic tokens."""

import pytest

from carlos_patient_portal import web_support

FAKE_SECRET = "FAKE csrf signing key used only in unit tests"
NOW = 1_800_000_000


@pytest.fixture
def clock(monkeypatch):
    current_time = [NOW]
    monkeypatch.setattr(web_support, "time", lambda: current_time[0])
    return current_time


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (0, True),
        (web_support.CSRF_TOKEN_TTL_SECONDS, True),
        (web_support.CSRF_TOKEN_TTL_SECONDS + 1, False),
        (-web_support.CSRF_FUTURE_SKEW_SECONDS, True),
        (-web_support.CSRF_FUTURE_SKEW_SECONDS - 1, False),
    ],
)
def test_authentic_csrf_tokens_obey_expiry_and_clock_skew_boundaries(clock, age, expected):
    clock[0] = NOW - age
    token = web_support.create_csrf_token(FAKE_SECRET)
    clock[0] = NOW

    assert web_support.is_valid_csrf_token(token, FAKE_SECRET) is expected


@pytest.mark.parametrize("token", [None, "", "FAKE token without separators"])
def test_missing_or_incomplete_csrf_tokens_are_refused(clock, token):
    assert web_support.is_valid_csrf_token(token, FAKE_SECRET) is False


@pytest.mark.parametrize("message", [f"{NOW}.", ".FAKE_nonce", "not-a-time.FAKE_nonce"])
def test_a_valid_signature_does_not_make_an_invalid_csrf_message_acceptable(clock, message):
    signature = web_support.sign_csrf_token(message, FAKE_SECRET)

    assert web_support.is_valid_csrf_token(f"{message}.{signature}", FAKE_SECRET) is False


@pytest.mark.parametrize("changed_part", ["timestamp", "nonce", "signature"])
def test_changing_any_signed_token_part_invalidates_the_token(clock, changed_part):
    token = web_support.create_csrf_token(FAKE_SECRET)
    timestamp, nonce, signature = token.split(".")
    if changed_part == "timestamp":
        # Remain inside the allowed skew so this must fail authentication, not age checking.
        timestamp = str(NOW + 1)
    elif changed_part == "nonce":
        nonce += "FAKE_tampering"
    else:
        signature = ("0" if signature[0] != "0" else "1") + signature[1:]

    assert web_support.is_valid_csrf_token(f"{timestamp}.{nonce}.{signature}", FAKE_SECRET) is False


def test_rotating_the_secret_invalidates_old_tokens_but_accepts_new_ones(clock):
    token = web_support.create_csrf_token(FAKE_SECRET)
    rotated_secret = "FAKE replacement csrf key used only in unit tests"
    assert web_support.is_valid_csrf_token(token, FAKE_SECRET) is True

    assert web_support.is_valid_csrf_token(token, rotated_secret) is False
    replacement = web_support.create_csrf_token(rotated_secret)
    assert web_support.is_valid_csrf_token(replacement, rotated_secret) is True


def test_double_submit_requires_both_matching_tokens_and_valid_authentication(clock):
    first = web_support.create_csrf_token(FAKE_SECRET)
    second = web_support.create_csrf_token(FAKE_SECRET)
    assert first != second
    assert web_support.is_valid_csrf_token(first, FAKE_SECRET) is True
    assert web_support.is_valid_csrf_token(second, FAKE_SECRET) is True

    assert web_support.is_valid_csrf_submission(first, second, FAKE_SECRET) is False
    assert web_support.is_valid_csrf_submission(first, first, FAKE_SECRET) is True
    # An attacker controlling both submitted values still cannot bypass authentication.
    forged = first + "FAKE_tampering"
    assert web_support.is_valid_csrf_submission(forged, forged, FAKE_SECRET) is False
    clock[0] += web_support.CSRF_TOKEN_TTL_SECONDS + 1
    assert web_support.is_valid_csrf_submission(first, first, FAKE_SECRET) is False


def test_non_ascii_signature_is_refused_without_a_comparison_error(clock):
    token = web_support.create_csrf_token(FAKE_SECRET)
    message, _, _ = token.rpartition(".")

    assert web_support.is_valid_csrf_token(f"{message}.FAKE_żółć", FAKE_SECRET) is False
