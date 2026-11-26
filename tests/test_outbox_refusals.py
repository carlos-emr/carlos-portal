"""What the delivery outbox refuses before anything reaches the database or the mail relay:
a blank secret, a payload that is too large, a row whose key is not in the keyring, a payload that
was changed or bound to another row, and a result that names no one. FAKE secrets and addresses.
"""

import json
from secrets import token_bytes

import pytest

from carlos_patient_portal import delivery_outbox as outbox
from carlos_patient_portal.auth import PasswordResetRequestResult, PasswordResetTokenInvalidError
from carlos_patient_portal.models import PatientPortalOutboundDelivery

SECRET = "FAKE-outbox-secret-one"
OTHER = "FAKE-outbox-secret-two"
KIND = outbox.OUTBOX_KIND_PASSWORD_RESET
MESSAGE = "<00000000-0000-4000-8000-000000000001@patient-portal.carlos.invalid>"


def delivery(
    payload=None, *, secret=SECRET, kind=KIND, account_id=5, message_id=MESSAGE, key_id="primary"
):
    ciphertext, nonce = outbox._encrypt_payload(
        {"recipient": "fake.patient@example.test"} if payload is None else payload,
        encryption_secret=secret,
        kind=kind,
        account_id=account_id,
        message_id=message_id,
    )
    return PatientPortalOutboundDelivery(
        kind=kind,
        account_id=account_id,
        message_id=message_id,
        encryption_key_id=key_id,
        encrypted_payload=ciphertext,
        encryption_nonce=nonce,
    )


@pytest.mark.parametrize("blank", ["", "   ", "\n\t"])
def test_a_blank_outbox_secret_is_refused(blank):
    with pytest.raises(ValueError, match="must not be blank"):
        outbox.derive_outbox_key(blank)


def test_the_key_comes_from_the_trimmed_secret_and_differs_by_secret():
    assert outbox.derive_outbox_key(SECRET) == outbox.derive_outbox_key(f"  {SECRET}\n")
    assert outbox.derive_outbox_key(SECRET) != outbox.derive_outbox_key(OTHER)
    assert len(outbox.derive_outbox_key(SECRET)) == 32


def test_a_payload_over_the_limit_is_never_encrypted():
    big = {"reset_url": "x" * outbox.MAX_OUTBOX_PAYLOAD_BYTES}
    with pytest.raises(ValueError, match="too large"):
        outbox._encrypt_payload(
            big, encryption_secret=SECRET, kind=KIND, account_id=5, message_id=MESSAGE
        )


def test_a_row_decrypts_with_its_own_key_and_with_a_rotated_keyring():
    row = delivery()
    expected = {"recipient": "fake.patient@example.test"}
    assert outbox._decrypt_payload(row, encryption_secret=SECRET) == expected
    # After a rotation the row's key id is still in the keyring beside the new one.
    keyring = {"primary": SECRET, "next": OTHER}
    assert (
        outbox._decrypt_payload(row, encryption_secret=OTHER, encryption_keys=keyring) == expected
    )


def test_a_row_whose_key_is_not_in_the_keyring_says_so_and_does_not_decrypt():
    row = delivery(key_id="retired")
    with pytest.raises(outbox.OutboxKeyUnavailableError, match="retired"):
        outbox._decrypt_payload(row, encryption_secret=SECRET)
    with pytest.raises(outbox.OutboxKeyUnavailableError):
        outbox._decrypt_payload(row, encryption_secret=SECRET, encryption_keys={"primary": SECRET})


@pytest.mark.parametrize(
    "change",
    [
        {"account_id": 6},  # bound to another account
        {"message_id": "<other@patient-portal.carlos.invalid>"},
        {"kind": outbox.OUTBOX_KIND_PASSWORD_RESET_REQUEST},
    ],
)
def test_a_row_moved_to_another_account_message_or_kind_does_not_decrypt(change):
    row = delivery()
    for field, value in change.items():
        setattr(row, field, value)
    with pytest.raises(outbox.OutboxPayloadError, match="invalid"):
        outbox._decrypt_payload(row, encryption_secret=SECRET)


def test_a_changed_wrong_keyed_or_wrong_nonce_row_does_not_decrypt():
    changed = delivery()
    changed.encrypted_payload = (
        bytes([changed.encrypted_payload[0] ^ 1]) + changed.encrypted_payload[1:]
    )
    wrong_nonce = delivery()
    wrong_nonce.encryption_nonce = token_bytes(len(wrong_nonce.encryption_nonce))
    for row in (changed, wrong_nonce, delivery(secret=OTHER)):
        with pytest.raises(outbox.OutboxPayloadError):
            outbox._decrypt_payload(row, encryption_secret=SECRET)


@pytest.mark.parametrize("value", [[], "text", 7, None])
def test_a_payload_that_is_not_an_object_is_invalid(value):
    # Encrypted by hand so the JSON, not the cipher, is what is wrong.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = token_bytes(outbox.OUTBOX_NONCE_LENGTH)
    ciphertext = AESGCM(outbox.derive_outbox_key(SECRET)).encrypt(
        nonce,
        json.dumps(value).encode(),
        outbox._associated_data(kind=KIND, account_id=5, message_id=MESSAGE),
    )
    row = PatientPortalOutboundDelivery(
        kind=KIND,
        account_id=5,
        message_id=MESSAGE,
        encryption_key_id="primary",
        encrypted_payload=ciphertext,
        encryption_nonce=nonce,
    )
    with pytest.raises(outbox.OutboxPayloadError):
        outbox._decrypt_payload(row, encryption_secret=SECRET)


@pytest.mark.parametrize(
    "result",
    [
        PasswordResetRequestResult(None, "fake@example.test", reset_token_id=1, account_id=None),
        PasswordResetRequestResult(None, "fake@example.test", reset_token_id=None, account_id=1),
        PasswordResetRequestResult(None, None, reset_token_id=1, account_id=1),
    ],
)
def test_a_reset_that_names_no_account_token_or_recipient_is_not_queued(result):
    with pytest.raises(PasswordResetTokenInvalidError):
        outbox.enqueue_password_reset_delivery(
            None,
            result=result,
            reset_url="https://portal.example.test/reset#token=x",
            expires_in_seconds=900,
            encryption_secret=SECRET,
        )


def test_a_queue_limit_below_one_is_refused():
    with pytest.raises(ValueError, match="max_pending must be positive"):
        outbox.enqueue_password_reset_request(
            None,
            username="fake.patient",
            email="fake.patient@example.test",
            client_reference_hash="0" * 64,
            encryption_secret=SECRET,
            max_pending=0,
        )


def test_the_retry_delay_grows_with_the_attempt_and_is_capped_with_jitter():
    cap = outbox.OUTBOX_MAX_RETRY_DELAY_SECONDS
    for attempt in range(0, 30):
        delay = outbox._retry_delay_seconds(attempt)
        ceiling = min(cap, 2 ** min(attempt, 10))
        assert ceiling * 0.5 <= delay <= ceiling, attempt
    assert outbox._retry_delay_seconds(100) <= cap
