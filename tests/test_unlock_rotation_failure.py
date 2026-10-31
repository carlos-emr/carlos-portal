import json

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from carlos_patient_portal import cli, unlock_secrets
from carlos_patient_portal.database import create_portal_engine
from carlos_patient_portal.models import PatientPortalUnlockSecret
from tests.support import development_settings, upgrade_to_head


def test_rotation_cli_rolls_back_an_interrupted_batch_and_can_retry(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    old_key, active_key = "o" * 32, "a" * 32
    database_url = f"sqlite+pysqlite:///{tmp_path / 'private-rotation.sqlite'}"
    settings = development_settings(
        database_url=database_url,
        unlock_secret_active_key_id="active",
        unlock_secret_encryption_keyring=json.dumps({"retired": old_key, "active": active_key}),
    )
    engine = create_portal_engine(database_url)
    metadata = (
        "encrypted_secret",
        "encryption_nonce",
        "encryption_context",
        "encryption_key_id",
        "encryption_algorithm",
        "updated_at",
    )

    def snapshot():
        with Session(engine) as session:
            return {
                record.id: tuple(getattr(record, name) for name in metadata)
                for record in session.scalars(
                    select(PatientPortalUnlockSecret).order_by(PatientPortalUnlockSecret.id)
                )
            }

    try:
        upgrade_to_head(engine)
        record_ids = []
        plaintexts = ["FAKE first document key", "FAKE second document key", "FAKE current key"]
        with Session(engine) as session, session.begin():
            for index, plaintext in enumerate(plaintexts):
                created = unlock_secrets.create_unlock_secret(
                    session,
                    clinic_id="clinic-a",
                    demographic_no=1234,
                    created_by="FAKE provider",
                    encryption_secret=active_key if index == 2 else old_key,
                    encryption_key_id="active" if index == 2 else "retired",
                    secret=plaintext,
                    source_reference=f"rotation-fixture-{index}",
                )
                record_ids.append(created.unlock_secret.id)
        valid = snapshot()
        with Session(engine) as session, session.begin():
            second = session.get(PatientPortalUnlockSecret, record_ids[1])
            original = second.encrypted_secret
            second.encrypted_secret = bytes([original[0] ^ 1]) + original[1:]
        corrupted = snapshot()
        replacements = []
        real_encrypt = unlock_secrets.encrypt_unlock_secret_payload

        def observe_encryption(*args, **kwargs):
            result = real_encrypt(*args, **kwargs)
            replacements.append(result.encrypted_secret)
            return result

        monkeypatch.setattr(cli, "get_settings", lambda: settings)
        monkeypatch.setattr(unlock_secrets, "encrypt_unlock_secret_payload", observe_encryption)
        with pytest.raises(unlock_secrets.UnlockSecretDecryptionError):
            cli.maintenance(["rotate-unlock-secrets", "--batch-size", "2"])

        # A real replacement was generated before the later row refused decryption.
        assert len(replacements) == 1
        assert replacements[0] != corrupted[record_ids[0]][0]
        assert capsys.readouterr().out == ""
        assert snapshot() == corrupted
        with Session(engine) as session:
            first = session.get(PatientPortalUnlockSecret, record_ids[0])
            assert (
                unlock_secrets.decrypt_unlock_secret_payload(
                    first, encryption_keys={"retired": old_key}
                )
                == plaintexts[0]
            )

        # Repair only the deliberately damaged fixture, then retry the same real command.
        with Session(engine) as session, session.begin():
            session.get(PatientPortalUnlockSecret, record_ids[1]).encrypted_secret = valid[
                record_ids[1]
            ][0]
        cli.maintenance(["rotate-unlock-secrets", "--batch-size", "2"])
        assert capsys.readouterr().out == "rotated 2 unlock secrets\n"
        assert len(replacements) == 3
        assert snapshot()[record_ids[2]] == valid[record_ids[2]]
        with Session(engine) as session:
            for record_id, plaintext in zip(record_ids, plaintexts, strict=True):
                record = session.get(PatientPortalUnlockSecret, record_id)
                assert record.encryption_key_id == "active"
                assert (
                    unlock_secrets.decrypt_unlock_secret_payload(
                        record, encryption_keys={"active": active_key}
                    )
                    == plaintext
                )
    finally:
        engine.dispose()
