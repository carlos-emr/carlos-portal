from datetime import date

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal.identity import IdentityProof
from carlos_patient_portal.invites import create_invite, prepare_create_invite, revoke_invite
from carlos_patient_portal.models import PatientPortalInvite


def test_invite_delivery_migration_follows_main_and_guards_prepared_tokens(tmp_path) -> None:
    config = Config()
    config.set_main_option("script_location", "carlos_patient_portal:migrations")
    database_url = f"sqlite+pysqlite:///{tmp_path / 'invite-delivery.db'}"
    config.set_main_option("sqlalchemy.url", database_url)
    scripts = ScriptDirectory.from_config(config)
    assert len(scripts.get_heads()) == 1
    assert scripts.get_revision("0012_atomic_invite_delivery").down_revision == (
        "0011_staff_assertion_replay"
    )
    command.upgrade(config, "0011_staff_assertion_replay")
    command.upgrade(config, "0012_atomic_invite_delivery")
    engine = create_engine(database_url)
    try:
        assert "patient_portal_staff_assertion_uses" in inspect(engine).get_table_names()
        assert "ux_pp_invites_first_delivery_per_patient" in {
            index["name"] for index in inspect(engine).get_indexes("patient_portal_invites")
        }
        with Session(engine) as session, session.begin():
            invite, _ = prepare_create_invite(
                session, 1234, "Preparing Staff",
                delivery_operation_id="migration-preparation",
                identity_proof=IdentityProof(
                    email="migration.patient@example.com",
                    date_of_birth=date(1980, 5, 20),
                    health_card_number="ABCD 1234-5678",
                ),
                proof_secret="p" * 32,
                encryption_secret="e" * 32,
                encryption_key_id="test-key",
                encryption_keys={"test-key": "e" * 32},
            )
            invite_id = invite.id
        with pytest.raises(RuntimeError, match="cannot downgrade while prepared"):
            command.downgrade(config, "0011_staff_assertion_replay")
        with Session(engine) as session, session.begin():
            assert session.get(PatientPortalInvite, invite_id).encrypted_invite_token is not None
            revoke_invite(session, invite_id, "Revoking Staff")
        command.downgrade(config, "0011_staff_assertion_replay")
        assert "patient_portal_staff_assertion_uses" in inspect(engine).get_table_names()
        assert "delivery_operation_id" not in {
            column["name"] for column in inspect(engine).get_columns("patient_portal_invites")
        }
        command.upgrade(config, "0012_atomic_invite_delivery")
        with engine.connect() as connection:
            assert connection.scalar(text("select version_num from alembic_version")) == (
                "0012_atomic_invite_delivery"
            )
    finally:
        engine.dispose()


def test_dropping_the_redundant_pending_index_keeps_pending_invites_unique(tmp_path) -> None:
    config = Config()
    config.set_main_option("script_location", "carlos_patient_portal:migrations")
    database_url = f"sqlite+pysqlite:///{tmp_path / 'pending-index.db'}"
    config.set_main_option("sqlalchemy.url", database_url)
    assert ScriptDirectory.from_config(config).get_revision(
        "0013_drop_redundant_pending_idx"
    ).down_revision == ("0012_atomic_invite_delivery")
    command.upgrade(config, "0013_drop_redundant_pending_idx")
    engine = create_engine(database_url)

    def index_names() -> set[str]:
        return {index["name"] for index in inspect(engine).get_indexes("patient_portal_invites")}

    try:
        assert "ux_patient_portal_invites_one_pending_per_patient" not in index_names()
        assert "ux_pp_invites_first_delivery_per_patient" in index_names()
        with Session(engine) as session, session.begin():
            first, _ = create_invite(
                session,
                1234,
                "Inviting Staff",
                identity_proof=IdentityProof(
                    email="pending.patient@example.com",
                    date_of_birth=date(1980, 5, 20),
                    health_card_number="ABCD 1234-5678",
                ),
                proof_secret="p" * 32,
            )
            columns = {
                column.name: getattr(first, column.name)
                for column in PatientPortalInvite.__table__.columns
                if column.name != "id"
            }
        # A second pending invite for the patient, bypassing create_invite's own revocation.
        same_patient = "clinic_id, patient_portal_invites.demographic_no"
        with pytest.raises(IntegrityError, match=same_patient):
            with Session(engine) as session, session.begin():
                session.add(PatientPortalInvite(**{**columns, "token_hash": "a" * 64}))
        command.downgrade(config, "0012_atomic_invite_delivery")
        assert "ux_patient_portal_invites_one_pending_per_patient" in index_names()
        command.upgrade(config, "head")
        assert "ux_patient_portal_invites_one_pending_per_patient" not in index_names()
    finally:
        engine.dispose()
