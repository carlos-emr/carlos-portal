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

"""Add the tables for linking myCarlos devices (carlos-portal#41, milestone M2).

Send to myCarlos lets CARLOS seal a document to a patient's own myCarlos device and leave it in
the portal for pickup. This revision adds only the linking data, with no routes yet:
- `patient_portal_mycarlos_recipients`: each account's opaque recipient ID;
- `patient_portal_mycarlos_devices`: linked devices (one row per link) and their public keys;
- `patient_portal_mycarlos_link_codes`: pending "Link myCarlos" codes, stored as keyed hashes;
- `patient_portal_mycarlos_link_failures`: wrong codes, for the per-account limit;
- `patient_portal_clinic_keys`: the CARLOS clinic public keys handed to myCarlos when it links.
It also adds the five `mycarlos.*` audit event types. Everything stays unused while
`PATIENT_PORTAL_MYCARLOS_DELIVERY_ENABLED` is off.

Revision ID: 0017_mycarlos_linking
Revises: 0016_job_assertion_audit
Create Date: 2026-10-21 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0017_mycarlos_linking",
    "down_revision": "0016_job_assertion_audit",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_AUDIT_TABLE = "patient_portal_audit_events"
_RECIPIENT_TABLE = "patient_portal_mycarlos_recipients"
_DEVICE_TABLE = "patient_portal_mycarlos_devices"
_LINK_CODE_TABLE = "patient_portal_mycarlos_link_codes"
_LINK_FAILURE_TABLE = "patient_portal_mycarlos_link_failures"
_CLINIC_KEY_TABLE = "patient_portal_clinic_keys"
_ACCOUNTS = "patient_portal_accounts.id"

# The list 0016 left. Another branch that also rewrites this CHECK must merge both lists.
_OLD_EVENT_TYPES = (
    "'activation', 'account.contact_update', 'account.disable', "
    "'account.email_change_confirm', 'account.email_change_request', "
    "'account.enable', 'account.lock', "
    "'account.mfa_update', 'account.password_change', 'account.unlock', "
    "'invite.create', 'invite.list', 'invite.resend', 'invite.revoke', "
    "'job.auth_refused', "
    "'login', 'mfa.challenge', 'mfa.delivery', 'mfa.resend', 'mfa.verify', "
    "'password_reset.complete', 'password_reset.delivery', "
    "'password_reset.request', 'retention.policy_override', 'session.logout', "
    "'staff.action', "
    "'fhir.read', 'fhir.search', "
    "'booking_prompt.create', 'booking_prompt.delivery', 'booking_prompt.list', "
    "'booking_prompt.read', 'booking_prompt.withdraw', "
    "'booking_prompt.offer', 'booking_prompt.choice', 'booking_prompt.result', "
    "'booking_prompt.decline', "
    "'unlock_secret.create', 'unlock_secret.list', 'unlock_secret.read', "
    "'unlock_secret.publish', 'unlock_secret.revoke'"
)
_MYCARLOS_EVENT_TYPES = (
    "'mycarlos.clinic_keys_publish', 'mycarlos.device_list', "
    "'mycarlos.device_remove', 'mycarlos.link', 'mycarlos.link_code_create', "
)
_NEW_EVENT_TYPES = _OLD_EVENT_TYPES.replace(
    "'job.auth_refused', ",
    "'job.auth_refused', " + _MYCARLOS_EVENT_TYPES,
)


def upgrade() -> None:
    op.create_table(
        _RECIPIENT_TABLE,
        sa.Column(
            "account_id",
            sa.Integer(),
            sa.ForeignKey(_ACCOUNTS, name="fk_pp_mycarlos_recipients_account"),
            primary_key=True,
            autoincrement=False,
        ),
        sa.Column("recipient_id", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(recipient_id) between 1 and 64",
            name="ck_pp_mycarlos_recipients_recipient_id_length",
        ),
    )
    op.create_index(
        "ux_pp_mycarlos_recipients_recipient_id",
        _RECIPIENT_TABLE,
        ["recipient_id"],
        unique=True,
    )

    op.create_table(
        _DEVICE_TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "account_id",
            sa.Integer(),
            sa.ForeignKey(_ACCOUNTS, name="fk_pp_mycarlos_devices_account"),
            nullable=False,
        ),
        sa.Column("device_key_id", sa.String(43), nullable=False),
        sa.Column("x25519_public_key", sa.LargeBinary(32), nullable=False),
        sa.Column("ed25519_public_key", sa.LargeBinary(32), nullable=False),
        sa.Column("device_name", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("removed_by", sa.String(16), nullable=True),
        sa.Column("vault_head_link", sa.String(64), nullable=True),
        sa.Column("vault_head_link_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "length(device_key_id) = 43",
            name="ck_pp_mycarlos_devices_device_key_id_length",
        ),
        sa.CheckConstraint(
            "length(x25519_public_key) = 32",
            name="ck_pp_mycarlos_devices_x25519_length",
        ),
        sa.CheckConstraint(
            "length(ed25519_public_key) = 32",
            name="ck_pp_mycarlos_devices_ed25519_length",
        ),
        sa.CheckConstraint(
            "length(device_name) between 1 and 64",
            name="ck_pp_mycarlos_devices_device_name_length",
        ),
        sa.CheckConstraint(
            "status in ('active', 'removed')",
            name="ck_pp_mycarlos_devices_status",
        ),
        sa.CheckConstraint(
            "removed_by is null or removed_by in ('patient', 'staff')",
            name="ck_pp_mycarlos_devices_removed_by",
        ),
        sa.CheckConstraint(
            "(status = 'active' and removed_at is null and removed_by is null) or "
            "(status = 'removed' and removed_at is not null and removed_by is not null)",
            name="ck_pp_mycarlos_devices_removal_complete",
        ),
        sa.CheckConstraint(
            "vault_head_link is null or length(vault_head_link) = 64",
            name="ck_pp_mycarlos_devices_vault_head_link_length",
        ),
        sa.CheckConstraint(
            "(vault_head_link is null) = (vault_head_link_at is null)",
            name="ck_pp_mycarlos_devices_vault_head_link_at",
        ),
        sqlite_autoincrement=True,
    )
    op.create_index(
        "ux_pp_mycarlos_devices_device_key_id",
        _DEVICE_TABLE,
        ["device_key_id"],
        unique=True,
    )
    op.create_index(
        "ix_pp_mycarlos_devices_account_status",
        _DEVICE_TABLE,
        ["account_id", "status"],
    )

    op.create_table(
        _LINK_CODE_TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "account_id",
            sa.Integer(),
            sa.ForeignKey(_ACCOUNTS, name="fk_pp_mycarlos_link_codes_account"),
            nullable=False,
        ),
        sa.Column(
            "session_id",
            sa.Integer(),
            sa.ForeignKey(
                "patient_portal_sessions.id",
                ondelete="CASCADE",
                name="fk_pp_mycarlos_link_codes_session",
            ),
            nullable=False,
        ),
        sa.Column("link_id", sa.String(8), nullable=False),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("wrong_codes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "device_id",
            sa.Integer(),
            sa.ForeignKey(f"{_DEVICE_TABLE}.id", name="fk_pp_mycarlos_link_codes_device"),
            nullable=True,
        ),
        sa.CheckConstraint(
            "length(link_id) = 8",
            name="ck_pp_mycarlos_link_codes_link_id_length",
        ),
        sa.CheckConstraint(
            "length(code_hash) = 64",
            name="ck_pp_mycarlos_link_codes_code_hash_length",
        ),
        sa.CheckConstraint(
            "status in ('pending', 'used', 'replaced')",
            name="ck_pp_mycarlos_link_codes_status",
        ),
        sa.CheckConstraint(
            "wrong_codes between 0 and 5",
            name="ck_pp_mycarlos_link_codes_wrong_codes",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_pp_mycarlos_link_codes_expiry_after_creation",
        ),
        sa.CheckConstraint(
            "(status = 'used' and device_id is not null and used_at is not null) or "
            "(status != 'used' and device_id is null and used_at is null)",
            name="ck_pp_mycarlos_link_codes_used_complete",
        ),
    )
    op.create_index(
        "ux_pp_mycarlos_link_codes_link_id",
        _LINK_CODE_TABLE,
        ["link_id"],
        unique=True,
    )
    op.create_index(
        "ix_pp_mycarlos_link_codes_account_status_created",
        _LINK_CODE_TABLE,
        ["account_id", "status", "created_at"],
    )
    op.create_index("ix_pp_mycarlos_link_codes_expires", _LINK_CODE_TABLE, ["expires_at"])
    op.create_index("ix_pp_mycarlos_link_codes_session", _LINK_CODE_TABLE, ["session_id"])

    op.create_table(
        _LINK_FAILURE_TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "account_id",
            sa.Integer(),
            sa.ForeignKey(_ACCOUNTS, name="fk_pp_mycarlos_link_failures_account"),
            nullable=False,
        ),
        sa.Column("link_id", sa.String(8), nullable=False),
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(link_id) = 8",
            name="ck_pp_mycarlos_link_failures_link_id_length",
        ),
    )
    op.create_index(
        "ix_pp_mycarlos_link_failures_account_failed",
        _LINK_FAILURE_TABLE,
        ["account_id", "failed_at"],
    )
    op.create_index("ix_pp_mycarlos_link_failures_failed", _LINK_FAILURE_TABLE, ["failed_at"])

    op.create_table(
        _CLINIC_KEY_TABLE,
        sa.Column("kid", sa.String(43), primary_key=True),
        sa.Column("clinic_id", sa.String(64), nullable=False),
        sa.Column("spki", sa.LargeBinary(512), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaces_kid", sa.String(43), nullable=True),
        sa.Column("replacement_signature", sa.LargeBinary(512), nullable=True),
        sa.CheckConstraint("length(kid) = 43", name="ck_pp_clinic_keys_kid_length"),
        sa.CheckConstraint(
            "length(clinic_id) between 1 and 64",
            name="ck_pp_clinic_keys_clinic_id_length",
        ),
        sa.CheckConstraint(
            "length(spki) between 1 and 512",
            name="ck_pp_clinic_keys_spki_length",
        ),
        sa.CheckConstraint(
            "status in ('active', 'revoked')",
            name="ck_pp_clinic_keys_status",
        ),
        sa.CheckConstraint(
            "(status = 'revoked') = (revoked_at is not null)",
            name="ck_pp_clinic_keys_revoked_at",
        ),
        sa.CheckConstraint(
            "replaces_kid is null or length(replaces_kid) = 43",
            name="ck_pp_clinic_keys_replaces_kid_length",
        ),
        sa.CheckConstraint(
            "replacement_signature is null or length(replacement_signature) between 1 and 512",
            name="ck_pp_clinic_keys_replacement_signature_length",
        ),
        sa.CheckConstraint(
            "(replaces_kid is null) = (replacement_signature is null)",
            name="ck_pp_clinic_keys_replacement_complete",
        ),
    )
    op.create_index("ix_pp_clinic_keys_clinic_status", _CLINIC_KEY_TABLE, ["clinic_id", "status"])

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint("ck_patient_portal_audit_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_patient_portal_audit_events_event_type",
            f"event_type in ({_NEW_EVENT_TYPES})",
        )


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0017 downgrade requires an online connection to check myCarlos rows"
        )
    connection = op.get_bind()
    mycarlos_events = connection.scalar(
        sa.text(
            "select count(*) from patient_portal_audit_events where event_type in "
            "('mycarlos.clinic_keys_publish', 'mycarlos.device_list', "
            "'mycarlos.device_remove', 'mycarlos.link', 'mycarlos.link_code_create')"
        )
    )
    if mycarlos_events:
        # As in 0014-0016: audit events are append-only, and the old constraint cannot hold these.
        raise RuntimeError("cannot downgrade migration 0017 while myCarlos audit events exist")
    linked_devices = connection.scalar(
        sa.text("select count(*) from patient_portal_mycarlos_devices")
    )
    if linked_devices:
        # Dropping the table would silently unlink every device, and CARLOS would keep sending.
        raise RuntimeError("cannot downgrade migration 0017 while myCarlos devices are linked")

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint("ck_patient_portal_audit_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_patient_portal_audit_events_event_type",
            f"event_type in ({_OLD_EVENT_TYPES})",
        )

    op.drop_index("ix_pp_clinic_keys_clinic_status", table_name=_CLINIC_KEY_TABLE)
    op.drop_table(_CLINIC_KEY_TABLE)
    op.drop_index("ix_pp_mycarlos_link_failures_failed", table_name=_LINK_FAILURE_TABLE)
    op.drop_index("ix_pp_mycarlos_link_failures_account_failed", table_name=_LINK_FAILURE_TABLE)
    op.drop_table(_LINK_FAILURE_TABLE)
    op.drop_index("ix_pp_mycarlos_link_codes_session", table_name=_LINK_CODE_TABLE)
    op.drop_index("ix_pp_mycarlos_link_codes_expires", table_name=_LINK_CODE_TABLE)
    op.drop_index("ix_pp_mycarlos_link_codes_account_status_created", table_name=_LINK_CODE_TABLE)
    op.drop_index("ux_pp_mycarlos_link_codes_link_id", table_name=_LINK_CODE_TABLE)
    op.drop_table(_LINK_CODE_TABLE)
    op.drop_index("ix_pp_mycarlos_devices_account_status", table_name=_DEVICE_TABLE)
    op.drop_index("ux_pp_mycarlos_devices_device_key_id", table_name=_DEVICE_TABLE)
    op.drop_table(_DEVICE_TABLE)
    op.drop_index("ux_pp_mycarlos_recipients_recipient_id", table_name=_RECIPIENT_TABLE)
    op.drop_table(_RECIPIENT_TABLE)
