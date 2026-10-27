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

"""Add self sign-up requests and the `signup.request` audit event type.

A patient asks for a portal account on a public page with their health card number, date of birth
and email address (carlos-portal#15). The portal stores the request encrypted until CARLOS collects
it (carlos-portal#16) or it expires, and audits each one with keyed hashes only.

Revision ID: 0019_self_signup_requests
Revises: 0018_mycarlos_mailbox_approval
Create Date: 2026-10-27 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0019_self_signup_requests",
    "down_revision": "0018_mycarlos_mailbox_approval",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_AUDIT_TABLE = "patient_portal_audit_events"
_SIGNUP_TABLE = "patient_portal_signup_requests"

# The exact 47-type policy left by 0017 and unchanged by 0018.
_OLD_EVENT_TYPES = (
    "'activation', 'account.contact_update', 'account.disable', "
    "'account.email_change_confirm', 'account.email_change_request', "
    "'account.enable', 'account.lock', "
    "'account.mfa_update', 'account.password_change', 'account.unlock', "
    "'invite.create', 'invite.list', 'invite.resend', 'invite.revoke', "
    "'job.auth_refused', 'mycarlos.clinic_keys_publish', 'mycarlos.device_list', "
    "'mycarlos.device_remove', 'mycarlos.link', 'mycarlos.link_code_create', "
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
_NEW_EVENT_TYPES = _OLD_EVENT_TYPES.replace(
    "'session.logout', ",
    "'session.logout', 'signup.request', ",
)


def upgrade() -> None:
    op.create_table(
        _SIGNUP_TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("clinic_id", sa.String(64), nullable=False),
        sa.Column("health_card_hash", sa.String(64), nullable=False),
        sa.Column("encrypted_payload", sa.LargeBinary(), nullable=False),
        sa.Column("encryption_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("encryption_key_id", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(clinic_id) between 1 and 64",
            name="ck_pp_signup_requests_clinic_id_length",
        ),
        sa.CheckConstraint(
            "length(health_card_hash) = 64",
            name="ck_pp_signup_requests_health_card_hash_length",
        ),
        sa.CheckConstraint(
            "length(encryption_key_id) between 1 and 64",
            name="ck_pp_signup_requests_key_id_length",
        ),
        sa.CheckConstraint(
            "length(encryption_nonce) = 12",
            name="ck_pp_signup_requests_nonce_length",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_pp_signup_requests_expiry_after_creation",
        ),
        sqlite_autoincrement=True,
    )
    op.create_index("ix_pp_signup_requests_expires", _SIGNUP_TABLE, ["expires_at"])

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint("ck_patient_portal_audit_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_patient_portal_audit_events_event_type",
            f"event_type in ({_NEW_EVENT_TYPES})",
        )


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0019 downgrade requires an online connection to check retained signup data"
        )
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        # Keep both retention decisions valid through CHECK replacement and DROP.
        connection.execute(
            sa.text(
                "LOCK TABLE patient_portal_audit_events, patient_portal_signup_requests "
                "IN ACCESS EXCLUSIVE MODE"
            )
        )
    elif connection.dialect.name == "sqlite":
        # sqlite3's legacy transaction mode leaves SELECT/DDL outside a transaction.
        # Reserve the writer before reading; an existing real transaction already
        # keeps a read snapshot whose promotion cannot overwrite a newer commit.
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
    else:
        raise RuntimeError("migration 0019 supports only SQLite and PostgreSQL")
    signup_events = connection.scalar(
        sa.text(
            "select count(*) from patient_portal_audit_events where event_type = 'signup.request'"
        )
    )
    if signup_events:
        # As in 0014 and 0015: audit events are append-only, and the old constraint cannot hold
        # these rows.
        raise RuntimeError("cannot downgrade migration 0019 while sign-up audit events exist")

    if connection.scalar(sa.text("select count(*) from patient_portal_signup_requests")):
        raise RuntimeError("cannot downgrade migration 0019 while stored sign-up requests exist")

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint("ck_patient_portal_audit_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_patient_portal_audit_events_event_type",
            f"event_type in ({_OLD_EVENT_TYPES})",
        )

    # Only empty signup storage can be removed; unrelated retained data is untouched.
    op.drop_index("ix_pp_signup_requests_expires", table_name=_SIGNUP_TABLE)
    op.drop_table(_SIGNUP_TABLE)
