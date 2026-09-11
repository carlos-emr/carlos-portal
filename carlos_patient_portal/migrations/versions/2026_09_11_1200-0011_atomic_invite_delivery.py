# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This software is published under the GPL GNU General Public License.
# You can redistribute it and/or modify it under the terms published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

"""Stage invite tokens until CARLOS has durably recorded their delivery.

Revision ID: 0011_atomic_invite_delivery
Revises: 0010_durable_reset_request_queue
Create Date: 2026-09-11 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0011_atomic_invite_delivery",
    "down_revision": "0010_durable_reset_request_queue",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_NEW_STATUSES = "status in ('prepared', 'pending', 'revoked', 'accepted', 'superseded')"
_OLD_STATUSES = "status in ('pending', 'revoked', 'accepted', 'superseded')"


def upgrade() -> None:
    with op.batch_alter_table("patient_portal_invites") as batch_op:
        batch_op.drop_constraint("ck_patient_portal_invites_status", type_="check")
        batch_op.add_column(sa.Column("delivery_operation_id", sa.String(64), nullable=True))
        batch_op.add_column(sa.Column("delivery_reference", sa.String(128), nullable=True))
        batch_op.add_column(sa.Column("encrypted_invite_token", sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column("invite_token_nonce", sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column("invite_token_key_id", sa.String(64), nullable=True))
        batch_op.create_check_constraint("ck_patient_portal_invites_status", _NEW_STATUSES)
        batch_op.create_check_constraint(
            "ck_pp_invites_prepared_token_fields_complete",
            "(encrypted_invite_token is null and invite_token_nonce is null and "
            "invite_token_key_id is null) or "
            "(encrypted_invite_token is not null and invite_token_nonce is not null and "
            "invite_token_key_id is not null)",
        )
        batch_op.create_check_constraint(
            "ck_pp_invites_prepared_fields_present",
            "status != 'prepared' or (delivery_operation_id is not null and "
            "encrypted_invite_token is not null and delivery_reference is null)",
        )
        batch_op.create_check_constraint(
            "ck_pp_invites_token_only_while_prepared",
            "status = 'prepared' or encrypted_invite_token is null",
        )
        batch_op.create_check_constraint(
            "ck_pp_invites_delivery_reference_has_operation",
            "delivery_reference is null or delivery_operation_id is not null",
        )
        batch_op.create_check_constraint(
            "ck_pp_invites_delivery_operation_length",
            "delivery_operation_id is null or length(delivery_operation_id) between 1 and 64",
        )
        batch_op.create_check_constraint(
            "ck_pp_invites_delivery_reference_length",
            "delivery_reference is null or length(delivery_reference) between 1 and 128",
        )
        batch_op.create_check_constraint(
            "ck_pp_invites_token_nonce_length",
            "invite_token_nonce is null or length(invite_token_nonce) = 12",
        )
        batch_op.create_check_constraint(
            "ck_pp_invites_token_key_id_length",
            "invite_token_key_id is null or length(invite_token_key_id) between 1 and 64",
        )
    op.create_index(
        "ux_pp_invites_clinic_delivery_operation",
        "patient_portal_invites",
        ["clinic_id", "delivery_operation_id"],
        unique=True,
    )
    op.create_index(
        "ux_pp_invites_clinic_delivery_reference",
        "patient_portal_invites",
        ["clinic_id", "delivery_reference"],
        unique=True,
    )
    op.create_index(
        "ux_pp_invites_one_prepared_per_patient",
        "patient_portal_invites",
        ["clinic_id", "demographic_no"],
        unique=True,
        sqlite_where=sa.text("status = 'prepared'"),
        postgresql_where=sa.text("status = 'prepared'"),
    )


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0011 downgrade requires an online connection to check prepared invites"
        )
    prepared = op.get_bind().scalar(
        sa.text("select count(*) from patient_portal_invites where status = 'prepared'")
    )
    if prepared:
        raise RuntimeError("cannot downgrade while prepared invite deliveries exist")
    op.drop_index("ux_pp_invites_one_prepared_per_patient", table_name="patient_portal_invites")
    op.drop_index("ux_pp_invites_clinic_delivery_reference", table_name="patient_portal_invites")
    op.drop_index("ux_pp_invites_clinic_delivery_operation", table_name="patient_portal_invites")
    with op.batch_alter_table("patient_portal_invites") as batch_op:
        batch_op.drop_constraint("ck_pp_invites_token_key_id_length", type_="check")
        batch_op.drop_constraint("ck_pp_invites_token_nonce_length", type_="check")
        batch_op.drop_constraint("ck_pp_invites_delivery_reference_length", type_="check")
        batch_op.drop_constraint("ck_pp_invites_delivery_operation_length", type_="check")
        batch_op.drop_constraint("ck_pp_invites_delivery_reference_has_operation", type_="check")
        batch_op.drop_constraint("ck_pp_invites_token_only_while_prepared", type_="check")
        batch_op.drop_constraint("ck_pp_invites_prepared_fields_present", type_="check")
        batch_op.drop_constraint("ck_pp_invites_prepared_token_fields_complete", type_="check")
        batch_op.drop_constraint("ck_patient_portal_invites_status", type_="check")
        batch_op.drop_column("invite_token_key_id")
        batch_op.drop_column("invite_token_nonce")
        batch_op.drop_column("encrypted_invite_token")
        batch_op.drop_column("delivery_reference")
        batch_op.drop_column("delivery_operation_id")
        batch_op.create_check_constraint("ck_patient_portal_invites_status", _OLD_STATUSES)
