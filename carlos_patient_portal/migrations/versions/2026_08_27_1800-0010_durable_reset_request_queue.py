# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This software is published under the GPL GNU General Public License.
# You can redistribute it and/or modify it under the terms published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

"""Queue password-reset identity resolution behind the generic public response.

Revision ID: 0010_durable_reset_request_queue
Revises: 0009_invariants_outbox_indexes
Create Date: 2026-08-27 18:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0010_durable_reset_request_queue",
    "down_revision": "0009_invariants_outbox_indexes",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_KINDS = "kind in ('password_reset_request', 'password_reset', 'contact_change')"
_KIND_FIELDS = (
    "(kind = 'password_reset' and account_id is not null and reset_token_id is not null) or "
    "(kind = 'contact_change' and account_id is not null and reset_token_id is null) or "
    "(kind = 'password_reset_request' and account_id is null and reset_token_id is null)"
)
_OLD_KINDS = "kind in ('password_reset', 'contact_change')"
_OLD_KIND_FIELDS = (
    "(kind = 'password_reset' and reset_token_id is not null) or "
    "(kind = 'contact_change' and reset_token_id is null)"
)


def upgrade() -> None:
    with op.batch_alter_table("patient_portal_outbound_deliveries") as batch_op:
        batch_op.drop_constraint("ck_pp_outbound_delivery_kind", type_="check")
        batch_op.drop_constraint("ck_pp_outbound_delivery_reset_token_kind", type_="check")
        batch_op.alter_column("account_id", existing_type=sa.Integer(), nullable=True)
        batch_op.create_check_constraint("ck_pp_outbound_delivery_kind", _KINDS)
        batch_op.create_check_constraint(
            "ck_pp_outbound_delivery_reset_token_kind",
            _KIND_FIELDS,
        )


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0010 downgrade requires an online connection to check queued requests"
        )
    connection = op.get_bind()
    queued_requests = connection.scalar(
        sa.text(
            "select count(*) from patient_portal_outbound_deliveries "
            "where kind = 'password_reset_request'"
        )
    )
    if queued_requests:
        raise RuntimeError(
            "drain and remove password_reset_request outbox rows before downgrading migration 0010"
        )

    with op.batch_alter_table("patient_portal_outbound_deliveries") as batch_op:
        batch_op.drop_constraint("ck_pp_outbound_delivery_kind", type_="check")
        batch_op.drop_constraint("ck_pp_outbound_delivery_reset_token_kind", type_="check")
        batch_op.alter_column("account_id", existing_type=sa.Integer(), nullable=False)
        batch_op.create_check_constraint("ck_pp_outbound_delivery_kind", _OLD_KINDS)
        batch_op.create_check_constraint(
            "ck_pp_outbound_delivery_reset_token_kind",
            _OLD_KIND_FIELDS,
        )
