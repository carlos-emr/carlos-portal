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

"""Let a removed device's availability subscriptions be revoked with it (carlos-portal#87).

`remove_device` revokes the device's waiting keys in its own transaction (0023). Its availability
subscriptions now go with them, recorded with the same values: `device_removed` when the patient
removed the device on the portal, `staff` when it was removed through CARLOS. This adds
`device_removed` to the subscriptions' `revoked_by` CHECK.

PostgreSQL changes the constraint in place. SQLite can change a CHECK only by rebuilding the
table, and the outbox references it by foreign key: dropping the old table while outbox rows point
at it is a violation SQLite still counts once the new table takes its name, even with the checks
deferred. So the outbox's rows are set aside for the rebuild and put back unchanged after it, in
the same transaction. The rebuild keeps AUTOINCREMENT, so no subscription row id is used twice.

Revision ID: 0024_avail_device_removed
Revises: 0023_mycarlos_waiting_keys
Create Date: 2026-11-06 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0024_avail_device_removed",
    "down_revision": "0023_mycarlos_waiting_keys",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_SUBSCRIPTIONS = "patient_portal_mycarlos_availability_subscriptions"
_OUTBOX = "patient_portal_mycarlos_availability_outbox"
_SET_ASIDE = "_pp_0024_outbox_set_aside"
_CHECK = "ck_pp_mycarlos_avail_subs_revoked_by"
_BEFORE = ("device", "provider", "staff")
_AFTER = ("device", "provider", "staff", "device_removed")


def _replace_check(values: tuple[str, ...]) -> None:
    allowed = ", ".join(f"'{value}'" for value in values)
    sqlite = op.get_bind().dialect.name == "sqlite"
    if sqlite:
        op.execute(f"create temporary table {_SET_ASIDE} as select * from {_OUTBOX}")  # noqa: S608
        op.execute(f"delete from {_OUTBOX}")  # noqa: S608
    with op.batch_alter_table(
        _SUBSCRIPTIONS, table_kwargs={"sqlite_autoincrement": True}
    ) as batch_op:
        batch_op.drop_constraint(_CHECK, type_="check")
        batch_op.create_check_constraint(_CHECK, f"revoked_by is null or revoked_by in ({allowed})")
    if sqlite:
        op.execute(f"insert into {_OUTBOX} select * from {_SET_ASIDE}")  # noqa: S608
        op.execute(f"drop table {_SET_ASIDE}")


def upgrade() -> None:
    _replace_check(_AFTER)


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError("migration 0024 downgrade requires an online connection to check rows")
    removed = op.get_bind().scalar(
        sa.text(f"select count(*) from {_SUBSCRIPTIONS} where revoked_by = 'device_removed'")  # noqa: S608
    )
    if removed:
        # The older CHECK has no value for who revoked these, and they must stay tombstones.
        raise RuntimeError(
            "cannot downgrade migration 0024 while subscriptions revoked by a device removal exist"
        )
    _replace_check(_BEFORE)
