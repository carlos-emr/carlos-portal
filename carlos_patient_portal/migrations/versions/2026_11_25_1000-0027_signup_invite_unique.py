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

"""One sign-up request per prepared invite.

Two sign-up requests must never name the same prepared invite: a match is reported with the invite
of its own request, and a shared one would let one patient's request stand for another's. The
column added by 0026 gets a unique index (requests without an invite hold NULL, which a unique
index does not compare). Downgrade drops the index only; no data is lost.

Revision ID: 0027_signup_invite_unique
Revises: 0026_signup_prepared_invite
Create Date: 2026-11-25 10:00:00+00:00
"""

from collections.abc import Sequence

from alembic import op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0027_signup_invite_unique",
    "down_revision": "0026_signup_prepared_invite",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_SIGNUP_TABLE = "patient_portal_signup_requests"
_INDEX = "uq_pp_signup_requests_prepared_invite"


def upgrade() -> None:
    op.create_index(_INDEX, _SIGNUP_TABLE, ["prepared_invite_id"], unique=True)


def downgrade() -> None:
    op.drop_index(_INDEX, table_name=_SIGNUP_TABLE)
