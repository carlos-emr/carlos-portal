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

"""The CARLOS jobs the portal knows: callers that run with no person behind them.

A job signs its own `X-CARLOS-Job-Assertion` with its own key and is never a CARLOS provider. The
list is code, not configuration: adding a job, or giving one another permission, is a reviewed
change here. Configuration only supplies each job's public keys
(`PATIENT_PORTAL_INTERNAL_JOB_ASSERTION_PUBLIC_KEYRING`), and a job without keys is off.

This module imports nothing from the rest of the package, so the settings, the verifier and the
routes can all read the same list without an import cycle.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

JOB_NAME_PATTERN = re.compile(r"[a-z0-9-]{1,32}")

JOB_BOOKING_SYNC = "booking-sync"
JOB_SIGNUP_POLL = "signup-poll"

# Spelled out rather than imported from internal_routes, which imports this module.
PERMISSION_BOOKING_PROMPT_SYNC = "portal.booking_prompt.sync"
PERMISSION_SIGNUP_MANAGE = "portal.signup.manage"
PERMISSION_INVITE_MANAGE = "portal.invite.manage"


@dataclass(frozen=True)
class SystemJob:
    name: str
    display_name: str
    permissions: frozenset[str]

    @property
    def actor_id(self) -> str:
        """The audit actor id: prefixed so it can never be mistaken for a CARLOS provider number."""
        return f"job:{self.name}"


SYSTEM_JOBS: Mapping[str, SystemJob] = MappingProxyType(
    {
        JOB_BOOKING_SYNC: SystemJob(
            name=JOB_BOOKING_SYNC,
            display_name="Clinic booking",
            permissions=frozenset({PERMISSION_BOOKING_PROMPT_SYNC}),
        ),
        # Registered so its keys can be configured and checked ahead of time. No route accepts it
        # yet: the sign-up routes, and the rule that its invite must name a sign-up request it has
        # claimed, arrive with the self sign-up feature.
        JOB_SIGNUP_POLL: SystemJob(
            name=JOB_SIGNUP_POLL,
            display_name="Patient self sign-up",
            permissions=frozenset({PERMISSION_SIGNUP_MANAGE, PERMISSION_INVITE_MANAGE}),
        ),
    }
)

# Permissions only a job may hold. A staff assertion carrying one is refused on every route, so a
# job's right can never ride on a person's login.
JOB_ONLY_PERMISSIONS = frozenset({PERMISSION_BOOKING_PROMPT_SYNC})
