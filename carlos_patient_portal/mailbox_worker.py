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

"""Default-off bounded expiry/event collection worker; never sends notifications."""

import logging
from time import monotonic

import anyio

from carlos_patient_portal.mailbox import clinic_lock, expire_batch, prune_collected_events
from carlos_patient_portal.runtime import PortalRuntime

logger = logging.getLogger(__name__)


def sweep(runtime: PortalRuntime) -> tuple[int, int]:
    expired = expire_batch(runtime.session_factory, limit=100)
    with runtime.session_factory() as session, session.begin():
        clinic = clinic_lock(session, runtime.settings.clinic_id)
        pruned = prune_collected_events(session, clinic, limit=100)
    return expired, pruned


async def run_worker(runtime: PortalRuntime) -> None:
    while True:
        deadline = monotonic() + 60
        try:
            # Default abandon_on_cancel=False: wait for the current owned DB transaction
            # to finish before lifespan disposes its engine. No detached DB worker.
            await anyio.to_thread.run_sync(sweep, runtime)
        except Exception as exc:
            # No SQL, bindings, proof/body bytes or clinical data in application logs.
            logger.error("myCarlos mailbox maintenance failed (%s)", type(exc).__name__)
        await anyio.sleep(max(0, deadline - monotonic()))
