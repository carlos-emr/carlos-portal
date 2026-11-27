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

"""A throwaway portal for the payment request browser check (scripts/...payment-requests...js).

In-memory database, the seeded FAKE patient already signed in, and three payment requests made
through the real internal API as FAKE front-desk staff: one open (with tax), one paid, one in each
other category. Prints nothing real; writes the session cookie to the fixture file it is given.

    python tests/serve_payment_requests_browser.py <fixture.json> <port>
"""

import json
import sys
from datetime import date, timedelta
from pathlib import Path

import uvicorn
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from carlos_patient_portal import web_support  # noqa: E402
from tests.support import (  # noqa: E402
    INTERNAL_API_TOKEN,
    OUTBOX_ENCRYPTION_SECRET,
    browser_sign_in_seeded_patient,
    carlos_staff_headers,
    migrated_development_app,
)

PATH = "/internal/carlos/patients/1234/payment-requests"


def main() -> None:
    fixture_path, port = Path(sys.argv[1]), int(sys.argv[2])
    app = migrated_development_app(
        clinic_id="clinic-a",
        clinic_name="Example Clinic",
        internal_api_token=INTERNAL_API_TOKEN,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        payment_instructions=(
            "Send an Interac e-Transfer to payments@example.invalid with the reference "
            "shown on your visit summary."
        ),
    )
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    cookie = client.cookies.get(web_support.PORTAL_SESSION_COOKIE_NAME)
    if not cookie:
        raise SystemExit("the seeded patient did not get a portal session")

    staff = TestClient(app)
    headers = carlos_staff_headers(
        "portal.payment.manage",
        clinic_id="clinic-a",
        token=INTERNAL_API_TOKEN,
        provider_name="Front Desk",
    )
    due = (date.today() + timedelta(days=21)).isoformat()
    open_request = staff.post(
        PATH,
        headers=headers,
        json={
            "operation_id": "browser-open",
            "invoice_ref": "browser-open-ref",
            "category": "uninsured_service",
            "payment_method": "clinic_instructions",
            "currency": "CAD",
            "amount_cents": 4500,
            "tax_cents": 518,
            "due_on": due,
        },
    ).json()
    paid = staff.post(
        PATH,
        headers=headers,
        json={
            "operation_id": "browser-paid",
            "invoice_ref": "browser-paid-ref",
            "category": "form_or_note",
            "payment_method": "clinic_instructions",
            "currency": "CAD",
            "amount_cents": 2000,
            "tax_cents": 0,
            "due_on": due,
        },
    ).json()
    staff.post(f"/internal/carlos/payment-requests/{paid['id']}/paid", headers=headers)
    fixture_path.write_text(
        json.dumps(
            {
                "cookie_name": web_support.PORTAL_SESSION_COOKIE_NAME,
                "cookie_value": cookie,
                "open_id": open_request["id"],
                "paid_id": paid["id"],
            }
        )
        + "\n"
    )
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
