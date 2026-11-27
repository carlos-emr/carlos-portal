# SPDX-License-Identifier: AGPL-3.0-or-later
"""A throwaway portal for scripts/patient-portal-document-passwords-playwright-checks.js.

Builds the development app on an in-memory database, signs the seeded FAKE patient in (through the
test client, with the development sign-in code the page shows), writes the signed-in session
cookie to a fixture file, then serves the app on a local port. Nothing here touches a real
database: run it only for the browser check.

    python tests/serve_document_passwords_browser.py FIXTURE.json PORT
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import uvicorn
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from carlos_patient_portal import web_support  # noqa: E402
from tests.support import (  # noqa: E402
    browser_sign_in_seeded_patient,
    migrated_development_app,
)


def main() -> None:
    fixture_path, port = Path(sys.argv[1]), int(sys.argv[2])
    app = migrated_development_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    cookie = client.cookies.get(web_support.PORTAL_SESSION_COOKIE_NAME)
    if not cookie:
        raise SystemExit("the seeded patient did not get a portal session")
    fixture_path.write_text(
        json.dumps(
            {
                "cookie_name": web_support.PORTAL_SESSION_COOKIE_NAME,
                "cookie_value": cookie,
            }
        )
        + "\n"
    )
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
