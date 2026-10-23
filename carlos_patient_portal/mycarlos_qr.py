# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Local QR producer for the frozen, unsigned myCarlos link format v1.

The native consumer applies its existing portal URL validator after comparing the raw JCS
payload. This producer preserves the configured URL; it does not introduce a URL normalizer.
"""

import json
import re

import segno

from carlos_patient_portal.mycarlos_links import IssuedLinkCode

_LINK_ID = re.compile(r"[0-9A-HJKMNP-TV-Z]{8}")
_LINK_CODE = re.compile(r"[0-9A-HJKMNP-TV-Z]{10}")
MAX_LINK_QR_BYTES = 4096
MAX_PORTAL_URL_BYTES = 1024


def link_qr_payload(issued: IssuedLinkCode, portal_url: str) -> bytes:
    """Emit exactly five JCS members, with the original configured URL and no patient data."""
    if not _LINK_ID.fullmatch(issued.link_id) or not _LINK_CODE.fullmatch(issued.code):
        raise ValueError("invalid link code")
    try:
        portal_bytes = portal_url.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("invalid portal address") from exc
    if (
        not portal_url.startswith("https://")
        or portal_url != portal_url.strip()
        or "\\" in portal_url
        or any(ord(character) < 32 or ord(character) == 127 for character in portal_url)
        or len(portal_bytes) > MAX_PORTAL_URL_BYTES
    ):
        raise ValueError("invalid portal address")
    # ASCII member names, strings and the fixed integer1 are the complete format. No floats or
    # arbitrary objects enter this serialization; Unicode is preserved without normalization.
    payload = json.dumps(
        {
            "code": issued.code,
            "link_id": issued.link_id,
            "portal_url": portal_url,
            "typ": "mycarlos-link",
            "v": 1,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(payload) > MAX_LINK_QR_BYTES:
        raise ValueError("link payload too large")
    return payload


def link_qr_data_uri(issued: IssuedLinkCode, portal_url: str | None) -> str | None:
    """Render only a configured HTTPS target, locally, without storing the plaintext payload."""
    if portal_url is None:
        return None
    try:
        payload = link_qr_payload(issued, portal_url)
    except ValueError:
        return None
    qr = segno.make_qr(payload, mode="byte", encoding="utf-8", eci=True, error="m")
    return qr.png_data_uri(scale=5, border=4)
