# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Canonical URI prefix for public device signatures, independent of browser/internal paths."""

from functools import lru_cache

from pydantic_core import Url

from carlos_patient_portal.config import Settings

MAX_PUBLIC_URL_BYTES = 1024


@lru_cache(maxsize=32)
def canonical_public_device_url(value: str) -> str:
    """Apply the frozen native HTTPS URL policy using the existing Rust URL parser family."""
    if (
        len(value.encode("utf-8")) > MAX_PUBLIC_URL_BYTES
        or value.strip() != value
        or "\\" in value
    ):
        raise ValueError("invalid public device address")
    parsed = Url(value)
    if (
        parsed.scheme != "https"
        or parsed.host is None
        or parsed.username not in (None, "")
        or parsed.password is not None
        or parsed.query is not None
        or parsed.fragment is not None
    ):
        raise ValueError("invalid public device address")
    canonical = str(parsed).rstrip("/")
    if (
        len(canonical.encode("utf-8")) > MAX_PUBLIC_URL_BYTES
        or str(Url(canonical)).rstrip("/") != canonical
    ):
        raise ValueError("invalid public device address")
    return canonical


@lru_cache(maxsize=32)
def _canonical_public_device_prefix(value: str) -> bytes:
    canonical = canonical_public_device_url(value)
    return (Url(canonical).path or "").rstrip("/").encode("ascii")


def public_device_prefix(settings: Settings) -> bytes:
    """Derive only signing bytes; preserve the existing unprefixed/development HTTP behavior."""
    value = settings.public_base_url
    if value is None:
        return b""
    if settings.is_development and value.startswith("http://"):
        # Existing server-only development behavior, never a native/QR HTTPS acceptance path.
        return settings.root_path.encode("utf-8")
    return _canonical_public_device_prefix(value)
