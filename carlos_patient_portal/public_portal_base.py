# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The frozen native portal-base policy using the same Rust url WHATWG parser."""

from pydantic_core import Url


def normalize_portal(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 1024
        or value != value.strip()
        or "\\" in value
    ):
        raise ValueError("myCarlos public portal base is invalid")
    try:
        parsed = Url(value)
    except ValueError:
        raise ValueError("myCarlos public portal base is invalid") from None
    if (
        parsed.scheme != "https"
        or parsed.host is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query is not None
        or parsed.fragment is not None
    ):
        raise ValueError("myCarlos public portal base is invalid")
    canonical = str(parsed).rstrip("/")
    if len(canonical.encode("utf-8")) > 1024 or str(Url(canonical)).rstrip("/") != canonical:
        raise ValueError("myCarlos public portal base is invalid")
    return canonical
