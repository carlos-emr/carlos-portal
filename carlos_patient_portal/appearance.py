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

"""The patient's appearance choice: System, Light or Dark, and a High contrast switch.

Kept per browser in two cookies, so it works before anyone signs in and needs no migration. It is
applied on the server as `data-theme` and `data-contrast` on `<html>`, so the first paint is already
right and nothing flashes. "System" is the default and sets no attribute at all, which leaves the
device's own colour scheme and contrast setting (the stylesheet's media queries) in charge.

A cookie value is never trusted: anything that is not on the allow-list below reads as the default.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Response
from markupsafe import Markup

THEME_COOKIE_NAME = "portal_theme"
CONTRAST_COOKIE_NAME = "portal_contrast"
APPEARANCE_COOKIE_MAX_AGE_SECONDS = 365 * 24 * 60 * 60

THEME_SYSTEM = "system"
THEME_LIGHT = "light"
THEME_DARK = "dark"
THEMES = (THEME_SYSTEM, THEME_LIGHT, THEME_DARK)

CONTRAST_STANDARD = "standard"
CONTRAST_MORE = "more"
CONTRASTS = (CONTRAST_STANDARD, CONTRAST_MORE)


@dataclass(frozen=True, slots=True)
class Appearance:
    theme: str = THEME_SYSTEM
    contrast: str = CONTRAST_STANDARD

    @property
    def color_scheme(self) -> str:
        """The `color-scheme` meta value: both while the device decides, one when it is chosen."""
        return {THEME_LIGHT: "light", THEME_DARK: "dark"}.get(self.theme, "light dark")

    @property
    def html_attributes(self) -> Markup:
        """` data-theme="dark" data-contrast="more"`, only for what was explicitly chosen."""
        parts = []
        if self.theme in (THEME_LIGHT, THEME_DARK):
            parts.append(f' data-theme="{self.theme}"')
        if self.contrast == CONTRAST_MORE:
            parts.append(f' data-contrast="{CONTRAST_MORE}"')
        # Both values come from the allow-lists above, never from the request.
        return Markup("".join(parts))  # noqa: S704 - fixed strings only


def normalize_theme(value: object) -> str:
    return value if isinstance(value, str) and value in THEMES else THEME_SYSTEM


def normalize_contrast(value: object) -> str:
    return value if isinstance(value, str) and value in CONTRASTS else CONTRAST_STANDARD


def read_appearance(cookies: object) -> Appearance:
    """The choice the browser sent; anything missing or unknown is the default."""
    get = getattr(cookies, "get", None)
    if get is None:
        return Appearance()
    return Appearance(
        theme=normalize_theme(get(THEME_COOKIE_NAME)),
        contrast=normalize_contrast(get(CONTRAST_COOKIE_NAME)),
    )


def set_appearance_cookies(response: Response, appearance: Appearance, *, secure: bool) -> None:
    """Remember a choice for a year.

    HttpOnly: nothing on the page reads these from script (the server applies them), so withholding
    them from JavaScript costs nothing. SameSite=Lax like the language cookie, so the choice
    follows a patient who arrives by a link. A default choice is stored too, so choosing System
    again undoes an earlier Dark.
    """
    for name, value in (
        (THEME_COOKIE_NAME, appearance.theme),
        (CONTRAST_COOKIE_NAME, appearance.contrast),
    ):
        response.set_cookie(
            name,
            value,
            max_age=APPEARANCE_COOKIE_MAX_AGE_SECONDS,
            httponly=True,
            samesite="lax",
            secure=secure,
            path="/",
        )
