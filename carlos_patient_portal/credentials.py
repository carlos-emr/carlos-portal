# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This software is published under the GPL GNU General Public License.
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# CARLOS EMR Project

import re
from threading import BoundedSemaphore
from unicodedata import normalize

from argon2 import PasswordHasher
from zxcvbn import zxcvbn

from carlos_patient_portal.models import MAX_USERNAME_LENGTH, MIN_USERNAME_LENGTH

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
MIN_PASSWORD_STRENGTH_SCORE = 3
# The library warns that analyzing more than 72 characters permits CPU denial of service. Longer
# passwords still receive full length, blocklist, sequence, short-repetition, and account-context
# checks; strength analysis of the first 72 characters is enough to reject a predictable prefix.
PASSWORD_STRENGTH_ANALYSIS_LENGTH = 72
USERNAME_PATTERN = re.compile(r"^[a-z0-9._-]+$")
PASSWORD_SKELETON_PATTERN = re.compile(r"[^a-z0-9]+")
PASSWORD_LEET_TRANSLATION = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)

# Kept in-process so password validation never discloses a candidate to a third-party breach
# service and never fails open when the network is unavailable. These are common/compromised bases
# rather than only literal passwords: the skeleton check also catches predictable numeric and
# punctuation suffixes such as Password1! and Welcome2026!. Site-specific terms are included because
# NIST calls out service names and other expected choices alongside breached passwords.
COMMON_PASSWORD_BASES = frozenset(
    {
        "abcdef",
        "admin",
        "administrator",
        "access",
        "andrew",
        "ashley",
        "baseball",
        "basketball",
        "batman",
        "charlie",
        "computer",
        "correcthorsebatterystaple",
        "carlos",
        "changeme",
        "clinic",
        "daniel",
        "default",
        "dragon",
        "flower",
        "football",
        "freedom",
        "george",
        "ginger",
        "harley",
        "hunter",
        "iloveyou",
        "jennifer",
        "jessica",
        "jordan",
        "letmein",
        "login",
        "maggie",
        "master",
        "michael",
        "michelle",
        "monkey",
        "mustang",
        "nicole",
        "password",
        "patient",
        "pepper",
        "pokemon",
        "princess",
        "portal",
        "purple",
        "qwerty",
        "ranger",
        "robert",
        "secret",
        "shadow",
        "soccer",
        "summer",
        "starwars",
        "sunshine",
        "superman",
        "taylor",
        "thomas",
        "trustnoone",
        "welcome",
        "whatever",
        "winter",
        "yankees",
    }
)

# Defaults sized for a small clinic VM. Peak hashing memory is roughly
# max_concurrency * memory_cost — 4 * 64 MiB = 256 MiB here — so a deployment with a different
# container limit needs to be able to move them; see configure_password_hashing().
DEFAULT_PASSWORD_HASH_MAX_CONCURRENCY = 4
DEFAULT_PASSWORD_HASH_TIME_COST = 3
DEFAULT_PASSWORD_HASH_MEMORY_KIB = 65536
DEFAULT_PASSWORD_HASH_PARALLELISM = 4

PASSWORD_HASH_MAX_CONCURRENCY = DEFAULT_PASSWORD_HASH_MAX_CONCURRENCY
password_hasher = PasswordHasher(
    time_cost=DEFAULT_PASSWORD_HASH_TIME_COST,
    memory_cost=DEFAULT_PASSWORD_HASH_MEMORY_KIB,
    parallelism=DEFAULT_PASSWORD_HASH_PARALLELISM,
    hash_len=32,
    salt_len=16,
)
password_hash_semaphore = BoundedSemaphore(PASSWORD_HASH_MAX_CONCURRENCY)


def configure_password_hashing(
    *,
    max_concurrency: int,
    time_cost: int,
    memory_kib: int,
    parallelism: int,
) -> None:
    """Rebind the process-wide hasher and its concurrency budget from settings.

    Module-level rather than injected because hash_password/verify_password are called from
    services that have no access to Settings, and a portal process serves exactly one
    configuration. Called once during app construction, before any request is served.

    Changing these does not invalidate existing hashes: Argon2 encodes its own parameters in the
    hash string, so verification uses the parameters the hash was created with.
    """
    global PASSWORD_HASH_MAX_CONCURRENCY, password_hasher, password_hash_semaphore
    PASSWORD_HASH_MAX_CONCURRENCY = max_concurrency
    password_hasher = PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=32,
        salt_len=16,
    )
    password_hash_semaphore = BoundedSemaphore(max_concurrency)


def hash_password(password: str) -> str:
    with password_hash_semaphore:
        return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    with password_hash_semaphore:
        return password_hasher.verify(password_hash, password)


def password_needs_rehash(password_hash: str) -> bool:
    """Check against the currently configured hasher rather than the import-time default."""
    return password_hasher.check_needs_rehash(password_hash)


def validate_username(username: str) -> str:
    normalized_username = username.strip().casefold()
    if not MIN_USERNAME_LENGTH <= len(normalized_username) <= MAX_USERNAME_LENGTH:
        raise ValueError(
            f"username must be between {MIN_USERNAME_LENGTH} and {MAX_USERNAME_LENGTH} characters"
        )
    if not USERNAME_PATTERN.fullmatch(normalized_username):
        raise ValueError(
            "username may only contain letters, numbers, dots, underscores, or hyphens"
        )
    return normalized_username


def _password_compact(value: str) -> str:
    normalized = normalize("NFKC", value).casefold()
    return PASSWORD_SKELETON_PATTERN.sub("", normalized)


def _password_skeleton(value: str) -> str:
    normalized = normalize("NFKC", value).casefold().translate(PASSWORD_LEET_TRANSLATION)
    return PASSWORD_SKELETON_PATTERN.sub("", normalized)


def validate_password(password: str, *, context_values: tuple[str, ...] = ()) -> str:
    """Apply NIST-style length and offline blocklist checks without composition rules."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"password must be {MAX_PASSWORD_LENGTH} characters or fewer")
    compact = _password_compact(password)
    skeleton = _password_skeleton(password)
    repeated_short_unit = any(
        len(compact) % unit_length == 0
        and compact == compact[:unit_length] * (len(compact) // unit_length)
        for unit_length in range(1, min(4, len(compact)) + 1)
    )
    predictable_sequences = (
        "0123456789" * 4,
        "9876543210" * 4,
        "abcdefghijklmnopqrstuvwxyz" * 2,
        "zyxwvutsrqponmlkjihgfedcba" * 2,
    )
    if any(
        skeleton == common
        or (skeleton.startswith(common) and len(skeleton) - len(common) <= 8)
        or (skeleton.endswith(common) and len(skeleton) - len(common) <= 8)
        for common in COMMON_PASSWORD_BASES
    ) or repeated_short_unit or any(compact in sequence for sequence in predictable_sequences):
        raise ValueError("password is too common or easily guessed")
    for context_value in context_values:
        context_skeleton = _password_skeleton(context_value)
        if len(context_skeleton) >= 4 and context_skeleton in skeleton:
            raise ValueError("password must not contain account or clinic information")
    # The small explicit set above catches service-specific derivatives efficiently; zxcvbn adds
    # an offline corpus of common passwords, names and English words plus spatial/repeat/sequence
    # matching. A score below 3 represents a pattern an online attacker is likely to reach within
    # a practical guessing campaign. This is screening, not a composition rule: long uncommon
    # passphrases remain valid without requiring capitals, digits, or punctuation.
    strength_sample = password[:PASSWORD_STRENGTH_ANALYSIS_LENGTH]
    if int(zxcvbn(strength_sample)["score"]) < MIN_PASSWORD_STRENGTH_SCORE:
        raise ValueError("password is too common or easily guessed")
    return password
