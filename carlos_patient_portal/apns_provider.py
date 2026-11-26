# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The Apple key behind the portal's iPhone push: the start-up check and the provider-token signer.

Apple's push service authenticates the portal with a provider token: a short-lived ES256 JWT
signed with the team's `.p8` key (`AuthKey_<key id>.p8`, a PKCS#8 EC key on P-256). The key is
account-wide: it signs pushes for every app of the team, so it is held by the publisher on its own
portal, as a file readable only by the portal's user, outside the repository and outside any
image (see `docs/apns-key-operations.md`). Nothing here logs, prints or returns key material; an
error carries a fixed code only.

* `check_apns_key_file` runs at start-up and refuses a missing, unreadable, over-permissive,
  oversized or malformed key, and malformed team or key ids.
* `ApnsProviderJwtSigner` is the `ProviderJwtSource` the APNs transport asks: it signs a token
  and reuses it for 45 minutes (Apple wants a token refreshed no more often than every 20 minutes
  and rejects one older than 60).
"""

from __future__ import annotations

import base64
import errno
import json
import os
import re
import stat
import threading
from collections.abc import Callable
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from carlos_patient_portal.notification_transports import ApnsConfig

# Apple's own formats: a team id and a key id are ten upper-case letters and digits.
_APPLE_ID = re.compile(r"[A-Z0-9]{10}")
MAX_KEY_FILE_BYTES = 4096
# Refreshed after 45 minutes: more than Apple's 20-minute floor, less than its 60-minute ceiling.
TOKEN_REUSE_SECONDS = 45 * 60


class ApnsKeyError(Exception):
    """The Apple key or its ids are not usable. Only the fixed ``code`` says why; never a path,
    a value or key material."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _load_key(path: Path) -> ec.EllipticCurvePrivateKey:
    """The key in `path`, after the file checks. Raises ``ApnsKeyError`` with a fixed code.

    The file is opened without following a link and without blocking (a FIFO with no writer would
    otherwise hang start-up), and every check is made on the open descriptor (type, owner, mode,
    size), so the file that is checked is the file that is read: nothing can be swapped between a
    check and the open. A FIFO or device is refused as not a regular file.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        raise ApnsKeyError("apns_key_missing") from None
    except OSError as exc:
        # ELOOP: the last path component is a link; EISDIR and the like are not regular files.
        if exc.errno == errno.ELOOP:
            raise ApnsKeyError("apns_key_not_a_regular_file") from None
        raise ApnsKeyError("apns_key_unreadable") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ApnsKeyError("apns_key_not_a_regular_file")
        if info.st_uid != os.geteuid():
            raise ApnsKeyError("apns_key_wrong_owner")
        if info.st_mode & 0o077:
            raise ApnsKeyError("apns_key_permissions_too_open")
        if info.st_size == 0 or info.st_size > MAX_KEY_FILE_BYTES:
            raise ApnsKeyError("apns_key_size")
        try:
            # Until end of file, at most one byte past the cap: a short read must not look like
            # a truncated key.
            chunks: list[bytes] = []
            total = 0
            while total <= MAX_KEY_FILE_BYTES:
                chunk = os.read(descriptor, MAX_KEY_FILE_BYTES + 1 - total)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            data = b"".join(chunks)
        except OSError:
            raise ApnsKeyError("apns_key_unreadable") from None
        if len(data) > MAX_KEY_FILE_BYTES:
            raise ApnsKeyError("apns_key_size")
    finally:
        os.close(descriptor)
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ApnsKeyError("apns_key_invalid") from None
    finally:
        del data
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ApnsKeyError("apns_key_invalid")
    return key


def check_apns_key_file(config: ApnsConfig) -> None:
    """Start-up check: the ids are Apple-shaped and the key file is a private P-256 key that only
    its owner can read. Raises ``ApnsKeyError``; returns nothing."""
    if not _APPLE_ID.fullmatch(config.team_id):
        raise ApnsKeyError("apns_team_id_invalid")
    if not _APPLE_ID.fullmatch(config.key_id):
        raise ApnsKeyError("apns_key_id_invalid")
    _load_key(config.key_path)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class ApnsProviderJwtSigner:
    """Signs APNs provider tokens (ES256) from the key file and caches one for 45 minutes.

    The key is read and checked when the signer is made, so a bad file stops the portal at
    start-up, not at the first push. ``provider_token()`` is safe to call from several threads.
    """

    def __init__(self, config: ApnsConfig, clock: Callable[[], int]) -> None:
        check_apns_key_file(config)
        self._key = _load_key(config.key_path)
        self._team_id = config.team_id
        self._key_id = config.key_id
        self._clock = clock
        self._lock = threading.Lock()
        self._token: str | None = None
        self._issued_at = 0

    def __repr__(self) -> str:
        return "ApnsProviderJwtSigner[REDACTED]"

    def _sign(self, issued_at: int) -> str:
        header = _b64url(
            json.dumps({"alg": "ES256", "kid": self._key_id}, separators=(",", ":")).encode()
        )
        claims = _b64url(
            json.dumps({"iss": self._team_id, "iat": issued_at}, separators=(",", ":")).encode()
        )
        signing_input = f"{header}.{claims}".encode("ascii")
        r, s = decode_dss_signature(self._key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        # JOSE wants the raw r || s, 32 bytes each, not the DER the library returns.
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{header}.{claims}.{_b64url(signature)}"

    def invalidate(self) -> None:
        """Forget the cached provider token, so the next push signs a new one (Apple said 403)."""
        with self._lock:
            self._token = None

    def provider_token(self) -> str:
        now = int(self._clock())
        with self._lock:
            if self._token is None or not 0 <= now - self._issued_at < TOKEN_REUSE_SECONDS:
                self._token = self._sign(now)
                self._issued_at = now
            return self._token
