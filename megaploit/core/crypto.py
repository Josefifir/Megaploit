"""
megaploit.core.crypto
~~~~~~~~~~~~~~~~~~~~~
HMAC-SHA256 challenge/response authentication helpers.
The server sends a random 16-byte challenge; the agent responds with
HMAC-SHA256(secret_key, challenge).  The server verifies with
hmac.compare_digest to prevent timing attacks.

Key file format
---------------
A plain hex string (64 ASCII hex chars = 32 raw bytes), no newline required.
Generate with:
    python -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"

Key fingerprint
---------------
The first 8 hex chars of SHA-256(key) are printed on startup so operators can
confirm both sides are using the same key without exposing the key itself.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import stat
import sys


def load_key(path: str = "secret.key") -> bytes:
    """
    Load and hex-decode the shared secret from *path*.
    Warns if the file is world-readable (permissions broader than 0o600 on Unix).
    Calls sys.exit(1) with a human-readable message on failure.
    """
    try:
        with open(path, "rb") as f:
            raw = f.read().decode().strip()
        key = bytes.fromhex(raw)
    except FileNotFoundError:
        _die(
            f"[-] secret.key not found at '{path}'.\n"
            "    Generate one with:\n"
            "    python -c \"import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))\""
        )
    except ValueError:
        _die(f"[-] '{path}' is corrupt — not valid hex.")

    _check_key_permissions(path)
    return key


def key_fingerprint(key: bytes) -> str:
    """Return the first 16 hex chars of SHA-256(key) as a human-readable fingerprint."""
    return hashlib.sha256(key).hexdigest()[:16]


def _check_key_permissions(path: str) -> None:
    """Warn if secret.key is readable by group or others (Unix only)."""
    if sys.platform == "win32":
        return
    try:
        mode = os.stat(path).st_mode
        if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            print(
                f"[!] WARNING: '{path}' is readable by group/others (mode {oct(mode)[-3:]}).\n"
                f"    Fix with:  chmod 600 {path}",
                file=sys.stderr,
            )
    except OSError:
        pass


def _die(msg: str) -> None:
    print(msg, file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Server side
# ---------------------------------------------------------------------------

def server_authenticate(conn: socket.socket, secret_key: bytes, timeout: int = 10) -> bool:
    """
    Send a 16-byte random challenge and verify the HMAC-SHA256 response.
    Returns True on success, False on failure or timeout.
    """
    old = conn.gettimeout()
    conn.settimeout(timeout)
    try:
        challenge = os.urandom(16)
        conn.sendall(challenge)

        resp = _recv_exactly(conn, 32)
        if resp is None:
            return False

        expected = hmac.new(secret_key, challenge, hashlib.sha256).digest()
        return hmac.compare_digest(resp, expected)
    except (socket.timeout, ConnectionError, OSError):
        return False
    finally:
        conn.settimeout(old)


# ---------------------------------------------------------------------------
# Agent side
# ---------------------------------------------------------------------------

def agent_authenticate(conn: socket.socket, secret_key: bytes, timeout: int = 15) -> bool:
    """
    Wait for the 16-byte challenge from the server and send back the HMAC.
    Returns True on success, False on failure.
    """
    old = conn.gettimeout()
    conn.settimeout(timeout)
    try:
        challenge = _recv_exactly(conn, 16)
        if challenge is None:
            return False

        response = hmac.new(secret_key, challenge, hashlib.sha256).digest()
        conn.sendall(response)
        return True
    except (socket.timeout, ConnectionError, OSError):
        return False
    finally:
        conn.settimeout(old)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _recv_exactly(conn: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
