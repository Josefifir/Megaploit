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
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import sys


def load_key(path: str = "secret.key") -> bytes:
    """Load and decode the shared secret from *path*."""
    try:
        with open(path, "rb") as f:
            raw = f.read().decode().strip()
        return bytes.fromhex(raw)
    except FileNotFoundError:
        _die(
            f"[-] secret.key not found at '{path}'.\n"
            "    Generate one with:\n"
            "    python -c \"import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))\""
        )
    except ValueError:
        _die(f"[-] '{path}' is corrupt — not valid hex.")


def _die(msg: str) -> None:
    print(msg, file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Server side
# ---------------------------------------------------------------------------

def server_authenticate(conn: socket.socket, secret_key: bytes, timeout: int = 30) -> bool:
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

def agent_authenticate(conn: socket.socket, secret_key: bytes, timeout: int = 40) -> bool:
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
