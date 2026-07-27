"""
megaploit.core.protocol
~~~~~~~~~~~~~~~~~~~~~~~
Wire protocol for Megaploit C2.

Messages
--------
Text messages are JSON-encoded and framed with a 4-byte big-endian length
prefix (no sentinel), which eliminates any possibility of the sentinel
appearing inside binary data:

    [4 bytes: uint32 payload length] [payload bytes]

File transfers
--------------
Binary files use the same length-prefix framing:

    [4 bytes: uint32 file length] [raw file bytes]

This replaces the old END_SENTINEL approach which could corrupt binary
payloads (PNG screenshots, WAV recordings, compiled binaries) if the
sentinel byte sequence happened to appear in the file content.

Backward-compatibility note
---------------------------
END_SENTINEL is kept in config.py for the audit-log module only.
"""

from __future__ import annotations

import socket
import struct
import json

_HDR = struct.Struct("!I")   # network-order unsigned 32-bit int


# ---------------------------------------------------------------------------
# Text / JSON messages
# ---------------------------------------------------------------------------

def send_msg(conn: socket.socket, data: object) -> None:
    """JSON-encode *data*, prefix with 4-byte length, and send."""
    payload = json.dumps(data).encode("utf-8")
    conn.sendall(_HDR.pack(len(payload)) + payload)


def recv_msg(conn: socket.socket) -> str:
    """
    Read a 4-byte length header then exactly that many bytes.
    Returns the decoded string.
    Raises ConnectionError on EOF, OSError on socket errors.
    """
    header = _recv_exactly(conn, 4)
    if header is None:
        raise ConnectionError("Connection closed while reading message length")
    (length,) = _HDR.unpack(header)
    if length == 0:
        return ""
    payload = _recv_exactly(conn, length)
    if payload is None:
        raise ConnectionError("Connection closed while reading message body")
    try:
        return json.loads(payload.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return payload.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Binary file transfers
# ---------------------------------------------------------------------------

def send_file(conn: socket.socket, path: str) -> None:
    """
    Read *path*, prefix the raw bytes with a 4-byte length header, send.
    The entire file is buffered — use chunked_send_file for files > ~50 MB.
    """
    with open(path, "rb") as f:
        data = f.read()
    conn.sendall(_HDR.pack(len(data)) + data)


def recv_file(conn: socket.socket, path: str, timeout: float | None = None) -> None:
    """
    Read a 4-byte length header then exactly that many bytes and write to *path*.
    Raises socket.timeout, ConnectionError, or IOError on failure.
    """
    old_timeout = conn.gettimeout()
    if timeout is not None:
        conn.settimeout(timeout)
    try:
        header = _recv_exactly(conn, 4)
        if header is None:
            raise ConnectionError("Connection closed while reading file length")
        (length,) = _HDR.unpack(header)
        if length == 0:
            # Empty file — create it and return
            open(path, "wb").close()
            return
        data = _recv_exactly(conn, length)
        if data is None:
            raise ConnectionError("Connection closed while reading file body")
        with open(path, "wb") as f:
            f.write(data)
    finally:
        conn.settimeout(old_timeout)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _recv_exactly(conn: socket.socket, n: int) -> bytes | None:
    """Read exactly *n* bytes from *conn*. Returns None on EOF."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
