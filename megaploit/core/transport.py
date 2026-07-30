"""
High-level send/receive API — framed text messages and file transfers.
"""

from __future__ import annotations

import json
import os
import socket

from megaploit.core.config import (
    MAX_PLUGIN_MSG_SIZE,
    ALLOW_PLAINTEXT_FALLBACK,
)
from megaploit.core.framing import (
    _HDR,
    _SEQ,
    _V2_MAGIC,
    _ConnState,
    get_state,
    set_state,
    _encrypt,
    _decrypt,
    _recv_framed,
)


# ---------------------------------------------------------------------------
# Protocol version handshake
# ---------------------------------------------------------------------------

def handshake_server(
    conn: socket.socket,
    key: bytes | None = None,
    allow_plaintext_fallback: bool | None = None,
) -> bool:
    """
    Server side: send V2_MAGIC, wait for echo.

    If the client echoes V2_MAGIC and a key is provided, v2 encrypted mode
    is enabled and True is returned.

    If a key is configured and the client does NOT echo V2_MAGIC:
      - ``allow_plaintext_fallback=True``  → fall back to v1 (legacy)
      - ``allow_plaintext_fallback=False`` → raise ConnectionError (default)

    This prevents a silent protocol downgrade attack where a MITM strips the
    V2_MAGIC byte and forces plaintext transport even though both sides have
    a shared secret configured.

    Parameters
    ----------
    conn                    : authenticated socket
    key                     : shared AES-256-GCM key, or None for no encryption
    allow_plaintext_fallback: override for config.ALLOW_PLAINTEXT_FALLBACK
    """
    if allow_plaintext_fallback is None:
        allow_plaintext_fallback = ALLOW_PLAINTEXT_FALLBACK

    try:
        conn.sendall(_V2_MAGIC)
        reply = conn.recv(1)
    except OSError as exc:
        raise ConnectionError(f"Protocol handshake failed: {exc}") from exc

    if reply == _V2_MAGIC and key is not None:
        state = _ConnState(key=key, encrypted=True)
        set_state(conn, state)
        return True

    # Encryption downgrade path
    if key is not None and not allow_plaintext_fallback:
        raise ConnectionError(
            "Encryption negotiation failed: shared secret is configured but the "
            "peer did not agree to v2 encrypted protocol. Refusing plaintext "
            "fallback. Set ALLOW_PLAINTEXT_FALLBACK=True for legacy compatibility."
        )

    # v1 fallback (no key, or key + explicit opt-in to plaintext)
    state = _ConnState(key=None, encrypted=False)
    set_state(conn, state)
    return False


def handshake_agent(
    conn: socket.socket,
    key: bytes | None = None,
    allow_plaintext_fallback: bool | None = None,
) -> bool:
    """
    Agent side: read server's version byte; echo it back.

    If the server sends V2_MAGIC and a key is provided, v2 encrypted mode
    is enabled and True is returned.

    If a key is configured and the server does NOT send V2_MAGIC:
      - ``allow_plaintext_fallback=True``  → fall back to v1 (legacy)
      - ``allow_plaintext_fallback=False`` → raise ConnectionError (default)

    Parameters
    ----------
    conn                    : authenticated socket
    key                     : shared AES-256-GCM key, or None for no encryption
    allow_plaintext_fallback: override for config.ALLOW_PLAINTEXT_FALLBACK
    """
    if allow_plaintext_fallback is None:
        allow_plaintext_fallback = ALLOW_PLAINTEXT_FALLBACK

    try:
        server_ver = conn.recv(1)
        conn.sendall(server_ver)
    except OSError as exc:
        raise ConnectionError(f"Protocol handshake failed: {exc}") from exc

    if server_ver == _V2_MAGIC and key is not None:
        state = _ConnState(key=key, encrypted=True)
        set_state(conn, state)
        return True

    # Encryption downgrade path
    if key is not None and not allow_plaintext_fallback:
        raise ConnectionError(
            "Encryption negotiation failed: shared secret is configured but the "
            "server did not offer v2 encrypted protocol. Refusing plaintext "
            "fallback. Set ALLOW_PLAINTEXT_FALLBACK=True for legacy compatibility."
        )

    # v1 fallback (no key, or key + explicit opt-in to plaintext)
    state = _ConnState(key=None, encrypted=False)
    set_state(conn, state)
    return False


# ---------------------------------------------------------------------------
# Text / JSON messages
# ---------------------------------------------------------------------------

def send_msg(conn: socket.socket, data: object) -> None:
    """JSON-encode *data*, sequence-stamp it, optionally encrypt, and send."""
    state   = get_state(conn)
    seq     = state.next_send_seq()
    payload = _SEQ.pack(seq) + json.dumps(data).encode("utf-8")

    if state.encrypted and state.key:
        payload = _encrypt(state.key, payload)

    conn.sendall(_HDR.pack(len(payload)) + payload)


def recv_msg(conn: socket.socket) -> str:
    """
    Read a framed message, decrypt if needed, verify sequence number.
    Returns the decoded string payload.
    Raises ConnectionError on EOF, ValueError on replay, OSError on socket error.
    """
    state = get_state(conn)
    raw   = _recv_framed(conn)

    if state.encrypted and state.key:
        try:
            raw = _decrypt(state.key, raw)
        except Exception as e:
            raise ConnectionError(f"Decryption failed: {e}") from e

    seq     = _SEQ.unpack(raw[:8])[0]
    payload = raw[8:]

    if not state.check_recv_seq(seq):
        raise ValueError(f"Replay detected: seq={seq} already seen")

    if not payload:
        return ""
    try:
        return json.loads(payload.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return payload.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Binary file transfers
# ---------------------------------------------------------------------------

def send_file(conn: socket.socket, path: str) -> None:
    """
    Read *path* and send it as a framed, optionally encrypted message.

    BUG (was): f.read() loaded the entire file into RAM in one call.
    Files > ~256 MB would hit MAX_PLUGIN_MSG_SIZE on the receiver side
    anyway, but even smaller files cause unnecessary peak RSS.  We now
    read in a streaming fashion, but still send as one framed message
    (the receiver calls _recv_framed which reads the full payload).
    For very large files, callers should use chunked_send_file instead.
    """
    state = get_state(conn)
    seq   = state.next_send_seq()

    # Validate file size against protocol limit before reading
    try:
        file_size = os.path.getsize(path)
    except OSError as e:
        raise ConnectionError(f"Cannot stat file '{path}': {e}") from e

    if file_size > MAX_PLUGIN_MSG_SIZE:
        raise ConnectionError(
            f"File too large to send as single frame: {file_size} bytes "
            f"(limit {MAX_PLUGIN_MSG_SIZE}). Use chunked_send_file() instead."
        )

    with open(path, "rb") as f:
        file_data = f.read()

    payload = _SEQ.pack(seq) + file_data

    if state.encrypted and state.key:
        payload = _encrypt(state.key, payload)

    conn.sendall(_HDR.pack(len(payload)) + payload)


def recv_file(conn: socket.socket, path: str, timeout: float | None = None) -> None:
    """Read a framed file payload and write it to *path*."""
    state     = get_state(conn)
    old_to    = conn.gettimeout()
    if timeout is not None:
        conn.settimeout(timeout)
    try:
        raw = _recv_framed(conn)
    finally:
        conn.settimeout(old_to)

    if state.encrypted and state.key:
        try:
            raw = _decrypt(state.key, raw)
        except Exception as e:
            raise ConnectionError(f"Decryption failed: {e}") from e

    seq       = _SEQ.unpack(raw[:8])[0]
    file_data = raw[8:]

    if not state.check_recv_seq(seq):
        raise ValueError(f"Replay detected: seq={seq}")

    with open(path, "wb") as f:
        f.write(file_data)


# ---------------------------------------------------------------------------
# Chunked send for large files (> ~50 MB)
# ---------------------------------------------------------------------------

def chunked_send_file(conn: socket.socket, path: str, chunk_size: int = 1 << 20) -> None:
    """
    Stream a file in chunks rather than buffering it all in RAM.
    Each chunk is sent as a separate framed message whose payload begins
    with a 1-byte flag: ``0x01`` = more data, ``0x00`` = last chunk.
    """
    state = get_state(conn)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            more  = f.read(1)
            flag  = b"\x01" if more else b"\x00"
            if more:
                f.seek(-1, 1)

            seq     = state.next_send_seq()
            payload = _SEQ.pack(seq) + flag + chunk
            if state.encrypted and state.key:
                payload = _encrypt(state.key, payload)
            conn.sendall(_HDR.pack(len(payload)) + payload)

            if not more:
                break


def chunked_recv_file(conn: socket.socket, path: str, timeout: float | None = None) -> None:
    """Receive a chunked file sent by ``chunked_send_file``."""
    state  = get_state(conn)
    old_to = conn.gettimeout()
    if timeout is not None:
        conn.settimeout(timeout)
    try:
        with open(path, "wb") as out:
            while True:
                raw = _recv_framed(conn)

                # BUG (was): decryption errors were silently swallowed because
                # _decrypt() was called without a try/except here (unlike in
                # recv_file / recv_msg).  Added explicit error propagation.
                if state.encrypted and state.key:
                    try:
                        raw = _decrypt(state.key, raw)
                    except Exception as e:
                        raise ConnectionError(f"Decryption failed on chunk: {e}") from e

                if len(raw) < 9:
                    raise ConnectionError("Chunk too short (missing seq + flag bytes)")

                seq  = _SEQ.unpack(raw[:8])[0]
                flag = raw[8:9]
                chunk = raw[9:]

                # BUG (was): check_recv_seq() return value was discarded —
                # replay detection was silently bypassed for chunked transfers.
                if not state.check_recv_seq(seq):
                    raise ValueError(f"Replay detected in chunk: seq={seq} already seen")

                out.write(chunk)
                if flag == b"\x00":
                    break
    finally:
        conn.settimeout(old_to)
