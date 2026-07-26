"""
megaploit.core.protocol
~~~~~~~~~~~~~~~~~~~~~~~
Wire protocol: all messages are JSON-encoded and delimited by END_SENTINEL.
Binary payloads (files, screenshots, recordings) are sent raw and also
terminated by END_SENTINEL so the single TCP connection stays clean.

Message flow
------------
  Server → Agent:  reliable_send(conn, cmd_string)
  Agent  → Server: reliable_send(conn, response_string)

File transfers
--------------
  Sender calls send_file(conn, path)  — streams bytes + sentinel
  Receiver calls recv_file(conn, path) — accumulates bytes until sentinel
"""

from __future__ import annotations

import json
import socket

from .config import BUFFER_SIZE, END_SENTINEL


# ---------------------------------------------------------------------------
# Text / JSON messages
# ---------------------------------------------------------------------------

def send_msg(conn: socket.socket, data: object) -> None:
    """JSON-encode *data* and write it to *conn* framed with END_SENTINEL."""
    payload = json.dumps(data).encode() + END_SENTINEL
    conn.sendall(payload)


def recv_msg(conn: socket.socket) -> str:
    """
    Block until a full JSON message (terminated by END_SENTINEL) is received.
    Returns the decoded string.
    Raises ConnectionError if the socket closes before the sentinel arrives.
    """
    buf = b""
    while True:
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
            raise ConnectionError("Connection closed before END_SENTINEL received")
        buf += chunk
        if END_SENTINEL in buf:
            payload, _ = buf.split(END_SENTINEL, 1)
            decoded = payload.decode("utf-8", errors="replace")
            try:
                return json.loads(decoded)
            except json.JSONDecodeError:
                return decoded


# ---------------------------------------------------------------------------
# Binary file transfers
# ---------------------------------------------------------------------------

def send_file(conn: socket.socket, path: str) -> None:
    """Stream the file at *path* to *conn*, then write END_SENTINEL."""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            conn.sendall(chunk)
    conn.sendall(END_SENTINEL)


def recv_file(conn: socket.socket, path: str, timeout: float | None = None) -> None:
    """
    Receive a file framed with END_SENTINEL and write it to *path*.
    Raises socket.timeout, ConnectionError, or IOError on failure.
    """
    old_timeout = conn.gettimeout()
    if timeout is not None:
        conn.settimeout(timeout)
    try:
        buf = b""
        with open(path, "wb") as f:
            while True:
                chunk = conn.recv(BUFFER_SIZE)
                if not chunk:
                    raise ConnectionError("Connection closed before END_SENTINEL received")
                buf += chunk
                while END_SENTINEL in buf:
                    data, buf = buf.split(END_SENTINEL, 1)
                    f.write(data)
                    return   # sentinel found — done
                # Write the safe prefix (can't contain a partial sentinel)
                safe_len = max(0, len(buf) - len(END_SENTINEL))
                f.write(buf[:safe_len])
                buf = buf[safe_len:]
    finally:
        conn.settimeout(old_timeout)
