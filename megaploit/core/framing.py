"""
Low-level frame encoding, AES-256-GCM helpers, and per-connection state.
"""

from __future__ import annotations

import os
import socket
import struct
import threading

# ---------------------------------------------------------------------------
# Struct objects and constants
# ---------------------------------------------------------------------------

_HDR  = struct.Struct("!I")    # 4-byte big-endian uint32 (outer length)
_SEQ  = struct.Struct("!Q")    # 8-byte big-endian uint64 (sequence number)
_NONCE_LEN  = 12
_TAG_LEN    = 16
_V2_MAGIC   = b"M"             # version byte sent in handshake
_unused_v1_magic = b"\x00"

# ---------------------------------------------------------------------------
# Per-connection encryption state (thread-local is NOT correct here —
# each Socket object carries its own _ConnState)
# ---------------------------------------------------------------------------

class _ConnState:
    """Mutable per-connection crypto + sequence state, attached to a socket."""

    def __init__(self, key: bytes | None = None, encrypted: bool = False) -> None:
        self.key:        bytes | None = key
        self.encrypted:  bool = encrypted
        self._send_seq:  int  = 0
        self._recv_seq:  int  = -1    # -1 means "not yet received anything"
        self._lock:      threading.Lock  # type annotation only
        self._lock       = threading.Lock()

    def next_send_seq(self) -> int:
        with self._lock:
            self._send_seq += 1
            return self._send_seq

    def check_recv_seq(self, seq: int) -> bool:
        """Return True if seq is valid (> last seen).  Always accept if first."""
        with self._lock:
            if seq > self._recv_seq:
                self._recv_seq = seq
                return True
            return False


# Socket → _ConnState registry.
# BUG (was): this dict grew without bound because remove_state() was only
# called on clean operator-initiated session close.  If an agent dropped
# the connection abruptly (network loss, crash), the fd stayed registered.
# Worse, the OS reuses file descriptors, so a brand-new connection could
# inherit the stale _ConnState of a dead session — wrong sequence numbers,
# potentially wrong key — and recv_msg() would immediately raise ValueError
# ("Replay detected: seq=1 already seen").
#
# Fix: get_state() ALWAYS creates a fresh _ConnState for an fd that is not
# already registered.  This is safe because:
#   1. handshake_server() calls set_state() immediately, overwriting any
#      stale entry with the correct key and encrypted=True.
#   2. remove_state() is still called on clean close to keep the dict small.
#   3. get_state() allocating a blank state for an unregistered fd is the
#      correct fallback for legacy/unencrypted connections.
_states: dict[int, _ConnState] = {}
_states_lock = threading.Lock()


def get_state(conn: socket.socket) -> _ConnState:
    fno = conn.fileno()
    with _states_lock:
        if fno not in _states:
            _states[fno] = _ConnState()
        return _states[fno]


def set_state(conn: socket.socket, state: _ConnState) -> None:
    with _states_lock:
        # Always replace — this is the primary defence against fd reuse:
        # handshake_server() calls set_state() with a fresh _ConnState
        # keyed to the new session, evicting any stale entry.
        _states[conn.fileno()] = state


def remove_state(conn: socket.socket) -> None:
    """Remove the _ConnState for *conn*.  Safe to call even if not registered."""
    try:
        fno = conn.fileno()
    except OSError:
        return
    with _states_lock:
        _states.pop(fno, None)


# ---------------------------------------------------------------------------
# AES-256-GCM helpers — requires the 'cryptography' package.
#
# The XOR-CTR fallback was removed because it provided no authentication
# (unauthenticated stream cipher with a fake 16-byte tag) while the wire
# protocol is documented as AES-256-GCM.  Operators relying on encrypted
# transport must have 'cryptography' installed.
# ---------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
except ImportError as _crypto_err:  # pragma: no cover
    raise ImportError(
        "The 'cryptography' package is required for AES-256-GCM transport.\n"
        "Install it with:  pip install cryptography\n"
        f"Original error: {_crypto_err}"
    ) from _crypto_err


def _encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Return  nonce(12) + ciphertext+tag  using AES-256-GCM."""
    nonce = os.urandom(_NONCE_LEN)
    ct    = _AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def _decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt  nonce(12) + ciphertext+tag  and return plaintext."""
    nonce  = data[:_NONCE_LEN]
    ct_tag = data[_NONCE_LEN:]
    return _AESGCM(key).decrypt(nonce, ct_tag, None)


# ---------------------------------------------------------------------------
# Internal recv helpers
# ---------------------------------------------------------------------------

from megaploit.core.config import MAX_PLUGIN_MSG_SIZE


def _recv_framed(conn: socket.socket) -> bytes:
    """Read a 4-byte length header then exactly that many bytes."""
    header = _recv_exactly(conn, 4)
    if header is None:
        raise ConnectionError("Connection closed while reading message length")
    (length,) = _HDR.unpack(header)
    if length == 0:
        return b""
    if length > MAX_PLUGIN_MSG_SIZE:
        raise ConnectionError(
            f"Frame too large: {length} bytes exceeds "
            f"MAX_PLUGIN_MSG_SIZE ({MAX_PLUGIN_MSG_SIZE} bytes). "
            "Possible memory exhaustion attack or misconfigured peer."
        )
    data = _recv_exactly(conn, length)
    if data is None:
        raise ConnectionError("Connection closed while reading message body")
    return data


def _recv_exactly(conn: socket.socket, n: int) -> bytes | None:
    """Read exactly *n* bytes from *conn*. Returns None on EOF."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
