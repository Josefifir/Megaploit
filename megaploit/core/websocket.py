"""
RFC 6455 WebSocket transport layer.
"""

from __future__ import annotations

import logging
import os
import socket
import struct

from megaploit.core.config import MAX_WEBSOCKET_FRAME_SIZE
from megaploit.core.framing import _recv_exactly

_LOG = logging.getLogger(__name__)


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
            except OSError as exc:
                _LOG.debug("WsTransport.close(): failed to send CLOSE frame", exc_info=True)
        self._closed = True
        try:
            self._conn.close()
        except OSError as exc:
            _LOG.debug("WsTransport.close(): failed to close underlying socket", exc_info=True)

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
        """Read and parse one WebSocket frame.  Returns (opcode, payload).

        Enforces:
        - Frame payload size ≤ MAX_WEBSOCKET_FRAME_SIZE before allocating memory
        - RFC 6455 masking rules: client→server frames MUST be masked;
          server→client frames MUST NOT be masked
        """
        header = _recv_exactly(self._conn, 2)
        if header is None:
            raise ConnectionError("WsTransport: connection closed in frame header")

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

        # Enforce frame size limit BEFORE allocating the payload buffer.
        # Without this check a peer can send a frame header claiming an
        # arbitrarily large length and cause a memory exhaustion DoS.
        if length > MAX_WEBSOCKET_FRAME_SIZE:
            raise ConnectionError(
                f"WsTransport: frame too large: {length} bytes exceeds "
                f"MAX_WEBSOCKET_FRAME_SIZE ({MAX_WEBSOCKET_FRAME_SIZE} bytes)"
            )

        # Enforce RFC 6455 §5.1 masking rules:
        #   - client→server (server_side=True  → we are reading from a client) MUST mask
        #   - server→client (server_side=False → we are reading from a server) MUST NOT mask
        if self._server_side and not masked:
            raise ConnectionError(
                "WsTransport: RFC 6455 violation — client frame must be masked"
            )
        if not self._server_side and masked:
            raise ConnectionError(
                "WsTransport: RFC 6455 violation — server frame must not be masked"
            )

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
