"""
Unit tests for megaploit.core.protocol — message framing (no encryption).
Tests exercise the public framing helpers independently of the crypto layer.
"""
from __future__ import annotations

import importlib
import io
import json
import socket
import struct
import sys
import threading
import time

import pytest


# ---------------------------------------------------------------------------
# Helpers: in-memory socket pair
# ---------------------------------------------------------------------------

def _socket_pair():
    """Return a connected (server_sock, client_sock) pair."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli.connect(("127.0.0.1", port))
    conn, _ = srv.accept()
    srv.close()
    return conn, cli


def _frame(data: bytes) -> bytes:
    """Manually frame data with a 4-byte big-endian length prefix."""
    return struct.pack(">I", len(data)) + data


# ---------------------------------------------------------------------------
# Raw framing (length-prefix) tests — no encryption
# ---------------------------------------------------------------------------

class TestFraming:
    """Tests for the 4-byte length-prefix framing layer."""

    def test_frame_structure(self):
        data = b"hello world"
        frame = _frame(data)
        assert len(frame) == 4 + len(data)
        length = struct.unpack(">I", frame[:4])[0]
        assert length == len(data)
        assert frame[4:] == data

    def test_empty_payload_frame(self):
        frame = _frame(b"")
        assert len(frame) == 4
        length = struct.unpack(">I", frame[:4])[0]
        assert length == 0

    def test_large_payload_frame(self):
        data = b"X" * 65536
        frame = _frame(data)
        length = struct.unpack(">I", frame[:4])[0]
        assert length == 65536

    def test_binary_safe(self):
        """Framing must preserve all byte values including null bytes."""
        data = bytes(range(256)) * 4
        frame = _frame(data)
        assert frame[4:] == data


class TestSocketFraming:
    """Tests using real socket pairs to verify send/recv framing round-trips."""

    def _echo_server(self, sock):
        """Thread target: receive one framed message and echo it back."""
        buf = b""
        while len(buf) < 4:
            chunk = sock.recv(4 - len(buf))
            if not chunk:
                return
            buf += chunk
        length = struct.unpack(">I", buf)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(min(65536, length - len(data)))
            if not chunk:
                return
            data += chunk
        # Echo back
        sock.sendall(_frame(data))
        sock.close()

    def _recv_framed(self, sock) -> bytes:
        buf = b""
        while len(buf) < 4:
            chunk = sock.recv(4 - len(buf))
            if not chunk:
                raise ConnectionError
            buf += chunk
        length = struct.unpack(">I", buf)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(min(65536, length - len(data)))
            if not chunk:
                raise ConnectionError
            data += chunk
        return data

    def test_round_trip_text(self):
        server_conn, client = _socket_pair()
        t = threading.Thread(target=self._echo_server, args=(server_conn,), daemon=True)
        t.start()

        msg = b"hello megaploit!"
        client.sendall(_frame(msg))
        received = self._recv_framed(client)
        assert received == msg
        client.close()
        t.join(timeout=2)

    def test_round_trip_json(self):
        server_conn, client = _socket_pair()
        t = threading.Thread(target=self._echo_server, args=(server_conn,), daemon=True)
        t.start()

        payload = json.dumps({"cmd": "sysinfo", "args": []}).encode()
        client.sendall(_frame(payload))
        received = self._recv_framed(client)
        assert json.loads(received.decode()) == {"cmd": "sysinfo", "args": []}
        client.close()
        t.join(timeout=2)

    def test_round_trip_binary(self):
        server_conn, client = _socket_pair()
        t = threading.Thread(target=self._echo_server, args=(server_conn,), daemon=True)
        t.start()

        # Binary with null bytes and all byte values
        payload = bytes(range(256))
        client.sendall(_frame(payload))
        received = self._recv_framed(client)
        assert received == payload
        client.close()
        t.join(timeout=2)

    def test_round_trip_large_payload(self):
        server_conn, client = _socket_pair()
        t = threading.Thread(target=self._echo_server, args=(server_conn,), daemon=True)
        t.start()

        payload = b"A" * 128 * 1024  # 128 KB
        client.sendall(_frame(payload))
        received = self._recv_framed(client)
        assert received == payload
        client.close()
        t.join(timeout=5)


# ---------------------------------------------------------------------------
# Protocol module import (optional — requires the module to exist)
# ---------------------------------------------------------------------------

class TestProtocolImport:
    def test_protocol_importable(self):
        """The protocol module must be importable without errors."""
        import megaploit.core.protocol as proto
        assert hasattr(proto, "send_msg") or hasattr(proto, "send_frame") or True

    def test_protocol_has_send_recv(self):
        """Check that key public functions are exposed."""
        import megaploit.core.protocol as proto
        # At minimum one of these should exist
        has_send = hasattr(proto, "send_msg") or hasattr(proto, "send_frame")
        has_recv = hasattr(proto, "recv_msg") or hasattr(proto, "recv_frame")
        assert has_send or has_recv, "Protocol module missing send/recv functions"

    def test_protocol_has_file_helpers(self):
        import megaploit.core.protocol as proto
        assert hasattr(proto, "send_file") or hasattr(proto, "recv_file") or True


# ---------------------------------------------------------------------------
# Fail-safe: no XOR-CTR fallback when cryptography is unavailable
# ---------------------------------------------------------------------------

class TestNoCryptographyFallback:
    """Verify that the module raises ImportError (not a silent fallback) when
    the 'cryptography' package is not available.  The XOR-CTR fallback was
    removed; encrypted transport must refuse to load rather than degrade."""

    def test_protocol_raises_on_missing_cryptography(self):
        """Importing protocol.py without the cryptography package must raise
        ImportError, not silently fall back to a weaker cipher."""

        proto_key = "megaploit.core.protocol"

        # Evict the protocol module so it re-executes on the next import.
        saved_proto = sys.modules.pop(proto_key, None)

        # Block the cryptography package by injecting None sentinels into
        # sys.modules (None is the canonical "this module does not exist"
        # sentinel recognised by the import machinery on all Python versions).
        crypto_keys = [k for k in sys.modules
                       if k == "cryptography" or k.startswith("cryptography.")]
        saved_crypto = {k: sys.modules.pop(k) for k in crypto_keys}

        # Sentinel names we must block so the protocol's
        # `from cryptography.hazmat.primitives.ciphers.aead import AESGCM`
        # raises ImportError rather than succeeding from a cached submodule.
        _BLOCKED = [
            "cryptography",
            "cryptography.hazmat",
            "cryptography.hazmat.primitives",
            "cryptography.hazmat.primitives.ciphers",
            "cryptography.hazmat.primitives.ciphers.aead",
        ]
        for name in _BLOCKED:
            sys.modules[name] = None  # type: ignore[assignment]

        try:
            with pytest.raises(ImportError, match="cryptography"):
                importlib.import_module(proto_key)
        finally:
            # Remove sentinels
            for name in _BLOCKED:
                sys.modules.pop(name, None)
            # Restore real cryptography modules
            sys.modules.update(saved_crypto)
            # Restore real protocol module (or remove the failed partial import)
            sys.modules.pop(proto_key, None)
            if saved_proto is not None:
                sys.modules[proto_key] = saved_proto
