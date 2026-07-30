"""
Typed msgpack/JSON envelope messages.
"""

from __future__ import annotations

import json
import socket

from megaploit.core.framing import (
    _HDR,
    _SEQ,
    get_state,
    _encrypt,
    _decrypt,
    _recv_framed,
)

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
