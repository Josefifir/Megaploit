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

# Re-export everything from the focused sub-modules for backward compatibility.
from megaploit.core.framing import (
    _HDR, _SEQ, _NONCE_LEN, _TAG_LEN,
    _ConnState, get_state, set_state, remove_state,
    _encrypt, _decrypt, _recv_framed, _recv_exactly,
)
from megaploit.core.transport import (
    handshake_server, handshake_agent,
    send_msg, recv_msg,
    send_file, recv_file,
    chunked_send_file, chunked_recv_file,
)
from megaploit.core.messages import (
    send_typed_msg, recv_typed_msg,
)
from megaploit.core.websocket import WsTransport

__all__ = [
    "_HDR", "_SEQ", "_NONCE_LEN", "_TAG_LEN",
    "_ConnState", "get_state", "set_state", "remove_state",
    "_encrypt", "_decrypt", "_recv_framed", "_recv_exactly",
    "handshake_server", "handshake_agent",
    "send_msg", "recv_msg",
    "send_file", "recv_file",
    "chunked_send_file", "chunked_recv_file",
    "send_typed_msg", "recv_typed_msg",
    "WsTransport",
]
