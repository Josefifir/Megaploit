"""
megaploit.server.listener
~~~~~~~~~~~~~~~~~~~~~~~~~
TCP listener that accepts incoming agent connections, performs SSL wrapping,
HMAC authentication, and hands off authenticated Sessions to the CLI.
"""

from __future__ import annotations

import socket
import ssl
import threading
from typing import Callable

from megaploit.core.crypto import server_authenticate
from megaploit.server.session import Session
from megaploit.core.config import AUTH_TIMEOUT


class Listener:
    """
    Runs a non-blocking accept loop in a background daemon thread.
    Authenticated sessions are enqueued; the CLI polls for them.
    """

    def __init__(
        self,
        bind_host: str,
        port: int,
        secret_key: bytes,
        on_session: Callable[[Session], None],
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.bind_host = bind_host
        self.port = port
        self.secret_key = secret_key
        self.on_session = on_session
        self.ssl_context = ssl_context
        self._server_sock: socket.socket | None = None
        self._session_counter = 0
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._running = False

    # ---------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------

    def start(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.bind_host, self.port))
        self._server_sock.listen(10)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass

    # ---------------------------------------------------------------
    # Accept loop
    # ---------------------------------------------------------------

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server_sock.accept()
            except OSError:
                break   # socket closed

            threading.Thread(
                target=self._handshake,
                args=(conn, addr),
                daemon=True,
            ).start()

    def _handshake(self, raw_conn: socket.socket, addr: tuple) -> None:
        ip, port = addr[0], addr[1]
        conn = raw_conn

        # Upgrade to TLS if configured
        if self.ssl_context:
            try:
                conn = self.ssl_context.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError:
                raw_conn.close()
                return

        # HMAC authentication
        if not server_authenticate(conn, self.secret_key, timeout=AUTH_TIMEOUT):
            conn.close()
            return

        with self._lock:
            self._session_counter += 1
            sid = self._session_counter

        session = Session(conn=conn, ip=ip, port=port, id=sid)
        self.on_session(session)


def build_ssl_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return ctx
