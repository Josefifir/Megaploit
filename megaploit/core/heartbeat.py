"""
megaploit.core.heartbeat
~~~~~~~~~~~~~~~~~~~~~~~~
Agent-side heartbeat sender and server-side session pruner.

Agent side
----------
A background daemon thread sends a ``PING`` message to the server every
``interval`` seconds.  If the server is reachable but doesn't respond within
``timeout`` seconds, the agent continues — keepalive is best-effort.  If the
socket is dead the existing reconnect loop already handles recovery.

Server side
-----------
``SessionPruner`` tracks when each session last sent a message (via
``record_activity``) and closes sessions that have been silent for longer
than ``max_idle`` seconds.  The pruner runs in a background daemon thread and
calls the caller-supplied ``on_prune`` callback for each removed session.

Usage
-----
Agent::

    from megaploit.core.heartbeat import start_heartbeat
    start_heartbeat(conn, interval=30)

Server::

    from megaploit.core.heartbeat import SessionPruner

    pruner = SessionPruner(
        get_sessions=lambda: dict(session_dict),
        on_prune=lambda sid, sess: print(f"Pruned idle session #{sid}"),
        max_idle=300,
    )
    pruner.start()

    # Call this every time a session produces output:
    pruner.record_activity(session.id)

    pruner.stop()
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Callable, Optional

__all__ = ["start_heartbeat", "SessionPruner"]


# ---------------------------------------------------------------------------
# Agent-side heartbeat sender
# ---------------------------------------------------------------------------

def start_heartbeat(
    conn: socket.socket,
    interval: float = 30.0,
    timeout: float  = 10.0,
    send_lock: Optional[threading.Lock] = None,
) -> threading.Thread:
    """
    Start a daemon thread that sends ``PING`` every *interval* seconds.

    Parameters
    ----------
    conn:      the live C2 socket
    interval:  seconds between PINGs (default 30)
    timeout:   socket send timeout for the PING (default 10)
    send_lock: optional lock shared with the shell loop so that PING
               cannot interleave with a command response on the socket.

    Returns
    -------
    The daemon thread (already started; can be ignored).
    """

    def _run() -> None:
        while True:
            time.sleep(interval)
            try:
                old_to = conn.gettimeout()
                conn.settimeout(timeout)
                try:
                    from megaploit.core.protocol import send_msg
                    if send_lock is not None:
                        with send_lock:
                            send_msg(conn, "PING")
                    else:
                        send_msg(conn, "PING")
                except Exception:
                    pass
                finally:
                    conn.settimeout(old_to)
            except OSError:
                break   # socket is gone — exit silently

    t = threading.Thread(target=_run, daemon=True, name="megaploit.heartbeat")
    t.start()
    return t


# ---------------------------------------------------------------------------
# Server-side session pruner
# ---------------------------------------------------------------------------

class SessionPruner:
    """
    Monitors session activity and closes sessions that have been idle longer
    than *max_idle* seconds.

    Parameters
    ----------
    get_sessions:  callable returning a ``{session_id: Session}`` snapshot
    on_prune:      callback called as ``on_prune(session_id, session)`` when
                   a session is removed.  Should remove the session from the
                   server's session dict and close the socket.
    max_idle:      idle threshold in seconds (default 300 = 5 minutes)
    check_interval: how often to scan for idle sessions (default 60 s)
    """

    def __init__(
        self,
        get_sessions: Callable[[], dict],
        on_prune: Callable[[int, object], None],
        max_idle: float = 300.0,
        check_interval: float = 60.0,
    ) -> None:
        self._get_sessions    = get_sessions
        self._on_prune        = on_prune
        self._max_idle        = max_idle
        self._check_interval  = check_interval
        self._activity: dict[int, float] = {}   # session_id → last-seen timestamp
        self._lock    = threading.Lock()
        self._stop    = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Activity tracking
    # ------------------------------------------------------------------

    def record_activity(self, session_id: int) -> None:
        """Call whenever a session produces output (recv or send)."""
        with self._lock:
            self._activity[session_id] = time.time()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background pruner thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="megaploit.session_pruner",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the background pruner thread."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self._check_interval + 2)
            self._thread = None

    # ------------------------------------------------------------------
    # Pruner loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        while not self._stop.wait(timeout=self._check_interval):
            try:
                self._prune_once()
            except Exception:
                pass

    def _prune_once(self) -> None:
        now      = time.time()
        sessions = self._get_sessions()

        with self._lock:
            # Seed any new sessions with current time so we don't
            # immediately prune a brand-new session that hasn't been
            # seen yet.
            for sid in sessions:
                if sid not in self._activity:
                    self._activity[sid] = now

            to_prune = [
                sid for sid, last in self._activity.items()
                if sid in sessions and (now - last) > self._max_idle
            ]

        for sid in to_prune:
            sess = sessions.get(sid)
            if sess is None:
                continue
            try:
                self._on_prune(sid, sess)
            except Exception:
                pass
            with self._lock:
                self._activity.pop(sid, None)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def idle_seconds(self, session_id: int) -> Optional[float]:
        """Return seconds since last activity for *session_id*, or None."""
        with self._lock:
            last = self._activity.get(session_id)
        if last is None:
            return None
        return time.time() - last

    def status(self) -> dict:
        now = time.time()
        with self._lock:
            return {
                sid: round(now - last, 1)
                for sid, last in self._activity.items()
            }

    def __repr__(self) -> str:
        return (
            f"<SessionPruner  max_idle={self._max_idle}s"
            f"  tracked={len(self._activity)}>"
        )
