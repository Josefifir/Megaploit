"""
megaploit.core.autorun
~~~~~~~~~~~~~~~~~~~~~~
AutoRunScript — automatically queue commands when a new session opens.

Config file:  ~/.megaploit_autorun.json

Schema
------
{
  "global": ["sysinfo", "whoami"],
  "windows": ["os_info", "installed_software", "scheduled_tasks"],
  "linux":   ["os_info", "find_suid", "env"],
  "darwin":  ["os_info", "startup_items"],
  "tags": {
    "dc": ["hashdump", "users"],
    "workstation": ["browser_creds", "wifi_passwords"]
  }
}

Matching logic
--------------
1.  Commands from ``global`` always run.
2.  Commands from the platform key (``windows`` / ``linux`` / ``darwin``)
    run if session.os_name contains that substring (case-insensitive).
3.  Commands from ``tags[tag]`` run if session.tag matches the key.

The returned list is deduplicated (preserving order) and safe to pass
directly to ``session.send_command()`` or a job queue.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from megaploit.server.session import Session

__all__ = ["AutoRunScript", "autorun"]

_CONFIG_PATH = os.path.expanduser("~/.megaploit_autorun.json")

_DEFAULT_CONFIG: dict = {
    "global":  ["sysinfo"],
    "windows": ["os_info"],
    "linux":   ["os_info"],
    "darwin":  ["os_info"],
    "tags":    {},
}


class AutoRunScript:
    """
    Loads the autorun config and resolves the command list for a session.
    """

    def __init__(self, config_path: str = _CONFIG_PATH) -> None:
        self._path   = config_path
        self._config: dict = {}
        self.reload()

    # ------------------------------------------------------------------
    # Config I/O
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """Reload config from disk (no-op if file absent)."""
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._config = {**_DEFAULT_CONFIG, **data}
        except FileNotFoundError:
            self._config = dict(_DEFAULT_CONFIG)
        except (json.JSONDecodeError, OSError) as exc:
            # Keep last known good config; don't crash the server
            if not self._config:
                self._config = dict(_DEFAULT_CONFIG)

    def save_default(self) -> None:
        """Write the default config to disk as a starter template."""
        template = {
            "global":  ["sysinfo"],
            "windows": ["os_info", "installed_software", "ps"],
            "linux":   ["os_info", "find_suid", "env", "users"],
            "darwin":  ["os_info", "startup_items", "users"],
            "tags": {
                "dc":          ["hashdump", "users", "scheduled_tasks"],
                "workstation": ["browser_creds", "wifi_passwords", "ps"],
            },
        }
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(template, f, indent=2)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Command resolution
    # ------------------------------------------------------------------

    def commands_for(self, session: "Session") -> list[str]:
        """
        Return the ordered, deduplicated list of commands to run for *session*.
        """
        seen:  set[str]  = set()
        cmds:  list[str] = []

        def _add(cmd_list: list) -> None:
            for c in cmd_list:
                if isinstance(c, str) and c.strip() and c not in seen:
                    seen.add(c)
                    cmds.append(c.strip())

        # 1.  Global commands
        _add(self._config.get("global", []))

        # 2.  Platform-specific commands
        os_lower = (session.os_name or "").lower()
        for platform_key in ("windows", "linux", "darwin"):
            if platform_key in os_lower:
                _add(self._config.get(platform_key, []))
                break

        # 3.  Tag-specific commands
        tag = (session.tag or "").lower()
        tags_map = self._config.get("tags", {})
        if isinstance(tags_map, dict) and tag in tags_map:
            _add(tags_map[tag])

        return cmds

    # ------------------------------------------------------------------
    # Convenience: apply to a session's queue
    # ------------------------------------------------------------------

    def apply(self, session: "Session",
              send_fn=None) -> list[str]:
        """
        Resolve commands and optionally dispatch them.

        Parameters
        ----------
        session : Session
            The newly opened session.
        send_fn : callable, optional
            If provided, called as ``send_fn(session, cmd)`` for each command.
            If None the list is returned without dispatching.

        Returns
        -------
        list[str]
            The commands that were (or will be) dispatched.
        """
        cmds = self.commands_for(session)
        if send_fn is not None:
            for cmd in cmds:
                try:
                    send_fn(session, cmd)
                except Exception:
                    pass
        return cmds

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        return {
            "path":    self._path,
            "global":  self._config.get("global", []),
            "windows": self._config.get("windows", []),
            "linux":   self._config.get("linux", []),
            "darwin":  self._config.get("darwin", []),
            "tags":    self._config.get("tags", {}),
        }

    def __repr__(self) -> str:
        n = sum(
            len(v) for v in self._config.values()
            if isinstance(v, list)
        )
        return f"<AutoRunScript  {n} command(s) configured>"


# Singleton
autorun = AutoRunScript()
