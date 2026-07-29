"""
megaploit.core.autorun
~~~~~~~~~~~~~~~~~~~~~~
AutoRunScript — automatically execute a list of C2 commands whenever a new
session opens.

Configuration is stored in a YAML or JSON file (default ``autorun.yaml`` in
the current working directory, or ``~/.megaploit_autorun.json`` for
backwards compatibility).  Commands can be scoped globally, by OS family, or
by session tag.

Config format (YAML example)
-----------------------------
::

    global:
      - sysinfo
      - os_info

    windows:
      - whoami_priv
      - hashdump

    linux:
      - "shell id"
      - find_suid

    darwin:
      - "shell sw_vers"

    tags:
      dev_box:
        - "shell uname -a"
        - installed_software

Usage
-----
    from megaploit.core.autorun import autorun

    cmds = autorun.commands_for(session)
    for cmd in cmds:
        dispatch(session, cmd)

    autorun.reload()          # re-read the config file
    autorun.save_default()    # write a starter config to disk
    autorun.apply(session, send_fn=dispatch)  # resolve + dispatch in one call
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Optional

__all__ = ["AutoRunScript", "autorun"]

_DEFAULT_PATH = "autorun.yaml"
# Legacy path used by older versions / test infrastructure
_LEGACY_PATH  = os.path.expanduser("~/.megaploit_autorun.json")


# ---------------------------------------------------------------------------
# YAML / JSON loader
# ---------------------------------------------------------------------------

def _load_config(path: str) -> dict:
    """Load YAML or JSON config from *path*.  Returns an empty dict on error."""
    if not os.path.isfile(path):
        return {}
    try:
        # Try YAML first (needs pyyaml; falls back to JSON)
        try:
            import yaml
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return data if isinstance(data, dict) else {}
        except ImportError:
            pass
        # JSON fallback
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


_DEFAULT_CONFIG: dict = {
    "global":  ["sysinfo"],
    "windows": [],
    "linux":   [],
    "darwin":  [],
    "tags":    {},
}

_DEFAULT_YAML = """\
# Megaploit AutoRunScript configuration
# Commands are sent to every new session automatically.
# Scope: global (all), windows/linux/darwin, or by session tag.

global:
  - sysinfo

windows:
  # - whoami_priv
  # - hashdump

linux:
  # - "shell id"
  # - find_suid

darwin:
  # - "shell sw_vers"

tags:
  # my_tag:
  #   - "shell hostname"
"""


# ---------------------------------------------------------------------------
# AutoRunScript
# ---------------------------------------------------------------------------

class AutoRunScript:
    """
    Loads and provides autorun command lists from a YAML/JSON config file.

    Thread-safe for concurrent reads; reload() replaces the config atomically.

    Parameters
    ----------
    path / config_path : str, optional
        Path to the YAML or JSON config file.
        ``config_path`` is the legacy keyword accepted by older code / tests.
    """

    def __init__(
        self,
        path: str = _DEFAULT_PATH,
        *,
        config_path: str | None = None,  # backwards-compat alias
    ) -> None:
        # config_path wins when supplied (legacy tests / API)
        self._path = config_path if config_path is not None else path
        self._cfg: dict = {}
        self.reload()

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """Re-read the config file from disk."""
        loaded = _load_config(self._path)
        self._cfg = {**_DEFAULT_CONFIG, **loaded}
        # Normalise tag section to dict[str, list[str]]
        if not isinstance(self._cfg.get("tags"), dict):
            self._cfg["tags"] = {}

    def save_default(self) -> None:
        """
        Write a default starter config to disk.

        The format matches the file extension:
        - ``.yaml`` / ``.yml``  → YAML
        - anything else          → JSON (backwards-compatible for tests)
        """
        ext = os.path.splitext(self._path)[1].lower()
        if ext in (".yaml", ".yml"):
            with open(self._path, "w", encoding="utf-8") as f:
                f.write(_DEFAULT_YAML)
        else:
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
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(template, f, indent=2)

    # ------------------------------------------------------------------
    # Command lookup
    # ------------------------------------------------------------------

    def commands_for(self, session) -> list[str]:
        """
        Return the ordered, deduplicated list of commands to run for *session*.

        Order: global → OS-specific → tag-specific.
        Duplicates are removed (first occurrence wins).
        """
        seen: set[str]  = set()
        cmds: list[str] = []

        def _add(cmd_list) -> None:
            for c in (cmd_list or []):
                if isinstance(c, str) and c.strip() and c not in seen:
                    seen.add(c)
                    cmds.append(c.strip())

        # 1. Global
        _add(self._cfg.get("global"))

        # 2. OS-specific
        os_name: str = getattr(session, "os_name", "") or ""
        os_lower = os_name.lower()
        if "windows" in os_lower:
            _add(self._cfg.get("windows"))
        elif os_lower.startswith("darwin") or "macos" in os_lower:
            _add(self._cfg.get("darwin"))
        elif os_lower:
            _add(self._cfg.get("linux"))

        # 3. Tag-specific
        tag: str = getattr(session, "tag", "") or ""
        tag_cmds = (self._cfg.get("tags") or {}).get(tag, [])
        _add(tag_cmds)

        return cmds

    # ------------------------------------------------------------------
    # apply() — resolve + dispatch in one call
    # ------------------------------------------------------------------

    def apply(self, session, send_fn: Callable | None = None) -> list[str]:
        """
        Resolve commands for *session* and optionally dispatch them.

        Parameters
        ----------
        session:  the newly opened session
        send_fn:  called as ``send_fn(session, cmd)`` for each command.
                  If None the list is returned without dispatching.

        Returns
        -------
        list[str]  — the commands that were (or would be) dispatched.
        """
        cmds = self.commands_for(session)
        if send_fn is not None:
            import logging as _log
            _logger = _log.getLogger(__name__)
            for cmd in cmds:
                try:
                    send_fn(session, cmd)
                except Exception as exc:
                    # M3: surface failures so operators know autorun commands
                    # did not run — swallowing silently made debugging impossible.
                    _logger.warning(
                        "autorun command %r failed for session %r: %s",
                        cmd, getattr(session, "id", session), exc,
                    )
        return cmds

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        return {
            "path":    self._path,
            "global":  list(self._cfg.get("global") or []),
            "windows": list(self._cfg.get("windows") or []),
            "linux":   list(self._cfg.get("linux") or []),
            "darwin":  list(self._cfg.get("darwin") or []),
            "tags":    dict(self._cfg.get("tags") or {}),
        }

    def __repr__(self) -> str:
        n = sum(
            len(v) for v in self._cfg.values()
            if isinstance(v, list)
        )
        return f"<AutoRunScript path={self._path!r} total_cmds={n}>"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

autorun = AutoRunScript()
