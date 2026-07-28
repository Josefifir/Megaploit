"""
megaploit.core.pipeline
~~~~~~~~~~~~~~~~~~~~~~~
Post-exploitation pipeline — automatic data collection on every new session.

The pipeline extends ``AutoRunScript`` with named *collection profiles* that
bundle sets of commands together so operators can enable comprehensive
collection with a single toggle.

Built-in profiles
-----------------
* ``basic``      — sysinfo, whoami, ipconfig/ifconfig
* ``creds``      — hashdump, wifi_passwords, browser_creds, ssh_harvest
* ``recon``      — ps, installed_software, scheduled_tasks, users
* ``full``       — all of the above

Usage
-----
::

    from megaploit.core.pipeline import pipeline

    # Enable a collection profile globally
    pipeline.enable_profile("creds")

    # Called by the console when a new session opens
    cmds = pipeline.commands_for(session)

    # Disable a profile
    pipeline.disable_profile("creds")

The pipeline respects ``AutoRunScript`` config as the baseline; profiles
ADD extra commands on top of whatever the user's autorun config specifies.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from megaploit.core.autorun import AutoRunScript

if TYPE_CHECKING:
    from megaploit.server.session import Session

__all__ = ["Pipeline", "pipeline"]


# ---------------------------------------------------------------------------
# Built-in collection profiles
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
        "hosts_file",
    ],
}

# "full" is a virtual profile that includes all of the above
_PROFILES["full"] = [
    cmd
    for profile in ("basic", "creds", "recon", "network")
    for cmd in _PROFILES[profile]
]


class Pipeline:
    """
    Wraps AutoRunScript and adds named collection profiles.

    Profiles add commands on top of the autorun baseline; they can be
    individually enabled/disabled at runtime without touching the config file.
    """

    def __init__(self) -> None:
        self._autorun          = AutoRunScript()
        self._active_profiles: set[str]      = set()
        self._lock             = threading.Lock()

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    def available_profiles(self) -> list[str]:
        """Return all known profile names."""
        return sorted(_PROFILES)

    def enable_profile(self, name: str) -> None:
        """Enable a collection profile by name.  Raises KeyError if unknown."""
        if name not in _PROFILES:
            raise KeyError(f"Unknown pipeline profile: {name!r}. "
                           f"Available: {sorted(_PROFILES)}")
        with self._lock:
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

    def commands_for(self, session: "Session") -> list[str]:
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
            for cmd in _PROFILES.get(profile_name, []):
                if cmd not in seen:
                    seen.add(cmd)
                    extra.append(cmd)

        return base + extra

    def reload_autorun(self) -> None:
        """Reload the underlying autorun config from disk."""
        self._autorun.reload()

    def summary(self) -> dict:
        return {
            "autorun": self._autorun.summary(),
            "active_profiles": self.active_profiles(),
            "available_profiles": self.available_profiles(),
        }

    def __repr__(self) -> str:
        return (
            f"<Pipeline  profiles={self.active_profiles()!r}>"
        )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

pipeline = Pipeline()
