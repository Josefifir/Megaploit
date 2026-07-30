"""
megaploit.core.profile
~~~~~~~~~~~~~~~~~~~~~~
Malleable C2 profile — YAML-based traffic shaping to evade IDS/IPS.

A *profile* lets operators customise the network appearance of the C2
channel without changing the core protocol logic:

* HTTP header sets that mimic real software (browser, Windows Update, etc.)
* URL path rotation (agents pick a path from a configurable list)
* User-Agent strings
* Jitter and sleep intervals
* Protocol metadata injection (blending into allowed traffic)

File format  (YAML)
-------------------
::

    name: "WindowsUpdate"
    description: "Mimic Windows Update traffic"

    # Agent sleep interval in seconds (float), plus random jitter (0..jitter_max)
    sleep:        60
    jitter_max:   15

    # Rotating URI paths for HTTP-mode agents
    uri_paths:
      - "/windowsupdate/v9/selfupdate/AU/x86/XP/en/au.cab"
      - "/msdownload/update/v3/static/trustedr/en/authrootstl.cab"
      - "/windowsupdate/redir/v6/muv4wuredir.cab"

    # HTTP headers injected into every request (agent → server)
    request_headers:
      Host: "update.microsoft.com"
      User-Agent: "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.21"
      Accept: "*/*"
      Connection: "Keep-Alive"
      Cache-Control: "no-cache"

    # HTTP headers returned by the server
    response_headers:
      Content-Type: "application/octet-stream"
      Server: "Microsoft-IIS/10.0"
      X-Powered-By: "ASP.NET"

    # Optional beacon fingerprint
    metadata:
      prepend:  "Cookie: "
      append:   ""
      location: "header"

Usage
-----
::

    from megaploit.core.profile import C2Profile, load_profile

    profile = load_profile("profiles/windows_update.yaml")
    print(profile.user_agent)
    print(profile.next_uri())
    print(profile.sleep_with_jitter())
    headers = profile.request_headers
"""

from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Iterator

__all__ = ["C2Profile", "load_profile", "default_profile"]


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class C2Profile:
    """
    Represents a loaded malleable C2 profile.

    All attributes are directly usable by agents and the server transport layer.
    """
    name:             str              = "default"
    description:      str              = "Default C2 profile (no traffic shaping)"

    # Sleep / jitter
    sleep:            float            = 5.0      # base beacon interval (seconds)
    jitter_max:       float            = 2.0      # max random jitter added to sleep

    # HTTP traffic shaping
    uri_paths:        list[str]        = field(default_factory=lambda: ["/"])
    request_headers:  dict[str, str]   = field(default_factory=dict)
    response_headers: dict[str, str]   = field(default_factory=dict)
    user_agent:       str              = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    # Metadata encoding  (how agent ID / auth tokens are transported)
    metadata_prepend: str              = ""
    metadata_append:  str              = ""
    metadata_location: str            = "header"  # "header" | "uri" | "body"

    # Source path (for reload)
    _source_path:     str              = field(default="", init=False, repr=False)

    # ------------------------------------------------------------------
    # Convenience methods used by agent / transport code
    # ------------------------------------------------------------------

    def next_uri(self) -> str:
        """Return a randomly chosen URI path from the profile."""
        return random.choice(self.uri_paths) if self.uri_paths else "/"

    def uri_cycle(self) -> Iterator[str]:
        """Endlessly cycle through URI paths in random order."""
        paths = list(self.uri_paths) or ["/"]
        while True:
            random.shuffle(paths)
            yield from paths

    def sleep_with_jitter(self) -> float:
        """Return sleep + random jitter (seconds).  Does NOT actually sleep."""
        return self.sleep + random.uniform(0, self.jitter_max)

    def wait(self) -> None:
        """Block for ``sleep_with_jitter()`` seconds."""
        time.sleep(self.sleep_with_jitter())

    def build_http_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Return the request header dict merged with *extra*."""
        headers = dict(self.request_headers)
        headers.setdefault("User-Agent", self.user_agent)
        if extra:
            headers.update(extra)
        return headers

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "name":              self.name,
            "description":       self.description,
            "sleep":             self.sleep,
            "jitter_max":        self.jitter_max,
            "uri_paths":         list(self.uri_paths),
            "request_headers":   dict(self.request_headers),
            "response_headers":  dict(self.response_headers),
            "user_agent":        self.user_agent,
            "metadata_prepend":  self.metadata_prepend,
            "metadata_append":   self.metadata_append,
            "metadata_location": self.metadata_location,
        }

    def __repr__(self) -> str:
        return (
            f"<C2Profile {self.name!r}  sleep={self.sleep}s "
            f"jitter={self.jitter_max}s  uri_paths={len(self.uri_paths)}>"
        )


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_profile(path: str) -> C2Profile:
    """
    Load a ``C2Profile`` from a YAML file.

    Falls back to ``json.load`` if PyYAML is not installed (the YAML file
    must then also be valid JSON — useful for simple profiles).

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    ValueError
        If the file cannot be parsed.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"C2Profile file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    data: dict = {}
    try:
        import yaml  # type: ignore[import]
        data = yaml.safe_load(raw) or {}
    except ImportError:
        import json
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Cannot parse {path!r}: PyYAML not installed and file is not "
                f"valid JSON: {exc}"
            ) from exc

    if not isinstance(data, dict):
        raise ValueError(f"C2Profile {path!r}: expected a YAML/JSON object at top level")

    profile = _from_dict(data)
    profile._source_path = path
    return profile


def _from_dict(data: dict) -> C2Profile:
    """Construct a ``C2Profile`` from a plain dict (e.g. from parsed YAML)."""
    meta = data.get("metadata", {}) or {}
    return C2Profile(
        name              = str(data.get("name", "default")),
        description       = str(data.get("description", "")),
        sleep             = float(data.get("sleep", 5.0)),
        jitter_max        = float(data.get("jitter_max", 2.0)),
        uri_paths         = list(data.get("uri_paths", ["/"])),
        request_headers   = dict(data.get("request_headers", {})),
        response_headers  = dict(data.get("response_headers", {})),
        user_agent        = str(
            data.get("user_agent")
            or data.get("request_headers", {}).get("User-Agent", "")
            or C2Profile.user_agent
        ),
        metadata_prepend  = str(meta.get("prepend", "")),
        metadata_append   = str(meta.get("append", "")),
        metadata_location = str(meta.get("location", "header")),
    )


# ---------------------------------------------------------------------------
# Default profile (no traffic shaping — bare TCP)
# ---------------------------------------------------------------------------

default_profile = C2Profile()
