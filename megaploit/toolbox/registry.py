"""
megaploit.toolbox.registry
~~~~~~~~~~~~~~~~~~~~~~~~~~
Persistent catalogue of installed GitHub tools.

Each tool record is stored in  tools/tools.json  so the catalogue
survives restarts. The tools themselves live in  tools/<name>/

Schema (one entry)
------------------
{
  "name":        "sqlmap",
  "repo":        "https://github.com/sqlmapproject/sqlmap",
  "description": "Automatic SQL injection and database takeover tool",
  "entry":       "sqlmap.py",      # relative path of the entry-point inside the repo
  "lang":        "python",         # detected language (python/go/rust/node/ruby/
                                   #  java/bash/powershell/binary/unknown)
  "run_cmd":     [],               # command template to launch the tool, e.g.
                                   #  ["python", "{entry}"] or ["./sqlmap"] or ["node", "index.js"]
                                   #  Use {entry} as a placeholder for entry_path.
  "installed_at":"2024-01-01T12:00:00",
  "tags":        ["web", "injection"]
}
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

TOOLS_DIR  = "tools"
INDEX_FILE = os.path.join(TOOLS_DIR, "tools.json")

# ---------------------------------------------------------------------------
# Supported language IDs
# ---------------------------------------------------------------------------

LANG_PYTHON      = "python"
LANG_GO          = "go"
LANG_RUST        = "rust"
LANG_NODE        = "node"
LANG_RUBY        = "ruby"
LANG_JAVA        = "java"
LANG_BASH        = "bash"
LANG_POWERSHELL  = "powershell"
LANG_BINARY      = "binary"     # pre-compiled native binary
LANG_UNKNOWN     = "unknown"


@dataclass
class Tool:
    name: str
    repo: str
    description: str
    entry: str                           # relative path inside the cloned repo
    lang: str = LANG_UNKNOWN             # detected language
    run_cmd: list[str] = field(default_factory=list)  # launch command template
    installed_at: str = ""
    tags: list[str] = field(default_factory=list)

    # ---------------------------------------------------------------
    # Computed paths
    # ---------------------------------------------------------------

    @property
    def path(self) -> str:
        """Absolute path to the cloned repo directory."""
        return os.path.abspath(os.path.join(TOOLS_DIR, self.name))

    @property
    def entry_path(self) -> str:
        """Absolute path to the tool's entry-point."""
        return os.path.join(self.path, self.entry)

    @property
    def is_installed(self) -> bool:
        return os.path.isdir(self.path)

    # ---------------------------------------------------------------
    # Launch command (with {entry} expanded)
    # ---------------------------------------------------------------

    def resolved_run_cmd(self) -> list[str]:
        """
        Return the launch command with {entry} replaced by the absolute
        entry_path. Falls back to a bare ['./entry'] for binaries.
        """
        if not self.run_cmd:
            return [self.entry_path]
        return [
            part.replace("{entry}", self.entry_path)
            for part in self.run_cmd
        ]

    # ---------------------------------------------------------------
    # Serialisation
    # ---------------------------------------------------------------

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Tool":
        known = set(Tool.__dataclass_fields__)
        return Tool(**{k: d[k] for k in known if k in d})


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class ToolRegistry:
    """Load/save the tool catalogue from disk."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        os.makedirs(TOOLS_DIR, exist_ok=True)
        self._load()

    def _load(self) -> None:
        if not os.path.isfile(INDEX_FILE):
            return
        try:
            with open(INDEX_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data:
                t = Tool.from_dict(entry)
                self._tools[t.name] = t
        except (json.JSONDecodeError, KeyError):
            pass

    def _save(self) -> None:
        os.makedirs(TOOLS_DIR, exist_ok=True)
        with open(INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump([t.to_dict() for t in self._tools.values()], f, indent=2)

    def add(self, tool: Tool) -> None:
        tool.installed_at = datetime.now(timezone.utc).isoformat()
        self._tools[tool.name] = tool
        self._save()

    def remove(self, name: str) -> bool:
        if name not in self._tools:
            return False
        del self._tools[name]
        self._save()
        return True

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def all(self) -> list[Tool]:
        return list(self._tools.values())

    def search(self, query: str) -> list[Tool]:
        q = query.lower()
        return [
            t for t in self._tools.values()
            if q in t.name.lower()
            or q in t.description.lower()
            or q in t.lang.lower()
            or any(q in tag for tag in t.tags)
        ]


# Module-level singleton
registry = ToolRegistry()
