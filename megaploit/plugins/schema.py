"""
megaploit.plugins.schema
~~~~~~~~~~~~~~~~~~~~~~~~
Data-model for Megaploit plugins.

A plugin is a single  .toml  file dropped into the  plugins/  directory.
No Python knowledge is required to write one.

TOML Schema
-----------

[plugin]
name        = "my-plugin"          # unique id, no spaces
version     = "1.0.0"
author      = "Alice"
description = "Does cool things"

# ── Commands ──────────────────────────────────────────────────────────────────
# Each [[command]] block defines one new CLI command.
# Commands come in three kinds, set via the `kind` field:
#
#   kind = "local"    — run a shell command on the OPERATOR machine
#   kind = "session"  — send a shell command to the active AGENT session
#   kind = "python"   — call a Python function  (dotted import path)
#
# Placeholders available in `shell` and `args` strings:
#   {session_ip}   — IP of the current session (session commands only)
#   {session_id}   — numeric session ID        (session commands only)
#   {lhost}        — operator's LHOST setting
#   {port}         — operator's PORT setting
#   {arg0..argN}   — positional args passed on the CLI after the command name
#
# [[command]]
# name        = "portscan"
# kind        = "local"
# description = "Quick nmap scan against the active session's IP"
# usage       = "portscan [ports]"
# shell       = "nmap -sV -p {arg0} {session_ip}"
# min_args    = 0      # optional; default 0
# dangerous   = false  # optional; shows [!] in help and requires confirmation
#
# [[command]]
# name        = "getuid"
# kind        = "session"
# description = "Print the current user on the target"
# shell       = "id"          # command sent to the agent shell
#
# [[command]]
# name        = "mycheck"
# kind        = "python"
# description = "Run a custom Python check"
# handler     = "myplugin.checks.run_check"   # must be importable
# usage       = "mycheck <target>"
# min_args    = 1
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# stdlib tomllib (Python ≥ 3.11) or fallback to tomli (pip install tomli)
# ---------------------------------------------------------------------------

try:
    import tomllib as _toml        # stdlib ≥ 3.11
except ImportError:
    try:
        import tomli as _toml      # pip install tomli
    except ImportError:
        _toml = None               # handled gracefully in loader


def _load_toml(path: str) -> dict:
    """Read *path* and return the parsed dict. Raises on parse errors."""
    if _toml is None:
        raise RuntimeError(
            "TOML support requires Python 3.11+ or:  pip install tomli\n"
            "Install it and restart Megaploit to use plugins."
        )
    with open(path, "rb") as f:
        return _toml.load(f)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PluginCommand:
    name: str
    kind: str                       # "local" | "session" | "python"
    description: str = ""
    usage: str = ""
    shell: str = ""                 # for kind=local or kind=session
    handler: str = ""               # dotted path for kind=python
    min_args: int = 0
    dangerous: bool = False

    def validate(self) -> None:
        if self.kind not in ("local", "session", "python"):
            raise ValueError(
                f"Command '{self.name}': kind must be 'local', 'session', or 'python' — got '{self.kind}'"
            )
        if self.kind in ("local", "session") and not self.shell:
            raise ValueError(
                f"Command '{self.name}' (kind={self.kind}) requires a 'shell' string."
            )
        if self.kind == "python" and not self.handler:
            raise ValueError(
                f"Command '{self.name}' (kind=python) requires a 'handler' dotted path."
            )


@dataclass
class Plugin:
    name: str
    version: str = "0.0.0"
    author: str = ""
    description: str = ""
    commands: list[PluginCommand] = field(default_factory=list)
    source_path: str = ""           # absolute path to the .toml file

    @staticmethod
    def from_toml(path: str) -> "Plugin":
        """Parse a plugin TOML file and return a validated Plugin."""
        data = _load_toml(path)

        meta = data.get("plugin", {})
        name = meta.get("name", "").strip()
        if not name:
            raise ValueError(f"Plugin at '{path}' is missing [plugin] name field.")

        plugin = Plugin(
            name=name,
            version=str(meta.get("version", "0.0.0")),
            author=meta.get("author", ""),
            description=meta.get("description", ""),
            source_path=path,
        )

        for raw_cmd in data.get("command", []):
            cmd_name = raw_cmd.get("name", "").strip()
            if not cmd_name:
                raise ValueError(f"Plugin '{name}': a [[command]] block is missing 'name'.")

            cmd = PluginCommand(
                name=cmd_name,
                kind=raw_cmd.get("kind", "local"),
                description=raw_cmd.get("description", ""),
                usage=raw_cmd.get("usage", cmd_name),
                shell=raw_cmd.get("shell", ""),
                handler=raw_cmd.get("handler", ""),
                min_args=int(raw_cmd.get("min_args", 0)),
                dangerous=bool(raw_cmd.get("dangerous", False)),
            )
            cmd.validate()
            plugin.commands.append(cmd)

        return plugin
