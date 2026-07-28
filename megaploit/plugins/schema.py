"""
megaploit.plugins.schema
~~~~~~~~~~~~~~~~~~~~~~~~
Data-model for Megaploit plugins.

A plugin is a single  .toml  **or**  .json  file dropped into the  plugins/
directory.  No Python knowledge is required to write one.

TOML Schema  (v2)
-----------------

[plugin]
name                = "my-plugin"      # unique id, no spaces
version             = "1.0.0"          # semver recommended
author              = "Alice"
description         = "Does cool things"
min_megaploit_version = "2.2.0"        # optional — enforced by loader
tags                = ["recon", "web"] # optional search tags
requires            = ["requests"]     # pip packages that must be present
homepage            = "https://…"      # optional URL
license             = "MIT"            # optional SPDX identifier

# ── Commands ─────────────────────────────────────────────────────────────────
# Each [[command]] block defines one new CLI command.
# Commands come in four kinds, set via the `kind` field:
#
#   kind = "local"    — run a shell command on the OPERATOR machine
#   kind = "session"  — send a shell command to the active AGENT session
#   kind = "python"   — call a Python function  (dotted import path)
#   kind = "native"   — compile and run a C / C++ source file
#
# Placeholders available in `shell` and `args` strings:
#   {session_ip}     — IP of the current session (session commands only)
#   {session_id}     — numeric session ID         (session commands only)
#   {session_tag}    — operator tag for the session
#   {session_os}     — os_name field of the session
#   {lhost}          — operator's LHOST setting
#   {port}           — operator's PORT setting
#   {arg0..argN}     — positional args passed on the CLI after the command name
#   {joined_args}    — all args joined with spaces
#
# [[command]]
# name          = "portscan"
# kind          = "local"
# description   = "Quick nmap scan against the active session's IP"
# usage         = "portscan [ports]"
# shell         = "nmap -sV -p {arg0:-top100} {session_ip}"
# min_args      = 0
# dangerous     = false
# timeout       = 120          # seconds; 0 = no limit
# output_format = "raw"        # "raw" | "table" | "json"
# tags          = ["network"]
# env_vars      = { NMAP_COLOR = "1" }
# retry         = 2            # retry count on failure
#
# [[command]]
# name          = "getuid"
# kind          = "session"
# description   = "Print the current user on the target"
# shell         = "id"
# output_format = "raw"
#
# [[command]]
# name          = "mycheck"
# kind          = "python"
# description   = "Run a custom Python check"
# handler       = "myplugin.checks.run_check"
# usage         = "mycheck <target>"
# min_args      = 1
# output_format = "json"
#
# [[command]]
# name           = "tcpprobe"
# kind           = "native"
# description    = "TCP probe via a compiled C++ binary"
# source_file    = "plugins/myplugin/probe.cpp"
# compiler_flags = "-std=c++17 -O2"   # optional; passed verbatim to gcc/g++
# usage          = "tcpprobe <host> <port>"
# min_args       = 2
# timeout        = 15
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

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
    """Read *path* and return the parsed dict.  Raises on parse errors."""
    if _toml is None:
        raise RuntimeError(
            "TOML support requires Python 3.11+ or:  pip install tomli\n"
            "Install it and restart Megaploit to use plugins."
        )
    with open(path, "rb") as f:
        return _toml.load(f)


def _load_json(path: str) -> dict:
    """Read a JSON plugin file and return the parsed dict."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Version comparison helper
# ---------------------------------------------------------------------------

def _parse_semver(v: str) -> tuple[int, int, int]:
    """Parse 'MAJOR.MINOR.PATCH' — returns (0,0,0) on failure."""
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", v.strip())
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def version_meets_minimum(version: str, minimum: str) -> bool:
    """Return True if *version* >= *minimum*."""
    return _parse_semver(version) >= _parse_semver(minimum)


# ---------------------------------------------------------------------------
# PluginContext  — passed to python-kind handlers
# ---------------------------------------------------------------------------

@dataclass
class PluginContext:
    """
    Execution context passed to Python plugin handlers.

    Handlers receive  (args: list[str], ctx: PluginContext)
    and should return a str result or None.
    """
    lhost: str = ""
    port: int = 0
    session_ip: str = ""
    session_id: int = 0
    session_tag: str = ""
    session_os: str = ""
    session_hostname: str = ""
    session_username: str = ""
    positional: list[str] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    command_name: str = ""
    plugin_name: str = ""

    # ── Output streaming (set by runner before calling the handler) ───
    _output_fn: Any = field(default=None, repr=False, compare=False)

    def emit(self, line: str) -> None:
        """Stream a single output line back to the operator console."""
        if self._output_fn is not None:
            self._output_fn(line)


# ---------------------------------------------------------------------------
# OutputFormat
# ---------------------------------------------------------------------------

_VALID_OUTPUT_FORMATS = ("raw", "table", "json", "pretty_json", "csv")


# ---------------------------------------------------------------------------
# PluginCommand
# ---------------------------------------------------------------------------

@dataclass
class PluginCommand:
    name: str
    kind: str                           # "local" | "session" | "python" | "native"
    description: str = ""
    usage: str = ""
    shell: str = ""                     # for kind=local or kind=session
    handler: str = ""                   # dotted path for kind=python
    source_file: str = ""               # path to .c / .cpp source for kind=native
    compiler_flags: str = ""            # extra flags passed verbatim to gcc/g++/clang
    min_args: int = 0
    max_args: int = -1                  # -1 = unlimited
    dangerous: bool = False
    timeout: int = 0                    # seconds; 0 = no limit
    output_format: str = "raw"          # "raw" | "table" | "json" | "pretty_json" | "csv"
    tags: list[str] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    retry: int = 0                      # retry count on non-zero exit
    notes: str = ""                     # operator-facing notes shown in help
    requires: list[str] = field(default_factory=list)  # pip packages

    # ── Plugin back-reference (set by Plugin.from_*) ──────────────────
    plugin_name: str = ""

    def validate(self) -> None:
        if self.kind not in ("local", "session", "python", "native"):
            raise ValueError(
                f"Command '{self.name}': kind must be 'local', 'session', 'python',"
                f" or 'native' — got '{self.kind}'"
            )
        if self.kind in ("local", "session") and not self.shell:
            raise ValueError(
                f"Command '{self.name}' (kind={self.kind}) requires a 'shell' string."
            )
        if self.kind == "python" and not self.handler:
            raise ValueError(
                f"Command '{self.name}' (kind=python) requires a 'handler' dotted path."
            )
        if self.kind == "native" and not self.source_file:
            raise ValueError(
                f"Command '{self.name}' (kind=native) requires a 'source_file' path."
            )
        if self.output_format not in _VALID_OUTPUT_FORMATS:
            raise ValueError(
                f"Command '{self.name}': output_format must be one of "
                f"{_VALID_OUTPUT_FORMATS} — got '{self.output_format}'"
            )
        if self.min_args < 0:
            raise ValueError(f"Command '{self.name}': min_args must be >= 0")
        if self.timeout < 0:
            raise ValueError(f"Command '{self.name}': timeout must be >= 0")

    def check_args(self, args: list[str]) -> Optional[str]:
        """
        Return an error string if *args* does not satisfy this command's
        arity constraints, or None if all is well.
        """
        if len(args) < self.min_args:
            return (
                f"[-] '{self.name}' requires at least {self.min_args} argument(s).\n"
                f"    Usage: {self.usage or self.name}"
            )
        if self.max_args >= 0 and len(args) > self.max_args:
            return (
                f"[-] '{self.name}' accepts at most {self.max_args} argument(s).\n"
                f"    Usage: {self.usage or self.name}"
            )
        return None

    def short_help(self) -> str:
        """One-liner for help tables."""
        danger = "  [!]" if self.dangerous else ""
        fmt    = f"  [{self.output_format}]" if self.output_format != "raw" else ""
        return f"{self.description}{danger}{fmt}"


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

@dataclass
class Plugin:
    name: str
    version: str = "0.0.0"
    author: str = ""
    description: str = ""
    homepage: str = ""
    license: str = ""
    tags: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)   # pip deps
    min_megaploit_version: str = ""
    commands: list[PluginCommand] = field(default_factory=list)
    source_path: str = ""               # absolute path to the .toml/.json file
    enabled: bool = True                # can be toggled by the loader

    # ──────────────────────────────────────────────────────────────────
    # Factories
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def from_toml(path: str) -> "Plugin":
        """Parse a plugin TOML file and return a validated Plugin."""
        return Plugin._from_dict(_load_toml(path), path)

    @staticmethod
    def from_json(path: str) -> "Plugin":
        """Parse a plugin JSON file and return a validated Plugin."""
        return Plugin._from_dict(_load_json(path), path)

    @staticmethod
    def from_file(path: str) -> "Plugin":
        """
        Auto-detect file format from extension and parse.

        Supported: .toml, .json
        """
        ext = os.path.splitext(path)[1].lower()
        if ext == ".toml":
            return Plugin.from_toml(path)
        if ext == ".json":
            return Plugin.from_json(path)
        raise ValueError(
            f"Unsupported plugin file format '{ext}' for '{path}'.\n"
            "Supported extensions: .toml  .json"
        )

    @staticmethod
    def _from_dict(data: dict, source_path: str) -> "Plugin":
        """Shared parser for both TOML and JSON plugin data."""
        meta = data.get("plugin", {})
        name = str(meta.get("name", "")).strip()
        if not name:
            raise ValueError(
                f"Plugin at '{source_path}' is missing [plugin] name field."
            )

        plugin = Plugin(
            name=name,
            version=str(meta.get("version", "0.0.0")),
            author=str(meta.get("author", "")),
            description=str(meta.get("description", "")),
            homepage=str(meta.get("homepage", "")),
            license=str(meta.get("license", "")),
            tags=[str(t) for t in meta.get("tags", [])],
            requires=[str(r) for r in meta.get("requires", [])],
            min_megaploit_version=str(meta.get("min_megaploit_version", "")),
            source_path=source_path,
            enabled=bool(meta.get("enabled", True)),
        )

        for raw_cmd in data.get("command", []):
            cmd = Plugin._parse_command(raw_cmd, plugin.name, source_path)
            cmd.validate()
            plugin.commands.append(cmd)

        return plugin

    @staticmethod
    def _parse_command(raw: dict, plugin_name: str, source_path: str) -> PluginCommand:
        cmd_name = str(raw.get("name", "")).strip()
        if not cmd_name:
            raise ValueError(
                f"Plugin '{plugin_name}' ({source_path}): a [[command]] block is missing 'name'."
            )
        env_raw = raw.get("env_vars", {})
        if not isinstance(env_raw, dict):
            env_raw = {}
        return PluginCommand(
            name=cmd_name,
            kind=str(raw.get("kind", "local")),
            description=str(raw.get("description", "")),
            usage=str(raw.get("usage", cmd_name)),
            shell=str(raw.get("shell", "")),
            handler=str(raw.get("handler", "")),
            source_file=str(raw.get("source_file", "")),
            compiler_flags=str(raw.get("compiler_flags", "")),
            min_args=int(raw.get("min_args", 0)),
            max_args=int(raw.get("max_args", -1)),
            dangerous=bool(raw.get("dangerous", False)),
            timeout=int(raw.get("timeout", 0)),
            output_format=str(raw.get("output_format", "raw")),
            tags=[str(t) for t in raw.get("tags", [])],
            env_vars={str(k): str(v) for k, v in env_raw.items()},
            retry=int(raw.get("retry", 0)),
            notes=str(raw.get("notes", "")),
            requires=[str(r) for r in raw.get("requires", [])],
            plugin_name=plugin_name,
        )

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    def get_command(self, name: str) -> Optional[PluginCommand]:
        for cmd in self.commands:
            if cmd.name == name:
                return cmd
        return None

    def command_names(self) -> list[str]:
        return [c.name for c in self.commands]

    def to_dict(self) -> dict:
        """Serialise the plugin metadata (not commands) to a plain dict."""
        return {
            "name":                   self.name,
            "version":                self.version,
            "author":                 self.author,
            "description":            self.description,
            "homepage":               self.homepage,
            "license":                self.license,
            "tags":                   self.tags,
            "requires":               self.requires,
            "min_megaploit_version":  self.min_megaploit_version,
            "commands":               [c.name for c in self.commands],
            "source_path":            self.source_path,
            "enabled":                self.enabled,
        }

    def __repr__(self) -> str:
        return (
            f"Plugin(name={self.name!r}, version={self.version!r}, "
            f"commands={len(self.commands)}, enabled={self.enabled})"
        )


# ---------------------------------------------------------------------------
# Placeholder-expansion constants  (shared with runner)
# ---------------------------------------------------------------------------

PLACEHOLDER_KEYS = (
    "session_ip",
    "session_id",
    "session_tag",
    "session_os",
    "session_hostname",
    "session_username",
    "lhost",
    "port",
    "joined_args",
)
