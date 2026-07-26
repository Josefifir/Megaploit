"""
megaploit.plugins.loader
~~~~~~~~~~~~~~~~~~~~~~~~
Scans the  plugins/  directory for  *.toml  files, parses each one with
Plugin.from_toml(), validates it, and keeps a registry of all loaded plugins.

Usage
-----
    from megaploit.plugins.loader import plugin_loader

    plugin_loader.load_all()          # call once on startup

    for plugin in plugin_loader.plugins():
        print(plugin.name, plugin.version)

    plugin = plugin_loader.get("my-plugin")
    cmd    = plugin_loader.get_command("portscan")
"""

from __future__ import annotations

import os
from typing import Iterator, Optional

from megaploit.plugins.schema import Plugin, PluginCommand

PLUGINS_DIR = "plugins"


class PluginLoader:
    """Discover and load plugins from the plugins/ directory."""

    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}     # name → Plugin
        self._commands: dict[str, PluginCommand] = {}  # cmd name → PluginCommand
        self._errors: list[tuple[str, str]] = []   # (filename, error message)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_all(self) -> tuple[int, int]:
        """
        (Re-)scan  plugins/  and load every .toml file found.
        Returns (loaded_count, error_count).
        Clears previous state first so this doubles as a reload.
        """
        self._plugins.clear()
        self._commands.clear()
        self._errors.clear()

        if not os.path.isdir(PLUGINS_DIR):
            os.makedirs(PLUGINS_DIR, exist_ok=True)
            return 0, 0

        loaded = 0
        errors = 0

        for fname in sorted(os.listdir(PLUGINS_DIR)):
            if not fname.endswith(".toml"):
                continue
            path = os.path.join(PLUGINS_DIR, fname)
            try:
                plugin = Plugin.from_toml(path)
                self._register(plugin)
                loaded += 1
            except Exception as e:
                self._errors.append((fname, str(e)))
                errors += 1

        return loaded, errors

    def _register(self, plugin: Plugin) -> None:
        """Add a plugin and index its commands.  Later plugins win on name clash."""
        self._plugins[plugin.name] = plugin
        for cmd in plugin.commands:
            self._commands[cmd.name] = cmd

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def plugins(self) -> list[Plugin]:
        return list(self._plugins.values())

    def get(self, name: str) -> Optional[Plugin]:
        return self._plugins.get(name)

    def get_command(self, name: str) -> Optional[PluginCommand]:
        return self._commands.get(name)

    def all_command_names(self) -> list[str]:
        return list(self._commands.keys())

    def errors(self) -> list[tuple[str, str]]:
        return list(self._errors)

    def is_plugin_command(self, name: str) -> bool:
        return name in self._commands


# Module-level singleton
plugin_loader = PluginLoader()
