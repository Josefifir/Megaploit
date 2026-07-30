"""
megaploit.plugins.loader
~~~~~~~~~~~~~~~~~~~~~~~~
Discovers and manages Megaploit plugins from the ``plugins/`` directory.

Supports:
  - Loading from .toml and .json plugin files
  - Loading a plugin from a .zip archive (extracts to plugins/)
  - Loading a plugin from a remote URL (downloads then loads)
  - Hot-reload via a background filesystem watcher thread
  - Per-plugin enable / disable
  - Version-conflict detection (two plugins registering the same command)
  - Dependency checking (pip packages listed in plugin.requires)
  - Min-megaploit-version enforcement

Usage
-----
    from megaploit.plugins.loader import plugin_loader

    plugin_loader.load_all()          # call once on startup

    for plugin in plugin_loader.plugins():
        print(plugin.name, plugin.version)

    plugin = plugin_loader.get("my-plugin")
    cmd    = plugin_loader.get_command("portscan")

    # Hot-reload watcher (background thread)
    plugin_loader.start_watcher()     # auto-reloads when plugins/ changes
    plugin_loader.stop_watcher()
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import urllib.request
import zipfile
from typing import Callable, Optional

from megaploit.plugins.schema import Plugin, PluginCommand, version_meets_minimum

PLUGINS_DIR = "plugins"
_MEGAPLOIT_VERSION = "2.2.0"          # used for min_megaploit_version checks

_LOG = logging.getLogger("megaploit.plugins.loader")

# ---------------------------------------------------------------------------
# Conflict record
# ---------------------------------------------------------------------------

class CommandConflict:
    """Records that two plugins define the same command name."""

    def __init__(self, command_name: str, winner: str, loser: str) -> None:
        self.command_name = command_name
        self.winner       = winner       # plugin name that "won"
        self.loser        = loser        # plugin name that was overridden

    def __str__(self) -> str:
        return (
            f"Command '{self.command_name}' defined by both '{self.loser}' and "
            f"'{self.winner}' — '{self.winner}' wins (loaded last)."
        )


# ---------------------------------------------------------------------------
# Missing-dependency record
# ---------------------------------------------------------------------------

class MissingDependency:
    """Records a pip package that a plugin requires but which is not installed."""

    def __init__(self, plugin_name: str, package: str) -> None:
        self.plugin_name = plugin_name
        self.package     = package

    def __str__(self) -> str:
        return f"Plugin '{self.plugin_name}' requires '{self.package}' — not installed."

    def install_hint(self) -> str:
        return f"pip install {self.package}"


# ---------------------------------------------------------------------------
# PluginLoader
# ---------------------------------------------------------------------------

class PluginLoader:
    """
    Discover, load, and manage plugins from the plugins/ directory.

    Thread-safety: individual load operations take ``_lock``.
    The hot-reload watcher runs in a daemon thread and acquires the lock
    before each reload.
    """

    def __init__(self) -> None:
        self._plugins:   dict[str, Plugin]        = {}   # name → Plugin
        self._commands:  dict[str, PluginCommand] = {}   # cmd name → PluginCommand
        self._errors:    list[tuple[str, str]]    = []   # (filename, error msg)
        self._conflicts: list[CommandConflict]    = []
        self._missing_deps: list[MissingDependency] = []
        self._disabled:  set[str]                 = set()  # disabled plugin names
        self._lock       = threading.Lock()
        self._watcher:   Optional[threading.Thread] = None
        self._watcher_stop = threading.Event()
        self._on_reload:  Optional[Callable[[int, int], None]] = None

    # ------------------------------------------------------------------
    # Loading — main entry point
    # ------------------------------------------------------------------

    def load_all(self) -> tuple[int, int]:
        """
        (Re-)scan the plugins directory and load every supported file.

        Returns ``(loaded_count, error_count)``.
        Clears previous state first, so this doubles as a full reload.
        """
        with self._lock:
            return self._load_all_unsafe()

    def _load_all_unsafe(self) -> tuple[int, int]:
        """Internal — must be called with self._lock held."""
        self._plugins.clear()
        self._commands.clear()
        self._errors.clear()
        self._conflicts.clear()
        self._missing_deps.clear()

        os.makedirs(PLUGINS_DIR, exist_ok=True)

        loaded = 0
        errors = 0

        for fname in sorted(os.listdir(PLUGINS_DIR)):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in (".toml", ".json"):
                continue
            path = os.path.join(PLUGINS_DIR, fname)
            ok, err = self._load_file_unsafe(path)
            if ok:
                loaded += 1
            else:
                errors += 1

        return loaded, errors

    def _load_file_unsafe(self, path: str) -> tuple[bool, Optional[str]]:
        """
        Parse, validate, and register a single plugin file.

        Returns ``(True, None)`` on success or ``(False, error_msg)``.
        Assumes ``self._lock`` is held.
        """
        fname = os.path.basename(path)
        try:
            plugin = Plugin.from_file(path)
        except Exception as e:
            err = str(e)
            self._errors.append((fname, err))
            _LOG.warning("Failed to parse plugin '%s': %s", fname, err)
            return False, err

        # Disabled check
        if plugin.name in self._disabled:
            plugin.enabled = False

        if not plugin.enabled:
            _LOG.debug("Plugin '%s' is disabled — skipping.", plugin.name)
            return True, None   # counted as loaded (just inactive)

        # min_megaploit_version
        if plugin.min_megaploit_version:
            if not version_meets_minimum(_MEGAPLOIT_VERSION, plugin.min_megaploit_version):
                err = (
                    f"Plugin '{plugin.name}' requires Megaploit >= "
                    f"{plugin.min_megaploit_version} (running {_MEGAPLOIT_VERSION})."
                )
                self._errors.append((fname, err))
                _LOG.warning(err)
                return False, err

        # Dependency check
        for pkg in plugin.requires:
            if not self._is_importable(pkg):
                md = MissingDependency(plugin.name, pkg)
                self._missing_deps.append(md)
                _LOG.warning(str(md))

        self._register_unsafe(plugin)
        return True, None

    def _register_unsafe(self, plugin: Plugin) -> None:
        """Register a plugin and index its commands.  Assumes lock held."""
        self._plugins[plugin.name] = plugin
        for cmd in plugin.commands:
            if cmd.name in self._commands:
                existing = self._commands[cmd.name]
                conflict = CommandConflict(
                    command_name=cmd.name,
                    winner=plugin.name,
                    loser=existing.plugin_name,
                )
                self._conflicts.append(conflict)
                _LOG.warning(str(conflict))
            self._commands[cmd.name] = cmd

    # ------------------------------------------------------------------
    # Load a single file (hot-add, for watcher)
    # ------------------------------------------------------------------

    def load_file(self, path: str) -> tuple[bool, Optional[str]]:
        """
        Load or reload a single plugin file by path.

        Safe to call from any thread.  Returns ``(ok, error_or_None)``.
        """
        with self._lock:
            # Unregister old version of this plugin if it was loaded
            existing = self._find_plugin_by_path(path)
            if existing:
                self._unregister_unsafe(existing.name)
            return self._load_file_unsafe(path)

    def _find_plugin_by_path(self, path: str) -> Optional[Plugin]:
        norm = os.path.normpath(os.path.abspath(path))
        for p in self._plugins.values():
            if os.path.normpath(os.path.abspath(p.source_path)) == norm:
                return p
        return None

    # ------------------------------------------------------------------
    # Load from ZIP archive
    # ------------------------------------------------------------------

    def load_zip(self, zip_path: str) -> tuple[int, int]:
        """
        Extract a .zip archive into ``plugins/`` and load all plugin files it
        contains.  The zip is expected to contain .toml or .json files at its
        root or in a single subdirectory.

        Returns ``(loaded, errors)``.
        """
        if not zipfile.is_zipfile(zip_path):
            raise ValueError(f"'{zip_path}' is not a valid ZIP archive.")

        extracted: list[str] = []
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                ext = os.path.splitext(member)[1].lower()
                if ext not in (".toml", ".json"):
                    continue
                # Flatten — always extract into PLUGINS_DIR root
                basename = os.path.basename(member)
                if not basename:
                    continue
                dest = os.path.join(PLUGINS_DIR, basename)
                with zf.open(member) as src, open(dest, "wb") as dst:
                    dst.write(src.read())
                extracted.append(dest)

        if not extracted:
            raise RuntimeError(
                f"ZIP '{zip_path}' contained no .toml or .json plugin files."
            )

        loaded = errors = 0
        for path in extracted:
            ok, _ = self.load_file(path)
            if ok:
                loaded += 1
            else:
                errors += 1
        return loaded, errors

    # ------------------------------------------------------------------
    # Load from URL
    # ------------------------------------------------------------------

    def load_url(self, url: str, timeout: int = 30) -> tuple[bool, Optional[str]]:
        """
        Download a plugin file from *url* and load it.

        The URL must point directly to a .toml, .json, or .zip file.
        Returns ``(ok, error_or_None)``.
        """
        ext = os.path.splitext(url.split("?")[0])[1].lower()
        if ext not in (".toml", ".json", ".zip"):
            return False, (
                f"URL must point to a .toml, .json, or .zip file — got '{ext}'."
            )

        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                data = resp.read()
        except Exception as e:
            return False, f"Failed to download '{url}': {e}"

        # Save to a temp file then hand off to existing loaders
        suffix = ext
        with tempfile.NamedTemporaryFile(
            suffix=suffix, dir=PLUGINS_DIR, delete=False
        ) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            if ext == ".zip":
                loaded, errors = self.load_zip(tmp_path)
                return errors == 0, None if errors == 0 else f"{errors} error(s) loading ZIP"
            else:
                return self.load_file(tmp_path)
        finally:
            # Keep the file on disk if load succeeded (it's in PLUGINS_DIR),
            # remove it if it was a zip temp file.
            if ext == ".zip":
                os.unlink(tmp_path)

    # ------------------------------------------------------------------
    # Enable / disable plugins
    # ------------------------------------------------------------------

    def disable(self, name: str) -> bool:
        """
        Disable a plugin by name.  Its commands are removed from the index
        immediately.  Returns True if the plugin was found and disabled.
        """
        with self._lock:
            if name not in self._plugins:
                return False
            self._disabled.add(name)
            self._plugins[name].enabled = False
            self._unregister_commands_unsafe(name)
            _LOG.info("Plugin '%s' disabled.", name)
            return True

    def enable(self, name: str) -> bool:
        """
        Re-enable a previously disabled plugin and re-index its commands.
        Returns True if the plugin was found and enabled.
        """
        with self._lock:
            if name not in self._plugins:
                return False
            self._disabled.discard(name)
            plugin = self._plugins[name]
            plugin.enabled = True
            for cmd in plugin.commands:
                self._commands[cmd.name] = cmd
            _LOG.info("Plugin '%s' enabled.", name)
            return True

    def is_enabled(self, name: str) -> bool:
        plugin = self._plugins.get(name)
        return plugin.enabled if plugin else False

    # ------------------------------------------------------------------
    # Unregister
    # ------------------------------------------------------------------

    def _unregister_unsafe(self, name: str) -> None:
        """Remove a plugin and its commands.  Assumes lock held."""
        self._unregister_commands_unsafe(name)
        self._plugins.pop(name, None)

    def _unregister_commands_unsafe(self, plugin_name: str) -> None:
        """Remove all commands owned by *plugin_name*.  Assumes lock held."""
        to_remove = [
            cname for cname, cmd in self._commands.items()
            if cmd.plugin_name == plugin_name
        ]
        for cname in to_remove:
            del self._commands[cname]

    # ------------------------------------------------------------------
    # Hot-reload watcher
    # ------------------------------------------------------------------

    def start_watcher(
        self,
        interval: float = 3.0,
        on_reload: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """
        Start a background thread that polls ``plugins/`` every *interval*
        seconds and calls ``load_all()`` when any file's mtime changes.

        *on_reload(loaded, errors)* is called after each successful reload
        that detected a change.
        """
        if self._watcher is not None and self._watcher.is_alive():
            return   # already running

        self._watcher_stop.clear()
        self._on_reload = on_reload
        self._watcher   = threading.Thread(
            target=self._watch_loop,
            args=(interval,),
            daemon=True,
            name="megaploit.plugins.watcher",
        )
        self._watcher.start()
        _LOG.info("Plugin hot-reload watcher started (interval=%.1fs).", interval)

    def stop_watcher(self) -> None:
        """Stop the hot-reload watcher thread."""
        self._watcher_stop.set()
        if self._watcher:
            self._watcher.join(timeout=5)
            self._watcher = None
        _LOG.info("Plugin hot-reload watcher stopped.")

    def _watch_loop(self, interval: float) -> None:
        last_snapshot = self._dir_snapshot()
        while not self._watcher_stop.wait(timeout=interval):
            try:
                snapshot = self._dir_snapshot()
                if snapshot != last_snapshot:
                    # Determine which changed paths are module files vs plugin descriptors
                    changed = {p for p in snapshot if snapshot.get(p) != last_snapshot.get(p)}
                    last_snapshot = snapshot

                    loaded, errors = self.load_all()
                    _LOG.info(
                        "Plugin reload triggered by file change: %d loaded, %d errors.",
                        loaded, errors
                    )

                    # Hot-reload module registry if any .py in megaploit/modules/ changed
                    if any(p.endswith(".py") for p in changed):
                        try:
                            from megaploit.modules.registry import module_registry as _mr
                            mod_count, mod_errors = _mr.reload()
                            _LOG.info(
                                "Module registry reloaded: %d modules, %d errors.",
                                mod_count, mod_errors,
                            )
                        except Exception as exc:
                            _LOG.debug("Module registry reload error: %s", exc)

                    if self._on_reload:
                        try:
                            self._on_reload(loaded, errors)
                        except Exception:
                            pass
            except Exception as e:
                _LOG.debug("Watcher loop error: %s", e)

    def _dir_snapshot(self) -> dict[str, float]:
        """
        Return a dict of {path: mtime} for all files that affect plugin state.

        Covers:
          - .toml / .json descriptor files in the plugins/ root
          - .c / .cpp source files referenced by loaded native commands
            (so a recompile is triggered whenever the source changes)
          - .py module files under megaploit/modules/ (feature 6c)
            (so a module hot-reload is triggered when a module is edited)
        """
        snapshot: dict[str, float] = {}
        if not os.path.isdir(PLUGINS_DIR):
            return snapshot

        # Descriptor files
        for fname in os.listdir(PLUGINS_DIR):
            ext = os.path.splitext(fname)[1].lower()
            if ext in (".toml", ".json"):
                path = os.path.join(PLUGINS_DIR, fname)
                try:
                    snapshot[path] = os.path.getmtime(path)
                except OSError:
                    pass

        # Native source files referenced by active commands
        with self._lock:
            for cmd in self._commands.values():
                if cmd.kind == "native" and cmd.source_file:
                    src = os.path.abspath(cmd.source_file)
                    try:
                        snapshot[src] = os.path.getmtime(src)
                    except OSError:
                        pass

        # Python module files under megaploit/modules/ (feature 6c)
        # Walk the modules directory and record every .py file's mtime so
        # any edit or new file triggers a module_registry.reload().
        _modules_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),   # plugins/
            "..",                                          # megaploit/
            "modules",
        )
        _modules_dir = os.path.normpath(_modules_dir)
        if os.path.isdir(_modules_dir):
            for dirpath, _dirs, filenames in os.walk(_modules_dir):
                _dirs[:] = [d for d in _dirs if not d.startswith("_")]
                for fname in filenames:
                    if fname.endswith(".py") and not fname.startswith("_"):
                        fpath = os.path.join(dirpath, fname)
                        try:
                            snapshot[fpath] = os.path.getmtime(fpath)
                        except OSError:
                            pass

        return snapshot

    # ------------------------------------------------------------------
    # Dependency installation helper
    # ------------------------------------------------------------------

    def install_missing_deps(self) -> dict[str, bool]:
        """
        Attempt to pip-install all packages listed in ``_missing_deps``.

        Returns ``{package_name: success}`` mapping.
        """
        results: dict[str, bool] = {}
        for md in list(self._missing_deps):
            pkg = md.package
            if pkg in results:
                continue
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "--quiet", pkg],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                results[pkg] = True
                _LOG.info("Installed missing dependency '%s'.", pkg)
            except subprocess.CalledProcessError:
                results[pkg] = False
                _LOG.warning("Failed to install dependency '%s'.", pkg)
        return results

    @staticmethod
    def _is_importable(package: str) -> bool:
        """
        Check whether a Python package is importable.

        Handles dotted names (e.g. ``yaml`` for PyYAML), dashes-to-underscores,
        and common aliases like ``Pillow`` → ``PIL``.
        """
        _ALIASES = {
            "pillow":    "PIL",
            "pyyaml":    "yaml",
            "scikit-learn": "sklearn",
            "beautifulsoup4": "bs4",
            "dnspython": "dns",
        }
        name = _ALIASES.get(package.lower(), package.replace("-", "_"))
        try:
            importlib.import_module(name)
            return True
        except ImportError:
            return False

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def plugins(self) -> list[Plugin]:
        """Return all loaded plugins (including disabled ones)."""
        return list(self._plugins.values())

    def active_plugins(self) -> list[Plugin]:
        """Return only enabled loaded plugins."""
        return [p for p in self._plugins.values() if p.enabled]

    def get(self, name: str) -> Optional[Plugin]:
        return self._plugins.get(name)

    def get_command(self, name: str) -> Optional[PluginCommand]:
        return self._commands.get(name)

    def all_command_names(self) -> list[str]:
        return list(self._commands.keys())

    def errors(self) -> list[tuple[str, str]]:
        return list(self._errors)

    def conflicts(self) -> list[CommandConflict]:
        return list(self._conflicts)

    def missing_deps(self) -> list[MissingDependency]:
        return list(self._missing_deps)

    def is_plugin_command(self, name: str) -> bool:
        return name in self._commands

    def search(self, query: str) -> list[Plugin]:
        """
        Return plugins whose name, description, or tags contain *query*
        (case-insensitive substring match).
        """
        q = query.lower()
        results: list[Plugin] = []
        for p in self._plugins.values():
            if (q in p.name.lower()
                    or q in p.description.lower()
                    or any(q in t.lower() for t in p.tags)):
                results.append(p)
        return results

    def commands_by_tag(self, tag: str) -> list[PluginCommand]:
        """Return all plugin commands that carry the given tag."""
        t = tag.lower()
        return [cmd for cmd in self._commands.values() if t in [x.lower() for x in cmd.tags]]

    def commands_by_kind(self, kind: str) -> list[PluginCommand]:
        """Return all plugin commands of the specified kind."""
        return [cmd for cmd in self._commands.values() if cmd.kind == kind]

    # ------------------------------------------------------------------
    # Status summary
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """Return a summary dict for display in the CLI."""
        return {
            "plugins_loaded":   len(self._plugins),
            "plugins_active":   sum(1 for p in self._plugins.values() if p.enabled),
            "plugins_disabled": len(self._disabled),
            "commands":         len(self._commands),
            "errors":           len(self._errors),
            "conflicts":        len(self._conflicts),
            "missing_deps":     len(self._missing_deps),
            "watcher_running":  self._watcher is not None and self._watcher.is_alive(),
        }

    def stats_line(self) -> str:
        s = self.status()
        parts = [
            f"{s['plugins_active']} active",
            f"{s['commands']} commands",
        ]
        if s["plugins_disabled"]:
            parts.append(f"{s['plugins_disabled']} disabled")
        if s["errors"]:
            parts.append(f"{s['errors']} errors")
        if s["conflicts"]:
            parts.append(f"{s['conflicts']} conflicts")
        if s["missing_deps"]:
            parts.append(f"{s['missing_deps']} missing deps")
        return "  ".join(parts)

    # ------------------------------------------------------------------
    # Persistence  (enabled/disabled state across restarts)
    # ------------------------------------------------------------------

    _STATE_FILE = os.path.join(PLUGINS_DIR, ".loader_state.json")

    def save_state(self) -> None:
        """Persist disabled plugin names to a JSON file."""
        try:
            os.makedirs(PLUGINS_DIR, exist_ok=True)
            with open(self._STATE_FILE, "w", encoding="utf-8") as f:
                json.dump({"disabled": sorted(self._disabled)}, f, indent=2)
        except OSError as e:
            _LOG.warning("Could not save plugin loader state: %s", e)

    def load_state(self) -> None:
        """Restore disabled plugin names from the JSON state file."""
        try:
            with open(self._STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._disabled = set(data.get("disabled", []))
        except FileNotFoundError:
            pass
        except (json.JSONDecodeError, OSError) as e:
            _LOG.warning("Could not load plugin loader state: %s", e)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

plugin_loader = PluginLoader()
