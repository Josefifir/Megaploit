"""
megaploit.modules.registry
~~~~~~~~~~~~~~~~~~~~~~~~~~
Auto-discovers and indexes all modules under megaploit/modules/.

Directory conventions
---------------------
  megaploit/modules/auxiliary/<name>.py
  megaploit/modules/exploits/<name>.py
  megaploit/modules/post/<name>.py
  megaploit/modules/payloads/<name>.py

Each module file must expose a module-level ``MODULE`` variable that is a
subclass of ``megaploit.modules.base.Module``.

Usage
-----
    from megaploit.modules.registry import module_registry

    module_registry.reload()                     # scan disk
    m = module_registry.get("auxiliary/scanner/tcp_port")
    inst = m()                                   # instantiate fresh copy
    inst.set("RHOSTS", "192.168.1.0/24")
    inst.run()

    # Iterate
    for entry in module_registry.all():
        print(entry.name, entry.module_type)
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import traceback
from dataclasses import dataclass, field
from typing import Iterator, Optional, Type

from megaploit.modules.base import Module, ModuleType

__all__ = ["ModuleEntry", "ModuleRegistry", "module_registry"]


# ---------------------------------------------------------------------------
# Module entry (metadata + class reference)
# ---------------------------------------------------------------------------

@dataclass
class ModuleEntry:
    """Lightweight catalogue entry returned by registry queries."""
    name:        str
    module_type: ModuleType
    description: str
    author:      str
    rank:        int
    path:        str            # filesystem path to the .py file
    klass:       Type[Module]   # the Module subclass (not yet instantiated)
    load_error:  str = ""       # non-empty if the file failed to import

    def instantiate(self) -> Module:
        """Return a fresh instance of the module."""
        return self.klass()

    def __repr__(self) -> str:
        return f"<ModuleEntry {self.name}>"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class ModuleRegistry:
    """Discovers, indexes, and provides access to all loaded modules."""

    # Root directories to scan, relative to the ``megaploit/modules/`` package
    _SCAN_DIRS = ["exploits", "auxiliary", "post", "payloads"]

    def __init__(self) -> None:
        self._modules: dict[str, ModuleEntry] = {}   # name → entry
        self._errors:  list[tuple[str, str]]  = []   # (path, message)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def reload(self, base_dir: str | None = None) -> tuple[int, int]:
        """
        Scan ``megaploit/modules/`` for module files and (re-)load them.

        Returns (loaded_count, error_count).
        """
        self._modules = {}
        self._errors  = []

        if base_dir is None:
            # Resolve relative to this file
            base_dir = os.path.dirname(os.path.abspath(__file__))

        for subdir in self._SCAN_DIRS:
            scan_path = os.path.join(base_dir, subdir)
            if not os.path.isdir(scan_path):
                continue
            for fname in sorted(os.listdir(scan_path)):
                if not fname.endswith(".py") or fname.startswith("_"):
                    continue
                fpath = os.path.join(scan_path, fname)
                self._load_file(fpath, subdir)

        return len(self._modules), len(self._errors)

    def _load_file(self, path: str, subdir: str) -> None:
        """Import a module file and register its MODULE class."""
        # Build a unique importlib module name
        stem = os.path.splitext(os.path.basename(path))[0]
        mod_name = f"megaploit.modules.{subdir}.{stem}"

        try:
            spec = importlib.util.spec_from_file_location(mod_name, path)
            if spec is None or spec.loader is None:
                self._errors.append((path, "Cannot create import spec"))
                return
            py_mod = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = py_mod
            spec.loader.exec_module(py_mod)  # type: ignore[attr-defined]
        except Exception:
            msg = traceback.format_exc(limit=3)
            self._errors.append((path, msg))
            return

        klass = getattr(py_mod, "MODULE", None)
        if klass is None:
            self._errors.append((path, "No MODULE variable defined"))
            return
        if not (isinstance(klass, type) and issubclass(klass, Module)):
            self._errors.append((path, "MODULE is not a subclass of Module"))
            return

        # Use the class-level .name attribute if set; fall back to filename
        try:
            inst_tmp = klass.__new__(klass)
            Module.__init__(inst_tmp)
        except Exception:
            self._errors.append((path, "Could not inspect module (init failed)"))
            return

        entry = ModuleEntry(
            name=inst_tmp.name,
            module_type=inst_tmp.module_type,
            description=inst_tmp.description,
            author=inst_tmp.author,
            rank=inst_tmp.rank,
            path=path,
            klass=klass,
        )
        self._modules[entry.name] = entry

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get(self, name: str) -> Optional[ModuleEntry]:
        return self._modules.get(name)

    def all(self) -> list[ModuleEntry]:
        return sorted(self._modules.values(), key=lambda e: e.name)

    def by_type(self, mtype: ModuleType) -> list[ModuleEntry]:
        return [e for e in self.all() if e.module_type == mtype]

    def search(self, query: str) -> list[ModuleEntry]:
        """Case-insensitive substring search over name + description."""
        q = query.lower()
        return [
            e for e in self.all()
            if q in e.name.lower() or q in e.description.lower()
        ]

    def errors(self) -> list[tuple[str, str]]:
        return list(self._errors)

    def names(self) -> list[str]:
        return sorted(self._modules.keys())

    def count(self) -> int:
        return len(self._modules)

    # ------------------------------------------------------------------
    # Tree view (for 'show modules' / completion)
    # ------------------------------------------------------------------

    def tree(self) -> dict[str, dict[str, list[str]]]:
        """
        Return nested dict: type → sub-path → [leaf names].

        Example::

            {
              "auxiliary": {
                "scanner": ["tcp_port", "smb_shares"],
              },
              "exploits": {
                "windows/smb": ["ms17_010"],
              }
            }
        """
        result: dict[str, dict[str, list[str]]] = {}
        for entry in self.all():
            parts = entry.name.split("/")
            if len(parts) < 2:
                mtype  = entry.module_type.value
                subkey = ""
                leaf   = parts[0]
            else:
                mtype  = parts[0]
                subkey = "/".join(parts[1:-1])
                leaf   = parts[-1]
            result.setdefault(mtype, {}).setdefault(subkey, []).append(leaf)
        return result

    def __repr__(self) -> str:
        return f"<ModuleRegistry  {self.count()} modules>"


# ---------------------------------------------------------------------------
# Singleton — import and use everywhere
# ---------------------------------------------------------------------------

module_registry = ModuleRegistry()
