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
            for dirpath, _dirs, filenames in os.walk(scan_path):
                _dirs[:] = sorted(d for d in _dirs if not d.startswith("_"))
                for fname in sorted(filenames):
                    if not fname.endswith(".py") or fname.startswith("_"):
                        continue
                    fpath = os.path.join(dirpath, fname)
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
        """
        Search modules supporting both plain substring and structured filters.

        Structured filter tokens (Metasploit-compatible):
            type:<exploit|auxiliary|post|payload>
            platform:<windows|linux|…>
            cve:<partial-cve-string>
            rank:>N  rank:<N  rank:N  (numeric comparison)
            author:<substring>
            name:<substring>

        Any remaining non-filter tokens are matched as plain substrings against
        name + description.

        Examples::

            search type:exploit platform:windows
            search cve:2024 rank:>400
            search type:auxiliary ldap
        """
        import re as _re

        tokens = query.split()
        plain_tokens: list[str] = []
        filters: dict[str, str] = {}

        _FILTER_RE = _re.compile(r'^(type|platform|cve|rank|author|name):(.+)$', _re.IGNORECASE)
        for tok in tokens:
            m = _FILTER_RE.match(tok)
            if m:
                filters[m.group(1).lower()] = m.group(2)
            else:
                plain_tokens.append(tok.lower())

        def _matches(e: "ModuleEntry") -> bool:
            # --- structured filters ---
            if "type" in filters:
                if filters["type"].lower() not in e.module_type.value.lower():
                    return False
            if "platform" in filters:
                plat_q = filters["platform"].lower()
                # module.platform is list[str]; ModuleEntry doesn't have it directly —
                # use the instance's class attribute via klass.platform
                plats = [p.lower() for p in getattr(e.klass, "platform", [])]
                if not any(plat_q in p for p in plats):
                    return False
            if "cve" in filters:
                cve_q = filters["cve"].lower()
                refs = " ".join(getattr(e.klass, "references", [])).lower()
                if cve_q not in refs and cve_q not in e.name.lower() and cve_q not in e.description.lower():
                    return False
            if "author" in filters:
                if filters["author"].lower() not in e.author.lower():
                    return False
            if "name" in filters:
                if filters["name"].lower() not in e.name.lower():
                    return False
            if "rank" in filters:
                raw_rank = filters["rank"]
                m_rank = _re.match(r'^([<>]?)(\d+)$', raw_rank)
                if m_rank:
                    op, threshold = m_rank.group(1), int(m_rank.group(2))
                    if op == ">":
                        if not (e.rank > threshold):
                            return False
                    elif op == "<":
                        if not (e.rank < threshold):
                            return False
                    else:
                        if e.rank != threshold:
                            return False

            # --- plain substring tokens (all must match) ---
            if plain_tokens:
                haystack = (e.name + " " + e.description + " " + e.author).lower()
                if not all(t in haystack for t in plain_tokens):
                    return False

            return True

        # If query was empty / whitespace return everything
        if not tokens:
            return self.all()

        return [e for e in self.all() if _matches(e)]

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
