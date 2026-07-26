"""
megaploit.toolbox.installer
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Clone a GitHub repository into  tools/<name>/ , optionally install its
Python dependencies, and register it in the ToolRegistry.

Strategy
--------
1. git clone  (using the system git binary via subprocess — no gitpython dep)
2. If a requirements.txt exists inside the repo, install it into a
   local venv at  tools/<name>/.venv/  so the tool's deps don't pollute
   the main environment.
3. Auto-detect the entry-point (configurable, with sensible defaults).
4. Register the Tool in the catalogue.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Callable, Optional

from megaploit.toolbox.registry import Tool, registry, TOOLS_DIR

# Progress callback type:  fn(line: str) -> None
ProgressFn = Callable[[str], None]

_NOOP: ProgressFn = lambda _: None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def install(
    repo_url: str,
    name: str,
    description: str = "",
    entry: str = "",
    tags: Optional[list[str]] = None,
    progress: ProgressFn = _NOOP,
) -> Tool:
    """
    Clone *repo_url* into tools/<name>, install deps, register the tool.

    Parameters
    ----------
    repo_url    : GitHub (or any git) URL
    name        : short tool name used as directory and command alias
    description : free-text description
    entry       : path to entry-point *relative to repo root* (auto-detected if "")
    tags        : list of category tags, e.g. ["web", "injection"]
    progress    : callback(line) — called with each progress message

    Returns the registered Tool.
    Raises RuntimeError on failure.
    """
    dest = os.path.join(TOOLS_DIR, name)

    if os.path.isdir(dest):
        raise RuntimeError(f"Tool '{name}' is already installed at {dest}")

    _check_git()
    progress(f"[*] Cloning {repo_url} → {dest}")
    _git_clone(repo_url, dest, progress)

    # Install dependencies if present
    req_file = os.path.join(dest, "requirements.txt")
    if os.path.isfile(req_file):
        progress(f"[*] Installing dependencies from requirements.txt")
        _install_deps(dest, req_file, progress)

    # Detect entry-point
    if not entry:
        entry = _detect_entry(dest, name)
        progress(f"[*] Detected entry-point: {entry}")

    tool = Tool(
        name=name,
        repo=repo_url,
        description=description or _infer_description(dest),
        entry=entry,
        tags=tags or [],
    )
    registry.add(tool)
    progress(f"[+] '{name}' installed and registered.")
    return tool


def uninstall(name: str, progress: ProgressFn = _NOOP) -> None:
    """Remove the tool directory and unregister it."""
    tool = registry.get(name)
    if not tool:
        raise RuntimeError(f"Tool '{name}' not found in registry")
    if os.path.isdir(tool.path):
        shutil.rmtree(tool.path)
        progress(f"[+] Removed {tool.path}")
    registry.remove(name)
    progress(f"[+] '{name}' unregistered.")


def update(name: str, progress: ProgressFn = _NOOP) -> None:
    """Run git pull inside the tool directory."""
    tool = registry.get(name)
    if not tool:
        raise RuntimeError(f"Tool '{name}' not found in registry")
    if not os.path.isdir(tool.path):
        raise RuntimeError(f"Tool directory not found: {tool.path}")
    _check_git()
    progress(f"[*] Pulling latest changes for '{name}'…")
    _run(["git", "-C", tool.path, "pull", "--ff-only"], progress)
    progress(f"[+] '{name}' updated.")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_git() -> None:
    if shutil.which("git") is None:
        raise RuntimeError(
            "git is not installed or not on PATH.\n"
            "Install it and try again."
        )


def _git_clone(url: str, dest: str, progress: ProgressFn) -> None:
    _run(["git", "clone", "--depth=1", "--recurse-submodules", url, dest], progress)


def _install_deps(repo_dir: str, req_file: str, progress: ProgressFn) -> None:
    """
    Install requirements into a local venv so they don't pollute the
    main environment.  Falls back to --user install if venv creation fails.
    """
    venv_dir = os.path.join(repo_dir, ".venv")
    python = sys.executable

    # Create venv
    try:
        _run([python, "-m", "venv", venv_dir], progress)
        venv_python = _venv_python(venv_dir)
        _run([venv_python, "-m", "pip", "install", "-q", "-r", req_file], progress)
        progress(f"[+] Deps installed into {venv_dir}")
    except RuntimeError:
        # venv failed — fall back to --user
        progress(f"[!] venv creation failed — falling back to --user install")
        _run([python, "-m", "pip", "install", "-q", "--user", "-r", req_file], progress)


def _venv_python(venv_dir: str) -> str:
    if sys.platform == "win32":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python")


def _detect_entry(repo_dir: str, name: str) -> str:
    """
    Heuristic: look for a Python file matching the tool name, then
    common entry-points like main.py / cli.py / run.py, then any .py at root.
    """
    candidates = [
        f"{name}.py",
        "main.py",
        "cli.py",
        "run.py",
        "__main__.py",
    ]
    for c in candidates:
        if os.path.isfile(os.path.join(repo_dir, c)):
            return c
    # First .py file at repo root
    for f in sorted(os.listdir(repo_dir)):
        if f.endswith(".py") and not f.startswith("_"):
            return f
    return "main.py"   # fallback, user can fix with `toolbox set-entry`


def _infer_description(repo_dir: str) -> str:
    """Try to read a one-line description from README.md."""
    for fname in ("README.md", "README.rst", "README.txt"):
        path = os.path.join(repo_dir, fname)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and len(line) > 10:
                            return line[:120]
            except OSError:
                pass
    return "(no description)"


def _run(cmd: list[str], progress: ProgressFn) -> None:
    """
    Run a subprocess, stream each line to *progress*.
    Raises RuntimeError on non-zero exit.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    for line in proc.stdout:
        progress(line.rstrip())
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed (exit {proc.returncode}): {' '.join(cmd)}")
