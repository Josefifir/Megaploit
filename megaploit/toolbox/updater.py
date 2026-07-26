"""
megaploit.toolbox.updater
~~~~~~~~~~~~~~~~~~~~~~~~~
Background update checker for:

  1. Megaploit itself  — compares the local git HEAD of the project repo
     against the remote origin/HEAD (via `git ls-remote`).
  2. Every installed toolbox tool — same git-based check, one per tool.

All checks run in a single daemon thread so they never block the CLI.
Results are pushed into a queue; the CLI drains it between prompts and
prints colour-coded notifications.

API
---
    from megaploit.toolbox.updater import UpdateChecker

    checker = UpdateChecker()
    checker.start()          # non-blocking — spawns daemon thread

    # in your prompt loop:
    for note in checker.drain():
        print(note)          # already formatted, ANSI-coloured string
"""

from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Iterator

from megaploit.toolbox.registry import registry as _registry

# How often to re-check (seconds).  First check happens immediately on start.
CHECK_INTERVAL: int = 300   # 5 minutes


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class UpdateNote:
    """A pending update notification ready to print."""
    kind: str       # "megaploit" | "tool"
    name: str       # project or tool name
    current: str    # short local commit hash
    latest: str     # short remote commit hash


# ---------------------------------------------------------------------------
# Git helpers (no gitpython — pure subprocess)
# ---------------------------------------------------------------------------

def _git_available() -> bool:
    return shutil.which("git") is not None


def _local_head(repo_dir: str) -> str | None:
    """Return the short commit hash of HEAD in *repo_dir*, or None on failure."""
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def _remote_head(repo_dir: str) -> str | None:
    """
    Fetch the remote HEAD hash without actually pulling.
    Uses `git ls-remote origin HEAD` which is read-only and fast.
    Returns a short (7-char) hash or None on failure.
    """
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "ls-remote", "origin", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        full_hash = result.stdout.split()[0]
        return full_hash[:7]
    except Exception:
        return None


def _has_update(repo_dir: str) -> tuple[str, str] | None:
    """
    Return (local_hash, remote_hash) if they differ, else None.
    Also returns None if either hash could not be obtained.
    """
    local  = _local_head(repo_dir)
    remote = _remote_head(repo_dir)
    if local and remote and local != remote:
        return local, remote
    return None


# ---------------------------------------------------------------------------
# UpdateChecker
# ---------------------------------------------------------------------------

class UpdateChecker:
    """
    Runs periodic checks in a daemon thread.
    Push UpdateNote objects into *_queue*; caller drains via drain().
    """

    def __init__(self, megaploit_dir: str = ".") -> None:
        """
        Parameters
        ----------
        megaploit_dir : path to the Megaploit project root (where .git lives).
                        Defaults to the current working directory.
        """
        self._megaploit_dir = os.path.abspath(megaploit_dir)
        self._queue: queue.Queue[UpdateNote] = queue.Queue()
        self._stop  = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background checker thread (daemon — dies with process)."""
        if not _git_available():
            return   # silently skip if git isn't on PATH
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="megaploit-updater"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------
    # Drain results
    # ------------------------------------------------------------------

    def drain(self) -> Iterator[str]:
        """
        Yield formatted ANSI strings for every pending update notification.
        Call this between CLI prompts.
        """
        while not self._queue.empty():
            try:
                note = self._queue.get_nowait()
                yield _format_note(note)
            except queue.Empty:
                break

    def check_now(self) -> None:
        """Trigger an immediate check (non-blocking — queues results async)."""
        threading.Thread(target=self._run_checks, daemon=True).start()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        # First check immediately
        self._run_checks()
        while not self._stop.wait(timeout=CHECK_INTERVAL):
            self._run_checks()

    def _run_checks(self) -> None:
        # 1. Check Megaploit itself
        if os.path.isdir(os.path.join(self._megaploit_dir, ".git")):
            result = _has_update(self._megaploit_dir)
            if result:
                local, remote = result
                self._queue.put(UpdateNote(
                    kind="megaploit", name="Megaploit",
                    current=local, latest=remote,
                ))

        # 2. Check every registered toolbox tool
        for tool in _registry.all():
            if not tool.is_installed:
                continue
            if not os.path.isdir(os.path.join(tool.path, ".git")):
                continue
            result = _has_update(tool.path)
            if result:
                local, remote = result
                self._queue.put(UpdateNote(
                    kind="tool", name=tool.name,
                    current=local, latest=remote,
                ))


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"


def _format_note(note: UpdateNote) -> str:
    if note.kind == "megaploit":
        label = f"{_BOLD}{_CYAN}Megaploit{_RESET}"
        cmd   = "git pull"
    else:
        label = f"{_BOLD}{_CYAN}{note.name}{_RESET}"
        cmd   = f"toolbox update {note.name}"

    return (
        f"\n  {_YELLOW}[↑]{_RESET} Update available for {label}  "
        f"{_YELLOW}{note.current}{_RESET} → {_GREEN}{note.latest}{_RESET}\n"
        f"     Run:  {_BOLD}{cmd}{_RESET}\n"
    )
