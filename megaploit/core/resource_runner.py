"""
megaploit.core.resource_runner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Resource script (.rc file) executor.

Operators create plain-text files containing one CLI command per line —
identical to what they would type at the Megaploit console prompt.  Comments
(lines starting with #) and blank lines are ignored.  Variable interpolation
is supported: ${LHOST}, ${PORT}, ${DATE}.

Usage
-----
    resource /path/to/script.rc
    resource load /path/to/script.rc     # alias

    # Example script  (setup.rc)
    set lhost 10.0.0.1
    set port 4444
    generate
    use auxiliary/scanner/tcp_port
    setopt RHOSTS 192.168.1.0/24
    run

CLI
---
Operators type  ``resource <path>``  at the Megaploit console.  The Console
class calls ``run_resource(path, dispatch_fn)`` where ``dispatch_fn`` accepts
a raw string command (as if the operator had typed it).

Python API
----------
    from megaploit.core.resource_runner import run_resource

    def my_dispatch(line: str) -> None:
        console._dispatch(line)

    errors = run_resource("setup.rc", my_dispatch)
    if errors:
        for lineno, line, exc in errors:
            print(f"  Line {lineno}: {exc}")
"""

from __future__ import annotations

import datetime
import os
import re
from typing import Callable

__all__ = ["run_resource", "load_resource_lines", "ResourceError"]


class ResourceError(Exception):
    """Raised when a resource script line fails hard (not just prints an error)."""


# ---------------------------------------------------------------------------
# Variable substitution
# ---------------------------------------------------------------------------

_BUILTIN_VARS: dict[str, str] = {}


def _resolve_vars(line: str, extra: dict[str, str] | None = None) -> str:
    """
    Replace ``${VAR}`` patterns.

    Built-in variables: LHOST, PORT, DATE, TIME, TIMESTAMP.
    Extra variables can be injected by the caller (e.g. from Console state).
    """
    now  = datetime.datetime.now(datetime.timezone.utc)
    builtins = {
        "DATE":      now.strftime("%Y-%m-%d"),
        "TIME":      now.strftime("%H:%M:%S"),
        "TIMESTAMP": now.strftime("%Y%m%d_%H%M%S"),
        **_BUILTIN_VARS,
    }
    if extra:
        builtins.update(extra)

    def _replacer(m: re.Match) -> str:
        name = m.group(1).upper()
        return builtins.get(name, m.group(0))   # leave unknown vars unchanged

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", _replacer, line)


# ---------------------------------------------------------------------------
# Line loader
# ---------------------------------------------------------------------------

def load_resource_lines(path: str) -> list[tuple[int, str]]:
    """
    Read a resource script file and return ``[(lineno, command), …]``.

    Strips blank lines and comment lines (``#``).
    Raises ``FileNotFoundError`` if the path does not exist.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Resource script not found: {path!r}")

    lines: list[tuple[int, str]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, raw in enumerate(f, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lines.append((lineno, stripped))
    return lines


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_resource(
    path: str,
    dispatch_fn: Callable[[str], None],
    extra_vars: dict[str, str] | None = None,
    stop_on_error: bool = False,
) -> list[tuple[int, str, Exception]]:
    """
    Execute a resource script.

    Parameters
    ----------
    path:           Path to the ``.rc`` script file.
    dispatch_fn:    Callable that accepts one raw command string — exactly as
                    if the operator had typed it at the console.
    extra_vars:     Additional ``${VAR}`` substitutions (e.g. LHOST, PORT from
                    the Console instance).
    stop_on_error:  If True, stop on the first line that raises an exception.

    Returns
    -------
    list of ``(lineno, command_line, exception)`` for any lines that failed.
    An empty list means complete success.
    """
    lines  = load_resource_lines(path)
    errors: list[tuple[int, str, Exception]] = []

    for lineno, cmd in lines:
        resolved = _resolve_vars(cmd, extra_vars)
        try:
            dispatch_fn(resolved)
        except Exception as exc:
            errors.append((lineno, resolved, exc))
            if stop_on_error:
                break

    return errors


# ---------------------------------------------------------------------------
# Interactive REPL helper — used by the Console.  Prints output as it runs.
# ---------------------------------------------------------------------------

def run_resource_interactive(
    path: str,
    dispatch_fn: Callable[[str], None],
    print_fn: Callable[[str], None] | None = None,
    extra_vars: dict[str, str] | None = None,
) -> None:
    """
    Execute a resource script, echoing each line to *print_fn* before running.

    Parameters
    ----------
    path:       Script path.
    dispatch_fn: Console dispatch function.
    print_fn:   Output sink (defaults to ``print``).
    extra_vars: Variable substitutions.
    """
    _print = print_fn or print
    lines  = load_resource_lines(path)

    _print(f"[*] Running resource script: {path}  ({len(lines)} command(s))")
    errors = 0
    for lineno, cmd in lines:
        resolved = _resolve_vars(cmd, extra_vars)
        _print(f"  rc:{lineno}  {resolved}")
        try:
            dispatch_fn(resolved)
        except Exception as exc:
            _print(f"  [-] Line {lineno} error: {exc}")
            errors += 1

    _print(f"[+] Resource script complete  — {len(lines)} cmd(s), {errors} error(s)")
