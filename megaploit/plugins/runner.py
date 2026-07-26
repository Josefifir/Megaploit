"""
megaploit.plugins.runner
~~~~~~~~~~~~~~~~~~~~~~~~
Execute a PluginCommand in the correct context.

Three execution modes
---------------------

kind = "local"
    Expand placeholders in the shell string, then run the resulting command
    on the operator machine via subprocess.  Output is streamed line-by-line
    to the *output* callback.

kind = "session"
    Expand placeholders, send the resulting command string to the active agent
    session via the C2 channel, and return the response.

kind = "python"
    Import the dotted handler path and call it with (args, context) where
    context is a dict of resolved placeholders.  The callable should return
    a string or None.

Placeholder reference
---------------------
    {session_ip}  — session.ip                 (session commands only)
    {session_id}  — str(session.id)             (session commands only)
    {lhost}       — console.lhost
    {port}        — str(console.port)
    {arg0}…{argN} — positional args from the CLI
"""

from __future__ import annotations

import importlib
import subprocess
import threading
from typing import Callable, Optional

from megaploit.plugins.schema import PluginCommand
from megaploit.server.commands import CommandResult

OutputFn = Callable[[str], None]
_NOOP: OutputFn = lambda _: None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_plugin_command(
    cmd: PluginCommand,
    args: list[str],
    session=None,          # megaploit.server.session.Session | None
    lhost: str = "",
    port: int = 0,
    output: OutputFn = _NOOP,
) -> CommandResult:
    """
    Execute *cmd* and return a CommandResult.

    *session* is required for kind='session' commands.
    *output*  is a streaming callback for local/python commands.
    """
    if len(args) < cmd.min_args:
        return CommandResult(
            ok=False,
            output=f"[-] '{cmd.name}' requires at least {cmd.min_args} argument(s).\n"
                   f"    Usage: {cmd.usage}",
        )

    ctx = _build_context(args, session, lhost, port)

    try:
        if cmd.kind == "local":
            return _run_local(cmd, ctx, output)
        elif cmd.kind == "session":
            return _run_session(cmd, ctx, session)
        elif cmd.kind == "python":
            return _run_python(cmd, args, ctx, output)
        else:
            return CommandResult(ok=False, output=f"[-] Unknown plugin command kind: {cmd.kind}")
    except Exception as e:
        return CommandResult(ok=False, output=f"[-] Plugin '{cmd.name}' error: {e}")


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def _build_context(args: list[str], session, lhost: str, port: int) -> dict[str, str]:
    ctx: dict[str, str] = {
        "lhost": lhost,
        "port":  str(port),
        "session_ip": session.ip  if session else "",
        "session_id": str(session.id) if session else "",
    }
    for i, a in enumerate(args):
        ctx[f"arg{i}"] = a
    return ctx


def _expand(template: str, ctx: dict[str, str]) -> str:
    """Replace {key} placeholders in *template* from *ctx*."""
    result = template
    for key, val in ctx.items():
        result = result.replace(f"{{{key}}}", val)
    return result


# ---------------------------------------------------------------------------
# Execution backends
# ---------------------------------------------------------------------------

def _run_local(cmd: PluginCommand, ctx: dict[str, str], output: OutputFn) -> CommandResult:
    """Run the shell string on the operator machine; stream output."""
    shell_cmd = _expand(cmd.shell, ctx)
    output(f"[*] Running: {shell_cmd}")

    lines: list[str] = []

    proc = subprocess.Popen(
        shell_cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    def _stream():
        for line in proc.stdout:
            stripped = line.rstrip()
            output(stripped)
            lines.append(stripped)

    t = threading.Thread(target=_stream, daemon=True)
    t.start()
    proc.wait()
    t.join(timeout=2)

    return CommandResult(ok=(proc.returncode == 0), output="\n".join(lines))


def _run_session(cmd: PluginCommand, ctx: dict[str, str], session) -> CommandResult:
    """Send the expanded shell command to the agent and return the response."""
    if session is None:
        return CommandResult(
            ok=False,
            output=f"[-] '{cmd.name}' is a session command — you must be inside a session (use <id>).",
        )
    from megaploit.core.protocol import send_msg, recv_msg

    shell_cmd = _expand(cmd.shell, ctx)
    send_msg(session.conn, shell_cmd)
    try:
        resp = recv_msg(session.conn)
        return CommandResult(ok=True, output=str(resp) if resp else "")
    except ConnectionError as e:
        return CommandResult(ok=False, output=f"[-] Connection lost: {e}", close_session=True)


def _run_python(
    cmd: PluginCommand, args: list[str], ctx: dict[str, str], output: OutputFn
) -> CommandResult:
    """
    Import and call the dotted handler.

    The callable receives  (args: list[str], context: dict)  and should
    return a string result or None.  It may also call output() for streaming.
    """
    parts = cmd.handler.rsplit(".", 1)
    if len(parts) != 2:
        return CommandResult(
            ok=False,
            output=f"[-] handler '{cmd.handler}' is not a valid dotted path (expected 'module.function').",
        )
    module_path, func_name = parts
    try:
        mod = importlib.import_module(module_path)
    except ImportError as e:
        return CommandResult(ok=False, output=f"[-] Cannot import '{module_path}': {e}")

    fn = getattr(mod, func_name, None)
    if fn is None:
        return CommandResult(
            ok=False,
            output=f"[-] '{func_name}' not found in module '{module_path}'.",
        )

    result = fn(args, ctx)
    return CommandResult(ok=True, output=str(result) if result is not None else "")
