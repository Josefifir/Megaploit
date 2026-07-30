"""
megaploit.plugins.runner
~~~~~~~~~~~~~~~~~~~~~~~~
Execute a PluginCommand in the correct context.

Three execution modes
---------------------

kind = "local"
    Expand placeholders in the shell string, then run the resulting command
    on the operator machine via subprocess.  Output is streamed line-by-line
    to the *output* callback.  Timeout, env injection, and retry are all
    enforced.

kind = "session"
    Expand placeholders, send the resulting command string to the active agent
    session via the C2 channel, and return the response.

kind = "python"
    Import the dotted handler path, build a PluginContext, and call the handler
    with ``(args: list[str], ctx: PluginContext)``.  The callable should return
    a str or None.  It may also call ``ctx.emit(line)`` for streaming output.

Placeholder reference
---------------------
    {session_ip}       session.ip
    {session_id}       str(session.id)
    {session_tag}      session.tag
    {session_os}       session.os_name
    {session_hostname} session.hostname
    {session_username} session.username
    {lhost}            console.lhost
    {port}             str(console.port)
    {arg0}…{argN}      positional args from the CLI
    {joined_args}      all args joined with a space

Output formats
--------------
    raw          — print as-is (default)
    json         — pretty-print JSON parsed from output
    pretty_json  — same as json but with sorted keys
    table        — render list-of-dicts or list-of-lists as an ASCII table
    csv          — render list-of-lists as CSV
"""

from __future__ import annotations

import csv
import hashlib
import io
import importlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Callable, Optional

from megaploit.core.exceptions import PluginTrustError
from megaploit.plugins import loader as _loader
from megaploit.plugins.schema import (
    PluginCommand,
    PluginContext,
)
from megaploit.server.commands import CommandResult

# Plugins directory — source_file paths must resolve inside the configured
# plugin root.  Use loader.PLUGINS_DIR so this stays consistent if the
# directory is ever reconfigured rather than hardcoding "plugins" here.
_PLUGINS_ABS = os.path.abspath(_loader.PLUGINS_DIR)

OutputFn = Callable[[str], None]
_NOOP: OutputFn = lambda _: None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_plugin_command(
    cmd: PluginCommand,
    args: list[str],
    session=None,           # megaploit.server.session.Session | None
    lhost: str = "",
    port: int = 0,
    output: OutputFn = _NOOP,
) -> CommandResult:
    """
    Execute *cmd* and return a CommandResult.

    *session* is required for kind='session' commands.
    *output*  is a streaming callback; called with each output line.
    Retry logic, timeout, and env_var injection are applied automatically.
    """
    # Arity check (uses schema's check_args)
    err = cmd.check_args(args)
    if err:
        return CommandResult(ok=False, output=err)

    ctx = _build_context(args, session, lhost, port)
    plugin_ctx = _build_plugin_context(args, cmd, session, lhost, port, output)

    last_result: Optional[CommandResult] = None
    attempts = max(1, cmd.retry + 1)

    for attempt in range(attempts):
        if attempt > 0:
            output(f"[*] Retry {attempt}/{cmd.retry} for '{cmd.name}'…")
            time.sleep(0.5 * attempt)   # back-off

        try:
            if cmd.kind == "local":
                result = _run_local(cmd, ctx, output)
            elif cmd.kind == "session":
                result = _run_session(cmd, ctx, session)
            elif cmd.kind == "python":
                result = _run_python(cmd, args, plugin_ctx, output)
            elif cmd.kind == "native":
                result = _run_native(cmd, ctx, output)
            else:
                return CommandResult(
                    ok=False,
                    output=f"[-] Unknown plugin command kind: {cmd.kind}",
                )
        except Exception as e:
            result = CommandResult(
                ok=False,
                output=f"[-] Plugin '{cmd.name}' raised an unhandled exception: {e}",
            )

        last_result = result
        if result.ok:
            break   # success — no retry needed

    assert last_result is not None
    # Apply output formatting
    if last_result.ok and last_result.output and cmd.output_format != "raw":
        last_result = _apply_output_format(last_result, cmd.output_format, output)

    return last_result


# ---------------------------------------------------------------------------
# Context builders
# ---------------------------------------------------------------------------

def _build_context(
    args: list[str],
    session,
    lhost: str,
    port: int,
) -> dict[str, str]:
    """Build the placeholder-expansion dict for shell templates."""
    ctx: dict[str, str] = {
        "lhost":            lhost,
        "port":             str(port),
        "session_ip":       getattr(session, "ip",       "") if session else "",
        "session_id":       str(getattr(session, "id",   0)) if session else "0",
        "session_tag":      getattr(session, "tag",      "") if session else "",
        "session_os":       getattr(session, "os_name",  "") if session else "",
        "session_hostname": getattr(session, "hostname", "") if session else "",
        "session_username": getattr(session, "username", "") if session else "",
        "joined_args":      " ".join(args),
    }
    for i, a in enumerate(args):
        ctx[f"arg{i}"] = a
    return ctx


def _build_plugin_context(
    args: list[str],
    cmd: PluginCommand,
    session,
    lhost: str,
    port: int,
    output: OutputFn,
) -> PluginContext:
    """Build the rich PluginContext for python-kind handlers."""
    ctx = PluginContext(
        lhost=lhost,
        port=port,
        session_ip=       getattr(session, "ip",       "") if session else "",
        session_id=       getattr(session, "id",        0) if session else 0,
        session_tag=      getattr(session, "tag",      "") if session else "",
        session_os=       getattr(session, "os_name",  "") if session else "",
        session_hostname= getattr(session, "hostname", "") if session else "",
        session_username= getattr(session, "username", "") if session else "",
        positional=list(args),
        env_vars=dict(cmd.env_vars),
        command_name=cmd.name,
        plugin_name=cmd.plugin_name,
    )
    ctx._output_fn = output
    return ctx


def _expand(template: str, ctx: dict[str, str]) -> str:
    """
    Replace ``{key}`` placeholders in *template* from *ctx*.

    Supports ``{key:-default}`` syntax: if the value for *key* is empty,
    the default string is used instead.
    """
    import re
    def _replacer(m: re.Match) -> str:
        key     = m.group(1)
        default = m.group(2)      # None if no :-default present
        val     = ctx.get(key, "")
        if not val and default is not None:
            return default
        return val

    return re.sub(r"\{(\w+)(?::-([^}]*))?\}", _replacer, template)


# ---------------------------------------------------------------------------
# Execution backends
# ---------------------------------------------------------------------------

def _run_local(
    cmd: PluginCommand,
    ctx: dict[str, str],
    output: OutputFn,
) -> CommandResult:
    """Run the shell string on the operator machine; stream output."""
    shell_cmd = _expand(cmd.shell, ctx)
    output(f"[*] Running: {shell_cmd}")

    # Build environment — start from current env, layer plugin env_vars on top
    env = dict(os.environ)
    for k, v in cmd.env_vars.items():
        env[k] = _expand(v, ctx)

    lines: list[str] = []
    timed_out = False

    proc = subprocess.Popen(
        shell_cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )

    def _stream() -> None:
        for line in proc.stdout:
            stripped = line.rstrip()
            output(stripped)
            lines.append(stripped)

    t = threading.Thread(target=_stream, daemon=True)
    t.start()

    timeout = cmd.timeout if cmd.timeout > 0 else None
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        timed_out = True
        output(f"[!] Command '{cmd.name}' timed out after {cmd.timeout}s.")
    t.join(timeout=2)

    if timed_out:
        return CommandResult(
            ok=False,
            output="\n".join(lines) + f"\n[-] Timed out after {cmd.timeout}s.",
        )
    return CommandResult(ok=(proc.returncode == 0), output="\n".join(lines))


def _run_session(
    cmd: PluginCommand,
    ctx: dict[str, str],
    session,
) -> CommandResult:
    """Send the expanded shell command to the agent and return the response."""
    if session is None:
        return CommandResult(
            ok=False,
            output=(
                f"[-] '{cmd.name}' is a session command — "
                f"you must be inside a session (use <id>)."
            ),
        )

    from megaploit.core.protocol import send_msg, recv_msg

    shell_cmd = _expand(cmd.shell, ctx)
    send_msg(session.conn, shell_cmd)

    try:
        resp = recv_msg(session.conn)
        return CommandResult(ok=True, output=str(resp) if resp else "")
    except ConnectionError as e:
        return CommandResult(
            ok=False,
            output=f"[-] Connection lost: {e}",
            close_session=True,
        )


# ---------------------------------------------------------------------------
# Native (C / C++) execution backend
# ---------------------------------------------------------------------------

# Compilers tried in order.  The first one found on $PATH is used.
_C_COMPILERS   = ["gcc",   "clang",   "cc"]
_CXX_COMPILERS = ["g++",   "clang++", "c++"]


def _find_compiler(source: str) -> str | None:
    """Return the first available compiler for *source* (.c → C, else C++)."""
    ext = os.path.splitext(source)[1].lower()
    candidates = _C_COMPILERS if ext == ".c" else _CXX_COMPILERS
    for name in candidates:
        if shutil.which(name):
            return name
    return None


def _binary_path(source: str) -> str:
    """
    Derive a stable cache path for the compiled binary next to the source.

    The binary name embeds a short SHA-256 digest of the *absolute* source
    path so two plugins with identically-named source files don't collide.
    """
    abs_src  = os.path.abspath(source)
    tag      = hashlib.sha256(abs_src.encode()).hexdigest()[:8]
    base     = os.path.splitext(abs_src)[0]
    suffix   = ".exe" if sys.platform == "win32" else ""
    return f"{base}_{tag}{suffix}"


def _needs_recompile(source: str, binary: str) -> bool:
    """True when the binary is missing or older than the source."""
    if not os.path.isfile(binary):
        return True
    return os.path.getmtime(source) > os.path.getmtime(binary)


def _compile(
    compiler: str,
    source: str,
    binary: str,
    extra_flags: str,
    output: "OutputFn",
) -> tuple[bool, str]:
    """
    Compile *source* → *binary*.

    Returns (success, stderr_output).
    """
    cmd_parts = [compiler, source, "-o", binary]
    if extra_flags.strip():
        import shlex
        cmd_parts += shlex.split(extra_flags)

    output(f"[*] Compiling: {' '.join(cmd_parts)}")
    try:
        proc = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()
        return True, ""
    except FileNotFoundError:
        return False, f"Compiler '{compiler}' not found on PATH."
    except subprocess.TimeoutExpired:
        return False, "Compilation timed out after 120 s."


def _run_native(
    cmd: "PluginCommand",
    ctx: dict[str, str],
    output: "OutputFn",
) -> "CommandResult":
    """
    Compile (if necessary) and run a C / C++ plugin.

    The compiled binary receives the expanded args as argv[1..N] and its
    stdout/stderr are captured exactly like ``_run_local``.

    The binary is recompiled automatically whenever the source file's mtime
    is newer than the cached binary (same logic as ``make``).
    """
    source = _expand(cmd.source_file, ctx)

    # Reject path traversal: the resolved source must stay inside plugins/.
    abs_source = os.path.normpath(os.path.abspath(source))
    if not abs_source.startswith(_PLUGINS_ABS + os.sep):
        raise PluginTrustError(
            f"Native plugin source '{source}' resolves outside the plugins/ "
            f"directory ({abs_source}). Path traversal is not permitted."
        )

    if not os.path.isfile(abs_source):
        return CommandResult(
            ok=False,
            output=f"[-] native plugin source not found: {abs_source}",
        )
    source = abs_source

    compiler = _find_compiler(source)
    if compiler is None:
        ext = os.path.splitext(source)[1].lower()
        lang = "C" if ext == ".c" else "C++"
        return CommandResult(
            ok=False,
            output=(
                f"[-] No {lang} compiler found on PATH.\n"
                f"    Install gcc/clang (Linux/macOS) or MinGW (Windows) and retry."
            ),
        )

    binary = _binary_path(source)

    if _needs_recompile(source, binary):
        ok, err = _compile(compiler, source, binary, cmd.compiler_flags, output)
        if not ok:
            return CommandResult(
                ok=False,
                output=f"[-] Compilation failed:\n{err}",
            )
        output(f"[+] Compiled: {binary}")

    # Build the invocation: binary + expanded positional args
    invoke_args = [binary] + [_expand(a, ctx) for a in ctx.get("joined_args", "").split() if a]

    # Honour env_vars the same way _run_local does
    env = dict(os.environ)
    for k, v in cmd.env_vars.items():
        env[k] = _expand(v, ctx)

    lines: list[str] = []
    timed_out = False

    proc = subprocess.Popen(
        invoke_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )

    def _stream() -> None:
        for line in proc.stdout:
            stripped = line.rstrip()
            output(stripped)
            lines.append(stripped)

    t = threading.Thread(target=_stream, daemon=True)
    t.start()

    timeout = cmd.timeout if cmd.timeout > 0 else None
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        timed_out = True
        output(f"[!] Native plugin '{cmd.name}' timed out after {cmd.timeout}s.")
    t.join(timeout=2)

    if timed_out:
        return CommandResult(
            ok=False,
            output="\n".join(lines) + f"\n[-] Timed out after {cmd.timeout}s.",
        )
    return CommandResult(ok=(proc.returncode == 0), output="\n".join(lines))


def _run_python(
    cmd: PluginCommand,
    args: list[str],
    ctx: PluginContext,
    output: OutputFn,
) -> CommandResult:
    """
    Import and call the dotted handler.

    Old-style handler signature:  fn(args: list[str], context: dict) → str | None
    New-style handler signature:  fn(args: list[str], ctx: PluginContext) → str | None

    Both are supported.  If the handler accepts a PluginContext it will receive
    the rich context; if it accepts a plain dict it receives a compatibility dict.
    """
    parts = cmd.handler.rsplit(".", 1)
    if len(parts) != 2:
        return CommandResult(
            ok=False,
            output=(
                f"[-] handler '{cmd.handler}' is not a valid dotted path "
                f"(expected 'module.function')."
            ),
        )

    module_path, func_name = parts
    try:
        mod = importlib.import_module(module_path)
    except ImportError as e:
        return CommandResult(
            ok=False,
            output=f"[-] Cannot import '{module_path}': {e}",
        )

    fn = getattr(mod, func_name, None)
    if fn is None:
        return CommandResult(
            ok=False,
            output=f"[-] '{func_name}' not found in module '{module_path}'.",
        )

    # Inspect handler signature to determine call style
    import inspect
    sig = inspect.signature(fn)
    params = list(sig.parameters.values())

    if len(params) >= 2 and params[1].annotation is PluginContext:
        # New-style: fn(args, ctx: PluginContext)
        result = fn(args, ctx)
    else:
        # Old/compat style: fn(args, dict)
        compat_dict: dict[str, str] = {
            "lhost":      ctx.lhost,
            "port":       str(ctx.port),
            "session_ip": ctx.session_ip,
            "session_id": str(ctx.session_id),
        }
        for i, a in enumerate(ctx.positional):
            compat_dict[f"arg{i}"] = a
        result = fn(args, compat_dict)

    return CommandResult(ok=True, output=str(result) if result is not None else "")


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _apply_output_format(
    result: CommandResult,
    fmt: str,
    output: OutputFn,
) -> CommandResult:
    """
    Reformat *result.output* according to *fmt*.

    On parse failure the original raw output is returned unchanged.
    """
    raw = result.output.strip()

    if fmt in ("json", "pretty_json"):
        try:
            parsed = json.loads(raw)
            sort_keys = (fmt == "pretty_json")
            formatted = json.dumps(parsed, indent=2, sort_keys=sort_keys, ensure_ascii=False)
            return CommandResult(ok=True, output=formatted)
        except json.JSONDecodeError:
            output("[!] Output format is 'json' but response is not valid JSON — showing raw.")
            return result

    if fmt == "table":
        return CommandResult(ok=True, output=_format_table(raw, output))

    if fmt == "csv":
        return CommandResult(ok=True, output=_format_csv(raw, output))

    return result


def _format_table(raw: str, output: OutputFn) -> str:
    """
    Parse *raw* as JSON (list of dicts or list of lists) and render as an
    aligned ASCII table.  Falls back to raw on parse failure.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        output("[!] 'table' format requires JSON output — showing raw.")
        return raw

    if not isinstance(data, list) or not data:
        return raw

    if isinstance(data[0], dict):
        # List-of-dicts → column headers from keys
        headers: list[str] = list(data[0].keys())
        rows: list[list[str]] = [
            [str(row.get(h, "")) for h in headers]
            for row in data
        ]
        return _render_table(headers, rows)

    if isinstance(data[0], list):
        rows = [[str(cell) for cell in row] for row in data]
        headers = [f"Col{i}" for i in range(len(rows[0]))] if rows else []
        return _render_table(headers, rows)

    return raw


def _render_table(headers: list[str], rows: list[list[str]]) -> str:
    all_rows = [headers] + rows
    widths   = [
        max(len(cell) for cell in col)
        for col in zip(*all_rows)
    ]
    sep  = "  " + "  ".join("-" * w for w in widths)
    hdr  = "  " + "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    body = "\n".join(
        "  " + "  ".join(cell.ljust(w) for cell, w in zip(row, widths))
        for row in rows
    )
    return "\n".join([hdr, sep, body])


def _format_csv(raw: str, output: OutputFn) -> str:
    """
    Parse *raw* as JSON list-of-lists and render as CSV.
    Falls back to raw on parse failure.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        output("[!] 'csv' format requires JSON output — showing raw.")
        return raw

    if not isinstance(data, list):
        return raw

    buf = io.StringIO()
    writer = csv.writer(buf)
    if data and isinstance(data[0], dict):
        headers = list(data[0].keys())
        writer.writerow(headers)
        for row in data:
            writer.writerow([row.get(h, "") for h in headers])
    else:
        for row in data:
            writer.writerow(row if isinstance(row, list) else [row])

    return buf.getvalue()
