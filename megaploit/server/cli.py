"""
megaploit.server.cli
~~~~~~~~~~~~~~~~~~~~
Metasploit-style interactive C2 console.

Features
--------
* Animated ASCII banner on startup
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

from megaploit.core.config import AUTH_TIMEOUT
from megaploit.core.crypto import load_key
from megaploit.server.commands import dispatch, all_commands, CommandResult
from megaploit.server.listener import Listener, build_ssl_context
from megaploit.server.session import Session

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_BLUE   = "\033[94m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_GREY   = "\033[90m"

def _c(text: str, *codes: str) -> str:
    """Wrap *text* in ANSI codes, reset at end."""
    return "".join(codes) + text + _RESET


def ok(msg: str)   -> str: return _c(f"[+] {msg}", _GREEN)
def err(msg: str)  -> str: return _c(f"[-] {msg}", _RED)
def info(msg: str) -> str: return _c(f"[*] {msg}", _CYAN)
def warn(msg: str) -> str: return _c(f"[!] {msg}", _YELLOW)


# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------

_BANNER_FRAMES = [
"""
  ███╗   ███╗███████╗ ██████╗  █████╗ ██████╗ ██╗      ██████╗ ██╗████████╗
  ████╗ ████║██╔════╝██╔════╝ ██╔══██╗██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
  ██╔████╔██║█████╗  ██║  ███╗███████║██████╔╝██║     ██║   ██║██║   ██║   
  ██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║██╔═══╝ ██║     ██║   ██║██║   ██║   
  ██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║██║     ███████╗╚██████╔╝██║   ██║   
  ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
""",
]

_SUBTITLE = "  Professional Remote Access Framework  |  v2.0.0  |  For Authorized Use Only"
_DIVIDER  = "  " + "─" * 74


def _print_banner() -> None:
    os.system("cls" if os.name == "nt" else "clear")
    for frame in _BANNER_FRAMES:
        print(_c(frame, _RED, _BOLD))
        time.sleep(0.04)
    print(_c(_SUBTITLE, _GREY))
    print(_c(_DIVIDER, _GREY))
    print()


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------

class _Spinner:
    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str) -> None:
        self._msg = message
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()
        # Clear the spinner line
        sys.stdout.write("\r" + " " * (len(self._msg) + 10) + "\r")
        sys.stdout.flush()

    def _run(self):
        i = 0
        while not self._stop.is_set():
            frame = self._FRAMES[i % len(self._FRAMES)]
            sys.stdout.write(f"\r  {_c(frame, _CYAN)} {_c(self._msg, _GREY)} ")
            sys.stdout.flush()
            time.sleep(0.08)
            i += 1


# ---------------------------------------------------------------------------
# Session table printer
# ---------------------------------------------------------------------------

def _print_sessions(sessions: dict[int, Session]) -> None:
    if not sessions:
        print(info("No active sessions."))
        return
    header = f"  {'ID':<5} {'IP':<18} {'PORT':<8} {'UPTIME':<12}"
    print()
    print(_c(header, _BOLD, _WHITE))
    print(_c("  " + "─" * 46, _GREY))
    for sid, sess in sessions.items():
        print(f"  {_c(str(sid), _CYAN):<14} {_c(sess.ip, _WHITE):<27} {sess.port:<8} {sess.uptime}")
    print()


# ---------------------------------------------------------------------------
# Tab completion
# ---------------------------------------------------------------------------

_GLOBAL_CMDS  = ["sessions", "use", "listen", "set", "generate", "help", "clear", "exit"]
_SESSION_CMDS = list(all_commands().keys()) + ["back", "clear"]

def _completer(text: str, state: int) -> Optional[str]:
    options = [c for c in _SESSION_CMDS if c.startswith(text)]
    return options[state] if state < len(options) else None

if _HAS_READLINE:
    readline.set_completer(_completer)
    readline.parse_and_bind("tab: complete")


# ---------------------------------------------------------------------------
# Main CLI class
# ---------------------------------------------------------------------------

class Console:
    """
    The interactive operator console.  Call run() to start.
    """

    def __init__(self) -> None:
        self._sessions: dict[int, Session] = {}
        self._sessions_lock = threading.Lock()
        self._new_sessions: queue.Queue[Session] = queue.Queue()
        self._listener: Optional[Listener] = None

        # Server config (set via 'set' or CLI args)
        self.bind_host: str = "0.0.0.0"
        self.lhost: str = ""
        self.port: int = 4444
        self.cert: str = ""
        self.key_file: str = ""
        self.secret_key: bytes = b""

    # ---------------------------------------------------------------
    # Entry point
    # ---------------------------------------------------------------

    def run(self, bind_host: str, lhost: str, port: int,
            cert: str = "", key_file: str = "",
            secret_key_path: str = "secret.key") -> None:
        self.bind_host = bind_host
        self.lhost = lhost
        self.port = port
        self.cert = cert
        self.key_file = key_file
        self.secret_key = load_key(secret_key_path)

        _print_banner()
        self._start_listener()
        self._global_loop()

    # ---------------------------------------------------------------
    # Listener management
    # ---------------------------------------------------------------

    def _start_listener(self) -> None:
        ssl_ctx: Optional[ssl.SSLContext] = None
        if self.cert and self.key_file:
            try:
                ssl_ctx = build_ssl_context(self.cert, self.key_file)
                print(ok(f"TLS configured ({self.cert})"))
            except ssl.SSLError as e:
                print(err(f"TLS error: {e}"))
                sys.exit(1)

        self._listener = Listener(
            bind_host=self.bind_host,
            port=self.port,
            secret_key=self.secret_key,
            on_session=self._on_new_session,
            ssl_context=ssl_ctx,
        )
        self._listener.start()
        print(ok(f"Listener started on {self.bind_host}:{self.port}"))
        print(info(f"Waiting for agents to connect back to {self.lhost}:{self.port}"))
        print()

    def _on_new_session(self, session: Session) -> None:
        with self._sessions_lock:
            self._sessions[session.id] = session
        self._new_sessions.put(session)

    # ---------------------------------------------------------------
    # New-session notification (printed between prompts)
    # ---------------------------------------------------------------

    def _drain_new_sessions(self) -> None:
        while not self._new_sessions.empty():
            try:
                sess = self._new_sessions.get_nowait()
                print()
                print(ok(f"New session #{sess.id} opened — {sess.ip}:{sess.port}"))
                print(info(f"  Type  use {sess.id}  to interact"))
                print()
            except queue.Empty:
                break

    # ---------------------------------------------------------------
    # Global prompt loop
    # ---------------------------------------------------------------

    def _global_loop(self) -> None:
        print(info("Type  help  for available commands.\n"))
        while True:
            self._drain_new_sessions()
            try:
                prompt = f"\n{_c('megaploit', _RED, _BOLD)} {_c('>', _GREY)} "
                raw = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                self._shutdown()
                return

            if not raw:
                continue

            parts = raw.split()
            cmd = parts[0].lower()
            args = parts[1:]

            if cmd == "exit":
                self._shutdown()
                return

            elif cmd in ("help", "?"):
                self._global_help()

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

            else:
                print(err(f"Unknown command: {cmd}  (type help)"))

    # ---------------------------------------------------------------
    # Session interaction loop
    # ---------------------------------------------------------------

    def _session_loop(self, session: Session) -> None:
        print()
        print(ok(f"Interacting with session #{session.id} ({session.ip})"))
        print(info("Type  help  for commands,  back  to return.\n"))

        while True:
            self._drain_new_sessions()
            try:
                prompt = (
                    f"\n{_c('megaploit', _RED, _BOLD)}"
                    f" {_c('session', _GREY)}({_c(str(session.id), _CYAN)})"
                    f"{_c('>', _GREY)} "
                )
                raw = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return

            if not raw:
                continue

            parts = raw.split()
            cmd_name = parts[0].lower()

            if cmd_name == "back":
                return

            if cmd_name == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                continue

            # Dangerous command confirmation
            cmds = all_commands()
            if cmd_name in cmds and cmds[cmd_name].dangerous:
                confirm = input(warn(f"  {cmd_name} is dangerous. Type YES to confirm: ")).strip()
                if confirm != "YES":
                    print(warn("  Cancelled."))
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
            # Colour [+] green, [-] red, [*] cyan within the output
            out = result.output
            out = re.sub(r"^\[\+\]", _c("[+]", _GREEN), out, flags=re.MULTILINE)
            out = re.sub(r"^\[-\]", _c("[-]", _RED),   out, flags=re.MULTILINE)
            out = re.sub(r"^\[\*\]", _c("[*]", _CYAN),  out, flags=re.MULTILINE)
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
        """Patch agent.py with LHOST/PORT and optionally byte-compile it."""
        if not self.lhost or not self.port:
            print(err("Set LHOST and PORT first:  set lhost <ip>  /  set port <port>"))
            return
        _patch_agent(self.lhost, self.port)
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
            print(ok(f"lhost => {val}"))
        elif key == "port":
            try:
                self.port = int(val)
                print(ok(f"port => {val}"))
            except ValueError:
                print(err("port must be an integer"))
        elif key == "cert":
            self.cert = val
            print(ok(f"cert => {val}"))
        elif key == "key":
            self.key_file = val
            print(ok(f"key => {val}"))
        else:
            print(err(f"Unknown option: {key}"))

    # ---------------------------------------------------------------
    # Help screens
    # ---------------------------------------------------------------

    def _global_help(self) -> None:
        lines = [
            "",
            _c("  Global Commands", _BOLD, _WHITE),
            _c("  " + "─" * 50, _GREY),
            f"  {'sessions':<22}  List active sessions",
            f"  {'use <id>':<22}  Interact with a session",
            f"  {'generate [-c]':<22}  Patch & (optionally compile) agent.py",
            f"  {'set <opt> <val>':<22}  Set lhost / port / cert / key",
            f"  {'clear':<22}  Clear the terminal",
            f"  {'exit':<22}  Quit Megaploit",
            "",
            _c("  Options", _BOLD, _WHITE),
            _c("  " + "─" * 50, _GREY),
        ]
        lines += [
            f"  {'lhost':<22}  {self.lhost or '(not set)'}",
            f"  {'port':<22}  {self.port}",
            f"  {'cert':<22}  {self.cert or '(none)'}",
            f"  {'key':<22}  {self.key_file or '(none)'}",
            "",
        ]
        print("\n".join(lines))

    # ---------------------------------------------------------------
    # Shutdown
    # ---------------------------------------------------------------

    def _shutdown(self) -> None:
        print()
        print(info("Shutting down…"))
        if self._listener:
            self._listener.stop()
        with self._sessions_lock:
            for sess in self._sessions.values():
                sess.close()
        print(ok("Goodbye."))


def _show_options(console: Console) -> None:
    print(f"\n  {'Option':<10}  Value")
    print(f"  {'─' * 10}  {'─' * 20}")
    print(f"  {'lhost':<10}  {console.lhost or '(not set)'}")
    print(f"  {'port':<10}  {console.port}")
    print(f"  {'cert':<10}  {console.cert or '(none)'}")
    print(f"  {'key':<10}  {console.key_file or '(none)'}")
    print()


# ---------------------------------------------------------------------------
# Agent patcher
# ---------------------------------------------------------------------------

def _patch_agent(lhost: str, port: int) -> None:
    """Find LHOST= line in agent.py and overwrite it."""
    try:
        with open("agent.py", "r") as f:
            lines = f.readlines()
        idx = next((i for i, l in enumerate(lines) if l.startswith("LHOST =")), None)
        if idx is None:
            print(err("Cannot find 'LHOST =' line in agent.py"))
            return
        lines[idx] = f'LHOST = "{lhost}"; PORT = {port}  # patched by server\n'
        with open("agent.py", "w") as f:
            f.writelines(lines)
        print(ok(f"agent.py patched: LHOST={lhost} PORT={port}"))
    except IOError as e:
        print(err(f"Patch failed: {e}"))
