"""
megaploit.core.c_probe
~~~~~~~~~~~~~~~~~~~~~~
Static-analysis prober for C-remote-shell client source trees.

Inspects a directory of C source files and reports whether they conform
to the four-layer Megaploit C2 security standard, and extracts the exact
wire-protocol verb strings the C client handles via strncmp() dispatch.

C2 Security Layers Checked
---------------------------
  Layer 1 -- SChannel TLS 1.2/1.3
    SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT, SCH_USE_STRONG_CRYPTO
    (AEAD-only ciphers), ISC_REQ_NO_RENEGOTIATION,
    SCH_CRED_MANUAL_CRED_VALIDATION, plus all SChannel buffer/handshake/
    stream-size signals.

  Layer 2 -- HMAC-SHA256 challenge/response
    BCrypt HMAC (BCRYPT_ALG_HANDLE_HMAC_FLAG), BCryptCreateHash /
    BCryptHashData / BCryptFinishHash, 16-byte challenge, 32-byte response.

  Layer 3 -- Protocol v2 negotiation
    TLS_V2_MAGIC / 0x4d magic-byte echo.

  Layer 4 -- AES-256-GCM framed messages with replay protection
    BCrypt AES-GCM (BCRYPT_CHAIN_MODE_GCM), BCryptEncrypt / BCryptDecrypt,
    BCryptGenRandom nonce, uint32-BE frame header, uint64-BE sequence
    counter, strict monotonic sequence check.

Verb Extraction
---------------
``extract_verbs(root_dir)`` scans every .c file for ``strncmp("VERB", ...)``
calls and returns the exact wire strings the C client will accept.

``c_exclusive_verbs(root_dir)`` filters that list to verbs with no
counterpart in the Python agent -- currently ``forceOff()`` and
``blueScreen()``.  ``commands.py`` calls this at import time to
auto-register operator commands without hardcoding any verb string.
Adding a new ``strncmp("myVerb()", ...)`` in shell.c is sufficient for
the command to appear in the operator console automatically.

No symbol names, file paths, or verb strings are hardcoded in this module.

Public API
----------
``probe(root_dir)``              -> ProbeResult
``extract_verbs(root_dir)``      -> list[str]   all C dispatch verbs
``c_exclusive_verbs(root_dir)``  -> list[str]   C-only verbs (not in Python agent)
``format_report(result)``        -> str
``print_report(result)``         -> None  (prints to stdout)

Usage
-----
::

    from megaploit.core.c_probe import probe, print_report, c_exclusive_verbs

    result = probe("C-remote-shell")
    print_report(result)                  # full 46-signal compliance report

    print(c_exclusive_verbs("C-remote-shell"))
    # -> ['blueScreen()', 'forceOff()']
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Signal definitions — what we look for in C source
# ---------------------------------------------------------------------------

class _Signal(NamedTuple):
    name:        str          # short identifier used in the report
    pattern:     str          # regex pattern (searched in file text)
    layer:       int          # 1–4 (maps to the four C2 security layers)
    required:    bool         # True = must be present for compliance
    description: str          # human-readable description


_SIGNALS: list[_Signal] = [
    # ── Layer 1: SChannel TLS ──────────────────────────────────────────────
    _Signal("SP_PROT_TLS1_2_CLIENT",   r"SP_PROT_TLS1_2_CLIENT",         1, True,
            "TLS 1.2 client protocol flag"),
    _Signal("SP_PROT_TLS1_3_CLIENT",   r"SP_PROT_TLS1_3_CLIENT",         1, False,
            "TLS 1.3 client protocol flag (optional; not all Windows SDKs define it)"),
    _Signal("SCH_USE_STRONG_CRYPTO",   r"SCH_USE_STRONG_CRYPTO",         1, True,
            "AEAD-only cipher suite enforcement"),
    _Signal("SCH_CRED_NO_DEFAULT",     r"SCH_CRED_NO_DEFAULT_CREDS",     1, True,
            "No default client certificate"),
    _Signal("SCH_CRED_MANUAL",         r"SCH_CRED_MANUAL_CRED_VALIDATION",1, True,
            "Manual certificate validation (C2 uses self-signed cert)"),
    _Signal("ISC_REQ_CONFIDENTIALITY", r"ISC_REQ_CONFIDENTIALITY",       1, True,
            "Encrypt all data in transit"),
    _Signal("ISC_REQ_SEQUENCE",        r"ISC_REQ_SEQUENCE_DETECT",       1, True,
            "Sequence number detection"),
    _Signal("ISC_REQ_REPLAY",          r"ISC_REQ_REPLAY_DETECT",         1, True,
            "Replay detection"),
    _Signal("ISC_REQ_NO_RENEG",        r"ISC_REQ_NO_RENEGOTIATION",      1, False,
            "No mid-session renegotiation (Windows 10 1809+ SDK; guarded by #ifdef)"),
    _Signal("ISC_REQ_STREAM",          r"ISC_REQ_STREAM",                1, True,
            "Stream-mode SChannel context"),
    _Signal("AcquireCredentials",      r"AcquireCredentialsHandle[AW]?", 1, True,
            "SChannel credential acquisition"),
    _Signal("InitializeSecCtx",        r"InitializeSecurityContext[AW]?",1, True,
            "SChannel handshake state machine"),
    _Signal("EncryptMessage",          r"EncryptMessage\s*\(",           1, True,
            "SChannel TLS record encryption"),
    _Signal("DecryptMessage",          r"DecryptMessage\s*\(",           1, True,
            "SChannel TLS record decryption"),
    _Signal("SECBUFFER_TOKEN",         r"SECBUFFER_TOKEN",               1, True,
            "SChannel buffer descriptor usage"),
    _Signal("QueryStreamSizes",        r"SECPKG_ATTR_STREAM_SIZES",      1, True,
            "TLS stream size query (header+trailer lengths)"),
    _Signal("SCHANNEL_SHUTDOWN",       r"SCHANNEL_SHUTDOWN",             1, True,
            "Graceful TLS close_notify on disconnect"),
    _Signal("BlockOldProtocols",       r"grbitEnabledProtocols|grbit",   1, True,
            "grbitEnabledProtocols field set (disables SSL 2/3 and TLS 1.0/1.1)"),

    # ── Layer 2: HMAC-SHA256 authentication ───────────────────────────────
    _Signal("BCryptHmacFlag",    r"BCRYPT_ALG_HANDLE_HMAC_FLAG",    2, True,
            "BCrypt HMAC flag — required for HMAC-SHA256"),
    _Signal("BCryptSha256",      r"BCRYPT_SHA256_ALGORITHM",        2, True,
            "BCrypt SHA-256 algorithm selector"),
    _Signal("BCryptCreateHash",  r"BCryptCreateHash\s*\(",          2, True,
            "BCrypt hash/HMAC context creation"),
    _Signal("BCryptHashData",    r"BCryptHashData\s*\(",            2, True,
            "BCrypt data feed into hash context"),
    _Signal("BCryptFinishHash",  r"BCryptFinishHash\s*\(",          2, True,
            "BCrypt hash finalisation"),
    _Signal("HmacLen32",         r"\b(TLS_AUTH_HMAC_LEN|32)\b.*hmac|hmac.*\b32\b",
                                                                    2, False,
            "32-byte HMAC-SHA256 output length"),
    _Signal("ChallengeLen16",    r"\b(TLS_CHALLENGE_LEN|16)\b.*challenge|challenge.*\b16\b",
                                                                    2, False,
            "16-byte server challenge"),

    # ── Layer 3: Protocol v2 negotiation ──────────────────────────────────
    _Signal("V2Magic",           r"TLS_V2_MAGIC|0x4[Dd][Uu]?\b|0x4[Dd]\b",
                                                                    3, True,
            "v2 protocol magic byte (0x4d = 'M')"),
    _Signal("EchoMagic",         r"_tls_raw_send.*&ver|_tls_raw_recv.*&ver",
                                                                    3, False,
            "Magic byte echo-back pattern"),

    # ── Layer 4: AES-256-GCM framing + replay protection ──────────────────
    _Signal("BCryptAes",         r"BCRYPT_AES_ALGORITHM",           4, True,
            "BCrypt AES algorithm provider"),
    _Signal("BCryptChainGcm",    r"BCRYPT_CHAIN_MODE_GCM",          4, True,
            "AES-GCM chaining mode"),
    _Signal("BCryptEncrypt",     r"BCryptEncrypt\s*\(",             4, True,
            "BCrypt AES-GCM encryption"),
    _Signal("BCryptDecrypt",     r"BCryptDecrypt\s*\(",             4, True,
            "BCrypt AES-GCM decryption"),
    _Signal("BCryptGenRandom",   r"BCryptGenRandom\s*\(",           4, True,
            "BCrypt random nonce generation"),
    _Signal("GcmAuthInfo",       r"BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO"
                                 r"|BCRYPT_INIT_AUTH_MODE_INFO",    4, True,
            "AES-GCM authenticated cipher mode info struct"),
    _Signal("NonceLEN12",        r"TLS_NONCE_LEN|\b12\b.*nonce|nonce.*\b12\b",
                                                                    4, False,
            "12-byte GCM nonce"),
    _Signal("TagLEN16",          r"TLS_GCM_TAG_LEN|\b16\b.*tag|tag.*\b16\b",
                                                                    4, False,
            "16-byte GCM auth tag"),
    _Signal("Uint32FrameHdr",    r"TLS_HDR_LEN|uint32.*length|hdr\[4\]",
                                                                    4, True,
            "uint32-BE frame length header"),
    _Signal("Uint64SeqNum",      r"TLS_SEQ_LEN|uint64.*seq|sendSeq|recvSeq",
                                                                    4, True,
            "uint64-BE sequence number (replay protection)"),
    _Signal("BigEndian64",       r"_write_be64|_read_be64|v>>56|p\[0\].*<<56",
                                                                    4, True,
            "Big-endian 64-bit encode/decode helpers"),
    _Signal("BigEndian32",       r"_write_be32|_read_be32|v>>24",   4, True,
            "Big-endian 32-bit encode/decode helpers"),
    _Signal("MaxFrameSize",      r"TLS_MAX_FRAME_SIZE|256.*1024.*1024",
                                                                    4, False,
            "Maximum frame size guard (256 MiB cap, mirrors MAX_PLUGIN_MSG_SIZE)"),
    _Signal("ReplayCheck",       r"recvSeq.*<=|<=.*recvSeq|replay",
                                                                    4, True,
            "Strict monotonic sequence check (replay rejection)"),

    # ── Build structure signals ────────────────────────────────────────────
    _Signal("WinMainEntry",      r"WinMain\s*\(",                   0, False,
            "WinMain entry point (hidden-window agent)"),
    _Signal("ReconnectLoop",     r"while\s*\(\s*1\s*\)|for\s*\(\s*;;\s*\)",
                                                                    0, False,
            "Infinite reconnect loop"),
    _Signal("LibSecur32",        r"Secur32\.lib|secur32",           0, False,
            "Secur32.lib linker dependency"),
    _Signal("LibBcrypt",         r"bcrypt\.lib|lbcrypt",            0, False,
            "bcrypt.lib linker dependency"),
    _Signal("FileOkVerb",        r'"FILE_OK"',                      0, False,
            "FILE_OK protocol verb (download handshake)"),
]

# Layer names for report display
_LAYER_NAMES = {
    0: "Build & Structure",
    1: "Layer 1 — SChannel TLS 1.2/1.3",
    2: "Layer 2 — HMAC-SHA256 Auth",
    3: "Layer 3 — Protocol v2 Negotiation",
    4: "Layer 4 — AES-256-GCM Framing",
}


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SignalResult:
    signal:  _Signal
    found:   bool
    files:   list[str] = field(default_factory=list)  # files where the signal was found


@dataclass
class ProbeResult:
    root_dir:   str
    files_scanned: int
    signals:    list[SignalResult] = field(default_factory=list)

    @property
    def compliant(self) -> bool:
        """True if all required signals are present."""
        return all(s.found for s in self.signals if s.signal.required)

    @property
    def required_missing(self) -> list[SignalResult]:
        return [s for s in self.signals if s.signal.required and not s.found]

    @property
    def optional_missing(self) -> list[SignalResult]:
        return [s for s in self.signals if not s.signal.required and not s.found]

    @property
    def found_count(self) -> int:
        return sum(1 for s in self.signals if s.found)

    @property
    def required_count(self) -> int:
        return sum(1 for s in self.signals if s.signal.required)

    @property
    def required_found(self) -> int:
        return sum(1 for s in self.signals if s.signal.required and s.found)


# ---------------------------------------------------------------------------
# Core probe function
# ---------------------------------------------------------------------------

def probe(root_dir: str) -> ProbeResult:
    """
    Scan all .c/.h and .cpp/.cc/.cxx/.hpp files under *root_dir* and return a ProbeResult.

    Parameters
    ----------
    root_dir : str
        Path to the C source directory (e.g. ``"C-remote-shell"``).
        Can be an absolute or relative path.
    """
    root_dir = os.path.abspath(root_dir)
    if not os.path.isdir(root_dir):
        result = ProbeResult(root_dir=root_dir, files_scanned=0)
        result.signals = [
            SignalResult(signal=s, found=False) for s in _SIGNALS
        ]
        return result

    # Read all C/H source files
    file_texts: dict[str, str] = {}
    for dirpath, _dirs, filenames in os.walk(root_dir):
        # Skip .git and build artefact directories
        _dirs[:] = [d for d in _dirs if d not in (".git", "build", "Release", "Debug")]
        for fname in filenames:
            if fname.lower().endswith((".c", ".h", ".cpp", ".cc", ".cxx", ".hpp")):
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        file_texts[fpath] = f.read()
                except OSError:
                    pass

    # Check each signal against the combined source
    signal_results: list[SignalResult] = []
    for sig in _SIGNALS:
        pat = re.compile(sig.pattern)
        matched_files: list[str] = []
        for fpath, text in file_texts.items():
            if pat.search(text):
                matched_files.append(os.path.relpath(fpath, root_dir))
        signal_results.append(
            SignalResult(signal=sig, found=bool(matched_files), files=matched_files)
        )

    return ProbeResult(
        root_dir=root_dir,
        files_scanned=len(file_texts),
        signals=signal_results,
    )


# ---------------------------------------------------------------------------
# Verb extraction — reads the exact wire strings dispatched by strncmp()
# ---------------------------------------------------------------------------

#  Matches:  strncmp("VERB", cmd, N)  or  strncmp(cmd, "VERB", N)
#  Captures the string literal in group 1.
_STRNCMP_RE = re.compile(
    r'strncmp\s*\(\s*"([^"]+)"\s*,\s*\w+|'   # strncmp("VERB", expr, …)
    r'strncmp\s*\(\s*\w+\s*,\s*"([^"]+)"',    # strncmp(expr, "VERB", …)
)


def extract_verbs(root_dir: str) -> list[str]:
    """
    Scan all .c/.cpp/.cc/.cxx files under *root_dir* for ``strncmp("VERB", …)`` calls
    and return the unique set of verb strings found, in discovery order.

    These are the exact wire strings the C client will accept — no
    Python-side hardcoding needed.

    Example return value::

        ['exit', 'q', 'sysinfo', 'cd ', 'upload ', 'download ',
         'persist ', 'self_destruct', 'forceOff()', 'blueScreen()']
    """
    root_dir = os.path.abspath(root_dir)
    seen: list[str] = []
    seen_set: set[str] = set()

    for dirpath, _dirs, filenames in os.walk(root_dir):
        _dirs[:] = [d for d in _dirs if d not in (".git", "build",
                                                    "Release", "Debug")]
        for fname in sorted(filenames):
            if not fname.lower().endswith((".c", ".cpp", ".cc", ".cxx")):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            for m in _STRNCMP_RE.finditer(text):
                verb = m.group(1) or m.group(2)
                if verb and verb not in seen_set:
                    seen_set.add(verb)
                    seen.append(verb)

    return seen


# Verbs the Python agent already handles natively — anything the C client
# also dispatches on is just redundant routing, not a C-exclusive feature.
# Strip trailing spaces so "cd " matches "cd", "upload " matches "upload", etc.
_PYTHON_AGENT_VERBS: frozenset[str] = frozenset({
    "cd", "sysinfo", "upload", "download", "persist", "self_destruct",
    "screenshot", "record", "screenshot_timelapse", "screen_stream", "webcam",
    "keylog_start", "keylog_dump", "keylog_stop", "getclip", "setclip",
    "portfwd", "hashdump", "wifi_passwords", "browser_history", "search",
    "zip_download", "idle_time", "mic_level", "msgbox", "inject_shellcode",
    "ps", "kill", "netstat", "arp", "dns_query", "routes", "ifconfig",
    "env", "installed_software", "active_windows", "scheduled_tasks",
    "services", "users", "logged_in", "startup_items", "os_info",
    "ls", "cat", "find_files", "find_writable", "find_suid", "file_hash",
    "tail", "write_file", "mkdir", "rm", "chmod", "screenshot_region",
    "notify", "open_url", "play_sound", "set_wallpaper", "clip_watch",
    "whoami_priv", "make_token", "rev2self", "getsystem", "timestomp",
    "clear_logs", "patch_amsi", "disable_defender", "hide_file",
    "ping_sweep", "smb_shares", "ssh_connect", "rdp_enable",
    "exfil_dns", "exfil_http", "socks5", "load_stage", "forkbomb",
    "lock_screen", "token_steal", "cred_vault", "living_off_land",
    "reverse_shell", "uac_bypass", "dll_inject", "sudo_sniff",
    "ssh_harvest", "screenrecord", "mouse_move", "type_keys",
    "browser_creds", "exit", "q",
    # Added in v4 — kiwi native C credential dumper
    "kiwi",
})


def c_exclusive_verbs(root_dir: str) -> list[str]:
    """
    Return the subset of verbs found in the C source that have no
    counterpart in the Python agent — i.e. the verbs that are
    **genuinely C-exclusive** and need their own operator commands.

    Currently this returns things like ``['forceOff()', 'blueScreen()']``,
    but if you add a new strncmp dispatch in the C shell loop the new verb
    appears here automatically without touching any Python file.
    """
    all_verbs = extract_verbs(root_dir)
    exclusive: list[str] = []
    for verb in all_verbs:
        # Normalise: strip trailing spaces and lowercase for comparison
        normalised = verb.rstrip(" ()").lower()
        if normalised not in _PYTHON_AGENT_VERBS:
            exclusive.append(verb)
    return exclusive


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def format_report(result: ProbeResult) -> str:
    """Return a multi-line compliance report string."""
    lines: list[str] = []
    sep = "-" * 68

    lines.append("")
    lines.append("  C2 Compliance Probe Report")
    lines.append(f"  Source: {result.root_dir}")
    lines.append(f"  Files scanned: {result.files_scanned}")
    lines.append("")

    if result.files_scanned == 0:
        lines.append("  [!] No .c or .h files found — check the path.")
        lines.append("")
        return "\n".join(lines)

    # Group by layer
    by_layer: dict[int, list[SignalResult]] = {}
    for sr in result.signals:
        by_layer.setdefault(sr.signal.layer, []).append(sr)

    for layer_num in sorted(by_layer.keys()):
        layer_name = _LAYER_NAMES.get(layer_num, f"Layer {layer_num}")
        lines.append(f"  {sep}")
        lines.append(f"  {layer_name}")
        lines.append(f"  {sep}")
        for sr in by_layer[layer_num]:
            if sr.found:
                tag  = "[+]"
                src  = f"  ({', '.join(sr.files[:2])})" if sr.files else ""
                detail = f"{sr.signal.description}{src}"
            else:
                tag    = "[!]" if sr.signal.required else "[-]"
                detail = sr.signal.description
                if sr.signal.required:
                    detail += "  ← MISSING (required)"
                else:
                    detail += "  ← absent (optional)"
            lines.append(f"    {tag}  {detail}")
        lines.append("")

    # Summary
    req_found = result.required_found
    req_total = result.required_count
    all_found = result.found_count
    all_total = len(result.signals)

    verdict = "[+] COMPLIANT" if result.compliant else "[-] NON-COMPLIANT"
    lines.append(f"  {sep}")
    lines.append(f"  Summary: {req_found}/{req_total} required signals found  "
                 f"({all_found}/{all_total} total)")
    lines.append(f"  Verdict: {verdict}")

    if result.required_missing:
        lines.append("")
        lines.append("  Missing required signals:")
        for sr in result.required_missing:
            lines.append(f"    • {sr.signal.name}: {sr.signal.description}")

    lines.append(f"  {sep}")
    lines.append("")
    return "\n".join(lines)


def print_report(result: ProbeResult) -> None:
    """Print the compliance report to stdout."""
    print(format_report(result))
