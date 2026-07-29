"""
megaploit.server.listener
~~~~~~~~~~~~~~~~~~~~~~~~~
TCP listener that accepts incoming agent connections, performs SSL wrapping,
HMAC authentication, and hands off authenticated Sessions to the CLI.

Hardening layers (applied in order on every inbound connection)
---------------------------------------------------------------
1. IP allowlist  — if configured, connections from unlisted IPs are dropped
                   before any data is read.
2. Rate limiter  — tracks auth attempts per source IP per 60-second window.
                   IPs that exceed MAX_AUTH_ATTEMPTS_PER_MIN are banned for
                   IP_BAN_DURATION seconds.
3. TLS           — optional; enforces TLS 1.2+ with AEAD-only cipher suites,
                   no renegotiation, no compression, forward secrecy required.
4. HMAC-SHA256   — challenge/response authentication; connection dropped on any
                   mismatch.
5. Audit log     — every attempt (allowed, denied, banned) is appended to
                   loot/audit.log with a UTC timestamp and source IP.
"""

from __future__ import annotations

import collections
import datetime
import hashlib
import logging
import os
import socket
import ssl
import subprocess
import threading
import time
from typing import Callable

from megaploit.core.crypto import server_authenticate
from megaploit.core.protocol import handshake_server, remove_state
from megaploit.server.session import Session
from megaploit.core.config import (
    AUTH_TIMEOUT,
    MAX_AUTH_ATTEMPTS_PER_MIN,
    IP_BAN_DURATION,
    AUDIT_LOG,
)


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

def _setup_audit_logger() -> logging.Logger:
    os.makedirs(os.path.dirname(AUDIT_LOG) or ".", exist_ok=True)
    logger = logging.getLogger("megaploit.audit")
    if not logger.handlers:
        handler = logging.FileHandler(AUDIT_LOG, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s UTC  %(message)s",
                                               datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

_audit = _setup_audit_logger()


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """
    Sliding-window rate limiter keyed on source IP.
    Thread-safe via a single lock.
    """

    def __init__(self, max_per_min: int, ban_duration: int) -> None:
        self._max   = max_per_min
        self._ban   = ban_duration
        self._lock  = threading.Lock()
        # ip → deque of timestamps (seconds)
        self._hits: dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque()
        )
        # ip → ban-expiry timestamp
        self._bans: dict[str, float] = {}

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            expiry = self._bans.get(ip, 0)
            if expiry and time.time() < expiry:
                return True
            if expiry:
                del self._bans[ip]
            return False

    def record(self, ip: str) -> bool:
        """
        Record a connection attempt.  Returns True if the IP should be allowed,
        False if it has exceeded the rate limit (and is now banned).
        """
        now = time.time()
        with self._lock:
            dq = self._hits[ip]
            # Drop timestamps outside the 60-second window
            while dq and now - dq[0] > 60:
                dq.popleft()
            dq.append(now)
            if len(dq) > self._max:
                self._bans[ip] = now + self._ban
                _audit.warning("BANNED  ip=%-18s  attempts=%d  ban_until=%s",
                               ip, len(dq),
                               time.strftime("%H:%M:%S", time.gmtime(now + self._ban)))
                return False
        return True


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------

class Listener:
    """
    Runs a non-blocking accept loop in a background daemon thread.
    Authenticated sessions are passed to on_session(); everything else
    is dropped after being recorded in the audit log.
    """

    def __init__(
        self,
        bind_host: str,
        port: int,
        secret_key: bytes,
        on_session: Callable[[Session], None],
        ssl_context: ssl.SSLContext | None = None,
        allowed_ips: list[str] | None = None,
    ) -> None:
        self.bind_host   = bind_host
        self.port        = port
        self.secret_key  = secret_key
        self.on_session  = on_session
        self.ssl_context = ssl_context
        # None = allow all; empty list = deny all; list of IPs = allowlist
        self._allowed_ips: set[str] | None = (
            set(allowed_ips) if allowed_ips is not None else None
        )
        self._rate       = _RateLimiter(MAX_AUTH_ATTEMPTS_PER_MIN, IP_BAN_DURATION)
        self._server_sock: socket.socket | None = None
        self._session_counter = 0
        self._lock  = threading.Lock()
        self._thread: threading.Thread | None = None
        self._running = False

    # ---------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------

    def start(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # SO_REUSEPORT speeds up restart on Linux (no TIME_WAIT delay)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        self._server_sock.bind((self.bind_host, self.port))
        self._server_sock.listen(10)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        _audit.info("LISTEN  bind=%s:%d  tls=%s  allowlist=%s",
                    self.bind_host, self.port,
                    "yes" if self.ssl_context else "no",
                    "none" if self._allowed_ips is None else str(sorted(self._allowed_ips)))

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        _audit.info("STOPPED")

    def cleanup_session(self, conn) -> None:
        """Call when a session socket is being closed."""
        remove_state(conn)

    # ---------------------------------------------------------------
    # Accept loop
    # ---------------------------------------------------------------

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server_sock.accept()
            except OSError:
                break
            threading.Thread(
                target=self._handshake,
                args=(conn, addr),
                daemon=True,
            ).start()

    # ---------------------------------------------------------------
    # Per-connection handshake (runs in its own thread)
    # ---------------------------------------------------------------

    def _handshake(self, raw_conn: socket.socket, addr: tuple) -> None:
        ip, src_port = addr[0], addr[1]

        # ── 1. IP allowlist ──────────────────────────────────────
        if self._allowed_ips is not None and ip not in self._allowed_ips:
            raw_conn.close()
            _audit.warning("BLOCKED ip=%-18s  reason=not_in_allowlist", ip)
            return

        # ── 2. Rate limiter ──────────────────────────────────────
        if self._rate.is_banned(ip):
            raw_conn.close()
            _audit.warning("BLOCKED ip=%-18s  reason=banned", ip)
            return

        if not self._rate.record(ip):
            raw_conn.close()
            # record() already wrote the BANNED audit entry
            return

        # ── 3. TLS upgrade ───────────────────────────────────────
        conn = raw_conn
        if self.ssl_context:
            try:
                conn = self.ssl_context.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError as e:
                raw_conn.close()
                _audit.warning("REJECTED ip=%-18s port=%d  reason=tls_error  detail=%s",
                               ip, src_port, e)
                return

        # ── 4. HMAC authentication ───────────────────────────────
        if not server_authenticate(conn, self.secret_key, timeout=AUTH_TIMEOUT):
            conn.close()
            _audit.warning("REJECTED ip=%-18s port=%d  reason=auth_failed", ip, src_port)
            return

        # ── 5. Protocol version handshake (AES-GCM v2) ──────────
        handshake_server(conn, self.secret_key)

        # ── 6. Session created ───────────────────────────────────
        with self._lock:
            self._session_counter += 1
            sid = self._session_counter

        # Record TLS cipher suite and cert fingerprint if TLS is on
        tls_info = ""
        if self.ssl_context and hasattr(conn, "cipher"):
            cipher = conn.cipher()
            tls_info = f"  cipher={cipher[0] if cipher else 'unknown'}"

        _audit.info("ACCEPTED ip=%-18s port=%d  session=%d%s",
                    ip, src_port, sid, tls_info)

        session = Session(conn=conn, ip=ip, port=src_port, id=sid)
        self.on_session(session)


# ---------------------------------------------------------------------------
# Auto-cert generation
# ---------------------------------------------------------------------------

# Canonical paths for auto-generated TLS credentials
_AUTO_CERT = os.path.join("loot", "tls", "megaploit.crt")
_AUTO_KEY  = os.path.join("loot", "tls", "megaploit.key")


def generate_self_signed_cert(
    cert_path: str = _AUTO_CERT,
    key_path:  str = _AUTO_KEY,
    cn:        str = "megaploit",
) -> tuple[str, str, str]:
    """Generate a self-signed RSA-3072 certificate valid for 365 days.

    Tries the ``cryptography`` package first; falls back to ``openssl req``
    (subprocess).  Returns ``(cert_path, key_path, sha256_fingerprint_hex)``.
    The fingerprint is the full 64-char hex digest of the DER-encoded cert.
    """
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)

    # ── Try cryptography package ──────────────────────────────────────────
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem  = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with open(cert_path, "wb") as f:
            f.write(cert_pem)
        with open(key_path, "wb") as f:
            f.write(key_pem)

        # Fingerprint: SHA-256 of the DER form
        der = cert.public_bytes(serialization.Encoding.DER)
        fp  = hashlib.sha256(der).hexdigest()
        return cert_path, key_path, fp

    except ImportError:
        pass

    # ── Fallback: openssl req ────────────────────────────────────────────
    subj = f"/CN={cn}"
    cmd  = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path, "-out", cert_path,
        "-days", "365", "-nodes", "-subj", subj, "-newkey", "rsa:3072",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise RuntimeError(
            "TLS auto-cert failed: neither 'cryptography' package nor 'openssl' "
            "binary is available.  Install via:  pip install cryptography\n"
            f"  (original error: {exc})"
        ) from exc

    # Fingerprint via DER conversion
    der_cmd = ["openssl", "x509", "-in", cert_path, "-outform", "DER"]
    der = subprocess.run(der_cmd, check=True, capture_output=True).stdout
    fp  = hashlib.sha256(der).hexdigest()
    return cert_path, key_path, fp


# ---------------------------------------------------------------------------
# TLS context builders
# ---------------------------------------------------------------------------

def build_ssl_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    """
    Build a hardened server-side TLS context:
      - TLS 1.2 minimum (TLS 1.3 preferred where available)
      - AEAD cipher suites only (AES-GCM, ChaCha20-Poly1305)
      - No renegotiation
      - No compression
      - Forward secrecy required
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    # Minimum protocol version
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Disable weak options
    ctx.options |= ssl.OP_NO_SSLv2
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.options |= ssl.OP_NO_TLSv1
    ctx.options |= ssl.OP_NO_TLSv1_1
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.options |= ssl.OP_SINGLE_DH_USE
    ctx.options |= ssl.OP_SINGLE_ECDH_USE
    # Disable renegotiation where supported (Python 3.7+)
    if hasattr(ssl, "OP_NO_RENEGOTIATION"):
        ctx.options |= ssl.OP_NO_RENEGOTIATION

    # AEAD-only cipher suites — no CBC, no RC4, no export
    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20"
        ":!aNULL:!eNULL:!EXPORT:!RC4:!DES:!MD5:!PSK:!SRP"
    )

    return ctx


def build_agent_ssl_context() -> ssl.SSLContext:
    """
    Build a client-side TLS context for the agent.
    We use a self-signed cert on the server so hostname/cert verification
    is disabled, but we still enforce TLS 1.2+ and AEAD ciphers.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    ctx.options |= ssl.OP_NO_SSLv2
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.options |= ssl.OP_NO_TLSv1
    ctx.options |= ssl.OP_NO_TLSv1_1
    ctx.options |= ssl.OP_NO_COMPRESSION
    if hasattr(ssl, "OP_NO_RENEGOTIATION"):
        ctx.options |= ssl.OP_NO_RENEGOTIATION

    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20"
        ":!aNULL:!eNULL:!EXPORT:!RC4:!DES:!MD5:!PSK:!SRP"
    )

    return ctx
