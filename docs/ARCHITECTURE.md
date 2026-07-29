# Megaploit Architecture

Technical overview of how Megaploit works internally.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      OPERATOR MACHINE                       │
│                                                             │
│  server.py                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Console (cli.py)                                    │  │
│  │    ├── Global prompt — sessions, modules, payloads   │  │
│  │    └── Session prompt — 135 commands dispatched      │  │
│  │                                                       │  │
│  │  Listener (listener.py)                              │  │
│  │    ├── TCP accept loop (background thread)           │  │
│  │    ├── HMAC-SHA256 authentication                    │  │
│  │    ├── Rate limiter                                  │  │
│  │    └── IP allowlist                                  │  │
│  │                                                       │  │
│  │  Session (session.py)                                │  │
│  │    ├── Connection socket                             │  │
│  │    ├── Loot paths                                    │  │
│  │    └── Metadata (IP, OS, hostname, tag, uptime)     │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  Module Registry — auto-discovers modules in modules/       │
│  Payload Builder — 14 formats + 12 encoders                │
│  Toolbox — 200+ tool installer                             │
│  Plugin System — TOML hot-reload                           │
│  Credential Store — SQLite                                 │
│  Loot Directory — files + audit log                        │
└─────────────────────────────────────────────────────────────┘
          │                 ▲
          │  AES-256-GCM    │  length-prefixed
          │  HMAC-SHA256    │  frames
          ▼                 │
┌─────────────────────────────────────────────────────────────┐
│                      TARGET MACHINE                         │
│                                                             │
│  agent.py  ─── connection.py (connect-back loop)           │
│                ├── HMAC-SHA256 authentication               │
│                ├── AES-256-GCM transport                   │
│                └── Auto-reconnect with jitter               │
│                                                             │
│  shell.py ─── recv → dispatch → respond loop               │
│                                                             │
│  handlers.py ─── 90+ victim-side handlers                  │
│  meterp.py   ─── 16 advanced post-exploitation handlers    │
│  keylogger.py                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Directory Layout

```
Megaploit/
├── server.py                    ← Entry point: parse args, launch Console
├── agent.py                     ← Agent entry point
├── secret.key                   ← Shared HMAC secret (generate once)
├── requirements.txt
├── install.sh
│
├── plugins/                     ← TOML plugin files
│   ├── c_remote_shell.toml      ← C-remote-shell plugin descriptor
│   └── c_remote_shell.py        ← C-remote-shell Python handlers
│
├── tools/                       ← Toolbox: git clones + tools.json
├── loot/                        ← All collected data + audit.log
│   ├── audit.log                ← Every command logged
│   ├── tls/                     ← Auto-generated TLS certs
│   └── session_N_IP/            ← Per-session loot
│       ├── screenshots/
│       ├── recordings/
│       └── downloads/
│
├── tests/                       ← 553 tests (pytest)
│
├── C-remote-shell/              ← Hardened C agent (git submodule)
│
└── megaploit/
    ├── server/
    │   ├── cli.py               ← Interactive operator console
    │   ├── commands.py          ← 135 session command dispatchers
    │   ├── meterp_session.py    ← Meterpreter-class console
    │   ├── listener.py          ← TCP accept + TLS + auth + rate limiter
    │   ├── session.py           ← Session dataclass with loot paths
    │   ├── http_listener.py     ← WebSocket HTTP upgrade listener
    │   └── dns_listener.py      ← DNS C2 listener
    │
    ├── agent/
    │   ├── connection.py        ← Connect-back loop with jitter + reconnect
    │   ├── handlers.py          ← 90+ victim-side handlers
    │   ├── meterp.py            ← Advanced post-exploitation handlers
    │   ├── keylogger.py         ← pynput keystroke logger
    │   ├── shell.py             ← recv → handle → respond loop
    │   ├── hollowing.py         ← Process hollowing helpers
    │   └── go_agent/
    │       ├── main.go          ← Go agent source
    │       └── go.mod
    │
    ├── core/
    │   ├── config.py            ← Shared constants
    │   ├── crypto.py            ← HMAC-SHA256 auth
    │   ├── protocol.py          ← AES-256-GCM transport + WsTransport
    │   ├── autorun.py           ← AutoRunScript engine
    │   ├── pipeline.py          ← Post-exploitation pipeline
    │   ├── profile.py           ← Malleable C2 profile
    │   ├── c_probe.py           ← C/C++ source compliance prober
    │   ├── jobs.py              ← Background job manager
    │   ├── heartbeat.py         ← Session pruner
    │   ├── resource_runner.py   ← Resource script runner
    │   └── staging.py           ← Staged payload delivery
    │
    ├── modules/
    │   ├── base.py              ← Module + AgentModule base classes
    │   ├── registry.py          ← Auto-discovery registry (os.walk)
    │   ├── auxiliary/           ← 12+ scanner modules
    │   └── exploits/            ← 20+ exploit modules
    │       ├── windows/smb/ rdp/ http/ ftp/
    │       ├── linux/ssh/ http/ redis/ misc/
    │       └── multi/handler/ http/ ftp/
    │
    ├── payload/
    │   ├── builder.py           ← 14-format builder + Go/C compilation
    │   └── encoders.py          ← 12-encoder pipeline
    │
    ├── db/
    │   ├── database.py          ← SQLite credential/host/loot store
    │   └── workspace.py         ← Named workspace support
    │
    ├── reporting/               ← HTML/JSON engagement report generator
    ├── web/                     ← Flask dashboard + SSE
    ├── streaming/               ← Screenshot stream helpers
    ├── toolbox/                 ← Tool installer + catalogue
    ├── plugins/                 ← TOML plugin loader + runner
    └── native/                  ← C compilation helpers (kiwi)
```

---

## Wire Protocol

All messages use a simple length-prefix framing:

```
[ uint32 length (4 bytes, big-endian) ][ payload ]
```

When AES-256-GCM is enabled (requires `cryptography` package):

```
[ uint32 length ][ uint64 sequence_number ][ IV (12 bytes) ][ ciphertext ][ GCM tag (16 bytes) ]
```

- Sequence numbers prevent replay attacks (out-of-order or replayed messages are rejected)
- Each message has a fresh random 12-byte IV
- GCM tag authenticates both the sequence number and ciphertext

---

## Transport Layers

```
Application data (JSON command / response)
         │
         ▼
  AES-256-GCM encryption (protocol.py)
         │
         ▼
  Length-prefix framing (4B big-endian)
         │
         ▼
  TLS (optional, via ssl.wrap_socket)
         │
         ▼
  TCP socket
         │
         │  OR
         ▼
  WebSocket framing (HTTP Upgrade)
         │
         ▼
  TLS (optional)
         │
         ▼
  TCP socket
```

---

## Authentication Flow

```
Operator listener               Agent
      │                           │
      │◄─── TCP connect ──────────│
      │                           │
      │──── 16-byte challenge ────►│
      │                           │
      │◄─── HMAC-SHA256(key,      │
      │     challenge) ───────────│
      │                           │
      │  verify with              │
      │  compare_digest()         │
      │                           │
      │  if OK: session accepted  │
      │  if FAIL: disconnect,     │
      │           rate-limit IP   │
      │                           │
      │◄═══ AES-256-GCM channel ══│
```

---

## Session Lifecycle

```
1. Agent connects → listener accepts socket
2. Authentication (HMAC challenge/response)
3. Session object created (ID, IP, port, loot paths)
4. Session added to sessions dict
5. Console shows "NEW SESSION #N" notification
6. Pipeline / AutoRunScript runs (background thread, 0.5s delay)
7. Operator types `use N` → session loop starts
8. Operator types commands → dispatched to agent via AES channel
9. Agent receives command → runs handler → sends response
10. Session loop receives response → prints to console
11. Operator types `background` → returns to global prompt
    (session stays alive)
12. Agent disconnects (network loss / `exit`) → session removed
```

---

## Command Dispatch

When you type a command in a session:

```
Operator types: "download /etc/shadow"
        │
        ▼
cli.py _session_loop()
        │
        ▼  calls
commands.dispatch(session, "download /etc/shadow")
        │
        ▼  looks up "download" in _registry
cmd_download(session, ["/etc/shadow"])
        │
        ├── send_msg(conn, "download /etc/shadow")   ← to agent
        │
        │  ← agent sends FILE_OK, then file bytes
        │
        ├── recv_file(conn, local_path)
        │
        └── returns CommandResult(ok=True, output="[+] Saved to: loot/...")
        │
        ▼
cli.py prints the result
```

---

## Agent-Side Architecture

The agent runs two threads:

```
Thread 1 — Main shell loop (shell.py)
  while True:
    msg = recv_msg(conn)            # blocks waiting for operator command
    if "PING": continue             # discard heartbeats
    result = dispatch_handler(msg)  # handlers.py or meterp.py
    send_msg(conn, result)

Thread 2 — Heartbeat (every 30s)
  while True:
    send_msg(conn, "PING")          # keep-alive
    sleep(30)
```

The server's `recv_msg` wrapper silently discards `PING` frames to keep the protocol in sync.

---

## Loot Organization

Every piece of collected data is saved automatically:

```
loot/
  audit.log                  ← every command: timestamp, session, IP, status
  tls/
    cert.pem, key.pem        ← auto-generated TLS certificate
  .session_1.history         ← per-session readline history
  session_1_10.0.0.42/
    screenshots/
      20240115_143022.png    ← PNG with embedded metadata (IP, timestamp)
    recordings/
      20240115_150000.wav    ← microphone recordings
    downloads/
      shadow                 ← downloaded files
      id_rsa
    stream/
      frame_0001.jpg         ← screenshot stream frames
      frame_0002.jpg
```

---

## Plugin System Architecture

Plugins extend Megaploit without modifying Python code.

**TOML plugin file** (`plugins/my_plugin.toml`):

```toml
name    = "my_plugin"
version = "1.0"
author  = "you"

[[command]]
name    = "portscan"
kind    = "local"              # run locally on operator machine
shell   = "nmap -sV -p {arg0:-1-1000} {session_ip}"
timeout = 120

[[command]]
name    = "deploy_tool"
kind    = "session"            # run on target via C2 channel
shell   = "upload {arg0} && shell chmod +x {arg0} && shell ./{arg0}"
dangerous = true

[[command]]
name    = "custom_python"
kind    = "python"             # run Python handler function
handler = "my_plugin.handle_custom"
```

**Handler function** (for `kind = "python"`):

```python
# plugins/my_plugin.py
from megaploit.server.commands import CommandResult

def handle_custom(session, args):
    # full access to session and C2 commands
    from megaploit.server.commands import dispatch
    result = dispatch(session, "whoami")
    return CommandResult(ok=True, output=f"Custom: {result.output}")
```

Plugins are hot-reloaded when files change (if `plugins watcher on` is enabled).

---

## Module Registry Auto-Discovery

The registry uses `os.walk()` to recursively scan `megaploit/modules/`:

```python
# Any .py file with MODULE = SomeClass at module level is registered
# The module's name attribute determines its path in the catalogue

class MyExploit(Module):
    name = "exploits/linux/http/my_exploit"   # ← catalogue path
    ...

MODULE = MyExploit   # ← required
```

After adding a new file, the registry auto-discovers it on next `show modules` or reload.

---

## Database Schema

SQLite database at `loot/megaploit.db`:

```sql
hosts (id, ip, hostname, os, notes, first_seen, last_seen)
services (id, host_id, port, proto, name, banner, version)
credentials (id, host_id, username, password, hash_type, source, captured_at)
loot_files (id, host_id, path, local_path, file_type, captured_at)
notes (id, host_id, title, content, created_at)
jobs (id, name, status, started_at, completed_at, output)
```

Access via CLI:

```
megaploit [0] » creds show
megaploit [0] » creds search admin
megaploit [0] » creds export creds.json
megaploit [0] » loot browse
```
