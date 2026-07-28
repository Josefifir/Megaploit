# Web Dashboard & Multi-Operator RPC

> For WebSocket transport integration, see [ARCHITECTURE.md](ARCHITECTURE.md#wstransport--rfc-6455-websocket-layer-new-v3).

## Web Dashboard

### Starting

```
megaploit [1] » web start
[+] Web dashboard started: http://127.0.0.1:8080/
[*] API key (X-API-Key header): abc123def456

megaploit [1] » web start --port 9090 --host 0.0.0.0
megaploit [1] » web stop
megaploit [1] » web status
```

### Installation

Flask is required:
```bash
pip install flask
```

### Dashboard UI

The dashboard (`http://127.0.0.1:8080/`) provides:

- **Stat counters** — live session count, job count, credential count, loot file count
- **Sessions table** — ID, IP:Port, OS badge, hostname, username, tag badge, uptime
- **Jobs table** — ID, name, status badge, start time
- **Live event feed** — scrolling log of SSE events (new sessions, job completion, new creds)

The UI auto-refreshes sessions and jobs every 10 seconds and updates immediately on SSE events.

### Authentication

All endpoints require authentication if an API key is set (derived from the first 16 chars of your HMAC key fingerprint):

```bash
# Header:
curl -H "X-API-Key: abc123def456" http://127.0.0.1:8080/api/sessions

# Query param:
curl "http://127.0.0.1:8080/api/sessions?apikey=abc123def456"
```

### REST API Reference

#### `GET /api/sessions`
Returns JSON array of active sessions.
```json
[
  {
    "id": 1, "ip": "10.0.0.5", "port": 52341,
    "os_name": "Windows 10", "hostname": "DESKTOP-ABC",
    "username": "alice", "tag": "dc", "uptime": "00:04:32"
  }
]
```

#### `GET /api/sessions/<id>`
Single session detail.

#### `POST /api/sessions/<id>/cmd`
Send a command to a session.
```json
// Request:
{"cmd": "sysinfo"}

// Response:
{"ok": true, "output": "[+] OS: Windows 10 ..."}
```

#### `GET /api/loot`
```json
[{"path": "1/screenshots/shot.jpg", "size": 45231}, ...]
```

#### `GET /api/creds`
Credentials with secrets redacted to first 4 chars.
```json
[{"id": 1, "host": "10.0.0.5", "username": "alice", "cred_type": "ntlm", "secret": "aad3..."}, ...]
```

#### `GET /api/jobs`
```json
[{"id": "a1b2c3", "name": "tcp_scan", "status": "running", "started": "14:32:01Z"}, ...]
```

#### `GET /api/modules`
```json
[{"name": "auxiliary/scanner/tcp_port", "type": "auxiliary", "description": "...", "rank": 300}, ...]
```

#### `GET /events`
Server-Sent Events stream. Connect with `EventSource` in JavaScript.

Events have `event: update` type with JSON data:
```json
{"ts": "14:32:18", "type": "new_session", "session_id": 2, "ip": "10.0.0.7"}
{"ts": "14:33:01", "type": "job_done", "job_id": "a1b2c3", "name": "tcp_scan"}
{"ts": "14:34:15", "type": "new_cred", "host": "10.0.0.5", "username": "admin"}
```

---

## Multi-Operator JSON-RPC Server

### Starting

```
megaploit [1] » rpc start
[+] RPC server started on 127.0.0.1:7777
[*] API key: abc123def456
[*] Connect with any JSON-RPC 2.0 client over TCP.

megaploit [1] » rpc start --port 7778 --host 0.0.0.0
megaploit [1] » rpc stop
megaploit [1] » rpc status
megaploit [1] » rpc operators
  alice     10.0.0.2   authed
  bob       10.0.0.3   authed
```

### Protocol

- Raw TCP, newline-delimited JSON
- JSON-RPC 2.0 specification
- Each message is one JSON object followed by `\n`
- Responses interleaved with server-push notifications

### Connecting

```bash
# Using netcat:
nc 127.0.0.1 7777

# Using Python:
import socket, json

s = socket.socket()
s.connect(("127.0.0.1", 7777))

def rpc(s, method, params={}, id=1):
    msg = json.dumps({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
    s.sendall((msg + "\n").encode())
    return json.loads(s.makefile().readline())

# Authenticate first:
rpc(s, "auth", {"api_key": "abc123def456", "name": "alice"})
```

### Methods Reference

#### `auth`
Must be called first. All other methods return error -32001 if not authenticated.
```json
// Request:
{"jsonrpc":"2.0","id":1,"method":"auth","params":{"api_key":"abc123def456","name":"alice"}}

// Response:
{"jsonrpc":"2.0","id":1,"result":{"authenticated":true,"operator_count":1}}
```

#### `ping`
```json
{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}
// Response: {"result": "pong"}
```

#### `sessions.list`
Returns all active sessions.

#### `sessions.get`
```json
{"method":"sessions.get","params":{"session_id": 1}}
```

#### `session.cmd`
Send a command to a session and get the output synchronously.
```json
{"method":"session.cmd","params":{"session_id":1,"cmd":"sysinfo"}}
// Response: {"result":{"ok":true,"output":"[+] OS: Windows 10 ..."}}
```

#### `chat.send`
Broadcast a message to all connected operators.
```json
{"method":"chat.send","params":{"message":"Found domain admin on session 3"}}
```

#### `chat.history`
```json
{"method":"chat.history","params":{"n":50}}
// Response: [{"operator":"alice","message":"...","ts":"14:32:01"}, ...]
```

#### `notes.add`
Add a note to a session. Synced to `session.notes` (visible in reports).
```json
{"method":"notes.add","params":{"session_id":1,"text":"DC01 — kerberoastable, SPN: MSSQLSvc/..."}}
```

#### `notes.list`
```json
{"method":"notes.list","params":{"session_id":1}}
// Response: ["[alice] DC01 — kerberoastable...", ...]
```

#### `creds.list`
Returns credential store (secrets redacted).

#### `jobs.list`
Returns background job list.

#### `operators.list`
Returns list of connected + authenticated operators.

### Server-Push Notifications

The server pushes notifications to all authenticated operators:

```json
// New session:
{"jsonrpc":"2.0","method":"event","params":{"type":"new_session","session_id":3,"ip":"10.0.0.7","ts":"14:32"}}

// Session closed:
{"jsonrpc":"2.0","method":"event","params":{"type":"session_closed","session_id":1,"ts":"14:45"}}

// Chat message:
{"jsonrpc":"2.0","method":"event","params":{"type":"chat","operator":"alice","message":"found creds","ts":"14:33"}}

// Note added:
{"jsonrpc":"2.0","method":"event","params":{"type":"note_added","session_id":1,"operator":"bob","text":"...","ts":"14:34"}}

// Operator joined/left:
{"jsonrpc":"2.0","method":"event","params":{"type":"operator_joined","operator":"charlie","ts":"14:40"}}
{"jsonrpc":"2.0","method":"event","params":{"type":"operator_left","operator":"charlie","ts":"14:55"}}
```

### Error Codes

| Code | Meaning |
|---|---|
| -32700 | Parse error (malformed JSON) |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32603 | Internal error |
| -32001 | Not authenticated |
| -32002 | Session not found |

---

## Python API

### WebServer

```python
from megaploit.web.app import WebServer

ws = WebServer(
    sessions_ref  = console._sessions,
    sessions_lock = console._sessions_lock,
    port          = 8080,
    host          = "127.0.0.1",
    api_key       = "my-secret-key",
)
ws.start()
print(ws.url())          # "http://127.0.0.1:8080/"
print(ws.is_running())   # True

# Push SSE event to all connected browsers:
ws.broadcast("new_session", "Session 3 opened", session_id=3)
```

### RpcServer

```python
from megaploit.web.rpc import RpcServer

rpc = RpcServer(
    sessions_ref  = console._sessions,
    sessions_lock = console._sessions_lock,
    host          = "127.0.0.1",
    port          = 7777,
    api_key       = "my-secret-key",
)
rpc.start()

# Push event to all operators:
rpc.broadcast_event("new_cred", host="10.0.0.5", username="admin")
```
