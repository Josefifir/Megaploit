# Megaploit

A professional Python-based C2 (Command & Control) framework for authorised
penetration testing and security research.  Released under [GNU GPL v3](LICENSE).

> **Warning — You must have explicit written permission to use this tool on any
> system.  Unauthorised use is illegal.  The authors accept no liability for misuse.**

---

## Features

| Feature | Details |
|---------|---------|
| Metasploit-style CLI | Animated banner, colour prompts, spinner, tab-completion |
| Multiple simultaneous sessions | `sessions` list, `use <id>` to switch |
| HMAC-SHA256 authentication | Every connection is cryptographically verified |
| Optional TLS encryption | Wrap the C2 channel with your own certificate |
| Screenshot / audio recording | Files saved to `loot/` automatically |
| Screen & webcam streaming | MJPEG over HTTP (no client software needed) |
| Keylogger | Runs as a silent daemon thread on the target |
| File upload / download | Framed binary transfer — no stream corruption |
| Windows persistence | Registry auto-run entry |
| Arbitrary shell execution | Shell fallback for any unknown command |

---

## Project Layout

```
megaploit/
├── core/
│   ├── config.py       ← shared constants (ports, timeouts, sentinel)
│   ├── crypto.py       ← HMAC auth helpers (server + agent)
│   └── protocol.py     ← send_msg / recv_msg / send_file / recv_file
├── server/
│   ├── cli.py          ← interactive Metasploit-style console
│   ├── commands.py     ← all operator commands (decorated registry)
│   ├── listener.py     ← TCP accept loop, SSL wrapping, auth handshake
│   └── session.py      ← per-connection state & loot path helpers
├── agent/
│   ├── connection.py   ← persistent connect-back loop
│   ├── handlers.py     ← all command implementations on the target
│   ├── keylogger.py    ← pynput keystroke capture
│   └── shell.py        ← recv-execute-respond loop
└── streaming/
    ├── screen.py       ← mss+OpenCV screen-grabber Camera class
    ├── desktop.py      ← Flask MJPEG app for desktop (port 5000)
    ├── webcam.py       ← Flask MJPEG app for webcam  (port 5001)
    └── templates/
        ├── desktop.html
        └── webcam.html

server.py               ← thin operator entrypoint
agent.py                ← thin agent payload entrypoint
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate a shared HMAC secret

Copy `secret.key` to **both** the operator machine and the target.

```bash
python -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
```

### 3. (Optional) Generate a self-signed TLS certificate

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 4. Start the C2 console

```bash
python server.py -lh 192.168.1.10 -p 4444
# With TLS:
python server.py -lh 192.168.1.10 -p 4444 --cert cert.pem --key key.pem
```

You will see the animated banner and a `megaploit >` prompt.

### 5. Generate and deploy the agent

Inside the console:

```
megaploit > set lhost 192.168.1.10
megaploit > set port 4444
megaploit > generate          # patches agent.py
megaploit > generate -c       # patches + byte-compiles agent.py
```

Copy `agent.py` (and `secret.key`) to the target, then run:

```bash
python agent.py
```

The agent silently reconnects every 10 s until the server is up.

---

## Console Commands

### Global context

| Command | Description |
|---------|-------------|
| `sessions` | List all active sessions |
| `use <id>` | Interact with a session |
| `generate [-c]` | Patch (and compile) agent.py |
| `set <opt> <val>` | Set `lhost` / `port` / `cert` / `key` |
| `clear` | Clear the terminal |
| `exit` | Quit Megaploit |

### Session context (`use <id>`)

| Command | Description |
|---------|-------------|
| `help` | List all session commands |
| `back` | Return to global prompt |
| `sysinfo` | OS, hostname, user, architecture |
| `cd <dir>` | Change directory on target |
| `shell <cmd>` | Execute a shell command |
| `upload <local>` | Send a local file to the target |
| `download <remote>` | Retrieve a file from the target |
| `screenshot` | Capture screenshot → `loot/screenshots/` |
| `record <secs>` | Record microphone → `loot/recordings/` |
| `screen_stream on\|off` | Desktop MJPEG at `http://<target>:5000` |
| `webcam on\|off` | Webcam MJPEG at `http://<target>:5001` |
| `persist <reg> <file>` | Windows registry persistence |
| `keylog_start` | Start keylogger |
| `keylog_dump` | Read captured keys |
| `keylog_stop` | Stop + delete keylog |
| `forkbomb` | ⚠ Crash target (Unix, confirmation required) |
| `exit` | Close session |

---

## Wire Protocol

All text messages are JSON-encoded and delimited by the `<<MEGAPLOIT_END>>`
sentinel.  Binary payloads (files, screenshots, recordings) are streamed
raw and also terminated by the same sentinel.  This means the single TCP
connection never gets corrupted by partial reads or mixed message types.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[issue tracker](https://github.com/JosephFrankFir/Megaploit/issues).
