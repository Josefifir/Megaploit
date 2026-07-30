# Payload Builder

Build payloads for any platform and delivery method.

```
megaploit [0] » payload <format> [options]
```

## Formats

| Format | Description |
|---|---|
| `py` | Pure Python source agent |
| `ps1` | PowerShell dropper (AMSI + ETW bypass) |
| `hta` | HTML Application dropper (VBScript) |
| `vba` | VBA macro dropper |
| `sh` | Bash/sh dropper |
| `bat` | Windows batch dropper |
| `exe` | PyInstaller Windows EXE |
| `elf` | PyInstaller Linux ELF |
| `go_exe` | Go agent compiled for Windows |
| `go_elf` | Go agent compiled for Linux/macOS |
| `oneliner_py` | Single Python one-liner (gzip+base64) |
| `oneliner_ps1` | Single PowerShell one-liner with AMSI bypass |
| `py_stealth` | ctypes-only agent (minimal AV signature) |
| `raw` | Alias for `py` |

## Examples

```bash
# Basic PowerShell dropper
megaploit [0] » payload ps1 --out agent.ps1

# Windows EXE with UPX packing
megaploit [0] » payload exe --out agent.exe --upx

# Windows EXE with spoofed PE metadata
megaploit [0] » payload exe --out agent.exe \
    --pe-company "Microsoft Corporation" \
    --pe-product "Windows Defender" \
    --pe-version "4.18.2304.8"

# Python agent with obfuscation layers
megaploit [0] » payload py --encoder comment_spam --encoder varname_rand --out obf.py

# Python agent with sandbox and ETW evasion
megaploit [0] » payload py --encoder sandbox_detect --encoder etw_patch --out hardened.py

# Go binary for Linux (no Python required on target)
megaploit [0] » payload go_elf --out agent_linux

# PowerShell one-liner with sleep (sandbox evasion)
megaploit [0] » payload ps1 --sleep 30 --out delayed.ps1

# Stealth Python agent
megaploit [0] » payload py_stealth --out stealth.py

# Print PowerShell one-liner to terminal
megaploit [0] » payload oneliner_ps1
```

## Encoders

Chain multiple encoders with `--encoder`:

| Encoder | Effect |
|---|---|
| `comment_spam` | Inject random comment blocks |
| `varname_rand` | Randomize variable names |
| `sandbox_detect` | Prepend sandbox detection (exits if in VM) |
| `etw_patch` | Prepend ETW disable stub |
| `b64_gzip` | Base64 + gzip compress |
| `xor_rolling` | Rolling XOR byte stream |
| `rc4` | RC4 stream cipher |
| `rev` | Reverse bytes |
| `null_pad` | Insert null bytes between instructions |
| `rot13_src` | ROT-13 source obfuscation |
