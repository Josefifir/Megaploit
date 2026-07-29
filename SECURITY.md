# Security Policy

## Supported Versions

| Version | Status |
|---------|--------|
| v4.x (current) | ✅ Actively maintained — all security fixes |
| v3.x | ⚠️ Critical security fixes only |
| v2.x and below | ❌ End of life — please upgrade |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via **GitHub Security Advisories**:  
👉 [https://github.com/Josefifir/Megaploit/security/advisories/new](https://github.com/Josefifir/Megaploit/security/advisories/new)

Or email the maintainer directly (see GitHub profile).

### What to include

| Field | Details |
|---|---|
| **Description** | What the vulnerability is and where it exists |
| **Steps to reproduce** | Minimal reproduction — exact commands, config, versions |
| **Impact** | What an attacker could achieve |
| **Component** | e.g. `listener.py`, `protocol.py`, `C-remote-shell/tls/` |
| **Fix suggestion** | Optional — any ideas on how to address it |

### Response timeline

| Milestone | Target |
|---|---|
| Initial acknowledgement | 72 hours |
| Severity assessment | 5 business days |
| Patch for critical issues | 14 days |
| Patch for high/medium issues | 30 days |
| Public disclosure | After patch is released |

We follow **coordinated disclosure** — we will credit researchers in the release notes unless anonymity is requested.

---

## Security Architecture

Megaploit implements defence-in-depth across four layers on every agent connection:

### Layer 1 — TLS 1.2/1.3 (transport)
- Optional but strongly recommended: `python server.py --tls`
- Auto-generates a self-signed cert; SHA-256 fingerprint printed on startup
- AEAD-only cipher suites enforced (`AES-128/256-GCM`, `ChaCha20-Poly1305`)
- No renegotiation, no compression, no null/RC4/export ciphers
- The C agent (`C-remote-shell`) uses Windows SChannel with `SCH_USE_STRONG_CRYPTO`

### Layer 2 — HMAC-SHA256 authentication
- Every connection must pass a challenge/response before any data is exchanged
- Server sends 16-byte random nonce; agent responds with `HMAC-SHA256(secret_key, nonce)`
- Verified with `hmac.compare_digest` (constant-time — no timing oracle)
- Connections that fail auth are dropped immediately and logged

### Layer 3 — AES-256-GCM encrypted framing
- All post-auth traffic is AES-256-GCM encrypted end-to-end
- Each message carries a random 12-byte nonce (never reused)
- 16-byte GCM authentication tag — any tampering causes decryption failure
- Requires the `cryptography` package; the server and agent refuse to start without it

### Layer 4 — Replay protection
- Every message carries a monotonic `uint64` sequence number
- Messages with a sequence number ≤ the last accepted are rejected immediately
- Prevents replay of captured ciphertext

### Additional hardening
| Control | Detail |
|---|---|
| **Per-IP rate limiting** | Auto-ban after 5 failed auth attempts per 60-second window |
| **IP allowlist** | Optional restriction to specific source IPs |
| **Audit log** | All connection attempts and commands logged to `loot/audit.log` (UTC timestamps) |
| **Dangerous command confirmation** | Destructive commands (`self_destruct`, `forceOff`, `blueScreen`, `forkbomb`, etc.) require explicit `YES` |
| **Secret key never logged** | Only the first 16 hex chars of `SHA-256(key)` are displayed as a fingerprint |
| **Secret key file permissions** | Server warns at startup if `secret.key` is readable by group/others (Unix) |

---

## Known Limitations

- **No certificate pinning** on the Python agent — TLS cert is accepted without validation (by design; C2 uses a self-signed cert). The HMAC layer compensates for this.
- **Python agent is not obfuscated** by default — the `payload` command's encoder pipeline provides obfuscation, but it is not a substitute for an AV-evasion product.

---

## Responsible Use

Megaploit is a penetration testing and security research tool.

You are solely responsible for:
- Obtaining **explicit written authorisation** before testing any system you do not own
- Complying with all applicable laws and regulations in your jurisdiction
- Not using this tool for malicious, illegal, or unauthorised purposes

The authors accept **no liability** for misuse. See [LICENSE](LICENSE) for the full terms.
