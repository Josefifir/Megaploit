# Security Policy

## Supported Versions

| Version | Supported          |
|---------|-------------------|
| 3.x     | ✅ Active support |
| 2.x     | ⚠️ Security fixes only |
| 1.x     | ❌ End of life |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues via:
1. GitHub's [Private Security Advisory](https://github.com/JosephFrankFir/Megaploit/security/advisories/new) feature
2. Email the maintainer directly (see GitHub profile)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

We aim to respond within **72 hours** and release a patch within **14 days** for critical issues.

## Security Design Principles

Megaploit is designed with the following security controls:

- **HMAC-SHA256 challenge-response authentication** — every connection is authenticated before any command executes
- **AES-256-GCM transport encryption** — per-session encrypted channel with sequence numbers and replay protection (requires `cryptography` package)
- **TLS 1.2+ enforcement** — when TLS is configured: AEAD-only cipher suites, no renegotiation, no compression, forward secrecy required
- **Per-IP rate limiting** — automatic ban after 5 failed auth attempts in 60 seconds
- **IP allowlist** — optional restriction to specific source IPs
- **Audit log** — all connection attempts and commands logged to `loot/audit.log` with UTC timestamps
- **Dangerous command confirmation** — destructive commands require explicit `YES` confirmation
- **Secret key never logged** — key fingerprint (SHA-256 prefix) used for display only

## Responsible Use

Megaploit is a penetration testing tool. You are responsible for:
- Obtaining explicit written authorisation before testing any system
- Complying with all applicable laws and regulations
- Not using this tool for malicious purposes

The authors accept no liability for misuse.
