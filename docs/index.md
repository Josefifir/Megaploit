# Megaploit Documentation

**Professional C2 Framework & Security Research Toolbox · v3.0.0**

> **For authorised security research and penetration testing only.**  
> You must have explicit written permission before using this tool against any system.  
> Misuse is illegal and unethical. The authors accept no liability.

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Architecture](ARCHITECTURE.md) | High-level design, components, transport, sessions, and internal structure |
| [CLI Reference](CLI_REFERENCE.md) | Complete command reference (global + session context) |
| [Module System](MODULE_SYSTEM.md) | How to use and write modules (including AgentModule) |
| [Payload Builder](PAYLOAD_BUILDER.md) | All payload formats, encoders, and Go agent compilation |
| [Post-Exploitation Pipeline](PIPELINE.md) | Named collection profiles (`basic`, `creds`, `recon`, etc.) |
| [Malleable C2 Profile](C2_PROFILE.md) | YAML traffic shaping, URI rotation, sleep/jitter, headers |
| [Web Dashboard](WEB_DASHBOARD.md) | Flask dashboard, SSE live updates, and REST API |
| [Networking](NETWORKING.md) | Transport, WebSocket evasion, TLS, and protocol details |

---

## Quick Links

- [Main README](https://github.com/Josefifir/Megaploit) — Installation, Quick Start & full overview
- [Contributing](https://github.com/Josefifir/Megaploit/blob/main/CONTRIBUTING.md)
- [Security Policy](https://github.com/Josefifir/Megaploit/blob/main/SECURITY.md)
- [Code of Conduct](https://github.com/Josefifir/Megaploit/blob/main/CODE_OF_CONDUCT.md)

---

## Getting Started

1. Install dependencies: `pip install -r requirements.txt`
2. Generate a secret key
3. Start the server: `python3 server.py -lh <IP> -p 4444`
4. Generate and deploy an agent
5. Interact with sessions using the console

For full installation and quick-start instructions, see the [main README](https://github.com/Josefifir/Megaploit).

---

*Made with ❤️ for the security research community.*
