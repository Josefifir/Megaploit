# Docker — Megaploit Operator Console

Run the Megaploit C2 **server / operator console** in a container, with all
operator state (secret key, loot, toolbox, settings) persisted across restarts.

> **For authorised security research and penetration testing only.**

---

## Requirements

- Docker 20.10+ (or Docker Desktop 4.x+)
- `docker compose` v2 (`docker compose` — note: no hyphen)

---

## Quick start

```bash
# 1. Clone the repository
git clone https://github.com/Josefifir/Megaploit.git
cd Megaploit

# 2. Build the image (lean, no Go toolchain)
docker build -t megaploit .

# 3. Run the interactive console
docker run -it --rm \
    -p 4444:4444 -p 8080:8080 -p 7777:7777 \
    -v megaploit-data:/data \
    -e LHOST=192.168.1.10 \
    megaploit
```

You see the Megaploit banner and `megaploit >` prompt.

The C2 listener binds to `0.0.0.0:4444` inside the container and is published on the
host. The first run auto-generates `secret.key` into the `megaploit-data` volume
(`/data/secret.key`) — nothing sensitive is printed to stdout.

---

## Configuration — environment variables

| Variable   | Default                     | Meaning                                                |
|------------|-----------------------------|--------------------------------------------------------|
| `LHOST`    | container's first IP        | **Required.** Callback IP the agent dials back to.     |
| `PORT`     | `4444`                      | C2 listener port                                       |
| `RHOST`    | `0.0.0.0`                   | Listener bind address                                  |
| `TLS_CERT` | `/data/cert.pem` if present | TLS certificate PEM path (enables TLS)                 |
| `TLS_KEY`  | `/data/key.pem` if present  | TLS private key PEM path                               |
| `USE_TLS`  | `0`                         | Set `1` to auto-generate a self-signed cert at startup |

**`LHOST` is the one value you must set** — it must be the IP or hostname the target
agent can reach (your LAN/VPN IP), not the container's internal address.

---

## What persists (`/data` volume)

A single named volume (`megaploit-data`) holds all mutable operator state:

```
/data
├── secret.key               HMAC shared secret (auto-generated on first run)
├── cert.pem, key.pem        drop your own here to enable TLS automatically
├── loot/                    audit.log, screenshots/, recordings/, downloads/, tls/
├── tools/                   toolbox git clones + tools.json catalogue
└── .megaploit*.json         operator settings, command history, autorun config
```

The entrypoint symlinks `loot/` and `tools/` into `/data`, places `secret.key`
there, and points `$HOME` at `/data` so `~/.megaploit*.json` files written by the
console survive container recreation.

**Generated payloads are ephemeral by default** (they land in the app directory
inside the container). To keep them:

```
megaploit > payload ps1 --out /data/agent.ps1
megaploit > stage0 generate --out /data/dropper.py
```

---

## Ports

| Port  | Service              | Notes                                                         |
|-------|----------------------|---------------------------------------------------------------|
| 4444  | C2 listener          | Agent callback. Override with `PORT` env var.                 |
| 8080  | Web dashboard        | Start from the console: `web start --host 0.0.0.0`            |
| 7777  | Multi-operator RPC   | Start from the console: `rpc start --host 0.0.0.0`            |

The web dashboard and RPC server bind to `127.0.0.1` by default; you **must** pass
`--host 0.0.0.0` when starting them if you want to reach them through published host ports.

---

## TLS

### Option A — auto-generate a self-signed cert at startup

```bash
docker run -it --rm \
    -p 4444:4444 \
    -v megaploit-data:/data \
    -e LHOST=192.168.1.10 \
    -e USE_TLS=1 \
    megaploit
```

The entrypoint passes `--tls` to `server.py`, which generates a cert and writes it to
`/data/loot/tls/` (persisted in the volume).

### Option B — bring your own cert

Copy `cert.pem` and `key.pem` into the named volume (or use a bind mount), then run
with `USE_TLS=1`. The entrypoint detects the files automatically:

```bash
# Copy certs into the volume (one-time)
docker run --rm -v megaploit-data:/data -v $(pwd):/src alpine \
    sh -c "cp /src/cert.pem /src/key.pem /data/"

# Start with TLS
docker run -it --rm \
    -p 4444:4444 \
    -v megaploit-data:/data \
    -e LHOST=192.168.1.10 \
    -e USE_TLS=1 \
    megaploit
```

---

## Docker Compose

The recommended way for persistent setups — handles ports, volume, and env vars.

```bash
# Interactive console (recommended for the REPL)
LHOST=192.168.1.10 docker compose run --rm --service-ports megaploit

# Background listener only (no TTY)
LHOST=192.168.1.10 docker compose up -d

# Attach to a running background container
docker attach megaploit

# Stop
docker compose down
```

Edit `docker-compose.yml` to permanently set `LHOST`, toggle TLS, or enable the Go
toolchain build arg.

---

## Optional: Go toolchain (`payload go_exe` / `payload go_elf`)

Go is **not** included by default (it adds ~700 MB). Build a "full" image:

```bash
# Build with Go
docker build --build-arg INSTALL_GO=1 -t megaploit:full .

# Or uncomment the args block in docker-compose.yml:
#   args:
#     INSTALL_GO: "1"
docker compose build
```

---

## One-off tasks

The entrypoint passes any arguments verbatim when provided:

```bash
# Run the test suite
docker run --rm -v megaploit-data:/data megaploit pytest tests/ -q

# Open a shell
docker run -it --rm -v megaploit-data:/data megaploit bash

# Run server.py with explicit flags (bypasses env-var assembly)
docker run -it --rm -p 4444:4444 -v megaploit-data:/data \
    megaploit python3 server.py -lh 10.0.0.1 -p 4444 --allow-ip 10.0.0.5

# Back up the entire /data volume to a tarball
docker run --rm \
    -v megaploit-data:/data \
    -v $(pwd):/backup \
    alpine tar czf /backup/megaploit-data-$(date +%Y%m%d).tar.gz /data
```

---

## Cross-platform builds (`buildx`)

```bash
# linux/amd64 (explicit)
docker buildx build --platform linux/amd64 -t megaploit:amd64 .

# linux/arm64 (Raspberry Pi / AWS Graviton)
docker buildx build --platform linux/arm64 -t megaploit:arm64 .
```

---

## Security notes

- The container runs as a **non-root** `megaploit` user. Volume ownership is fixed
  by the root entrypoint stage before privileges are dropped via `gosu`.
- `secret.key`, `*.pem`, and `*.key` are excluded from the build context by
  `.dockerignore` — they only ever live in the runtime volume.
- The default healthcheck probes the C2 listener on `127.0.0.1:<PORT>`.
- Web dashboard and RPC bind to `127.0.0.1` by default — they are not exposed
  unless you explicitly pass `--host 0.0.0.0` from the console.
- **This is an offensive-security tool. Only run it against systems you are
  authorised to test.**
