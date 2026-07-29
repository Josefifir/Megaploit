# Docker — Megaploit operator console

Run the Megaploit C2 **server / operator console** in a container, with all
operator state (secret key, loot, toolbox, settings) persisted across restarts.

> For authorised security research and penetration testing only.

---

## Quick start

```bash
# 1. Build the image
docker build -t megaploit .

# 2. Run the interactive console
docker run -it --rm \
    -p 4444:4444 -p 8080:8080 -p 7777:7777 \
    -v megaploit-data:/data \
    -e LHOST=192.168.1.10 -e PORT=4444 \
    megaploit
```

You should see the Megaploit banner and the `megaploit >` prompt. The C2
listener is bound to `0.0.0.0:4444` inside the container and published on the
host.

The first run auto-generates `secret.key` into the `megaploit-data` volume
(`/data/secret.key`) and prints nothing sensitive to stdout.

---

## Configuration via environment

| Variable   | Default                                   | Meaning                                             |
|------------|-------------------------------------------|----------------------------------------------------|
| `LHOST`    | container's first IP                      | Callback IP the agent dials back to (set this!)    |
| `PORT`     | `4444`                                    | C2 listener port                                   |
| `RHOST`    | `0.0.0.0`                                 | Listener bind address                              |
| `TLS_CERT` | `/data/cert.pem` if present               | TLS certificate PEM (enables TLS)                  |
| `TLS_KEY`  | `/data/key.pem` if present                | TLS private key PEM                                |
| `USE_TLS`  | `0`                                       | Set `1` to expect TLS (warns if cert/key missing)  |

**`LHOST` is the one value you really must set** — it must be an IP the agent
(target) can reach (typically your host/LAN IP), not a container-internal IP.

---

## What persists (`/data` volume)

A single named volume holds all mutable operator state:

```
/data
├── secret.key              ← HMAC shared secret (auto-generated on first run)
├── cert.pem, key.pem       ← drop your own here to enable TLS
├── loot/                   ← audit.log, screenshots/, recordings/, downloads/
├── tools/                  ← toolbox git clones + tools.json
└── .megaploit*.json        ← operator settings, command history, autorun config
```

This works because the entrypoint symlinks `loot/` and `tools/` into `/data`,
sets `secret.key` there, and points `$HOME` at `/data` so the `~/.megaploit*`
files written by the console survive container recreation.

**Generated payloads / agents are ephemeral by default** (they land in the app
directory). To keep them, write into the volume, e.g.:

```
megaploit > payload ps1 --out /data/agent.ps1
megaploit > stage0 generate --out /data/dropper.py
```

---

## Ports

| Port  | Service              | Notes                                                    |
|-------|----------------------|----------------------------------------------------------|
| 4444  | C2 listener          | Agent callback. Override with `PORT`.                    |
| 8080  | Web dashboard        | Start from the console: `web start --host 0.0.0.0`       |
| 7777  | Multi-operator RPC   | Start from the console: `rpc start --host 0.0.0.0`       |

The web dashboard and RPC server bind to `127.0.0.1` by default, so to reach
them through the published host ports you **MUST** pass `--host 0.0.0.0` when
starting them inside the console.

---

## TLS

Drop your certificate and key into the volume and (re)run:

```bash
docker run -it --rm -p 4444:4444 -v megaploit-data:/data \
    -e LHOST=192.168.1.10 -e USE_TLS=1 megaploit
```

With `cert.pem` + `key.pem` present in `/data`, the entrypoint automatically
adds `--cert` / `--key` to the server invocation.

---

## Docker Compose

```bash
# interactive console (recommended entrypoint for the REPL)
LHOST=192.168.1.10 docker compose run --rm --service-ports megaploit

# or just build
docker compose build
```

`docker-compose.yml` wires up the same ports, volume, and env vars. Edit the
file to toggle the Go toolchain build arg or TLS.

---

## Optional: Go toolchain

`payload go_exe` / `payload go_elf` cross-compile the Go agent. Go is **not**
included by default (it adds ~700 MB). Build a "full" image:

```bash
docker build --build-arg INSTALL_GO=1 -t megaploit:full .
# or uncomment INSTALL_GO in docker-compose.yml
```

---

## One-off tasks

Because the entrypoint passes through any command you give it:

```bash
docker run --rm megaploit pytest                 # run the test suite
docker run --rm megaploit bash                   # shell into the image
docker run --rm megaploit python3 server.py -lh 10.0.0.1 -p 4444 --allow-ip 10.0.0.5
```

---

## Security notes

- The container runs as a **non-root** user (`megaploit`). Volume ownership is
  fixed up by the root entrypoint before privileges are dropped via `gosu`.
- `secret.key`, `*.pem`, and `*.key` are excluded from the image by
  `.dockerignore` — they only ever live in the runtime volume.
- The default healthcheck probes the C2 listener on `127.0.0.1:<PORT>`.
- This is an offensive-security tool. Only run it against systems you are
  authorised to test.
