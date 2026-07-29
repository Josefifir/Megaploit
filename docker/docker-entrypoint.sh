#!/usr/bin/env bash
# =============================================================================
#  Megaploit — container entrypoint
#
#  Runs as root first to fix volume ownership, then re-execs itself as the
#  non-root `megaploit` user via gosu. Responsibilities:
#
#    1. Ensure /data is owned by the runtime user
#    2. Generate secret.key on first run (256-bit HMAC key)
#    3. Symlink mutable paths (loot/, tools/, secret.key) into /data so all
#       operator state persists across container restarts
#    4. Auto-detect TLS material in /data
#    5. Exec server.py, driven by LHOST / PORT / TLS_* env vars
#
#  Override by passing any command after the image name:
#    docker run --rm megaploit pytest          # run tests
#    docker run -it megaploit bash             # shell
#    docker run -it megaploit python3 server.py -lh 1.2.3.4 -p 4444 --allow-ip 10.0.0.5
# =============================================================================
set -euo pipefail

APP_DIR="${MEGAPLOIT_HOME:-/opt/megaploit}"
DATA_DIR="${MEGAPLOIT_DATA:-/data}"
RUN_USER="${MEGAPLOIT_USER:-megaploit}"

log()  { printf '[megaploit] %s\n' "$*"; }
warn() { printf '[megaploit] WARN: %s\n' "$*" >&2; }
err()  { printf '[megaploit] ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Phase 1 (root): fix /data ownership, then drop privileges via gosu
# ---------------------------------------------------------------------------
if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR"
    chown -R "$RUN_USER":"$RUN_USER" "$DATA_DIR"
    exec gosu "$RUN_USER" "$0" "$@"
fi

cd "$APP_DIR"

# ---------------------------------------------------------------------------
# Phase 2 (megaploit user): wire up persistent /data volume
# ---------------------------------------------------------------------------

# loot/ -> /data/loot  (audit log, screenshots, recordings, downloads, reports)
mkdir -p \
    "$DATA_DIR/loot/tls" \
    "$DATA_DIR/loot/screenshots" \
    "$DATA_DIR/loot/recordings" \
    "$DATA_DIR/loot/downloads" \
    "$DATA_DIR/loot/reports"
if [ -d loot ] && [ ! -L loot ]; then
    # Copy any pre-existing loot stubs then replace with symlink
    cp -rn loot/. "$DATA_DIR/loot/" 2>/dev/null || true
    rm -rf loot
fi
[ ! -L loot ] && ln -s "$DATA_DIR/loot" loot

# tools/ -> /data/tools  (toolbox git clones + tools.json catalogue)
mkdir -p "$DATA_DIR/tools"
if [ -d tools ] && [ ! -L tools ]; then
    # Preserve the bundled tools.json catalogue
    [ -f tools/tools.json ] && cp tools/tools.json "$DATA_DIR/tools/tools.json" 2>/dev/null || true
    rm -rf tools
fi
[ ! -L tools ] && ln -s "$DATA_DIR/tools" tools

# secret.key -> /data/secret.key  (generate 256-bit HMAC key on first run)
if [ ! -f "$DATA_DIR/secret.key" ]; then
    python3 -c \
      "import os,binascii; open('$DATA_DIR/secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
    log "Generated new secret.key at $DATA_DIR/secret.key"
fi
# Symlink app-dir secret.key into the volume
if [ ! -e secret.key ] || [ -L secret.key ]; then
    ln -sf "$DATA_DIR/secret.key" secret.key
fi

# ---------------------------------------------------------------------------
# Phase 3: resolve runtime configuration from environment
# ---------------------------------------------------------------------------
# LHOST — callback IP the agent dials back to. Default: first non-loopback IP.
LHOST="${LHOST:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
PORT="${PORT:-4444}"
RHOST="${RHOST:-0.0.0.0}"

# TLS — look for cert + key in /data (or explicit TLS_CERT / TLS_KEY paths)
CERT="${TLS_CERT:-}"
KEYF="${TLS_KEY:-}"
[ -z "$CERT" ] && [ -f "$DATA_DIR/cert.pem" ] && CERT="$DATA_DIR/cert.pem"
[ -z "$KEYF" ] && [ -f "$DATA_DIR/key.pem"  ] && KEYF="$DATA_DIR/key.pem"

log "Megaploit operator console starting"
log "  callback IP  (LHOST) : ${LHOST:-<not set — set LHOST env var>}"
log "  C2 port      (PORT)  : ${PORT}"
log "  bind IP      (RHOST) : ${RHOST}"
log "  data volume          : ${DATA_DIR}"

# ---------------------------------------------------------------------------
# Phase 4: if the caller passed explicit arguments, run them verbatim
# ---------------------------------------------------------------------------
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

# ---------------------------------------------------------------------------
# Phase 5: build server.py argument list and exec
# ---------------------------------------------------------------------------
args=(-lh "$LHOST" -p "$PORT" -rh "$RHOST" --secret secret.key)

if [ -n "$CERT" ] && [ -n "$KEYF" ]; then
    args+=(--cert "$CERT" --key "$KEYF")
    log "  TLS                  : enabled  (cert: $CERT)"
elif [ "${USE_TLS:-0}" = "1" ]; then
    # USE_TLS=1 but no cert/key found — fall back to auto-TLS
    args+=(--tls)
    log "  TLS                  : auto-generate (USE_TLS=1, no cert/key in /data)"
else
    log "  TLS                  : disabled  (set USE_TLS=1 or drop cert.pem+key.pem in /data)"
fi

exec python3 server.py "${args[@]}"
