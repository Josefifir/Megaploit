#!/usr/bin/env bash
# ===========================================================================
#  Megaploit — container entrypoint
#
#  Runs as root first to fix volume ownership, then re-execs itself as the
#  non-root `megaploit` user. Responsibilities:
#    1. ensure /data is owned by the runtime user
#    2. generate secret.key on first run
#    3. symlink mutable paths (secret.key, loot/, tools/) into /data
#    4. exec server.py, driven by LHOST / PORT / TLS_* env
# ===========================================================================
set -euo pipefail

APP_DIR="${MEGAPLOIT_HOME:-/opt/megaploit}"
DATA_DIR="${MEGAPLOIT_DATA:-/data}"
RUN_USER="${MEGAPLOIT_USER:-megaploit}"

# Review /data mountpoint

log()  { printf '[entrypoint] %s\n' "$*"; }
warn() { printf '[entrypoint] WARN: %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Phase 1 (root): fix ownership, then drop privileges
# ---------------------------------------------------------------------------
if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR"
    chown -R "$RUN_USER":"$RUN_USER" "$DATA_DIR"
    exec gosu "$RUN_USER" "$0" "$@"
fi

cd "$APP_DIR"

# ---------------------------------------------------------------------------
# Phase 2 (megaploit user): wire up persistent volume
# ---------------------------------------------------------------------------

# loot/  ->  /data/loot  (audit log, screenshots, recordings, downloads)
mkdir -p "$DATA_DIR/loot/screenshots" "$DATA_DIR/loot/recordings" "$DATA_DIR/loot/downloads"
if [ ! -L loot ]; then rm -rf loot; ln -s "$DATA_DIR/loot" loot; fi

# tools/ ->  /data/tools  (toolbox git clones + tools.json)
mkdir -p "$DATA_DIR/tools"
if [ ! -L tools ]; then rm -rf tools 2>/dev/null || true; ln -s "$DATA_DIR/tools" tools; fi

# secret.key -> /data/secret.key  (generate a fresh 256-bit HMAC key on first run)
if [ ! -f "$DATA_DIR/secret.key" ]; then
    python3 -c "import os,binascii; open('$DATA_DIR/secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
    log "generated new secret.key at $DATA_DIR/secret.key"
fi
if [ ! -L secret.key ] && [ ! -e secret.key ]; then
    ln -s "$DATA_DIR/secret.key" secret.key
elif [ ! -e secret.key ]; then
    ln -sf "$DATA_DIR/secret.key" secret.key
fi

# ---------------------------------------------------------------------------
# Phase 3: assemble server.py invocation from environment
# ---------------------------------------------------------------------------
LHOST="${LHOST:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
PORT="${PORT:-4444}"
RHOST="${RHOST:-0.0.0.0}"

log "Megaploit operator console starting"
log "  callback IP (LHOST) : ${LHOST:-<unset>}"
log "  C2 port   (PORT)    : ${PORT}"
log "  bind IP   (RHOST)   : ${RHOST}"
log "  data volume         : ${DATA_DIR}"

# TLS: mount /data/cert.pem + /data/key.pem, or set TLS_CERT / TLS_KEY
CERT="${TLS_CERT:-}"
KEYF="${TLS_KEY:-}"
[ -z "$CERT" ] && [ -f "$DATA_DIR/cert.pem" ] && CERT="$DATA_DIR/cert.pem"
[ -z "$KEYF" ] && [ -f "$DATA_DIR/key.pem" ]  && KEYF="$DATA_DIR/key.pem"

args=(-lh "$LHOST" -p "$PORT" -rh "$RHOST" --secret secret.key)
if [ -n "$CERT" ] && [ -n "$KEYF" ]; then
    args+=(--cert "$CERT" --key "$KEYF")
    log "  TLS                 : enabled ($CERT)"
elif [ "${USE_TLS:-0}" = "1" ]; then
    warn "USE_TLS=1 but no cert/key found in /data — starting plaintext listener."
fi

# ---------------------------------------------------------------------------
# Phase 4: exec
#    - no extra args  -> env-driven console launch
#    - args given     -> run them verbatim (pytest, bash, or a full
#                        `python3 server.py ...` invocation)
# ---------------------------------------------------------------------------
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

exec python3 server.py "${args[@]}"
