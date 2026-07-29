# syntax=docker/dockerfile:1
#
# ===========================================================================
#  Megaploit — Dockerized operator console (C2 server)
#  For authorised security research / penetration testing only.
# ===========================================================================
#
#  Build (lean, no Go toolchain):
#      docker build -t megaploit .
#
#  Build with Go toolchain (enables `payload go_exe` / `payload go_elf`,
#  adds ~700 MB):
#      docker build --build-arg INSTALL_GO=1 -t megaploit:full .
#
#  Run (interactive console):
#      docker run -it --rm \
#          -p 4444:4444 -p 8080:8080 -p 7777:7777 \
#          -v megaploit-data:/data \
#          -e LHOST=192.168.1.10 -e PORT=4444 \
#          megaploit
#
#

ARG PYTHON_VERSION=3.11
FROM python:${PYTHON_VERSION}-slim

LABEL org.opencontainers.image.title="Megaploit" \
      org.opencontainers.image.description="Professional C2 framework & security research toolbox" \
      org.opencontainers.image.version="3.0.0" \
      org.opencontainers.image.source="https://github.com/Josefifir/Megaploit" \
      org.opencontainers.image.licenses="MIT"

# --- Optional: install the Go toolchain (off by default to keep the image lean)
ARG INSTALL_GO=0

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MEGAPLOIT_HOME=/opt/megaploit \
    MEGAPLOIT_DATA=/data

# ---------------------------------------------------------------------------
# System dependencies
#   git                 toolbox clone/update + self-update checks
#   libgl1, libglib2.0-0   opencv-python runtime libs
#   libffi-dev, libssl-dev, build-essential   build wheels (cryptography, etc.)
#   curl, ca-certificates   healthcheck / convenience
#   gosu                privilege drop to the non-root operator user
#   golang-go           only when INSTALL_GO=1
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl \
        libgl1 libglib2.0-0 \
        libffi-dev libssl-dev \
        build-essential \
        bash gosu \
        $([ "$INSTALL_GO" = "1" ] && echo golang-go || true) \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Non-root operator user + application / data directories
# ---------------------------------------------------------------------------
RUN groupadd -r megaploit \
 && useradd -r -m -g megaploit -d /home/megaploit -s /bin/bash megaploit \
 && mkdir -p ${MEGAPLOIT_HOME} ${MEGAPLOIT_DATA} \
 && chown -R megaploit:megaploit ${MEGAPLOIT_HOME} ${MEGAPLOIT_DATA}

WORKDIR ${MEGAPLOIT_HOME}

# ---------------------------------------------------------------------------
# Python dependencies (cached layer — rebuilds only when requirements change)
# ---------------------------------------------------------------------------
COPY requirements.txt ./
RUN pip install --upgrade pip \
 && pip install -r requirements.txt \
 && pip install pyyaml dnspython impacket pytest pytest-cov

# ---------------------------------------------------------------------------
# Application code
# ---------------------------------------------------------------------------
COPY --chown=megaploit:megaploit . .

# Remove the committed loot stubs so the entrypoint can symlink loot/ into the
# persistent /data volume. tools/ is created at runtime by the toolbox.
RUN rm -rf loot agent_compiled \
 && mkdir -p loot

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# All operator state persists in /data: secret.key, loot/, tools/ and the
# ~/.megaploit*.json settings (HOME points here so expanduser('~') lands in the volume).
ENV HOME=${MEGAPLOIT_DATA}

VOLUME ["/data"]

#   4444  C2 listener (agent callback)        — configurable via PORT
#   8080  web dashboard  (start: `web start --host 0.0.0.0`)
#   7777  multi-operator RPC (start: `rpc start --host 0.0.0.0`)
EXPOSE 4444 8080 7777

# Light TCP probe of the C2 listener. bash /dev/tcp reaches 127.0.0.1:<PORT>
# because the listener binds 0.0.0.0.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD /bin/bash -c '</dev/tcp/127.0.0.1/${PORT:-4444}' || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
# Default command is assembled by the entrypoint from LHOST / PORT / TLS_* env.
# Override to run anything else, e.g. `pytest`, `bash`, or
# `python3 server.py -lh 1.2.3.4 -p 4444 --allow-ip 10.0.0.5`.
# !!//may need to be reviewed//!!
CMD []
