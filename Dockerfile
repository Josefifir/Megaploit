# syntax=docker/dockerfile:1
# =============================================================================
#  Megaploit — Dockerized operator console (C2 server)
#
#  For authorised security research / penetration testing only.
#
#  Build (lean, no Go toolchain):
#      docker build -t megaploit .
#
#  Build with Go toolchain (enables `payload go_exe` / `payload go_elf`,
#  adds ~700 MB to the image):
#      docker build --build-arg INSTALL_GO=1 -t megaploit:full .
#
#  Run (interactive console):
#      docker run -it --rm \
#          -p 4444:4444 \
#          -v megaploit-data:/data \
#          -e LHOST=192.168.1.10 \
#          megaploit
#
#  See docker-compose.yml and docs/DOCKER.md for full usage.
# =============================================================================

ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim

LABEL org.opencontainers.image.title="Megaploit" \
      org.opencontainers.image.description="Professional C2 framework & security research toolbox" \
      org.opencontainers.image.source="https://github.com/Josefifir/Megaploit" \
      org.opencontainers.image.licenses="GPL-3.0"

# ---------------------------------------------------------------------------
# Optional: install the Go toolchain for `payload go_exe` / `payload go_elf`
# Off by default — adds ~700 MB.  Enable with: --build-arg INSTALL_GO=1
# ---------------------------------------------------------------------------
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
#   git                     toolbox clone/update + self-update checks
#   libgl1, libglib2.0-0    opencv-python runtime libs
#   libffi-dev, libssl-dev  build cryptography / cffi wheels
#   build-essential         compile C extensions
#   upx-ucl                 `payload --upx` binary packing
#   gosu                    clean privilege drop in entrypoint
#   golang-go               only installed when INSTALL_GO=1
# ---------------------------------------------------------------------------
RUN set -eux; \
    apt-get update -qq; \
    apt-get install -y --no-install-recommends \
        git ca-certificates curl bash \
        libgl1 libglib2.0-0 \
        libffi-dev libssl-dev \
        build-essential \
        upx-ucl \
        gosu; \
    if [ "$INSTALL_GO" = "1" ]; then \
        apt-get install -y --no-install-recommends golang-go; \
    fi; \
    rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Non-root operator user + application / data directories
# ---------------------------------------------------------------------------
RUN groupadd -r megaploit \
 && useradd -r -m -g megaploit -d /home/megaploit -s /bin/bash megaploit \
 && mkdir -p ${MEGAPLOIT_HOME} ${MEGAPLOIT_DATA} \
 && chown -R megaploit:megaploit ${MEGAPLOIT_HOME} ${MEGAPLOIT_DATA}

WORKDIR ${MEGAPLOIT_HOME}

# ---------------------------------------------------------------------------
# Python dependencies — cached layer (only rebuilds when requirements.txt changes)
# ---------------------------------------------------------------------------
COPY requirements.txt ./
RUN pip install --upgrade pip \
 && pip install \
        -r requirements.txt \
        cryptography \
        flask \
        impacket \
        paramiko \
        dnspython \
        pyinstaller \
        pyyaml \
        pytest \
        pytest-cov

# ---------------------------------------------------------------------------
# Application code
# ---------------------------------------------------------------------------
COPY --chown=megaploit:megaploit . .

# Remove any committed loot stubs — the entrypoint will symlink loot/ into
# the persistent /data volume at runtime so data survives container recreation.
RUN rm -rf loot agent_compiled \
 && mkdir -p loot

# ---------------------------------------------------------------------------
# Entrypoint script
# ---------------------------------------------------------------------------
COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# All operator state persists in /data: secret.key, loot/, tools/ and
# ~/.megaploit*.json (HOME points here so expanduser('~') resolves to the volume).
ENV HOME=${MEGAPLOIT_DATA}

VOLUME ["/data"]

# ---------------------------------------------------------------------------
# Ports
#   4444  C2 listener (agent callback)             — configurable via PORT
#   8080  Web dashboard  (web start --host 0.0.0.0)
#   7777  Multi-operator RPC (rpc start --host 0.0.0.0)
# ---------------------------------------------------------------------------
EXPOSE 4444 8080 7777

# TCP probe of the C2 listener — lightweight and dependency-free.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python3 -c \
    "import socket,os,sys; \
     s=socket.socket(); s.settimeout(2); \
     s.connect(('127.0.0.1', int(os.getenv('PORT','4444')))); s.close()" \
  || exit 1

# Entrypoint handles privilege drop, volume wiring, TLS detection, and
# assembles the server.py command line from environment variables.
# Pass any command after the image name to override (e.g. pytest, bash).
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD []
