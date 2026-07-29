# ─── Megaploit — Docker image ────────────────────────────────────────────────
#
# Build:
#   docker build -t megaploit .
#
# Run (quick):
#   docker run -it --rm -p 4444:4444 megaploit -lh <YOUR_IP> -p 4444
#
# Run (persistent loot + secret):
#   docker run -it --rm \
#     -p 4444:4444 \
#     -v "$(pwd)/loot:/app/loot" \
#     -v "$(pwd)/secret.key:/app/secret.key:ro" \
#     megaploit -lh <YOUR_IP> -p 4444
#
# See docker-compose.yml for a fully-configured stack.
# ──────────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim AS base

# Build-time deps for packages that compile C extensions (numpy, opencv, etc.)
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        git \
        gcc \
        libgl1 \
        libglib2.0-0 \
        libffi-dev \
        libssl-dev \
        curl \
        upx-ucl \
    && rm -rf /var/lib/apt/lists/*

# ── pip layer — install deps before copying source so this layer is cached ───
WORKDIR /app
COPY requirements.txt .

# Core + all optional extras in one pass so the layer is reusable
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        -r requirements.txt \
        cryptography \
        flask \
        impacket \
        paramiko \
        dnspython \
        pyinstaller \
        pyyaml

# ── Source ────────────────────────────────────────────────────────────────────
COPY . .

# Ensure loot directories exist (volumes may not have them)
RUN mkdir -p loot/tls loot/screenshots loot/recordings loot/downloads loot/reports

# Generate a secret key if none is baked in (CI / quick-start convenience).
# The key is re-generated every image build; mount your own via -v for
# persistent engagements so the agent and server share the same key.
RUN if [ ! -f secret.key ]; then \
        python3 -c \
          "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"; \
        echo "[docker] Generated a fresh secret.key — mount your own for production use."; \
    fi

# ── Runtime ───────────────────────────────────────────────────────────────────
# Expose the default C2 listener port. Pass a different -p flag at runtime
# or override the EXPOSE port with docker-compose.
EXPOSE 4444

# Drop to a non-root user for a slightly narrower attack surface.
# The operator must explicitly --user root if they need privileged ops.
RUN useradd -m -s /bin/bash megaploit && \
    chown -R megaploit:megaploit /app
USER megaploit

# Entrypoint: server.py — all docker run args are forwarded verbatim.
# Example:  docker run -it megaploit -lh 10.0.0.1 -p 4444 --tls
ENTRYPOINT ["python3", "server.py"]

# Sensible defaults — override at runtime with your real LHOST.
CMD ["-lh", "0.0.0.0", "-p", "4444"]
