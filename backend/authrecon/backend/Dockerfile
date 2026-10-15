# syntax=docker/dockerfile:1.6

# Extra CA certificates for networks that inspect TLS (see certs/README.md).
# docker-compose.yml passes the repo's certs/ directory as the `certs` build
# context; this empty stage is the default for a plain `docker build`.
FROM scratch AS certs

FROM python:3.11-slim AS base

# Trust any certificates in certs/ (none by default, then nothing changes).
# Multi-certificate PEM files are split, because update-ca-certificates
# expects one certificate per file.
RUN --mount=type=bind,from=certs,target=/tmp/extra-certs \
    set -e; found=0; \
    for f in /tmp/extra-certs/*.crt /tmp/extra-certs/*.pem; do \
        [ -f "$f" ] || continue; \
        name="$(basename "$f")"; \
        grep -q "BEGIN CERTIFICATE" "$f" || { echo "certs/$name is not a PEM certificate (see certs/README.md)" >&2; exit 1; }; \
        safe="$(printf '%s' "${name%.*}" | tr -c 'A-Za-z0-9._-' '_')"; \
        tr -d '\r' < "$f" | awk -v p="/usr/local/share/ca-certificates/extra-$safe" \
            '/BEGIN CERTIFICATE/ {n++; out = p "-" n ".crt"} out {print > out} /END CERTIFICATE/ {close(out); out = ""}'; \
        found=1; \
    done; \
    if [ "$found" = 1 ]; then update-ca-certificates; fi
# Point Python, pip and Node at the system bundle, which now includes them.
ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    chromium \
    chromium-driver \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcairo2 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnss3 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libxss1 \
    libxtst6 \
    xvfb \
    x11vnc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Optional private package index (docker-compose.mirror.yml). A BuildKit
# secret, so the URL and its credentials never reach an image layer.
RUN --mount=type=secret,id=pip_index_url \
    if [ -s /run/secrets/pip_index_url ]; then \
        PIP_INDEX_URL="$(cat /run/secrets/pip_index_url)"; export PIP_INDEX_URL; \
    fi; \
    pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (Chromium for HAR capture + modern SPA support)
# This downloads ~300MB of browser binaries but enables:
# - Real HAR file generation (network.har artifacts)
# - Modern SPA/React/Vue authentication flows
# - API endpoint discovery via Chrome DevTools Protocol
# Note: --with-deps fails on Debian Trixie due to font package names
# Install dependencies manually, then browser
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-unifont \
    fonts-ubuntu-title \
    && rm -rf /var/lib/apt/lists/* \
    && playwright install chromium

COPY app ./app
COPY alembic.ini .
COPY alembic ./alembic
COPY docker-entrypoint.sh ./docker-entrypoint.sh

# Download and install noVNC for browser-based VNC viewing
RUN curl -fsSL https://github.com/novnc/noVNC/archive/refs/tags/v1.4.0.tar.gz -o /tmp/novnc.tar.gz \
    && echo "89b0354c94ad0b0c88092ec7a08e28086d3ed572f13660bac28d5470faaae9c1  /tmp/novnc.tar.gz" | sha256sum -c \
    && tar -xzf /tmp/novnc.tar.gz -C /opt \
    && mv /opt/noVNC-1.4.0 /opt/novnc \
    && rm /tmp/novnc.tar.gz

RUN chmod +x ./docker-entrypoint.sh

# Create non-root runtime user. Chrome's sandbox requires non-root — this is the O5 fix.
# uid=1000 matches the host developer uid so bind-mounted app code is accessible.
RUN useradd --create-home --uid 1000 --shell /bin/bash authrecon \
    && mkdir -p /app/data/artifacts \
    && chown -R authrecon:authrecon /opt/playwright-browsers /app

USER authrecon

EXPOSE 8000

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
