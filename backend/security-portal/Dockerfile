# Extra CA certificates for networks that inspect TLS (see certs/README.md).
# docker-compose.yml passes the repo's certs/ directory as the `certs` build
# context; this empty stage is the default for a plain `docker build`.
FROM scratch AS certs

FROM python:3.12-slim

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
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    iputils-ping \
    traceroute \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
# Optional private package index (docker-compose.mirror.yml). A BuildKit
# secret, so the URL and its credentials never reach an image layer.
RUN --mount=type=secret,id=pip_index_url \
    if [ -s /run/secrets/pip_index_url ]; then \
        PIP_INDEX_URL="$(cat /run/secrets/pip_index_url)"; export PIP_INDEX_URL; \
    fi; \
    pip install --no-cache-dir -r /tmp/requirements.txt

RUN groupadd --system portal && useradd --system --gid portal --home-dir /app --shell /usr/sbin/nologin portal

COPY . /app
RUN mkdir -p /app/data /app/logs && chown -R portal:portal /app/data /app/logs

EXPOSE 9000

# Entrypoint fixes volume ownership, then drops to the portal user.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9000", "--ws", "wsproto"]
