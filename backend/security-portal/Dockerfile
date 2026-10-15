FROM python:3.12-slim

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
RUN pip install --no-cache-dir -r /tmp/requirements.txt

RUN groupadd --system portal && useradd --system --gid portal --home-dir /app --shell /usr/sbin/nologin portal

COPY . /app
RUN mkdir -p /app/data /app/logs && chown -R portal:portal /app/data /app/logs

EXPOSE 9000

# Entrypoint fixes volume ownership, then drops to the portal user.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9000", "--ws", "wsproto"]
