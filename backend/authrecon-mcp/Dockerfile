FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin mcp \
    && chown -R mcp:mcp /app
USER mcp

ENV MCP_HOST=0.0.0.0 \
    MCP_PORT=8765

EXPOSE 8765

CMD ["python", "app.py"]
