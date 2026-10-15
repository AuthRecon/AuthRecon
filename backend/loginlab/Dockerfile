FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Run unprivileged (this service is intentionally vulnerable)
RUN useradd --system --no-create-home --shell /usr/sbin/nologin loginlab
USER loginlab

# Expose port (5500 to avoid Tenable agent conflict on 5000/5001)
EXPOSE 5500

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5500"]
