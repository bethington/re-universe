# Monitoring Dashboard Service - Multi-stage Docker build
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# The static/ directory is empty and untracked: git cannot commit an empty
# directory, so a fresh clone never contains it. But main.py mounts it with
# StaticFiles(directory="static"), which raises RuntimeError at import time if
# it is missing. Create it so the image builds and starts from any clean
# checkout.
RUN mkdir -p static

# Expose port
EXPOSE 8096

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8096/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8096"]