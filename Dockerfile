# NetworkSentinel Multi-Stage / Production Dockerfile
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies for Scapy raw socket packet capture and BPF compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    libcap2-bin \
    net-tools \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install pinned Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Set capabilities so Python can bind to raw network sockets without running as root
RUN setcap cap_net_raw,cap_net_admin=eip $(which python3) || true

EXPOSE 8000

# Start Uvicorn ASGI server with production concurrency
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
