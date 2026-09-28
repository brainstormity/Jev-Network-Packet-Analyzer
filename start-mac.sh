#!/usr/bin/env bash
# ==============================================================================
# NetworkSentinel - Native macOS Live Packet Sniffer Launcher
# ==============================================================================
# Binds directly to macOS Darwin /dev/bpf* devices on your physical Wi-Fi (en0)
# to capture real live network traffic with zero Docker VM isolation.
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=========================================================="
echo "🛡️  NetworkSentinel: Starting Native macOS Live Sniffer"
echo "=========================================================="

# 1. Check or start Redis service
echo "Checking Redis status..."
if nc -z localhost 6379 2>/dev/null; then
    echo "✅ Redis is running locally on port 6379."
else
    echo "Starting Redis via Docker..."
    if command -v docker >/dev/null 2>&1; then
        export PATH="/Applications/Docker.app/Contents/Resources/bin:$HOME/.docker/bin:$PATH"
        docker compose up -d redis
        echo "Waiting for Redis to become healthy..."
        sleep 2
    else
        echo "❌ Redis is not running and Docker is not found. Please install Redis (brew install redis) or Docker Desktop."
        exit 1
    fi
fi

# 2. Detect active physical network interface on macOS
DEFAULT_IFACE=$(route get default 2>/dev/null | grep interface | awk '{print $2}')
if [ -z "$DEFAULT_IFACE" ]; then
    DEFAULT_IFACE="en0"
fi
echo "✅ Active macOS physical interface detected: ${DEFAULT_IFACE}"

# 3. Virtual environment setup
PYTHON_CMD="python3"
if [ -d ".venv" ]; then
    PYTHON_CMD="$DIR/.venv/bin/python3"
elif [ -d "venv" ]; then
    PYTHON_CMD="$DIR/venv/bin/python3"
fi

# 4. Verify raw packet capture permissions
echo ""
echo "🚀 Launching NetworkSentinel on http://localhost:8000"
echo "   Capturing REAL live packets on physical interface: ${DEFAULT_IFACE}"
echo "   (Raw socket packet capture on macOS requires sudo/root access)"
echo "----------------------------------------------------------"

sudo CAPTURE_INTERFACE="${DEFAULT_IFACE}" "$PYTHON_CMD" -m uvicorn app.main:app --host 0.0.0.0 --port 8000
