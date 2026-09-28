# NetworkSentinel (Jev System One Edition)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-red.svg)](https://scapy.net)
[![Redis](https://img.shields.io/badge/Redis-7+-dc382d.svg)](https://redis.io)
[![TypeSafe AI](https://img.shields.io/badge/TypeSafe%20AI-Jev%20System%20One-6366f1.svg)](https://typesafe.ai)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**NetworkSentinel** is an open-source, lightweight, real-time network telemetry triage and threat mitigation engine. It passively captures Layer 3/4 network traffic using Scapy, filters noise and reassembles flows, buffers events in Redis, classifies anomalies using **TypeSafe AI's Jev** System One decision model, serves a real-time FastAPI dashboard over WebSockets, and dispatches email alerts using **Resend**.

---

## 1. Architecture Overview

![NetworkSentinel Architecture](architecture.jpeg)

### Data Flow Breakdown
1. **Layer 1 (Capture & Pre-Filtering):** Runs Scapy's synchronous `sniff(store=0)` inside a dedicated background thread with kernel BPF filtering. Noise packets (pure TCP ACKs with zero payload, loopback chatter, multicast) are pruned in-memory before serialization.
2. **Layer 2 (Redis Ingestion & Caching):** Surviving packet states are queued into Redis (`net:raw_events`). Before forwarding to Jev, domains and destination IPs are checked against a Redis cache with a 1-hour TTL. Benign domains with >95% confidence skip the external API call, slashing API consumption by up to ~90%.
3. **Layer 3 (Jev System One Triage):** An async consumer worker pool rates connection state using TypeSafe AI's Jev model (`jev-latest`), evaluating Noul (`is_suspicious`), Choice (`threat_category`), and Score (`severity`). Rate limits are strictly maintained at $\le 18\text{ req/sec}$ via an async Token Bucket.
4. **Layer 4 (Alerting & Dashboard):** High-severity anomalies trigger async Resend email alerts guarded by a 5-minute per-source cooldown key. All evaluated telemetry streams to the single-page Tailwind + Chart.js dashboard over WebSockets (`/ws/live-events`).

---

## 2. Prerequisites

* **Operating System:** Linux (Ubuntu 20.04+, Debian 11+, Arch) or macOS (12+)
* **Python:** Version 3.11 or newer
* **Redis Server:** Redis 6.2+ (or Docker Redis)
* **Raw Socket Privileges:** Required for Scapy packet capture:
  * Linux: Either run with `sudo` or grant `cap_net_raw,cap_net_admin` Linux capabilities.
  * macOS: Run with `sudo` or run via Docker Compose.
* **TypeSafe AI API Key:** Obtain from [TypeSafe AI](https://typesafe.ai).
* **Resend API Key & Verified Domain:** Obtain from [Resend](https://resend.com).

---

## 3. Step-by-Step Setup Guide

### 3.1 Clone & Virtual Environment

```bash
git clone https://github.com/your-username/network-sentinel.git
cd network-sentinel

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3.2 Network Interface Identification

Identify the network interface you want to monitor:

* **Linux:**
  ```bash
  ip link show
  # or
  ip a
  ```
  *(Typical interfaces: `eth0`, `enp3s0`, `wlan0`)*

* **macOS:**
  ```bash
  ifconfig -l
  ```
  *(Typical interfaces: `en0` for Wi-Fi, `en1` for Ethernet)*

### 3.3 Grant Linux Capabilities (No Root Required)

To allow Python to capture raw packets without running the entire application as `root`:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

*(Note: If using a virtual environment, target the virtual environment's Python binary: `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))`)*

### 3.4 Configure Environment Variables

Copy the provided example template and supply your keys:

```bash
cp .env.example .env
```

Edit `.env`:

```ini
# TypeSafe Jev Settings
TYPESAFE_API_KEY=your_actual_typesafe_key_here
JEV_API_URL=https://api.typesafe.ai/v1/systemone
JEV_MODEL=jev-latest

# Network Interface Settings
CAPTURE_INTERFACE=eth0    # Leave empty to auto-detect default route
BPF_FILTER=ip and not net 127.0.0.0/8 and not udp port 5353 and not udp port 1900

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# Alerting Thresholds
ALERT_THRESHOLD_NOUL=0.85
ALERT_MIN_SEVERITY=3

# Resend Settings
RESEND_API_KEY=re_your_resend_api_key
RESEND_FROM_EMAIL=security@your-verified-domain.com
ALERT_RECIPIENT=admin@yourcompany.com
```

### 3.5 Start Redis

If running Redis locally:

```bash
# macOS (Homebrew)
brew services start redis

# Ubuntu/Debian
sudo systemctl start redis-server
```

### 3.6 Run the Application

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open your browser at **`http://localhost:8000`** to view the live dashboard.

---

## 4. Running with Docker Compose (Zero-Config)

Docker Compose spins up Redis alongside NetworkSentinel with full networking capabilities:

```bash
# 1. Prepare environment
cp .env.example .env
# Fill in your TYPESAFE_API_KEY and RESEND_API_KEY in .env

# 2. Build and launch
docker-compose up -d --build

# 3. View live logs
docker-compose logs -f sentinel
```

> **Host Network Sniffing in Docker:**
> To sniff the host machine's physical network adapter directly rather than container bridge traffic, uncomment `network_mode: host` in `docker-compose.yml`.

---

## 5. Dashboard Tour & REST/WebSocket APIs

### 5.1 Dashboard Features (`http://localhost:8000`)
* **KPI Metrics Bar:**
  * **Packets Captured:** Total volume ingested by the Scapy kernel BPF filter.
  * **Evaluated by Jev:** Cumulative decisions rendered by the System One triage worker.
  * **Active Threats:** Confirmed network anomalies (Exploits, C2, DNS exfil, Recon).
  * **Cache Hit Ratio:** Percentage of repetitive traffic resolved via Redis deduplication cache without consuming Jev API tokens.
* **Telemetry Velocity Chart (Chart.js):** Real-time dual-line timeline displaying benign vs. threat packet frequency.
* **Threat Distribution (Chart.js):** Doughnut breakdown across threat categories.
* **Interactive Threat Simulator:** Click **"Simulate Threat"** to inject test attack scenarios with 1 click (C2 Beacon, DNS Tunnel, SQLi, Port Scan, or Benign HTTPS).
* **Live Feed Table:** Dynamic table with pause/resume, category filters, threat badges, entropy indicators, and an **"Inspect"** button showing full JSON state and decision records.
* **Alerts Log Drawer:** View recent email alerts, Resend transmission IDs, and cooldown suppression status.

### 5.2 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web dashboard single-page interface |
| `GET` | `/health` | Health status of Redis, capture engine, worker, and APIs |
| `GET` | `/api/stats` | Aggregate telemetry KPIs and breakdown counts |
| `GET` | `/api/events?limit=50` | Retrieve recent evaluated packets from SQLite |
| `GET` | `/api/alerts?limit=30` | Retrieve recent alert dispatches from SQLite |
| `POST` | `/api/simulate` | Inject simulated attack scenarios (`c2_beacon`, `dns_tunneling`, `exploit_attempt`, `reconnaissance`, `benign`) |
| `WS` | `/ws/live-events` | Real-time bi-directional WebSocket telemetry stream |

---

## 6. Testing & Simulation CLI

You can generate test traffic using the built-in CLI tool:

```bash
# Inject a C2 Beaconing scenario into Redis
python3 simulate.py --scenario c2_beacon --count 5

# Inject a DNS Data Exfiltration scenario via HTTP API
python3 simulate.py --scenario dns_tunneling --http http://localhost:8000

# Inject all attack scenarios sequentially
python3 simulate.py --scenario all --count 3 --delay 0.5
```

### Running Automated Test Suite

```bash
pytest -v
```

---

## 7. Troubleshooting & FAQs

### Q: Why do I see `PermissionError: [Errno 1] Operation not permitted` on startup?
**A:** Scapy requires root or raw socket capabilities to bind to network interfaces in promiscuous mode.
* **Linux:** Run `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`
* **macOS:** Run with `sudo uvicorn app.main:app ...` or use simulation mode (`SIMULATION_MODE=true` in `.env`).

### Q: How does NetworkSentinel handle high-traffic bursts without dropping packets?
**A:** NetworkSentinel separates capture from AI evaluation:
1. Scapy uses compiled BPF filters at the kernel socket layer (`SO_ATTACH_FILTER`), immediately discarding non-relevant traffic (e.g. ACKs, mDNS, SSDP).
2. The packet callback only extracts minimal connection metadata and pushes to Redis (`net:raw_events`) in microseconds.
3. The Token Bucket worker pulls from Redis at a smooth 18 req/sec pace, using Redis as an elastic shock absorber.

### Q: Why didn't I receive an email for consecutive attacks?
**A:** NetworkSentinel implements a strict 5-minute (300-second) anti-spam deduplication cooldown key: `alert:cooldown:<src_ip>:<threat_category>`. If an attacker fires 100 identical exploit probes within 5 minutes, 1 alert is sent, and the remaining 99 are recorded as `throttled` in the SQLite database and dashboard.

### Q: Why is my Resend alert failing?
**A:** Verify that:
1. `RESEND_API_KEY` starts with `re_`.
2. `RESEND_FROM_EMAIL` matches a domain verified in your Resend account dashboard (e.g. `alerts@yourdomain.com`). If using Resend sandbox, use `onboarding@resend.dev`.

---

## 8. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
