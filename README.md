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

## 3. Quick Start with Docker Compose (Recommended)

The fastest and most reliable way to run NetworkSentinel is using **Docker Compose**. It automatically packages all low-level networking libraries (`libpcap-dev`, `tcpdump`), handles capability privileges for raw packet sniffing, sets up **Redis 7**, and runs the FastAPI backend and Jev triage worker without manual dependency management.

### Step 1: Install Docker
If you do not have Docker installed yet, download and install **Docker Desktop** (or Docker Engine on Linux):
* **macOS / Windows / Linux:** Download from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
* Make sure Docker Desktop is open and running before proceeding.

### Step 2: Clone Repository & Enter Directory
Open your terminal and run:
```bash
git clone https://github.com/your-username/network-sentinel.git
cd "network-sentinel"
```

### Step 3: Configure Environment File
Create your local `.env` configuration from the provided template:
```bash
cp .env.example .env
```

Open `.env` in any text editor (e.g. `nano .env` or VS Code) and configure your keys:
```ini
# TypeSafe Jev API Key (Get yours at https://typesafe.ai)
TYPESAFE_API_KEY=your_actual_typesafe_key_here
JEV_API_URL=https://api.typesafe.ai/v1/systemone
JEV_MODEL=jev-latest

# Resend Email Settings (Optional: leave default for simulated alert logging)
RESEND_API_KEY=re_your_resend_api_key_here
RESEND_FROM_EMAIL=security@your-verified-domain.com
ALERT_RECIPIENT=your_notification_email@gmail.com
```
*(Note: If you don't have API keys yet, NetworkSentinel automatically operates in intelligent simulation mode so you can still test all dashboards, rate pacing, and threat scenarios immediately).*

### Step 4: Build and Start Containers
Run the following command to build the image and start Redis and NetworkSentinel in the background:
```bash
docker compose up -d --build
```
*(If you are on an older Docker installation, you can use `docker-compose up -d --build`).*

### Step 5: View Real-Time Logs
To verify that all services started cleanly and packet capture is active:
```bash
docker compose logs -f sentinel
```
*(Press `Ctrl + C` at any time to exit log streaming; containers will keep running).*

### Step 6: Open the Dashboard
Open your web browser and navigate to:
```
http://localhost:8000
```
You will be greeted by the live telemetry dashboard, real-time KPI cards, and dynamic Chart.js visualizations!

### Step 7: Stopping the Application
When you want to stop the system:
```bash
docker compose down
```

> **Host Network Sniffing (Linux Users):**
> By default, Docker monitors bridge container network traffic. If you are on Linux and want NetworkSentinel to capture your physical machine's network card (e.g., `eth0`), uncomment `network_mode: host` in `docker-compose.yml`.

---

## 4. Manual Local Installation (Alternative without Docker)

Follow this step-by-step guide if you prefer running NetworkSentinel directly on your host operating system using Python and a local Redis instance.

### Step 1: Install System Prerequisites
* **Python 3.11+**
* **Redis Server**
* **libpcap** (for raw packet sniffing):
  * **Debian/Ubuntu:** `sudo apt-get install -y libpcap-dev tcpdump libcap2-bin`
  * **macOS:** `brew install libpcap redis`
  * **Arch Linux:** `sudo pacman -S libpcap tcpdump redis`

### Step 2: Set Up Python Virtual Environment
Navigate to the project root and create an isolated virtual environment:
```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# On macOS / Linux:
source .venv/bin/activate

# Install all pinned dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Identify Your Network Interface
Find the exact name of the network interface you want to monitor:
* **Linux:** `ip a` (commonly `eth0`, `enp3s0`, or `wlan0`)
* **macOS:** `ifconfig -l` (commonly `en0` for Wi-Fi, `en1` for Ethernet)

### Step 4: Configure Raw Socket Permissions
Capturing network packets at Layer 3/4 requires raw socket privileges:
* **Linux (Recommended without root):** Grant Linux capabilities directly to Python:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
  ```
* **macOS:** Run the application using `sudo` with your virtual environment's Python, or set `SIMULATION_MODE=true` in `.env` if testing without root privileges.

### Step 5: Create and Configure `.env`
```bash
cp .env.example .env
```
Edit `.env` to match your interface and credentials:
```ini
CAPTURE_INTERFACE=eth0    # Or en0 on macOS, or leave empty for auto-detect
REDIS_URL=redis://localhost:6379/0
TYPESAFE_API_KEY=your_actual_typesafe_key_here
```

### Step 6: Start Redis Service
Ensure Redis is running locally:
* **macOS (Homebrew):** `brew services start redis`
* **Linux (systemd):** `sudo systemctl start redis-server`
* **Test connection:** `redis-cli ping` (should output `PONG`)

### Step 7: Launch NetworkSentinel
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Open **`http://localhost:8000`** in your browser.

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
