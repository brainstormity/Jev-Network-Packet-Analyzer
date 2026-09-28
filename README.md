# NetworkSentinel (Jev System One Edition)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-red.svg)](https://scapy.net)
[![Redis](https://img.shields.io/badge/Redis-7+-dc382d.svg)](https://redis.io)
[![TypeSafe AI](https://img.shields.io/badge/TypeSafe%20AI-Jev%20System%20One-6366f1.svg)](https://typesafe.ai)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**NetworkSentinel** is a lightweight, real-time network telemetry triage and threat detection system. It passively captures Layer 3/4 network traffic, filters noise in memory, buffers flows in Redis, evaluates anomalies using **TypeSafe AI's Jev** System One decision model, streams live telemetry to a cyber-styled dashboard over WebSockets, and dispatches containment alerts via **Resend**.

---

## ⚡ Core Features

* **Passive L3/L4 Capture**: Kernel BPF filtering and asynchronous packet processing powered by Scapy.
* **L1 Deterministic Pre-Filter**: Bypasses encrypted TLS application data and zero-payload TCP packets, eliminating token waste and latency on benign traffic.
* **Bidirectional Flow Caching**: Redis-backed flow pair caching delivers a **>99% cache hit ratio** for routine connections.
* **Jev System One AI Triage**: Evaluates suspicious probability (`is_suspicious`), threat category (`threat_category`), and operational risk score (`severity`).
* **Real-Time SOC Dashboard (`/`)**: Live telemetry velocity charts, threat distribution doughnut, and instant packet inspection.
* **Incident Dispatch Center (`/alerts`)**: Dedicated full-screen audit ledger with status tabs, search, and one-click Resend tracking.
* **Automated Email Alerting**: Instant incident dispatch via Resend with a 5-minute per-source cooldown to prevent notification fatigue.
* **Built-In Attack Simulator**: 1-click security drills for C2 Beacons, SQL Injection, DNS Tunneling, and Port Scanning.

---

## 🚀 Quick Start (Docker Compose)

The fastest and recommended way to run NetworkSentinel is with Docker Compose:

### 1. Clone & Configure
```bash
git clone https://github.com/your-username/network-sentinel.git
cd "network-sentinel"
cp .env.example .env
```

Edit `.env` with your API keys:
```ini
# TypeSafe Jev API (https://typesafe.ai)
TYPESAFE_API_KEY=your_typesafe_key_here

# Resend Email Alerts (https://resend.com)
RESEND_API_KEY=re_your_resend_key_here
RESEND_FROM_EMAIL=onboarding@resend.dev   # Free sandbox sender (no domain needed)
ALERT_RECIPIENT=your_registered_email@gmail.com
```

### 2. Start the Application
```bash
docker compose up -d --build
```

### 3. Open the Dashboard
* **Live Telemetry Stream**: [http://localhost:8000](http://localhost:8000)
* **Incident Dispatch Center**: [http://localhost:8000/alerts](http://localhost:8000/alerts)

To stop the system:
```bash
docker compose down
```

---

## 📖 In-Depth Documentation

For detailed guides, architecture diagrams, and complete manuals, see [**docs.md**](docs.md):

| Documentation Section | What It Covers |
|---|---|
| [**Architecture & Multi-Tier Funnel**](docs.md#1-system-architecture--multi-tier-triage-funnel) | Ingestion pipeline, Redis queue, and Jev cognitive triage workflow. |
| [**Dashboard Operator Guide**](docs.md#2-dashboard-operator-guide-) | Live KPI cards, Chart.js metrics, and the 3-tab Forensic Inspector modal. |
| [**Incident Dispatch Center (`/alerts`)**](docs.md#3-incident-dispatch-center-alerts) | Full-screen alerts ledger, status filters, search, and Resend auditing. |
| [**L1 Pre-Filter & Caching Engine**](docs.md#4-l1-deterministic-pre-filter--bidirectional-flow-caching) | TLS data bypass, zero-payload pruning, and bidirectional flow keys. |
| [**Email Alerting & Resend Setup**](docs.md#5-email-alerting--resend-dispatch-engine) | Sandbox setup, custom domain verification, and 5-min cooldown logic. |
| [**REST & WebSocket API Reference**](docs.md#6-rest--websocket-api-reference) | Full reference for all HTTP endpoints and WebSocket feeds. |
| [**Bare-Metal Manual Installation**](docs.md#7-manual-bare-metal-setup--hardware-deployment) | Running on Linux/macOS with Python, `setcap` permissions, and Redis. |
| [**Troubleshooting & FAQs**](docs.md#8-advanced-troubleshooting--faqs) | Common network interface, permission, and Resend delivery questions. |

---

## 🧪 Security Drills & CLI Testing

Run simulated cyber incidents to test detection and alerting without sending real attacks:

```bash
# Inject a C2 Beaconing scenario
python3 simulate.py --scenario c2_beacon --count 5

# Inject a DNS Tunneling exfiltration scenario
python3 simulate.py --scenario dns_tunneling --http http://localhost:8000

# Run automated test suite
pytest -v
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
