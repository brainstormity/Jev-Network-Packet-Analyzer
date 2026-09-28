# NetworkSentinel (Jev System One Edition)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-red.svg)](https://scapy.net)
[![Redis](https://img.shields.io/badge/Redis-7+-dc382d.svg)](https://redis.io)
[![TypeSafe AI](https://img.shields.io/badge/TypeSafe%20AI-Jev%20System%20One-6366f1.svg)](https://typesafe.ai)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**NetworkSentinel** is a lightweight, real-time network telemetry triage and threat detection system. It passively captures Layer 3/4 network traffic, filters noise in memory, buffers flows in Redis, evaluates anomalies using **TypeSafe AI's Jev** System One decision model, streams live telemetry to a cyber-styled dashboard over WebSockets, and dispatches containment email alerts via **Resend**.

![NetworkSentinel Architecture](architecture.jpeg)

---

## Core Features

* **Passive L3/L4 Capture**: Kernel BPF filtering and asynchronous packet processing powered by Scapy.
* **Pre-Filter Pipeline (Zero Token Waste)**: 
  * *Noise Elimination*: In-memory discard engine strips broadcast, loopback, and zero-payload TCP ACK chatter before queuing.
  * *L1 Deterministic Pre-Filter*: Automatically bypasses encrypted TLS data streams, HTTP/3 (QUIC) UDP 443 packets, and major CDN subnets (Cloudflare, Google, Apple, AWS) as benign.
  * *Bidirectional Flow Caching*: Redis-backed bidirectional flow tracking caches routine connections for 24 hours, delivering a **>99% cache hit ratio**.
  * **Result**: Only genuine anomalies, unclassified payloads, or explicit threat signatures ever reach the AI decision engine.
* **Jev System One AI Triage**: Evaluates suspicious probability (`is_suspicious`), threat category (`threat_category`), and operational risk score (`severity`).
* **Real-Time SOC Dashboard (`/`)**: Live telemetry velocity charts, threat distribution doughnut, and instant packet inspection.
* **Incident Dispatch Center (`/alerts`)**: Dedicated full-screen audit ledger with status tabs, search, and one-click Resend tracking.
* **Automated Email Alerting**: Instant incident dispatch via Resend with a 5-minute per-source cooldown to prevent notification fatigue.
* **Built-In Attack Simulator**: 1-click security drills for C2 Beacons, SQL Injection, DNS Tunneling, and Port Scanning.

---

## Quick Start: Choose Your Environment

NetworkSentinel captures **real physical network traffic** across three environments:

### 1. Clone & Configure
```bash
git clone https://github.com/your-username/network-sentinel.git
cd "network-sentinel"
cp .env.example .env
```
Edit `.env` with your [TypeSafe Jev](https://typesafe.ai) and [Resend](https://resend.com) API keys.

---

### 2. Choose How to Run

Select the deployment option that matches your platform and monitoring goals:

### Option 1: Run Locally (macOS & Linux)
> **Required for macOS:** Docker Desktop on macOS runs inside a virtual machine and cannot capture traffic outside the container. Running locally gives NetworkSentinel direct raw socket access to your physical Wi-Fi/Ethernet interface (`en0` / `eth0` / `wlan0`). This method works identically on both macOS and Linux.

```bash
# 1. Start Redis in background (via Docker or local package manager)
docker run -d -p 6379:6379 --name redis redis:alpine

# 2. Set up Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Launch NetworkSentinel (sudo required for raw socket capture)
sudo venv/bin/python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
*(On macOS, you can also run `./start-mac.sh` which automates these steps).*

---

### Option 2: Run via Docker (Linux Only)
> **Linux Only:** On Linux, Docker runs directly on the native host kernel (`network_mode: host`), allowing containers to capture real traffic from physical adapters (`eth0`, `wlan0`) outside the container. *(This does NOT work on macOS due to Docker VM isolation).*

```bash
docker compose -f docker-compose.linux.yml up -d --build
```

---

### Option 3: Whole-Home Network Monitoring (All Devices: Smart TVs, Phones, IoT)
> **Monitor Everything:** Home Wi-Fi routers enforce unicast isolation between client devices. To passively inspect traffic from **every device across your household** (phones, smart TVs, IoT cameras):
* **Router DNS / Gateway Redirection**: Point your home router's Primary DNS or Gateway to NetworkSentinel (Pi-hole style).
* **Managed Switch Port Mirroring (SPAN)**: Duplicate 100% of router traffic to NetworkSentinel with zero added latency.
* **Inline Appliance**: Run NetworkSentinel on a dual-NIC Raspberry Pi or Mini PC as a transparent hardware bridge.

👉 Follow the complete step-by-step setup in [**docs.md: Whole-Home Network Monitoring Guide**](docs.md#73-whole-home-network-monitoring-all-devices-smart-tvs-phones-iot).

---

### 3. Open the Dashboard
* **Live Telemetry Stream**: [http://localhost:8000](http://localhost:8000)
* **Incident Dispatch Center**: [http://localhost:8000/alerts](http://localhost:8000/alerts)

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
| [**Deployment Architectures (Local, Linux Docker, Whole-Network)**](docs.md#7-real-world-traffic-capture--deployment-architectures) | Running locally on Mac/Linux, host-mode Docker on Linux, and whole-home monitoring. |
| [**Troubleshooting & FAQs**](docs.md#8-advanced-troubleshooting--faqs) | Common network interface, permission, and Resend delivery questions. |

---

## Security Drills & CLI Testing

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

## Project Vision & Roadmap

NetworkSentinel began as a fast, fun weekend experiment to test how TypeSafe AI's Jev model handles real-world Layer 3/4 packet classification. The project is open-sourced under the MIT license so the security and developer community can fork, adapt, and build upon it:

* **Local Model Implementation (Recommended for Privacy)**:  
  While this proof-of-concept leverages the cloud-hosted TypeSafe Jev API, running network packet inspection on private infrastructure is best paired with a **local model** (e.g., via Ollama, vLLM, or llama.cpp). Swapping the cloud triage engine for a local SLM/LLM ensures that **zero telemetry ever leaves your home LAN or air-gapped network**.
* **Isolated Attack Test Lab**:  
  Plans are underway to deploy an isolated test network to systematically fire live exploit vectors, reverse shells, C2 implants, and DNS exfiltration tools to benchmark and stress-test detection accuracy and false-positive resilience.
* **Community Customization**:  
  Feel free to fork the repository, tailor the L1 pre-filters to your own homelab setup, hook in alternative notification providers, or plug in your own custom inference backends.

---

## Disclaimer & Responsible Use

> ⚠️ **Important Notice**: This repository is an experimental proof-of-concept and research project intended strictly for educational, defensive research, and homelab experimentation.
>
> * **Do NOT rely on this software as a primary or production security system.** It is not an enterprise-certified Network Intrusion Detection System (NIDS) or SIEM.
> * The author and contributors assume **no responsibility or liability** for any security incidents, missed detections, false alerts, compromised devices, or damages arising from the use or inability to use this software.
> * Always implement industry-standard security practices, including network segmentation, endpoint antivirus, robust firewall policies, and regular patch management.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

