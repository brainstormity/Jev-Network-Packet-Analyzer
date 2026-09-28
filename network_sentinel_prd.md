# Project Specification: NetworkSentinel (Jev System One Edition)

NetworkSentinel is an open-source, real-time, lightweight network telemetry triage and alerting system. It captures network traffic, filters noise and reassembles flows, buffers events in Redis, classifies anomalies using **TypeSafe AI's Jev** System One decision model, serves a real-time FastAPI dashboard over WebSockets, and dispatches email alerts using **Resend**.

---

## 1. High-Level Architecture

```
[ Network Interface ]
        │ (Raw Packets: Layer 3/4)
        ▼
[ Layer 1: Scapy Capture (Threaded / AF_PACKET) ]
        │ - Kernel/BPF Filter (Drops pure ACKs, routine broadcast, ARP, mDNS)
        │ - Protocol state extractor (DNS, TLS SNI, HTTP URI, IP/Port, Shannon Entropy)
        ▼
[ Layer 2: Redis Deduplication & Ingestion Queue (`net:raw_events`) ]
        │ - Skips known-benign cached domains (TTL: 1 hour)
        │ - Acts as shock absorber for packet micro-bursts
        ▼ (Worker Pool - Controlled to ≤ 18 req/sec via Token Bucket / Async Rate Pacer)
[ Layer 3: Jev System One Triage Worker ]
        │ - Evaluates state via TypeSafe API (Choice + Score + Noul primitives)
        │ - Emits classified results to Redis Pub/Sub (`net:classified`) & SQLite
        ▼
 ┌──────┴───────────────────────────────────────────────────────┐
 │                                                              │
 ▼ (If threat detected & confidence > threshold)                ▼ (All evaluated sessions)
[ Email Dispatcher ]                                     [ FastAPI Backend ]
 (Resend REST API via HTTPX Async)                              │ (REST + WebSockets)
 (With 5-min deduplication cooldown)                            ▼
                                                        [ Live Web Dashboard ]
                                                         (Tailwind + Chart.js)
```

---

## 2. Technology Stack & Dependencies

* **Language/Runtime:** Python 3.11+
* **Web Framework:** `fastapi` with `uvicorn[standard]`
* **Packet Capture:** `scapy` (specifically utilizing `store=0` and compiled BPF filters for near-zero memory footprint).
* **Message Broker & Rate Limiting:** `redis` (`redis-py` async client)
* **HTTP Client:** `httpx` (async, used for both Jev API and Resend API)
* **AI Decision Layer:** TypeSafe AI Jev System One API (`https://api.typesafe.ai/v1/decisions` or `https://thejevai.com/v1/systemone`)
* **Local Persistence:** `aiosqlite` (lightweight storage of recent events & alerts)
* **Email Provider:** Resend (via REST API for non-blocking HTTP dispatch)
* **Frontend:** Single-page dashboard served directly by FastAPI (`templates/index.html` with Tailwind CDN, Chart.js, and native WebSockets)

---

## 3. Data Ingestion & Pre-Filtering Engine

### 3.1 What to Discard (Noise Elimination)
To prevent overwhelming the system, the capture thread must filter aggressively at the kernel level using BPF:
1. **BPF Filter String Example:** `ip and not arp and not udp port 5353 and not udp port 1900 and not net 127.0.0.0/8`
2. **In-Memory Discard:** 
   * Ignore TCP packets with pure `ACK` flags and zero payload length.
   * Ignore established bulk transfers from known whitelisted ASNs/IPs (e.g., Netflix, YouTube, standard OS updates).
   * Filter out loopback and internal broadcast chatter.

### 3.2 State Extracted for Jev
For surviving connections, extract this minimal structured dictionary:
```json
{
  "timestamp": 1727481600.123,
  "protocol": "TCP",
  "src_ip": "192.168.1.45",
  "dst_ip": "185.220.101.5",
  "dst_port": 4444,
  "domain_or_sni": "c2-checkin.dynamic-dns.net",
  "payload_snippet": "GET /beacon?id=4910 HTTP/1.1\\r\\nUser-Agent: curl/7.88.1",
  "entropy": 4.12
}
```

---

## 4. Jev System One Decision Integration

### 4.1 Endpoint Specification
* **URL:** `POST https://api.typesafe.ai/v1/decisions` (or fallback `https://thejevai.com/v1/systemone`)
* **Headers:** `Authorization: Bearer <TYPESAFE_API_KEY>`, `Content-Type: application/json`
* **Request Body Schema:**
```json
{
  "model": "jev-latest",
  "state": "<JSON string of the extracted connection state>",
  "questions": {
    "is_suspicious": {
      "type": "noul",
      "instructions": "Does this network event indicate malicious behavior, exploit activity, unauthorized tunneling, or C2 beaconing?"
    },
    "threat_category": {
      "type": "choice",
      "instructions": "Categorize the threat classification of this traffic.",
      "criteria": {
        "benign": "Routine user browsing, trusted CDNs, OS telemetry, or standard developer tools.",
        "c2_beacon": "Periodic or suspicious outbound connection to an unknown external IP or dynamic DNS service without legitimate SNI.",
        "dns_tunneling": "High-entropy, encoded subdomains or data exfiltration over port 53.",
        "exploit_attempt": "SQL injection, reverse shell syntax, unauthorized command payloads, or path traversal.",
        "reconnaissance": "Port scanning, host enumeration, or abnormal flag combinations."
      }
    },
    "severity": {
      "type": "score",
      "instructions": "Rate the operational risk of this network anomaly.",
      "levels": [
        "0: Informational / benign",
        "1: Low - minor anomaly or atypical configuration",
        "2: Medium - unverified external connection or abnormal telemetry",
        "3: High - potential compromise, DGA domain, or active exploit probe",
        "4: Critical - confirmed exploit payload, active C2, or large exfiltration"
      ]
    }
  }
}
```

### 4.2 Rate Limiting & Deduplication (Critical for Performance)
* **Jev Limit:** 20 requests per second.
* **Token Bucket Worker:** Enforce `asyncio.sleep(1 / 18)` to pace Redis `BRPOP` consumption, ensuring requests never exceed 18 req/sec.
* **Redis Caching:** Before sending to Jev, check a Redis hash/key (e.g., `cache:domain:<domain_or_sni>`). If a domain/IP was evaluated as `benign` with `confidence > 0.95` in the last hour, **skip the Jev API call** and auto-mark as benign. This reduces API calls by ~90% in typical household/office networks.

---

## 5. Resend Notification Engine

Using Resend via its REST API avoids the blocking nature and connection overhead of standard SMTP.

### 5.1 Asynchronous HTTP Dispatch
Use `httpx.AsyncClient` to send the payload to `https://api.resend.com/emails`.
* **Endpoint:** `POST https://api.resend.com/emails`
* **Headers:** `Authorization: Bearer <RESEND_API_KEY>`, `Content-Type: application/json`
* **Payload:**
```json
{
  "from": "Network Sentinel <security@your-verified-domain.com>",
  "to": ["your_email@example.com"],
  "subject": "🚨 [Alert] High Severity Threat Detected: <threat_category>",
  "html": "<p>Jev has identified a <strong><severity></strong> severity anomaly...</p>"
}
```

### 5.2 Alert Throttling (Anti-Spam)
* Maintain an in-memory or Redis alert cooldown key: `alert:cooldown:<src_ip>:<threat_category>`.
* Set a TTL of 300 seconds (5 minutes) on this key.
* If the key exists, suppress duplicate emails for identical triggers within the window while still logging them to the dashboard/database.

---

## 6. Real-Time Dashboard (FastAPI + WebSockets)

Accessible at `http://localhost:8000/`.
1. **Header KPI Cards:** Packets Captured, Evaluated by Jev, Active Threats, Cache Hit Ratio.
2. **Live Feed Table:** Incoming stream of evaluated packets showing Timestamp, Source IP, Destination IP, Protocol/Port, Jev Classification, Risk Score, and Status Badge.
3. **WebSocket Stream (`/ws/live-events`):** Broadcasts every evaluated event to connected browser clients instantly.

---

## 7. Configuration Specification (`.env`)

```ini
# TypeSafe Jev Settings
TYPESAFE_API_KEY=your_typesafe_jev_key_here
JEV_API_URL=https://api.typesafe.ai/v1/decisions
JEV_MODEL=jev-latest

# Network Interface Settings
CAPTURE_INTERFACE=eth0
BPF_FILTER=ip and not net 127.0.0.0/8 and not udp port 5353 and not udp port 1900

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# Alerting Thresholds
ALERT_THRESHOLD_NOUL=0.85
ALERT_MIN_SEVERITY=3

# Resend Settings
RESEND_API_KEY=re_your_resend_api_key_here
RESEND_FROM_EMAIL=security@your-verified-domain.com
ALERT_RECIPIENT=your_notification_email@gmail.com
```

---

## 8. File Structure for the Agent to Generate

```
network-sentinel/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI server & WebSocket broadcaster
│   ├── config.py            # Pydantic Settings reading .env
│   ├── capture.py           # Scapy live sniffer running in ThreadPoolExecutor
│   ├── worker.py            # Redis consumer, Token Bucket rate-limiter, Jev client
│   ├── notifier.py          # Resend HTTPX async dispatcher with cooldowns
│   ├── database.py          # SQLite persistence for events and alerts
│   └── templates/
│       └── index.html       # Single-file HTML/Tailwind/WebSocket dashboard
├── .gitignore               # Comprehensive Git ignore rules
├── requirements.txt         # Pinned Python dependencies
├── .env.example             # Clean environment template
├── README.md                # In-depth architectural & deployment guide
└── docker-compose.yml       # Spins up Redis and the FastAPI/Worker container
```

---

## 9. Required Content for Supporting Files

### 9.1 `.gitignore` Requirements
The agent must generate a complete, production-grade `.gitignore` containing:
* **Environment & Secrets:** `.env`, `.env.*`, `*.pem`, `*.key`
* **Python Artifacts:** `__pycache__/`, `*.py[cod]`, `*$py.class`, `.pytest_cache/`, `*.egg-info/`, `.venv/`, `env/`, `venv/`
* **Local Storage & Databases:** `*.sqlite3`, `*.db`, `*.log`, `*.pcap`, `data/`
* **OS & IDE Cruft:** `.DS_Store`, `Thumbs.db`, `.vscode/`, `.idea/`

### 9.2 In-Depth `README.md` Requirements
The generated `README.md` must be comprehensive and well-structured, including:
1. **Project Overview & Architecture Diagram:** Clear ASCII explanation of how packets move from the NIC through Redis to Jev and Resend.
2. **Prerequisites:** Linux/macOS raw socket privileges (Capabilities/`sudo`), Redis, Python 3.11+, TypeSafe Jev API key, and Resend domain configuration.
3. **Step-by-Step Setup Guide:**
   * Virtual environment setup & dependency installation.
   * Interface identification (`ip a` or `ifconfig`).
   * Setting Linux capabilities for Scapy without root: `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`.
   * Environment variable configuration (.env setup).
4. **Running with Docker Compose:** Instructions for zero-config startup (`docker-compose up -d --build`).
5. **Dashboard Tour & API Docs:** Explanation of the UI widgets, WebSocket events, and REST endpoints.
6. **Troubleshooting & FAQs:**
   * Handling permission denied on network interfaces.
   * Managing high-traffic home networks and packet drops.
   * Debugging Resend domain verification and spam suppression.

---

## 10. Implementation Directives for the AI Agent

1. **Pure Asynchronous Networking:** Use `asyncio`, `httpx.AsyncClient()`, and `aioredis`. Never use blocking `requests` or `time.sleep()`.
2. **Thread Boundary for Packet Sniffing:** Scapy's `sniff(store=0)` is synchronous. Run it inside a `concurrent.futures.ThreadPoolExecutor` or `asyncio.to_thread`. The packet callback (`prn`) must push raw events to Redis synchronously or via a thread-safe helper so it does not block the sniffer loop.
3. **Resilience & Fallbacks:** If the Jev API returns a temporary 429 or 5xx, requeue the event into Redis with an exponential backoff.
4. **Single-File Frontend:** Keep `index.html` zero-build. Use CDN-imported Tailwind CSS and Chart.js so the user does not need `npm` or build tools.