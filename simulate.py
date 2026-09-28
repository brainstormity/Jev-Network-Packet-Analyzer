#!/usr/bin/env python3
"""Simulation and testing script for NetworkSentinel.

Generates realistic network traffic scenarios (Benign CDN, C2 Beacon, DNS Tunnel,
SQLi Exploit, Port Reconnaissance) and injects them directly into Redis or via REST API.
"""

import argparse
import asyncio
import json
import random
import time
import httpx
import redis.asyncio as aioredis

from app.config import settings

SCENARIOS = {
    "benign": {
        "protocol": "TCP",
        "src_ip": "192.168.1.105",
        "dst_ip": "142.250.190.46",
        "dst_port": 443,
        "domain_or_sni": "fonts.googleapis.com",
        "payload_snippet": "GET /css2?family=Inter:wght@400;600 HTTP/1.1\r\nHost: fonts.googleapis.com",
        "entropy": 3.12,
    },
    "c2_beacon": {
        "protocol": "TCP",
        "src_ip": "192.168.1.45",
        "dst_ip": "185.220.101.5",
        "dst_port": 4444,
        "domain_or_sni": "c2-checkin.dynamic-dns.net",
        "payload_snippet": "GET /beacon?id=4910&stage=2 HTTP/1.1\r\nUser-Agent: curl/7.88.1\r\nHost: c2-checkin.dynamic-dns.net",
        "entropy": 4.12,
    },
    "dns_tunneling": {
        "protocol": "UDP",
        "src_ip": "10.0.4.12",
        "dst_ip": "198.51.100.53",
        "dst_port": 53,
        "domain_or_sni": "a83f9b2d7e10c4a9.exfil.darkops.io",
        "payload_snippet": "\x00\x01\x01\x00\x00\x01a83f9b2d7e10c4a9\x05exfil\x07darkops\x02io",
        "entropy": 5.84,
    },
    "exploit_attempt": {
        "protocol": "TCP",
        "src_ip": "45.33.32.156",
        "dst_ip": "192.168.1.10",
        "dst_port": 80,
        "domain_or_sni": "internal-api.corp",
        "payload_snippet": "GET /api/user?id=1' UNION SELECT username,password FROM users-- HTTP/1.1",
        "entropy": 4.65,
    },
    "reconnaissance": {
        "protocol": "TCP",
        "src_ip": "91.240.118.172",
        "dst_ip": "192.168.1.1",
        "dst_port": 22,
        "domain_or_sni": "",
        "payload_snippet": "SSH-2.0-Nmap-SSH-Scan-Probe",
        "entropy": 2.45,
    },
}


async def inject_via_redis(scenario_name: str, count: int = 1, delay: float = 0.1) -> None:
    """Inject scenario events directly into the Redis raw queue."""
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    template = SCENARIOS.get(scenario_name)
    if not template:
        print(f"Unknown scenario: {scenario_name}. Available: {list(SCENARIOS.keys())}")
        return

    print(f"Injecting {count} event(s) for scenario '{scenario_name}' into Redis: {settings.REDIS_RAW_QUEUE}...")
    for i in range(count):
        event = {
            **template,
            "timestamp": time.time(),
            "is_simulated": True,
        }
        await r.lpush(settings.REDIS_RAW_QUEUE, json.dumps(event))
        await r.incr("net:stats:captured")
        print(f"  [{i+1}/{count}] Injected {scenario_name} (dest: {event['dst_ip']}:{event['dst_port']})")
        if delay > 0 and i < count - 1:
            await asyncio.sleep(delay)
    await r.aclose()
    print("Done!")


async def inject_via_http(api_url: str, scenario_name: str, count: int = 1) -> None:
    """Inject scenario events via HTTP POST to /api/simulate."""
    async with httpx.AsyncClient(base_url=api_url) as client:
        print(f"Injecting {count} event(s) for scenario '{scenario_name}' via API {api_url}/api/simulate...")
        for i in range(count):
            res = await client.post("/api/simulate", json={"scenario": scenario_name})
            if res.status_code == 200:
                print(f"  [{i+1}/{count}] OK: {res.json().get('status')}")
            else:
                print(f"  [{i+1}/{count}] Failed: HTTP {res.status_code} {res.text}")


def main() -> None:
    parser = argparse.ArgumentParser(description="NetworkSentinel Traffic Simulation Tool")
    parser.add_argument(
        "--scenario",
        choices=["all", "benign", "c2_beacon", "dns_tunneling", "exploit_attempt", "reconnaissance"],
        default="c2_beacon",
        help="Attack or traffic scenario to simulate",
    )
    parser.add_argument("--count", type=int, default=1, help="Number of packets to inject")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay in seconds between injections")
    parser.add_argument("--http", type=str, default="", help="HTTP API base URL (e.g. http://localhost:8000)")

    args = parser.parse_args()

    scenarios = list(SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]

    async def run() -> None:
        for s in scenarios:
            if args.http:
                await inject_via_http(args.http, s, args.count)
            else:
                await inject_via_redis(s, args.count, args.delay)

    asyncio.run(run())


if __name__ == "__main__":
    main()
