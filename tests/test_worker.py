"""Tests for JevWorker, rate limiting, and deduplication cache."""

import json
import pytest
import fakeredis.aioredis
import httpx
import respx

from app.config import settings
from app.worker import JevWorker, TokenBucketRateLimiter, simulate_jev_decision
from app import database


@pytest.mark.asyncio
async def test_token_bucket_rate_limiter():
    limiter = TokenBucketRateLimiter(rate=20.0, capacity=2.0)
    # First 2 tokens should be immediately available
    await limiter.acquire()
    await limiter.acquire()
    assert limiter.tokens < 1.0


def test_simulate_jev_decision_heuristics():
    # Exploit attempt
    is_susp, cat, cat_conf, sev, sev_conf = simulate_jev_decision({
        "payload_snippet": "id=1' UNION SELECT username,password FROM users--",
        "dst_port": 80,
    })
    assert cat == "exploit_attempt"
    assert is_susp >= 0.90
    assert sev >= 3.5

    # C2 Beacon
    is_susp, cat, cat_conf, sev, sev_conf = simulate_jev_decision({
        "domain_or_sni": "c2-checkin.dynamic-dns.net",
        "payload_snippet": "GET /beacon?id=4910",
        "dst_port": 4444,
    })
    assert cat == "c2_beacon"
    assert is_susp >= 0.90

    # Benign
    is_susp, cat, cat_conf, sev, sev_conf = simulate_jev_decision({
        "domain_or_sni": "fonts.googleapis.com",
        "payload_snippet": "GET /css HTTP/1.1",
        "dst_port": 443,
    })
    assert cat == "benign"
    assert is_susp < 0.1
    assert sev == 0.0


@pytest.mark.asyncio
async def test_worker_caching_and_processing(tmp_path):
    db_file = str(tmp_path / "test_worker.db")
    await database.init_db(db_file)
    settings.DATABASE_PATH = db_file

    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    worker = JevWorker()
    worker._redis = fake_redis

    client = httpx.AsyncClient()

    # 1. Process Benign Event (should populate cache)
    benign_event = {
        "timestamp": 1727481600.0,
        "protocol": "TCP",
        "src_ip": "192.168.1.100",
        "dst_ip": "142.250.190.46",
        "dst_port": 443,
        "domain_or_sni": "gstatic.com",
        "payload_snippet": "GET /images HTTP/1.1",
        "entropy": 2.1,
    }

    res = await worker.process_event(json.dumps(benign_event), client)
    assert res is not None
    assert res["threat_category"] == "benign"

    # Verify cache key was set in Redis
    cached_val = await fake_redis.get(f"{settings.REDIS_CACHE_PREFIX}gstatic.com")
    assert cached_val == "benign"

    # 2. Process same domain again - should be marked cached
    res2 = await worker.process_event(json.dumps(benign_event), client)
    assert res2 is not None
    assert res2["cached"] is True

    cached_count = int(await fake_redis.get("net:stats:cached") or 0)
    assert cached_count == 1

    await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_worker_with_mocked_jev_api(tmp_path):
    db_file = str(tmp_path / "test_worker_api.db")
    await database.init_db(db_file)
    settings.DATABASE_PATH = db_file
    settings.TYPESAFE_API_KEY = "test_key_xyz"
    settings.SIMULATION_MODE = False

    mock_jev_response = {
        "model": "jev-latest",
        "answers": {
            "is_suspicious": {"type": "noul", "noul": 0.97},
            "threat_category": {"type": "choice", "choice": "c2_beacon", "confidence": 0.94, "probabilities": {"c2_beacon": 0.94}},
            "severity": {"type": "score", "score": 3.9, "confidence": 0.91, "legend": {}, "probabilities": {}},
        },
        "usage": {"input_tokens": 120, "output_tokens": 12},
    }

    respx.post("https://api.typesafe.ai/v1/systemone").respond(
        status_code=200, json=mock_jev_response
    )

    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    worker = JevWorker()
    worker._redis = fake_redis

    client = httpx.AsyncClient()

    c2_event = {
        "timestamp": 1727481600.0,
        "protocol": "TCP",
        "src_ip": "192.168.1.45",
        "dst_ip": "185.220.101.5",
        "dst_port": 4444,
        "domain_or_sni": "c2-checkin.dynamic-dns.net",
        "payload_snippet": "beacon 4910",
        "entropy": 4.12,
    }

    res = await worker.process_event(json.dumps(c2_event), client)
    assert res is not None
    assert res["threat_category"] == "c2_beacon"
    assert res["severity"] == 3.9
    assert res["alert_dispatched"] is True

    await client.aclose()
