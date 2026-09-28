"""Tests for FastAPI endpoints and WebSocket interface."""

import asyncio
import pytest
from httpx import ASGITransport, AsyncClient
import fakeredis.aioredis

from app.config import settings
from app.main import app
from app import database


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    orig_sim = settings.SIMULATION_MODE
    orig_db = settings.DATABASE_PATH
    db_file = str(tmp_path / "test_api.db")
    asyncio.run(database.init_db(db_file))
    settings.DATABASE_PATH = db_file
    settings.SIMULATION_MODE = True

    # Use fake redis for app
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr("redis.asyncio.from_url", lambda *args, **kwargs: fake_redis)

    yield

    settings.SIMULATION_MODE = orig_sim
    settings.DATABASE_PATH = orig_db


@pytest.mark.asyncio
async def test_dashboard_home_page():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/")
        assert res.status_code == 200
        assert "NetworkSentinel" in res.text
        assert "Jev System One" in res.text
        assert "Live Packet Triage Feed" in res.text


@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert "redis" in data
        assert "capture" in data
        assert "integrations" in data


@pytest.mark.asyncio
async def test_stats_and_simulate_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Simulate packet
        sim_res = await client.post("/api/simulate", json={"scenario": "c2_beacon"})
        assert sim_res.status_code == 200
        sim_data = sim_res.json()
        assert sim_data["status"] == "queued"
        assert sim_data["scenario"] == "c2_beacon"

        # Check stats
        stats_res = await client.get("/api/stats")
        assert stats_res.status_code == 200
        stats = stats_res.json()
        assert "packets_captured" in stats
        assert "evaluated_by_jev" in stats
        assert "cache_hit_ratio" in stats


@pytest.mark.asyncio
async def test_events_and_alerts_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        events_res = await client.get("/api/events?limit=10")
        assert events_res.status_code == 200
        assert isinstance(events_res.json(), list)

        alerts_res = await client.get("/api/alerts?limit=10")
        assert alerts_res.status_code == 200
        assert isinstance(alerts_res.json(), list)

        # 404 tests
        not_found_alert = await client.get("/api/alerts/99999")
        assert not_found_alert.status_code == 404

        not_found_event = await client.get("/api/events/99999")
        assert not_found_event.status_code == 404

        # Insert and test specific alert/event fetch
        event_id = await database.save_event({
            "timestamp": 1727481600.0,
            "protocol": "TCP",
            "src_ip": "192.168.1.45",
            "dst_ip": "185.220.101.5",
            "dst_port": 4444,
            "domain_or_sni": "c2-checkin.dynamic-dns.net",
            "payload_snippet": "GET /beacon?id=4910&stage=2",
            "entropy": 4.12,
            "is_suspicious": 0.96,
            "threat_category": "c2_beacon",
            "category_confidence": 0.94,
            "severity": 3.65,
            "severity_confidence": 0.92,
            "cached": 0,
            "alert_dispatched": 1,
        })
        alert_id = await database.save_alert({
            "event_id": event_id,
            "src_ip": "192.168.1.45",
            "dst_ip": "185.220.101.5",
            "threat_category": "c2_beacon",
            "severity": 3.65,
            "recipient": "security@corp.internal",
            "status": "sent",
            "resend_id": "resend_c2_test",
        })

        fetch_alert = await client.get(f"/api/alerts/{alert_id}")
        assert fetch_alert.status_code == 200
        data = fetch_alert.json()
        assert data["threat_category"] == "c2_beacon"
        assert data["payload_snippet"] == "GET /beacon?id=4910&stage=2"
        assert data["dst_port"] == 4444

        fetch_event = await client.get(f"/api/events/{event_id}")
        assert fetch_event.status_code == 200
        e_data = fetch_event.json()
        assert e_data["src_ip"] == "192.168.1.45"
        assert e_data["domain_or_sni"] == "c2-checkin.dynamic-dns.net"

        # Test filtering on /api/events
        threats_res = await client.get("/api/events?threats_only=true")
        assert threats_res.status_code == 200
        assert len(threats_res.json()) >= 1

        cat_res = await client.get("/api/events?category=c2_beacon")
        assert cat_res.status_code == 200
        assert len(cat_res.json()) >= 1
        assert cat_res.json()[0]["threat_category"] == "c2_beacon"

        search_res = await client.get("/api/events?search=4910")
        assert search_res.status_code == 200
        assert len(search_res.json()) >= 1
        assert "4910" in search_res.json()[0]["payload_snippet"]
