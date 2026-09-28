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
