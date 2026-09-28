"""Tests for Resend email notification engine and cooldown anti-spam throttling."""

import pytest
import fakeredis.aioredis
import httpx
import respx

from app.config import settings
from app.notifier import (
    dispatch_alert,
    generate_alert_html,
    generate_startup_html,
    send_startup_notification,
)
from app import database


def test_generate_alert_html():
    event = {
        "threat_category": "c2_beacon",
        "severity": 3.8,
        "is_suspicious": 0.95,
        "src_ip": "192.168.1.45",
        "dst_ip": "185.220.101.5",
        "dst_port": 4444,
        "protocol": "TCP",
        "domain_or_sni": "c2-checkin.dynamic-dns.net",
        "entropy": 4.12,
        "payload_snippet": "GET /beacon?id=4910",
    }
    content = generate_alert_html(event)
    assert "C2_BEACON" in content
    assert "3.8" in content
    assert "192.168.1.45" in content
    assert "c2-checkin.dynamic-dns.net" in content


@pytest.mark.asyncio
async def test_alert_cooldown_throttling(tmp_path):
    db_file = str(tmp_path / "test_notifier.db")
    await database.init_db(db_file)
    settings.DATABASE_PATH = db_file

    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    event = {
        "src_ip": "10.0.0.99",
        "dst_ip": "198.51.100.1",
        "threat_category": "exploit_attempt",
        "severity": 4.0,
        "is_suspicious": 0.99,
        "id": 1,
    }

    # First dispatch -> mock_sent or sent
    res1 = await dispatch_alert(event, fake_redis)
    assert res1.get("status") in ("sent", "mock_sent")

    # Cooldown key must be active in Redis
    cooldown_key = f"{settings.REDIS_ALERT_COOLDOWN_PREFIX}10.0.0.99:exploit_attempt"
    assert await fake_redis.get(cooldown_key) == "1"

    # Second immediate dispatch -> MUST be throttled
    res2 = await dispatch_alert(event, fake_redis)
    assert res2.get("status") == "throttled"
    assert res2.get("cooldown") is True


@pytest.mark.asyncio
@respx.mock
async def test_resend_api_dispatch_success(tmp_path):
    db_file = str(tmp_path / "test_notifier_resend.db")
    await database.init_db(db_file)
    settings.DATABASE_PATH = db_file
    settings.RESEND_API_KEY = "re_test_real_key_123"

    respx.post("https://api.resend.com/emails").respond(
        status_code=200, json={"id": "email_abc_789"}
    )

    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    event = {
        "src_ip": "192.168.1.88",
        "dst_ip": "203.0.113.5",
        "threat_category": "dns_tunneling",
        "severity": 3.6,
        "is_suspicious": 0.92,
        "id": 2,
    }

    async with httpx.AsyncClient() as client:
        res = await dispatch_alert(event, fake_redis, client)
        assert res.get("status") == "sent"
        assert res.get("resend_id") == "email_abc_789"


def test_generate_startup_html():
    html_content = generate_startup_html()
    assert "SYSTEM ONLINE" in html_content
    assert "NetworkSentinel Started Successfully" in html_content
    assert settings.ALERT_RECIPIENT in html_content


@pytest.mark.asyncio
@respx.mock
async def test_send_startup_notification_success(tmp_path):
    db_file = str(tmp_path / "test_startup.db")
    await database.init_db(db_file)
    settings.DATABASE_PATH = db_file
    settings.RESEND_API_KEY = "re_test_startup_key"

    respx.post("https://api.resend.com/emails").respond(
        status_code=200, json={"id": "startup_email_123"}
    )

    async with httpx.AsyncClient() as client:
        res = await send_startup_notification(client)
        assert res.get("status") == "sent"
        assert res.get("resend_id") == "startup_email_123"

    alerts = await database.get_recent_alerts(limit=5, db_path=db_file)
    assert len(alerts) == 1
    assert alerts[0]["threat_category"] == "SYSTEM_STARTUP"
    assert alerts[0]["resend_id"] == "startup_email_123"
