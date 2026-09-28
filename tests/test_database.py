"""Tests for asynchronous SQLite database operations."""

import os
import pytest
from app import database


@pytest.mark.asyncio
async def test_database_init_and_crud(tmp_path):
    db_file = str(tmp_path / "test_sentinel.db")
    await database.init_db(db_file)

    # 1. Save Event
    event_data = {
        "timestamp": 1727481600.0,
        "protocol": "TCP",
        "src_ip": "192.168.1.50",
        "dst_ip": "185.220.101.5",
        "dst_port": 4444,
        "domain_or_sni": "c2.test.com",
        "payload_snippet": "beacon probe",
        "entropy": 4.15,
        "is_suspicious": 0.95,
        "threat_category": "c2_beacon",
        "category_confidence": 0.92,
        "severity": 3.8,
        "severity_confidence": 0.90,
        "cached": 0,
        "alert_dispatched": 1,
    }
    event_id = await database.save_event(event_data, db_file)
    assert event_id > 0

    # 2. Save Alert
    alert_data = {
        "event_id": event_id,
        "src_ip": "192.168.1.50",
        "dst_ip": "185.220.101.5",
        "threat_category": "c2_beacon",
        "severity": 3.8,
        "recipient": "security@corp.internal",
        "status": "sent",
        "resend_id": "resend_12345",
        "error_message": None,
    }
    alert_id = await database.save_alert(alert_data, db_file)
    assert alert_id > 0

    # 3. Retrieve recent events
    recent_events = await database.get_recent_events(limit=10, db_path=db_file)
    assert len(recent_events) == 1
    assert recent_events[0]["src_ip"] == "192.168.1.50"
    assert recent_events[0]["threat_category"] == "c2_beacon"

    # 4. Retrieve recent alerts
    recent_alerts = await database.get_recent_alerts(limit=10, db_path=db_file)
    assert len(recent_alerts) == 1
    assert recent_alerts[0]["resend_id"] == "resend_12345"

    # 5. Check aggregate statistics
    stats = await database.get_stats(db_path=db_file)
    assert stats["total_events"] == 1
    assert stats["total_threats"] == 1
    assert stats["total_alerts_sent"] == 1
    assert stats["category_counts"]["c2_beacon"] == 1
