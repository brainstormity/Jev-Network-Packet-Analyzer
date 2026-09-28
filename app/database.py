"""Async SQLite storage for events and alerts using aiosqlite."""

import logging
from typing import Any, Dict, List, Optional
import aiosqlite
from app.config import settings

logger = logging.getLogger(__name__)

CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    protocol TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER,
    domain_or_sni TEXT,
    payload_snippet TEXT,
    entropy REAL,
    is_suspicious REAL,
    threat_category TEXT,
    category_confidence REAL,
    severity REAL,
    severity_confidence REAL,
    cached INTEGER DEFAULT 0,
    alert_dispatched INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_threat ON events(threat_category);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    src_ip TEXT NOT NULL,
    dst_ip TEXT,
    threat_category TEXT NOT NULL,
    severity REAL NOT NULL,
    recipient TEXT NOT NULL,
    status TEXT NOT NULL,
    resend_id TEXT,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(event_id) REFERENCES events(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
"""


async def init_db(db_path: Optional[str] = None) -> None:
    """Initialize SQLite tables and indexes."""
    path = db_path or settings.DATABASE_PATH
    async with aiosqlite.connect(path) as db:
        await db.executescript(CREATE_TABLES_SQL)
        await db.commit()
    logger.info("Initialized database at %s", path)


async def save_event(event: Dict[str, Any], db_path: Optional[str] = None) -> int:
    """Save an evaluated network event to SQLite and return its new row ID."""
    path = db_path or settings.DATABASE_PATH
    sql = """
    INSERT INTO events (
        timestamp, protocol, src_ip, dst_ip, dst_port,
        domain_or_sni, payload_snippet, entropy,
        is_suspicious, threat_category, category_confidence,
        severity, severity_confidence, cached, alert_dispatched
    ) VALUES (
        :timestamp, :protocol, :src_ip, :dst_ip, :dst_port,
        :domain_or_sni, :payload_snippet, :entropy,
        :is_suspicious, :threat_category, :category_confidence,
        :severity, :severity_confidence, :cached, :alert_dispatched
    )
    """
    params = {
        "timestamp": float(event.get("timestamp", 0.0)),
        "protocol": str(event.get("protocol", "TCP")),
        "src_ip": str(event.get("src_ip", "")),
        "dst_ip": str(event.get("dst_ip", "")),
        "dst_port": int(event.get("dst_port", 0)) if event.get("dst_port") is not None else None,
        "domain_or_sni": event.get("domain_or_sni"),
        "payload_snippet": event.get("payload_snippet"),
        "entropy": float(event.get("entropy", 0.0)) if event.get("entropy") is not None else 0.0,
        "is_suspicious": float(event.get("is_suspicious", 0.0)) if event.get("is_suspicious") is not None else 0.0,
        "threat_category": str(event.get("threat_category", "benign")),
        "category_confidence": float(event.get("category_confidence", 1.0)) if event.get("category_confidence") is not None else 1.0,
        "severity": float(event.get("severity", 0.0)) if event.get("severity") is not None else 0.0,
        "severity_confidence": float(event.get("severity_confidence", 1.0)) if event.get("severity_confidence") is not None else 1.0,
        "cached": 1 if event.get("cached") else 0,
        "alert_dispatched": 1 if event.get("alert_dispatched") else 0,
    }

    async with aiosqlite.connect(path) as db:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.lastrowid or 0


async def save_alert(alert: Dict[str, Any], db_path: Optional[str] = None) -> int:
    """Save an alert dispatch record to SQLite and return its row ID."""
    path = db_path or settings.DATABASE_PATH
    sql = """
    INSERT INTO alerts (
        event_id, src_ip, dst_ip, threat_category, severity,
        recipient, status, resend_id, error_message
    ) VALUES (
        :event_id, :src_ip, :dst_ip, :threat_category, :severity,
        :recipient, :status, :resend_id, :error_message
    )
    """
    params = {
        "event_id": alert.get("event_id"),
        "src_ip": str(alert.get("src_ip", "")),
        "dst_ip": alert.get("dst_ip"),
        "threat_category": str(alert.get("threat_category", "unknown")),
        "severity": float(alert.get("severity", 0.0)),
        "recipient": str(alert.get("recipient", settings.ALERT_RECIPIENT)),
        "status": str(alert.get("status", "sent")),
        "resend_id": alert.get("resend_id"),
        "error_message": alert.get("error_message"),
    }

    async with aiosqlite.connect(path) as db:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.lastrowid or 0


async def get_recent_events(limit: int = 100, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch recent evaluated events in reverse chronological order."""
    path = db_path or settings.DATABASE_PATH
    sql = """
    SELECT
        id, timestamp, protocol, src_ip, dst_ip, dst_port,
        domain_or_sni, payload_snippet, entropy,
        is_suspicious, threat_category, category_confidence,
        severity, severity_confidence, cached, alert_dispatched,
        created_at
    FROM events
    ORDER BY id DESC
    LIMIT ?
    """
    async with aiosqlite.connect(path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def get_recent_alerts(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch recent alert records."""
    path = db_path or settings.DATABASE_PATH
    sql = """
    SELECT
        id, event_id, src_ip, dst_ip, threat_category, severity,
        recipient, status, resend_id, error_message, created_at
    FROM alerts
    ORDER BY id DESC
    LIMIT ?
    """
    async with aiosqlite.connect(path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def get_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Calculate aggregate telemetry metrics from SQLite."""
    path = db_path or settings.DATABASE_PATH
    async with aiosqlite.connect(path) as db:
        # Total events
        async with db.execute("SELECT COUNT(*) FROM events") as cursor:
            total_events = (await cursor.fetchone())[0]

        # Total cached events
        async with db.execute("SELECT COUNT(*) FROM events WHERE cached = 1") as cursor:
            total_cached = (await cursor.fetchone())[0]

        # Total threats (threat_category != 'benign' or is_suspicious >= 0.85)
        async with db.execute(
            "SELECT COUNT(*) FROM events WHERE threat_category != 'benign' OR is_suspicious >= ?",
            (settings.ALERT_THRESHOLD_NOUL,),
        ) as cursor:
            total_threats = (await cursor.fetchone())[0]

        # Total alerts dispatched
        async with db.execute("SELECT COUNT(*) FROM alerts WHERE status = 'sent'") as cursor:
            total_alerts_sent = (await cursor.fetchone())[0]

        # Category breakdown
        async with db.execute(
            "SELECT threat_category, COUNT(*) FROM events GROUP BY threat_category"
        ) as cursor:
            rows = await cursor.fetchall()
            category_counts = {row[0]: row[1] for row in rows}

        # Severity breakdown
        async with db.execute(
            "SELECT CAST(ROUND(severity) AS INTEGER) AS sev, COUNT(*) FROM events GROUP BY sev"
        ) as cursor:
            rows = await cursor.fetchall()
            severity_counts = {int(row[0]): row[1] for row in rows if row[0] is not None}

    cache_hit_ratio = (
        round((total_cached / total_events) * 100, 1) if total_events > 0 else 0.0
    )

    return {
        "total_events": total_events,
        "total_cached": total_cached,
        "total_threats": total_threats,
        "total_alerts_sent": total_alerts_sent,
        "cache_hit_ratio": cache_hit_ratio,
        "category_counts": category_counts,
        "severity_counts": severity_counts,
    }
