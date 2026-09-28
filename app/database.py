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
    is_simulated INTEGER DEFAULT 0,
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
    is_simulated INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(event_id) REFERENCES events(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_cooldown ON alerts(src_ip, threat_category, created_at);
"""


async def init_db(db_path: Optional[str] = None) -> None:
    """Initialize SQLite tables and indexes."""
    path = db_path or settings.DATABASE_PATH
    async with aiosqlite.connect(path) as db:
        await db.executescript(CREATE_TABLES_SQL)
        try:
            await db.execute("ALTER TABLE events ADD COLUMN is_simulated INTEGER DEFAULT 0")
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE alerts ADD COLUMN is_simulated INTEGER DEFAULT 0")
        except Exception:
            pass
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
        severity, severity_confidence, cached, alert_dispatched,
        is_simulated
    ) VALUES (
        :timestamp, :protocol, :src_ip, :dst_ip, :dst_port,
        :domain_or_sni, :payload_snippet, :entropy,
        :is_suspicious, :threat_category, :category_confidence,
        :severity, :severity_confidence, :cached, :alert_dispatched,
        :is_simulated
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
        "is_simulated": 1 if event.get("is_simulated") else 0,
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
        recipient, status, resend_id, error_message, is_simulated
    ) VALUES (
        :event_id, :src_ip, :dst_ip, :threat_category, :severity,
        :recipient, :status, :resend_id, :error_message, :is_simulated
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
        "is_simulated": 1 if alert.get("is_simulated") else 0,
    }

    async with aiosqlite.connect(path) as db:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.lastrowid or 0


async def is_alert_in_cooldown(
    src_ip: str,
    threat_category: str,
    cooldown_seconds: int = 300,
    db_path: Optional[str] = None,
) -> bool:
    """Check if an alert for this src_ip and threat_category was already dispatched recently in SQLite."""
    path = db_path or settings.DATABASE_PATH
    sql = """
    SELECT id FROM alerts
    WHERE LOWER(src_ip) = LOWER(?)
      AND LOWER(threat_category) = LOWER(?)
      AND status IN ('sent', 'mock_sent')
      AND (strftime('%s', 'now') - strftime('%s', created_at)) < ?
    ORDER BY id DESC
    LIMIT 1
    """
    try:
        async with aiosqlite.connect(path) as db:
            async with db.execute(
                sql, (src_ip.strip(), threat_category.strip(), cooldown_seconds)
            ) as cursor:
                row = await cursor.fetchone()
                return row is not None
    except Exception as e:
        logger.warning("Error checking DB alert cooldown: %s", e)
        return False


async def get_recent_events(
    limit: int = 100,
    threats_only: bool = False,
    category: Optional[str] = None,
    search: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch recent evaluated events in reverse chronological order with optional filtering."""
    path = db_path or settings.DATABASE_PATH
    conditions: List[str] = []
    params: List[Any] = []

    if threats_only:
        conditions.append("(LOWER(threat_category) != 'benign' OR is_suspicious >= ? OR severity >= 3.0)")
        params.append(settings.ALERT_THRESHOLD_NOUL)

    if category and category.lower() not in ("all", "threats"):
        conditions.append("LOWER(threat_category) = ?")
        params.append(category.lower())

    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        conditions.append(
            "(LOWER(src_ip) LIKE ? OR LOWER(dst_ip) LIKE ? OR LOWER(COALESCE(domain_or_sni, '')) LIKE ? OR LOWER(COALESCE(payload_snippet, '')) LIKE ?)"
        )
        params.extend([term, term, term, term])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
    SELECT
        id, timestamp, protocol, src_ip, dst_ip, dst_port,
        domain_or_sni, payload_snippet, entropy,
        is_suspicious, threat_category, category_confidence,
        severity, severity_confidence, cached, alert_dispatched,
        is_simulated,
        created_at
    FROM events
    {where_clause}
    ORDER BY id DESC
    LIMIT ?
    """
    params.append(limit)

    async with aiosqlite.connect(path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, tuple(params)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def get_recent_alerts(
    limit: int = 50,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch recent alert records joined with their associated event telemetry with optional filtering."""
    path = db_path or settings.DATABASE_PATH
    conditions: List[str] = []
    params: List[Any] = []

    if status and status.lower() not in ("all", ""):
        if status.lower() == "drills":
            conditions.append("(a.is_simulated = 1 OR COALESCE(e.is_simulated, 0) = 1)")
        elif status.lower() == "sent":
            conditions.append("a.status IN ('sent', 'mock_sent')")
        else:
            conditions.append("LOWER(a.status) = ?")
            params.append(status.lower())

    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        conditions.append(
            "(LOWER(a.src_ip) LIKE ? OR LOWER(COALESCE(a.dst_ip, '')) LIKE ? OR LOWER(a.threat_category) LIKE ? OR LOWER(COALESCE(a.resend_id, '')) LIKE ? OR LOWER(COALESCE(e.payload_snippet, '')) LIKE ?)"
        )
        params.extend([term, term, term, term, term])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
    SELECT
        a.id, a.event_id, a.src_ip, a.dst_ip, a.threat_category, a.severity,
        a.recipient, a.status, a.resend_id, a.error_message,
        COALESCE(a.is_simulated, e.is_simulated, 0) as is_simulated,
        a.created_at,
        e.timestamp as event_timestamp, e.protocol, e.dst_port, e.domain_or_sni,
        e.payload_snippet, e.entropy, e.is_suspicious, e.category_confidence,
        e.severity_confidence, e.cached, e.alert_dispatched
    FROM alerts a
    LEFT JOIN events e ON a.event_id = e.id
    {where_clause}
    ORDER BY a.id DESC
    LIMIT ?
    """
    params.append(limit)

    async with aiosqlite.connect(path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, tuple(params)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def get_alert_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Calculate aggregate statistics specifically for alert dispatches."""
    path = db_path or settings.DATABASE_PATH
    async with aiosqlite.connect(path) as db:
        async with db.execute("SELECT COUNT(*) FROM alerts") as cur:
            total = (await cur.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('sent', 'mock_sent')") as cur:
            sent = (await cur.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM alerts WHERE status = 'throttled'") as cur:
            throttled = (await cur.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM alerts WHERE is_simulated = 1") as cur:
            drills = (await cur.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM alerts WHERE severity >= 3.5") as cur:
            critical = (await cur.fetchone())[0]

        return {
            "total_alerts": total,
            "alerts_sent": sent,
            "alerts_throttled": throttled,
            "alerts_drills": drills,
            "alerts_critical": critical,
        }


async def get_alert_by_id(alert_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetch a single alert by ID with its associated telemetry event log."""
    path = db_path or settings.DATABASE_PATH
    sql = """
    SELECT
        a.id, a.event_id, a.src_ip, a.dst_ip, a.threat_category, a.severity,
        a.recipient, a.status, a.resend_id, a.error_message,
        COALESCE(a.is_simulated, e.is_simulated, 0) as is_simulated,
        a.created_at,
        e.timestamp as event_timestamp, e.protocol, e.dst_port, e.domain_or_sni,
        e.payload_snippet, e.entropy, e.is_suspicious, e.category_confidence,
        e.severity_confidence, e.cached, e.alert_dispatched
    FROM alerts a
    LEFT JOIN events e ON a.event_id = e.id
    WHERE a.id = ?
    """
    async with aiosqlite.connect(path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, (alert_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def get_event_by_id(event_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetch a single telemetry event by ID."""
    path = db_path or settings.DATABASE_PATH
    sql = """
    SELECT
        id, timestamp, protocol, src_ip, dst_ip, dst_port,
        domain_or_sni, payload_snippet, entropy,
        is_suspicious, threat_category, category_confidence,
        severity, severity_confidence, cached, alert_dispatched,
        is_simulated,
        created_at
    FROM events
    WHERE id = ?
    """
    async with aiosqlite.connect(path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, (event_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


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
