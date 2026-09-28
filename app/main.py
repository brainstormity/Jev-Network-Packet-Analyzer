"""FastAPI application, REST API endpoints, and real-time WebSocket broadcaster."""

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import redis.asyncio as aioredis

from app.capture import CaptureEngine
from app.config import settings
from app import database
from app import notifier
from app.worker import JevWorker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("network_sentinel")

# Path definitions
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)


class ConnectionManager:
    """Manages active browser WebSocket connections for real-time live telemetry streaming."""

    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info("WebSocket client connected. Active: %d", len(self.active_connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self.active_connections.discard(websocket)
        logger.info("WebSocket client disconnected. Active: %d", len(self.active_connections))

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast JSON message to all active WebSocket clients."""
        async with self._lock:
            clients = list(self.active_connections)

        if not clients:
            return

        dead_clients: List[WebSocket] = []
        for connection in clients:
            try:
                await connection.send_json(message)
            except Exception:
                dead_clients.append(connection)

        if dead_clients:
            async with self._lock:
                for dead in dead_clients:
                    self.active_connections.discard(dead)


manager = ConnectionManager()


async def redis_pubsub_listener(app: FastAPI) -> None:
    """Listen to Redis Pub/Sub channel 'net:classified' and broadcast events over WebSockets."""
    redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(settings.REDIS_PUB_SUB_CHANNEL)
    logger.info("Subscribed to Redis Pub/Sub channel: %s", settings.REDIS_PUB_SUB_CHANNEL)

    try:
        async for message in pubsub.listen():
            if message and message.get("type") == "message":
                try:
                    data = json.loads(message["data"])
                    await manager.broadcast({"type": "packet_event", "data": data})
                except Exception as e:
                    logger.debug("Failed broadcasting Pub/Sub event: %s", e)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.warning("PubSub listener error: %s", e)
    finally:
        try:
            await pubsub.unsubscribe(settings.REDIS_PUB_SUB_CHANNEL)
            await pubsub.close()
            await redis_client.aclose()
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager: startup and shutdown services."""
    logger.info("Initializing NetworkSentinel system...")

    # 1. Initialize SQLite Database
    await database.init_db()

    # 2. Start Capture Engine
    capture_engine = CaptureEngine()
    if not settings.SIMULATION_MODE:
        capture_engine.start()
    app.state.capture_engine = capture_engine

    # 3. Start Jev Triage Worker
    worker = JevWorker()
    worker.start()
    app.state.worker = worker

    # 4. Start Redis Pub/Sub WebSocket Broadcaster
    pubsub_task = asyncio.create_task(redis_pubsub_listener(app))
    app.state.pubsub_task = pubsub_task

    # 5. Dispatch one-time startup notification email to verify Resend service
    asyncio.create_task(notifier.send_startup_notification())

    logger.info("NetworkSentinel services are online.")
    yield

    # Shutdown sequence
    logger.info("Shutting down NetworkSentinel services...")
    pubsub_task.cancel()
    try:
        await pubsub_task
    except asyncio.CancelledError:
        pass

    await worker.stop()
    capture_engine.stop()
    logger.info("NetworkSentinel shut down successfully.")


app = FastAPI(
    title="NetworkSentinel - Jev System One Edition",
    description="Real-Time Network Telemetry Triage & Threat Alerting System powered by TypeSafe AI",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Simulation Request Model ---
class SimulatePacketRequest(BaseModel):
    scenario: str = "c2_beacon"  # benign, c2_beacon, dns_tunneling, exploit_attempt, reconnaissance
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    domain_or_sni: Optional[str] = None
    payload_snippet: Optional[str] = None


# --- Web Page Route ---
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request) -> Any:
    """Serve single-page cyber-security dashboard."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "jev_configured": settings.is_jev_configured,
            "resend_configured": settings.is_resend_configured,
            "jev_model": settings.JEV_MODEL,
            "bpf_filter": settings.BPF_FILTER,
            "capture_interface": settings.CAPTURE_INTERFACE or "Auto-Detect",
        },
    )


# --- REST API Endpoints ---
@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Health status check of Redis, Capture Engine, Worker, and API integrations."""
    redis_healthy = False
    redis_ping_latency = -1.0
    try:
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        t0 = time.monotonic()
        await r.ping()
        redis_ping_latency = round((time.monotonic() - t0) * 1000, 2)
        redis_healthy = True
        await r.aclose()
    except Exception:
        redis_healthy = False

    capture_engine = getattr(app.state, "capture_engine", None)
    is_sniffing = capture_engine.is_running if capture_engine else False

    return {
        "status": "healthy" if redis_healthy else "degraded",
        "redis": {
            "connected": redis_healthy,
            "latency_ms": redis_ping_latency,
        },
        "capture": {
            "running": is_sniffing,
            "interface": settings.CAPTURE_INTERFACE or "default",
            "filter": settings.BPF_FILTER,
            "packets_captured": capture_engine.packet_count if capture_engine else 0,
        },
        "integrations": {
            "jev_api_configured": settings.is_jev_configured,
            "resend_api_configured": settings.is_resend_configured,
            "model": settings.JEV_MODEL,
        },
    }


@app.get("/api/stats")
async def get_dashboard_stats() -> Dict[str, Any]:
    """Return live KPI statistics aggregated from Redis and SQLite."""
    # Pull stats from SQLite
    db_stats = await database.get_stats()

    # Pull real-time counters from Redis
    try:
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        captured = int(await r.get("net:stats:captured") or 0)
        evaluated = int(await r.get("net:stats:evaluated") or 0)
        threats = int(await r.get("net:stats:threats") or 0)
        cached = int(await r.get("net:stats:cached") or 0)
        await r.aclose()
    except Exception:
        captured = db_stats["total_events"]
        evaluated = db_stats["total_events"]
        threats = db_stats["total_threats"]
        cached = db_stats["total_cached"]

    # Use max to reflect combination of persistent and active counters
    total_captured = max(captured, db_stats["total_events"])
    total_evaluated = max(evaluated, db_stats["total_events"])
    total_threats = max(threats, db_stats["total_threats"])
    total_cached = max(cached, db_stats["total_cached"])

    hit_ratio = round((total_cached / total_evaluated * 100), 1) if total_evaluated > 0 else 0.0

    return {
        "packets_captured": total_captured,
        "evaluated_by_jev": total_evaluated,
        "active_threats": total_threats,
        "cache_hits": total_cached,
        "cache_hit_ratio": hit_ratio,
        "alerts_dispatched": db_stats["total_alerts_sent"],
        "category_counts": db_stats["category_counts"],
        "severity_counts": db_stats["severity_counts"],
        "active_ws_connections": len(manager.active_connections),
    }


@app.get("/api/events")
async def get_events(
    limit: int = Query(default=50, ge=1, le=500),
    threats_only: bool = Query(default=False),
    category: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """Retrieve recent network events evaluated by Jev with optional category/threat/search filtering."""
    return await database.get_recent_events(
        limit=limit,
        threats_only=threats_only,
        category=category,
        search=search,
    )


@app.get("/api/alerts")
async def get_alerts(limit: int = Query(default=30, ge=1, le=200)) -> List[Dict[str, Any]]:
    """Retrieve recent alerts dispatched or throttled."""
    return await database.get_recent_alerts(limit=limit)


@app.get("/api/alerts/{alert_id}")
async def get_alert_detail(alert_id: int) -> Dict[str, Any]:
    """Retrieve comprehensive details of a specific alert with associated telemetry log."""
    alert = await database.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert record not found")
    return alert


@app.get("/api/events/{event_id}")
async def get_event_detail(event_id: int) -> Dict[str, Any]:
    """Retrieve comprehensive details of a specific evaluated network event."""
    event = await database.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event log record not found")
    return event


@app.post("/api/simulate")
async def simulate_event(req: SimulatePacketRequest) -> Dict[str, Any]:
    """Inject a pre-crafted or custom packet scenario for interactive testing and demonstration."""
    now = time.time()
    scenarios = {
        "benign": {
            "timestamp": now,
            "protocol": "TCP",
            "src_ip": req.src_ip or "192.168.1.105",
            "dst_ip": req.dst_ip or "142.250.190.46",
            "dst_port": req.dst_port or 443,
            "domain_or_sni": req.domain_or_sni or "fonts.googleapis.com",
            "payload_snippet": req.payload_snippet or "GET /css2?family=Inter:wght@400;600 HTTP/1.1\r\nHost: fonts.googleapis.com",
            "entropy": 3.12,
        },
        "c2_beacon": {
            "timestamp": now,
            "protocol": "TCP",
            "src_ip": req.src_ip or "192.168.1.45",
            "dst_ip": req.dst_ip or "185.220.101.5",
            "dst_port": req.dst_port or 4444,
            "domain_or_sni": req.domain_or_sni or "c2-checkin.dynamic-dns.net",
            "payload_snippet": req.payload_snippet or "GET /beacon?id=4910&stage=2 HTTP/1.1\r\nUser-Agent: curl/7.88.1\r\nHost: c2-checkin.dynamic-dns.net",
            "entropy": 4.12,
        },
        "dns_tunneling": {
            "timestamp": now,
            "protocol": "UDP",
            "src_ip": req.src_ip or "10.0.4.12",
            "dst_ip": req.dst_ip or "198.51.100.53",
            "dst_port": req.dst_port or 53,
            "domain_or_sni": req.domain_or_sni or "a83f9b2d7e10c4a9.exfil.darkops.io",
            "payload_snippet": req.payload_snippet or "\x00\x01\x01\x00\x00\x01a83f9b2d7e10c4a9\x05exfil\x07darkops\x02io",
            "entropy": 5.84,
        },
        "exploit_attempt": {
            "timestamp": now,
            "protocol": "TCP",
            "src_ip": req.src_ip or "45.33.32.156",
            "dst_ip": req.dst_ip or "192.168.1.10",
            "dst_port": req.dst_port or 80,
            "domain_or_sni": req.domain_or_sni or "internal-api.corp",
            "payload_snippet": req.payload_snippet or "GET /api/user?id=1' UNION SELECT username,password FROM users-- HTTP/1.1",
            "entropy": 4.65,
        },
        "reconnaissance": {
            "timestamp": now,
            "protocol": "TCP",
            "src_ip": req.src_ip or "91.240.118.172",
            "dst_ip": req.dst_ip or "192.168.1.1",
            "dst_port": req.dst_port or 22,
            "domain_or_sni": req.domain_or_sni or "",
            "payload_snippet": req.payload_snippet or "SSH-2.0-Nmap-SSH-Scan-Probe",
            "entropy": 2.45,
        },
    }

    packet_data = scenarios.get(req.scenario)
    if not packet_data:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario '{req.scenario}'. Choose from: {list(scenarios.keys())}",
        )
    packet_data["is_simulated"] = True

    # Push to Redis Raw Queue
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    await r.lpush(settings.REDIS_RAW_QUEUE, json.dumps(packet_data))
    await r.incr("net:stats:captured")
    await r.aclose()

    return {
        "status": "queued",
        "scenario": req.scenario,
        "event": packet_data,
    }


# --- WebSocket Live Events Stream ---
@app.websocket("/ws/live-events")
async def websocket_live_events(websocket: WebSocket) -> None:
    """Real-time bi-directional WebSocket connection for live telemetry streaming."""
    await manager.connect(websocket)

    # Send initial connection handshake and baseline stats
    try:
        stats = await get_dashboard_stats()
        await websocket.send_json({
            "type": "handshake",
            "message": "Connected to NetworkSentinel Jev Telemetry Feed",
            "stats": stats,
        })

        # Keep connection alive and process incoming client messages/filters
        while True:
            data = await websocket.receive_text()
            # Respond to client ping/heartbeat
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.debug("WebSocket error: %s", e)
        await manager.disconnect(websocket)
