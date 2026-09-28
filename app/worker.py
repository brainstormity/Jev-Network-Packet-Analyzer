"""Redis consumer, Token Bucket rate pacer, and TypeSafe Jev System One triage worker."""

import asyncio
import ipaddress
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx
import redis.asyncio as aioredis

from app.config import settings
from app import database
from app import notifier

logger = logging.getLogger(__name__)

# Jev question configuration schema adhering to wire specifications
JEV_QUESTIONS = {
    "is_suspicious": {
        "type": "noul",
        "instructions": (
            "Does this network event indicate malicious behavior, exploit activity, "
            "unauthorized tunneling, or C2 beaconing?"
        ),
    },
    "threat_category": {
        "type": "choice",
        "instructions": "Categorize the threat classification of this traffic.",
        "criteria": {
            "benign": "Routine user browsing, trusted CDNs, OS telemetry, or standard developer tools.",
            "c2_beacon": "Periodic or suspicious outbound connection to an unknown external IP or dynamic DNS service without legitimate SNI.",
            "dns_tunneling": "High-entropy, encoded subdomains or data exfiltration over port 53.",
            "exploit_attempt": "SQL injection, reverse shell syntax, unauthorized command payloads, or path traversal.",
            "reconnaissance": "Port scanning, host enumeration, or abnormal flag combinations.",
        },
    },
    "severity": {
        "type": "score",
        "instructions": "Rate the operational risk of this network anomaly.",
        "criteria": [
            "0: Informational / benign",
            "1: Low - minor anomaly or atypical configuration",
            "2: Medium - unverified external connection or abnormal telemetry",
            "3: High - potential compromise, DGA domain, or active exploit probe",
            "4: Critical - confirmed exploit payload, active C2, or large exfiltration",
        ],
    },
}


class TokenBucketRateLimiter:
    """Async token bucket / rate pacer enforcing <= 18 requests per second."""

    def __init__(self, rate: float = 18.0, capacity: float = 18.0):
        self.rate = rate  # tokens added per second
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available to enforce rate limits."""
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.last_update = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return

                # Calculate required sleep duration to reach 1 token
                needed = 1.0 - self.tokens
                sleep_time = needed / self.rate
                await asyncio.sleep(sleep_time)


def simulate_jev_decision(state: Dict[str, Any]) -> Tuple[float, str, float, float, float]:
    """Smart heuristic fallback when running in mock mode or without a live API key.

    Returns: (is_suspicious, threat_category, category_confidence, severity, severity_confidence)
    """
    domain = (state.get("domain_or_sni") or "").lower()
    snippet = (state.get("payload_snippet") or "").lower()
    port = state.get("dst_port", 0)
    entropy = float(state.get("entropy", 0.0))

    # 1. Exploit attempts (SQLi, traversal, reverse shell)
    if any(k in snippet for k in ("union select", "select *", "/etc/passwd", "eval(", "/bin/sh", "cmd.exe", "<script>")):
        return 0.98, "exploit_attempt", 0.96, 4.0, 0.95

    # 2. DNS Tunneling
    if port == 53 and (entropy > 4.5 or len(domain) > 40):
        return 0.94, "dns_tunneling", 0.92, 3.4, 0.90

    # 3. C2 Beaconing
    if any(k in snippet for k in ("beacon", "c2-checkin", "uuid=", "cmd_exec", "heartbeat")) or any(
        k in domain for k in ("dynamic-dns", "duckdns", "ngrok", "c2-checkin", "evil-corp")
    ) or port in (4444, 1337, 8888, 31337):
        return 0.95, "c2_beacon", 0.94, 3.8, 0.92

    # 4. Reconnaissance / Port scanning
    if "nmap" in snippet or port in (21, 23, 135, 445, 3389) or "masscan" in snippet:
        return 0.88, "reconnaissance", 0.89, 2.7, 0.85

    # 5. Default benign
    return 0.02, "benign", 0.99, 0.0, 0.99


EXPLOIT_KEYWORDS = (
    "union select",
    "select *",
    "/etc/passwd",
    "eval(",
    "/bin/sh",
    "cmd.exe",
    "<script>",
    "../",
    "exec(",
    "system(",
    "passthru(",
)

C2_KEYWORDS = (
    "beacon",
    "c2-checkin",
    "uuid=",
    "cmd_exec",
    "heartbeat",
)

SUSPICIOUS_DOMAINS = (
    "dynamic-dns",
    "duckdns",
    "ngrok",
    "c2-checkin",
    "evil-corp",
)

SUSPICIOUS_PORTS = {21, 23, 135, 445, 1337, 3389, 4444, 6667, 8888, 31337}


def has_exploit_or_suspicion(state: Dict[str, Any]) -> bool:
    """Check if the packet state has any explicit exploit, C2, or anomaly indicators."""
    snippet = (state.get("payload_snippet") or "").lower()
    domain = (state.get("domain_or_sni") or "").lower()
    port = state.get("dst_port", 0)
    entropy = float(state.get("entropy", 0.0))

    if any(k in snippet for k in EXPLOIT_KEYWORDS):
        return True
    if any(k in snippet for k in C2_KEYWORDS):
        return True
    if any(k in domain for k in SUSPICIOUS_DOMAINS):
        return True
    if port in SUSPICIOUS_PORTS:
        return True
    if port == 53 and (entropy > 4.5 or len(domain) > 40):
        return True
    if state.get("is_simulated"):
        return True
    return False


def is_l1_bypassed_benign(state: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """L1 Deterministic Pre-Filter.

    Bypasses encrypted TLS application data streams and zero-payload TCP packets
    if they contain no exploit or anomaly signatures.
    """
    if has_exploit_or_suspicion(state):
        return False, None

    port = state.get("dst_port", 0)
    snippet = state.get("payload_snippet") or ""
    payload_len = state.get("payload_len", len(snippet))
    is_tls = state.get("is_tls_app_data", False) or snippet.startswith("\x17\x03")

    # 1. Encrypted TLS Application Data on standard TLS ports (443, 8443, etc.)
    # Ciphertext cannot be meaningfully analyzed by Jev AI and causes false flags or token waste
    if is_tls and port in (443, 8443, 993, 995, 465, 8080):
        return True, "l1_tls_app_data"

    # 2. Zero-Payload TCP control packets on routine ports (80, 443, 8080, etc.)
    if payload_len == 0 or not snippet.strip():
        if port in (80, 443, 8080, 8443, 53) or port > 1024:
            return True, "l1_zero_payload"

    return False, None


def is_private_ip(ip_str: str) -> bool:
    """Identify RFC 1918 private, loopback, or link-local IP addresses."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except (ValueError, AttributeError):
        return False


def get_flow_cache_keys(state: Dict[str, Any]) -> List[str]:
    """Generate multi-level cache keys: domain, bidirectional host flow pair, and external peer IP."""
    keys: List[str] = []
    domain = (state.get("domain_or_sni") or "").strip().lower()
    src_ip = (state.get("src_ip") or "").strip()
    dst_ip = (state.get("dst_ip") or "").strip()

    # 1. Domain cache key (e.g. cache:domain:gstatic.com)
    if domain:
        keys.append(f"{settings.REDIS_CACHE_PREFIX}{domain}")

    # 2. Bidirectional host flow pair (e.g. cache:flow:104.18.25.46:172.18.0.3)
    if src_ip and dst_ip:
        ip_pair = sorted([src_ip, dst_ip])
        keys.append(f"cache:flow:{ip_pair[0]}:{ip_pair[1]}")

    # 3. External peer IP key (if one IP is private and one is public)
    if dst_ip and not is_private_ip(dst_ip):
        keys.append(f"cache:ip:{dst_ip}")
    elif src_ip and not is_private_ip(src_ip):
        keys.append(f"cache:ip:{src_ip}")

    # Fallback to direct dst_ip for backwards compatibility
    if dst_ip and f"{settings.REDIS_CACHE_PREFIX}{dst_ip}" not in keys:
        keys.append(f"{settings.REDIS_CACHE_PREFIX}{dst_ip}")

    return keys


class JevWorker:
    """Consumes raw events from Redis, evaluates with Jev, and emits classified records."""

    def __init__(
        self,
        redis_url: Optional[str] = None,
        rate_pacer: Optional[TokenBucketRateLimiter] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self.redis_url = redis_url or settings.REDIS_URL
        self.rate_pacer = rate_pacer or TokenBucketRateLimiter(rate=18.0, capacity=18.0)
        self.http_client = http_client
        self._redis: Optional[aioredis.Redis] = None
        self._is_running = False
        self._task: Optional[asyncio.Task] = None

    async def get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(self.redis_url, decode_responses=True)
        return self._redis

    async def evaluate_with_jev(
        self, state: Dict[str, Any], client: httpx.AsyncClient
    ) -> Tuple[float, str, float, float, float]:
        """Send extracted network state to TypeSafe Jev System One API."""
        if not settings.is_jev_configured or settings.SIMULATION_MODE:
            return simulate_jev_decision(state)

        # Prepare request according to wire schema
        body = {
            "model": settings.JEV_MODEL,
            "state": json.dumps(state),
            "questions": JEV_QUESTIONS,
        }
        headers = {
            "Authorization": f"Bearer {settings.TYPESAFE_API_KEY}",
            "Content-Type": "application/json",
        }

        # Try designated Jev URL (fallback to secondary endpoint if requested)
        endpoints = [settings.JEV_API_URL]
        if "thejevai.com" not in settings.JEV_API_URL:
            endpoints.append("https://thejevai.com/v1/systemone")

        last_error = None
        for endpoint in endpoints:
            try:
                response = await client.post(endpoint, json=body, headers=headers, timeout=10.0)
                if response.status_code == 200:
                    data = response.json()
                    answers = data.get("answers", {})

                    # Parse Noul answer
                    noul_ans = answers.get("is_suspicious", {})
                    is_suspicious = float(noul_ans.get("noul", 0.0))

                    # Parse Choice answer
                    choice_ans = answers.get("threat_category", {})
                    threat_category = str(choice_ans.get("choice", "benign"))
                    category_confidence = float(choice_ans.get("confidence", 1.0))

                    # Parse Score answer
                    score_ans = answers.get("severity", {})
                    severity = float(score_ans.get("score", 0.0))
                    severity_confidence = float(score_ans.get("confidence", 1.0))

                    return (
                        is_suspicious,
                        threat_category,
                        category_confidence,
                        severity,
                        severity_confidence,
                    )
                elif response.status_code in (429, 500, 502, 503, 504):
                    logger.warning("Jev API returned status %d. Will retry or requeue.", response.status_code)
                    last_error = Exception(f"HTTP {response.status_code}: {response.text}")
                    continue
                else:
                    logger.error("Jev API client error HTTP %d: %s", response.status_code, response.text)
                    last_error = Exception(f"HTTP {response.status_code}: {response.text}")
                    break
            except Exception as e:
                logger.warning("Error contacting Jev endpoint %s: %s", endpoint, e)
                last_error = e

        if last_error:
            raise last_error
        return simulate_jev_decision(state)

    async def process_event(
        self, raw_event_str: str, client: httpx.AsyncClient
    ) -> Optional[Dict[str, Any]]:
        """Process a single event through deduplication cache, rate pacer, Jev triage, and alert dispatch."""
        r = await self.get_redis()
        try:
            state = json.loads(raw_event_str)
        except Exception:
            return None

        is_sim = bool(state.get("is_simulated", False))
        is_threat_suspect = has_exploit_or_suspicion(state)
        cache_keys = get_flow_cache_keys(state)

        cached = False
        # 1. Check Redis Deduplication Cache (skip cache if explicit exploit/threat suspect or simulated drill)
        if not is_sim and not is_threat_suspect and cache_keys:
            try:
                for ck in cache_keys:
                    cached_val = await r.get(ck)
                    if cached_val == "benign":
                        cached = True
                        await r.incr("net:stats:cached")
                        break
            except Exception as e:
                logger.debug("Redis cache check error: %s", e)

        # 2. L1 Pre-Filter & TLS Application Data bypass
        # If not already in cache, check if L1 pre-filter can resolve it as benign immediately
        if not cached and not is_sim:
            bypassed, reason = is_l1_bypassed_benign(state)
            if bypassed:
                cached = True
                await r.incr("net:stats:cached")
                # Populate Redis flow cache for this benign flow (TTL: 24 hours / 86400s)
                try:
                    for ck in cache_keys:
                        await r.set(ck, "benign", ex=86400)
                except Exception as e:
                    logger.debug("Failed populating L1 Redis flow cache: %s", e)

        if cached:
            is_suspicious = 0.01
            threat_category = "benign"
            category_confidence = 0.99
            severity = 0.0
            severity_confidence = 0.99
        else:
            # Enforce <= 18 req/sec rate limit
            await self.rate_pacer.acquire()

            try:
                (
                    is_suspicious,
                    threat_category,
                    category_confidence,
                    severity,
                    severity_confidence,
                ) = await self.evaluate_with_jev(state, client)
            except Exception as e:
                logger.warning(
                    "Jev evaluation failed for %s -> %s: %s. Requeueing event with backoff.",
                    state.get("src_ip"),
                    state.get("dst_ip"),
                    e,
                )
                # Requeue event with backoff to prevent packet loss
                requeue_count = state.get("_requeue_count", 0) + 1
                if requeue_count <= 3:
                    state["_requeue_count"] = requeue_count
                    await asyncio.sleep(1.0 * requeue_count)
                    await r.lpush(settings.REDIS_RAW_QUEUE, json.dumps(state))
                return None

            # Only increment evaluated counter when Jev AI evaluation actually occurred!
            await r.incr("net:stats:evaluated")

            # Cache benign domains and bidirectional flows with high confidence (> 0.95) for 24 hours (86400s)
            if cache_keys and threat_category == "benign" and category_confidence >= 0.95:
                try:
                    for ck in cache_keys:
                        await r.set(ck, "benign", ex=86400)
                except Exception as e:
                    logger.debug("Failed setting Redis flow cache keys: %s", e)

        # Assemble classified event record
        classified_event = {
            **state,
            "is_suspicious": is_suspicious,
            "threat_category": threat_category,
            "category_confidence": category_confidence,
            "severity": severity,
            "severity_confidence": severity_confidence,
            "cached": cached,
            "alert_dispatched": False,
            "is_simulated": bool(state.get("is_simulated", False)),
        }

        # 2. Persist to SQLite
        try:
            event_id = await database.save_event(classified_event)
            classified_event["id"] = event_id
        except Exception as e:
            logger.error("Failed persisting event to SQLite: %s", e)

        # 3. Check Alerting Thresholds
        should_alert = (
            is_suspicious >= settings.ALERT_THRESHOLD_NOUL
            and severity >= settings.ALERT_MIN_SEVERITY
            and threat_category != "benign"
        )
        if should_alert:
            await r.incr("net:stats:threats")
            classified_event["alert_dispatched"] = True
            # Non-blocking email dispatch with cooldown
            asyncio.create_task(notifier.dispatch_alert(classified_event, r, client))

        # 4. Emit classified result to Redis Pub/Sub for WebSockets
        try:
            await r.publish(settings.REDIS_PUB_SUB_CHANNEL, json.dumps(classified_event))
        except Exception as e:
            logger.warning("Failed publishing event to Pub/Sub: %s", e)

        return classified_event

    async def _worker_loop(self) -> None:
        """Main consumer loop popping events from Redis."""
        logger.info("Jev System One triage worker started. Polling %s...", settings.REDIS_RAW_QUEUE)
        r = await self.get_redis()

        own_client = False
        client = self.http_client
        if client is None:
            client = httpx.AsyncClient(timeout=10.0)
            own_client = True

        try:
            while self._is_running:
                try:
                    # BRPOP with 1-second timeout so the loop can check self._is_running
                    pop_result = await r.brpop(settings.REDIS_RAW_QUEUE, timeout=1)
                    if pop_result is not None:
                        _, raw_event_str = pop_result
                        await self.process_event(raw_event_str, client)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error("Error in JevWorker loop: %s", e)
                    await asyncio.sleep(0.5)
        finally:
            if own_client:
                await client.aclose()
            logger.info("Jev System One triage worker stopped.")

    def start(self) -> None:
        """Launch the worker in an asyncio task."""
        if self._is_running:
            return
        self._is_running = True
        self._task = asyncio.create_task(self._worker_loop())

    async def stop(self) -> None:
        """Cancel and await worker task shutdown."""
        self._is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._redis:
            await self._redis.aclose()
            self._redis = None
