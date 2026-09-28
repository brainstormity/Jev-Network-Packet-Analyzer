"""Resend email notification engine with anti-spam cooldown throttling."""

import html
import logging
from typing import Any, Dict, Optional
import httpx

from app.config import settings
from app import database

logger = logging.getLogger(__name__)

RESEND_API_URL = "https://api.resend.com/emails"


def generate_alert_html(event: Dict[str, Any]) -> str:
    """Generate high-impact, cyber-security themed HTML email for critical alerts."""
    category = html.escape(str(event.get("threat_category", "Unknown Threat")).upper())
    severity = float(event.get("severity", 0.0))
    is_suspicious = float(event.get("is_suspicious", 0.0)) * 100
    src_ip = html.escape(str(event.get("src_ip", "Unknown")))
    dst_ip = html.escape(str(event.get("dst_ip", "Unknown")))
    dst_port = event.get("dst_port", 0)
    protocol = html.escape(str(event.get("protocol", "TCP")))
    domain = html.escape(str(event.get("domain_or_sni", "N/A")))
    entropy = event.get("entropy", 0.0)
    snippet = html.escape(str(event.get("payload_snippet", "No payload snippet available")))

    severity_color = "#ef4444" if severity >= 3.5 else "#f97316"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>NetworkSentinel Threat Alert</title>
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f1f5f9; padding: 20px; margin: 0; }}
        .card {{ max-width: 620px; margin: 0 auto; background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        .header {{ background-color: #1e1b4b; border-bottom: 2px solid {severity_color}; padding: 24px; text-align: left; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 700; text-transform: uppercase; background-color: {severity_color}; color: #ffffff; }}
        .title {{ font-size: 20px; font-weight: 700; margin: 12px 0 4px 0; color: #ffffff; }}
        .subtitle {{ font-size: 13px; color: #94a3b8; }}
        .content {{ padding: 24px; }}
        .metrics-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; }}
        .metric-box {{ background-color: #1f2937; padding: 12px; border-radius: 6px; }}
        .metric-label {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 600; }}
        .metric-value {{ font-size: 16px; font-weight: 700; color: #f8fafc; margin-top: 4px; }}
        .table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px; }}
        .table td {{ padding: 8px 12px; border-bottom: 1px solid #374151; }}
        .table td:first-child {{ color: #94a3b8; font-weight: 600; width: 35%; }}
        .table td:last-child {{ color: #f1f5f9; font-family: monospace; }}
        .payload {{ background-color: #030712; border: 1px solid #1f2937; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #38bdf8; word-break: break-all; white-space: pre-wrap; }}
        .footer {{ padding: 16px 24px; background-color: #0f172a; text-align: center; font-size: 11px; color: #64748b; border-top: 1px solid #1f2937; }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <span class="badge">Critical Threat Level: {severity:.1f} / 4.0</span>
          <div class="title">🚨 Jev AI Detected: {category}</div>
          <div class="subtitle">NetworkSentinel Automated Telemetry Triage</div>
        </div>
        <div class="content">
          <div class="metrics-grid">
            <div class="metric-box">
              <div class="metric-label">Risk Severity Score</div>
              <div class="metric-value" style="color: {severity_color};">{severity:.2f} / 4.0</div>
            </div>
            <div class="metric-box">
              <div class="metric-label">Suspicious Probability</div>
              <div class="metric-value" style="color: #38bdf8;">{is_suspicious:.1f}%</div>
            </div>
          </div>

          <table class="table">
            <tr><td>Source IP</td><td>{src_ip}</td></tr>
            <tr><td>Destination</td><td>{dst_ip}:{dst_port}</td></tr>
            <tr><td>Protocol</td><td>{protocol}</td></tr>
            <tr><td>Domain / SNI</td><td>{domain}</td></tr>
            <tr><td>Payload Entropy</td><td>{entropy:.2f} / 8.0</td></tr>
          </table>

          <div style="font-size: 12px; font-weight: 600; color: #94a3b8; margin-bottom: 6px;">PAYLOAD SNIPPET</div>
          <div class="payload">{snippet}</div>
        </div>
        <div class="footer">
          Dispatched by NetworkSentinel (Jev System One Edition) &bull; 5-min cooldown active for this source & threat
        </div>
      </div>
    </body>
    </html>
    """


async def dispatch_alert(
    event: Dict[str, Any],
    redis_client: Any,
    client: Optional[httpx.AsyncClient] = None,
) -> Dict[str, Any]:
    """Evaluate cooldown and send email alert via Resend REST API."""
    src_ip = event.get("src_ip", "0.0.0.0")
    threat_category = event.get("threat_category", "unknown")
    severity = float(event.get("severity", 0.0))

    cooldown_key = f"{settings.REDIS_ALERT_COOLDOWN_PREFIX}{src_ip}:{threat_category}"

    # 1. Anti-spam cooldown check (5 minutes / 300s TTL)
    try:
        is_cooldown = await redis_client.get(cooldown_key)
        if is_cooldown:
            logger.info(
                "Alert throttled for %s [%s] (5-min cooldown active)",
                src_ip,
                threat_category,
            )
            await database.save_alert(
                {
                    "event_id": event.get("id"),
                    "src_ip": src_ip,
                    "dst_ip": event.get("dst_ip"),
                    "threat_category": threat_category,
                    "severity": severity,
                    "recipient": settings.ALERT_RECIPIENT,
                    "status": "throttled",
                    "resend_id": None,
                    "error_message": "Suppressed by 5-minute deduplication cooldown",
                }
            )
            return {"status": "throttled", "cooldown": True}
    except Exception as e:
        logger.warning("Redis cooldown lookup failed: %s", e)

    # Set 300-second cooldown immediately
    try:
        await redis_client.set(cooldown_key, "1", ex=300)
    except Exception as e:
        logger.warning("Could not set Redis alert cooldown: %s", e)

    # 2. Check if Resend is configured
    if not settings.is_resend_configured:
        logger.info(
            "[MOCK ALERT] Resend API key not configured. Mocking alert for %s: %s (Severity %.1f)",
            src_ip,
            threat_category,
            severity,
        )
        alert_id = await database.save_alert(
            {
                "event_id": event.get("id"),
                "src_ip": src_ip,
                "dst_ip": event.get("dst_ip"),
                "threat_category": threat_category,
                "severity": severity,
                "recipient": settings.ALERT_RECIPIENT,
                "status": "mock_sent",
                "resend_id": "mock_resend_id",
                "error_message": None,
            }
        )
        return {"status": "mock_sent", "alert_id": alert_id}

    # 3. Dispatch to Resend REST API
    headers = {
        "Authorization": f"Bearer {settings.RESEND_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "from": f"Network Sentinel <{settings.RESEND_FROM_EMAIL}>",
        "to": [settings.ALERT_RECIPIENT],
        "subject": f"🚨 [Alert] High Severity Threat Detected: {threat_category.upper()} (Risk: {severity:.1f}/4.0)",
        "html": generate_alert_html(event),
    }

    own_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=10.0)
        own_client = True

    try:
        response = await client.post(RESEND_API_URL, json=payload, headers=headers)
        if response.status_code in (200, 201):
            res_data = response.json()
            resend_id = res_data.get("id", "")
            logger.info("Resend alert dispatched successfully! ID=%s", resend_id)
            await database.save_alert(
                {
                    "event_id": event.get("id"),
                    "src_ip": src_ip,
                    "dst_ip": event.get("dst_ip"),
                    "threat_category": threat_category,
                    "severity": severity,
                    "recipient": settings.ALERT_RECIPIENT,
                    "status": "sent",
                    "resend_id": resend_id,
                    "error_message": None,
                }
            )
            return {"status": "sent", "resend_id": resend_id}
        else:
            err_text = response.text
            logger.error("Resend API rejected dispatch: HTTP %d %s", response.status_code, err_text)
            await database.save_alert(
                {
                    "event_id": event.get("id"),
                    "src_ip": src_ip,
                    "dst_ip": event.get("dst_ip"),
                    "threat_category": threat_category,
                    "severity": severity,
                    "recipient": settings.ALERT_RECIPIENT,
                    "status": "failed",
                    "resend_id": None,
                    "error_message": f"HTTP {response.status_code}: {err_text[:200]}",
                }
            )
            return {"status": "failed", "error": err_text}
    except Exception as e:
        logger.error("Exception dispatching alert via Resend: %s", e)
        await database.save_alert(
            {
                "event_id": event.get("id"),
                "src_ip": src_ip,
                "dst_ip": event.get("dst_ip"),
                "threat_category": threat_category,
                "severity": severity,
                "recipient": settings.ALERT_RECIPIENT,
                "status": "failed",
                "resend_id": None,
                "error_message": str(e),
            }
        )
        return {"status": "failed", "error": str(e)}
    finally:
        if own_client:
            await client.aclose()
