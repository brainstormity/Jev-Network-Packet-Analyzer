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

    # Inline styles for cross-client email rendering (specifically Desktop Gmail PC)
    td_label_style = "padding: 9px 12px; border-bottom: 1px solid #374151; color: #94a3b8; font-weight: 600; width: 35%; font-size: 13px;"
    td_val_style = "padding: 9px 12px; border-bottom: 1px solid #374151; color: #f8fafc; font-family: 'JetBrains Mono', Consolas, Monaco, monospace; font-size: 13px;"
    link_style = "color: #38bdf8 !important; text-decoration: none !important; font-weight: 600;"

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>NetworkSentinel Threat Alert</title>
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f1f5f9; padding: 20px; margin: 0; }}
        .card {{ max-width: 620px; margin: 0 auto; background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        a, a:visited, a:hover, a:active {{ color: #38bdf8 !important; text-decoration: none !important; }}
      </style>
    </head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f1f5f9; padding: 20px; margin: 0;">
      <div class="card" style="max-width: 620px; margin: 0 auto; background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
        <div style="background-color: #1e1b4b; border-bottom: 2px solid {severity_color}; padding: 24px; text-align: left;">
          <span style="display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 700; text-transform: uppercase; background-color: {severity_color}; color: #ffffff;">Critical Threat Level: {severity:.1f} / 4.0</span>
          <div style="font-size: 20px; font-weight: 700; margin: 12px 0 4px 0; color: #ffffff;">🚨 Jev AI Detected: {category}</div>
          <div style="font-size: 13px; color: #94a3b8;">NetworkSentinel Automated Telemetry Triage</div>
        </div>
        <div style="padding: 24px;">
          <table style="width: 100%; border-collapse: separate; border-spacing: 12px 0; margin-bottom: 20px;">
            <tr>
              <td style="width: 50%; background-color: #1f2937; padding: 12px; border-radius: 6px; border: 1px solid #374151;">
                <div style="font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 600;">Risk Severity Score</div>
                <div style="font-size: 18px; font-weight: 700; color: {severity_color}; margin-top: 4px;">{severity:.2f} / 4.0</div>
              </td>
              <td style="width: 50%; background-color: #1f2937; padding: 12px; border-radius: 6px; border: 1px solid #374151;">
                <div style="font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 600;">Suspicious Probability</div>
                <div style="font-size: 18px; font-weight: 700; color: #38bdf8; margin-top: 4px;">{is_suspicious:.1f}%</div>
              </td>
            </tr>
          </table>

          <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px;">
            <tr>
              <td style="{td_label_style}">Source IP</td>
              <td style="{td_val_style}"><span style="color: #f8fafc; font-weight: 600;">{src_ip}</span> <span style="font-size: 11px; color: #94a3b8; font-family: -apple-system, BlinkMacSystemFont, sans-serif;">(Internal LAN)</span></td>
            </tr>
            <tr>
              <td style="{td_label_style}">Destination</td>
              <td style="{td_val_style}"><a href="http://{dst_ip}:{dst_port}" style="{link_style}">{dst_ip}:{dst_port}</a></td>
            </tr>
            <tr>
              <td style="{td_label_style}">Protocol</td>
              <td style="{td_val_style}"><span style="color: #f8fafc; font-weight: 600;">{protocol}</span></td>
            </tr>
            <tr>
              <td style="{td_label_style}">Domain / SNI</td>
              <td style="{td_val_style}"><a href="http://{domain}" style="{link_style}">{domain}</a></td>
            </tr>
            <tr>
              <td style="{td_label_style}">Payload Entropy</td>
              <td style="{td_val_style}"><span style="color: #f8fafc; font-weight: 600;">{entropy:.2f}</span> <span style="color: #94a3b8;">/ 8.0</span></td>
            </tr>
          </table>

          <div style="font-size: 12px; font-weight: 600; color: #94a3b8; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px;">PAYLOAD SNIPPET</div>
          <div style="background-color: #030712; border: 1px solid #1f2937; padding: 14px; border-radius: 6px; font-family: 'JetBrains Mono', Consolas, Monaco, monospace; font-size: 12px; color: #38bdf8; word-break: break-all; white-space: pre-wrap; line-height: 1.5;">{snippet}</div>
        </div>
        <div style="padding: 16px 24px; background-color: #0f172a; text-align: center; font-size: 11px; color: #94a3b8; border-top: 1px solid #1f2937;">
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


def generate_startup_html() -> str:
    """Generate professional cyber-themed HTML email sent once when NetworkSentinel starts up."""
    bpf = html.escape(settings.BPF_FILTER)
    model = html.escape(settings.JEV_MODEL)
    interface = html.escape(settings.CAPTURE_INTERFACE or "Auto-Detect")
    recipient = html.escape(settings.ALERT_RECIPIENT)

    td_label_style = "padding: 9px 12px; border-bottom: 1px solid #374151; color: #94a3b8; font-weight: 600; width: 38%; font-size: 13px;"
    td_val_style = "padding: 9px 12px; border-bottom: 1px solid #374151; color: #f8fafc; font-family: 'JetBrains Mono', Consolas, Monaco, monospace; font-size: 13px;"

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>NetworkSentinel Online</title>
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f1f5f9; padding: 20px; margin: 0; }}
        .card {{ max-width: 620px; margin: 0 auto; background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        a, a:visited, a:hover, a:active {{ color: #10b981 !important; text-decoration: none !important; }}
      </style>
    </head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f1f5f9; padding: 20px; margin: 0;">
      <div class="card" style="max-width: 620px; margin: 0 auto; background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
        <div style="background-color: #064e3b; border-bottom: 2px solid #10b981; padding: 24px; text-align: left;">
          <span style="display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 700; text-transform: uppercase; background-color: #10b981; color: #022c22;">&#10003; SYSTEM ONLINE</span>
          <div style="font-size: 20px; font-weight: 700; margin: 12px 0 4px 0; color: #ffffff;">&#128737;&#65039; NetworkSentinel Started Successfully</div>
          <div style="font-size: 13px; color: #a7f3d0;">TypeSafe AI Jev System One Edition</div>
        </div>
        <div style="padding: 24px;">
          <div style="background-color: #1e293b; border-left: 4px solid #10b981; padding: 14px; border-radius: 4px; margin-bottom: 20px; font-size: 13px; color: #e2e8f0; line-height: 1.5;">
            This automated email confirms that <strong>NetworkSentinel</strong> is now actively running and your <strong>Resend email service is verified and fully operational</strong>. You will receive immediate notifications whenever high-severity threats or anomalies are detected.
          </div>

          <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px;">
            <tr><td style="{td_label_style}">Monitoring Interface</td><td style="{td_val_style}">{interface}</td></tr>
            <tr><td style="{td_label_style}">BPF Kernel Filter</td><td style="{td_val_style}">{bpf}</td></tr>
            <tr><td style="{td_label_style}">Decision Model</td><td style="{td_val_style}">{model}</td></tr>
            <tr><td style="{td_label_style}">Rate Limit Pacer</td><td style="{td_val_style}">&le; 18 req/sec (Token Bucket)</td></tr>
            <tr><td style="{td_label_style}">Deduplication Window</td><td style="{td_val_style}">1 Hour (TTL: 3600s)</td></tr>
            <tr><td style="{td_label_style}">Alert Cooldown</td><td style="{td_val_style}">5 Minutes Anti-Spam</td></tr>
            <tr><td style="{td_label_style}">Alert Recipient</td><td style="{td_val_style}">{recipient}</td></tr>
          </table>
        </div>
        <div style="padding: 16px 24px; background-color: #0f172a; text-align: center; font-size: 11px; color: #94a3b8; border-top: 1px solid #1f2937;">
          NetworkSentinel Automated Security Notification &bull; Resend Dispatch Engine
        </div>
      </div>
    </body>
    </html>
    """


async def send_startup_notification(client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """Send a single verification email via Resend when NetworkSentinel starts up."""
    if not settings.is_resend_configured:
        logger.info("[STARTUP] Resend not configured. Skipping startup notification email.")
        return {"status": "skipped", "reason": "Resend API key not configured"}

    logger.info("Dispatching system startup notification email to %s...", settings.ALERT_RECIPIENT)
    headers = {
        "Authorization": f"Bearer {settings.RESEND_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "from": f"Network Sentinel <{settings.RESEND_FROM_EMAIL}>",
        "to": [settings.ALERT_RECIPIENT],
        "subject": "🛡️ [NetworkSentinel] Telemetry Analyzer Online & Active",
        "html": generate_startup_html(),
    }

    own_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=10.0)
        own_client = True

    try:
        await database.init_db()
    except Exception:
        pass

    try:
        response = await client.post(RESEND_API_URL, json=payload, headers=headers)
        if response.status_code in (200, 201):
            res_data = response.json()
            resend_id = res_data.get("id", "")
            logger.info("Startup notification email delivered successfully! Resend ID=%s", resend_id)
            await database.save_alert(
                {
                    "event_id": None,
                    "src_ip": "127.0.0.1",
                    "dst_ip": "resend.com",
                    "threat_category": "SYSTEM_STARTUP",
                    "severity": 0.0,
                    "recipient": settings.ALERT_RECIPIENT,
                    "status": "sent",
                    "resend_id": resend_id,
                    "error_message": None,
                }
            )
            return {"status": "sent", "resend_id": resend_id}
        else:
            err_text = response.text
            logger.warning("Resend rejected startup email: HTTP %d %s", response.status_code, err_text)
            await database.save_alert(
                {
                    "event_id": None,
                    "src_ip": "127.0.0.1",
                    "dst_ip": "resend.com",
                    "threat_category": "SYSTEM_STARTUP",
                    "severity": 0.0,
                    "recipient": settings.ALERT_RECIPIENT,
                    "status": "failed",
                    "resend_id": None,
                    "error_message": f"HTTP {response.status_code}: {err_text[:200]}",
                }
            )
            return {"status": "failed", "error": err_text}
    except Exception as e:
        logger.error("Exception sending startup notification email: %s", e)
        return {"status": "failed", "error": str(e)}
    finally:
        if own_client:
            await client.aclose()

