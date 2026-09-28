"""Packet capture engine utilizing Scapy, kernel BPF filters, and state extraction."""

import json
import logging
import math
import re
import threading
import time
from collections import Counter
from typing import Any, Dict, Optional

import redis
from scapy.all import (  # type: ignore
    DNS,
    DNSQR,
    IP,
    Raw,
    TCP,
    UDP,
    conf,
    sniff,
)

from app.config import settings

logger = logging.getLogger(__name__)

# Compile regex for HTTP Host extraction from raw payload
HTTP_HOST_RE = re.compile(rb"(?i)Host:\s*([^\r\n:]+)")


def calculate_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return max(0.0, round(entropy, 2))


def extract_sni_from_payload(payload: bytes) -> Optional[str]:
    """Parse TLS ClientHello handshake from raw byte payload to extract SNI domain."""
    try:
        # TLS Record: Content Type 0x16 (Handshake), Version >= 0x0301 (TLS 1.0+)
        if len(payload) > 43 and payload[0] == 0x16 and payload[1] == 0x03:
            # Handshake Type: 0x01 (Client Hello)
            if payload[5] == 0x01:
                # Session ID length at offset 43
                session_id_len = payload[43]
                idx = 44 + session_id_len
                if idx + 2 > len(payload):
                    return None
                cipher_suites_len = int.from_bytes(payload[idx : idx + 2], "big")
                idx += 2 + cipher_suites_len
                if idx >= len(payload):
                    return None
                comp_methods_len = payload[idx]
                idx += 1 + comp_methods_len
                if idx + 2 <= len(payload):
                    ext_len = int.from_bytes(payload[idx : idx + 2], "big")
                    idx += 2
                    end_ext = idx + ext_len
                    while idx + 4 <= end_ext and idx + 4 <= len(payload):
                        ext_type = int.from_bytes(payload[idx : idx + 2], "big")
                        ext_val_len = int.from_bytes(payload[idx + 2 : idx + 4], "big")
                        idx += 4
                        if ext_type == 0:  # server_name extension
                            if idx + 5 <= len(payload):
                                name_len = int.from_bytes(payload[idx + 3 : idx + 5], "big")
                                sni = payload[idx + 5 : idx + 5 + name_len].decode("utf-8", errors="ignore")
                                return sni.strip()
                        idx += ext_val_len
    except Exception:
        pass
    return None


def extract_domain_or_sni(packet: Any, payload: bytes) -> Optional[str]:
    """Extract domain from DNS query, TLS SNI, or HTTP Host header."""
    # 1. DNS Query
    try:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname
            if qname:
                decoded = qname.decode("utf-8", errors="ignore").rstrip(".")
                if decoded:
                    return decoded
    except Exception:
        pass

    # 2. TLS SNI
    sni = extract_sni_from_payload(payload)
    if sni:
        return sni

    # 3. HTTP Host header
    if payload:
        match = HTTP_HOST_RE.search(payload)
        if match:
            return match.group(1).decode("utf-8", errors="ignore").strip()

    return None


def is_noise_packet(packet: Any) -> bool:
    """Pre-filter discard engine for in-memory noise elimination (Section 3.1)."""
    # Require IP layer
    if not packet.haslayer(IP):
        return True

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Discard loopback or internal broadcast chatter
    if (
        src_ip.startswith("127.")
        or dst_ip.startswith("127.")
        or dst_ip in ("255.255.255.255", "0.0.0.0")
        or dst_ip.startswith("224.")
    ):
        return True

    # Pure TCP ACK with zero payload: flags == 0x10 and empty payload
    if packet.haslayer(TCP):
        tcp_flags = int(packet[TCP].flags)
        # 0x10 is ACK flag alone
        if tcp_flags == 0x10:
            payload = bytes(packet[TCP].payload)
            if len(payload) == 0:
                return True

    return False


def extract_packet_state(packet: Any) -> Optional[Dict[str, Any]]:
    """Transform a raw Scapy packet into the minimal structured state required by Jev (Section 3.2)."""
    if is_noise_packet(packet):
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    timestamp = float(getattr(packet, "time", time.time()))

    protocol = "OTHER"
    dst_port = 0
    payload = b""

    if packet.haslayer(TCP):
        protocol = "TCP"
        dst_port = int(packet[TCP].dport)
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        dst_port = int(packet[UDP].dport)
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
    else:
        protocol = packet[IP].sprintf("%IP.proto%")
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)

    # Domain or SNI
    domain_or_sni = extract_domain_or_sni(packet, payload)

    # Payload snippet (up to 256 bytes printable string)
    payload_snippet = ""
    if payload:
        snippet_bytes = payload[:256]
        # Clean non-printable characters for clean JSON transmission
        payload_snippet = snippet_bytes.decode("utf-8", errors="replace").replace("\x00", " ")

    entropy = calculate_entropy(payload)

    return {
        "timestamp": timestamp,
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "domain_or_sni": domain_or_sni or "",
        "payload_snippet": payload_snippet,
        "entropy": entropy,
    }


class CaptureEngine:
    """Threaded packet sniffer boundary that pushes telemetry events to Redis."""

    def __init__(
        self,
        redis_url: Optional[str] = None,
        queue_name: Optional[str] = None,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
    ):
        self.redis_url = redis_url or settings.REDIS_URL
        self.queue_name = queue_name or settings.REDIS_RAW_QUEUE
        self.interface = interface or settings.CAPTURE_INTERFACE
        self.bpf_filter = bpf_filter or settings.BPF_FILTER

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sync_redis: Optional[redis.Redis] = None
        self._packet_count = 0
        self._is_running = False

    def _get_redis(self) -> redis.Redis:
        if self._sync_redis is None:
            self._sync_redis = redis.Redis.from_url(self.redis_url, decode_responses=True)
        return self._sync_redis

    def _packet_callback(self, packet: Any) -> None:
        """Synchronous Scapy callback executed per packet inside sniffer thread."""
        try:
            state = extract_packet_state(packet)
            if state is not None:
                self._packet_count += 1
                r = self._get_redis()
                r.lpush(self.queue_name, json.dumps(state))
                r.incr("net:stats:captured")
        except Exception as e:
            logger.debug("Error processing captured packet: %s", e)

    def _sniff_loop(self) -> None:
        """Main sniffer execution loop running inside dedicated background thread."""
        logger.info(
            "Starting Scapy sniffer on interface=%s with BPF filter='%s'",
            self.interface or "default",
            self.bpf_filter,
        )
        conf.verb = 0

        kwargs: Dict[str, Any] = {
            "store": 0,
            "filter": self.bpf_filter,
            "prn": self._packet_callback,
            "stop_filter": lambda _: self._stop_event.is_set(),
        }
        if self.interface:
            kwargs["iface"] = self.interface

        try:
            sniff(**kwargs)
        except PermissionError:
            logger.error(
                "Permission denied opening raw socket for packet capture. "
                "Run with elevated privileges or execute: "
                "sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)"
            )
        except Exception as e:
            logger.error("Capture engine encountered an error: %s", e)
        finally:
            self._is_running = False
            logger.info("Scapy sniffer thread stopped. Total captured: %d", self._packet_count)

    def start(self) -> None:
        """Start the background packet capture thread."""
        if self._is_running:
            return
        self._stop_event.clear()
        self._is_running = True
        self._thread = threading.Thread(target=self._sniff_loop, name="ScapySniffer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the capture thread to terminate and wait for completion."""
        self._stop_event.set()
        self._is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        if self._sync_redis:
            try:
                self._sync_redis.close()
            except Exception:
                pass
            self._sync_redis = None

    def inject_event(self, event: Dict[str, Any]) -> None:
        """Inject an event dictionary directly into the Redis queue (useful for testing/simulation)."""
        r = self._get_redis()
        r.lpush(self.queue_name, json.dumps(event))
        r.incr("net:stats:captured")

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def packet_count(self) -> int:
        return self._packet_count
