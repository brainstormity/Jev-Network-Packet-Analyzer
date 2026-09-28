"""Tests for packet capture pre-filtering and state extraction."""

import pytest
from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP
from app.capture import (
    calculate_entropy,
    extract_domain_or_sni,
    extract_packet_state,
    extract_sni_from_payload,
    is_noise_packet,
)


def test_calculate_entropy():
    # Empty payload
    assert calculate_entropy(b"") == 0.0

    # Low entropy (single repeating byte)
    low = calculate_entropy(b"AAAAAAAAAA")
    assert low == 0.0

    # High entropy (uniform distribution of all 256 bytes)
    high = calculate_entropy(bytes(range(256)))
    assert high == 8.0

    # Moderate entropy
    text = b"The quick brown fox jumps over the lazy dog"
    ent = calculate_entropy(text)
    assert 3.5 <= ent <= 4.5


def test_is_noise_packet_pure_tcp_ack():
    # Pure TCP ACK (flags=0x10) without payload must be discarded
    ack_pkt = IP(src="192.168.1.10", dst="142.250.190.46") / TCP(flags=0x10, dport=443)
    assert is_noise_packet(ack_pkt) is True

    # TCP packet with payload (e.g. PSH-ACK or ACK with data) must NOT be discarded
    data_pkt = IP(src="192.168.1.10", dst="142.250.190.46") / TCP(flags=0x10, dport=443) / Raw(b"GET / HTTP/1.1\r\n")
    assert is_noise_packet(data_pkt) is False


def test_is_noise_packet_loopback_and_broadcast():
    # Loopback IP
    loopback_pkt = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(dport=80)
    assert is_noise_packet(loopback_pkt) is True

    # Broadcast
    bcast_pkt = IP(src="192.168.1.5", dst="255.255.255.255") / UDP(dport=67)
    assert is_noise_packet(bcast_pkt) is True


def test_extract_dns_query_domain():
    # Simulated DNS Query
    dns_pkt = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname="malicious-c2.net."))
    domain = extract_domain_or_sni(dns_pkt, b"")
    assert domain == "malicious-c2.net"


def test_extract_http_host_header():
    # Simulated HTTP packet
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.org\r\nUser-Agent: curl\r\n\r\n"
    http_pkt = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(dport=80) / Raw(payload)
    domain = extract_domain_or_sni(http_pkt, payload)
    assert domain == "example.org"


def test_extract_packet_state_structure():
    payload = b"GET /beacon?id=4910 HTTP/1.1\r\nHost: c2-checkin.dynamic-dns.net\r\n"
    pkt = IP(src="192.168.1.45", dst="185.220.101.5") / TCP(dport=4444) / Raw(payload)

    state = extract_packet_state(pkt)
    assert state is not None
    assert state["protocol"] == "TCP"
    assert state["src_ip"] == "192.168.1.45"
    assert state["dst_ip"] == "185.220.101.5"
    assert state["dst_port"] == 4444
    assert state["domain_or_sni"] == "c2-checkin.dynamic-dns.net"
    assert "GET /beacon" in state["payload_snippet"]
    assert state["entropy"] > 0.0
