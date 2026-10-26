"""Wireshark display-filter suggestions (values are validated before being embedded)."""
from __future__ import annotations

import re

SAFE = re.compile(r"^[A-Za-z0-9._:\-]+$")

CHEATSHEET = [
    ("DNS", "All DNS traffic", "dns"),
    ("DNS", "DNS queries only", "dns.flags.response == 0"),
    ("DNS", "NXDOMAIN responses", "dns.flags.rcode == 3"),
    ("DNS", "Long query names", "dns.qry.name.len > 50"),
    ("DNS", "TXT queries (tunneling candidates)", "dns.qry.type == 16"),
    ("HTTP", "HTTP requests", "http.request"),
    ("HTTP", "POST requests", 'http.request.method == "POST"'),
    ("HTTP", "Filter by Host", 'http.host contains "example.com"'),
    ("HTTP", "Filter by user-agent", 'http.user_agent contains "curl"'),
    ("TLS", "ClientHello (SNI visible)", "tls.handshake.type == 1"),
    ("TLS", "Filter by SNI", 'tls.handshake.extensions_server_name contains "example"'),
    ("TLS", "JA3 hash", "tls.handshake.ja3 == \"<hash>\""),
    ("TCP", "TCP resets", "tcp.flags.reset == 1"),
    ("TCP", "SYN packets (no ACK)", "tcp.flags.syn == 1 && tcp.flags.ack == 0"),
    ("TCP", "SYN-ACK packets", "tcp.flags.syn == 1 && tcp.flags.ack == 1"),
    ("TCP", "Retransmissions", "tcp.analysis.retransmission"),
    ("IP", "Specific IP (either direction)", "ip.addr == 192.168.1.10"),
    ("IP", "Source/destination pair", "ip.src == 192.168.1.10 && ip.dst == 203.0.113.50"),
    ("Services", "SMB", "smb || smb2"),
    ("Services", "SSH", "tcp.port == 22"),
    ("Services", "RDP", "tcp.port == 3389"),
    ("ICMP", "ICMP echo requests", "icmp.type == 8"),
]


def _ok(v) -> bool:
    return bool(v) and bool(SAFE.match(str(v)))


def filters_for_alert(a) -> list[str]:
    out = []
    src, dst, port = a.src_ip, a.dst_ip, a.dst_port
    if _ok(src) and _ok(dst) and dst != "multiple" and "." in dst + src:
        f = f"ip.addr == {src} && ip.addr == {dst}"
        if port:
            f += f" && {'udp' if a.protocol == 'UDP' else 'tcp'}.port == {int(port)}"
        out.append(f)
    elif _ok(src):
        out.append(f"ip.src == {src}")
    dom = a.extra.get("domain")
    if _ok(dom):
        out.append(f'dns.qry.name contains "{dom}"')
    if a.category == "Scan" and _ok(src):
        out.append(f"ip.src == {src} && tcp.flags.syn == 1 && tcp.flags.ack == 0")
        out.append(f"ip.dst == {src} && tcp.flags.reset == 1")
    if a.category == "TLS" and _ok(dst):
        out.append(f"ip.addr == {dst} && tls.handshake.type == 1")
    if a.category == "HTTP" and _ok(src):
        out.append(f"ip.src == {src} && http.request")
    return list(dict.fromkeys(out))
