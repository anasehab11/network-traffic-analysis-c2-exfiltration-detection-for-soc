"""PCAP/PCAPNG validation and packet parsing.

Only metadata is extracted (addresses, ports, flags, sizes, DNS names, HTTP request
line/headers, TLS ClientHello fields). Payload bodies are never stored or logged.
The file is parsed with Scapy as data only; nothing inside it is ever executed.
"""
from __future__ import annotations

import hashlib
import logging
import struct
from pathlib import Path

import pandas as pd
from scapy.error import Scapy_Exception
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.utils import PcapReader

from core.utils import safe_text

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
log = logging.getLogger(__name__)

ALLOWED_EXT = {".pcap", ".pcapng", ".cap"}
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

PACKET_COLUMNS = [
    "ts", "src", "dst", "ip_ver", "proto", "sport", "dport", "length", "ttl", "tcp_flags",
    "tcp_window", "payload_len", "app", "app_detail", "port_app", "icmp_type",
    "dns_qname", "dns_qtype", "dns_qr", "dns_rcode", "dns_answers",
    "http_method", "http_host", "http_path", "http_ua", "http_clen", "http_status",
    "tls_sni", "tls_version", "tls_ja3",
]

PORT_APPS = {20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
             68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS",
             138: "NetBIOS", 139: "SMB", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
             445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
             995: "POP3S", 1433: "MSSQL", 1900: "SSDP", 3306: "MySQL", 3389: "RDP",
             5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT",
          28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ",
                b"CONNECT ", b"TRACE ", b"TRACK ", b"PROPFIND ")
TLS_VERSIONS = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1", 0x0301: "TLS 1.0", 0x0300: "SSL 3.0"}


class PcapValidationError(Exception):
    """Raised for files that are missing, too large, wrong type or unreadable."""


def validate_file(path, max_mb: int = 200) -> str:
    """Validate extension, size and magic bytes. Returns 'pcap' or 'pcapng'."""
    p = Path(path)
    if not p.is_file():
        raise PcapValidationError("File not found.")
    if p.suffix.lower() not in ALLOWED_EXT:
        raise PcapValidationError(f"Unsupported file type '{p.suffix}'. Use .pcap, .pcapng or .cap.")
    size = p.stat().st_size
    if size < 24:
        raise PcapValidationError("File is empty or too small to be a capture.")
    if size > max_mb * 1024 * 1024:
        raise PcapValidationError(f"File is {size / 1048576:.1f} MB; the limit is {max_mb} MB "
                                  "(raise it in Settings or split the capture).")
    with p.open("rb") as f:
        head = f.read(4)
    if head == PCAPNG_MAGIC:
        return "pcapng"
    if head in PCAP_MAGICS:
        return "pcap"
    raise PcapValidationError("File content is not a valid PCAP/PCAPNG (bad magic number).")


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- payload parsers
def parse_http(payload: bytes):
    """Parse an HTTP/1.x request line + headers or a status line. Never keeps the body."""
    if not payload:
        return None
    head = payload[:4096]
    if head.startswith(b"HTTP/1."):
        parts = head.split(b"\r\n", 1)[0].split(b" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        return {"kind": "response", "status": status}
    if not head.startswith(HTTP_METHODS):
        return None
    lines = head.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
    first = lines[0].decode("latin-1").split(" ")
    hdrs = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            hdrs[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    clen = hdrs.get("content-length", "")
    return {"kind": "request", "method": first[0], "path": safe_text(first[1] if len(first) > 1 else "", 300),
            "host": safe_text(hdrs["host"], 255).lower() if "host" in hdrs else None,
            "ua": safe_text(hdrs["user-agent"], 200) if "user-agent" in hdrs else None,
            "clen": int(clen) if clen.isdigit() else None}


def _is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def parse_client_hello(payload: bytes):
    """Extract SNI, highest offered version and JA3 hash from a TLS ClientHello."""
    try:
        if len(payload) < 45 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 9
        client_version = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + 32
        pos += 1 + payload[pos]
        cs_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        ciphers = [int.from_bytes(payload[i:i + 2], "big") for i in range(pos, min(pos + cs_len, len(payload)) - 1, 2)]
        pos += cs_len
        pos += 1 + payload[pos]
        sni, exts, curves, pfs, versions = None, [], [], [], []
        if pos + 2 <= len(payload):
            total = int.from_bytes(payload[pos:pos + 2], "big")
            pos += 2
            end = min(len(payload), pos + total)
            while pos + 4 <= end:
                et = int.from_bytes(payload[pos:pos + 2], "big")
                el = int.from_bytes(payload[pos + 2:pos + 4], "big")
                pos += 4
                data = payload[pos:pos + el]
                pos += el
                exts.append(et)
                if et == 0 and len(data) >= 5:
                    nl = int.from_bytes(data[3:5], "big")
                    sni = data[5:5 + nl].decode("ascii", "ignore").lower() or None
                elif et == 10 and len(data) >= 2:
                    curves = [int.from_bytes(data[i:i + 2], "big") for i in range(2, len(data) - 1, 2)]
                elif et == 11 and len(data) >= 1:
                    pfs = list(data[1:1 + data[0]])
                elif et == 43 and len(data) >= 1:
                    versions = [int.from_bytes(data[i:i + 2], "big") for i in range(1, len(data) - 1, 2)]
    except (IndexError, ValueError):
        return None
    clean = lambda xs: [x for x in xs if not _is_grease(x)]
    ja3_str = ",".join([str(client_version), "-".join(map(str, clean(ciphers))), "-".join(map(str, clean(exts))),
                        "-".join(map(str, clean(curves))), "-".join(map(str, pfs))])
    offered = clean(versions) or [client_version]
    return {"sni": safe_text(sni, 255) if sni else None,
            "version": TLS_VERSIONS.get(max(offered), f"0x{max(offered):04x}"),
            "ja3": hashlib.md5(ja3_str.encode()).hexdigest()}


def classify_payload(payload: bytes):
    if not payload:
        return None, None
    if len(payload) >= 5 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 3 and payload[2] <= 4:
        return "TLS", None
    if payload.startswith(b"SSH-"):
        return "SSH", safe_text(payload[:80].split(b"\r\n")[0].decode("latin-1"), 60)
    if len(payload) >= 8 and payload[4:8] in (b"\xffSMB", b"\xfeSMB"):
        return "SMB", "SMB1" if payload[4:5] == b"\xff" else "SMB2/3"
    return None, None


# ---------------------------------------------------------------- DNS helpers
def _first_qr(dns):
    qd = dns.qd
    if qd is None:
        return None
    if isinstance(qd, (list, tuple)):
        return qd[0] if qd else None
    return qd


def _iter_rr(rr):
    if rr is None:
        return
    if isinstance(rr, (list, tuple)):
        yield from rr
        return
    cur = rr
    while cur is not None and hasattr(cur, "rrname"):
        yield cur
        cur = getattr(cur, "payload", None)


def _dns_fields(dns) -> dict:
    out = {}
    qr = _first_qr(dns)
    if qr is None or getattr(qr, "qname", None) is None:
        return out
    name = qr.qname.decode("utf-8", "replace") if isinstance(qr.qname, bytes) else str(qr.qname)
    out["dns_qname"] = safe_text(name.rstrip(".").lower(), 255)
    out["dns_qtype"] = QTYPES.get(int(qr.qtype), str(int(qr.qtype)))
    out["dns_qr"] = int(dns.qr)
    if int(dns.qr) == 1:
        out["dns_rcode"] = int(dns.rcode)
        answers = []
        try:
            for rr in _iter_rr(dns.an):
                if int(rr.type) in (1, 28):
                    answers.append(str(rr.rdata))
        except Exception:  # malformed answer sections are common in captures
            pass
        if answers:
            out["dns_answers"] = ",".join(answers[:5])
    return out


# ---------------------------------------------------------------- packet record
def _record(pkt):
    rec = dict.fromkeys(PACKET_COLUMNS)
    rec["ts"] = float(pkt.time)
    rec["length"] = int(getattr(pkt, "wirelen", None) or len(pkt))
    if pkt.haslayer(IP):
        ip = pkt[IP]
        rec.update(src=ip.src, dst=ip.dst, ip_ver=4, ttl=int(ip.ttl))
        l3 = ip
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        rec.update(src=ip.src, dst=ip.dst, ip_ver=6, ttl=int(ip.hlim))
        l3 = ip
    elif pkt.haslayer(ARP):
        a = pkt[ARP]
        rec.update(src=a.psrc, dst=a.pdst, proto="ARP", ip_ver=4)
        rec["port_app"] = "ARP"
        return rec
    else:
        return None

    payload = b""
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        rec.update(proto="TCP", sport=int(t.sport), dport=int(t.dport), tcp_flags=str(t.flags),
                   tcp_window=int(t.window))
        payload = bytes(t.payload)
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        rec.update(proto="UDP", sport=int(u.sport), dport=int(u.dport))
        if pkt.haslayer(DNS):
            rec.update(_dns_fields(pkt[DNS]))
            if rec["dns_qname"]:
                rec["app"] = "DNS"
        payload = bytes(u.payload)
    elif pkt.haslayer(ICMP):
        rec.update(proto="ICMP", icmp_type=int(pkt[ICMP].type))
    elif l3.__class__ is IPv6 and getattr(l3, "nh", None) == 58:
        rec.update(proto="ICMPv6")
    else:
        rec["proto"] = "OTHER"
    rec["payload_len"] = len(payload)

    if rec["proto"] == "TCP" and payload:
        http = parse_http(payload)
        if http:
            rec["app"] = "HTTP"
            if http["kind"] == "request":
                rec.update(http_method=http["method"], http_host=http["host"], http_path=http["path"],
                           http_ua=http["ua"], http_clen=http["clen"])
            else:
                rec["http_status"] = http["status"]
        else:
            hello = parse_client_hello(payload)
            if hello:
                rec.update(app="TLS", tls_sni=hello["sni"], tls_version=hello["version"], tls_ja3=hello["ja3"])
            else:
                app, detail = classify_payload(payload)
                rec["app"], rec["app_detail"] = app, detail
    sp, dp = rec["sport"], rec["dport"]
    rec["port_app"] = PORT_APPS.get(dp) or PORT_APPS.get(sp)
    return rec


def parse_pcap(path, max_packets: int = 250_000, max_mb: int = 200, progress=None):
    """Parse a capture. Returns (packet DataFrame, metadata dict)."""
    fmt = validate_file(path, max_mb)
    rows, errors, non_ip, truncated, warnings = [], 0, 0, False, []
    reader = None
    try:
        reader = PcapReader(str(path))
        for i, pkt in enumerate(reader):
            if i >= max_packets:
                truncated = True
                warnings.append(f"Packet limit reached: only the first {max_packets:,} packets were analysed.")
                break
            try:
                rec = _record(pkt)
            except Exception:  # one bad packet must not abort the analysis
                errors += 1
                continue
            if rec is None:
                non_ip += 1
                continue
            rows.append(rec)
            if progress and i % 5000 == 0:
                progress(i)
    except (Scapy_Exception, EOFError, struct.error, OSError, ValueError) as exc:
        log.warning("Capture parse stopped early: %s", exc.__class__.__name__)
        warnings.append("The capture appears truncated or corrupted; results cover only the readable part.")
        if not rows:
            raise PcapValidationError("The capture could not be parsed (corrupted or unsupported format).") from exc
    finally:
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass

    df = pd.DataFrame(rows, columns=PACKET_COLUMNS)
    for c in ("sport", "dport", "tcp_window", "payload_len", "dns_qr", "dns_rcode", "http_clen", "http_status",
              "icmp_type", "ttl"):
        df[c] = pd.to_numeric(df[c], errors="coerce").astype("Int64")
    df["ts"] = df["ts"].astype(float)
    df["length"] = df["length"].fillna(0).astype(int)
    df["proto_label"] = df["app"].fillna(df["port_app"]).fillna(df["proto"])
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    if errors:
        warnings.append(f"{errors} packet(s) could not be decoded and were skipped.")
    if df.empty:
        warnings.append("No IP/ARP packets were found in this capture.")
    p = Path(path)
    meta = {"filename": p.name, "format": fmt, "size_bytes": p.stat().st_size, "sha256": sha256_file(p),
            "packets": int(len(df)), "non_ip_packets": non_ip, "parse_errors": errors, "truncated": truncated,
            "first_ts": float(df.ts.min()) if len(df) else None, "last_ts": float(df.ts.max()) if len(df) else None,
            "duration": float(df.ts.max() - df.ts.min()) if len(df) else 0.0, "warnings": warnings}
    log.info("Parsed %s: %d packets (%s)", p.name, len(df), fmt)
    return df, meta
