"""Generate SAFE, SYNTHETIC demonstration PCAPs.

Everything here is SIMULATED. No real malware, no real victims. Addresses come from RFC1918 (internal) and the
RFC5737 documentation ranges (198.51.100.0/24, 203.0.113.0/24); domains use reserved names (*.example).

Usage:  python sample_data/generate_samples.py [output_dir]
"""
from __future__ import annotations

import hashlib
import logging
import random
import sys
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap  # noqa: E402

T0 = 1_760_000_000.0  # fixed epoch so output is reproducible
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SIMULATED-BROWSER/1.0"
B32 = "abcdefghijklmnopqrstuvwxyz234567"
CONS = "bcdfghjklmnpqrstvwxz"


def mac(ip: str) -> str:
    h = hashlib.md5(ip.encode()).digest()
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(h[:5])


def build_client_hello(sni, rng=None, versions=(0x0304, 0x0303),
                       ciphers=(0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8),
                       groups=(29, 23, 24), pf=(0,)) -> bytes:
    """Minimal TLS ClientHello with SNI (used for demos and unit tests)."""
    rng = rng or random.Random(0)

    def ext(t, d):
        return t.to_bytes(2, "big") + len(d).to_bytes(2, "big") + d

    exts = b""
    if sni:
        s = sni.encode()
        exts += ext(0, (len(s) + 3).to_bytes(2, "big") + b"\x00" + len(s).to_bytes(2, "big") + s)
    exts += ext(10, (2 * len(groups)).to_bytes(2, "big") + b"".join(g.to_bytes(2, "big") for g in groups))
    exts += ext(11, bytes([len(pf)]) + bytes(pf))
    exts += ext(43, bytes([2 * len(versions)]) + b"".join(v.to_bytes(2, "big") for v in versions))
    body = (b"\x03\x03" + rng.randbytes(32) + b"\x20" + rng.randbytes(32) + (2 * len(ciphers)).to_bytes(2, "big")
            + b"".join(c.to_bytes(2, "big") for c in ciphers) + b"\x01\x00" + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def tls_data(rng, n):
    return b"\x17\x03\x03" + n.to_bytes(2, "big") + rng.randbytes(n)


class Builder:
    def __init__(self, seed=1):
        self.pkts, self.rng = [], random.Random(seed)

    def add(self, t, pkt):
        pkt.time = t
        self.pkts.append(pkt)

    def _eth(self, a, b):
        return Ether(src=mac(a), dst=mac(b))

    def tcp(self, t, c, s, sport, dport, c_data=(), s_data=(), rtt=0.02, close=True, window=64240, gap=0.01):
        sc, ss = self.rng.randrange(1000, 2**31), self.rng.randrange(1000, 2**31)
        tt = t
        self.add(tt, self._eth(c, s) / IP(src=c, dst=s, ttl=64) / TCP(sport=sport, dport=dport, flags="S", seq=sc, window=window, options=[("MSS", 1460)]))
        tt += rtt
        self.add(tt, self._eth(s, c) / IP(src=s, dst=c, ttl=57) / TCP(sport=dport, dport=sport, flags="SA", seq=ss, ack=sc + 1, window=65535))
        tt += rtt
        sc += 1
        ss += 1
        self.add(tt, self._eth(c, s) / IP(src=c, dst=s, ttl=64) / TCP(sport=sport, dport=dport, flags="A", seq=sc, ack=ss, window=window))
        for i in range(max(len(c_data), len(s_data))):
            if i < len(c_data):
                tt += gap
                p = c_data[i]
                self.add(tt, self._eth(c, s) / IP(src=c, dst=s, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=sc, ack=ss, window=window) / Raw(p))
                sc += len(p)
                tt += rtt
                self.add(tt, self._eth(s, c) / IP(src=s, dst=c, ttl=57) / TCP(sport=dport, dport=sport, flags="A", seq=ss, ack=sc, window=65535))
            if i < len(s_data):
                tt += gap
                p = s_data[i]
                self.add(tt, self._eth(s, c) / IP(src=s, dst=c, ttl=57) / TCP(sport=dport, dport=sport, flags="PA", seq=ss, ack=sc, window=65535) / Raw(p))
                ss += len(p)
                tt += rtt
                self.add(tt, self._eth(c, s) / IP(src=c, dst=s, ttl=64) / TCP(sport=sport, dport=dport, flags="A", seq=sc, ack=ss, window=window))
        if close:
            tt += gap
            self.add(tt, self._eth(c, s) / IP(src=c, dst=s, ttl=64) / TCP(sport=sport, dport=dport, flags="FA", seq=sc, ack=ss, window=window))
            tt += rtt
            self.add(tt, self._eth(s, c) / IP(src=s, dst=c, ttl=57) / TCP(sport=dport, dport=sport, flags="FA", seq=ss, ack=sc + 1, window=65535))
            tt += rtt
            self.add(tt, self._eth(c, s) / IP(src=c, dst=s, ttl=64) / TCP(sport=sport, dport=dport, flags="A", seq=sc + 1, ack=ss + 1, window=window))
        return tt

    def dns(self, t, client, resolver, name, qtype="A", rcode=0, answer=None, rtt=0.015):
        sport, qid = self.rng.randrange(20000, 60000), self.rng.randrange(1, 65535)
        self.add(t, self._eth(client, resolver) / IP(src=client, dst=resolver) / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=qtype)))
        an = DNSRR(rrname=name, type="A", ttl=300, rdata=answer) if (answer and rcode == 0) else None
        r = DNS(id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype=qtype), an=an, ancount=1 if an else 0)
        self.add(t + rtt, self._eth(resolver, client) / IP(src=resolver, dst=client) / UDP(sport=53, dport=sport) / r)


def scenario_normal(b: Builder, base=T0):
    c, res = "192.168.1.10", "192.168.1.1"
    sites = [("www.example.com", "198.51.100.10"), ("cdn.example.net", "198.51.100.20"), ("mail.example.org", "198.51.100.30"),
             ("news.example.com", "198.51.100.11"), ("docs.example.net", "198.51.100.21")]
    t = base + 1
    for i in range(24):
        name, ip = b.rng.choice(sites)
        b.dns(t, c, res, name, answer=ip)
        b.tcp(t + 0.05, c, ip, b.rng.randrange(40000, 60000), 443,
              [build_client_hello(name, b.rng), tls_data(b.rng, 180)], [tls_data(b.rng, 1200), tls_data(b.rng, 900)])
        t += b.rng.uniform(8, 55)
    b.dns(base + 30, c, res, "updates.example.com", answer="198.51.100.40")
    b.tcp(base + 30.1, c, "198.51.100.40", 51111, 80,
          [f"GET /index.html HTTP/1.1\r\nHost: updates.example.com\r\nUser-Agent: {UA}\r\nAccept: */*\r\n\r\n".encode()],
          [b"HTTP/1.1 200 OK\r\nContent-Length: 600\r\n\r\n" + b"x" * 600])
    for i in range(12):  # NTP every 64 s: periodic but benign (shows the benign-port downgrade)
        tt = base + 5 + i * 64
        b.add(tt, b._eth(c, "203.0.113.123") / IP(src=c, dst="203.0.113.123") / UDP(sport=123, dport=123) / Raw(b"\x23" + b"\x00" * 47))
        b.add(tt + 0.03, b._eth("203.0.113.123", c) / IP(src="203.0.113.123", dst=c) / UDP(sport=123, dport=123) / Raw(b"\x24" + b"\x00" * 47))


def scenario_beacon(b: Builder, base=T0):
    c, s = "192.168.1.50", "203.0.113.50"
    for i in range(36):  # SIMULATED beacon: ~60 s with +/-1.5 s jitter, near-constant sizes
        t = base + 20 + i * 60 + b.rng.uniform(-1.5, 1.5)
        b.tcp(t, c, s, b.rng.randrange(40000, 60000), 8443,
              [build_client_hello("c2-sim.example", b.rng), tls_data(b.rng, 140)], [tls_data(b.rng, 300)])


def scenario_portscan(b: Builder, base=T0 + 600):
    sc, tgt = "192.168.1.66", "192.168.1.20"
    ports = list(range(1, 201)) + [445, 3389, 8080, 8443, 3306, 5432, 5900, 1433]
    b.rng.shuffle(ports)
    open_ports = {22, 80, 445, 3389}
    ports += [22, 80]
    t = base
    for p in ports:
        sport = b.rng.randrange(40000, 60000)
        seq = b.rng.randrange(1000, 2**31)
        b.add(t, b._eth(sc, tgt) / IP(src=sc, dst=tgt, ttl=45) / TCP(sport=sport, dport=p, flags="S", seq=seq, window=1024, options=[("MSS", 1460)]))
        if p in open_ports:
            b.add(t + 0.001, b._eth(tgt, sc) / IP(src=tgt, dst=sc) / TCP(sport=p, dport=sport, flags="SA", seq=9000, ack=seq + 1, window=65535))
            b.add(t + 0.002, b._eth(sc, tgt) / IP(src=sc, dst=tgt, ttl=45) / TCP(sport=sport, dport=p, flags="R", seq=seq + 1, window=0))
        else:
            b.add(t + 0.001, b._eth(tgt, sc) / IP(src=tgt, dst=sc) / TCP(sport=p, dport=sport, flags="RA", seq=0, ack=seq + 1, window=0))
        t += 0.004
    t += 5
    for h in range(100, 141):  # sweep of TCP/445
        host = f"192.168.1.{h}"
        sport, seq = b.rng.randrange(40000, 60000), b.rng.randrange(1000, 2**31)
        b.add(t, b._eth(sc, host) / IP(src=sc, dst=host, ttl=45) / TCP(sport=sport, dport=445, flags="S", seq=seq, window=1024, options=[("MSS", 1460)]))
        if h in (110, 125):
            b.add(t + 0.001, b._eth(host, sc) / IP(src=host, dst=sc) / TCP(sport=445, dport=sport, flags="RA", seq=0, ack=seq + 1, window=0))
        t += 0.05
    t += 3
    for h in range(1, 31):  # ICMP sweep
        host = f"192.168.1.{h}"
        b.add(t, b._eth(sc, host) / IP(src=sc, dst=host) / ICMP(type=8, id=7, seq=h) / Raw(b"abcdefgh"))
        if h % 3 == 0:
            b.add(t + 0.002, b._eth(host, sc) / IP(src=host, dst=sc) / ICMP(type=0, id=7, seq=h) / Raw(b"abcdefgh"))
        t += 0.03
    t += 3
    for path in ("/cgi-bin/test.cgi", "/admin/", "/phpmyadmin/", "/index.php?cmd=id"):
        b.tcp(t, sc, tgt, b.rng.randrange(40000, 60000), 80,
              [f"GET {path} HTTP/1.1\r\nHost: 192.168.1.20\r\nUser-Agent: Nikto/2.1.6 (SIMULATED)\r\n\r\n".encode()],
              [b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"])
        t += 0.5


def scenario_exfil(b: Builder, base=T0 + 900):
    c, s = "192.168.1.77", "198.51.100.25"
    total = 2000
    b.dns(base, c, "192.168.1.1", "files-sim.example", answer=s)
    body_len = total * 1400
    hdr = (f"POST /upload HTTP/1.1\r\nHost: files-sim.example\r\nUser-Agent: python-requests/2.31 (SIMULATED)\r\n"
           f"Content-Length: {body_len}\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    data = [hdr] + [b"\x00" * 1400] * (total - 1)
    sport = 50505
    t = base + 0.1
    sc, ss = 5000, 9000
    b.add(t, b._eth(c, s) / IP(src=c, dst=s) / TCP(sport=sport, dport=8080, flags="S", seq=sc, window=64240, options=[("MSS", 1460)]))
    b.add(t + 0.02, b._eth(s, c) / IP(src=s, dst=c) / TCP(sport=8080, dport=sport, flags="SA", seq=ss, ack=sc + 1))
    b.add(t + 0.04, b._eth(c, s) / IP(src=c, dst=s) / TCP(sport=sport, dport=8080, flags="A", seq=sc + 1, ack=ss + 1))
    sc, ss, t = sc + 1, ss + 1, t + 0.05
    for i, p in enumerate(data):
        b.add(t, b._eth(c, s) / IP(src=c, dst=s) / TCP(sport=sport, dport=8080, flags="PA", seq=sc, ack=ss) / Raw(p))
        sc += len(p)
        if i % 2 == 1:
            b.add(t + 0.0005, b._eth(s, c) / IP(src=s, dst=c) / TCP(sport=8080, dport=sport, flags="A", seq=ss, ack=sc))
        t += 0.008
    b.add(t, b._eth(s, c) / IP(src=s, dst=c) / TCP(sport=8080, dport=sport, flags="PA", seq=ss, ack=sc) / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
    b.add(t + 0.01, b._eth(c, s) / IP(src=c, dst=s) / TCP(sport=sport, dport=8080, flags="FA", seq=sc, ack=ss + 40))


def scenario_dns(b: Builder, base=T0 + 1200):
    c, res = "192.168.1.88", "192.168.1.1"
    t = base
    for i in range(300):  # SIMULATED tunnel-like names (random base32 labels)
        label = "".join(b.rng.choice(B32) for _ in range(44))
        name = f"{label}.t.tunnel-sim.example"
        nx = b.rng.random() < 0.3
        b.dns(t, c, res, name, qtype="TXT", rcode=3 if nx else 0, answer=None)
        t += b.rng.uniform(0.2, 0.6)
    for i in range(45):  # SIMULATED DGA-like names
        n = b.rng.randint(12, 16)
        label = "".join(b.rng.choice(CONS) if b.rng.random() > 0.08 else b.rng.choice("aeiou") for _ in range(n))
        b.dns(t, c, res, f"{label}.example", rcode=3)
        t += b.rng.uniform(0.5, 2.0)


SCENARIOS = {
    "normal_browsing_sim": [scenario_normal], "beacon_sim": [scenario_beacon], "portscan_sim": [scenario_portscan],
    "exfil_sim": [scenario_exfil], "dns_suspicious_sim": [scenario_dns],
}


def generate_all(out_dir) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written, combined = [], []
    for i, (name, fns) in enumerate(SCENARIOS.items()):
        b = Builder(seed=i + 1)
        for fn in fns:
            fn(b)
        pk = sorted(b.pkts, key=lambda p: float(p.time))
        path = out / f"{name}.pcap"
        wrpcap(str(path), pk)
        written.append(path)
        combined += pk
    path = out / "demo_combined_sim.pcap"
    wrpcap(str(path), sorted(combined, key=lambda p: float(p.time)))
    written.append(path)
    try:
        from scapy.utils import wrpcapng
        p2 = out / "demo_combined_sim.pcapng"
        wrpcapng(str(p2), sorted(combined, key=lambda p: float(p.time)))
        written.append(p2)
    except Exception:  # pcapng writing is optional
        pass
    return written


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parent)
    for f in generate_all(target):
        print(f"wrote {f} ({f.stat().st_size / 1024:.0f} KB)  [SIMULATED]")
