import random

from core.dns_analysis import analyze_dns, split_domain


def _q(i, src, name, t, qtype="A"):
    return dict(ts=t, src=src, dst="192.168.1.1", dns_qname=name, dns_qtype=qtype, dns_qr=0, app="DNS")


def _r(src_client, name, t, rcode):
    return dict(ts=t, src="192.168.1.1", dst=src_client, sport=53, dport=40000, dns_qname=name, dns_qtype="A", dns_qr=1, dns_rcode=rcode, app="DNS")


def test_split_domain():
    assert split_domain("a.b.example.com") == ("a.b", "example.com")
    assert split_domain("www.example.co.uk") == ("www", "example.co.uk")
    assert split_domain("example.com") == ("", "example.com")


def test_tunneling_detected(pkts_factory, cfg):
    rng = random.Random(3)
    rows = []
    for i in range(120):
        lab = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(44))
        rows.append(_q(i, "10.0.0.5", f"{lab}.t.tun.example", i * 0.3, "TXT"))
    res = analyze_dns(pkts_factory(rows), cfg)
    a = [x for x in res.alerts if x.rule == "DNS-TUNNEL"]
    assert a and a[0].severity in ("Medium", "High") and "tun.example" in a[0].title
    assert "not decoded" in " ".join(a[0].evidence) or a[0].evidence_strength == "Heuristic"


def test_normal_browsing_not_flagged(pkts_factory, cfg):
    names = ["www.example.com", "mail.example.com", "cdn.example.net", "api.example.org"]
    rows = [_q(i, "10.0.0.5", names[i % 4], i * 20.0) for i in range(40)]
    res = analyze_dns(pkts_factory(rows), cfg)
    assert not [a for a in res.alerts if a.rule in ("DNS-TUNNEL", "DNS-DGA", "DNS-ANOMALY")]


def test_many_unique_but_short_subdomains_is_not_tunnel(pkts_factory, cfg):
    rows = [_q(i, "10.0.0.5", f"n{i}.cdn.example.net", i * 5.0) for i in range(60)]   # CDN-like
    res = analyze_dns(pkts_factory(rows), cfg)
    assert not [a for a in res.alerts if a.rule == "DNS-TUNNEL"]


def test_dga_and_nxdomain(pkts_factory, cfg):
    rng = random.Random(5)
    rows = []
    for i in range(30):
        name = "".join(rng.choice("bcdfghjklmnpqrstvwxz") for _ in range(13)) + ".example"
        rows += [_q(i, "10.0.0.9", name, i), _r("10.0.0.9", name, i + 0.01, 3)]
    res = analyze_dns(pkts_factory(rows), cfg)
    dga = [a for a in res.alerts if a.rule == "DNS-DGA"]
    assert dga and dga[0].confidence == "High"
    assert not [a for a in res.alerts if a.rule == "DNS-NXDOMAIN"]   # folded into DGA alert


def test_nxdomain_only(pkts_factory, cfg):
    rows = []
    for i in range(40):
        n = f"host{i}.corp.example"
        rows += [_q(i, "10.0.0.7", n, i), _r("10.0.0.7", n, i + 0.01, 3)]
    res = analyze_dns(pkts_factory(rows), cfg)
    assert [a for a in res.alerts if a.rule == "DNS-NXDOMAIN"]


def test_no_dns(pkts_factory, cfg):
    res = analyze_dns(pkts_factory([dict(ts=1.0, proto="TCP")]), cfg)
    assert res.alerts == [] and res.summary["queries"] == 0
