from core.exfiltration_detection import detect_exfiltration, outbound_table
from core.http_tls_analysis import analyze_http_tls


def _flow(**kw):
    base = dict(src="192.168.1.77", dst="198.51.100.25", dport=8080, bytes_fwd=3_000_000, bytes_rev=20_000)
    base.update(kw)
    return base


def test_ratio_rule(flows_factory, pkts_factory, cfg):
    _, al = detect_exfiltration(flows_factory([_flow()]), pkts_factory([]), cfg)
    assert al and al[0].rule == "EXFIL-RATIO" and al[0].severity == "Medium" and al[0].confidence == "Low"
    assert any("encrypted" in e.lower() for e in al[0].evidence)


def test_large_and_ratio_is_high(flows_factory, pkts_factory, cfg):
    _, al = detect_exfiltration(flows_factory([_flow(bytes_fwd=50_000_000)]), pkts_factory([]), cfg)
    assert al[0].rule == "EXFIL-LARGE" and al[0].severity == "High"


def test_download_is_not_exfil(flows_factory, pkts_factory, cfg):
    _, al = detect_exfiltration(flows_factory([_flow(bytes_fwd=20_000, bytes_rev=50_000_000)]), pkts_factory([]), cfg)
    assert al == []


def test_balanced_transfer_not_flagged(flows_factory, pkts_factory, cfg):
    _, al = detect_exfiltration(flows_factory([_flow(bytes_fwd=3_000_000, bytes_rev=2_500_000)]), pkts_factory([]), cfg)
    assert al == []


def test_internal_to_internal_is_low(flows_factory, pkts_factory, cfg):
    _, al = detect_exfiltration(flows_factory([_flow(dst="192.168.1.50")]), pkts_factory([]), cfg)
    assert al and al[0].severity == "Low"


def test_remote_initiated_downgraded(flows_factory, pkts_factory, cfg):
    f = flows_factory([_flow(src="198.51.100.25", dst="192.168.1.77", dport=443, bytes_fwd=20_000, bytes_rev=3_000_000)])
    t = outbound_table(f)
    assert t.iloc[0].initiated_by == "remote" and t.iloc[0].bytes_out == 3_000_000
    _, al = detect_exfiltration(f, pkts_factory([]), cfg)
    assert al and al[0].severity == "Low"


def test_http_post_large(flows_factory, pkts_factory, cfg):
    p = pkts_factory([dict(ts=1.0, proto="TCP", src="192.168.1.77", dst="198.51.100.25", dport=80, http_method="POST",
                           http_host="up.example", http_path="/u", http_clen=5_000_000, app="HTTP")])
    _, al = detect_exfiltration(flows_factory([]), p, cfg)
    assert [a for a in al if a.rule == "EXFIL-HTTP-POST"]


# ---- HTTP / TLS
def _req(ua, path="/", **kw):
    d = dict(ts=1.0, proto="TCP", src="192.168.1.5", dst="198.51.100.9", dport=80, http_method="GET", http_host="site.example",
             http_path=path, http_ua=ua, app="HTTP")
    d.update(kw)
    return d


def test_scanner_ua(flows_factory, pkts_factory, cfg):
    _, _, al = analyze_http_tls(pkts_factory([_req("Nikto/2.1.6")]), flows_factory([]), cfg)
    assert [a for a in al if a.rule == "HTTP-SCANNER-UA"]


def test_normal_ua_no_alert(flows_factory, pkts_factory, cfg):
    _, _, al = analyze_http_tls(pkts_factory([_req("Mozilla/5.0 (X11; Linux) Firefox/120")]), flows_factory([]), cfg)
    assert al == []


def test_webshell_path_low_confidence(flows_factory, pkts_factory, cfg):
    _, _, al = analyze_http_tls(pkts_factory([_req("Mozilla/5.0", "/uploads/shell.php?cmd=id")]), flows_factory([]), cfg)
    a = [x for x in al if x.rule == "HTTP-PATH"][0]
    assert a.confidence == "Low" and a.extra["webshell"] is True
    assert any("cannot be confirmed" in e for e in a.evidence)


def test_missing_ua_informational(flows_factory, pkts_factory, cfg):
    _, _, al = analyze_http_tls(pkts_factory([_req(None)]), flows_factory([]), cfg)
    assert al and al[0].severity == "Informational"


def test_tls_dga_sni_and_old_version(flows_factory, pkts_factory, cfg):
    rows = [dict(ts=i, proto="TCP", src="192.168.1.5", dst="198.51.100.9", dport=443, tls_sni="xkqzpwvtrnlbhd.example",
                 tls_version="TLS 1.0", tls_ja3="a" * 32, app="TLS") for i in range(3)]
    _, _, al = analyze_http_tls(pkts_factory(rows), flows_factory([]), cfg)
    rules = {a.rule for a in al}
    assert {"TLS-DGA-SNI", "TLS-OLD-VERSION"} <= rules
