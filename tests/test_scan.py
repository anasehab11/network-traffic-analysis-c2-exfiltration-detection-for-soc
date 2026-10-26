from core.scan_detection import detect_scans


def _syn(dst, port, i, state="REJECTED"):
    return dict(src="192.168.1.66", dst=dst, dport=port, start=i * 0.01, syn=1, synack=0, state=state, pkts_rev=1, syn_win=1024.0)


def test_vertical_scan(flows_factory, cfg):
    rows = [_syn("192.168.1.20", p, p) for p in range(1, 101)]
    _, alerts = detect_scans(flows_factory(rows), cfg)
    v = [a for a in alerts if a.rule == "SCAN-VERTICAL"]
    assert v and v[0].severity == "High"          # internal source
    assert any("Nmap" in e for e in v[0].evidence)  # honest limitation note
    assert any("100 distinct" in e for e in v[0].evidence)


def test_horizontal_sweep(flows_factory, cfg):
    rows = [_syn(f"192.168.1.{h}", 445, h, "NO_RESPONSE") for h in range(1, 41)]
    _, alerts = detect_scans(flows_factory(rows), cfg)
    assert [a for a in alerts if a.rule == "SCAN-HORIZONTAL"]


def test_below_threshold_no_alert(flows_factory, cfg):
    rows = [_syn("192.168.1.20", p, p) for p in range(1, 10)]
    assert detect_scans(flows_factory(rows), cfg)[1] == []


def test_successful_connections_not_scan(flows_factory, cfg):
    rows = [dict(src="192.168.1.5", dst="192.168.1.20", dport=p, start=p, synack=1, state="CLOSED") for p in range(1, 60)]
    assert [a for a in detect_scans(flows_factory(rows), cfg)[1] if a.rule == "SCAN-VERTICAL"] == []


def test_external_source_is_medium(flows_factory, cfg):
    rows = [dict(_syn("192.168.1.20", p, p), src="198.51.100.9") for p in range(1, 101)]
    alerts = detect_scans(flows_factory(rows), cfg)[1]
    assert alerts and alerts[0].severity == "Medium"


def test_service_enumeration(flows_factory, cfg):
    ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3389]
    rows = [dict(src="192.168.1.5", dst="192.168.1.20", dport=p, start=p, synack=1, state="CLOSED") for p in ports]
    alerts = detect_scans(flows_factory(rows), cfg)[1]
    assert [a for a in alerts if a.rule == "SCAN-SERVICE-ENUM"]


def test_icmp_sweep(flows_factory, cfg):
    rows = [dict(proto="ICMP", src="192.168.1.66", dst=f"192.168.1.{h}", dport=0, start=h, syn=0, synack=0, state="NO_REPLY", pkts_rev=0) for h in range(1, 31)]
    assert [a for a in detect_scans(flows_factory(rows), cfg)[1] if a.rule == "SCAN-ICMP-SWEEP"]
