import random

from core.beacon_detection import detect_beacons


def _group(times, **kw):
    return [dict(start=t, dst="203.0.113.50", dport=8443, **kw) for t in times]


def test_regular_beacon_detected(flows_factory, cfg):
    rng = random.Random(1)
    times = [i * 60 + rng.uniform(-1.5, 1.5) for i in range(30)]
    table, alerts = detect_beacons(flows_factory(_group(times, bytes_fwd=200, bytes_rev=600)), cfg)
    assert len(alerts) == 1 and alerts[0].rule == "BEACON-PERIODIC"
    assert alerts[0].severity == "High"
    assert any("CV" in e for e in alerts[0].evidence)
    assert table.iloc[0].periodic


def test_random_timing_not_flagged(flows_factory, cfg):
    rng = random.Random(2)
    t, times = 0, []
    for _ in range(30):
        t += rng.uniform(1, 200)
        times.append(t)
    _, alerts = detect_beacons(flows_factory(_group(times)), cfg)
    assert alerts == []


def test_too_few_connections(flows_factory, cfg):
    _, alerts = detect_beacons(flows_factory(_group([0, 60, 120, 180])), cfg)
    assert alerts == []


def test_burst_traffic_ignored(flows_factory, cfg):
    _, alerts = detect_beacons(flows_factory(_group([i * 0.1 for i in range(50)])), cfg)
    assert alerts == []   # mean interval below minimum


def test_benign_port_capped_informational(flows_factory, cfg):
    rows = [dict(start=i * 64.0, dst="203.0.113.1", dport=123, proto="UDP", state="REPLIED") for i in range(12)]
    _, alerts = detect_beacons(flows_factory(rows), cfg)
    assert alerts and alerts[0].severity == "Informational"


def test_one_missed_beat_tolerated(flows_factory, cfg):
    times = [i * 60 for i in range(20) if i != 9]
    _, alerts = detect_beacons(flows_factory(_group(times)), cfg)
    assert alerts   # jitter-tolerance fraction keeps it detected despite the doubled interval


def test_periodic_alone_is_not_high(flows_factory, cfg):
    times = [i * 30 for i in range(10)]
    rows = [dict(start=t, dst="192.168.1.99", dport=443, bytes_fwd=100 + i * 90, bytes_rev=50 + i * 400) for i, t in enumerate(times)]
    _, alerts = detect_beacons(flows_factory(rows), cfg)
    assert alerts and alerts[0].severity in ("Low", "Informational")   # internal dst, common port, varying sizes
