from core.flow_analysis import build_flows
from core.pcap_parser import parse_pcap
from sample_data.generate_samples import generate_all


def test_flow_states_from_scan(tmp_path):
    files = {p.name: p for p in generate_all(tmp_path)}
    pk, _ = parse_pcap(files["portscan_sim.pcap"])
    fl = build_flows(pk)
    tcp = fl[fl.proto == "TCP"]
    assert (tcp.state == "REJECTED").sum() > 150          # closed ports answered with RST
    assert (tcp.state == "NO_RESPONSE").sum() >= 30        # sweep of silent hosts
    assert tcp[tcp.syn > 0].src.eq("192.168.1.66").all()   # initiator is the scanner


def test_established_flow_and_direction(tmp_path):
    files = {p.name: p for p in generate_all(tmp_path)}
    pk, _ = parse_pcap(files["beacon_sim.pcap"])
    fl = build_flows(pk)
    assert (fl.state == "CLOSED").all() and len(fl) == 36
    assert fl.src.eq("192.168.1.50").all() and fl.dport.eq(8443).all()
    assert (fl.bytes_fwd > 0).all() and (fl.bytes_rev > 0).all()


def test_udp_idle_split(pkts_factory):
    rows = []
    for i in range(5):  # same 5-tuple every 64 s (like NTP): must become 5 flows
        rows.append(dict(ts=i * 64.0, proto="UDP", src="192.168.1.10", dst="203.0.113.1", sport=123, dport=123))
        rows.append(dict(ts=i * 64.0 + 0.03, proto="UDP", src="203.0.113.1", dst="192.168.1.10", sport=123, dport=123))
    fl = build_flows(pkts_factory(rows))
    assert len(fl) == 5 and fl.state.eq("REPLIED").all()


def test_empty_input(pkts_factory):
    assert build_flows(pkts_factory([])).empty
