import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config.settings import Thresholds  # noqa: E402
from core.flow_analysis import FLOW_COLUMNS  # noqa: E402
from core.pcap_parser import PACKET_COLUMNS  # noqa: E402

FLOW_DEFAULTS = dict(proto="TCP", src="192.168.1.10", sport=40000, dst="203.0.113.5", dport=443, start=0.0, end=1.0,
                     duration=1.0, pkts_fwd=5, pkts_rev=5, bytes_fwd=500, bytes_rev=1000, payload_fwd=100, payload_rev=800,
                     syn=1, synack=1, rst=0, fin=1, state="CLOSED", app=None, sni=None, http_host=None, syn_win=64240.0)


@pytest.fixture
def cfg():
    return Thresholds()


def make_flows(rows):
    out = []
    for i, r in enumerate(rows):
        d = {**FLOW_DEFAULTS, **r, "flow_id": i}
        d["end"] = r.get("end", d["start"] + 1.0)
        d["duration"] = d["end"] - d["start"]
        d["bytes_total"] = d["bytes_fwd"] + d["bytes_rev"]
        out.append(d)
    return pd.DataFrame(out, columns=FLOW_COLUMNS)


def make_pkts(rows):
    out = []
    for r in rows:
        d = dict.fromkeys(PACKET_COLUMNS)
        d.update(ip_ver=4, proto="UDP", length=100, src="192.168.1.10", dst="192.168.1.1", sport=40000, dport=53, payload_len=40)
        d.update(r)
        out.append(d)
    df = pd.DataFrame(out, columns=PACKET_COLUMNS)
    for c in ("sport", "dport", "tcp_window", "payload_len", "dns_qr", "dns_rcode", "http_clen", "http_status", "icmp_type", "ttl"):
        df[c] = pd.to_numeric(df[c], errors="coerce").astype("Int64")
    df["proto_label"] = df["app"].fillna(df["port_app"]).fillna(df["proto"])
    return df


@pytest.fixture
def flows_factory():
    return make_flows


@pytest.fixture
def pkts_factory():
    return make_pkts
