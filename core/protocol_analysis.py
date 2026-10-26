"""Traffic statistics, baseline summary, filtering and SMB/SSH/RDP analysis."""
from __future__ import annotations

import pandas as pd

from core.models import make_alert
from core.utils import fmt_bytes, is_external, is_internal

REMOTE_PORTS = {445: "SMB", 139: "SMB", 3389: "RDP", 22: "SSH"}


def protocol_distribution(pkts: pd.DataFrame) -> pd.DataFrame:
    if pkts.empty:
        return pd.DataFrame(columns=["protocol", "packets", "bytes"])
    g = pkts.groupby("proto_label").agg(packets=("ts", "size"), bytes=("length", "sum")).reset_index()
    return g.rename(columns={"proto_label": "protocol"}).sort_values("packets", ascending=False)


def transport_distribution(pkts: pd.DataFrame) -> pd.DataFrame:
    if pkts.empty:
        return pd.DataFrame(columns=["transport", "packets", "bytes"])
    g = pkts.groupby("proto").agg(packets=("ts", "size"), bytes=("length", "sum")).reset_index()
    return g.rename(columns={"proto": "transport"}).sort_values("packets", ascending=False)


def tcp_flag_summary(pkts: pd.DataFrame) -> pd.DataFrame:
    tcp = pkts[pkts["proto"] == "TCP"]
    f = tcp["tcp_flags"].fillna("")
    s, a = f.str.contains("S"), f.str.contains("A")
    rows = [("SYN (connection attempts)", int((s & ~a).sum())), ("SYN-ACK (accepted)", int((s & a).sum())),
            ("RST (reset / refused)", int(f.str.contains("R").sum())), ("FIN (graceful close)", int(f.str.contains("F").sum()))]
    return pd.DataFrame(rows, columns=["flag", "packets"])


def top_talkers(pkts: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    if pkts.empty:
        return pd.DataFrame(columns=["host", "packets_sent", "bytes_sent", "bytes_received", "scope"])
    out = pkts.groupby("src").agg(packets_sent=("ts", "size"), bytes_sent=("length", "sum"))
    inn = pkts.groupby("dst").agg(bytes_received=("length", "sum"))
    t = out.join(inn, how="outer").fillna(0).reset_index().rename(columns={"index": "host"})
    t = t.rename(columns={t.columns[0]: "host"})
    t["scope"] = t["host"].map(lambda x: "internal" if is_internal(x) else ("external" if is_external(x) else "special"))
    return t.sort_values("bytes_sent", ascending=False).head(n).reset_index(drop=True)


def top_dst_ports(flows: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    f = flows[flows["proto"].isin(["TCP", "UDP"])]
    if f.empty:
        return pd.DataFrame(columns=["proto", "dport", "service", "flows", "bytes"])
    g = f.groupby(["proto", "dport"]).agg(flows=("flow_id", "size"), bytes=("bytes_total", "sum"),
                                          service=("app", "first")).reset_index()
    return g.sort_values("flows", ascending=False).head(n).reset_index(drop=True)


def connection_stats(flows: pd.DataFrame) -> pd.DataFrame:
    if flows.empty:
        return pd.DataFrame(columns=["state", "flows"])
    return flows.groupby(["proto", "state"]).size().reset_index(name="flows").sort_values("flows", ascending=False)


def protocol_map(flows: pd.DataFrame, top: int = 25) -> pd.DataFrame:
    if flows.empty:
        return pd.DataFrame(columns=["src", "service", "dst", "flows", "bytes"])
    f = flows.assign(service=flows["app"].fillna(flows["proto"]))
    g = f.groupby(["src", "service", "dst"]).agg(flows=("flow_id", "size"), bytes=("bytes_total", "sum")).reset_index()
    return g.sort_values("flows", ascending=False).head(top).reset_index(drop=True)


def baseline_summary(meta: dict, pkts: pd.DataFrame, flows: pd.DataFrame) -> dict:
    if pkts.empty:
        return {"packets": 0}
    dur = max(meta.get("duration") or 0.0, 1e-9)
    hosts = set(pkts["src"]) | set(pkts["dst"])
    tt, tp = top_talkers(pkts, 1), top_dst_ports(flows, 1)
    return {
        "packets": int(len(pkts)), "total_bytes": int(pkts["length"].sum()), "duration_s": round(dur, 2),
        "avg_packets_per_s": round(len(pkts) / dur, 2), "avg_packet_size": round(float(pkts["length"].mean()), 1),
        "unique_hosts": len(hosts), "internal_hosts": sum(is_internal(h) for h in hosts),
        "external_hosts": sum(is_external(h) for h in hosts), "flows": int(len(flows)),
        "tcp_packets": int((pkts.proto == "TCP").sum()), "udp_packets": int((pkts.proto == "UDP").sum()),
        "icmp_packets": int(pkts.proto.isin(["ICMP", "ICMPv6"]).sum()),
        "top_protocol": protocol_distribution(pkts).iloc[0]["protocol"],
        "top_talker": None if tt.empty else f"{tt.iloc[0]['host']} ({fmt_bytes(tt.iloc[0]['bytes_sent'])} sent)",
        "top_dst_port": None if tp.empty else f"{tp.iloc[0]['proto']}/{int(tp.iloc[0]['dport'])}",
    }


def apply_filters(pkts: pd.DataFrame, ip: str = "", proto=None, port=None, start=None, end=None) -> pd.DataFrame:
    """Filter by IP (comma separated, src or dst), protocol label, port and epoch time range."""
    d = pkts
    if ip:
        ips = [x.strip() for x in ip.split(",") if x.strip()]
        d = d[d["src"].isin(ips) | d["dst"].isin(ips)]
    if proto:
        protos = [proto] if isinstance(proto, str) else list(proto)
        d = d[d["proto_label"].isin(protos) | d["proto"].isin(protos)]
    if port not in (None, "", 0):
        p = int(port)
        d = d[(d["sport"] == p) | (d["dport"] == p)]
    if start is not None:
        d = d[d["ts"] >= start]
    if end is not None:
        d = d[d["ts"] <= end]
    return d


def analyze_remote_services(flows: pd.DataFrame, cfg):
    """SMB/SSH/RDP connection metadata and connection-pattern alerts. Authentication success is never inferred."""
    cols = ["service", "src", "dst", "dport", "flows", "completed", "failed", "bytes_out", "bytes_in",
            "median_duration", "first", "last"]
    sel = flows[(flows["proto"] == "TCP") & flows["dport"].isin(REMOTE_PORTS.keys())]
    if sel.empty:
        return pd.DataFrame(columns=cols), []
    sel = sel.assign(done=sel["synack"] > 0, bad=sel["state"].isin(["REJECTED", "NO_RESPONSE"]))
    t = sel.groupby(["src", "dst", "dport"]).agg(
        flows=("flow_id", "size"), completed=("done", "sum"), failed=("bad", "sum"), bytes_out=("bytes_fwd", "sum"),
        bytes_in=("bytes_rev", "sum"), median_duration=("duration", "median"), first=("start", "min"),
        last=("end", "max")).reset_index()
    t["service"] = t["dport"].map(REMOTE_PORTS)
    alerts = []
    steps = ["Identify the source host and its owner; check whether remote administration from it is expected.",
             "Review authentication logs (Windows Security 4624/4625, SSH auth.log) on the destination(s).",
             "In Wireshark filter on the source and port to review timing and session lengths."]
    # sweeps: one source -> many hosts on one remote-access port
    for (src, dport), g in sel.groupby(["src", "dport"]):
        hosts = g["dst"].nunique()
        if hosts >= cfg.remote_sweep_hosts:
            svc = REMOTE_PORTS[dport]
            done = g[g["done"]]["dst"].nunique()
            alerts.append(make_alert(
                f"REMOTE-{svc}-SWEEP", f"{svc} connections to many hosts from one source", "Remote Services",
                "Medium", "Medium" if done else "Low", src, "multiple", dport, "TCP", g.start.min(), g.end.max(),
                [f"{src} contacted {hosts} distinct hosts on TCP/{dport} ({svc}).",
                 f"{done} host(s) completed the TCP handshake; this does NOT show a successful login.",
                 f"Total flows: {len(g)}."],
                f"distinct destination hosts >= {cfg.remote_sweep_hosts} on one {svc} port", steps,
                ["Admin/inventory/backup tools legitimately contact many hosts.", "Vulnerability scanners."],
                extra={"iocs": [{"type": "internal_host", "value": src}]}))
    # repeated short sessions: brute-force-like
    for _, r in t.iterrows():
        if r.flows >= cfg.remote_repeat_conns and r.median_duration < 10:
            svc = r.service
            alerts.append(make_alert(
                "REMOTE-REPEAT", f"Repeated short {svc} sessions (possible password guessing)", "Remote Services",
                "Medium" if svc in ("SSH", "RDP") else "Low", "Low", r.src, r.dst, r.dport, "TCP", r["first"], r["last"],
                [f"{int(r.flows)} connections from {r.src} to {r.dst}:{int(r.dport)}, median duration {r.median_duration:.2f}s.",
                 f"{int(r.completed)} completed the TCP handshake, {int(r.failed)} were refused/unanswered.",
                 "The capture cannot show whether authentication succeeded or failed."],
                f"flows >= {cfg.remote_repeat_conns} with median duration < 10 s", steps,
                ["Automation, monitoring checks or load balancers health-probing the service.",
                 "Users reconnecting after network drops."], extra={"iocs": [{"type": "ip", "value": r.src}]}))
    # exposure from an external address
    for _, r in t.iterrows():
        if is_external(r.src) and is_internal(r.dst) and r.completed > 0:
            alerts.append(make_alert(
                "REMOTE-EXPOSED", f"{r.service} service reachable from an external address", "Remote Services",
                "Medium" if r.service in ("SMB", "RDP") else "Low", "Medium", r.src, r.dst, r.dport, "TCP",
                r["first"], r["last"],
                [f"External host {r.src} completed {int(r.completed)} TCP handshake(s) with internal {r.dst}:{int(r.dport)}.",
                 "Shows exposure of the service, not a compromise."],
                "external source with completed handshake to internal remote-access port",
                ["Confirm the service is meant to be Internet-reachable.", "Check firewall/NAT rules and VPN requirements."],
                ["Intentional remote access (VPN/jump host)."], extra={"iocs": [{"type": "ip", "value": r.src}]}))
    return t[cols], alerts[: cfg.max_alerts_per_rule]
