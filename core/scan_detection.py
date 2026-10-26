"""Reconnaissance detection: port scans, host sweeps, service enumeration, ping sweeps.

A capture can show scan-LIKE behaviour; it cannot by itself prove that Nmap (or any
specific tool) was used.
"""
from __future__ import annotations

import pandas as pd

from core.models import make_alert
from core.utils import fmt_ports, is_internal

SERVICE_PORTS = {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 587, 636, 993, 995,
                 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}
NMAP_NOTE = ("Evidence is insufficient to confirm Nmap specifically: SYN probes with a small fixed window are only "
             "consistent with Nmap defaults; OS fingerprinting/NSE traffic would need payload or option-level review.")


def _steps(src):
    return [f"Determine whether {src} is an authorised scanner or asset-inventory host.",
            "Review firewall/IDS logs for the same source in the surrounding hours.",
            "If unauthorised, isolate the source and investigate how it was compromised (internal) or block it (external).",
            "Check the targets for newly opened ports/services shown in the evidence."]


def detect_scans(flows: pd.DataFrame, cfg):
    cols = ["src", "dst", "probe_flows", "unique_ports", "failed_ratio", "open_ports", "first", "last"]
    tcp = flows[(flows["proto"] == "TCP") & (flows["syn"] > 0)]
    alerts, rows = [], []
    if not tcp.empty:
        tcp = tcp.assign(failed=tcp["state"].isin(["REJECTED", "NO_RESPONSE"]))
        for (src, dst), g in tcp.groupby(["src", "dst"]):
            ports = g["dport"].unique()
            rows.append({"src": src, "dst": dst, "probe_flows": len(g), "unique_ports": len(ports),
                         "failed_ratio": round(float(g["failed"].mean()), 2),
                         "open_ports": fmt_ports(g.loc[g["synack"] > 0, "dport"]), "first": g.start.min(), "last": g.end.max()})
            fr = float(g["failed"].mean())
            if len(ports) >= cfg.scan_min_ports and len(g) >= cfg.scan_min_flows and fr >= cfg.scan_failed_ratio:
                alerts.append(_alert("SCAN-VERTICAL", f"Port scan-like activity: {src} -> {dst}", src, dst, None, g, ports, fr, cfg,
                                     f"{len(ports)} distinct destination ports on {dst}"))
        for (src, dport), g in tcp.groupby(["src", "dport"]):
            hosts = g["dst"].nunique()
            fr = float(g["failed"].mean())
            if hosts >= cfg.scan_min_hosts and len(g) >= cfg.scan_min_flows and fr >= cfg.scan_failed_ratio:
                alerts.append(_alert("SCAN-HORIZONTAL", f"Host sweep on TCP/{dport} from {src}", src, "multiple", dport, g, [dport], fr, cfg,
                                     f"{hosts} distinct hosts probed on port {dport}"))
        flagged = {(a.src_ip, a.dst_ip) for a in alerts if a.rule == "SCAN-VERTICAL"}
        for (src, dst), g in tcp.groupby(["src", "dst"]):
            svc = sorted(set(g["dport"]) & SERVICE_PORTS)
            if len(svc) >= cfg.scan_service_enum_ports and (src, dst) not in flagged:
                alerts.append(make_alert(
                    "SCAN-SERVICE-ENUM", f"Service enumeration-like activity: {src} -> {dst}", "Scan",
                    "Medium" if is_internal(src) else "Low", "Low", src, dst, None, "TCP", g.start.min(), g.end.max(),
                    [f"{len(svc)} distinct well-known service ports contacted: {fmt_ports(svc)}.",
                     f"Open (SYN-ACK) ports observed: {fmt_ports(g.loc[g['synack'] > 0, 'dport']) or 'none'}.", NMAP_NOTE],
                    f">= {cfg.scan_service_enum_ports} well-known service ports on one host", _steps(src),
                    ["Monitoring or CMDB discovery tools.", "A user/application that legitimately uses many services on a server."],
                    extra={"iocs": [{"type": "internal_host", "value": src}]}))
    icmp = flows[(flows["proto"] == "ICMP")]
    for src, g in icmp.groupby("src"):
        hosts = g["dst"].nunique()
        if hosts >= cfg.scan_icmp_sweep_hosts:
            replied = int((g["pkts_rev"] > 0).sum())
            alerts.append(make_alert(
                "SCAN-ICMP-SWEEP", f"ICMP sweep-like activity from {src}", "Scan", "Low", "Medium", src, "multiple", None, "ICMP",
                g.start.min(), g.end.max(),
                [f"{src} sent ICMP to {hosts} distinct hosts; {replied} replied.", "ICMP type/code are not used to prove host discovery intent."],
                f">= {cfg.scan_icmp_sweep_hosts} distinct ICMP destinations from one source", _steps(src),
                ["Network monitoring (ping checks), traceroute, inventory tools."],
                extra={"iocs": [{"type": "internal_host", "value": src}]}))
    return pd.DataFrame(rows, columns=cols).sort_values("unique_ports", ascending=False).reset_index(drop=True), alerts[: cfg.max_alerts_per_rule]


def _alert(rule, title, src, dst, dport, g, ports, fr, cfg, headline):
    n = len(g)
    duration = max(g.end.max() - g.start.min(), 1e-6)
    ports_sorted = sorted(int(p) for p in ports)
    contiguous = sum(1 for a, b in zip(ports_sorted, ports_sorted[1:]) if b == a + 1) / max(len(ports_sorted) - 1, 1)
    win = g["syn_win"].dropna()
    win_share = float((win == 1024).mean()) if len(win) else 0.0
    opened = fmt_ports(g.loc[g["synack"] > 0, "dport"])
    strong = fr >= 0.9 and (len(ports) >= 2 * cfg.scan_min_ports or g["dst"].nunique() >= 2 * cfg.scan_min_hosts)
    ev = [f"{headline}; {n} SYN probe flows in {duration:.1f}s (~{n / duration:.0f} probes/s).",
          f"{fr:.0%} of probes got no answer or a reset (threshold {cfg.scan_failed_ratio:.0%}).",
          f"Ports probed: {fmt_ports(ports_sorted)}; {contiguous:.0%} of probed port numbers are contiguous (dense range coverage).",
          f"Open ports observed (SYN-ACK): {opened or 'none'}.",
          f"{win_share:.0%} of SYN probes used TCP window 1024 (consistent with, not proof of, Nmap defaults).", NMAP_NOTE]
    internal = is_internal(src)
    return make_alert(
        rule, title, "Scan", "High" if internal else "Medium", "High" if strong else "Medium", src, dst, dport, "TCP",
        g.start.min(), g.end.max(), ev,
        f"flows >= {cfg.scan_min_flows} and failed ratio >= {cfg.scan_failed_ratio:.0%} and (ports >= {cfg.scan_min_ports} on one host or hosts >= {cfg.scan_min_hosts} on one port)",
        _steps(src),
        ["Authorised vulnerability scanner or asset discovery.", "Internet background scanning (if the source is external)."],
        extra={"iocs": [{"type": "internal_host" if internal else "ip", "value": src}], "failed_ratio": fr})
