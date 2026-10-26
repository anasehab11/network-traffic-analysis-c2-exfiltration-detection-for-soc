"""C2 beaconing detection from connection timing.

Periodicity alone is NOT proof of malice: many legitimate programs poll on a schedule.
Severity rises only when timing is combined with other weak signals.
"""
from __future__ import annotations

import pandas as pd

from core.models import make_alert
from core.utils import coeff_var, fmt_bytes, interval_stats, is_external, ts_to_str

COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3389, 445, 8080}


def is_periodic(st: dict, cfg) -> bool:
    return bool(st) and (st["cv"] <= cfg.beacon_max_cv or st["jitter_ok"] >= cfg.beacon_tolerance_fraction)


def detect_beacons(flows: pd.DataFrame, cfg):
    cols = ["src", "dst", "dport", "proto", "connections", "mean_interval", "median_interval", "std", "cv",
            "on_schedule", "bytes_out_mean", "bytes_in_mean", "periodic", "points", "first", "last"]
    if flows.empty:
        return pd.DataFrame(columns=cols), []
    f = flows[(flows["pkts_fwd"] > 0) & flows["proto"].isin(["TCP", "UDP"])]
    rows, alerts = [], []
    for (src, dst, dport, proto), g in f.groupby(["src", "dst", "dport", "proto"]):
        if len(g) < cfg.beacon_min_connections:
            continue
        st = interval_stats(g["start"], cfg.beacon_tolerance)
        if not st or not (cfg.beacon_min_interval_sec <= st["mean"] <= cfg.beacon_max_interval_sec):
            continue
        periodic = is_periodic(st, cfg)
        out_cv, in_cv = coeff_var(g["bytes_fwd"]), coeff_var(g["bytes_rev"])
        consistent = out_cv <= 0.2 and in_cv <= 0.3
        points = 0
        if periodic:
            points += int(is_external(dst)) + int(dport not in COMMON_PORTS) + int(consistent) + int(len(g) >= 20) + int(st["cv"] < 0.1)
        rows.append({"src": src, "dst": dst, "dport": int(dport), "proto": proto, "connections": len(g),
                     "mean_interval": round(st["mean"], 2), "median_interval": round(st["median"], 2),
                     "std": round(st["std"], 2), "cv": round(st["cv"], 3), "on_schedule": round(st["jitter_ok"], 2),
                     "bytes_out_mean": round(g["bytes_fwd"].mean(), 1), "bytes_in_mean": round(g["bytes_rev"].mean(), 1),
                     "periodic": periodic, "points": points, "first": g["start"].min(), "last": g["start"].max()})
        if not periodic:
            continue
        benign_port = int(dport) in set(cfg.beacon_benign_ports)
        if benign_port:
            sev, conf = "Informational", "Low"
        else:
            sev = "Low" if points <= 1 else "Medium" if points <= 3 else "High"
            conf = "Low" if points <= 1 else "Medium" if points <= 3 else "High"
        ok = int((g["state"].isin(["ESTABLISHED", "CLOSED", "RESET", "REPLIED"])).sum())
        starts = ", ".join(ts_to_str(t).split(" ")[1] for t in sorted(g["start"])[:5])
        ev = [f"{len(g)} {proto} connections from {src} to {dst}:{int(dport)} between {ts_to_str(g['start'].min())} and {ts_to_str(g['start'].max())}.",
              f"Interval mean {st['mean']:.2f}s, median {st['median']:.2f}s, std {st['std']:.2f}s, CV {st['cv']:.3f}; "
              f"{st['jitter_ok']:.0%} of intervals within +/-{cfg.beacon_tolerance:.0%} of the median.",
              f"Mean bytes per connection: {fmt_bytes(g['bytes_fwd'].mean())} out / {fmt_bytes(g['bytes_rev'].mean())} in "
              f"(size CV out {out_cv:.2f}, in {in_cv:.2f}).",
              f"{ok} of {len(g)} connections received a reply. First start times: {starts}.",
              f"Scoring signals ({points}): external destination={is_external(dst)}, non-standard port={dport not in COMMON_PORTS}, "
              f"consistent sizes={consistent}, >=20 connections={len(g) >= 20}, very regular (CV<0.1)={st['cv'] < 0.1}."]
        if benign_port:
            ev.append(f"Port {int(dport)} is on the benign-periodic list (e.g. NTP/DNS); severity capped at Informational.")
        alerts.append(make_alert(
            "BEACON-PERIODIC", f"Periodic connections to {dst}:{int(dport)} (beacon-like timing)", "Beaconing", sev, conf,
            src, dst, dport, proto, g["start"].min(), g["start"].max(), ev,
            f">= {cfg.beacon_min_connections} connections; CV <= {cfg.beacon_max_cv} or >= {cfg.beacon_tolerance_fraction:.0%} of intervals within +/-{cfg.beacon_tolerance:.0%}",
            ["Identify the process on the source host that opens these connections (EDR, netstat/Sysmon event 3).",
             "Check the destination IP/domain reputation and whether other hosts contact it.",
             "Inspect jitter, payload sizes and any HTTP/TLS metadata (SNI, JA3) for the group.",
             "If unexplained, isolate the host and collect memory/disk artefacts before remediation."],
            ["Software update checks, telemetry, heartbeat/keep-alive, monitoring agents, mail/chat polling, NTP.",
             "Browser tabs or SaaS clients refreshing on a timer."],
            extra={"iocs": ([{"type": "ip", "value": dst}] if is_external(dst) else []) + [{"type": "internal_host", "value": src}],
                   "points": points, "interval_mean": st["mean"], "nonstandard_port": dport not in COMMON_PORTS,
                   "benign_port": benign_port}))
    table = pd.DataFrame(rows, columns=cols).sort_values(["periodic", "points", "connections"], ascending=False)
    alerts.sort(key=lambda a: a.extra.get("points", 0), reverse=True)
    return table.reset_index(drop=True), alerts[: cfg.max_alerts_per_rule]
