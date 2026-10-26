"""Potential data exfiltration indicators.

Encrypted payloads cannot be inspected; volume and direction are only indicators.
"""
from __future__ import annotations

import pandas as pd

from core.models import make_alert
from core.utils import fmt_bytes, is_external, is_internal, ts_to_str

STEPS = ["Identify the process/user on the internal host responsible for the transfer (EDR, proxy logs).",
         "Check whether the destination is an approved backup/cloud/file-sharing service.",
         "Review what data was accessible to that host around that time (file-server and DLP logs).",
         "If unapproved: block the destination, preserve evidence and start incident handling."]
FP = ["Backups, cloud sync (OneDrive/Dropbox), software uploads, video conferencing, crash-dump uploads.",
      "Large legitimate file shares or mail attachments."]


def outbound_table(flows: pd.DataFrame) -> pd.DataFrame:
    """Aggregate traffic per (local, remote, port, proto) oriented from the internal host's point of view."""
    cols = ["local", "remote", "dport", "proto", "initiated_by", "flows", "bytes_out", "bytes_in", "ratio",
            "pkts_out", "first", "last", "remote_scope"]
    if flows.empty:
        return pd.DataFrame(columns=cols)
    f = flows[flows["proto"].isin(["TCP", "UDP"])].copy()
    si, di = f["src"].map(is_internal), f["dst"].map(is_internal)
    se, de = f["src"].map(is_external), f["dst"].map(is_external)
    up = si & de
    down = se & di
    lan = si & di
    f = f[up | down | lan]
    if f.empty:
        return pd.DataFrame(columns=cols)
    up, down = up[f.index], down[f.index]
    f["local"] = f["src"].where(~down, f["dst"])
    f["remote"] = f["dst"].where(~down, f["src"])
    f["bytes_out"] = f["bytes_fwd"].where(~down, f["bytes_rev"])
    f["bytes_in"] = f["bytes_rev"].where(~down, f["bytes_fwd"])
    f["pkts_out"] = f["pkts_fwd"].where(~down, f["pkts_rev"])
    f["initiated_by"] = down.map({True: "remote", False: "local"})
    f["remote_scope"] = f["remote"].map(lambda x: "external" if is_external(x) else "internal")
    g = f.groupby(["local", "remote", "dport", "proto", "initiated_by", "remote_scope"]).agg(
        flows=("flow_id", "size"), bytes_out=("bytes_out", "sum"), bytes_in=("bytes_in", "sum"),
        pkts_out=("pkts_out", "sum"), first=("start", "min"), last=("end", "max")).reset_index()
    g["ratio"] = (g["bytes_out"] / g["bytes_in"].clip(lower=1)).round(1)
    return g[cols].sort_values("bytes_out", ascending=False).reset_index(drop=True)


def detect_exfiltration(flows: pd.DataFrame, pkts: pd.DataFrame, cfg, dns_domains: pd.DataFrame | None = None):
    table = outbound_table(flows)
    alerts = []
    for _, r in table.iterrows():
        large = r.bytes_out >= cfg.exfil_large_bytes
        ratio = r.bytes_out >= cfg.exfil_ratio_min_bytes and r.ratio >= cfg.exfil_ratio
        if not (large or ratio):
            continue
        dur = max(r["last"] - r["first"], 1e-6)
        sev = "High" if (large and ratio) else "Medium"
        conf = "Medium" if (large and ratio) else "Low"
        notes = []
        if r.remote_scope == "internal":
            sev, conf = "Low", "Low"
            notes.append("Destination is internal: lateral/internal transfer, much more likely to be normal.")
        elif r.initiated_by == "remote":
            sev = {"High": "Medium", "Medium": "Low"}.get(sev, sev)
            notes.append("The remote host initiated the connection, so this looks like data served to a client rather than an upload.")
        rule = "EXFIL-LARGE" if large else "EXFIL-RATIO"
        ev = [f"{r.local} sent {fmt_bytes(r.bytes_out)} ({int(r.pkts_out)} packets) to {r.remote}:{int(r.dport)}/{r.proto} over {dur:.1f}s "
              f"(~{r.bytes_out / dur / 1024:.0f} KB/s) across {int(r.flows)} flow(s); {fmt_bytes(r.bytes_in)} came back.",
              f"Outbound-to-inbound ratio {r.ratio:.1f}:1. Large-volume rule {'met' if large else 'not met'} (>= {fmt_bytes(cfg.exfil_large_bytes)}); "
              f"ratio rule {'met' if ratio else 'not met'} (>= {cfg.exfil_ratio}:1 and >= {fmt_bytes(cfg.exfil_ratio_min_bytes)}).",
              "Byte counts are frame sizes seen in the capture; encrypted content cannot be inspected, so the data type is unknown."] + notes
        alerts.append(make_alert(
            rule, f"Large outbound transfer to {r.remote}:{int(r.dport)}", "Exfiltration", sev, conf, r.local, r.remote,
            r.dport, r.proto, r["first"], r["last"], ev,
            f"bytes_out >= {cfg.exfil_large_bytes} OR (bytes_out >= {cfg.exfil_ratio_min_bytes} AND out/in >= {cfg.exfil_ratio})", STEPS, FP,
            extra={"iocs": ([{"type": "ip", "value": r.remote}] if r.remote_scope == "external" else []) + [{"type": "internal_host", "value": r.local}],
                   "bytes_out": int(r.bytes_out)}))
    # HTTP POST/PUT with large declared body
    if pkts is not None and not pkts.empty:
        h = pkts[pkts["http_method"].isin(["POST", "PUT"]) & (pkts["http_clen"].fillna(0) >= cfg.exfil_http_post_bytes)]
        for (src, dst, dport), g in h.groupby(["src", "dst", "dport"]):
            n = int(g["http_clen"].max())
            host = g["http_host"].dropna().iloc[0] if g["http_host"].notna().any() else None
            alerts.append(make_alert(
                "EXFIL-HTTP-POST", f"Large HTTP {g['http_method'].iloc[0]} upload to {host or dst}", "Exfiltration",
                "Medium" if is_external(dst) else "Low", "Medium", src, dst, dport, "TCP", g.ts.min(), g.ts.max(),
                [f"{len(g)} cleartext HTTP request(s) declared Content-Length up to {fmt_bytes(n)} (host: {host or 'n/a'}, path: {g['http_path'].iloc[0]}).",
                 "Content-Length is what the client declared; the body itself is not stored or analysed."],
                f"POST/PUT Content-Length >= {cfg.exfil_http_post_bytes}", STEPS, FP + ["Legitimate web-form/file uploads."],
                extra={"iocs": ([{"type": "ip", "value": dst}] if is_external(dst) else []) + ([{"type": "domain", "value": host}] if host else []) + [{"type": "internal_host", "value": src}]}))
    # DNS data channel volume
    if dns_domains is not None and not dns_domains.empty:
        d = dns_domains[(dns_domains["query_name_bytes"] >= cfg.dns_exfil_bytes) & (dns_domains["unique_subdomains"] >= cfg.dns_tunnel_min_unique_subdomains)]
        for _, r in d.iterrows():
            alerts.append(make_alert(
                "EXFIL-DNS", f"Possible data transfer over DNS names under {r.domain}", "Exfiltration", "Medium", "Low", r.src,
                "resolver", 53, "UDP", r["first"], r["last"],
                [f"{int(r.queries)} queries carrying about {fmt_bytes(r.query_name_bytes)} of query-name text, {int(r.unique_subdomains)} unique subdomains under {r.domain}.",
                 "Data could be encoded into subdomain labels; the capture does not prove that anything was decoded by the server."],
                f"query-name bytes >= {cfg.dns_exfil_bytes} and unique subdomains >= {cfg.dns_tunnel_min_unique_subdomains}", STEPS,
                FP[:0] + ["CDN/telemetry hostnames with encoded identifiers."],
                extra={"iocs": [{"type": "domain", "value": r.domain}, {"type": "internal_host", "value": r.src}]}))
    return table, alerts[: cfg.max_alerts_per_rule * 2]
