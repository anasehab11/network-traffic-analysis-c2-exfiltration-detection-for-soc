"""DNS investigation: statistics, tunneling, DGA-like and NXDOMAIN indicators."""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from core.beacon_detection import is_periodic
from core.models import make_alert
from core.utils import fmt_bytes, interval_stats, shannon_entropy, vowel_ratio

SECOND_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "co.in", "com.br",
                "com.cn", "com.eg", "gov.eg", "edu.eg", "com.sa", "co.za", "com.tr", "co.nz"}
IGNORED_SUFFIX = (".arpa", ".local", ".lan", ".home", ".internal")


def split_domain(qname: str):
    """Return (subdomain, registered_domain) using a small second-level suffix list."""
    labels = qname.strip(".").split(".")
    n = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL else 2
    if len(labels) <= n:
        return "", qname
    return ".".join(labels[:-n]), ".".join(labels[-n:])


@dataclass
class DNSResult:
    summary: dict = field(default_factory=dict)
    queries: pd.DataFrame = field(default_factory=pd.DataFrame)
    domains: pd.DataFrame = field(default_factory=pd.DataFrame)
    alerts: list = field(default_factory=list)


STEPS_TUNNEL = [
    "Pivot in Wireshark with the suggested DNS filter and look at query names, record types and response sizes.",
    "Check whether the client runs software that legitimately generates many DNS names (CDN, AV cloud lookups, DNS-based blocklists).",
    "Review the domain's registration age/reputation using your approved internal tooling; do not browse to it.",
    "If suspicious: isolate the host, capture endpoint process-to-network mapping (EDR) and block the domain at the resolver.",
]


def analyze_dns(pkts: pd.DataFrame, cfg) -> DNSResult:
    res = DNSResult()
    dns = pkts[pkts["dns_qname"].notna()]
    if dns.empty:
        res.summary = {"queries": 0, "responses": 0}
        return res
    qr = dns["dns_qr"].fillna(-1)
    q = dns[qr == 0].copy()
    r = dns[qr == 1].copy()
    q = q[~q["dns_qname"].str.endswith(IGNORED_SUFFIX)]
    r = r[~r["dns_qname"].str.endswith(IGNORED_SUFFIX)]
    parts = q["dns_qname"].map(split_domain)
    q["sub"] = parts.map(lambda t: t[0])
    q["reg"] = parts.map(lambda t: t[1])
    q["sub_nd"] = q["sub"].str.replace(".", "", regex=False)
    q["qlen"] = q["dns_qname"].str.len()
    q["label_max"] = q["dns_qname"].map(lambda s: max(len(x) for x in s.split(".")))
    q["entropy"] = q["sub_nd"].map(shannon_entropy)
    q["minute"] = (q["ts"] // 60).astype(int)
    r["reg"] = r["dns_qname"].map(lambda s: split_domain(s)[1])
    r["nx"] = r["dns_rcode"].fillna(-1) == 3

    resp_g = r.groupby(["dst", "reg"]).agg(resp=("nx", "size"), nx=("nx", "sum")) if not r.empty else pd.DataFrame()
    nx_by_client = r.groupby("dst").agg(resp=("nx", "size"), nx=("nx", "sum")) if not r.empty else pd.DataFrame()

    rows, alerts = [], []
    for (src, reg), g in q.groupby(["src", "reg"]):
        n = len(g)
        uniq = g.loc[g["sub"] != "", "sub"].nunique()
        long_n = int(((g.qlen >= cfg.dns_long_name_len) | (g.label_max >= cfg.dns_long_label_len)).sum())
        avg_sub = float(g.loc[g["sub"] != "", "sub_nd"].str.len().mean()) if uniq else 0.0
        hi_n = int(((g.sub_nd.str.len() >= cfg.dns_entropy_min_len) & (g.entropy >= cfg.dns_entropy_min)).sum())
        txt_ratio = float(g["dns_qtype"].isin(["TXT", "NULL", "ANY"]).mean())
        max_min = int(g.groupby("minute").size().max())
        nx_n, resp_n = 0, 0
        if not resp_g.empty and (src, reg) in resp_g.index:
            resp_n, nx_n = int(resp_g.loc[(src, reg), "resp"]), int(resp_g.loc[(src, reg), "nx"])
        name_bytes = int(g["qlen"].sum())
        ind = {
            "many_unique_subdomains": uniq >= cfg.dns_tunnel_min_unique_subdomains,
            "high_entropy": hi_n >= cfg.dns_min_hits,
            "long_names": long_n >= cfg.dns_min_hits or (n >= 10 and avg_sub >= cfg.dns_tunnel_avg_label_len),
            "txt_null_heavy": n >= 10 and txt_ratio >= 0.5,
            "high_frequency": max_min >= cfg.dns_high_freq_per_min,
        }
        score = sum(ind.values())
        rows.append({"src": src, "domain": reg, "queries": n, "unique_subdomains": uniq, "avg_subdomain_len": round(avg_sub, 1),
                     "mean_entropy": round(float(g.entropy[g.sub_nd.str.len() > 0].mean() or 0), 2) if uniq else 0.0,
                     "long_names": long_n, "high_entropy_names": hi_n, "txt_null_ratio": round(txt_ratio, 2),
                     "max_per_minute": max_min, "responses": resp_n, "nxdomain": nx_n, "query_name_bytes": name_bytes,
                     "tunnel_indicators": score, "first": g.ts.min(), "last": g.ts.max()})
        ev_common = [f"{n} queries from {src} for names under {reg} ({g.ts.min():.0f}-{g.ts.max():.0f} epoch).",
                     f"{uniq} unique subdomains; average subdomain length {avg_sub:.1f}; {hi_n} high-entropy names; "
                     f"{long_n} unusually long names; {txt_ratio:.0%} TXT/NULL/ANY queries; peak {max_min} queries/min."]
        if resp_n:
            ev_common.append(f"{nx_n} of {resp_n} responses were NXDOMAIN.")
        samples = g["dns_qname"].drop_duplicates().head(3).tolist()
        ev_common.append("Sample names: " + "; ".join(samples))
        extra = {"iocs": [{"type": "domain", "value": reg}, {"type": "internal_host", "value": src}],
                 "domain": reg, "indicators": [k for k, v in ind.items() if v]}
        thr = (f"tunnel indicators >= {cfg.dns_tunnel_min_score} of 5 (unique subdomains >= {cfg.dns_tunnel_min_unique_subdomains}, "
               f"entropy >= {cfg.dns_entropy_min}, name length >= {cfg.dns_long_name_len}, TXT/NULL >= 50%, rate >= {cfg.dns_high_freq_per_min}/min)")
        if score >= cfg.dns_tunnel_min_score:
            alerts.append(make_alert(
                "DNS-TUNNEL", f"Possible DNS tunneling to {reg}", "DNS", "High" if score >= 4 else "Medium",
                "High" if score >= 4 else "Medium", src, "resolver", 53, "UDP", g.ts.min(), g.ts.max(),
                ev_common + [f"Indicators met: {', '.join(extra['indicators'])}.",
                             "These are statistical indicators; the data inside the queries is not decoded."],
                thr, STEPS_TUNNEL,
                ["CDN, antivirus or telemetry services that encode identifiers in hostnames.",
                 "DNS-based blocklists / reputation lookups (e.g. mail filters).", "Wildcard DNS test tools."], extra=extra))
        elif ind["long_names"] or ind["high_entropy"]:
            alerts.append(make_alert(
                "DNS-ANOMALY", f"Unusual DNS names under {reg}", "DNS", "Low", "Low", src, "resolver", 53, "UDP",
                g.ts.min(), g.ts.max(), ev_common, "long names or high-entropy subdomains (below tunneling score)",
                STEPS_TUNNEL[:2], ["Cloud services using encoded hostnames."], extra=extra))
        elif ind["high_frequency"]:
            alerts.append(make_alert(
                "DNS-HIGHFREQ", f"High DNS query rate for {reg}", "DNS", "Low", "Low", src, "resolver", 53, "UDP",
                g.ts.min(), g.ts.max(), ev_common, f">= {cfg.dns_high_freq_per_min} queries/min to one domain",
                STEPS_TUNNEL[:2], ["Busy applications, short TTL records or retry loops."], extra=extra))
        # exfil-style volume handled in exfiltration_detection (uses query_name_bytes)

    domains = pd.DataFrame(rows)
    # DGA-like domains per source
    if not q.empty:
        q["sld"] = q["reg"].str.split(".").str[0]
        cand = q[(q["sld"].str.len() >= 10)]
        mask = cand["sld"].map(lambda s: shannon_entropy(s) >= cfg.dns_dga_min_entropy and vowel_ratio(s) <= cfg.dns_dga_max_vowel_ratio).astype(bool)
        cand = cand[mask]
        for src, g in cand.groupby("src"):
            regs = g["reg"].unique()
            if len(regs) >= cfg.dns_dga_min_domains:
                rr = r[(r["dst"] == src) & r["reg"].isin(regs)]
                nx, tot = int(rr["nx"].sum()), len(rr)
                high = tot >= 10 and nx / tot >= 0.7
                alerts.append(make_alert(
                    "DNS-DGA", "Many random-looking domain names (DGA-like pattern)", "DNS", "Medium",
                    "High" if high else "Medium", src, "resolver", 53, "UDP", g.ts.min(), g.ts.max(),
                    [f"{src} queried {len(regs)} distinct domains whose second-level labels look random (entropy >= {cfg.dns_dga_min_entropy}, vowel ratio <= {cfg.dns_dga_max_vowel_ratio}).",
                     (f"{nx} of {tot} matching responses were NXDOMAIN." if tot else "No responses captured, so NXDOMAIN rate unknown."),
                     "Samples: " + "; ".join(list(regs[:6]))],
                    f">= {cfg.dns_dga_min_domains} random-looking domains from one source",
                    ["Check whether the host runs software known to use random names (browser captive-portal checks, Chromium DNS probes).",
                     "Look for the process responsible via EDR; most DGAs are produced by malware or by coverage/probing tools.",
                     "Block at the resolver and review other hosts querying the same names."],
                    ["Browser/OS connectivity probes generate a few random names (Chromium), usually fewer than the threshold.",
                     "Security scanners or sandbox detonation."],
                    extra={"iocs": [{"type": "domain", "value": d} for d in regs[:10]] + [{"type": "internal_host", "value": src}],
                           "indicators": ["dga_like"]}))
    # overall NXDOMAIN
    if not nx_by_client.empty:
        for client, row in nx_by_client.iterrows():
            if row["resp"] >= cfg.dns_nxdomain_min_responses and row["nx"] / row["resp"] >= cfg.dns_nxdomain_ratio:
                if any(a.rule == "DNS-DGA" and a.src_ip == client for a in alerts):
                    continue
                alerts.append(make_alert(
                    "DNS-NXDOMAIN", "High NXDOMAIN rate", "DNS", "Low", "Medium", client, "resolver", 53, "UDP",
                    r.ts.min(), r.ts.max(),
                    [f"{int(row['nx'])} of {int(row['resp'])} responses to {client} were NXDOMAIN ({row['nx']/row['resp']:.0%})."],
                    f"NXDOMAIN >= {cfg.dns_nxdomain_ratio:.0%} of >= {cfg.dns_nxdomain_min_responses} responses",
                    ["List the failing names (Wireshark: dns.flags.rcode == 3).", "Check for typos, stale config or search-suffix lookups."],
                    ["Misconfigured software, stale hostnames, search-domain suffix expansion."],
                    extra={"iocs": [{"type": "internal_host", "value": client}]}))
    # periodic identical lookups
    for (src, name), g in q.groupby(["src", "dns_qname"]):
        if len(g) >= cfg.beacon_min_connections:
            st = interval_stats(g["ts"], cfg.beacon_tolerance)
            if st and is_periodic(st, cfg) and st["mean"] >= max(cfg.beacon_min_interval_sec, 5):
                alerts.append(make_alert(
                    "DNS-PERIODIC", f"Periodic DNS lookups for {name}", "DNS", "Low", "Low", src, "resolver", 53, "UDP",
                    g.ts.min(), g.ts.max(),
                    [f"{len(g)} lookups of {name}; mean interval {st['mean']:.1f}s, CV {st['cv']:.2f}, {st['jitter_ok']:.0%} of intervals on schedule."],
                    "regular intervals (see beacon thresholds)",
                    ["Determine which application polls this name.", "Compare with the domain's reputation."],
                    ["Software update checks, NTP/pool lookups, monitoring agents, mail clients."],
                    extra={"iocs": [{"type": "domain", "value": split_domain(name)[1]}]}))
    qt = q["dns_qtype"].value_counts().rename_axis("qtype").reset_index(name="queries")
    rc = r["dns_rcode"].map({0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}).fillna("OTHER").value_counts().rename_axis("rcode").reset_index(name="responses") if not r.empty else pd.DataFrame(columns=["rcode", "responses"])
    top = q["reg"].value_counts().head(15).rename_axis("domain").reset_index(name="queries")
    res.summary = {"queries": int(len(q)), "responses": int(len(r)), "unique_names": int(q["dns_qname"].nunique()),
                   "unique_domains": int(q["reg"].nunique()), "nxdomain_ratio": float(r["nx"].mean()) if len(r) else None,
                   "avg_name_len": float(q["qlen"].mean()) if len(q) else 0.0, "qtypes": qt, "rcodes": rc, "top_domains": top}
    res.queries, res.domains = q, domains
    res.alerts = alerts[: cfg.max_alerts_per_rule * 2]
    return res
