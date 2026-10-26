"""Network Traffic Analysis & C2/Exfiltration Detection for SOC - Streamlit dashboard.

Run with:  streamlit run app.py
All detection logic lives in core/; this file only renders results.
"""
from __future__ import annotations

import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from config.settings import THRESHOLD_SPEC, AppSettings, Thresholds, load_settings, save_settings
from core import report as report_mod
from core.analyzer import analyze_pcap
from core.pcap_parser import PcapValidationError
from core.protocol_analysis import (apply_filters, connection_stats, protocol_distribution, protocol_map, tcp_flag_summary,
                                    top_dst_ports, top_talkers, transport_distribution)
from core.utils import SEVERITIES, defang, fmt_bytes, ts_to_str
from core.wireshark_filters import CHEATSHEET
from database import db
from integrations import ollama_integration as oll
from integrations import suricata_integration as suri
from integrations import zeek_integration as zk

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
st.set_page_config(page_title="SOC Network Traffic Analyzer", page_icon="🛡️", layout="wide")

SEV_COLORS = {"Informational": "#6c8ebf", "Low": "#3fa34d", "Medium": "#e0a800", "High": "#e8590c", "Critical": "#c92a2a"}
GLOSSARY = {
    "PCAP": "A file of captured network packets.", "Flow": "All packets of one connection (same protocols, IPs and ports).",
    "SYN / RST / FIN": "TCP flags: SYN starts a connection, RST refuses or aborts it, FIN closes it politely.",
    "C2 / beaconing": "Command-and-Control: malware 'phoning home' at regular intervals to receive instructions.",
    "Exfiltration": "Unauthorised transfer of data out of the network.", "DNS tunneling": "Hiding data inside DNS queries/answers.",
    "DGA": "Domain Generation Algorithm: malware that invents many random domain names to find its server.",
    "SNI": "Server Name Indication: the hostname a TLS client asks for, visible before encryption starts.",
    "JA3": "A fingerprint (hash) of how a TLS client says hello; identifies client software, not a person.",
    "CV (coefficient of variation)": "Std-dev divided by mean of intervals; near 0 means very regular timing.",
    "Heuristic": "A rule-of-thumb finding. It points to something worth checking; it does not prove an attack.",
    "Corroborated": "Backed by stronger evidence such as a signature match or an analyst-supplied watchlist.",
}


# ------------------------------------------------------------------ helpers
def settings() -> AppSettings:
    if "settings" not in st.session_state:
        st.session_state.settings = load_settings()
    return st.session_state.settings


def table(df: pd.DataFrame, height: int | None = None):
    kw = {"height": height} if height else {}
    st.dataframe(df, width="stretch", hide_index=True, **kw)


def with_time(df: pd.DataFrame, *cols: str) -> pd.DataFrame:
    d = df.copy()
    for c in cols:
        if c in d:
            d[c] = pd.to_datetime(d[c], unit="s", utc=True).dt.strftime("%Y-%m-%d %H:%M:%S")
    return d


def get_result():
    r = st.session_state.get("result")
    if r is None:
        st.info("No analysis loaded yet. Go to **Upload PCAP** and analyze a capture or a bundled simulated sample.")
    return r


def alerts_df(alerts) -> pd.DataFrame:
    rows = [{"ID": a.alert_id, "Severity": a.severity, "Confidence": a.confidence, "Strength": a.evidence_strength, "Category": a.category,
             "Title": a.title, "Source": a.src_ip, "Destination": a.dst_ip, "Port": a.dst_port, "Proto": a.protocol,
             "First seen": ts_to_str(a.start_ts), "Risk": a.risk_score, "Rule": a.rule} for a in alerts]
    return pd.DataFrame(rows)


def sev_chart(alerts):
    c = pd.Series([a.severity for a in alerts]).value_counts().reindex(SEVERITIES, fill_value=0).reset_index()
    c.columns = ["Severity", "Alerts"]
    fig = px.bar(c, x="Severity", y="Alerts", color="Severity", color_discrete_map=SEV_COLORS, title="Alerts by severity")
    fig.update_layout(showlegend=False, height=300, margin=dict(t=40, b=10))
    st.plotly_chart(fig, width="stretch")


def alert_detail(a):
    badge = "Heuristic finding (threshold-based)" if a.evidence_strength == "Heuristic" else "Corroborated (signature / watchlist evidence)"
    st.markdown(f"### {a.title}")
    st.caption(f"{a.alert_id}  |  Severity **{a.severity}**  |  Confidence **{a.confidence}**  |  {badge}")
    c1, c2, c3 = st.columns(3)
    c1.metric("Source", a.src_ip)
    c2.metric("Destination", f"{a.dst_ip or 'n/a'}:{a.dst_port if a.dst_port is not None else 'n/a'}")
    c3.metric("Protocol", a.protocol)
    st.write(f"**Time range:** {ts_to_str(a.start_ts)} to {ts_to_str(a.end_ts)}")
    st.write(f"**Detection rule:** `{a.rule}`  -  **Threshold:** {a.threshold}")
    st.markdown("**Evidence**")
    for e in a.evidence:
        st.markdown(f"- {e}")
    with st.expander("Recommended investigation steps", expanded=True):
        for s in a.investigation_steps:
            st.markdown(f"- {s}")
    with st.expander("Possible false positives"):
        for s in a.false_positives:
            st.markdown(f"- {s}")
    with st.expander("MITRE ATT&CK"):
        if a.mitre:
            for t in a.mitre:
                st.markdown(f"- **{t['id']} {t['name']}** ({t['tactic']}): {t['rationale']}")
        else:
            st.write("No technique mapped: the evidence does not support a mapping.")
    if a.wireshark_filter:
        st.markdown("**Wireshark filter(s)**")
        for f in a.wireshark_filter.split(" | "):
            st.code(f, language="text")
    st.info("A heuristic alert is a lead to validate, not a confirmed attack.")


def alerts_for(result, *categories):
    return [a for a in result.alerts if a.category in categories]


def show_alert_list(alerts, key: str):
    if not alerts:
        st.success("No alerts in this category for the current thresholds.")
        return
    table(alerts_df(alerts))
    pick = st.selectbox("Inspect alert", [f"{a.alert_id} - {a.title}" for a in alerts], key=f"pick_{key}")
    alert_detail(next(a for a in alerts if pick.startswith(a.alert_id)))


def tool_status() -> pd.DataFrame:
    s = settings()
    o = oll.status(s.ollama_host)
    z, su = zk.status(s.zeek_path), suri.status(s.suricata_path)
    ts = shutil.which("tshark") or (s.tshark_path if s.tshark_path and Path(s.tshark_path).is_file() else None)
    try:
        import reportlab  # noqa: F401
        pdf = True
    except ImportError:
        pdf = False
    import scapy
    rows = [("Built-in detection engine (Scapy)", True, f"Scapy {scapy.VERSION}"),
            ("TShark / Wireshark", bool(ts), ts or "Optional, only needed for manual validation in Wireshark"),
            ("Zeek", z["available"], z["detail"]), ("Suricata", su["available"], su["detail"]),
            ("Ollama (local AI)", bool(o.get("available")), o.get("detail", "")),
            ("PDF export (reportlab)", pdf, "Available" if pdf else "pip install reportlab")]
    return pd.DataFrame(rows, columns=["Component", "Available", "Detail"])


# ------------------------------------------------------------------ pages
def page_dashboard():
    st.title("🛡️ SOC Network Traffic Analyzer")
    st.caption("Offline PCAP triage: reconnaissance, C2 beaconing, DNS abuse and data-exfiltration indicators.")
    r = get_result()
    if not r:
        st.dataframe(tool_status(), width="stretch", hide_index=True)
        return
    b = r.baseline
    c = st.columns(5)
    c[0].metric("Packets", f"{b.get('packets', 0):,}")
    c[1].metric("Duration", f"{b.get('duration_s', 0):.0f} s")
    c[2].metric("Hosts", b.get("unique_hosts", 0))
    c[3].metric("Alerts", len(r.alerts))
    c[4].metric("Overall risk", f"{r.risk_level}", f"{r.risk_score:.0f}/100", delta_color="off")
    st.caption(f"File: {r.meta['filename']}  |  SHA-256: {r.meta['sha256'][:16]}...  |  Risk is a heuristic prioritisation, not a verdict.")
    for w in r.meta.get("warnings", []):
        st.warning(w)
    l, rt = st.columns(2)
    with l:
        sev_chart(r.alerts) if r.alerts else st.success("No alerts raised.")
    with rt:
        if r.alerts:
            cat = pd.Series([a.category for a in r.alerts]).value_counts().reset_index()
            cat.columns = ["Category", "Alerts"]
            fig = px.pie(cat, names="Category", values="Alerts", title="Alerts by category", hole=0.4)
            fig.update_layout(height=300, margin=dict(t=40, b=10))
            st.plotly_chart(fig, width="stretch")
    if not r.hosts.empty:
        st.subheader("Hosts ranked by risk")
        table(r.hosts)
    if r.alerts:
        st.subheader("Top priority alerts")
        table(alerts_df(r.alerts[:8]).drop(columns=["Rule"]))
    st.subheader("Tool status")
    table(tool_status())


def page_upload():
    st.title("Upload PCAP")
    s = settings()
    st.write(f"Accepted: `.pcap`, `.pcapng`, `.cap` up to **{s.max_file_mb} MB**. Files are analysed locally and are never executed. "
             "Only use captures you are **authorised** to analyse.")
    up = st.file_uploader("Choose a capture file", type=["pcap", "pcapng", "cap"])
    samples = sorted((ROOT / "sample_data").glob("*.pcap*"))
    sample = st.selectbox("...or analyse a bundled SIMULATED sample", ["(none)"] + [p.name for p in samples])
    st.caption("Samples are synthetic scenarios generated by sample_data/generate_samples.py - not real malware captures.")
    c1, c2 = st.columns(2)
    use_zeek = c1.checkbox("Also run Zeek (if installed)", value=False, disabled=not zk.status(s.zeek_path)["available"])
    use_suri = c2.checkbox("Also run Suricata (if installed)", value=False, disabled=not suri.status(s.suricata_path)["available"])
    if st.button("Analyze", type="primary"):
        tmp_path, name = None, None
        try:
            if up is not None:
                if up.size > s.max_file_mb * 1024 * 1024:
                    st.error(f"File is {up.size / 1048576:.1f} MB; the limit is {s.max_file_mb} MB (change it in Settings).")
                    return
                suffix = Path(up.name).suffix.lower()
                fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix="upload_")
                with os.fdopen(fd, "wb") as f:
                    f.write(up.getbuffer())
                path, name = tmp_path, Path(up.name).name
            elif sample != "(none)":
                path, name = str(ROOT / "sample_data" / sample), sample
            else:
                st.warning("Choose a file or a sample first.")
                return
            bar, msg = st.progress(0.0), st.empty()

            def cb(text, pct=None):
                msg.text(text)
                if pct is not None:
                    bar.progress(min(pct, 1.0))

            result = analyze_pcap(path, s, progress=cb, run_zeek=use_zeek, run_suricata=use_suri, display_name=name)
            st.session_state.result = result
            st.session_state.analysis_id = db.save_analysis(s.db_path, result)
            st.session_state.ai_outputs = {}
            bar.progress(1.0)
            st.success(f"Analysis complete: {result.meta['packets']:,} packets, {len(result.alerts)} alerts. Open the other pages from the sidebar.")
            for w in result.meta.get("warnings", []):
                st.warning(w)
        except PcapValidationError as exc:
            st.error(str(exc))
        except Exception as exc:  # noqa: BLE001
            logging.getLogger(__name__).exception("Analysis failed")
            st.error(f"Unexpected error ({exc.__class__.__name__}). See the terminal log; the file may be unsupported.")
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)


def page_traffic():
    st.title("Traffic Overview")
    r = get_result()
    if not r:
        return
    p = r.pkts
    with st.expander("Filters", expanded=True):
        c1, c2, c3 = st.columns(3)
        ip = c1.text_input("IP address(es), comma-separated")
        protos = c2.multiselect("Protocol", sorted(p["proto_label"].dropna().unique()))
        port = c3.text_input("Port")
        start = end = None
        if r.meta["duration"] > 1:
            t0, t1 = pd.to_datetime(r.meta["first_ts"], unit="s").to_pydatetime(), pd.to_datetime(r.meta["last_ts"], unit="s").to_pydatetime()
            lo, hi = st.slider("Time range (UTC)", min_value=t0, max_value=t1, value=(t0, t1))
            start, end = lo.replace(tzinfo=__import__("datetime").timezone.utc).timestamp(), hi.replace(tzinfo=__import__("datetime").timezone.utc).timestamp()
    f = apply_filters(p, ip, protos, int(port) if port.strip().isdigit() else None, start, end)
    st.caption(f"{len(f):,} of {len(p):,} packets match.")
    if f.empty:
        st.warning("No packets match the filters.")
        return
    b = r.baseline
    c = st.columns(4)
    c[0].metric("Avg packets/s", b["avg_packets_per_s"])
    c[1].metric("Total bytes", fmt_bytes(b["total_bytes"]))
    c[2].metric("Top protocol", b["top_protocol"])
    c[3].metric("Top talker", (b["top_talker"] or "n/a").split(" ")[0])
    h = f.assign(time=pd.to_datetime(f["ts"], unit="s"))
    st.plotly_chart(px.histogram(h, x="time", nbins=60, title="Packets over time (UTC)").update_layout(height=280), width="stretch")
    l, rt = st.columns(2)
    d = protocol_distribution(f)
    l.plotly_chart(px.pie(d, names="protocol", values="packets", title="Protocol distribution", hole=0.35), width="stretch")
    tt = top_talkers(f, 10)
    rt.plotly_chart(px.bar(tt, x="host", y="bytes_sent", title="Top talkers (bytes sent)"), width="stretch")
    pf = r.flows[r.flows["start"].between(f.ts.min(), f.ts.max())]
    tp = top_dst_ports(pf, 10).assign(port=lambda x: x["proto"] + "/" + x["dport"].astype(str))
    l.plotly_chart(px.bar(tp, x="port", y="flows", title="Top destination ports (flows)"), width="stretch")
    rt.plotly_chart(px.bar(tcp_flag_summary(f), x="flag", y="packets", title="TCP flag analysis"), width="stretch")
    st.subheader("Network protocol map")
    pm = protocol_map(pf, 25)
    if not pm.empty:
        nodes = list(dict.fromkeys(list(pm.src) + list(pm.service) + list(pm.dst)))
        idx = {n: i for i, n in enumerate(nodes)}
        links = {"source": [], "target": [], "value": []}
        for _, row in pm.iterrows():
            links["source"] += [idx[row.src], idx[row.service]]
            links["target"] += [idx[row.service], idx[row.dst]]
            links["value"] += [row.flows, row.flows]
        fig = go.Figure(go.Sankey(node=dict(label=nodes, pad=12), link=links))
        fig.update_layout(height=450, margin=dict(t=10))
        st.plotly_chart(fig, width="stretch")
    st.subheader("Baseline summary")
    table(pd.DataFrame(list(b.items()), columns=["Metric", "Value"]).astype(str))
    st.subheader("Packet sample (first 500 matches)")
    table(with_time(f[["ts", "src", "dst", "proto", "proto_label", "sport", "dport", "length", "tcp_flags"]].head(500), "ts"), height=300)
    st.subheader("Wireshark display filter cheat sheet")
    table(pd.DataFrame(CHEATSHEET, columns=["Topic", "Purpose", "Display filter"]), height=300)


def page_protocol():
    st.title("Protocol Analysis")
    r = get_result()
    if not r:
        return
    l, rt = st.columns(2)
    l.subheader("Transport protocols")
    l.dataframe(transport_distribution(r.pkts), hide_index=True, width="stretch")
    rt.subheader("Connection states (flows)")
    rt.dataframe(connection_stats(r.flows), hide_index=True, width="stretch")
    st.subheader("Application protocols")
    st.plotly_chart(px.bar(protocol_distribution(r.pkts), x="protocol", y="packets", color="protocol"), width="stretch")
    st.caption("TCP states: ESTABLISHED = handshake seen; REJECTED = SYN answered by RST; NO_RESPONSE = SYN unanswered; "
               "PARTIAL = capture started mid-connection.")
    st.subheader("TCP flows")
    state = st.multiselect("State", sorted(r.flows["state"].unique()))
    fl = r.flows if not state else r.flows[r.flows["state"].isin(state)]
    table(with_time(fl.drop(columns=["flow_id"]).head(1000), "start", "end"), height=350)
    st.subheader("SMB / SSH / RDP connections")
    st.caption("Metadata only. A completed TCP handshake does not show that a login succeeded, and file contents are not visible.")
    table(with_time(r.remote_table, "first", "last")) if not r.remote_table.empty else st.write("No SMB/SSH/RDP traffic found.")
    show_alert_list(alerts_for(r, "Remote Services"), "remote")


def page_dns():
    st.title("DNS Investigation")
    r = get_result()
    if not r:
        return
    s = r.dns.summary
    if not s.get("queries"):
        st.info("No DNS queries found in this capture.")
        return
    c = st.columns(4)
    c[0].metric("Queries", s["queries"])
    c[1].metric("Unique names", s["unique_names"])
    c[2].metric("Unique domains", s["unique_domains"])
    c[3].metric("NXDOMAIN rate", "n/a" if s["nxdomain_ratio"] is None else f"{s['nxdomain_ratio']:.0%}")
    l, rt = st.columns(2)
    l.plotly_chart(px.bar(s["qtypes"], x="qtype", y="queries", title="Query types"), width="stretch")
    if len(s["rcodes"]):
        rt.plotly_chart(px.pie(s["rcodes"], names="rcode", values="responses", title="Response codes"), width="stretch")
    st.subheader("Per-source, per-domain behaviour")
    st.caption("tunnel_indicators counts: many unique subdomains, high entropy, long names, TXT/NULL-heavy, high query rate. 3+ raises a tunneling alert.")
    table(with_time(r.dns.domains.sort_values("tunnel_indicators", ascending=False), "first", "last"), height=300)
    st.subheader("Top queried domains")
    table(s["top_domains"])
    st.subheader("DNS alerts")
    show_alert_list(alerts_for(r, "DNS"), "dns")
    with st.expander("Query log sample (first 500)"):
        table(with_time(r.dns.queries[["ts", "src", "dns_qname", "dns_qtype", "entropy", "qlen"]].head(500), "ts"))


def page_http_tls():
    st.title("HTTP / TLS Investigation")
    r = get_result()
    if not r:
        return
    st.caption("TLS 1.3 encrypts certificates and payloads. Only the ClientHello (SNI, offered versions, JA3) and sizes/timing are visible.")
    t1, t2 = st.tabs(["HTTP (cleartext)", "TLS"])
    with t1:
        if r.http.empty:
            st.write("No cleartext HTTP requests found.")
        else:
            c1, c2 = st.columns(2)
            c1.subheader("User-agents")
            c1.dataframe(r.http["http_ua"].fillna("(missing)").value_counts().rename_axis("user-agent").reset_index(name="requests"), hide_index=True, width="stretch")
            c2.subheader("Hosts / methods")
            c2.dataframe(r.http.groupby(["http_host", "http_method"], dropna=False).size().reset_index(name="requests"), hide_index=True, width="stretch")
            table(with_time(r.http, "ts").head(500), height=300)
    with t2:
        if r.tls.empty:
            st.write("No TLS ClientHello messages found.")
        else:
            c1, c2 = st.columns(2)
            c1.subheader("Server names (SNI)")
            c1.dataframe(r.tls["tls_sni"].fillna("(none)").value_counts().rename_axis("SNI").reset_index(name="handshakes"), hide_index=True, width="stretch")
            c2.subheader("JA3 client fingerprints")
            c2.dataframe(r.tls["tls_ja3"].value_counts().rename_axis("JA3").reset_index(name="handshakes"), hide_index=True, width="stretch")
            table(with_time(r.tls, "ts").head(500), height=300)
    st.subheader("HTTP / TLS alerts")
    show_alert_list(alerts_for(r, "HTTP", "TLS"), "httptls")


def page_alerts():
    st.title("Alerts and Anomalies")
    r = get_result()
    if not r:
        return
    c1, c2, c3 = st.columns(3)
    sev = c1.multiselect("Severity", SEVERITIES, default=SEVERITIES)
    cats = c2.multiselect("Category", sorted({a.category for a in r.alerts}), default=sorted({a.category for a in r.alerts}))
    host = c3.text_input("Source or destination contains")
    al = [a for a in r.alerts if a.severity in sev and a.category in cats and (not host or host in a.src_ip or host in a.dst_ip)]
    st.caption(f"{len(al)} alert(s). Severity reflects potential impact; confidence reflects strength of evidence.")
    if not al:
        st.success("No alerts match.")
        return
    table(alerts_df(al))
    pick = st.selectbox("Inspect alert", [f"{a.alert_id} - {a.title}" for a in al])
    a = next(x for x in al if pick.startswith(x.alert_id))
    alert_detail(a)
    aid = st.session_state.get("analysis_id")
    if aid:
        notes = db.get_alert_notes(settings().db_path, aid).get(a.alert_id, {"status": "New", "note": ""})
        statuses = ["New", "Investigating", "False positive", "Confirmed (analyst-validated)", "Closed"]
        st.subheader("Analyst triage")
        s_val = st.selectbox("Status", statuses, index=statuses.index(notes["status"]) if notes["status"] in statuses else 0, key=f"st_{a.alert_id}")
        n_val = st.text_area("Notes", notes["note"], key=f"nt_{a.alert_id}")
        if st.button("Save triage", key=f"sv_{a.alert_id}"):
            db.set_alert_note(settings().db_path, aid, a.alert_id, s_val, n_val)
            st.success("Saved.")


def page_scan():
    st.title("Port Scan Analysis")
    r = get_result()
    if not r:
        return
    st.caption("A scan-like pattern is many probes that get no answer or a reset. A capture can rarely prove which tool (e.g. Nmap) was used.")
    if r.scan_table.empty:
        st.info("No TCP SYN probe activity found.")
    else:
        top = r.scan_table.head(15).assign(pair=lambda d: d["src"] + " -> " + d["dst"])
        st.plotly_chart(px.bar(top, x="pair", y="unique_ports", color="failed_ratio", title="Distinct ports probed per source/target pair"), width="stretch")
        table(with_time(r.scan_table, "first", "last"))
    show_alert_list(alerts_for(r, "Scan"), "scan")


def page_beacon():
    st.title("C2 Beaconing Analysis")
    r = get_result()
    if not r:
        return
    st.caption("Beaconing = repeated connections at near-regular intervals. Plenty of legitimate software does this too, so timing alone is rated low.")
    bt = r.beacon_table
    if bt.empty:
        st.info("No groups reached the minimum number of repeated connections.")
    else:
        table(with_time(bt, "first", "last"))
        opts = [f"{x.src} -> {x.dst}:{x.dport}/{x.proto}" for x in bt.itertuples()]
        pick = st.selectbox("Timeline for group", opts)
        x = bt.iloc[opts.index(pick)]
        g = r.flows[(r.flows.src == x.src) & (r.flows.dst == x.dst) & (r.flows.dport == x.dport) & (r.flows.proto == x.proto)].sort_values("start")
        iv = g["start"].diff().dropna()
        l, rt = st.columns(2)
        l.plotly_chart(px.scatter(g.assign(t=pd.to_datetime(g["start"], unit="s"), n=range(len(g))), x="t", y="n", title="Connection start times"), width="stretch")
        if len(iv):
            rt.plotly_chart(px.histogram(iv, nbins=20, title="Interval distribution (seconds)").update_layout(showlegend=False), width="stretch")
    show_alert_list(alerts_for(r, "Beaconing"), "beacon")


def page_exfil():
    st.title("Potential Exfiltration")
    r = get_result()
    if not r:
        return
    st.caption("Volume and direction are indicators only. Encrypted payloads cannot be inspected, so the type of data is unknown.")
    o = r.outbound
    if o.empty:
        st.info("No internal/external flow pairs to evaluate.")
    else:
        top = o.head(15).assign(dest=lambda d: d["local"] + " -> " + d["remote"] + ":" + d["dport"].astype(str))
        st.plotly_chart(px.bar(top, x="dest", y="bytes_out", color="ratio", title="Top outbound byte volumes"), width="stretch")
        t = o.copy()
        t["bytes_out"], t["bytes_in"] = t["bytes_out"].map(fmt_bytes), t["bytes_in"].map(fmt_bytes)
        table(with_time(t, "first", "last"))
    show_alert_list(alerts_for(r, "Exfiltration"), "exfil")


def page_ioc():
    st.title("IOC Explorer")
    r = get_result()
    if not r:
        return
    st.caption("Indicators extracted from the capture. 'Suspicious' only means referenced by an alert; validate before blocking anything.")
    d = r.iocs
    if d is None or d.empty:
        st.info("No indicators extracted.")
        return
    c1, c2, c3 = st.columns(3)
    types = c1.multiselect("Type", sorted(d["type"].unique()), default=sorted(d["type"].unique()))
    only = c2.checkbox("Only alert-referenced", value=True)
    df_ = c3.checkbox("Defang values", value=True)
    v = d[d["type"].isin(types)]
    v = v[v["suspicious"]] if only else v
    v = v.drop(columns=["first_seen", "last_seen"])
    if df_:
        v = v.assign(value=v["value"].map(lambda x: defang(x)))
    table(v, height=420)
    st.download_button("Download CSV", v.to_csv(index=False), "iocs.csv", "text/csv")


def page_mitre():
    st.title("MITRE ATT&CK Mapping")
    r = get_result()
    if not r:
        return
    st.caption("Techniques are mapped only where the evidence supports them. All mappings are candidates that need analyst validation.")
    if not r.mitre:
        st.info("No techniques were mapped for this capture.")
        return
    m = pd.DataFrame(r.mitre)
    st.plotly_chart(px.bar(m.groupby("tactic").size().reset_index(name="techniques"), x="tactic", y="techniques", title="Techniques by tactic"), width="stretch")
    show = m.assign(alert_ids=m["alert_ids"].map(", ".join), evidence=m["evidence"].map(lambda e: " | ".join(e)))
    table(show[["tactic", "id", "name", "confidence", "rationale", "alert_ids", "evidence", "url"]])


def page_ai():
    st.title("AI Investigation Assistant")
    r = get_result()
    if not r:
        return
    s = settings()
    info = oll.status(s.ollama_host)
    st.warning("AI output is a DRAFT. It can be wrong. Validate every claim against the evidence. PCAP-derived text is passed as untrusted data and the model cannot run commands.")
    if info.get("available"):
        st.success(f"Ollama is running: {info['detail']}")
    else:
        st.info(f"Local AI unavailable ({info.get('detail')}). Showing built-in non-AI summaries instead.")
    task = st.selectbox("Task", list(oll.TASKS))
    model = st.selectbox("Local model", info["models"]) if info.get("available") else None
    ctx = oll.build_context(r)
    with st.expander("Exactly what is sent to the model (structured summary, never the PCAP)"):
        st.json(ctx)
    if st.button("Run", type="primary"):
        if model:
            with st.spinner("Asking the local model..."):
                out = oll.generate(model, task, ctx, s.ollama_host, s.ollama_timeout)
            if out["ok"]:
                st.session_state.setdefault("ai_outputs", {})[task] = out["text"]
                st.caption(oll.LABEL)
                st.markdown(out["text"])
            else:
                st.error(out["text"])
        else:
            text = report_mod.fallback_text(r, task)
            st.caption("Non-AI fallback (template-based, built from detection results).")
            st.markdown(text)
    if st.session_state.get("ai_outputs"):
        st.caption("AI drafts saved for this session will be appended to exported reports as labelled appendices.")
    with st.expander("Prompt library"):
        for k, v in oll.TASKS.items():
            st.markdown(f"**{k}** - {v}")
        st.code(oll.SYSTEM_PROMPT, language="text")


def page_reports():
    st.title("Reports and Analysis History")
    r = get_result()
    s = settings()
    if r:
        st.subheader("Export report")
        concl = st.text_area("Analyst conclusion (written by you after validation)", key="conclusion", height=120)
        rep = report_mod.build_report(r, st.session_state.get("ai_outputs") or None, concl)
        md = report_mod.to_markdown(rep)
        c1, c2, c3 = st.columns(3)
        c1.download_button("Markdown", md, "soc_report.md", "text/markdown")
        c2.download_button("JSON", report_mod.to_json(rep), "soc_report.json", "application/json")
        fd, tmp = tempfile.mkstemp(suffix=".pdf")
        os.close(fd)
        try:
            if report_mod.to_pdf(rep, tmp):
                c3.download_button("PDF", Path(tmp).read_bytes(), "soc_report.pdf", "application/pdf")
            else:
                c3.caption("PDF unavailable: pip install reportlab")
        finally:
            os.unlink(tmp)
        if st.session_state.get("analysis_id") and st.button("Save conclusion to history"):
            db.set_conclusion(s.db_path, st.session_state.analysis_id, concl)
            st.success("Saved.")
        with st.expander("Preview"):
            st.markdown(md)
    st.subheader("Analysis history")
    hist = db.list_analyses(s.db_path)
    if not hist:
        st.write("No saved analyses yet.")
        return
    h = pd.DataFrame(hist)
    h["created_at"] = pd.to_datetime(h["created_at"], unit="s").dt.strftime("%Y-%m-%d %H:%M")
    table(h.drop(columns=["sha256"]))
    sel = st.selectbox("Open saved analysis", [f"{x['id']} - {x['filename']}" for x in hist])
    aid = int(sel.split(" - ")[0])
    rec = db.get_analysis(s.db_path, aid)
    st.json({"filename": rec["filename"], "risk": rec["summary"]["risk"], "alerts": len(rec["summary"]["alerts"]), "conclusion": rec["conclusion"]}, expanded=False)
    st.dataframe(pd.DataFrame(rec["summary"]["alerts"])[["alert_id", "severity", "confidence", "title", "src_ip", "dst_ip"]] if rec["summary"]["alerts"] else pd.DataFrame(), width="stretch", hide_index=True)
    if st.button("Delete this saved analysis"):
        db.delete_analysis(s.db_path, aid)
        st.rerun()


def page_settings():
    st.title("Settings and Tool Status")
    s = settings()
    st.subheader("Tool status")
    table(tool_status())
    st.caption("Everything optional can be missing; the built-in engine keeps working.")
    st.subheader("Limits and paths")
    s.max_file_mb = st.number_input("Max upload size (MB)", 1, 2000, int(s.max_file_mb))
    s.max_packets = st.number_input("Max packets analysed", 1000, 5_000_000, int(s.max_packets), step=10000)
    s.ollama_host = st.text_input("Ollama host (loopback only)", s.ollama_host)
    s.zeek_path = st.text_input("Zeek path (optional)", s.zeek_path)
    s.suricata_path = st.text_input("Suricata path (optional)", s.suricata_path)
    s.suricata_config = st.text_input("Suricata config (optional)", s.suricata_config)
    st.subheader("Detection thresholds")
    cur = s.get_thresholds().to_dict()
    new = {}
    groups = {"DNS": "dns_", "Beaconing": "beacon_", "Scanning": "scan_", "Remote services": "remote_", "Exfiltration": "exfil_", "HTTP/TLS & general": ""}
    used = set()
    for title, prefix in groups.items():
        with st.expander(title):
            for k, (default, desc) in THRESHOLD_SPEC.items():
                if k in used or (prefix and not k.startswith(prefix)) or (not prefix and k in used):
                    continue
                if title.startswith("DNS") and k == "dns_exfil_bytes":
                    continue
                used.add(k)
                if isinstance(default, list):
                    v = st.text_input(f"{k} (default {default})", ", ".join(map(str, cur[k])), help=desc)
                    new[k] = [int(x) for x in v.replace(" ", "").split(",") if x.isdigit()]
                elif isinstance(default, float):
                    new[k] = st.number_input(f"{k} (default {default})", value=float(cur[k]), help=desc)
                else:
                    new[k] = int(st.number_input(f"{k} (default {default})", value=int(cur[k]), step=1, help=desc))
    c1, c2 = st.columns(2)
    if c1.button("Save settings", type="primary"):
        s.thresholds = Thresholds(**new).to_dict()
        save_settings(s)
        st.success("Saved to config/settings.json. Re-analyse the capture to apply new thresholds.")
    if c2.button("Reset thresholds to defaults"):
        s.thresholds = None
        save_settings(s)
        st.rerun()


PAGES = {"Dashboard": page_dashboard, "Upload PCAP": page_upload, "Traffic Overview": page_traffic,
         "Protocol Analysis": page_protocol, "DNS Investigation": page_dns, "HTTP/TLS Investigation": page_http_tls,
         "Alerts and Anomalies": page_alerts, "Port Scan Analysis": page_scan, "C2 Beaconing Analysis": page_beacon,
         "Potential Exfiltration": page_exfil, "IOC Explorer": page_ioc, "MITRE ATT&CK": page_mitre,
         "AI Investigation Assistant": page_ai, "Reports and Analysis History": page_reports,
         "Settings and Tool Status": page_settings}

with st.sidebar:
    st.header("Navigation")
    choice = st.radio("Page", list(PAGES), label_visibility="collapsed")
    with st.expander("Glossary"):
        for k, v in GLOSSARY.items():
            st.markdown(f"**{k}**: {v}")
    st.caption("Offline analysis. Findings are heuristic indicators, not confirmed attacks.")
PAGES[choice]()
