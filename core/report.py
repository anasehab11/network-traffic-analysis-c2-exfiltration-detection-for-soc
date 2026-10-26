"""SOC incident report generation (JSON, Markdown, optional PDF). Works without AI."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from core.utils import SEVERITIES, defang, fmt_bytes, ts_to_str

REMEDIATION = {
    "Beaconing": ["Isolate the source host from the network pending triage.", "Block the destination IP/domain at the firewall/proxy after validation.",
                  "Collect process, memory and persistence artefacts with EDR; identify the program making the connections."],
    "DNS": ["Block or sinkhole the suspicious domain(s) at the resolver.", "Restrict outbound DNS to approved resolvers and enable DNS logging.",
            "Alert on long/high-entropy query patterns and high NXDOMAIN rates."],
    "Scan": ["Confirm whether the scanner is authorised; if not, isolate the source and review how it was compromised.",
             "Review exposed services on the targeted hosts and close what is not needed.", "Add IDS rules/rate limits for SYN scans and sweeps."],
    "Exfiltration": ["Determine what data the host could access and whether it left the network (DLP, proxy, cloud logs).",
                     "Block the destination if unapproved and preserve evidence.", "Enforce egress filtering and upload-size alerting."],
    "HTTP": ["Review web-server logs for the matching requests and responses.", "Patch/harden the targeted web application and enable a WAF where appropriate."],
    "TLS": ["Review the destination/SNI with threat intelligence; consider TLS inspection policy where lawful."],
    "Remote Services": ["Restrict SMB/RDP/SSH to management networks or VPN.", "Enforce MFA and account lockout; review authentication logs."],
    "Watchlist": ["Treat as high priority: find all hosts that contacted the indicator."],
}


def build_report(result, ai_sections: dict | None = None, conclusion: str = "") -> dict:
    m, b = result.meta, result.baseline
    sev = Counter(a.severity for a in result.alerts)
    top = result.alerts[:10]
    hi = [a for a in result.alerts if a.severity in ("High", "Critical")]
    exec_summary = (
        f"The capture '{m['filename']}' ({m['packets']:,} packets, {b.get('duration_s', 0)} s, {b.get('unique_hosts', 0)} hosts) was analysed "
        f"offline. The detection engine raised {len(result.alerts)} alert(s): "
        + ", ".join(f"{sev[s]} {s}" for s in reversed(SEVERITIES) if sev.get(s)) + ". " if result.alerts else
        f"The capture '{m['filename']}' ({m['packets']:,} packets) was analysed offline; no alerts were raised. ")
    if hi:
        exec_summary += (f"The highest-priority indicators are: " + "; ".join(f"{a.title} ({a.src_ip} -> {a.dst_ip or 'n/a'})" for a in hi[:3]) + ". ")
    exec_summary += (f"Overall heuristic risk is {result.risk_level} ({result.risk_score:.0f}/100). All findings are indicators that "
                     "require analyst validation; none is confirmed malicious activity on its own.")
    categories = sorted({a.category for a in result.alerts})
    remediation = []
    for c in categories:
        remediation += [f"[{c}] {r}" for r in REMEDIATION.get(c, [])]
    rep = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "executive_summary": exec_summary,
        "investigation_scope": ("Offline analysis of a single packet capture using the built-in heuristic engine"
                                + (" plus Suricata/Zeek output" if result.integrations else "") +
                                ". No live scanning, no external lookups, no payload extraction. Thresholds: see 'thresholds'."),
        "pcap_metadata": {k: m.get(k) for k in ("filename", "format", "size_bytes", "sha256", "packets", "non_ip_packets", "truncated")}
                         | {"first_packet_utc": ts_to_str(m.get("first_ts")), "last_packet_utc": ts_to_str(m.get("last_ts")),
                            "duration_s": round(m.get("duration") or 0, 2)},
        "network_overview": b,
        "key_findings": [f"[{a.severity}/{a.confidence}] {a.title}: {a.evidence[0] if a.evidence else ''}" for a in top],
        "prioritized_alerts": [{k: v for k, v in a.to_dict().items() if k not in ("extra",)} for a in result.alerts],
        "ioc_list": [] if result.iocs is None or result.iocs.empty else
                    result.iocs[result.iocs["suspicious"]].drop(columns=["first_seen", "last_seen"], errors="ignore").head(200).to_dict("records"),
        "mitre_mapping": result.mitre,
        "evidence_and_limitations": result.limitations,
        "false_positive_considerations": sorted({fp for a in result.alerts for fp in a.false_positives})[:25],
        "recommended_containment_and_remediation": remediation or ["No remediation actions suggested: no alerts were raised."],
        "analyst_conclusion": conclusion or "To be completed by the analyst after validating the findings above (status: UNREVIEWED).",
        "host_risk": [] if result.hosts.empty else result.hosts.to_dict("records"),
        "thresholds": result.thresholds,
        "ai_sections": ai_sections or {},
    }
    return rep


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str)


def _alert_md(a: dict) -> str:
    ev = "\n".join(f"  - {e}" for e in a["evidence"])
    steps = "\n".join(f"  - {s}" for s in a["investigation_steps"])
    fps = "\n".join(f"  - {s}" for s in a["false_positives"])
    mit = ", ".join(f"{t['id']} {t['name']}" for t in a["mitre"]) or "none (evidence insufficient for a mapping)"
    return (f"#### {a['alert_id']} - {a['title']}\n- **Severity / confidence:** {a['severity']} / {a['confidence']} ({a['evidence_strength']})\n"
            f"- **Source -> destination:** {a['src_ip']} -> {a['dst_ip'] or 'n/a'}:{a['dst_port'] if a['dst_port'] is not None else 'n/a'} ({a['protocol']})\n"
            f"- **Time range:** {ts_to_str(a['start_ts'])} to {ts_to_str(a['end_ts'])}\n- **Rule:** {a['rule']} - {a['threshold']}\n"
            f"- **Evidence:**\n{ev}\n- **Investigation steps:**\n{steps}\n- **Possible false positives:**\n{fps}\n- **MITRE ATT&CK:** {mit}\n"
            + (f"- **Wireshark filter(s):** `{a['wireshark_filter']}`\n" if a.get("wireshark_filter") else ""))


def to_markdown(rep: dict, defang_iocs: bool = True) -> str:
    md = ["# SOC Incident Investigation Report", f"_Generated {rep['generated_utc']} - draft for analyst review_", "",
          "## 1. Executive Summary", rep["executive_summary"], "", "## 2. Investigation Scope", rep["investigation_scope"], "",
          "## 3. PCAP File Metadata", *[f"- **{k}:** {v}" for k, v in rep["pcap_metadata"].items()], "",
          "## 4. Network Overview", *[f"- **{k}:** {v}" for k, v in rep["network_overview"].items()], "", "## 5. Key Findings"]
    md += [f"- {f}" for f in rep["key_findings"]] or ["- No alerts raised."]
    md += ["", "## 6. Prioritized Alerts"]
    md += [_alert_md(a) for a in rep["prioritized_alerts"]] or ["No alerts."]
    md += ["", "## 7. IOC List", "_Indicators referenced by alerts. Validate before blocking; values are defanged._" if defang_iocs else "_Validate before blocking._", "",
           "| Type | Value | Count | Related alerts |", "|---|---|---|---|"]
    for i in rep["ioc_list"]:
        v = defang(i["value"]) if defang_iocs and i["type"] != "ja3" else i["value"]
        md.append(f"| {i['type']} | `{v}` | {i['count']} | {i['related_alerts']} |")
    md += ["", "## 8. MITRE ATT&CK Mapping", "| Technique | Tactic | Confidence | Rationale | Alerts |", "|---|---|---|---|---|"]
    md += [f"| {t['id']} {t['name']} | {t['tactic']} | {t['confidence']} | {t['rationale']} | {', '.join(t['alert_ids'])} |" for t in rep["mitre_mapping"]] or ["| none | | | Evidence did not support a mapping | |"]
    md += ["", "## 9. Evidence and Limitations", *[f"- {x}" for x in rep["evidence_and_limitations"]], "",
           "## 10. False-Positive Considerations", *[f"- {x}" for x in rep["false_positive_considerations"]], "",
           "## 11. Recommended Containment and Remediation", *[f"- {x}" for x in rep["recommended_containment_and_remediation"]], "",
           "## 12. Analyst Conclusion", rep["analyst_conclusion"]]
    for name, text in rep.get("ai_sections", {}).items():
        md += ["", f"## Appendix - {name}", "> AI-GENERATED DRAFT - validate against the evidence before use.", "", text]
    return "\n".join(md) + "\n"


def to_pdf(rep: dict, path: str) -> bool:
    """Create a simple PDF with reportlab. Returns False if reportlab is not installed."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
        from xml.sax.saxutils import escape
    except ImportError:
        return False
    st = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=A4, title="SOC Incident Investigation Report")
    flow = []
    for line in to_markdown(rep).splitlines():
        if not line.strip():
            flow.append(Spacer(1, 5))
            continue
        text = escape(line.replace("`", "").replace("**", ""))
        if line.startswith("# "):
            flow.append(Paragraph(text[2:], st["Title"]))
        elif line.startswith("## "):
            flow.append(Paragraph(text[3:], st["Heading2"]))
        elif line.startswith("#### "):
            flow.append(Paragraph(text[5:], st["Heading4"]))
        else:
            flow.append(Paragraph(text, st["BodyText"]))
    doc.build(flow)
    return True


def fallback_text(result, task: str) -> str:
    """Non-AI explanations used when Ollama is unavailable."""
    a = result.alerts[:8]
    if task.startswith("Explain"):
        return "\n\n".join(f"**{x.title}** ({x.severity}, confidence {x.confidence})\n{x.evidence[0] if x.evidence else ''}\n"
                           f"Why it may be benign: {x.false_positives[0] if x.false_positives else 'n/a'}\nFirst check: {x.investigation_steps[0] if x.investigation_steps else 'n/a'}" for x in a) or "No alerts."
    if task.startswith("Suggest Wireshark"):
        return "\n".join(f"- {x.alert_id}: `{x.wireshark_filter}`" for x in a if x.wireshark_filter) or "No alert-specific filters."
    if task.startswith("Draft IOC"):
        s = result.iocs[result.iocs["suspicious"]] if result.iocs is not None and not result.iocs.empty else []
        return "\n".join(f"- {r['type']}: {defang(r['value'])} (alerts: {r['related_alerts']})" for _, r in s.head(30).iterrows()) or "No indicators referenced by alerts."
    if task.startswith("Suggest defensive") or task.startswith("Recommend"):
        return "\n".join(f"- {x}" for x in build_report(result)["recommended_containment_and_remediation"])
    if task.startswith("Draft SOC"):
        return to_markdown(build_report(result))
    return build_report(result)["executive_summary"] + "\n\n" + "\n".join(f"- {f}" for f in build_report(result)["key_findings"])
