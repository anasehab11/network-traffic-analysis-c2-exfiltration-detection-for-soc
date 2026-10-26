"""MITRE ATT&CK mapping. Techniques are attached only when the rule's evidence supports them."""
from __future__ import annotations

TECHNIQUES = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1595.001": ("Active Scanning: Scanning IP Blocks", "Reconnaissance"),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "Reconnaissance"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1018": ("Remote System Discovery", "Discovery"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1572": ("Protocol Tunneling", "Command and Control"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1568.002": ("Dynamic Resolution: Domain Generation Algorithms", "Command and Control"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1048.003": ("Exfiltration Over Unencrypted Non-C2 Protocol", "Exfiltration"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1110": ("Brute Force", "Credential Access"),
}
TACTIC_ORDER = ["Reconnaissance", "Initial Access", "Persistence", "Credential Access", "Discovery",
                "Lateral Movement", "Command and Control", "Exfiltration"]
# Rules with no entry (e.g. DNS-NXDOMAIN, HTTP-SCRIPT-UA, TLS-NO-SNI) intentionally have NO mapping.


def techniques_for(rule: str, ctx: dict | None = None, internal_src: bool = True) -> list[dict]:
    ctx = ctx or {}
    out: list[tuple[str, str]] = []
    if rule in ("SCAN-VERTICAL", "SCAN-SERVICE-ENUM"):
        out = [("T1046", "Many ports/services probed on a host from an internal source.")] if internal_src else \
              [("T1595", "External source probing many ports on a target.")]
    elif rule == "SCAN-HORIZONTAL":
        out = [("T1046", "One internal source probed the same port on many hosts.")] if internal_src else \
              [("T1595.001", "External source sweeping one port across many addresses.")]
    elif rule == "SCAN-ICMP-SWEEP":
        out = [("T1018", "Internal source sent ICMP to many hosts (host discovery-like).")] if internal_src else \
              [("T1595.001", "External source sweeping address space.")]
    elif rule == "BEACON-PERIODIC":
        if ctx.get("benign_port"):
            return []  # NTP/DNS-style periodic traffic: evidence does not support a C2 mapping
        port = ctx.get("dst_port")
        out = [("T1071.001" if port in (80, 443, 8080, 8443) else "T1071",
                "Regular periodic connections are consistent with C2 check-ins; payload not inspected, so protocol use is unconfirmed.")]
        if ctx.get("nonstandard_port"):
            out.append(("T1571", "Periodic traffic on a port outside the common-service list."))
    elif rule == "DNS-TUNNEL":
        out = [("T1071.004", "Many high-entropy, long DNS names under one domain."), ("T1572", "Pattern consistent with data encoded into DNS names.")]
    elif rule == "DNS-DGA":
        out = [("T1568.002", "Many random-looking domain names queried by one source.")]
    elif rule == "DNS-PERIODIC":
        out = [("T1071.004", "Regularly repeated lookups of the same name (low confidence).")]
    elif rule in ("EXFIL-LARGE", "EXFIL-RATIO"):
        out = [("T1048", "Unusually large outbound volume to one destination (could be legitimate).")]
    elif rule == "EXFIL-HTTP-POST":
        out = [("T1048.003", "Large cleartext HTTP upload.")]
    elif rule == "EXFIL-DNS":
        out = [("T1048.003", "Data volume carried in DNS query names."), ("T1071.004", "DNS used as the transport.")]
    elif rule == "HTTP-SCANNER-UA":
        out = [("T1595.002", "User-agent of a known scanning tool.")]
    elif rule == "HTTP-PATH":
        if ctx.get("webshell"):
            out.append(("T1505.003", "Request path resembles a web-shell file."))
        if ctx.get("inbound"):
            out.append(("T1190", "Exploit-like request sent to an internal web service."))
    elif rule == "TLS-DGA-SNI":
        out = [("T1568.002", "Random-looking TLS server name.")]
    elif rule == "TLS-NONSTD-PORT":
        out = [("T1571", "TLS handshakes on a non-standard port.")]
    elif rule == "REMOTE-SMB-SWEEP":
        out = [("T1021.002", "One source connecting to SMB on many hosts.")]
    elif rule == "REMOTE-RDP-SWEEP":
        out = [("T1021.001", "One source connecting to RDP on many hosts.")]
    elif rule == "REMOTE-SSH-SWEEP":
        out = [("T1021.004", "One source connecting to SSH on many hosts.")]
    elif rule == "REMOTE-REPEAT":
        out = [("T1110", "Repeated short sessions are consistent with password guessing (authentication outcome not visible).")]
    return [{"id": t, "name": TECHNIQUES[t][0], "tactic": TECHNIQUES[t][1], "rationale": why} for t, why in out]


def build_mapping(alerts: list) -> list[dict]:
    """Aggregate per-alert techniques into a technique table."""
    agg: dict[str, dict] = {}
    rank = {"Low": 1, "Medium": 2, "High": 3}
    for a in alerts:
        for t in a.mitre:
            e = agg.setdefault(t["id"], {"id": t["id"], "name": t["name"], "tactic": t["tactic"], "rationale": t["rationale"],
                                         "alert_ids": [], "confidence": "Low", "evidence": a.evidence[:2]})
            e["alert_ids"].append(a.alert_id)
            if rank[a.confidence] > rank[e["confidence"]]:
                e["confidence"], e["evidence"] = a.confidence, a.evidence[:2]
    for e in agg.values():
        e["status"] = "Candidate - requires analyst validation"
        e["url"] = "https://attack.mitre.org/techniques/" + e["id"].replace(".", "/") + "/"
    return sorted(agg.values(), key=lambda e: (TACTIC_ORDER.index(e["tactic"]) if e["tactic"] in TACTIC_ORDER else 99, e["id"]))
