"""Risk scoring, correlation and alert prioritisation."""
from __future__ import annotations

import pandas as pd

from core.mitre_mapping import TECHNIQUES
from core.utils import bump_confidence, is_internal

SEV_BASE = {"Informational": 5, "Low": 25, "Medium": 50, "High": 75, "Critical": 90}
CONF_FACTOR = {"Low": 0.8, "Medium": 1.0, "High": 1.1}


def score_alert(a) -> float:
    s = SEV_BASE[a.severity] * CONF_FACTOR[a.confidence] * (1.1 if a.evidence_strength == "Corroborated" else 1.0)
    return round(min(s, 100.0), 1)


def correlate_alerts(alerts: list) -> None:
    """Link beacon + exfil to the same destination (possible C2-channel exfiltration)."""
    beacons = [a for a in alerts if a.rule == "BEACON-PERIODIC"]
    for ex in (a for a in alerts if a.category == "Exfiltration"):
        for b in beacons:
            if b.src_ip == ex.src_ip and b.dst_ip == ex.dst_ip:
                ex.evidence.append(f"Correlated: periodic connections to the same destination were also detected ({b.alert_id}).")
                b.evidence.append(f"Correlated: large outbound transfer to the same destination was also detected ({ex.alert_id}).")
                ex.confidence = bump_confidence(ex.confidence, 1)
                t = TECHNIQUES["T1041"]
                ex.mitre.append({"id": "T1041", "name": t[0], "tactic": t[1],
                                 "rationale": "Large outbound transfer to a destination that is also contacted periodically (correlation, not proof)."})
                ex.extra["correlated_with"] = b.alert_id
                b.extra["correlated_with"] = ex.alert_id


def finalize(alerts: list) -> list:
    for a in alerts:
        a.risk_score = score_alert(a)
    return sorted(alerts, key=lambda a: (-a.risk_score, a.start_ts))


def host_risk(alerts: list) -> pd.DataFrame:
    cols = ["host", "scope", "alerts", "categories", "risk_score", "risk_level", "top_alert"]
    hosts: dict[str, list] = {}
    for a in alerts:
        if a.src_ip and a.src_ip != "multiple":
            hosts.setdefault(a.src_ip, []).append(a)
    rows = []
    for h, items in hosts.items():
        best: dict[str, float] = {}
        for x in items:  # one score per category so a single activity is not counted many times
            best[x.category] = max(best.get(x.category, 0.0), x.risk_score)
        scores = sorted(best.values(), reverse=True)
        cats = sorted(best)
        s = min(100.0, scores[0] + 0.15 * sum(scores[1:]))
        if len(cats) >= 3:
            s = min(100.0, s + 5)
        rows.append({"host": h, "scope": "internal" if is_internal(h) else "external", "alerts": len(items),
                     "categories": ", ".join(cats), "risk_score": round(s, 1), "risk_level": level(s),
                     "top_alert": max(items, key=lambda x: x.risk_score).title})
    return pd.DataFrame(rows, columns=cols).sort_values("risk_score", ascending=False).reset_index(drop=True)


def level(score: float) -> str:
    return "Critical" if score >= 90 else "High" if score >= 65 else "Medium" if score >= 40 else "Low" if score >= 15 else "Informational"


def overall_risk(alerts: list):
    if not alerts:
        return 0.0, "Informational"
    h = host_risk(alerts)
    s = float(h["risk_score"].max()) if not h.empty else max(a.risk_score for a in alerts)
    return s, level(s)
