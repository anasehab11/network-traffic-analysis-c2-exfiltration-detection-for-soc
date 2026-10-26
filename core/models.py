"""Alert data model shared by all detectors."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict


@dataclass
class Alert:
    alert_id: str
    title: str
    category: str            # DNS, Beaconing, Scan, Exfiltration, HTTP, TLS, Remote Services, Watchlist, ...
    rule: str                # stable rule id, e.g. BEACON-PERIODIC
    severity: str            # Informational | Low | Medium | High | Critical
    confidence: str          # Low | Medium | High
    src_ip: str
    dst_ip: str
    dst_port: int | None
    protocol: str
    start_ts: float
    end_ts: float
    evidence: list = field(default_factory=list)
    threshold: str = ""
    investigation_steps: list = field(default_factory=list)
    false_positives: list = field(default_factory=list)
    evidence_strength: str = "Heuristic"   # Heuristic | Corroborated
    mitre: list = field(default_factory=list)
    risk_score: float = 0.0
    wireshark_filter: str = ""
    status: str = "New"
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def make_alert(rule, title, category, severity, confidence, src_ip, dst_ip, dst_port, protocol,
               start_ts, end_ts, evidence, threshold, steps, false_positives,
               strength="Heuristic", extra=None) -> Alert:
    key = f"{rule}|{src_ip}|{dst_ip}|{dst_port}|{title}"
    aid = f"{rule.split('-')[0][:4]}-{hashlib.sha1(key.encode()).hexdigest()[:8].upper()}"
    return Alert(alert_id=aid, title=title, category=category, rule=rule, severity=severity,
                 confidence=confidence, src_ip=str(src_ip), dst_ip=str(dst_ip or ""),
                 dst_port=None if dst_port is None else int(dst_port), protocol=protocol,
                 start_ts=float(start_ts), end_ts=float(end_ts), evidence=list(evidence),
                 threshold=threshold, investigation_steps=list(steps),
                 false_positives=list(false_positives), evidence_strength=strength,
                 extra=extra or {})
