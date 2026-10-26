"""Analysis pipeline: parse -> flows -> detectors -> IOCs -> MITRE -> scoring.

Detection logic lives in core/*; this module only orchestrates it (no UI code).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import pandas as pd

from config.settings import AppSettings
from core import (beacon_detection, dns_analysis, exfiltration_detection, flow_analysis, http_tls_analysis,
                  ioc_extraction, mitre_mapping, pcap_parser, protocol_analysis, risk_scoring, scan_detection)
from core.utils import is_internal
from core.wireshark_filters import filters_for_alert

log = logging.getLogger(__name__)
EMPTY = pd.DataFrame()


@dataclass
class AnalysisResult:
    meta: dict
    pkts: pd.DataFrame
    flows: pd.DataFrame
    baseline: dict = field(default_factory=dict)
    dns: object = None
    http: pd.DataFrame = field(default_factory=lambda: EMPTY)
    tls: pd.DataFrame = field(default_factory=lambda: EMPTY)
    scan_table: pd.DataFrame = field(default_factory=lambda: EMPTY)
    beacon_table: pd.DataFrame = field(default_factory=lambda: EMPTY)
    outbound: pd.DataFrame = field(default_factory=lambda: EMPTY)
    remote_table: pd.DataFrame = field(default_factory=lambda: EMPTY)
    alerts: list = field(default_factory=list)
    iocs: pd.DataFrame = field(default_factory=lambda: EMPTY)
    mitre: list = field(default_factory=list)
    hosts: pd.DataFrame = field(default_factory=lambda: EMPTY)
    risk_score: float = 0.0
    risk_level: str = "Informational"
    limitations: list = field(default_factory=list)
    integrations: dict = field(default_factory=dict)
    thresholds: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_summary_dict(self) -> dict:
        """JSON-friendly result (no packet table, no payloads)."""
        return {
            "meta": self.meta, "baseline": self.baseline, "risk": {"score": self.risk_score, "level": self.risk_level},
            "alerts": [a.to_dict() for a in self.alerts],
            "iocs": [] if self.iocs is None or self.iocs.empty else self.iocs.drop(columns=["first_seen", "last_seen"], errors="ignore").head(500).to_dict("records"),
            "mitre": self.mitre, "hosts": [] if self.hosts.empty else self.hosts.to_dict("records"),
            "limitations": self.limitations, "thresholds": self.thresholds,
            "integrations": {k: {kk: vv for kk, vv in v.items() if kk != "alerts"} for k, v in self.integrations.items()},
        }


def _limitations(meta, pkts, flows, dns_res) -> list[str]:
    lim = ["Findings are heuristic indicators computed from packet metadata; they are not confirmed malicious activity."]
    if meta.get("truncated") or meta.get("warnings"):
        lim += list(meta.get("warnings", []))
    if not pkts.empty:
        tls_share = (pkts["app"] == "TLS").mean()
        if tls_share > 0.05 or (pkts["dport"].isin([443, 8443]) | pkts["sport"].isin([443, 8443])).mean() > 0.1:
            lim.append("Much of the traffic is encrypted (TLS); payloads, URLs and file contents cannot be inspected. Only metadata (SNI, JA3, sizes, timing) is available.")
        if dns_res is not None and dns_res.summary.get("queries", 0) and not dns_res.summary.get("responses"):
            lim.append("No DNS responses were captured, so NXDOMAIN-based rules cannot be evaluated.")
        tcp = flows[flows["proto"] == "TCP"] if not flows.empty else flows
        if not tcp.empty and (tcp["state"] == "PARTIAL").mean() > 0.3:
            lim.append("Many TCP flows have no visible handshake (capture started mid-stream); direction and state may be inaccurate.")
        if meta.get("duration", 0) < 60:
            lim.append("The capture is shorter than one minute; timing-based detections (beaconing) have limited evidence.")
    lim.append("Capture position matters: traffic that did not cross the capture point is invisible, and NAT can hide the real source host.")
    lim.append("Scan, brute-force and lateral-movement rules show connection patterns only; they do not show authentication success or file contents.")
    return lim


def analyze_pcap(path, settings: AppSettings | None = None, progress=None, run_zeek: bool = False,
                 run_suricata: bool = False, display_name: str | None = None) -> AnalysisResult:
    settings = settings or AppSettings()
    cfg = settings.get_thresholds()
    step = (lambda msg, pct=None: progress(msg, pct)) if progress else (lambda *a, **k: None)

    step("Parsing capture", 0.05)
    pkts, meta = pcap_parser.parse_pcap(path, settings.max_packets, settings.max_file_mb,
                                        progress=lambda n: step(f"Parsed {n:,} packets", None))
    if display_name:
        meta["filename"] = display_name[:120]
    step("Building flows", 0.35)
    flows = flow_analysis.build_flows(pkts)
    res = AnalysisResult(meta=meta, pkts=pkts, flows=flows, thresholds=cfg.to_dict())
    res.baseline = protocol_analysis.baseline_summary(meta, pkts, flows)
    if pkts.empty:
        res.limitations = _limitations(meta, pkts, flows, None)
        return res

    alerts: list = []
    step("DNS analysis", 0.45)
    res.dns = dns_analysis.analyze_dns(pkts, cfg)
    alerts += res.dns.alerts
    step("HTTP/TLS analysis", 0.55)
    res.http, res.tls, a = http_tls_analysis.analyze_http_tls(pkts, flows, cfg)
    alerts += a
    step("Scan detection", 0.65)
    res.scan_table, a = scan_detection.detect_scans(flows, cfg)
    alerts += a
    step("Beacon detection", 0.72)
    res.beacon_table, a = beacon_detection.detect_beacons(flows, cfg)
    alerts += a
    step("Exfiltration detection", 0.8)
    res.outbound, a = exfiltration_detection.detect_exfiltration(flows, pkts, cfg, res.dns.domains)
    alerts += a
    res.remote_table, a = protocol_analysis.analyze_remote_services(flows, cfg)
    alerts += a
    alerts += ioc_extraction.watchlist_alerts(pkts, flows, ioc_extraction.load_watchlist())

    if run_suricata:
        from integrations import suricata_integration as su
        step("Running Suricata", 0.85)
        out = su.run_suricata(path, settings.suricata_path, settings.suricata_config, settings.tool_timeout)
        res.integrations["suricata"] = out
        alerts += out["alerts"]
    if run_zeek:
        from integrations import zeek_integration as ze
        step("Running Zeek", 0.9)
        out = ze.run_zeek(path, settings.zeek_path, settings.tool_timeout)
        res.integrations["zeek"] = out
        alerts += out["alerts"]

    step("Mapping, scoring", 0.95)
    for al in alerts:
        al.mitre = mitre_mapping.techniques_for(al.rule, {**al.extra, "dst_port": al.dst_port}, is_internal(al.src_ip))
    risk_scoring.correlate_alerts(alerts)
    res.alerts = risk_scoring.finalize(alerts)
    for al in res.alerts:
        al.wireshark_filter = " | ".join(filters_for_alert(al))
    res.iocs = ioc_extraction.build_ioc_table(pkts, flows, res.alerts)
    res.mitre = mitre_mapping.build_mapping(res.alerts)
    res.hosts = risk_scoring.host_risk(res.alerts)
    res.risk_score, res.risk_level = risk_scoring.overall_risk(res.alerts)
    res.limitations = _limitations(meta, pkts, flows, res.dns)
    step("Done", 1.0)
    log.info("Analysis complete: %d packets, %d alerts", meta["packets"], len(res.alerts))
    return res
