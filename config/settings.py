"""Application settings and configurable detection thresholds.

Every threshold has a documented default. Users can override values in
``config/settings.json`` (created from the Settings page) without touching code.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CONFIG_DIR.parent
USER_SETTINGS_FILE = CONFIG_DIR / "settings.json"
log = logging.getLogger(__name__)

# name: (default, description)
THRESHOLD_SPEC: dict[str, tuple] = {
    # ---- DNS ----
    "dns_long_name_len": (52, "Query name length (chars) considered unusually long."),
    "dns_long_label_len": (40, "Single DNS label length considered unusually long."),
    "dns_entropy_min": (3.5, "Shannon entropy of the subdomain part considered high."),
    "dns_entropy_min_len": (16, "Minimum subdomain length before entropy is evaluated."),
    "dns_min_hits": (5, "Minimum number of matching queries before an indicator counts."),
    "dns_high_freq_per_min": (100, "Queries per minute from one source to one registered domain."),
    "dns_nxdomain_min_responses": (20, "Minimum DNS responses before NXDOMAIN ratio is judged."),
    "dns_nxdomain_ratio": (0.5, "NXDOMAIN share of responses considered high."),
    "dns_tunnel_min_unique_subdomains": (30, "Unique subdomains under one domain (tunneling indicator)."),
    "dns_tunnel_avg_label_len": (20, "Average subdomain length (tunneling indicator)."),
    "dns_tunnel_min_score": (3, "Number of DNS tunneling indicators needed for a tunneling alert (max 5)."),
    "dns_dga_min_domains": (10, "Distinct random-looking domains from one source for a DGA-like alert."),
    "dns_dga_max_vowel_ratio": (0.30, "Max vowel ratio for a label to look random (English is ~0.38)."),
    "dns_dga_min_entropy": (3.0, "Min entropy of a second-level label to look random."),
    # ---- Beaconing ----
    "beacon_min_connections": (8, "Minimum repeated connections in a group before timing is analysed."),
    "beacon_max_cv": (0.25, "Max coefficient of variation (std/mean) of intervals for 'regular'."),
    "beacon_min_interval_sec": (1.0, "Ignore groups whose mean interval is shorter (bursty traffic)."),
    "beacon_max_interval_sec": (7200.0, "Ignore groups whose mean interval is longer."),
    "beacon_tolerance": (0.2, "Interval counts as on-schedule if within +/- this fraction of the median."),
    "beacon_tolerance_fraction": (0.8, "Share of intervals that must be on-schedule (tolerates missed beats)."),
    "beacon_benign_ports": ([53, 67, 68, 123, 137, 138, 1900, 5353],
                            "Ports where periodic traffic is normally benign (alerts capped at Informational)."),
    # ---- Scanning ----
    "scan_min_ports": (20, "Distinct destination ports on one host from one source (vertical scan)."),
    "scan_min_hosts": (15, "Distinct hosts on one port from one source (horizontal sweep)."),
    "scan_failed_ratio": (0.6, "Share of SYN probes that got no answer or a reset."),
    "scan_min_flows": (20, "Minimum probe count before a scan alert can fire."),
    "scan_service_enum_ports": (8, "Distinct well-known service ports on one host (service enumeration)."),
    "scan_icmp_sweep_hosts": (15, "Distinct hosts receiving ICMP from one source (ping sweep)."),
    # ---- Remote services ----
    "remote_repeat_conns": (10, "Repeated short SMB/SSH/RDP connections from one source to one host."),
    "remote_sweep_hosts": (5, "Distinct hosts contacted on SMB/SSH/RDP by one source."),
    # ---- Exfiltration ----
    "exfil_large_bytes": (10_000_000, "Outbound bytes to one destination considered unusually large."),
    "exfil_ratio_min_bytes": (1_000_000, "Minimum outbound bytes before the out/in ratio is judged."),
    "exfil_ratio": (10.0, "Outbound-to-inbound byte ratio considered unusual."),
    "exfil_http_post_bytes": (1_000_000, "HTTP POST/PUT Content-Length considered large."),
    "dns_exfil_bytes": (20_000, "Total query-name bytes to one domain considered a DNS data channel."),
    # ---- HTTP / TLS ----
    "http_repeat_min": (10, "Repeat connections to one uncommon destination."),
    "http_long_path_len": (200, "HTTP request path length considered unusual."),
    # ---- General ----
    "max_alerts_per_rule": (50, "Cap on alerts emitted per detection rule family."),
}


class Thresholds:
    """Attribute-style access to thresholds with defaults + overrides."""

    def __init__(self, **overrides):
        for k, (d, _) in THRESHOLD_SPEC.items():
            setattr(self, k, list(d) if isinstance(d, list) else d)
        for k, v in overrides.items():
            if k not in THRESHOLD_SPEC:
                log.warning("Unknown threshold ignored: %s", k)
                continue
            d = THRESHOLD_SPEC[k][0]
            try:
                setattr(self, k, [int(x) for x in v] if isinstance(d, list) else type(d)(v))
            except (TypeError, ValueError):
                log.warning("Invalid value for threshold %s: %r", k, v)

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in THRESHOLD_SPEC}


@dataclass
class AppSettings:
    max_file_mb: int = 200
    max_packets: int = 250_000
    db_path: str = str(PROJECT_ROOT / "database" / "investigations.db")
    ollama_host: str = "http://127.0.0.1:11434"
    ollama_timeout: int = 180
    tool_timeout: int = 120
    suricata_config: str = ""
    zeek_path: str = ""
    suricata_path: str = ""
    tshark_path: str = ""
    thresholds: dict | None = None

    def get_thresholds(self) -> Thresholds:
        return Thresholds(**(self.thresholds or {}))


def load_settings() -> AppSettings:
    s = AppSettings()
    if USER_SETTINGS_FILE.exists():
        try:
            data = json.loads(USER_SETTINGS_FILE.read_text(encoding="utf-8"))
            for k, v in data.items():
                if hasattr(s, k):
                    setattr(s, k, v)
        except (OSError, ValueError) as exc:
            log.warning("Could not read %s: %s", USER_SETTINGS_FILE, exc)
    return s


def save_settings(s: AppSettings) -> None:
    USER_SETTINGS_FILE.write_text(json.dumps(asdict(s), indent=2), encoding="utf-8")
