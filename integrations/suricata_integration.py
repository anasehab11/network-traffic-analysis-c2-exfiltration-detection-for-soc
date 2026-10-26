"""Optional Suricata integration (offline PCAP mode, no shell, with timeout)."""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from core.models import make_alert

log = logging.getLogger(__name__)
COMMON_PATHS = [r"C:\Program Files\Suricata\suricata.exe", "/usr/bin/suricata", "/usr/local/bin/suricata"]
SEV = {1: "High", 2: "Medium", 3: "Low"}


def find_suricata(custom: str = "") -> str | None:
    if custom and Path(custom).is_file():
        return custom
    return shutil.which("suricata") or next((p for p in COMMON_PATHS if Path(p).is_file()), None)


def status(custom: str = "") -> dict:
    path = find_suricata(custom)
    return {"name": "Suricata", "available": bool(path), "path": path,
            "detail": "Found" if path else "Not installed (optional). Signature alerts are skipped; built-in detections still work."}


def run_suricata(pcap_path, custom: str = "", config: str = "", timeout: int = 180) -> dict:
    exe = find_suricata(custom)
    if not exe:
        return {"ran": False, "error": "Suricata not available", "alerts": [], "count": 0}
    with tempfile.TemporaryDirectory(prefix="suri_") as tmp:
        cmd = [exe, "-r", str(Path(pcap_path).resolve()), "-l", tmp, "-k", "none"]
        if config and Path(config).is_file():
            cmd += ["-c", config]
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"ran": False, "error": f"Suricata timed out after {timeout}s", "alerts": [], "count": 0}
        except OSError as exc:
            return {"ran": False, "error": f"Suricata could not start: {exc.__class__.__name__}", "alerts": [], "count": 0}
        eve, alerts = Path(tmp) / "eve.json", []
        if eve.exists():
            for ln in eve.read_text(errors="ignore").splitlines()[:100000]:
                try:
                    e = json.loads(ln)
                except ValueError:
                    continue
                if e.get("event_type") != "alert":
                    continue
                a = e.get("alert", {})
                from datetime import datetime
                try:
                    ts = datetime.fromisoformat(e["timestamp"]).timestamp()
                except (KeyError, ValueError):
                    ts = 0.0
                alerts.append(make_alert(
                    "SURICATA-SIG", f"Suricata: {str(a.get('signature', 'signature'))[:100]}", "Suricata",
                    SEV.get(a.get("severity", 3), "Low"), "High", str(e.get("src_ip", "")), str(e.get("dest_ip", "")),
                    e.get("dest_port"), str(e.get("proto", "")), ts, ts,
                    [f"Signature id {a.get('signature_id')} category '{a.get('category', '')}'. Signature hit = rule-based evidence, still verify."],
                    "Suricata ruleset match", ["Check the rule's reference and false-positive notes.", "Correlate with built-in alerts for the same hosts."],
                    ["Outdated or noisy rules."], strength="Corroborated"))
        return {"ran": True, "error": None, "alerts": alerts[:200], "count": len(alerts)}
