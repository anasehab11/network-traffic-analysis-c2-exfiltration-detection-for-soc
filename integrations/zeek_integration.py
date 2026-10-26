"""Optional Zeek integration. Runs Zeek offline on the PCAP (no shell, with timeout)."""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from core.models import make_alert

log = logging.getLogger(__name__)
COMMON_PATHS = ["/opt/zeek/bin/zeek", "/usr/local/zeek/bin/zeek", "/usr/bin/zeek"]


def find_zeek(custom: str = "") -> str | None:
    if custom and Path(custom).is_file():
        return custom
    return shutil.which("zeek") or next((p for p in COMMON_PATHS if Path(p).is_file()), None)


def status(custom: str = "") -> dict:
    path = find_zeek(custom)
    return {"name": "Zeek", "available": bool(path), "path": path,
            "detail": "Found" if path else "Not installed (optional). Zeek runs on Linux/WSL2/Docker; built-in detections still work."}


def run_zeek(pcap_path, custom: str = "", timeout: int = 120) -> dict:
    exe = find_zeek(custom)
    if not exe:
        return {"ran": False, "error": "Zeek not available", "alerts": [], "logs": {}}
    with tempfile.TemporaryDirectory(prefix="zeek_") as tmp:
        cmd = [exe, "-C", "-r", str(Path(pcap_path).resolve()), "LogAscii::use_json=T"]
        try:
            subprocess.run(cmd, cwd=tmp, capture_output=True, timeout=timeout, check=False)  # list args, no shell
        except subprocess.TimeoutExpired:
            return {"ran": False, "error": f"Zeek timed out after {timeout}s", "alerts": [], "logs": {}}
        except OSError as exc:
            return {"ran": False, "error": f"Zeek could not start: {exc.__class__.__name__}", "alerts": [], "logs": {}}
        logs, alerts = {}, []
        for name in ("conn", "dns", "http", "ssl", "notice"):
            f = Path(tmp) / f"{name}.log"
            rows = []
            if f.exists():
                for ln in f.read_text(errors="ignore").splitlines()[:50000]:
                    try:
                        rows.append(json.loads(ln))
                    except ValueError:
                        continue
            logs[name] = len(rows)
            if name == "notice":
                for r in rows[:100]:
                    alerts.append(make_alert(
                        "ZEEK-NOTICE", f"Zeek notice: {str(r.get('note', 'unknown'))[:80]}", "Zeek", "Medium", "Medium",
                        str(r.get("src", "")), str(r.get("dst", "")), r.get("p"), "n/a", float(r.get("ts", 0)), float(r.get("ts", 0)),
                        [str(r.get("msg", ""))[:300]], "Zeek policy script notice", ["Review the matching entries in conn.log."],
                        ["Zeek policy noise."], strength="Corroborated"))
        return {"ran": True, "error": None, "alerts": alerts, "logs": logs}
