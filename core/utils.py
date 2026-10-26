"""Shared helpers (no packet parsing or detection logic here)."""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache

import numpy as np

_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "127.0.0.0/8", "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128")]
SEVERITIES = ["Informational", "Low", "Medium", "High", "Critical"]
CONFIDENCES = ["Low", "Medium", "High"]
VOWELS = set("aeiou")


@lru_cache(maxsize=65536)
def ip_scope(ip) -> str:
    """Return 'internal', 'external' or 'special' (multicast/broadcast/unspecified)."""
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return "special"
    if a.is_multicast or a.is_unspecified or str(a) == "255.255.255.255":
        return "special"
    return "internal" if any(a in n for n in _INTERNAL) else "external"


def is_internal(ip) -> bool:
    return ip_scope(ip) == "internal"


def is_external(ip) -> bool:
    return ip_scope(ip) == "external"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def vowel_ratio(s: str) -> float:
    letters = [c for c in s.lower() if c.isalpha()]
    return sum(c in VOWELS for c in letters) / len(letters) if letters else 0.0


def fmt_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "n/a"
    for unit in ("B", "KB", "MB", "GB", "TB"):  # decimal units (1 MB = 1,000,000 bytes)
        if abs(n) < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1000
    return f"{n:.2f} TB"


def ts_to_str(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return "n/a"


def safe_text(value, maxlen: int = 200) -> str:
    """Strip control characters and truncate. Used for every attacker-controlled string."""
    s = "" if value is None else str(value)
    s = re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", s)
    return s[:maxlen]


def defang(value: str) -> str:
    v = str(value).replace("http://", "hxxp://").replace("https://", "hxxps://")
    return v.replace(".", "[.]")


def fmt_ports(ports, limit: int = 12) -> str:
    p = sorted({int(x) for x in ports})
    if not p:
        return ""
    runs, start, prev = [], p[0], p[0]
    for x in p[1:]:
        if x == prev + 1:
            prev = x
            continue
        runs.append((start, prev))
        start = prev = x
    runs.append((start, prev))
    out = [f"{a}" if a == b else f"{a}-{b}" for a, b in runs]
    return ", ".join(out[:limit]) + (" ..." if len(out) > limit else "")


def interval_stats(times, tolerance: float = 0.2):
    """Timing statistics for a series of event timestamps (None if too few)."""
    t = np.sort(np.asarray(list(times), dtype=float))
    if len(t) < 3:
        return None
    iv = np.diff(t)
    mean = float(iv.mean())
    med = float(np.median(iv))
    std = float(iv.std())
    cv = std / mean if mean > 0 else float("inf")
    within = float(np.mean(np.abs(iv - med) <= tolerance * med)) if med > 0 else 0.0
    return {"count": int(len(t)), "mean": mean, "median": med, "std": std, "cv": cv,
            "jitter_ok": within, "min": float(iv.min()), "max": float(iv.max())}


def coeff_var(values) -> float:
    a = np.asarray(list(values), dtype=float)
    if len(a) < 2 or a.mean() == 0:
        return float("inf") if len(a) < 2 else 0.0
    return float(a.std() / a.mean())


def bump_severity(sev: str, n: int) -> str:
    i = SEVERITIES.index(sev) + n
    return SEVERITIES[max(0, min(len(SEVERITIES) - 1, i))]


def bump_confidence(c: str, n: int) -> str:
    i = CONFIDENCES.index(c) + n
    return CONFIDENCES[max(0, min(len(CONFIDENCES) - 1, i))]
