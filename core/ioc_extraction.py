"""IOC extraction and analyst watchlist matching."""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from core.dns_analysis import split_domain
from core.models import make_alert
from core.utils import is_external, ts_to_str

WATCHLIST_FILE = Path(__file__).resolve().parent.parent / "config" / "watchlist.txt"


def load_watchlist(path=WATCHLIST_FILE) -> set:
    """Analyst-supplied indicators (one per line, '#' comments). Ships empty; no threat intel is bundled."""
    p = Path(path)
    if not p.exists():
        return set()
    return {ln.strip().lower() for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines()
            if ln.strip() and not ln.strip().startswith("#")}


def _observed(pkts: pd.DataFrame, flows: pd.DataFrame) -> pd.DataFrame:
    rows = []

    def add(kind, series, ts):
        s = pd.DataFrame({"value": series, "ts": ts}).dropna()
        if s.empty:
            return
        g = s.groupby("value").agg(count=("ts", "size"), first_seen=("ts", "min"), last_seen=("ts", "max")).reset_index()
        g.insert(0, "type", kind)
        rows.append(g)

    if not pkts.empty:
        ips = pd.concat([pkts[["src", "ts"]].rename(columns={"src": "value"}), pkts[["dst", "ts"]].rename(columns={"dst": "value"})])
        ips = ips[ips["value"].map(is_external)]
        add("ip", ips["value"], ips["ts"])
        q = pkts[(pkts["dns_qr"].fillna(-1) == 0) & pkts["dns_qname"].notna()]
        add("domain", q["dns_qname"].map(lambda s: split_domain(s)[1]), q["ts"])
        t = pkts[pkts["tls_sni"].notna()]
        add("domain", t["tls_sni"], t["ts"])
        h = pkts[pkts["http_host"].notna()]
        add("domain", h["http_host"].str.replace(r":\d+$", "", regex=True), h["ts"])
        hh = pkts[pkts["http_host"].notna() & pkts["http_path"].notna()]
        add("url", "http://" + hh["http_host"] + hh["http_path"], hh["ts"])
        j = pkts[pkts["tls_ja3"].notna()]
        add("ja3", j["tls_ja3"], j["ts"])
        u = pkts[pkts["http_ua"].notna() & (pkts["http_ua"] != "")]
        add("user_agent", u["http_ua"], u["ts"])
    if not rows:
        return pd.DataFrame(columns=["type", "value", "count", "first_seen", "last_seen"])
    out = pd.concat(rows)
    return out.groupby(["type", "value"]).agg(count=("count", "sum"), first_seen=("first_seen", "min"), last_seen=("last_seen", "max")).reset_index()


def watchlist_alerts(pkts: pd.DataFrame, flows: pd.DataFrame, watch: set):
    if not watch:
        return []
    obs = _observed(pkts, flows)
    hits = obs[obs["value"].str.lower().isin(watch) | obs["value"].str.lower().map(lambda v: split_domain(v)[1] in watch if "." in v else False)]
    alerts = []
    for _, r in hits.iterrows():
        alerts.append(make_alert(
            "WATCHLIST-MATCH", f"Watchlist match: {r['type']} {r['value']}", "Watchlist", "High", "High", "multiple", r["value"] if r["type"] == "ip" else "",
            None, "n/a", r.first_seen, r.last_seen,
            [f"Observed {r['type']} '{r['value']}' {int(r['count'])} time(s); it is on the analyst-supplied watchlist."],
            "exact match with config/watchlist.txt",
            ["Find every internal host that contacted this indicator.", "Check the source/age/confidence of the watchlist entry."],
            ["Stale or over-broad watchlist entries."], strength="Corroborated",
            extra={"iocs": [{"type": r["type"], "value": r["value"]}]}))
    return alerts


def build_ioc_table(pkts: pd.DataFrame, flows: pd.DataFrame, alerts: list) -> pd.DataFrame:
    obs = _observed(pkts, flows)
    link: dict = {}
    for a in alerts:
        for ioc in a.extra.get("iocs", []):
            link.setdefault((ioc["type"], ioc["value"]), []).append(a.alert_id)
    # indicators referenced by alerts but not "observed" (e.g. internal hosts) are added
    extra_rows = [{"type": t, "value": v, "count": 0, "first_seen": None, "last_seen": None}
                  for (t, v) in link if not ((obs["type"] == t) & (obs["value"] == v)).any()]
    if extra_rows:
        add = pd.DataFrame(extra_rows).astype({"first_seen": "float64", "last_seen": "float64"})
        obs = add if obs.empty else pd.concat([obs, add], ignore_index=True)
    obs["related_alerts"] = [", ".join(dict.fromkeys(link.get((t, v), []))) for t, v in zip(obs["type"], obs["value"])]
    obs["suspicious"] = obs["related_alerts"] != ""
    obs.loc[obs["type"] == "internal_host", "suspicious"] = obs["related_alerts"] != ""
    obs["note"] = obs["suspicious"].map({True: "Referenced by an alert - validate before blocking", False: "Observed, no alert"})
    obs["first_seen_utc"] = obs["first_seen"].map(lambda t: ts_to_str(t) if pd.notna(t) else "")
    return obs.sort_values(["suspicious", "count"], ascending=False).reset_index(drop=True)
