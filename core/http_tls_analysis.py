"""HTTP and TLS metadata investigation (cleartext HTTP headers, TLS ClientHello fields)."""
from __future__ import annotations

import re

import pandas as pd

from core.models import make_alert
from core.utils import is_external, shannon_entropy, vowel_ratio

SCANNER_UA = ("sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "wpscan", "hydra", "zgrab", "acunetix", "nessus", "openvas")
SCRIPT_UA = ("curl/", "wget/", "python-requests", "python-urllib", "go-http-client", "libwww-perl", "powershell", "java/", "okhttp")
ODD_METHODS = {"TRACE", "TRACK", "CONNECT", "PROPFIND"}
PATH_RULES = [
    (re.compile(r"(?i)(\?|&)(cmd|exec|command|shell)="), "command-like parameter", False),
    (re.compile(r"(?i)/(shell|cmd|c99|r57|webshell|b374k|wso)\.(php|asp|aspx|jsp)"), "web-shell-like file name", True),
    (re.compile(r"\.\./|%2e%2e%2f"), "path traversal sequence", False),
    (re.compile(r"(?i)/etc/passwd|/windows/win\.ini"), "sensitive file reference", False),
    (re.compile(r"(?i)union(\s|%20|\+)+select|<script"), "injection-like string", False),
    (re.compile(r"[A-Za-z0-9+/=]{60,}"), "long base64-like path segment", False),
]
COMMON_SUFFIXES = ("google.com", "gstatic.com", "microsoft.com", "windowsupdate.com", "office.com", "apple.com",
                   "icloud.com", "amazonaws.com", "cloudfront.net", "akamai.net", "cloudflare.com", "mozilla.org",
                   "github.com", "ubuntu.com", "example.com", "example.net", "example.org")
STD_TLS_PORTS = {443, 8443, 993, 995, 465, 636, 989, 990, 5061, 853}


def http_table(pkts: pd.DataFrame) -> pd.DataFrame:
    cols = ["ts", "src", "dst", "dport", "http_method", "http_host", "http_path", "http_ua", "http_clen"]
    return pkts[pkts["http_method"].notna()][cols].reset_index(drop=True)


def tls_table(pkts: pd.DataFrame) -> pd.DataFrame:
    cols = ["ts", "src", "dst", "dport", "tls_sni", "tls_version", "tls_ja3"]
    return pkts[pkts["tls_ja3"].notna()][cols].reset_index(drop=True)


def _common(name) -> bool:
    return bool(name) and str(name).lower().endswith(COMMON_SUFFIXES)


def analyze_http_tls(pkts: pd.DataFrame, flows: pd.DataFrame, cfg):
    http, tls = http_table(pkts), tls_table(pkts)
    alerts = []
    steps = ["Open the request/handshake in Wireshark using the suggested filter.",
             "Confirm the client application and destination are expected.",
             "Review proxy/web-server logs for response codes; the capture alone may not show success."]
    for (src, dst, dport), g in http.groupby(["src", "dst", "dport"]):
        ua = g["http_ua"]
        low = ua.fillna("").str.lower()
        t0, t1 = g.ts.min(), g.ts.max()
        host = g["http_host"].dropna().iloc[0] if g["http_host"].notna().any() else None
        base_ioc = [{"type": "ip", "value": dst}] if is_external(dst) else []
        base_ioc += [{"type": "domain", "value": host}] if host and not re.fullmatch(r"[\d.:]+", host) else []
        scan_hits = sorted({s for s in SCANNER_UA if low.str.contains(s, regex=False).any()})
        script_hits = sorted({s for s in SCRIPT_UA if low.str.contains(s, regex=False).any()})
        if scan_hits:
            alerts.append(make_alert(
                "HTTP-SCANNER-UA", "HTTP user-agent associated with scanning/attack tools", "HTTP", "Medium", "Medium", src, dst, dport,
                "TCP", t0, t1, [f"User-Agent contains: {', '.join(scan_hits)} ({len(g)} request(s)).",
                                f"Example: {ua.dropna().iloc[0]}", "User-agents are trivially spoofed; absence/presence is only an indicator."],
                "user-agent matches scanner keyword list", steps,
                ["Authorised vulnerability scans.", "Another tool reusing the string."], extra={"iocs": base_ioc + [{"type": "user_agent", "value": ua.dropna().iloc[0]}]}))
        elif script_hits or ua.isna().any() or (ua == "").any():
            what = ", ".join(script_hits) if script_hits else "missing/empty User-Agent"
            alerts.append(make_alert(
                "HTTP-SCRIPT-UA", "Scripted or unusual HTTP client", "HTTP", "Informational", "Low", src, dst, dport, "TCP", t0, t1,
                [f"Client indicators: {what} ({len(g)} request(s)) to {host or dst}."], "user-agent is a scripting library or absent", steps,
                ["Admin scripts, package managers, health checks, developer tools."],
                extra={"iocs": base_ioc + ([{"type": "user_agent", "value": ua.dropna().iloc[0]}] if ua.notna().any() else [])}))
        odd = sorted(set(g["http_method"]) & ODD_METHODS)
        if odd:
            alerts.append(make_alert(
                "HTTP-METHOD", f"Unusual HTTP method(s): {', '.join(odd)}", "HTTP", "Low", "Low", src, dst, dport, "TCP", t0, t1,
                [f"Methods seen: {', '.join(odd)} to {host or dst}."], "method in {TRACE, TRACK, CONNECT, PROPFIND}", steps,
                ["CONNECT is normal for explicit proxies; WebDAV uses PROPFIND."], extra={"iocs": base_ioc}))
        for _, r in g.iterrows():
            path = r["http_path"] or ""
            hit = [(lbl, ws) for rx, lbl, ws in PATH_RULES if rx.search(path)]
            if len(path) >= cfg.http_long_path_len:
                hit.append((f"very long path ({len(path)} chars)", False))
            if hit:
                labels = ", ".join(sorted({h[0] for h in hit}))
                alerts.append(make_alert(
                    "HTTP-PATH", "Suspicious HTTP request path", "HTTP", "Medium", "Low", src, dst, dport, "TCP", r.ts, r.ts,
                    [f"Request to {host or dst}: {r['http_method']} {path[:160]}", f"Matched: {labels}.",
                     "The response code/body was not evaluated here, so success cannot be confirmed."],
                    "path matches suspicious-pattern list", steps,
                    ["Vulnerability scanners, applications with long encoded query strings."],
                    extra={"iocs": base_ioc, "webshell": any(h[1] for h in hit), "inbound": not is_external(dst)}))
                break  # one path alert per client/destination pair
        if host and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", host) and len(g) >= 3:
            alerts.append(make_alert(
                "HTTP-IPHOST", "HTTP requests addressed to a raw IP address", "HTTP", "Informational", "Low", src, dst, dport, "TCP", t0, t1,
                [f"{len(g)} requests used a bare IP as Host ({host})."], "Host header is an IP literal", steps,
                ["Internal appliances, device web UIs, APIs."], extra={"iocs": base_ioc}))
    # ---- TLS ----
    for (src, dst, dport), g in tls.groupby(["src", "dst", "dport"]):
        t0, t1 = g.ts.min(), g.ts.max()
        sni = g["tls_sni"].dropna()
        ioc = ([{"type": "ip", "value": dst}] if is_external(dst) else []) + [{"type": "domain", "value": s} for s in sni.unique()[:3]]
        ioc += [{"type": "ja3", "value": j} for j in g["tls_ja3"].unique()[:3]]
        if int(dport) not in STD_TLS_PORTS and len(g) >= 3:
            alerts.append(make_alert(
                "TLS-NONSTD-PORT", f"TLS on non-standard port {int(dport)}", "TLS", "Low", "Low", src, dst, dport, "TCP", t0, t1,
                [f"{len(g)} TLS ClientHello(s) to {dst}:{int(dport)}; SNI: {', '.join(sni.unique()[:3]) or 'none'}."],
                "TLS handshake on a port outside the standard TLS list", steps,
                ["Management interfaces, custom apps, VPN/remote-access products."], extra={"iocs": ioc}))
        if len(g) >= cfg.http_repeat_min and sni.empty:
            alerts.append(make_alert(
                "TLS-NO-SNI", "Repeated TLS connections without SNI", "TLS", "Low", "Low", src, dst, dport, "TCP", t0, t1,
                [f"{len(g)} ClientHellos to {dst}:{int(dport)} carried no Server Name Indication."], f"no-SNI handshakes >= {cfg.http_repeat_min}", steps,
                ["IoT devices, older clients, some VPNs and custom software omit SNI."], extra={"iocs": ioc}))
        old = g[g["tls_version"].isin(["SSL 3.0", "TLS 1.0", "TLS 1.1"])]
        if len(old):
            alerts.append(make_alert(
                "TLS-OLD-VERSION", "Client offers only deprecated TLS/SSL versions", "TLS", "Low", "Medium", src, dst, dport, "TCP", t0, t1,
                [f"{len(old)} ClientHello(s) with max offered version {old['tls_version'].iloc[0]}."], "max offered version < TLS 1.2",
                ["Identify and update/retire the client software."], ["Legacy devices and embedded systems."], extra={"iocs": ioc}))
        for s in sni.unique():
            sld = s.split(".")[-2] if s.count(".") >= 1 else s
            if len(sld) >= 10 and shannon_entropy(sld) >= cfg.dns_dga_min_entropy and vowel_ratio(sld) <= cfg.dns_dga_max_vowel_ratio:
                alerts.append(make_alert(
                    "TLS-DGA-SNI", "Random-looking TLS server name (SNI)", "TLS", "Medium", "Low", src, dst, dport, "TCP", t0, t1,
                    [f"SNI '{s}' has entropy/vowel ratio typical of generated names."], "entropy and vowel-ratio test on second-level label", steps,
                    ["CDN or SaaS tenants with machine-generated names."], extra={"iocs": ioc}))
                break
    # repeated connections to uncommon destinations (informational)
    if not flows.empty:
        f = flows[flows["app"].isin(["TLS", "HTTP", "HTTPS", "HTTP-Alt", "HTTPS-Alt"]) & flows["dst"].map(is_external)]
        for (src, dst, dport), g in f.groupby(["src", "dst", "dport"]):
            name = g["sni"].dropna().iloc[0] if g["sni"].notna().any() else (g["http_host"].dropna().iloc[0] if g["http_host"].notna().any() else None)
            if len(g) >= cfg.http_repeat_min and not _common(name) and not any(a.dst_ip == dst and a.dst_port == dport for a in alerts):
                alerts.append(make_alert(
                    "TLS-UNCOMMON-REPEAT", f"Repeated connections to uncommon destination {dst}", "TLS", "Informational", "Low", src, dst, dport,
                    "TCP", g.start.min(), g.start.max(),
                    [f"{len(g)} web/TLS connections to {name or dst}:{int(dport)}; name is not on the built-in common-services list.",
                     "'Uncommon' only means 'not on a small allow-list'; most such destinations are legitimate."],
                    f">= {cfg.http_repeat_min} connections to a destination not on the allow-list", steps,
                    ["Any SaaS/API service not on the small built-in list."],
                    extra={"iocs": ([{"type": "ip", "value": dst}] + ([{"type": "domain", "value": name}] if name else []))}))
    return http, tls, alerts[: cfg.max_alerts_per_rule * 2]
