# Detection Rules and Methodology

Every rule works on **metadata** (addresses, ports, flags, sizes, timing, DNS names, HTTP headers, TLS ClientHello fields). Rules are *heuristics*:
they say "this pattern is worth a look", never "this is an attack". Each alert states the rule, the threshold, the evidence, a confidence level,
whether the evidence is `Heuristic` or `Corroborated`, investigation steps and likely false positives.

## Severity, confidence, risk

* **Severity** = potential impact if the finding is real: Informational, Low, Medium, High, Critical (Critical is reserved for host-level scores, see below).
* **Confidence** (Low/Medium/High) = how strong the evidence is. Timing alone gives Low; several independent signals give Medium/High.
* **Evidence strength**: `Heuristic` = threshold rule on metadata. `Corroborated` = Suricata signature, Zeek notice or analyst watchlist match.
* **Alert risk score** = severity base (5/25/50/75/90) x confidence factor (0.8/1.0/1.1) x 1.1 if Corroborated, capped at 100.
* **Host risk** = best score per category + 15% of the other categories' best scores (+5 if 3 or more categories), capped at 100.
  Levels: >= 90 Critical, >= 65 High, >= 40 Medium, >= 15 Low. A single heuristic alert cannot reach Critical.

## Rule catalogue

### DNS (`core/dns_analysis.py`)
Queries are grouped per (source, registered domain). Names ending in `.arpa`, `.local`, `.lan`, `.home`, `.internal` are ignored.

| Rule | Fires when | Notes |
|---|---|---|
| `DNS-TUNNEL` | At least `dns_tunnel_min_score` of 5 indicators: many unique subdomains, high-entropy subdomains, long names, TXT/NULL/ANY-heavy, high query rate | Medium at 3 indicators, High at 4+. Data inside queries is never decoded. |
| `DNS-ANOMALY` | Long names or high-entropy subdomains but below the tunneling score | Low |
| `DNS-HIGHFREQ` | Peak queries/min to one domain >= `dns_high_freq_per_min` and nothing else | Low |
| `DNS-DGA` | >= `dns_dga_min_domains` distinct domains whose second-level label is >= 10 chars, entropy >= `dns_dga_min_entropy`, vowel ratio <= `dns_dga_max_vowel_ratio` | Confidence High if >= 70% of matching responses are NXDOMAIN (needs captured responses) |
| `DNS-NXDOMAIN` | Client gets >= `dns_nxdomain_min_responses` responses and NXDOMAIN share >= `dns_nxdomain_ratio` | Needs responses in the capture; suppressed when a DGA alert covers the same client. No ATT&CK mapping. |
| `DNS-PERIODIC` | Same name looked up >= `beacon_min_connections` times at regular intervals | Low |

Entropy is Shannon entropy (bits per character) of the subdomain text without dots. Random base32 text scores about 4.5; ordinary words about 2.5-3.

### Beaconing (`core/beacon_detection.py`)
1. Take TCP/UDP flows and group by (source, destination, destination port, protocol).
2. Require >= `beacon_min_connections` connections and a mean interval between `beacon_min_interval_sec` and `beacon_max_interval_sec`.
3. Compute intervals between flow start times: mean, median, standard deviation, **coefficient of variation (CV = std/mean)** and the share of intervals within +/- `beacon_tolerance` of the median.
4. A group is *periodic* if CV <= `beacon_max_cv` **or** >= `beacon_tolerance_fraction` of intervals are on schedule (the second test tolerates a missed beat).
5. Points are added only for periodic groups: external destination, non-standard port, near-constant byte sizes, >= 20 connections, CV < 0.1.
   Severity: 0-1 points Low, 2-3 Medium, 4+ High. Ports in `beacon_benign_ports` (NTP, DHCP, DNS, mDNS...) are capped at Informational.

Periodic traffic is common in legitimate software (updates, telemetry, keep-alives). The alert always lists those false-positive explanations.

### Scanning (`core/scan_detection.py`)
Probe = TCP flow where the initiator sent a SYN. Failed probe = no response (`NO_RESPONSE`) or reset (`REJECTED`).

| Rule | Fires when |
|---|---|
| `SCAN-VERTICAL` | one source, one target: >= `scan_min_ports` ports and >= `scan_min_flows` probes and failed share >= `scan_failed_ratio` |
| `SCAN-HORIZONTAL` | one source, one port: >= `scan_min_hosts` hosts and the same probe/failed conditions |
| `SCAN-SERVICE-ENUM` | one source reaches >= `scan_service_enum_ports` well-known service ports on one host (not already a vertical scan) |
| `SCAN-ICMP-SWEEP` | one source sends ICMP to >= `scan_icmp_sweep_hosts` hosts |

Internal sources are rated High (possible compromised host or lateral reconnaissance); external sources Medium (Internet background scanning is common).
Evidence includes probe rate, ports, open ports seen (SYN-ACK) and the share of SYNs with TCP window 1024. **The tool never claims the scanner was Nmap**:
a small fixed window is consistent with Nmap defaults but not proof, and OS-fingerprinting/NSE traffic cannot be confirmed from metadata.

### Exfiltration (`core/exfiltration_detection.py`)
Flows are oriented from the internal host's point of view (internal<->external, or internal<->internal at Low).

| Rule | Fires when |
|---|---|
| `EXFIL-LARGE` | bytes out to one destination >= `exfil_large_bytes` |
| `EXFIL-RATIO` | bytes out >= `exfil_ratio_min_bytes` and out/in >= `exfil_ratio` |
| `EXFIL-HTTP-POST` | cleartext POST/PUT whose declared Content-Length >= `exfil_http_post_bytes` |
| `EXFIL-DNS` | query-name text to one domain >= `dns_exfil_bytes` with many unique subdomains |

Large + ratio = High/Medium confidence; one rule alone = Medium/Low. If the remote host initiated the connection (data *served* to a client) severity drops one level.
If a beacon alert exists for the same source and destination, both alerts gain a correlation note and the exfiltration confidence rises one level
(and ATT&CK T1041 is added with a "correlation, not proof" rationale). Encrypted payloads cannot be inspected; the type of data is unknown.

### HTTP and TLS (`core/http_tls_analysis.py`)
| Rule | Fires when | Severity |
|---|---|---|
| `HTTP-SCANNER-UA` | User-Agent contains a scanner keyword (sqlmap, nikto, nmap, masscan, ...) | Medium |
| `HTTP-SCRIPT-UA` | scripting-library or missing User-Agent | Informational |
| `HTTP-METHOD` | TRACE, TRACK, CONNECT or PROPFIND | Low |
| `HTTP-PATH` | path matches command parameter, web-shell file name, traversal, injection string, long base64 segment or very long path | Medium, confidence Low (response not evaluated) |
| `HTTP-IPHOST` | >= 3 requests with an IP literal as Host | Informational |
| `TLS-NONSTD-PORT` | >= 3 ClientHellos on a non-standard TLS port | Low |
| `TLS-NO-SNI` | >= `http_repeat_min` ClientHellos without SNI to one destination | Low |
| `TLS-OLD-VERSION` | highest offered version below TLS 1.2 | Low |
| `TLS-DGA-SNI` | random-looking SNI (same test as DGA) | Medium, confidence Low |
| `TLS-UNCOMMON-REPEAT` | >= `http_repeat_min` web/TLS connections to an external destination not on a small allow-list | Informational |

JA3 fingerprints are extracted and shown as IOCs. No JA3 blocklist ships with the tool; add hashes you trust to `config/watchlist.txt`.

### SMB, SSH, RDP (`core/protocol_analysis.py`)
Metadata only: **authentication success and file contents are never inferred.**

| Rule | Fires when |
|---|---|
| `REMOTE-SMB-SWEEP` / `REMOTE-RDP-SWEEP` / `REMOTE-SSH-SWEEP` | one source contacts >= `remote_sweep_hosts` hosts on that service |
| `REMOTE-REPEAT` | >= `remote_repeat_conns` connections from one source to one host with median duration < 10 s (password-guessing-like) |
| `REMOTE-EXPOSED` | an external address completes a handshake with an internal SMB/RDP/SSH port |

### Optional integrations and watchlist
* `SURICATA-SIG` (from `eve.json` alerts) and `ZEEK-NOTICE` (from `notice.log`) are marked Corroborated.
* `WATCHLIST-MATCH`: exact match with `config/watchlist.txt` (Corroborated, High).

## MITRE ATT&CK mapping (`core/mitre_mapping.py`)
A technique is attached only when the rule's evidence supports it, always as a *candidate* needing validation. Rules **without** a mapping on purpose:
`DNS-NXDOMAIN`, `DNS-HIGHFREQ`, `DNS-ANOMALY`, `HTTP-SCRIPT-UA`, `HTTP-METHOD`, `HTTP-IPHOST`, `TLS-NO-SNI`, `TLS-OLD-VERSION`, `TLS-UNCOMMON-REPEAT`, `REMOTE-EXPOSED`,
benign-port beacons and watchlist matches.

| Rule | Techniques |
|---|---|
| `SCAN-VERTICAL`, `SCAN-SERVICE-ENUM` | T1046 (internal source) or T1595 (external) |
| `SCAN-HORIZONTAL` | T1046 (internal) or T1595.001 (external) |
| `SCAN-ICMP-SWEEP` | T1018 (internal) or T1595.001 (external) |
| `BEACON-PERIODIC` | T1071 (T1071.001 on web ports), plus T1571 on non-standard ports |
| `DNS-TUNNEL` | T1071.004, T1572 |
| `DNS-DGA`, `TLS-DGA-SNI` | T1568.002 |
| `DNS-PERIODIC` | T1071.004 (low confidence) |
| `EXFIL-LARGE`, `EXFIL-RATIO` | T1048 |
| `EXFIL-HTTP-POST` | T1048.003 |
| `EXFIL-DNS` | T1048.003, T1071.004 |
| correlated beacon + exfil | T1041 |
| `HTTP-SCANNER-UA` | T1595.002 |
| `HTTP-PATH` | T1505.003 (web-shell-like name), T1190 (request to an internal host) |
| `TLS-NONSTD-PORT` | T1571 |
| `REMOTE-SMB-SWEEP` / `-RDP-` / `-SSH-` | T1021.002 / T1021.001 / T1021.004 |
| `REMOTE-REPEAT` | T1110 |

## Thresholds and defaults
All thresholds can be changed on **Settings and Tool Status** (saved to `config/settings.json`) or in code via `config/settings.py`. Defaults:

| Threshold | Default | Meaning |
|---|---|---|
| `dns_long_name_len` | `52` | Query name length (chars) considered unusually long. |
| `dns_long_label_len` | `40` | Single DNS label length considered unusually long. |
| `dns_entropy_min` | `3.5` | Shannon entropy of the subdomain part considered high. |
| `dns_entropy_min_len` | `16` | Minimum subdomain length before entropy is evaluated. |
| `dns_min_hits` | `5` | Minimum number of matching queries before an indicator counts. |
| `dns_high_freq_per_min` | `100` | Queries per minute from one source to one registered domain. |
| `dns_nxdomain_min_responses` | `20` | Minimum DNS responses before NXDOMAIN ratio is judged. |
| `dns_nxdomain_ratio` | `0.5` | NXDOMAIN share of responses considered high. |
| `dns_tunnel_min_unique_subdomains` | `30` | Unique subdomains under one domain (tunneling indicator). |
| `dns_tunnel_avg_label_len` | `20` | Average subdomain length (tunneling indicator). |
| `dns_tunnel_min_score` | `3` | Number of DNS tunneling indicators needed for a tunneling alert (max 5). |
| `dns_dga_min_domains` | `10` | Distinct random-looking domains from one source for a DGA-like alert. |
| `dns_dga_max_vowel_ratio` | `0.3` | Max vowel ratio for a label to look random (English is ~0.38). |
| `dns_dga_min_entropy` | `3.0` | Min entropy of a second-level label to look random. |
| `beacon_min_connections` | `8` | Minimum repeated connections in a group before timing is analysed. |
| `beacon_max_cv` | `0.25` | Max coefficient of variation (std/mean) of intervals for 'regular'. |
| `beacon_min_interval_sec` | `1.0` | Ignore groups whose mean interval is shorter (bursty traffic). |
| `beacon_max_interval_sec` | `7200.0` | Ignore groups whose mean interval is longer. |
| `beacon_tolerance` | `0.2` | Interval counts as on-schedule if within +/- this fraction of the median. |
| `beacon_tolerance_fraction` | `0.8` | Share of intervals that must be on-schedule (tolerates missed beats). |
| `beacon_benign_ports` | `[53, 67, 68, 123, 137, 138, 1900, 5353]` | Ports where periodic traffic is normally benign (alerts capped at Informational). |
| `scan_min_ports` | `20` | Distinct destination ports on one host from one source (vertical scan). |
| `scan_min_hosts` | `15` | Distinct hosts on one port from one source (horizontal sweep). |
| `scan_failed_ratio` | `0.6` | Share of SYN probes that got no answer or a reset. |
| `scan_min_flows` | `20` | Minimum probe count before a scan alert can fire. |
| `scan_service_enum_ports` | `8` | Distinct well-known service ports on one host (service enumeration). |
| `scan_icmp_sweep_hosts` | `15` | Distinct hosts receiving ICMP from one source (ping sweep). |
| `remote_repeat_conns` | `10` | Repeated short SMB/SSH/RDP connections from one source to one host. |
| `remote_sweep_hosts` | `5` | Distinct hosts contacted on SMB/SSH/RDP by one source. |
| `exfil_large_bytes` | `10000000` | Outbound bytes to one destination considered unusually large. |
| `exfil_ratio_min_bytes` | `1000000` | Minimum outbound bytes before the out/in ratio is judged. |
| `exfil_ratio` | `10.0` | Outbound-to-inbound byte ratio considered unusual. |
| `exfil_http_post_bytes` | `1000000` | HTTP POST/PUT Content-Length considered large. |
| `dns_exfil_bytes` | `20000` | Total query-name bytes to one domain considered a DNS data channel. |
| `http_repeat_min` | `10` | Repeat connections to one uncommon destination. |
| `http_long_path_len` | `200` | HTTP request path length considered unusual. |
| `max_alerts_per_rule` | `50` | Cap on alerts emitted per detection rule family. |

Tune thresholds against a baseline of your own environment; the defaults favour catching the simulated scenarios while staying quiet on ordinary browsing.

## Known limitations
* Capture position and NAT hide traffic and real source hosts; missing packets, truncation or snaplen limits reduce evidence.
* TCP flows are keyed by 5-tuple; reused ports within one TCP session window can merge flows. UDP/ICMP flows are split after 30 s idle.
* Encrypted traffic: only SNI, versions, JA3, sizes and timing are visible. TLS 1.3 hides certificates.
* DNS-over-HTTPS/TLS and QUIC are not decoded. IPv6 is parsed but less exercised.
* Thresholds are generic; legitimate backup, CDN, telemetry and monitoring traffic can trip them.
