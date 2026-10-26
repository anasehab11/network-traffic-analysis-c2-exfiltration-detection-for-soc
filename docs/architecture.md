# Architecture

```
            +-------------------------+
            |  app.py (Streamlit UI)  |   renders only; no detection logic
            +------------+------------+
                         | AnalysisResult
            +------------v------------+
            |  core/analyzer.py       |   orchestrates the pipeline
            +------------+------------+
   parse -> flows -> detectors -> IOC -> MITRE -> risk -> report
```

Detection code never imports Streamlit, so every rule can be unit-tested with plain DataFrames (`tests/conftest.py` builds them).

## Data flow
1. `pcap_parser.parse_pcap` validates the file and extracts one metadata row per packet (DataFrame). Payload bodies are discarded.
2. `flow_analysis.build_flows` groups packets into bidirectional flows (initiator, bytes/packets each way, TCP state).
3. Detectors consume the packet and/or flow tables and return `Alert` objects (`core/models.py`).
4. `mitre_mapping` attaches candidate techniques; `risk_scoring` correlates alerts and ranks alerts/hosts.
5. `ioc_extraction` builds the indicator table and links indicators to alerts.
6. `report` renders JSON/Markdown/PDF; `database/db.py` stores summaries and analyst notes; `integrations/*` add optional context.

## Module responsibilities
| Path | Responsibility |
|---|---|
| `app.py` | Streamlit dashboard (15 pages) |
| `config/settings.py` | thresholds with defaults + descriptions, app settings, load/save of `config/settings.json` |
| `config/watchlist.txt` | analyst-supplied IOCs (ships empty) |
| `core/pcap_parser.py` | file validation (extension, size, magic), Scapy parsing, DNS/HTTP/TLS metadata, JA3 |
| `core/flow_analysis.py` | flow reconstruction and TCP/UDP state |
| `core/protocol_analysis.py` | protocol/port/talker/flag statistics, baseline, filters, SMB/SSH/RDP analysis |
| `core/dns_analysis.py` | DNS statistics, tunneling, DGA-like, NXDOMAIN, periodic lookups |
| `core/http_tls_analysis.py` | HTTP header and TLS ClientHello investigation |
| `core/scan_detection.py` | port scan, host sweep, service enumeration, ICMP sweep |
| `core/beacon_detection.py` | interval statistics and beacon scoring |
| `core/exfiltration_detection.py` | outbound volume/ratio, HTTP upload, DNS data volume |
| `core/ioc_extraction.py` | IOC table, watchlist matching |
| `core/mitre_mapping.py` | evidence-gated ATT&CK mapping |
| `core/risk_scoring.py` | alert/host scores, beacon-exfil correlation |
| `core/wireshark_filters.py` | cheat sheet and per-alert filters (values validated) |
| `core/report.py` | 12-section report, exports, non-AI fallback text |
| `core/analyzer.py` | pipeline and `AnalysisResult` |
| `core/models.py`, `core/utils.py` | alert model, shared helpers (entropy, scope, formatting, sanitising) |
| `integrations/zeek_integration.py` | optional Zeek offline run (list args, timeout) |
| `integrations/suricata_integration.py` | optional Suricata offline run (list args, timeout) |
| `integrations/ollama_integration.py` | loopback-only Ollama client, prompt library, untrusted-data handling |
| `database/db.py` | SQLite history, triage notes |
| `sample_data/generate_samples.py` | safe synthetic scenario generator |
| `tests/` | pytest suite (parser, flows, each detector, scoring, report, DB, AI safety, end-to-end) |

## Security design
* Offline by default; the only network call is to a loopback Ollama endpoint, and only when the user runs an AI task.
* Uploads are validated (extension, size, magic bytes), written to a temp file, parsed as data, then deleted. Nothing is executed.
* External tools are launched with argument lists (no shell), in temp directories, with timeouts and no elevated privileges.
* Attacker-controlled strings (hostnames, URLs, user-agents) pass through `safe_text` (control characters stripped, length-limited); AI context additionally neutralises delimiter tags.
* The AI model has no tools and its output is display-only; AI text is labelled as unvalidated draft.
* Logs contain counts and exception class names, never payloads or environment variables.
* Wireshark filter values embedded in alerts are restricted to a safe character set.
