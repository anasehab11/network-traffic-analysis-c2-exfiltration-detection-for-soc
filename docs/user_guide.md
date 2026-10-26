# User Guide

Start the app with `streamlit run app.py` (see `docs/installation.md`). Use the sidebar to switch pages. The sidebar **Glossary** explains technical terms.

## Reading an alert
Every alert shows: title, severity, confidence, a badge saying whether it is a **Heuristic finding** (threshold-based) or **Corroborated** (Suricata/Zeek/watchlist),
source and destination, destination port and protocol, time range, evidence bullets, the detection rule and threshold, MITRE ATT&CK mapping (only if supported),
investigation steps, possible false positives and Wireshark filters.

> Severity answers "how bad if real?"; confidence answers "how sure are we?". A *High severity / Low confidence* alert is a lead, not a conclusion.

## Pages
| Page | What it does |
|---|---|
| **Dashboard** | summary cards, severity and category charts, hosts ranked by risk, top alerts, tool status |
| **Upload PCAP** | upload `.pcap/.pcapng/.cap` (size-checked, magic-byte validated) or pick a bundled `_sim` sample; optional Zeek/Suricata |
| **Traffic Overview** | filter by IP, protocol, port and time range; packets-over-time, protocol distribution, top talkers/ports, TCP flags, protocol-map Sankey, baseline summary, Wireshark cheat sheet |
| **Protocol Analysis** | transport/application protocol tables, flow states, TCP flow table, SMB/SSH/RDP metadata and alerts |
| **DNS Investigation** | query types, response codes, per-source/domain indicator table, top domains, DNS alerts, query log |
| **HTTP/TLS Investigation** | user-agents, hosts, methods, SNI list, JA3 fingerprints, HTTP/TLS alerts |
| **Alerts and Anomalies** | filter all alerts, inspect evidence, set triage status and notes (saved in SQLite) |
| **Port Scan Analysis** | per source/target probe statistics and scan alerts |
| **C2 Beaconing Analysis** | candidate groups with interval statistics, timeline and interval histogram |
| **Potential Exfiltration** | outbound volume by destination with out/in ratio and alerts |
| **IOC Explorer** | IPs, domains, URLs, JA3, user-agents; filter, defang, export CSV |
| **MITRE ATT&CK** | mapped techniques with rationale, evidence and linked alerts |
| **AI Investigation Assistant** | local-model tasks (summaries, hypotheses, filters, report drafts) or built-in template fallback |
| **Reports and Analysis History** | export Markdown/JSON/PDF, write your analyst conclusion, browse saved analyses |
| **Settings and Tool Status** | tool detection, limits, tool paths, every threshold with its default |

## Typical workflow
1. **Upload PCAP** > Analyze. Read the warnings (truncation, missing responses) first.
2. **Dashboard**: which hosts are highest risk, which categories fired?
3. **Alerts and Anomalies**: open the top alert, read evidence and false positives.
4. Validate in Wireshark with the printed filter (and in EDR/proxy/DNS logs). Record the result: set status *False positive*, *Investigating* or *Confirmed (analyst-validated)* and add a note.
5. Check the specialised page (DNS, Beaconing, Exfiltration...) to see the statistics behind the alert.
6. **IOC Explorer**: export indicators only after validating them; they are defanged by default.
7. **AI Investigation Assistant** (optional): ask for hypotheses/Wireshark filters. Treat output as a draft.
8. **Reports**: type your conclusion, export Markdown/JSON/PDF.

## Validating findings
* Reproduce the evidence: use the Wireshark filter and confirm counts/timing by eye.
* Look for the benign explanation listed in the alert before escalating.
* Corroborate outside the PCAP: process-to-socket mapping (EDR/Sysmon), firewall/proxy/DNS logs, authentication logs.
* Never block an indicator solely because it appears in the IOC table.

## Using the app when optional tools are missing
* No Ollama: the AI page shows template-based summaries/explanations/filters from the same results.
* No Zeek/Suricata: the checkboxes are disabled; built-in detections run as usual.
* No TShark/Wireshark: the app does not need them; install Wireshark only for manual validation.
* No reportlab: PDF export is hidden; Markdown and JSON still work.

## Exports
* **Markdown**: the 12-section SOC report (Executive Summary ... Analyst Conclusion). IOC values are defanged.
* **JSON**: full structured report (alerts with evidence, MITRE, IOCs, host risk, thresholds, limitations).
* **PDF**: a plain rendering of the Markdown report (reportlab).
* AI drafts you generated in this session are appended as clearly labelled appendices ("AI-GENERATED DRAFT").
* The *Analyst conclusion* is left as "UNREVIEWED" until you write one.

## Privacy and safety
Packet payload bodies are never stored, shown or logged. Stored metadata includes IPs, domains, HTTP host/path/user-agent and TLS SNI/JA3: treat exports and `database/investigations.db` as sensitive.
