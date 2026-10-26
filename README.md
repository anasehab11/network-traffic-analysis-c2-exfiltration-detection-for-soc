# Network Traffic Analysis & C2/Exfiltration Detection for SOC

A local, offline Blue Team tool that analyses PCAP/PCAPNG files and helps a SOC analyst find **reconnaissance, C2 beaconing, DNS tunneling/DGA-like activity,
suspicious HTTP/TLS metadata and potential data exfiltration**, map findings to MITRE ATT&CK, extract IOCs and write an incident report.
Built in Python with Streamlit, Scapy, Pandas, Plotly and SQLite. Optional: Zeek, Suricata and a local LLM through Ollama. No paid APIs, no cloud services.

> **Important:** every detection is a *heuristic indicator*, not proof of compromise. Alerts always list evidence, thresholds, confidence and possible false positives.
> All bundled sample traffic is **synthetic and simulated** (`*_sim.pcap`); no real malware or victims are involved.

## Features by week
| Week | Implemented |
|---|---|
| 1 Foundations | PCAP/PCAPNG validation, packet/flow tables, TCP flag analysis (SYN/SYN-ACK/RST/FIN), DNS query/response analysis, protocol distribution, top talkers/ports, filters by IP/protocol/port/time, protocol map, baseline summary, Wireshark cheat sheet |
| 2 Anomalies | DNS (long names, entropy, frequency, NXDOMAIN, tunneling), beaconing, unusual ports, failed connections, large outbound transfers, HTTP user-agent/method/path, TLS SNI/JA3/version, SMB/SSH/RDP metadata |
| 3 Recon/C2/Exfil | scan/sweep/service-enumeration/ICMP-sweep rules, interval-statistics beaconing, exfiltration volume/ratio/HTTP/DNS rules, evidence-gated MITRE mapping, correlation |
| 4 AI & reporting | local Ollama assistant with fallback, prompt library, 12-section SOC report (Markdown/JSON/PDF), analyst triage notes, SQLite history |

## Quick start (Windows 10/11, PowerShell)
```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```
Open **Upload PCAP**, pick `demo_combined_sim.pcap` from the sample list, click **Analyze**. Stop with `Ctrl+C`.
Full setup (VS Code, optional Wireshark/Ollama/Suricata/Zeek, troubleshooting) is in [`docs/installation.md`](docs/installation.md).

Regenerate samples: `python sample_data/generate_samples.py`  -  Run tests: `pip install -r requirements-dev.txt` then `python -m pytest`

## Project structure
```
network-threat-detection/
  app.py                  Streamlit dashboard (15 pages)
  requirements.txt  requirements-dev.txt  pytest.ini  .gitignore  README.md
  config/                 settings.py (thresholds + defaults), watchlist.txt (ships empty)
  core/                   detection engine (no UI code)
    pcap_parser.py  flow_analysis.py  protocol_analysis.py  dns_analysis.py  http_tls_analysis.py
    scan_detection.py  beacon_detection.py  exfiltration_detection.py  ioc_extraction.py
    mitre_mapping.py  risk_scoring.py  wireshark_filters.py  report.py  analyzer.py  models.py  utils.py
  integrations/           zeek_integration.py  suricata_integration.py  ollama_integration.py   (all optional)
  database/               db.py  (SQLite history; investigations.db is created at first run)
  reports/                (exports you save manually)
  sample_data/            generate_samples.py + simulated PCAPs
  tests/                  pytest suite
  docs/                   installation.md user_guide.md detection_rules.md wireshark_filters.md troubleshooting.md
                          architecture.md tutorial.md ai_prompt_library.md annotated_pcap_analysis.md network_protocol_map.md
                          example_output/ (sample SOC report as .md/.json/.pdf)
```
Module responsibilities and the data flow are described in [`docs/architecture.md`](docs/architecture.md).

## Documentation map
| Document | Purpose |
|---|---|
| [docs/installation.md](docs/installation.md) | Windows setup, optional tools, safe use of real PCAPs |
| [docs/tutorial.md](docs/tutorial.md) | step-by-step walkthrough of the demo |
| [docs/user_guide.md](docs/user_guide.md) | pages, alert reading, validation, exports |
| [docs/detection_rules.md](docs/detection_rules.md) | every rule, threshold defaults, MITRE table, limitations |
| [docs/wireshark_filters.md](docs/wireshark_filters.md) | Wireshark display/capture filter cheat sheet |
| [docs/annotated_pcap_analysis.md](docs/annotated_pcap_analysis.md), [docs/network_protocol_map.md](docs/network_protocol_map.md) | Week 1 deliverables from the sample data |
| [docs/ai_prompt_library.md](docs/ai_prompt_library.md) | Week 4 prompt library and validation checklist |
| [docs/example_output/](docs/example_output/) | example analysis output / sample incident report |
| [docs/troubleshooting.md](docs/troubleshooting.md) | common errors and fixes |

## Safety and limitations (summary)
* Offline analysis; the app never scans, resolves or contacts addresses found in a capture. Files are validated, size-limited and never executed.
* Payload bodies are not stored or logged. Optional tools run without a shell, with timeouts and no admin rights.
* The AI assistant is optional, loopback-only, receives structured summaries (not the PCAP), treats packet text as untrusted data, and its output is labelled as an unvalidated draft.
* Encrypted traffic exposes only metadata; missing/truncated packets, NAT and capture position limit conclusions. SMB/SSH/RDP rules show connection patterns, not authentication success or file contents.
* Thresholds are configurable (defaults documented) and need tuning to your environment.
