# Step-by-Step Tutorial: Run and Use the Project

Goal: in about 20 minutes, analyse the simulated demo capture and understand every finding. Windows 10/11, PowerShell.

## Part A - Install and start (5 min)
1. Install Python 3.11 (tick *Add to PATH*). Check: `py -3.11 --version`.
2. Unzip the project, open the folder in VS Code, open a terminal (*Terminal > New Terminal*).
3. Create and activate the environment, install packages, start the app:
   ```powershell
   py -3.11 -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   streamlit run app.py
   ```
4. The browser opens `http://localhost:8501`. The **Dashboard** shows the tool status table: Scapy is *available*; Zeek, Suricata, Ollama may say not available. That is fine.

## Part B - Analyse the demo capture (3 min)
1. Sidebar > **Upload PCAP**.
2. In *bundled SIMULATED sample* choose `demo_combined_sim.pcap` > **Analyze**. (To regenerate samples: `python sample_data/generate_samples.py`.)
3. When "Analysis complete" appears, open **Dashboard**: about 5,100 packets, 15 alerts, five hosts ranked by risk.

## Part C - Walk the investigation (10 min)
The demo merges five simulated scenarios, each from a different host. Find each one.

| Step | Page | What to look at | What you should find |
|---|---|---|---|
| 1 | Traffic Overview | Protocol map, top talkers, TCP flags | `192.168.1.77` sends the most bytes; many RSTs relative to SYN-ACKs |
| 2 | Alerts and Anomalies | Sort by Risk | beaconing, scan, DNS tunneling, DGA-like, exfiltration alerts |
| 3 | C2 Beaconing Analysis | Select `192.168.1.50 -> 203.0.113.50:8443` | 36 connections, interval ~60 s, CV ~0.02, near-identical sizes, evenly spaced timeline |
| 4 | Port Scan Analysis | `192.168.1.66 -> 192.168.1.20` | ~208 ports probed, ~95% failed, open ports 22/80/445/3389; also a sweep of TCP/445 and an ICMP sweep |
| 5 | DNS Investigation | Per-source table, sort by `tunnel_indicators` | `192.168.1.88`, 300 long high-entropy TXT queries under `tunnel-sim.example`, plus DGA-like names answered with NXDOMAIN |
| 6 | Potential Exfiltration | Top outbound volumes | `192.168.1.77 -> 198.51.100.25:8080`, ~2.8 MB out, ratio ~54:1 |
| 7 | HTTP/TLS Investigation | User-agents, SNI, JA3 | scanner user-agent from the scanning host, `c2-sim.example` SNI with one JA3 for all beacons |
| 8 | Protocol Analysis | SMB/SSH/RDP section | SMB connections to 42 hosts (connection metadata only) |
| 9 | MITRE ATT&CK | Technique table | T1046, T1071.x, T1572, T1568.002, T1048.x ... each marked *candidate* |
| 10 | IOC Explorer | Alert-referenced indicators | external IP, domains, JA3 (defanged) |

Also notice what is **not** flagged: the normal browsing host `192.168.1.10` has only an *Informational* periodic NTP note (port 123 is on the benign-periodic list).

## Part D - Triage like an analyst
1. Alerts page > open the beacon alert. Read *Evidence*, *Possible false positives* and *Investigation steps*.
2. Copy the Wireshark filter, open `sample_data/beacon_sim.pcap` in Wireshark and paste it. Count the connections and compare with the alert.
3. Set *Status* to **Investigating** and add a note; click **Save triage**.
4. Open the exfiltration alert: notice confidence is only *Low* because it rests on volume/ratio and the payload is not inspectable.

## Part E - Optional AI assistance
1. Install Ollama and run `ollama pull llama3.2` (see `docs/installation.md`).
2. **AI Investigation Assistant** > open *Exactly what is sent to the model* > choose a task such as *Generate investigation hypotheses* > **Run**.
3. Validate the answer with the checklist in `docs/ai_prompt_library.md`. Without Ollama, the same page produces template-based text.

## Part F - Export the report
1. **Reports and Analysis History**: write your own *Analyst conclusion*.
2. Download **Markdown**, **JSON** or **PDF**. Compare with `docs/example_output/sample_soc_incident_report.md`.
3. Your analysis is also listed under *Analysis history* (SQLite file `database/investigations.db`).

## Part G - Try your own (authorised) capture
Upload a `.pcap`/`.pcapng` you are allowed to analyse. Read the warnings and *Evidence and Limitations* first, compare against a baseline capture of a quiet period,
and tune thresholds on **Settings and Tool Status** if needed. Re-run **Analyze** after changing thresholds.

## Part H - Stop and test
* Stop: `Ctrl+C` in the terminal. Run the tests: `pip install -r requirements-dev.txt` then `python -m pytest`.
