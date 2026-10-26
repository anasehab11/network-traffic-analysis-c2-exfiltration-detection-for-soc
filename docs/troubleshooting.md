# Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `py` or `python` is not recognised | Python is not on PATH. Re-run the installer with *Add python.exe to PATH*, or use the full path; open a **new** terminal afterwards. |
| `Activate.ps1 cannot be loaded because running scripts is disabled` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again. Or use `.venv\Scripts\activate.bat` in Command Prompt. |
| `streamlit` is not recognised | The virtual environment is not active (no `(.venv)` prefix) or dependencies were not installed. Activate and run `pip install -r requirements.txt`. |
| `ModuleNotFoundError: scapy` (or pandas, plotly) | Same as above: install into the active environment. Run `pip list` to confirm. |
| Pip build errors on a very new Python | Use Python 3.11 or 3.12; create the venv with `py -3.11 -m venv .venv`. |
| Port 8501 already in use | Another Streamlit is running. Close it, or `streamlit run app.py --server.port 8502`. |
| Browser does not open | Open <http://localhost:8501> manually. |
| "Unsupported file type" | Only `.pcap`, `.pcapng`, `.cap`. Convert other formats with Wireshark (*File > Save As*). |
| "bad magic number" | The file is not really a PCAP (renamed text/zip/ETL). Re-export from Wireshark. |
| "File is X MB; the limit is 200 MB" | Raise *Max upload size* on Settings, or split the capture in Wireshark (*File > Export Specified Packets*). Streamlit's own upload cap is 200 MB by default; to raise it run `streamlit run app.py --server.maxUploadSize 500`. |
| Warning "capture appears truncated" | The file ended mid-packet. Results cover the readable part. Re-capture or re-export. |
| "Packet limit reached" | Only the first N packets were analysed (default 250,000). Raise *Max packets analysed* on Settings (slower, uses more RAM) or filter the capture first. |
| Analysis is slow | Scapy parsing is the bottleneck (a few thousand packets per second in the bundled sample runs). Use smaller captures or a Wireshark-filtered subset. |
| No DNS NXDOMAIN alerts although I expect some | The capture has queries but no responses (one-directional capture), so response-based rules cannot run. See *Evidence and Limitations*. |
| No beaconing found in a long capture | The group may have fewer than `beacon_min_connections` connections, intervals too irregular, or the capture is too short. Lower thresholds on Settings to explore. |
| Too many alerts / noisy | Raise thresholds on Settings, review the false-positive notes, and compare with a baseline capture. Informational alerts are expected on busy networks. |
| Ollama shows "Installed but not running" | Start the Ollama app or run `ollama serve`. |
| Ollama shows "no models pulled" | `ollama pull llama3.2`, then refresh the page. |
| "Blocked: only local (loopback) Ollama hosts" | By design. Use `http://127.0.0.1:11434`. |
| AI request times out | Large models are slow on CPU. Pick a smaller model or raise `ollama_timeout` in `config/settings.json`. |
| Suricata/Zeek checkbox disabled | The executable was not found. Enter its path on Settings. Zeek is not available natively on Windows (use WSL2). |
| Suricata ran but produced no alerts | No rules loaded or no matching traffic. Check `suricata.yaml` and rules; the app only imports `alert` events from `eve.json`. |
| PDF button missing | `pip install reportlab`. |
| `database is locked` | Close other copies of the app using the same `database/investigations.db`. |
| Streamlit prints `use_container_width` deprecation text | Harmless: use the pinned `streamlit>=1.49,<1.50` from `requirements.txt` (the app already uses `width="stretch"`). |
| Reset everything | Delete `database/investigations.db` and `config/settings.json` while the app is stopped. |
| Tests fail on import | Run from the project root with the venv active: `python -m pytest`. |

Still stuck? Run `streamlit run app.py` in a terminal and read the log lines (they contain counts and error classes, never packet payloads).
