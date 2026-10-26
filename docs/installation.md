# Installation Guide (Windows 10/11)

Everything below is tested against the files in this project. Commands are for **PowerShell** unless stated.

## 1. What you need

| Software | Required? | Purpose |
|---|---|---|
| Python 3.11 (3.12 also works) | **Required** | runs the app |
| VS Code | Recommended | editing/terminal |
| Wireshark (includes TShark) | Optional | validating alerts manually |
| Ollama | Optional | local AI assistant |
| Suricata | Optional | signature alerts (Windows MSI available) |
| Zeek | Optional | extra network logs (Linux/WSL2 only, see below) |

The app **works without any optional tool**; missing tools are shown as "not available" on *Settings and Tool Status*.
No Npcap/WinPcap is needed because the app only reads capture files (it never sniffs live traffic).

## 2. Install Python and check the version
1. Download Python 3.11 from <https://www.python.org/downloads/windows/>. Run the installer and **tick "Add python.exe to PATH"**.
2. Open a new PowerShell window and verify:
   ```powershell
   py -3.11 --version
   ```
   You should see `Python 3.11.x`. (If you installed 3.12, use `py -3.12`; if `py` is missing try `python --version`.)

## 3. Open the project in VS Code
1. Unzip `network-threat-detection.zip`, e.g. to `C:\Users\<you>\Documents\network-threat-detection`.
2. VS Code > **File > Open Folder...** > select that folder.
3. Open a terminal: **Terminal > New Terminal** (it opens in the project folder).

## 4. Create and activate a virtual environment
```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
```
Your prompt should now start with `(.venv)`.
If PowerShell says scripts are disabled, run this once for the current window only, then activate again:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
(In classic Command Prompt use `.venv\Scripts\activate.bat` instead.)

## 5. Install dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```
Developers who want to run the tests use `pip install -r requirements-dev.txt` instead.

## 6. Start the application
```powershell
streamlit run app.py
```
The browser opens at <http://localhost:8501>. If Streamlit asks for an email on first run, just press Enter.

**Stop the app:** click the terminal and press `Ctrl+C`. Deactivate the environment with `deactivate`.

## 7. Create or load sample traffic
The zip already contains simulated captures in `sample_data/`. To regenerate them:
```powershell
python sample_data/generate_samples.py
```
Then open **Upload PCAP**, choose `demo_combined_sim.pcap` in the sample list and click **Analyze**.
All samples are synthetic and labelled `_sim`; they use documentation IP ranges and `.example` domains.

## 8. Run the unit tests
```powershell
pip install -r requirements-dev.txt
python -m pytest
```
Expected: all tests pass (about 30 seconds; some tests generate temporary PCAPs).

## 9. Optional tools

### Wireshark / TShark
Download from <https://www.wireshark.org/download.html>. The installer offers Npcap and TShark; accepting the defaults is fine.
Check: `tshark --version`. The app only reports whether `tshark` is on PATH; analysis does not depend on it.

### Ollama (local AI)
1. Install from <https://ollama.com/download/windows> and start it (it runs in the system tray).
2. Pull a model, for example: `ollama pull llama3.2`
3. Check: `ollama list`. In the app open **AI Investigation Assistant**; the status shows "Ollama is running" and a model dropdown appears.
Only `localhost` addresses are accepted; nothing is sent to the Internet by this app. If Ollama is missing the page shows built-in template summaries instead.

### Suricata
Download the Windows MSI from <https://suricata.io/download/> and install it with rules (see the Suricata docs for `suricata-update`).
Open **Settings and Tool Status**; if the executable is not on PATH, enter its full path (for example `C:\Program Files\Suricata\suricata.exe`) and, if needed,
the path to `suricata.yaml`. Then tick *Also run Suricata* on **Upload PCAP**. The app runs it offline (`-r file -l tempdir -k none`) with a timeout.

### Zeek
Zeek does not run natively on Windows. Options: run the whole project inside **WSL2** (Ubuntu) where Zeek is installed
(see <https://docs.zeek.org/en/master/install.html>), or skip Zeek. When a `zeek` executable is reachable on the same OS as the app, the checkbox
*Also run Zeek* is enabled; the app runs `zeek -C -r <pcap> LogAscii::use_json=T` offline in a temporary folder and imports `notice.log` entries and log counts.

## 10. Using real PCAPs safely
* Only analyse captures you are **authorised** to handle; they may contain credentials and personal data.
* The app works offline, never executes files, and never scans or contacts addresses found in a capture.
* It stores metadata only (no payload bodies). Reports contain IPs, domains and URLs/paths seen in the capture: treat exports as sensitive.
* Do not browse to domains from the IOC list; use defanged values and your approved reputation tooling.
* Keep real captures out of Git (the `.gitignore` already excludes `*.pcap`, `*.pcapng`; only `*_sim` samples are allowed).
* Default limits: 200 MB per file and 250,000 packets (change on the Settings page).
