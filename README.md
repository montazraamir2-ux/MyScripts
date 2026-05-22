# MyScripts — Modular Reconnaissance & OSINT Suite

A modular reconnaissance and OSINT suite built in Python 3, designed
to operate inside a non-rooted Termux/Proot Ubuntu environment on
ARM64 Android. All network interaction uses TCP connect() — no root
privileges required.

---

## Architecture
````
MyScripts/
├── main.py               # Interactive menu — suite orchestrator
├── report_generator.py   # HTML report generator
├── scan.log              # Unified JSON log (auto-generated)
├── report.html           # Scan report output (auto-generated)
├── core/
│   └── logger.py         # Shared structured logging interface
└── modules/
├── scanner.py        # Network scanner
├── banner.py         # Banner grabber
└── osint_tool.py     # OSINT username reconnaissance
---

## Modules

### 1. Network Scanner — `modules/scanner.py`
Scans a single IP or a full CIDR range for open ports using TCP
connect() with concurrent threading.

- **Input:** Target IP or CIDR range (e.g. `192.168.1.0/24`),
  optional custom port list
- **Output:** Dictionary mapping each live IP to its open ports
- **Default ports:** 21, 22, 23, 25, 53, 80, 443, 8080, 8443
- **Concurrency:** Up to 100 threads via ThreadPoolExecutor
- **Constraint:** TCP connect() only — no SYN scan, no root required

```bash
python modules/scanner.py 192.168.1.0/24
python modules/scanner.py 192.168.1.1 80,443,8080

2. Banner Grabber — modules/banner.py
Connects to a specified IP and port, sends an HTTP GET request, and
captures the server's raw response to identify running services.
Input: Target IP + port (interactive prompt)
Output: Raw server response (up to 4096 bytes)
Protocol: HTTP — plaintext services only
Use case: Service identification on discovered open ports

python modules/banner.py

3. OSINT Username Reconnaissance — modules/osint_tool.py
Searches for a target username across 10 platforms simultaneously
using concurrent threading with false-positive mitigation.
Input: Target username (interactive prompt)
Output: List of confirmed profile URLs per platform
Platforms: Instagram · GitHub · Reddit · Telegram · Steam ·
DockerHub · Pinterest · Medium · GitLab · Cracked.io
Concurrency: One thread per platform — all run in parallel
False-positive handling: Instagram logic filters login redirects
and post URLs before confirming a result

python modules/osint_tool.py

4. HTML Report Generator — report_generator.py
Reads the unified scan.log JSON file and produces a formatted
dark-theme HTML report with event statistics and a full event table.
Input: scan.log (auto-populated by all modules)
Output: report.html — self-contained HTML file
Statistics: Total events · Profiles found · Errors
Event types: scan_start · discovered_ip · profile_found ·
banner_grab · scan_error

python report_generator.py

Core — Unified Logging Interface (core/logger.py)
Every module writes to a single shared scan.log using structured
JSON records. No module handles logging independently.

{
  "timestamp": "2025-05-22 01:11:00",
  "tool": "scanner",
  "level": "INFO",
  "event": "discovered_ip",
  "data": { "ip": "192.168.1.5", "port": 80 }
}


Available log functions:
Function
Event
log_scan_start(tool, target)
Marks the beginning of any scan
log_discovered_ip(tool, ip, port)
Records an open port found
log_banner_grab(tool, ip, port, banner)
Records a captured banner
log_profile_found(tool, platform, url)
Records a confirmed profile
log_scan_error(tool, error, ip)
Records any scan-time error

# Inside Proot Ubuntu on Termux
apt install python3 python3-pip
pip install requests
git clone https://github.com/montazraamir2-ux/MyScripts
cd MyScripts
python main.py

Usage
python main.py

╔══════════════════════════════════════╗
║         MyScripts Recon Suite        ║
║     Modular Reconnaissance Tool      ║
╚══════════════════════════════════════╝

[1] Network Scanner
[2] OSINT Username Lookup
[3] Banner Grabber
[0] Exit

Environment
Property
Value
Language
Python 3
Platform
Termux / Proot Ubuntu / ARM64 Android
Root required
No
Scan method
TCP connect()
Log format
Structured JSON

Roadmap
[ ] JSON → HTML report pipeline (Phase 2 — complete)
[ ] Severity classification: Info / Low / Medium / High
[ ] Session management — named scan sessions
[ ] Shodan · VirusTotal · WHOIS API integrations
[ ] argparse CLI for all modules
[ ] Gemma 2B / Ollama offline log analysis integration

Legal
This suite is designed for authorized testing and reconnaissance
on networks and systems you own or have explicit permission to test.
Unauthorized use against third-party systems is illegal.

Maintained by https://www.linkedin.com/in/montazar-amer-06743b38a— Cybersecurity Engineering Student | Offensive Security & OSCP Track