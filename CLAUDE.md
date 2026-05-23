CLAUDE.md — MyScripts Recon Suite
Environment
Property
Value
Runtime
Proot Ubuntu inside Termux on Android
Architecture
ARM64 (aarch64)
Root Status
Non-rooted — no sudo ever
Python
Python 3
Package Manager
apt install (inside Proot Ubuntu)
Hard Constraints
Raw Sockets are forbidden. Use TCP connect() via socket.create_connection() exclusively.
No SYN scan. No OS fingerprinting via Nmap or Scapy.
No sudo. No root-dependent system calls.
No code comments of any kind (inline, block, or docstring).
All code must be ARM64-compatible and Python-native where possible.
Project Architecture
MyScripts/
├── main.py                  ← interactive menu — sole entry point
├── report_generator.py      ← reads scan.log → produces report.html
├── scan.log                 ← unified NDJSON log (auto-generated)
├── report.html              ← scan report output (auto-generated)
├── CLAUDE.md                ← this file
├── requirements.txt
├── core/
│   ├── logger.py            ← only logging interface — all modules use this
│   └── analyzer.py          ← Gemma 2B integration via Ollama
└── modules/
    ├── scanner.py           ← TCP connect() network scanner
    ├── banner.py            ← banner grabber
    ├── fingerprint.py       ← service fingerprinting — used internally by scanner
    └── osint_tool.py        ← OSINT username reconnaissance

Data Pipeline
scanner.run()
    → scan_host() / scan_network()           [TCP connect scan]
    → log_discovered_ip()                    [audit trail per port]
    → fingerprint_host()                     [service + banner per open port]
    → log_findings()                         [structured findings entry]
         ↓
    scan.log  (NDJSON — one JSON object per line)
         ↓
    report_generator.py  → report.html
    core/analyzer.py     → Gemma 2B analysis
Log Entry Formats
Event entry (audit trail):
{"timestamp": "...", "session_id": "...", "tool": "...", "level": "INFO", "event": "...", "data": {}}
Findings entry (consumed by report_generator and analyzer):
{"timestamp": "...", "session_id": "...", "tool": "scanner", "findings": [{"ip": "...", "hostname": "...", "open_ports": [{"port": 22, "service": "SSH", "banner": "..."}]}]}
Logger Contract
from core.logger import log_scan_start, log_discovered_ip, log_scan_error
from core.logger import log_banner_grab, log_profile_found, log_findings

log_findings(tool, session_id, findings)
All logger functions accept session_id as an optional parameter (default: "").
Module Contract
Every module callable from main.py exposes:
def main() -> None      # for standalone invocation
def run(...) -> None    # for menu invocation with session_id
AI Role Separation
Role
Connectivity
Claude Code CLI
Code authoring, refactoring
Requires internet
Gemma 2B via Ollama
Log analysis, scan interpretation
Fully offline
Current Phase
Phase 1 complete — Architectural Foundation.
Phase 2 complete — report_generator.py implemented.
Next: Phase 3 — expand OSINT modules + passive network monitor.
Ollama
Start before using [4] Analyze:
ollama serve &
Model in use: gemma2:2b
