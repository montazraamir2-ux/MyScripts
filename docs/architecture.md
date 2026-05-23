# MyScripts Recon Suite — Architecture

## Project Overview

MyScripts is a modular, passive reconnaissance suite built for Python 3 on ARM64 Linux. It is designed to run inside a Proot Ubuntu environment on non-rooted Android devices via Termux. All network connectivity is restricted to TCP connect scans using `socket.create_connection()`; raw sockets, SYN probes, and root-dependent system calls are prohibited.

The suite provides network scanning, DNS enumeration, WHOIS lookup, passive network monitoring, service fingerprinting, banner grabbing, and OSINT username reconnaissance. Every module writes structured findings to a unified NDJSON log (`scan.log`), which is consumed by a report generator and an offline AI analysis component.

---

## Directory Tree

```
MyScripts/
├── main.py                   ← interactive menu and argparse CLI — sole entry point
├── report_generator.py       ← reads scan.log → produces report.html
├── scan.log                  ← unified NDJSON log (auto-generated)
├── report.html               ← HTML scan report (auto-generated)
├── CLAUDE.md                 ← project constraints and architecture reference
├── requirements.txt
├── docs/
│   ├── architecture.md
│   ├── scanner.md
│   ├── dns.md
│   ├── whois.md
│   ├── monitor.md
│   └── osint.md
├── core/
│   ├── logger.py             ← only logging interface — all modules use this
│   ├── analyzer.py           ← Gemma 2B integration via Ollama
│   └── utils.py              ← shared utilities (hostname resolution)
└── modules/
    ├── scanner.py            ← TCP connect network scanner
    ├── banner.py             ← banner grabber (standalone)
    ├── fingerprint.py        ← service fingerprinting — called internally by scanner
    ├── osint_tool.py         ← OSINT username reconnaissance
    ├── dns.py                ← DNS record enumeration
    ├── whois_lookup.py       ← WHOIS domain lookup
    └── monitor.py            ← passive TCP sweep network monitor
```

---

## Data Pipeline

```
main.py  (interactive menu  or  python main.py --module <name> --target <value>)
    │
    ├── modules/scanner.py
    │       scan_host() / scan_network()     [TCP connect() per port]
    │       log_discovered_ip()              [audit trail per open port]
    │       fingerprint_host()              [service label + banner per open port]
    │       log_findings()
    │
    ├── modules/dns.py
    │       _query()  ×6 record types       [dnspython resolver]
    │       log_findings()
    │
    ├── modules/whois_lookup.py
    │       whois.whois()                   [python-whois library]
    │       log_findings()
    │
    ├── modules/monitor.py
    │       _sweep()                        [TCP connect() on 4 probe ports]
    │       log_findings()
    │
    ├── modules/osint_tool.py
    │       check_platform()               [HTTP GET per platform, threaded]
    │       log_profile_found()
    │
    └── modules/banner.py
            grab_banner()                  [TCP connect() + HTTP probe]
            log_banner_grab()
                │
                ▼
          scan.log   (NDJSON — one JSON object per line)
                │
        ┌───────┴────────┐
        ▼                ▼
report_generator.py    core/analyzer.py
→ report.html          → Gemma 2B via Ollama (offline)
```

---

## Module Contract

Every module callable from `main.py` exposes two entry points:

```python
def main() -> None
```

Standalone invocation. Reads arguments from `sys.argv` or prompts interactively via `input()`. Called when the module is executed directly (`python modules/<name>.py`).

```python
def run(...) -> None
```

Menu and CLI invocation. Accepts a `target` parameter and a `session_id` parameter (assigned by `main.py`). Writes all output to `scan.log` via `core.logger` functions. Returns `None`; side effects are the log entry and console output.

All logger functions accept `session_id` as an optional keyword argument with a default of `""`.

---

## Log Entry Formats

All entries are written to `scan.log` as newline-delimited JSON (NDJSON). Two structural variants exist.

### Event Entry

Emitted by audit-trail functions (`log_scan_start`, `log_discovered_ip`, `log_scan_error`, `log_banner_grab`, `log_profile_found`).

```json
{
  "timestamp": "2026-05-23 14:00:00",
  "session_id": "a1b2c3d4",
  "tool": "scanner",
  "level": "INFO",
  "event": "scan_start",
  "data": {
    "target": "192.168.0.1"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `timestamp` | string | Local datetime, format `%Y-%m-%d %H:%M:%S` |
| `session_id` | string | 8-character UUID prefix assigned per `main.py` invocation |
| `tool` | string | Module name emitting the entry |
| `level` | string | `"INFO"` or `"ERROR"` |
| `event` | string | Event identifier (e.g. `scan_start`, `discovered_ip`, `profile_found`) |
| `data` | object | Event-specific key/value payload |

### Findings Entry

Emitted by `log_findings()`. Consumed by `report_generator.py` and `core/analyzer.py`.

```json
{
  "timestamp": "2026-05-23 14:00:05",
  "session_id": "a1b2c3d4",
  "tool": "scanner",
  "findings": [
    {
      "ip": "192.168.0.1",
      "hostname": "router.local",
      "open_ports": [
        {"port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_8.9"},
        {"port": 80, "service": "HTTP", "banner": "HTTP/1.1 200 OK Server: nginx"}
      ]
    }
  ]
}
```

| Field | Type | Description |
|---|---|---|
| `timestamp` | string | Local datetime |
| `session_id` | string | Session identifier |
| `tool` | string | Module name emitting the entry |
| `findings` | array | Module-specific result objects (structure varies per tool) |

The `findings` array structure is defined per module. See the individual module documentation for the schema each tool produces.

---

## AI Role Separation

| Role | Tool | Connectivity | Responsibility |
|---|---|---|---|
| Code authoring and refactoring | Claude Code CLI | Requires internet | Writing, modifying, and reviewing source files |
| Log analysis and scan interpretation | Gemma 2B via Ollama | Fully offline | Reading `scan.log` findings and producing security summaries |

Gemma 2B is served locally via `ollama serve` on `http://localhost:11434`. It must be started manually in the Proot Ubuntu environment before using menu option `[4] Analyze Log`. The model receives a structured plaintext summary of scan findings and returns a brief security analysis with identified concerns and recommended next steps.
