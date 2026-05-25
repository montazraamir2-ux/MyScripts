# MyScripts

Modular reconnaissance and OSINT suite built for non-rooted Termux/Proot Ubuntu on ARM64 Android. Performs host discovery and service fingerprinting via TCP connect() scanning, pipes results through a locally-hosted Gemma 2B model via Ollama for offline AI risk analysis, and produces self-contained HTML reports — the entire pipeline runs without internet access after initial setup.

---

## Environment

| Property     | Value                          |
|--------------|--------------------------------|
| Platform     | Android (non-rooted)           |
| Runtime      | Proot Ubuntu inside Termux     |
| Architecture | ARM64 (aarch64)                |
| Python       | 3.x (stdlib + netifaces)       |
| Local AI     | Ollama + Gemma 2B              |
| Scan Method  | TCP connect() — no Raw Sockets |

---

## Installation

**1. Install Termux from F-Droid** (not the Play Store build).

**2. Install Proot Ubuntu and core tools inside Termux:**

```sh
pkg install proot-distro git python
```

**3. Install and enter the Ubuntu environment:**

```sh
proot-distro install ubuntu
proot-distro login ubuntu
```

**4. Inside Proot Ubuntu, install Python and pip:**

```sh
apt install python3 python3-pip git
```

**5. Install Python dependencies:**

```sh
pip install netifaces watchdog
```

**6. Clone the repository:**

```sh
git clone <repo-url>
cd MyScripts
```

**7. Install Ollama for ARM64:**

```sh
curl -fsSL https://ollama.com/install.sh | sh
```

**8. Pull the Gemma 2B model:**

```sh
ollama pull gemma2:2b
```

Before any run that includes AI analysis, start the Ollama server:

```sh
ollama serve &
```

---

## Usage

### CLI Mode

| Flag               | Description                                 |
|--------------------|---------------------------------------------|
| `--scan`           | Run full recon pipeline                     |
| `--cidr CIDR`      | Target network (auto-detect if omitted)     |
| `--ports PORT ...` | Custom port list (space-separated)          |
| `--no-ai`          | Skip AI analysis                            |
| `--no-report`      | Skip HTML report generation                 |
| `--report`         | Generate report from last session           |
| `--session ID`     | Specify session ID for report               |
| `--info`           | Display local network info                  |

Display local network information without scanning:

```sh
python3 main.py --info
```

Run a full scan with auto-detected network:

```sh
python3 main.py --scan
```

Scan a specific CIDR block:

```sh
python3 main.py --scan --cidr 192.168.1.0/24
```

Scan specific ports only, skip AI analysis:

```sh
python3 main.py --scan --ports 22 80 443 --no-ai
```

Regenerate the HTML report from the most recent session:

```sh
python3 main.py --report
```

Regenerate a report for a specific session:

```sh
python3 main.py --report --session abc123f
```

### Interactive Mode

```sh
python3 main.py
```

| Option | Action                                               |
|--------|------------------------------------------------------|
| `1`    | Full scan using auto-detected network CIDR           |
| `2`    | Prompt for a CIDR, then run full pipeline            |
| `3`    | Display local network info (equivalent to `--info`)  |
| `4`    | Generate HTML report from the last session           |
| `5`    | Exit                                                 |

---

## Demo Output

### Full Scan Pipeline

```
  Session: a9df8943 | Network: 192.168.0.0/24
  Scanning 192.168.0.0/24 ...
  [ALIVE] 192.168.0.1 | Ports: 22, 80
  [SERVICE] 192.168.0.1:80 — HTTP | unknown
  [SERVICE] 192.168.0.1:22 — SSH | Dropbear 2.0
  Scan complete — 1 host(s) found.
  [REPORT] /root/MyScripts/logs/report_a9df8943.html
```

### OSINT Lookup

```
  [OSINT] Target: 8.8.8.8 (ip)
  [OSINT] Organisation: Google LLC
  [OSINT] Country: US
  [OSINT] DNS A Records: []
  [OSINT] MX Present: no
  [DNS] PTR: dns.google
  [OSINT] Reputation: Google LLC
  [OSINT] Summary: Target 8.8.8.8 is registered to Google LLC in US. No MX records detected. Shodan data unavailable — no API key provided. IP flagged as hosting/datacenter.
```

### Session History

```
ID        Name              Date              Hosts  High  Med
──────────────────────────────────────────────────────────────
c63b8d99  unnamed           2026-05-25 00:40  0      0     0
4ceacb8c  unnamed           2026-05-25 00:40  0      0     0
a9df8943  portfolio_demo    2026-05-25 00:39  1      0     0
8a56043c  unnamed           2026-05-25 00:39  0      0     0
cca14d8b  unnamed           2026-05-25 00:15  0      0     0
888530aa  unnamed           2026-05-25 00:15  0      0     0
d72eed9d  unnamed           2026-05-25 00:15  0      0     0
25fe313b  unnamed           2026-05-25 00:14  0      0     0
218365c0  portfolio_demo    2026-05-25 00:13  1      0     1
fd43bc6a  unnamed           2026-05-25 00:11  0      0     0
741699dc  demo_final        2026-05-25 00:09  1      1     0
38a763cd  demo_final        2026-05-25 00:03  1      0     1
04c99a2d  unnamed           2026-05-24 23:59  0      0     0
4db978ef  unnamed           2026-05-24 23:58  0      0     0
3f3b9ee3  unnamed           2026-05-24 23:57  0      0     0
114d51fa  home_network_dem  2026-05-24 23:55  1      0     1
339b26eb  unnamed           2026-05-24 23:48  0      0     0
1e8e51a9  unnamed           2026-05-24 23:47  0      0     0
27605688  unnamed           2026-05-24 23:46  0      0     0
cf5408fd  unnamed           2026-05-24 23:46  0      0     0
```

### Passive Monitor

```
[MONITOR] Watching: 192.168.0.0/28
[MONITOR] Interval: 10s
[MONITOR] Press Ctrl+C to stop.
[MONITOR] Baseline: 1 devices detected.
[MONITOR] Cycle 1 complete.
[MONITOR] Cycle 2 complete.
[MONITOR] Cycle 3 complete.
[MONITOR] Cycle 4 complete.
[MONITOR] Stopped after 4 scans.
```

### HTML Report

A self-contained HTML report is available at
`demo/demo_report.html` — open it in any browser
to view the full interactive report including
AI analysis and risk classification.

---

## Module Reference

| Module            | Role                                      |
|-------------------|-------------------------------------------|
| `network_info.py` | Local IP, interface, and CIDR detection   |
| `logger.py`       | Unified NDJSON log writer and session ID  |
| `scanner.py`      | TCP connect() host and port scanner       |
| `fingerprint.py`  | Banner-based service identification       |
| `ai_analyst.py`   | Offline AI risk analysis via Ollama       |
| `reporter.py`     | HTML report generation from session log   |

---

## Log Format

All events are written to `logs/myscripts.log` as newline-delimited JSON (NDJSON) — one JSON object per line. The file is directly parseable by `jq`, Python's `json` module, or any line-oriented tool.

Each entry follows this structure:

```json
{
  "timestamp": "2024-11-14T08:32:11.045821",
  "session_id": "a3f7c91b",
  "tool": "scanner",
  "target": "192.168.0.42",
  "severity": "info",
  "findings": {
    "ip": "192.168.0.42",
    "open_ports": [22, 80, 443],
    "banners": {
      "22": "SSH-2.0-OpenSSH_8.9p1"
    },
    "scan_duration_ms": 312.5,
    "services": [
      {
        "port": 22,
        "protocol": "TCP",
        "service": "SSH",
        "software": "OpenSSH",
        "version": "8.9p1",
        "raw_banner": "SSH-2.0-OpenSSH_8.9p1"
      }
    ]
  }
}
```

The `tool` field identifies the originating module. The `severity` field mirrors the AI risk level for `ai_analyst` entries and is `"info"` for all other entry types.

---

## Output

### Terminal

```
  Session: a3f7c91b | Network: 192.168.0.0/24
  Scanning 192.168.0.0/24 ...
  [ALIVE] 192.168.0.1 | Ports: 22, 80, 443
  [SERVICE] 192.168.0.1:22 — SSH | OpenSSH 8.9p1
  [SERVICE] 192.168.0.1:80 — HTTP | nginx 1.24.0
  [ALIVE] 192.168.0.42 | Ports: 21, 23
  [SERVICE] 192.168.0.42:23 — unknown |
  Scan complete — 2 host(s) found.
  [AI] 192.168.0.1 | Risk: low
  [AI] Summary: Host exposes SSH and HTTP. Both services are current versions with no immediately known CVEs.
  [AI] 192.168.0.42 | Risk: high
  [AI] Summary: Telnet and FTP are active. These protocols transmit credentials in plaintext.
  [FLAG] Telnet service detected — unencrypted remote access
  [FLAG] FTP service detected — plaintext credential exposure
  [REPORT] /root/MyScripts/logs/report_a3f7c91b.html
```

### Log File

```
logs/myscripts.log
```

One JSON object per line. Entries accumulate across sessions; filter by `session_id` to isolate a single run.

### HTML Report

```
logs/report_<session_id>.html
```

Self-contained single file — no external assets, no CDN links, no JavaScript dependencies. Sections:

- **Summary cards** — hosts alive, total services found, high-risk count, medium-risk count.
- **Host results table** — IP, open ports, identified services, and AI-assigned risk level per host.
- **AI analysis cards** — per-host risk badge, summary paragraph, and flagged findings list.

---

## Architecture

```
network_info
     |
     v
  scanner -------> fingerprint
     |                  |
     |<-----------------+
     |
     v
 ai_analyst
     |
     v
  reporter
     |
     v
 HTML Report
```

On startup, `network_info` detects the local interface and derives the CIDR. `scanner` performs concurrent TCP connect() scans across all hosts in the subnet and, for each open port, passes the raw banner to `fingerprint` for service identification. The combined host results are written to the session log by `logger`. If AI analysis is enabled, each host with identified services is sent to `ai_analyst`, which builds a structured prompt and queries the local Ollama instance; parsed results are logged as `ai_analyst` entries. `reporter` then reads all session entries from the log and renders the HTML report.

---

## Constraints & Design Decisions

| Constraint       | Decision                                               |
|------------------|--------------------------------------------------------|
| No root          | TCP connect() replaces raw sockets and SYN scans       |
| ARM64            | Python-native implementation, no compiled binary deps  |
| Offline-first    | Ollama runs locally — no cloud AI, no API keys         |
| Resource-limited | `ThreadPoolExecutor` with bounded workers; 90s AI timeout |

---

## Ethical Scope

This tool is designed for authorized penetration testing and personal network environments only. OSINT modules operate exclusively on publicly available information.

---

## License

MIT
