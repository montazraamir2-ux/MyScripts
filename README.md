# MyScripts — Reconnaissance & OSINT Suite

## Overview

MyScripts is a modular Python 3 reconnaissance and OSINT suite engineered to run inside a non-rooted Proot Ubuntu environment on Termux (ARM64 Android). It provides network scanning, DNS enumeration, WHOIS lookup, service banner grabbing, username OSINT across major platforms, and passive network monitoring — all without root privileges. Every network operation uses TCP connect() exclusively, making the suite portable and compliant with the strict constraints of a non-privileged mobile environment. What distinguishes MyScripts is its unified NDJSON logging pipeline, which feeds both a self-contained HTML report generator and an offline Gemma 2B analysis engine via Ollama, enabling structured interpretation of scan results without any cloud dependency.

---

## Features

| Module | Capability | Method |
|---|---|---|
| scanner | TCP port scanning of single IPs and CIDR ranges with concurrent threading | TCP connect() via ThreadPoolExecutor (100 threads) |
| dns | DNS record enumeration — A, MX, NS, TXT, CNAME | dnspython resolver queries |
| whois | Domain registration and ownership lookup | python-whois registry queries |
| osint | Username reconnaissance across 10+ social platforms with false-positive filtering | Concurrent HTTP requests, one thread per platform |
| banner | Service banner grabbing on any discovered open port | Raw TCP socket with HTTP GET probe |
| monitor | Passive subnet host discovery and periodic availability monitoring | Recurring TCP connect() sweeps across a /24 subnet |

---

## Installation

Requirements: Python 3, pip3, Proot Ubuntu running inside Termux on an Android device.

```bash
git clone https://github.com/montazraamir2-ux/MyScripts
cd MyScripts
pip3 install -r requirements.txt --break-system-packages
python3 main.py
```

To enable offline AI log analysis, install and start Ollama with the Gemma 2B model before using the Analyze option:

```bash
ollama pull gemma2:2b
ollama serve &
```

---

## Usage

### Interactive Menu

```bash
python3 main.py
```

Launches the numbered menu. Each option prompts for the required input inline.

### CLI

```bash
python3 main.py --module scanner --target 192.168.0.1
python3 main.py --module dns --target example.com
python3 main.py --module whois --target example.com
python3 main.py --module osint --target username
python3 main.py --module monitor --subnet 192.168.0
python3 main.py --report
python3 main.py --analyze
```

`--report` generates `report.html` from the current `scan.log`. `--analyze` passes the log to Gemma 2B via Ollama for offline interpretation.

---

## Architecture

All modules write structured findings to a shared `scan.log` in NDJSON format. The report generator and AI analyzer consume this log independently, keeping every output stage decoupled from the scan runtime. Session IDs tie related log entries together across a full scan run. For a detailed breakdown of module contracts, log entry schemas, and the data pipeline, see [docs/architecture.md](docs/architecture.md).

---

## Environment

| Property | Value |
|---|---|
| Platform | Termux / Proot Ubuntu / Android |
| Architecture | ARM64 (aarch64) |
| Root Required | No |
| Python | Python 3 |
| AI Engine | Gemma 2B via Ollama (fully offline) |

---

## Legal & Ethics

MyScripts is intended exclusively for authorized security testing, research, and education. Run network scans only against systems you own or have explicit written permission to test. OSINT modules query publicly available information only — never use them to target individuals without lawful authorization. The author assumes no liability for misuse. Unauthorized use against third-party systems is illegal and unethical.

---

Maintained by [Montazar](https://www.linkedin.com/in/montazar-amer-06743b38a) — Cybersecurity Engineering Student | Offensive Security & OSCP Track
