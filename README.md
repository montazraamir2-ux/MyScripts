# MyScripts

A collection of Python network and OSINT tools with unified logging to `scan.log`.

## Tools

### `scanner.py` — Network Port Scanner
Multithreaded TCP port scanner for single hosts or entire CIDR ranges.

**Usage:**
```bash
python scanner.py 192.168.1.1               # single host, default ports
python scanner.py 192.168.1.1 22,80,443     # single host, custom ports
python scanner.py 192.168.1.0/24            # full network range
```

**Default ports:** `21, 22, 23, 25, 53, 80, 443, 8080, 8443`

---

### `banner.py` — Banner Grabber
Connects to a target IP and port via raw TCP, sends an HTTP GET request, and prints the server response (banner).

Configure the target inside the script:
```python
target_ip = "192.168.0.1"
target_port = 80
```

**Usage:**
```bash
python banner.py
```

---

### `osint_tool.py` — Username Reconnaissance
Checks a username across 10 platforms concurrently using threads.

**Platforms checked:** Instagram, GitHub, Reddit, Telegram, Steam, DockerHub, Pinterest, Medium, GitLab, Cracked.io

**Usage:**
```bash
python osint_tool.py
# Enter target username to scan: johndoe
```

---

### `scan_logger.py` — Shared Logging Module
Central logging module used by all three tools. Writes timestamped entries to `scan.log`.

| Function | Description |
|---|---|
| `log_scan_start(tool, target)` | Logged when a scan begins |
| `log_discovered_ip(ip, port)` | Logged when an open port is found |
| `log_banner_grab(ip, port, banner)` | Logged when a banner is grabbed |
| `log_profile_found(platform, url)` | Logged when a username profile is found |
| `log_scan_error(error, ip)` | Logged on connection or scan errors |

**Log format:**
```
2026-05-19 00:37:20 [INFO]  [osint] Scan started — target: johndoe
2026-05-19 00:37:21 [INFO]  Profile found — GitHub: https://github.com/johndoe
2026-05-19 00:37:21 [ERROR] Scan error on Cracked.io: Failed to resolve hostname
```

---

## Requirements

```bash
pip install requests
```

## Notes

- All tools write to a shared `scan.log` in the working directory.
- Run scripts from within the `MyScripts/` directory so `scan_logger` is importable.
