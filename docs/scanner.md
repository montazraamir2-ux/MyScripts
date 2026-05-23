# Scanner Module

## Description

`modules/scanner.py` is a TCP connect port scanner. It probes individual IPv4 hosts or entire subnets expressed in CIDR notation for open TCP ports using `socket.create_connection()`. No raw sockets, ICMP probes, or SYN packets are used.

After identifying open ports on a host, the module invokes `modules/fingerprint.py` to attempt service label assignment and banner retrieval for each open port. Final results are written to `scan.log` as a findings entry and printed to the console.

---

## Usage

### Interactive (via main.py menu)

```
[1] Network Scanner
Enter target IP or CIDR: 192.168.0.1
```

```
[1] Network Scanner
Enter target IP or CIDR: 192.168.0.0/24
```

### CLI

```
python main.py --module scanner --target 192.168.0.1
python main.py --module scanner --target 192.168.0.0/24
```

### Standalone

```
python modules/scanner.py 192.168.0.1
python modules/scanner.py 192.168.0.1 22,80,443
python modules/scanner.py 10.0.0.0/24
```

When run standalone, the second positional argument is a comma-separated list of ports. Fingerprinting is not performed in standalone mode; only raw open port lists are printed.

---

## Input Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `target` | string | — | IPv4 address or CIDR range (e.g. `192.168.0.1`, `10.0.0.0/24`) |
| `ports` | list[int] | `[21,22,23,25,53,80,443,8080,8443]` | TCP ports to probe |
| `timeout` | float | `1.0` | Per-port connection timeout in seconds |
| `session_id` | string | `""` | Session UUID prefix assigned by `main.py` |

The default port list covers FTP, SSH, Telnet, SMTP, DNS, HTTP, HTTPS, HTTP-Alt, and HTTPS-Alt.

---

## Output Format

### Console

```
  192.168.0.1: [22, 80, 443]
  192.168.0.5: [22]
```

Each line shows the host IP and the list of open port numbers found.

### scan.log — Findings Entry

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
        {"port": 80, "service": "HTTP", "banner": "HTTP/1.1 200 OK Server: nginx"},
        {"port": 443, "service": "HTTPS", "banner": null}
      ]
    }
  ]
}
```

One findings entry is written per `run()` invocation, covering all discovered hosts. If no hosts have open ports, no findings entry is written.

### scan.log — Audit Trail (Event Entries)

The scanner emits the following event entries during execution:

| Event | Trigger |
|---|---|
| `scan_start` | Once at the beginning of `run()` |
| `discovered_ip` | Once per open port discovered |
| `scan_error` | On `OSError` during a connection attempt |

---

## Known Limitations

- Only TCP ports are scanned. UDP services are not detectable.
- The default port list covers 9 ports. Services on non-standard ports are missed unless the port list is specified explicitly via the standalone CLI.
- Fingerprinting uses a static port-to-service map (`SERVICE_MAP` in `fingerprint.py`). Services running on non-standard ports are labelled `"unknown"`.
- CIDR ranges of `/31` and `/32` produce no hosts via `ipaddress.ip_network(...).hosts()` and will return empty results.
- `MAX_WORKERS = 100` concurrent threads are used for subnet scans. On memory-constrained Proot/Android environments, large subnets may cause resource pressure.
- Banner retrieval has its own 2-second timeout (`fingerprint.py` `TIMEOUT`). Services that do not respond to the probe strategy for their port number return `banner: null`.
- The interactive menu does not expose `timeout` or `ports` as configurable parameters; defaults are used for all interactive invocations.
