# Network Monitor Module

## Description

`modules/monitor.py` is a passive network change detection module. It performs repeated TCP connect sweeps across a /24 subnet and compares each sweep result to the previous one, reporting hosts that newly appear or disappear between intervals. Change events are written to `scan.log` as a findings entry at the end of the monitoring session.

The module runs for a fixed duration of 60 seconds, issuing an initial sweep followed by additional sweeps at 20-second intervals (three total sweeps). It can be interrupted early with `Ctrl+C`.

---

## Usage

### Interactive (via main.py menu)

```
[8] Network Monitor
Enter subnet prefix (e.g. 192.168.0): 192.168.1
```

The subnet prefix is the first three octets of the /24 range to monitor (e.g. `192.168.1` monitors `192.168.1.1`–`192.168.1.254`).

### CLI

```
python main.py --module monitor --subnet 192.168.1
python main.py --module monitor --target 192.168.1
```

Both `--subnet` and `--target` are accepted; `--subnet` takes precedence. If neither is provided, the default subnet `192.168.0` is used.

---

## Detection Method (TCP Connect Sweep)

For each host address `<subnet>.1` through `<subnet>.254`, the module attempts `socket.create_connection()` on each of four probe ports in order: `22`, `80`, `443`, `8080`. The connection timeout per attempt is `1.0` second.

A host is classified as **alive** if any single probe connection succeeds. The remaining probe ports for that host are not attempted once a successful connection is established. Up to 100 concurrent threads are used per sweep via `ThreadPoolExecutor`.

The initial sweep result is used as the baseline. Subsequent sweeps compare their alive set against the previous sweep's alive set:

- Hosts present in the current sweep but absent from the previous sweep are recorded as `new_host` events.
- Hosts present in the previous sweep but absent from the current sweep are recorded as `host_gone` events.

---

## Output Format

### Console

```
[MONITOR] TCP sweep monitor on 192.168.1.0/24
  Duration: 60s | Sweep every: 20s
  Press Ctrl+C to stop early.

  [*] Initial sweep...
  [*] 3 active host(s) found: ['192.168.1.1', '192.168.1.5', '192.168.1.10']

  [*] Sweeping... (20s)
  [NEW]  192.168.1.20 | android-b7c3d1f2.local
  [GONE] 192.168.1.5

  [*] Sweeping... (40s)

  [*] Sweeping... (60s)

  [+] 2 network events logged.
```

If no changes are detected across all sweeps:

```
  [!] No network changes detected.
```

When stopped with `Ctrl+C`, any events accumulated up to that point are logged.

### scan.log — Findings Entry

```json
{
  "timestamp": "2026-05-23 14:10:00",
  "session_id": "a1b2c3d4",
  "tool": "monitor",
  "findings": [
    {
      "event": "new_host",
      "ip": "192.168.1.20",
      "hostname": "android-b7c3d1f2.local"
    },
    {
      "event": "host_gone",
      "ip": "192.168.1.5"
    }
  ]
}
```

| Field | Present on | Description |
|---|---|---|
| `event` | all entries | `"new_host"` or `"host_gone"` |
| `ip` | all entries | IP address of the affected host |
| `hostname` | `new_host` only | Reverse-resolved hostname, or `"unknown"` if resolution fails |

One findings entry is written per session, containing all change events observed across all sweeps. If there are no change events, no findings entry is written.

---

## Known Limitations

- The subnet is always treated as a /24. The module sweeps `.1`–`.254` within the given prefix regardless of the actual network mask.
- Only four TCP ports (`22, 80, 443, 8080`) are probed. Hosts that expose no services on these ports will be reported as offline regardless of actual network presence.
- Monitoring duration (60 seconds) and sweep interval (20 seconds) are hardcoded constants. They are not configurable via the menu or CLI without modifying the source.
- The initial baseline sweep result is not written to `scan.log`; only delta events (changes from one sweep to the next) are logged.
- `host_gone` entries do not include a `hostname` field. Hostname resolution is only performed for newly discovered hosts.
- Each sweep takes a variable amount of time depending on network conditions and the number of non-responsive hosts (which must time out). For a full /24 with all 254 hosts unresponsive, a sweep may take close to 1 second (the timeout) regardless of thread count.
- No event-level audit entries are emitted by this module; only the `log_findings` call is made.
