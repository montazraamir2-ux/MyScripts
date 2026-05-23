# DNS Enumeration Module

## Description

`modules/dns.py` enumerates DNS records for a given domain using the `dnspython` library (`dns.resolver`). It queries six standard record types in sequence and collects all responses. Records that resolve successfully are printed to the console and written to `scan.log` as a findings entry. Record types that return no results are silently omitted.

The module performs passive enumeration only. It does not attempt zone transfers, subdomain brute-forcing, or recursive resolution beyond what the system resolver provides.

---

## Usage

### Interactive (via main.py menu)

```
[6] DNS Enumeration
Enter domain (e.g. example.com): example.com
```

### CLI

```
python main.py --module dns --target example.com
```

---

## Record Types Queried

| Type | Description |
|---|---|
| `A` | IPv4 address records |
| `AAAA` | IPv6 address records |
| `MX` | Mail exchange records (includes priority) |
| `NS` | Authoritative nameserver records |
| `TXT` | Text records (SPF, DKIM, verification tokens, etc.) |
| `CNAME` | Canonical name alias records |

Queries are issued in the order listed above. Each query uses a 5-second lifetime (`lifetime=5` passed to `dns.resolver.resolve()`).

---

## Output Format

### Console

```
[DNS] Enumerating records for example.com
  [A] 93.184.216.34
  [AAAA] 2606:2800:21f:cb07:6820:80da:af6b:8b2c
  [NS] a.iana-servers.net.
  [NS] b.iana-servers.net.
  [TXT] "v=spf1 -all"

  [+] 5 records found. Logged.
```

If no record types return results:

```
  [!] No DNS records found.
```

### scan.log — Findings Entry

```json
{
  "timestamp": "2026-05-23 14:01:00",
  "session_id": "a1b2c3d4",
  "tool": "dns",
  "findings": [
    {
      "target": "example.com",
      "dns_records": {
        "A": ["93.184.216.34"],
        "AAAA": ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
        "NS": ["a.iana-servers.net.", "b.iana-servers.net."],
        "TXT": ["\"v=spf1 -all\""]
      }
    }
  ]
}
```

The `dns_records` object contains only the record types that returned at least one result. Each key maps to a list of strings as returned by `dnspython`'s `str(r)` representation.

---

## Known Limitations

- Uses the system-configured DNS resolver. In offline or DNS-restricted environments, all queries will fail silently and report no records found.
- No subdomain enumeration or zone transfer (`AXFR`) attempts are made.
- `CNAME` resolution returns the alias target (the right-hand side of the CNAME record), not the resolved `A` record of the canonical name.
- Each query has a 5-second lifetime. Slow or unresponsive resolvers will produce empty results for affected record types rather than raising an error.
- `PTR` reverse DNS lookups are not supported.
- Results are not deduplicated across query types; if a name appears in multiple record types it will appear in each.
- No event-level audit entries (`log_scan_start`, etc.) are emitted by this module; only the `log_findings` call is made.
