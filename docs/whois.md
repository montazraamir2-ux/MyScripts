# WHOIS Lookup Module

## Description

`modules/whois_lookup.py` queries the public WHOIS database for a domain using the `python-whois` library. It extracts seven registration metadata fields, omits any that are null or absent, prints the populated fields to the console, and writes a findings entry to `scan.log`.

The module operates on domain names only. IP address WHOIS lookups are not supported.

---

## Usage

### Interactive (via main.py menu)

```
[7] WHOIS Lookup
Enter domain (e.g. example.com): example.com
```

### CLI

```
python main.py --module whois --target example.com
```

---

## Fields Extracted

| Field | Description |
|---|---|
| `registrar` | Organization responsible for domain registration |
| `creation_date` | Date the domain was first registered |
| `expiration_date` | Date the domain registration expires |
| `name_servers` | Set of authoritative DNS nameservers |
| `emails` | Contact or abuse email addresses present in the WHOIS record |
| `org` | Registrant organization name |
| `country` | Registrant country code |

Fields whose value is `None`, an empty string, or the literal string `"None"` are excluded from both the console output and the log entry.

All field values are passed through `str()` before storage. Python `datetime` objects and lists returned by `python-whois` are converted to their string representations.

---

## Output Format

### Console

```
[WHOIS] Looking up example.com
  [REGISTRAR] ICANN
  [CREATION_DATE] 1995-08-14 04:00:00
  [EXPIRATION_DATE] 2025-08-13 04:00:00
  [NAME_SERVERS] {'a.iana-servers.net', 'b.iana-servers.net'}
  [ORG] Internet Assigned Numbers Authority
  [COUNTRY] US

  [+] WHOIS data logged.
```

If the WHOIS query fails:

```
[WHOIS] Looking up example.com
  [!] WHOIS failed: <error message>
```

On failure, no findings entry is written to `scan.log`.

### scan.log — Findings Entry

```json
{
  "timestamp": "2026-05-23 14:02:00",
  "session_id": "a1b2c3d4",
  "tool": "whois",
  "findings": [
    {
      "target": "example.com",
      "whois": {
        "registrar": "ICANN",
        "creation_date": "1995-08-14 04:00:00",
        "expiration_date": "2025-08-13 04:00:00",
        "name_servers": "{'a.iana-servers.net', 'b.iana-servers.net'}",
        "org": "Internet Assigned Numbers Authority",
        "country": "US"
      }
    }
  ]
}
```

The `whois` object contains only the fields that had non-null values after cleaning.

---

## Known Limitations

- Requires internet access and reachability of the authoritative WHOIS server for the queried TLD.
- Many registrars redact personal contact fields under GDPR/RDAP policies. The `emails`, `org`, and `country` fields are frequently absent for domains registered after 2018.
- `creation_date` and `expiration_date` may be returned as a single `datetime`, a list of `datetime` objects, or a string depending on the registrar's WHOIS format. The `str()` conversion applied by the module preserves this variance in the log entry.
- `name_servers` is serialized as a Python `set` string literal (e.g. `"{'a.iana-servers.net', 'b.iana-servers.net'}"`) rather than a JSON array because `python-whois` returns it as a set. Downstream consumers that parse this field should account for this format.
- IP address WHOIS lookups are not supported. Passing an IP address may produce unpredictable results or an exception.
- Rate limiting by WHOIS servers can cause failures when multiple lookups are performed in rapid succession.
- No event-level audit entries are emitted by this module; only the `log_findings` call is made.
