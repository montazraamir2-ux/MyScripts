# OSINT Username Reconnaissance Module

## Description

`modules/osint_tool.py` checks for the existence of a username across ten public platforms by issuing HTTP GET requests. Each platform check runs in its own thread, so all ten requests are dispatched concurrently. Platforms that return a positive result are logged to `scan.log` as event entries and printed to the console.

Detection is HTTP status-code based for nine of the ten platforms. Instagram applies additional filtering: a `200` response is only accepted if the response URL has not redirected to a login page and does not contain `/p/` (which indicates a post rather than a profile).

---

## Usage

### Interactive (via main.py menu)

```
[2] OSINT Username Lookup
Enter target username: johndoe
```

### CLI

```
python main.py --module osint --target johndoe
```

---

## Platforms Checked

| Platform | URL Pattern |
|---|---|
| Instagram | `https://www.instagram.com/<username>/` |
| GitHub | `https://github.com/<username>` |
| Reddit | `https://www.reddit.com/user/<username>` |
| Telegram | `https://t.me/<username>` |
| Steam | `https://steamcommunity.com/id/<username>` |
| DockerHub | `https://hub.docker.com/u/<username>` |
| Pinterest | `https://www.pinterest.com/<username>` |
| Medium | `https://medium.com/@<username>` |
| GitLab | `https://gitlab.com/<username>` |
| Cracked.io | `https://cracked.io/<username>` |

All requests use the following headers:

```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept-Language: en-US,en;q=0.9
```

Redirects are followed (`allow_redirects=True`). The per-request timeout is 5 seconds.

---

## Output Format

### Console

```
============================================================
       EXPANDED OSINT USERNAME RECONNAISSANCE TOOL
============================================================

  Scanning for username: johndoe
------------------------------------------------------------
  [+] FOUND on GitHub       : https://github.com/johndoe
  [+] FOUND on GitLab       : https://gitlab.com/johndoe
  [+] FOUND on DockerHub    : https://hub.docker.com/u/johndoe
------------------------------------------------------------
Expanded OSINT Scan completed successfully.
```

Platforms where the username is not found produce no console output. Network errors are logged silently to `scan.log` and do not appear on the console.

### scan.log — Event Entries

One event entry is written per confirmed positive result:

```json
{
  "timestamp": "2026-05-23 14:05:00",
  "session_id": "a1b2c3d4",
  "tool": "osint",
  "level": "INFO",
  "event": "profile_found",
  "data": {
    "platform": "GitHub",
    "url": "https://github.com/johndoe"
  }
}
```

Network errors during platform checks are written as `scan_error` event entries:

```json
{
  "timestamp": "2026-05-23 14:05:01",
  "session_id": "a1b2c3d4",
  "tool": "osint",
  "level": "ERROR",
  "event": "scan_error",
  "data": {
    "ip": "Telegram",
    "error": "ConnectionError: ..."
  }
}
```

A `scan_start` audit entry is written at the beginning of `run()`. No `log_findings` entry is produced; all results are recorded as individual event entries via `log_profile_found`.

---

## Known Limitations

- Detection relies on HTTP `200` status codes. Some platforms return `200` for non-existent usernames (e.g. a generic "user not found" page), which would produce false positives.
- Instagram detection includes redirect-URL and path-pattern heuristics, but these are brittle and may break if Instagram changes its response structure or introduces new redirect targets.
- All ten platform threads are dispatched simultaneously with no concurrency limit. If the platform list grows significantly, this approach will not scale.
- No retry logic is implemented. Transient network errors cause the check for that platform to be skipped and logged as a `scan_error`.
- The static `User-Agent` header may be blocked or rate-limited by platforms that detect automated requests.
- Cracked.io may be inaccessible in certain regions or network configurations.
- The module has no `main()` standalone entry point with argument parsing; running it directly (`python modules/osint_tool.py`) falls through to the `main()` function which calls `input()` interactively.
