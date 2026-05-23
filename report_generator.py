import json
from pathlib import Path
from datetime import datetime

def _load_log(log_file: str) -> list[dict]:
    try:
        with open(log_file) as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []

def _build_host_rows(entries: list[dict]) -> str:
    rows = ""
    for entry in entries:
        if "findings" not in entry:
            continue
        for host in entry["findings"]:
            ip = host.get("ip", "")
            hostname = host.get("hostname") or "unknown"
            ports = host.get("open_ports", [])
            for p in ports:
                port = p.get("port", "")
                service = p.get("service", "unknown")
                banner = p.get("banner") or "—"
                rows += f"""
                <tr>
                    <td>{ip}</td>
                    <td>{hostname}</td>
                    <td>{port}</td>
                    <td>{service}</td>
                    <td class="banner">{banner}</td>
                </tr>"""
    return rows

def _build_events(entries: list[dict]) -> str:
    rows = ""
    for entry in entries:
        if "event" not in entry:
            continue
        detail = json.dumps(entry.get('data', {})) if entry.get('data') else ''
        rows += f"""
        <tr>
            <td>{entry.get('timestamp', '')}</td>
            <td>{entry.get('event', '')}</td>
            <td>{detail}</td>
        </tr>"""
    return rows

def generate_report(log_file: str) -> str:
    entries = _load_log(log_file)
    session_id = entries[0].get("session_id", "unknown") if entries else "unknown"
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host_rows = _build_host_rows(entries)
    event_rows = _build_events(entries)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MyScripts Report — {session_id}</title>
<style>
    body {{ font-family: monospace; background: #0d0d0d; color: #e0e0e0; padding: 2rem; }}
    h1 {{ color: #00ff88; border-bottom: 1px solid #333; padding-bottom: 0.5rem; }}
    h2 {{ color: #00aaff; margin-top: 2rem; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
    th {{ background: #1a1a2e; color: #00ff88; padding: 0.6rem 1rem; text-align: left; }}
    td {{ padding: 0.5rem 1rem; border-bottom: 1px solid #222; }}
    tr:hover {{ background: #1a1a1a; }}
    .banner {{ color: #aaa; font-size: 0.85em; word-break: break-all; }}
    .meta {{ color: #888; font-size: 0.9em; margin-bottom: 1rem; }}
</style>
</head>
<body>
<h1>MyScripts — Scan Report</h1>
<p class="meta">Session: {session_id} &nbsp;|&nbsp; Generated: {generated_at}</p>

<h2>Discovered Hosts & Services</h2>
<table>
    <thead>
        <tr>
            <th>IP</th><th>Hostname</th><th>Port</th><th>Service</th><th>Banner</th>
        </tr>
    </thead>
    <tbody>{host_rows}</tbody>
</table>

<h2>Scan Events</h2>
<table>
    <thead>
        <tr><th>Timestamp</th><th>Event</th><th>Detail</th></tr>
    </thead>
    <tbody>{event_rows}</tbody>
</table>
</body>
</html>"""

    output_path = Path(log_file).with_suffix(".html")
    with open(output_path, "w") as f:
        f.write(html)

    return str(output_path)
