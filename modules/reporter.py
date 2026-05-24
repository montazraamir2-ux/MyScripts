from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

_LOG_FILE = Path(__file__).parent.parent / "logs" / "myscripts.log"
_REPORT_DIR = Path(__file__).parent.parent / "logs"


@dataclass
class ReportData:
    session_id: str
    generated_at: str
    network_cidr: str
    total_hosts: int
    alive_hosts: int
    services_found: list[dict]
    ai_findings: list[dict]
    risk_summary: dict[str, int]


def load_session(session_id: str) -> ReportData:
    entries: list[dict] = []
    try:
        with _LOG_FILE.open("r") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    data = json.loads(stripped)
                    if data.get("session_id") == session_id:
                        entries.append(data)
                except json.JSONDecodeError as _:
                    pass
    except Exception as _:
        pass

    network_cidr = ""
    total_hosts = 0
    services_found: list[dict] = []
    ai_findings: list[dict] = []

    for entry in entries:
        tool = entry.get("tool", "")
        findings = entry.get("findings", {})
        if tool == "network_info":
            network_cidr = findings.get("cidr", "")
            total_hosts = findings.get("usable_hosts", 0)
        elif tool == "scanner":
            services_found.append(findings)
        elif tool == "ai_analyst":
            ai_findings.append(findings)

    risk_summary: dict[str, int] = {"info": 0, "low": 0, "medium": 0, "high": 0}
    for af in ai_findings:
        level = af.get("risk_level", "info")
        if level in risk_summary:
            risk_summary[level] += 1

    return ReportData(
        session_id=session_id,
        generated_at=datetime.utcnow().isoformat(),
        network_cidr=network_cidr,
        total_hosts=total_hosts,
        alive_hosts=len(services_found),
        services_found=services_found,
        ai_findings=ai_findings,
        risk_summary=risk_summary,
    )


def severity_color(level: str) -> str:
    return {
        "high": "#e74c3c",
        "medium": "#e67e22",
        "low": "#f1c40f",
        "info": "#3498db",
    }.get(level, "#95a5a6")


def _build_host_rows(services_found: list[dict], ai_by_ip: dict[str, dict]) -> str:
    if not services_found:
        return '<tr><td colspan="4" class="empty-cell">No hosts discovered.</td></tr>'
    rows = []
    for sf in services_found:
        ip = html.escape(sf.get("ip", ""))
        ports = html.escape(", ".join(str(p) for p in sf.get("open_ports", [])))
        svc_pairs = [
            f"{html.escape(s.get('service', ''))}:{html.escape(s.get('software', ''))}"
            for s in sf.get("services", [])
            if s.get("service") != "unknown" or s.get("software")
        ]
        services_cell = "<br>".join(svc_pairs) if svc_pairs else "—"
        ai_entry = ai_by_ip.get(sf.get("ip", ""), {})
        risk = ai_entry.get("risk_level", "info") if ai_entry else "info"
        color = severity_color(risk)
        rows.append(
            f"<tr>"
            f"<td>{ip}</td>"
            f"<td>{ports}</td>"
            f"<td>{services_cell}</td>"
            f'<td class="risk-cell" style="background:{color};color:#0d1117">{html.escape(risk)}</td>'
            f"</tr>"
        )
    return "\n    ".join(rows)


def _build_ai_cards(ai_findings: list[dict]) -> str:
    if not ai_findings:
        return '<p class="empty">No AI analysis data for this session.</p>'
    cards = []
    for af in ai_findings:
        ip = html.escape(af.get("ip", ""))
        risk = af.get("risk_level", "info")
        color = severity_color(risk)
        summary = html.escape(af.get("summary", ""))
        flags = af.get("flags", [])
        flag_items = "".join(f"<li>{html.escape(f)}</li>" for f in flags)
        flags_html = f'<ul class="flags">{flag_items}</ul>' if flag_items else ""
        cards.append(
            f'<div class="ai-card">'
            f'<div class="ai-card-header">'
            f'<span class="ai-ip">{ip}</span>'
            f'<span class="risk-badge" style="background:{color}">{html.escape(risk)}</span>'
            f"</div>"
            f'<p class="ai-summary">{summary}</p>'
            f"{flags_html}"
            f"</div>"
        )
    return "\n".join(cards)


def render_html(data: ReportData) -> str:
    total_services = sum(len(sf.get("services", [])) for sf in data.services_found)
    ai_by_ip = {af.get("ip", ""): af for af in data.ai_findings}

    host_rows = _build_host_rows(data.services_found, ai_by_ip)
    ai_section = _build_ai_cards(data.ai_findings)

    high_count = data.risk_summary.get("high", 0)
    medium_count = data.risk_summary.get("medium", 0)

    sid = html.escape(data.session_id)
    cidr = html.escape(data.network_cidr)
    generated = html.escape(data.generated_at)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MyScripts Recon Report — {sid}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;color:#c9d1d9;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;padding:2rem;line-height:1.5}}
h1{{color:#58a6ff;font-size:1.8rem;margin-bottom:.5rem}}
h2{{color:#58a6ff;font-size:1.1rem;margin:2rem 0 .8rem;text-transform:uppercase;letter-spacing:.08em}}
.header{{border-bottom:1px solid #30363d;padding-bottom:1.2rem;margin-bottom:2rem}}
.header p{{color:#8b949e;font-size:.88rem;margin-top:.25rem}}
.header span{{color:#c9d1d9}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:1.2rem 2rem;min-width:130px;text-align:center}}
.num{{display:block;font-size:2.4rem;font-weight:700;color:#58a6ff}}
.card.high .num{{color:#e74c3c}}
.card.medium .num{{color:#e67e22}}
.label{{display:block;font-size:.78rem;color:#8b949e;margin-top:.25rem}}
table{{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:6px;overflow:hidden;margin-bottom:2rem;font-size:.84rem}}
th{{background:#21262d;color:#58a6ff;padding:.65rem 1rem;text-align:left;border-bottom:1px solid #30363d;font-weight:600}}
td{{padding:.55rem 1rem;border-bottom:1px solid #21262d;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#1c2128}}
.risk-cell{{font-weight:700;text-align:center;text-transform:uppercase;font-size:.78rem}}
.empty-cell{{color:#8b949e;text-align:center;padding:1.2rem}}
.ai-card{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:1.2rem 1.4rem;margin-bottom:1rem}}
.ai-card-header{{display:flex;align-items:center;gap:.8rem;margin-bottom:.7rem}}
.ai-ip{{color:#58a6ff;font-weight:700;font-size:.95rem}}
.risk-badge{{color:#0d1117;font-size:.72rem;font-weight:700;padding:.15rem .55rem;border-radius:4px;text-transform:uppercase;letter-spacing:.05em}}
.ai-summary{{font-size:.85rem;color:#c9d1d9;line-height:1.65;margin-bottom:.7rem}}
.flags{{padding-left:1.4rem;color:#8b949e;font-size:.82rem}}
.flags li{{margin-top:.3rem}}
.empty{{color:#8b949e;font-size:.88rem;font-style:italic}}
footer{{border-top:1px solid #30363d;padding-top:1rem;margin-top:2.5rem;color:#8b949e;font-size:.78rem;text-align:center}}
</style>
</head>
<body>

<div class="header">
  <h1>MyScripts Recon Report</h1>
  <p>Session: <span>{sid}</span></p>
  <p>Generated: <span>{generated}</span></p>
  <p>Network: <span>{cidr}</span></p>
</div>

<div class="cards">
  <div class="card">
    <span class="num">{data.alive_hosts}</span>
    <span class="label">Hosts Alive</span>
  </div>
  <div class="card">
    <span class="num">{total_services}</span>
    <span class="label">Services Found</span>
  </div>
  <div class="card high">
    <span class="num">{high_count}</span>
    <span class="label">Risk: High</span>
  </div>
  <div class="card medium">
    <span class="num">{medium_count}</span>
    <span class="label">Risk: Medium</span>
  </div>
</div>

<h2>Host Results</h2>
<table>
  <thead>
    <tr>
      <th>IP</th>
      <th>Open Ports</th>
      <th>Services</th>
      <th>Risk Level</th>
    </tr>
  </thead>
  <tbody>
    {host_rows}
  </tbody>
</table>

<h2>AI Analysis</h2>
{ai_section}

<footer>Generated by MyScripts | Offline AI: Gemma 2B | {generated}</footer>

</body>
</html>"""


def generate_report(session_id: str) -> Path:
    safe_id = "".join(c for c in session_id if c.isalnum())
    data = load_session(safe_id)
    html_content = render_html(data)
    _REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = _REPORT_DIR / f"report_{safe_id}.html"
    out_path.write_text(html_content, encoding="utf-8")
    return out_path
