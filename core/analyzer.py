import json
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "gemma2:2b"

def _is_ollama_running() -> bool:
    try:
        urllib.request.urlopen("http://localhost:11434", timeout=3)
        return True
    except Exception:
        return False

def _build_summary(findings: list[dict]) -> str:
    lines = []
    for entry in findings:
        for host in entry.get("findings", []):
            ip = host.get("ip", "")
            hostname = host.get("hostname") or "unknown"
            ports = host.get("open_ports", [])
            port_list = ", ".join(
                f"{p['port']}({p.get('service','?')})" for p in ports
            )
            lines.append(f"Host: {ip} ({hostname}) | Open ports: {port_list}")
    return "\n".join(lines)

def _query_gemma(prompt: str) -> str:
    payload = json.dumps({
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }).encode()

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=300) as resp:
        data = json.loads(resp.read().decode())
        return data.get("response", "").strip()

def analyze_log(log_file: str) -> str:
    if not _is_ollama_running():
        return "[!] Ollama is not running. Start it in Proot Ubuntu with: ollama serve"

    entries = []
    with open(log_file) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    findings = [e for e in entries if "findings" in e]

    if not findings:
        return "[!] No scan findings found in log file."

    summary = _build_summary(findings)
    prompt = f"You are a network security analyst. Analyze this scan result briefly:\n\n{summary}\n\nProvide: 1) Summary 2) Security concerns 3) Next steps. Be concise."

    return _query_gemma(prompt)
