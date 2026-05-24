from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "gemma2:2b"
TIMEOUT = 90


@dataclass
class AnalysisResult:
    session_id: str
    target_ip: str
    risk_level: str
    summary: str
    flags: list[str]
    raw_response: str


def build_prompt(ip: str, services: list[dict]) -> str:
    lines: list[str] = []
    for svc in services:
        port = svc.get("port", "?")
        protocol = svc.get("protocol", "TCP")
        service = svc.get("service", "unknown")
        software = svc.get("software", "")
        version = svc.get("version", "")
        parts = [str(port), "/", protocol, " ", service]
        if software:
            parts += [" ", software]
        if version:
            parts += [" ", version]
        lines.append("".join(parts))
    services_block = "\n".join(lines) if lines else "none"
    return (
        "You are a network security analyst. Analyze the following scan result"
        " and respond in this exact JSON format only, no markdown, no explanation:\n"
        "{\n"
        '  "risk_level": "info|low|medium|high",\n'
        '  "summary": "one paragraph assessment",\n'
        '  "flags": ["flag1", "flag2"]\n'
        "}\n\n"
        f"Target IP: {ip}\n"
        f"Discovered services:\n{services_block}\n\n"
        "Assess risk based on: exposed services, known vulnerable software,"
        " unusual port combinations, and weak protocols like Telnet, FTP, VNC."
    )


def query_ollama(prompt: str) -> str:
    try:
        payload = json.dumps(
            {"model": MODEL, "prompt": prompt, "stream": False}
        ).encode()
        req = urllib.request.Request(
            OLLAMA_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
            return data.get("response", "")
    except Exception as _:
        return ""


def parse_response(raw: str) -> dict:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        end = len(lines)
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].strip() == "```":
                end = i
                break
        text = "\n".join(lines[1:end])
    try:
        return json.loads(text)
    except Exception as _:
        return {"risk_level": "info", "summary": "", "flags": []}


def analyse_host(
    session_id: str,
    ip: str,
    services: list[dict],
) -> AnalysisResult:
    prompt = build_prompt(ip, services)
    raw = query_ollama(prompt)
    if not raw:
        return AnalysisResult(
            session_id=session_id,
            target_ip=ip,
            risk_level="info",
            summary="ollama unavailable",
            flags=[],
            raw_response="",
        )
    parsed = parse_response(raw)
    return AnalysisResult(
        session_id=session_id,
        target_ip=ip,
        risk_level=parsed.get("risk_level", "info"),
        summary=parsed.get("summary", ""),
        flags=parsed.get("flags", []),
        raw_response=raw,
    )


def to_log_findings(result: AnalysisResult) -> dict:
    return {
        "ip": result.target_ip,
        "risk_level": result.risk_level,
        "summary": result.summary,
        "flags": result.flags,
    }
