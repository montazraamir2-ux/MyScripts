from __future__ import annotations

import dataclasses
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from modules.session_manager import register_session as _register_session

SESSION_ID: str = uuid.uuid4().hex[:8]
_register_session(SESSION_ID)

_LOG_FILE = Path(__file__).parent.parent / "logs" / "myscripts.log"


@dataclass
class LogEntry:
    timestamp: str
    session_id: str
    tool: str
    target: str
    severity: str
    findings: dict


def make_entry(tool: str, target: str, severity: str, findings: dict) -> LogEntry:
    return LogEntry(
        timestamp=datetime.utcnow().isoformat(),
        session_id=SESSION_ID,
        tool=tool,
        target=target,
        severity=severity,
        findings=findings,
    )


def write_log(entry: LogEntry) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as fh:
            fh.write(json.dumps(dataclasses.asdict(entry)) + "\n")
    except Exception as _:
        pass


def read_session_log(session_id: str) -> list[dict]:
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
    return entries
