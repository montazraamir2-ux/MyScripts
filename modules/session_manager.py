from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "logs" / "sessions.db"


@dataclass
class SessionRecord:
    session_id: str
    name: str
    created_at: str
    cidr: str
    alive_hosts: int
    total_services: int
    risk_high: int
    risk_medium: int
    risk_low: int
    risk_info: int


def init_db() -> None:
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id     TEXT PRIMARY KEY,
                    name           TEXT NOT NULL DEFAULT 'unnamed',
                    created_at     TEXT NOT NULL,
                    cidr           TEXT NOT NULL DEFAULT '',
                    alive_hosts    INTEGER NOT NULL DEFAULT 0,
                    total_services INTEGER NOT NULL DEFAULT 0,
                    risk_high      INTEGER NOT NULL DEFAULT 0,
                    risk_medium    INTEGER NOT NULL DEFAULT 0,
                    risk_low       INTEGER NOT NULL DEFAULT 0,
                    risk_info      INTEGER NOT NULL DEFAULT 0
                )
                """
            )
    except Exception as _:
        pass


def register_session(session_id: str, name: str = "unnamed") -> None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO sessions
                  (session_id, name, created_at, cidr,
                   alive_hosts, total_services,
                   risk_high, risk_medium, risk_low, risk_info)
                VALUES (?, ?, ?, '', 0, 0, 0, 0, 0, 0)
                """,
                (session_id, name, datetime.utcnow().isoformat()),
            )
            if name != "unnamed":
                conn.execute(
                    "UPDATE sessions SET name = ? WHERE session_id = ?",
                    (name, session_id),
                )
    except Exception as _:
        pass


def update_session_stats(
    session_id: str,
    cidr: str = "",
    alive_hosts: int = 0,
    total_services: int = 0,
    risk_high: int = 0,
    risk_medium: int = 0,
    risk_low: int = 0,
    risk_info: int = 0,
) -> None:
    defaults: dict[str, object] = {
        "cidr": "",
        "alive_hosts": 0,
        "total_services": 0,
        "risk_high": 0,
        "risk_medium": 0,
        "risk_low": 0,
        "risk_info": 0,
    }
    candidates: dict[str, object] = {
        "cidr": cidr,
        "alive_hosts": alive_hosts,
        "total_services": total_services,
        "risk_high": risk_high,
        "risk_medium": risk_medium,
        "risk_low": risk_low,
        "risk_info": risk_info,
    }
    updates = {col: val for col, val in candidates.items() if val != defaults[col]}
    if not updates:
        return
    set_clause = ", ".join(f"{col} = ?" for col in updates)
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                f"UPDATE sessions SET {set_clause} WHERE session_id = ?",
                [*updates.values(), session_id],
            )
    except Exception as _:
        pass


def get_session(session_id: str) -> SessionRecord | None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return SessionRecord(**dict(row)) if row else None
    except Exception as _:
        return None


def list_sessions(limit: int = 20) -> list[SessionRecord]:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [SessionRecord(**dict(row)) for row in rows]
    except Exception as _:
        return []


def get_last_session_id() -> str | None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT session_id FROM sessions ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        return row[0] if row else None
    except Exception as _:
        return None


def format_sessions_table(sessions: list[SessionRecord]) -> str:
    if not sessions:
        return ""
    header = f"{'ID':<10}{'Name':<18}{'Date':<18}{'Hosts':<7}{'High':<6}Med"
    separator = "─" * 62
    rows = [header, separator]
    for s in sessions:
        name = s.name[:16]
        date = s.created_at.replace("T", " ")[:16]
        rows.append(
            f"{s.session_id:<10}{name:<18}{date:<18}"
            f"{s.alive_hosts:<7}{s.risk_high:<6}{s.risk_medium}"
        )
    return "\n".join(rows)


init_db()
