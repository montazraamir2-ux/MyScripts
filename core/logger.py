import logging
import json
from datetime import datetime
from pathlib import Path

_LOG_FILE = Path(__file__).parent.parent / "scan.log"

def _get_logger(tool: str = "myscripts") -> logging.Logger:
    logger = logging.getLogger(tool)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(_LOG_FILE)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger

def _write(tool: str, level: str, event: str, data: dict) -> None:
    record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool": tool,
        "level": level,
        "event": event,
        "data": data
    }
    _get_logger(tool).info(json.dumps(record))

def log_scan_start(tool: str, target: str) -> None:
    _write(tool, "INFO", "scan_start", {"target": target})

def log_discovered_ip(tool: str, ip: str, port: int = None) -> None:
    _write(tool, "INFO", "discovered_ip", {"ip": ip, "port": port})

def log_scan_error(tool: str, error: str, ip: str = None) -> None:
    _write(tool, "ERROR", "scan_error", {"ip": ip, "error": error})

def log_banner_grab(tool: str, ip: str, port: int, banner: str) -> None:
    snippet = banner.strip().splitlines()[0][:120] if banner.strip() else "(empty)"
    _write(tool, "INFO", "banner_grab", {"ip": ip, "port": port, "banner": snippet})

def log_profile_found(tool: str, platform: str, url: str) -> None:
    _write(tool, "INFO", "profile_found", {"platform": platform, "url": url})
