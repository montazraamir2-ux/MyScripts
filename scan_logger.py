import logging
from pathlib import Path

_LOG_FILE = "scan.log"

def _get_logger() -> logging.Logger:
    logger = logging.getLogger("scanner")
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(_LOG_FILE)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)
    return logger


def log_discovered_ip(ip: str, port: int | None = None) -> None:
    msg = f"Discovered IP: {ip}" if port is None else f"Discovered IP: {ip}:{port}"
    _get_logger().info(msg)


def log_scan_error(error: str, ip: str | None = None) -> None:
    msg = f"Scan error on {ip}: {error}" if ip else f"Scan error: {error}"
    _get_logger().error(msg)


def log_scan_start(tool: str, target: str) -> None:
    _get_logger().info(f"[{tool}] Scan started — target: {target}")


def log_banner_grab(ip: str, port: int, banner: str) -> None:
    snippet = banner.strip().splitlines()[0][:120] if banner.strip() else "(empty response)"
    _get_logger().info(f"Banner grabbed from {ip}:{port} — {snippet}")


def log_profile_found(platform: str, url: str) -> None:
    _get_logger().info(f"Profile found — {platform}: {url}")
