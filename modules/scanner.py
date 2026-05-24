from __future__ import annotations

import dataclasses
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from modules.fingerprint import ServiceInfo, fingerprint_host
from modules.network_info import iter_cidr_hosts

COMMON_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 139, 143,
    443, 445, 3306, 3389, 5900, 8080, 8443,
]


@dataclass
class HostResult:
    ip: str
    is_alive: bool
    open_ports: list[int]
    banners: dict[int, str]
    scan_duration_ms: float
    services: list = field(default_factory=list)


def grab_banner(ip: str, port: int) -> str:
    try:
        with socket.create_connection((ip, port), timeout=2.0) as s:
            s.sendall(b"\r\n")
            return s.recv(1024).decode("utf-8", errors="ignore").strip()
    except Exception as _:
        return ""


def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception as _:
        return False


def scan_host(
    ip: str,
    ports: list[int] = COMMON_PORTS,
    max_workers: int = 50,
) -> HostResult:
    start = time.monotonic()
    open_ports: list[int] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in as_completed(futures):
            try:
                if future.result():
                    open_ports.append(futures[future])
            except Exception as _:
                pass

    banners: dict[int, str] = {}
    for port in open_ports:
        banner = grab_banner(ip, port)
        if banner:
            banners[port] = banner

    return HostResult(
        ip=ip,
        is_alive=len(open_ports) > 0,
        open_ports=sorted(open_ports),
        banners=banners,
        scan_duration_ms=round((time.monotonic() - start) * 1000, 2),
        services=fingerprint_host(ip, banners),
    )


def scan_network(
    cidr: str,
    ports: list[int] = COMMON_PORTS,
    max_workers: int = 100,
) -> list[HostResult]:
    hosts = [str(h) for h in iter_cidr_hosts(cidr)]
    alive: list[HostResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_host, ip, ports): ip for ip in hosts}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result.is_alive:
                    alive.append(result)
            except Exception as _:
                pass

    return alive


def to_log_findings(result: HostResult) -> dict:
    return {
        "ip": result.ip,
        "open_ports": result.open_ports,
        "banners": result.banners,
        "scan_duration_ms": result.scan_duration_ms,
        "services": [dataclasses.asdict(s) for s in result.services],
    }


def run(target: str, session_id: str = "") -> None:
    from modules.logger import make_entry, write_log

    if "/" in target:
        results = scan_network(target)
    else:
        result = scan_host(target)
        results = [result] if result.is_alive else []

    for result in results:
        write_log(make_entry("scanner", result.ip, "info", to_log_findings(result)))
        ports_str = ", ".join(str(p) for p in result.open_ports)
        print(f"  [ALIVE] {result.ip} | Ports: {ports_str or 'none'}")

    print(f"\n  Scan complete — {len(results)} host(s) found.")


def main() -> None:
    import sys
    run(target=sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1")


if __name__ == "__main__":
    main()
