import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import log_discovered_ip, log_scan_error, log_scan_start, log_findings
from core.utils import resolve_hostname
from modules.fingerprint import fingerprint_host

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 443, 8080, 8443]
DEFAULT_TIMEOUT = 1.0
MAX_WORKERS = 100


def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT, session_id: str = "") -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, TimeoutError):
        return False
    except OSError as e:
        log_scan_error("scanner", str(e), ip, session_id)
        return False


def scan_host(ip: str, ports: list[int] = DEFAULT_PORTS,
              timeout: float = DEFAULT_TIMEOUT, session_id: str = "") -> list[int]:
    open_ports = []
    for port in ports:
        if scan_port(ip, port, timeout, session_id):
            log_discovered_ip("scanner", ip, port, session_id)
            open_ports.append(port)
    return open_ports


def scan_network(cidr: str, ports: list[int] = DEFAULT_PORTS,
                 timeout: float = DEFAULT_TIMEOUT, session_id: str = "") -> dict[str, list[int]]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        log_scan_error("scanner", f"Invalid network range '{cidr}': {e}", session_id=session_id)
        return {}

    results: dict[str, list[int]] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(scan_host, str(ip), ports, timeout, session_id): str(ip)
            for ip in network.hosts()
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                open_ports = future.result()
                if open_ports:
                    results[ip] = open_ports
            except Exception as e:
                log_scan_error("scanner", str(e), ip, session_id)

    return results


def run(target: str, session_id: str = "", ports: list = None) -> None:
    if ports is None:
        ports = DEFAULT_PORTS

    log_scan_start("scanner", target, session_id)

    if "/" in target:
        raw_results = scan_network(target, ports, session_id=session_id)
    else:
        open_ports = scan_host(target, ports, session_id=session_id)
        raw_results = {target: open_ports} if open_ports else {}

    findings = []
    for ip, open_ports in raw_results.items():
        port_details = fingerprint_host(ip, open_ports)
        findings.append({
            "ip": ip,
            "hostname": resolve_hostname(ip),
            "open_ports": port_details
        })

    if findings:
        log_findings("scanner", session_id, findings)

    for host in findings:
        print(f"  {host['ip']}: {[p['port'] for p in host['open_ports']]}")


def main():
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    ports = list(map(int, sys.argv[2].split(","))) if len(sys.argv) > 2 else DEFAULT_PORTS

    log_scan_start("scanner", target)

    if "/" in target:
        results = scan_network(target, ports)
        for ip, open_ports in results.items():
            print(f"  {ip}: {open_ports}")
    else:
        open_ports = scan_host(target, ports)
        print(f"  {target}: {open_ports or 'no open ports found'}")


if __name__ == "__main__":
    main()
