import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from scan_logger import log_discovered_ip, log_scan_error, log_scan_start

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 443, 8080, 8443]
DEFAULT_TIMEOUT = 1.0
MAX_WORKERS = 100


def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, TimeoutError):
        return False
    except OSError as e:
        log_scan_error(str(e), ip)
        return False


def scan_host(ip: str, ports: list[int] = DEFAULT_PORTS, timeout: float = DEFAULT_TIMEOUT) -> list[int]:
    open_ports = []
    for port in ports:
        if scan_port(ip, port, timeout):
            log_discovered_ip(ip, port)
            open_ports.append(port)
    return open_ports


def scan_network(cidr: str, ports: list[int] = DEFAULT_PORTS, timeout: float = DEFAULT_TIMEOUT) -> dict[str, list[int]]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        log_scan_error(f"Invalid network range '{cidr}': {e}")
        return {}

    results: dict[str, list[int]] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(scan_host, str(ip), ports, timeout): str(ip) for ip in network.hosts()}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                open_ports = future.result()
                if open_ports:
                    results[ip] = open_ports
            except Exception as e:
                log_scan_error(str(e), ip)

    return results


if __name__ == "__main__":
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
