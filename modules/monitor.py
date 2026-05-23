import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import log_findings
from core.utils import resolve_hostname

_PORTS = [22, 80, 443, 8080]
_TIMEOUT = 1.0
_MAX_WORKERS = 100


def _is_alive(ip: str) -> bool:
    for port in _PORTS:
        try:
            with socket.create_connection((ip, port), timeout=_TIMEOUT):
                return True
        except (ConnectionRefusedError, TimeoutError, OSError):
            continue
    return False


def _sweep(subnet: str) -> set[str]:
    alive = set()
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        futures = {
            executor.submit(_is_alive, f"{subnet}.{i}"): f"{subnet}.{i}"
            for i in range(1, 255)
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    alive.add(ip)
            except Exception:
                pass
    return alive


def run(target: str, session_id: str) -> None:
    duration = 60
    interval = 20
    subnet = target if target else "192.168.0"

    print(f"[MONITOR] TCP sweep monitor on {subnet}.0/24")
    print(f"  Duration: {duration}s | Sweep every: {interval}s")
    print("  Press Ctrl+C to stop early.\n")

    print("  [*] Initial sweep...")
    previous = _sweep(subnet)
    print(f"  [*] {len(previous)} active host(s) found: {sorted(previous)}\n")

    findings = []
    elapsed = 0

    try:
        while elapsed < duration:
            time.sleep(interval)
            elapsed += interval
            print(f"  [*] Sweeping... ({elapsed}s)")
            current = _sweep(subnet)

            new_hosts = current - previous
            gone_hosts = previous - current

            for ip in new_hosts:
                hostname = resolve_hostname(ip)
                entry = {
                    "event": "new_host",
                    "ip": ip,
                    "hostname": hostname or "unknown",
                }
                findings.append(entry)
                print(f"  [NEW]  {ip} | {hostname or 'unknown'}")

            for ip in gone_hosts:
                entry = {
                    "event": "host_gone",
                    "ip": ip,
                }
                findings.append(entry)
                print(f"  [GONE] {ip}")

            previous = current

    except KeyboardInterrupt:
        print("\n  [!] Monitor stopped by user.")

    if findings:
        log_findings("monitor", session_id, findings)
        print(f"\n  [+] {len(findings)} network events logged.")
    else:
        print(f"\n  [!] No network changes detected.")
