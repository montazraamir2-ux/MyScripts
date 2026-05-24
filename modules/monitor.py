from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime

from modules.network_info import iter_cidr_hosts
from modules.scanner import scan_port


MONITOR_PORTS: list[int] = [22, 80, 443, 8080, 8443, 445, 3389, 21, 23]


@dataclass
class DeviceEvent:
    event_type: str
    ip: str
    detected_at: str
    open_ports: list[int]
    response_time_ms: float


@dataclass
class MonitorState:
    cidr: str
    interval_seconds: int
    known_hosts: dict[str, DeviceEvent]
    running: bool
    scan_count: int
    started_at: str


def probe_host(
    ip: str,
    ports: list[int] = MONITOR_PORTS,
    timeout: float = 0.5,
) -> tuple[bool, list[int], float]:
    start = time.monotonic()
    open_ports: list[int] = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            try:
                if future.result():
                    open_ports.append(futures[future])
            except Exception as _:
                pass

    elapsed_ms = round((time.monotonic() - start) * 1000, 2)
    return bool(open_ports), sorted(open_ports), elapsed_ms


def scan_network_once(
    cidr: str,
    ports: list[int] = MONITOR_PORTS,
) -> dict[str, tuple[list[int], float]]:
    hosts = [str(h) for h in iter_cidr_hosts(cidr)]
    alive: dict[str, tuple[list[int], float]] = {}

    with ThreadPoolExecutor(max_workers=80) as executor:
        futures = {executor.submit(probe_host, ip, ports): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                is_alive, open_ports, elapsed_ms = future.result()
                if is_alive:
                    alive[ip] = (open_ports, elapsed_ms)
            except Exception as _:
                pass

    return alive


def diff_scan(
    previous: dict[str, DeviceEvent],
    current: dict[str, tuple[list[int], float]],
) -> list[DeviceEvent]:
    events: list[DeviceEvent] = []
    now = datetime.utcnow().isoformat()

    for ip, (open_ports, response_time_ms) in current.items():
        if ip not in previous:
            events.append(DeviceEvent(
                event_type="joined",
                ip=ip,
                detected_at=now,
                open_ports=open_ports,
                response_time_ms=response_time_ms,
            ))

    for ip in previous:
        if ip not in current:
            events.append(DeviceEvent(
                event_type="left",
                ip=ip,
                detected_at=now,
                open_ports=[],
                response_time_ms=0.0,
            ))

    return events


def start_monitor(
    cidr: str,
    interval_seconds: int = 30,
    on_event: callable = None,
) -> MonitorState:
    baseline = scan_network_once(cidr)
    now = datetime.utcnow().isoformat()
    known_hosts: dict[str, DeviceEvent] = {
        ip: DeviceEvent(
            event_type="joined",
            ip=ip,
            detected_at=now,
            open_ports=open_ports,
            response_time_ms=response_time_ms,
        )
        for ip, (open_ports, response_time_ms) in baseline.items()
    }

    print(f"[MONITOR] Baseline: {len(known_hosts)} devices detected.")

    state = MonitorState(
        cidr=cidr,
        interval_seconds=interval_seconds,
        known_hosts=known_hosts,
        running=True,
        scan_count=0,
        started_at=now,
    )

    t = threading.Thread(target=_monitor_loop, args=(state, on_event), daemon=True)
    t.start()

    return state


def _monitor_loop(
    state: MonitorState,
    on_event: callable,
) -> None:
    while state.running:
        time.sleep(state.interval_seconds)
        try:
            current = scan_network_once(state.cidr)
            events = diff_scan(state.known_hosts, current)

            for event in events:
                if event.event_type == "joined":
                    ports_str = ", ".join(str(p) for p in event.open_ports)
                    print(f"[MONITOR] joined: {event.ip} | Ports: {ports_str} | +{event.response_time_ms:.0f}ms")
                    state.known_hosts[event.ip] = event
                else:
                    print(f"[MONITOR] left: {event.ip}")
                    state.known_hosts.pop(event.ip, None)

                if on_event is not None:
                    on_event(event)

            state.scan_count += 1
        except Exception as _:
            pass


def stop_monitor(state: MonitorState) -> None:
    state.running = False
    print(f"[MONITOR] Stopped after {state.scan_count} scans.")


def to_log_findings(event: DeviceEvent) -> dict:
    return {
        "event_type": event.event_type,
        "ip": event.ip,
        "open_ports": event.open_ports,
        "response_time_ms": event.response_time_ms,
    }
