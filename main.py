#!/usr/bin/env python3

from __future__ import annotations

import argparse
import dataclasses
import sys
import time

from modules.logger import SESSION_ID, make_entry, write_log
from modules.network_info import get_network_info, to_log_dict
from modules.scanner import COMMON_PORTS, scan_network, to_log_findings as scanner_findings
from modules.ai_analyst import analyse_host, to_log_findings
from modules.reporter import generate_report

_BANNER = """\
╔══════════════════════════════╗
║     MyScripts Recon Suite   ║
╚══════════════════════════════╝"""

_MENU = """\

[1] Full scan (auto-detect network)
[2] Scan custom CIDR
[3] Network info only
[4] Generate report (last session)
[6] OSINT lookup (IP or domain)
[7] List all sessions
[8] Passive network monitor
[5] Exit"""


def run_scan(
    cidr: str | None,
    ports: list[int] | None,
    ai: bool,
    report: bool,
    name: str = "unnamed",
) -> None:
    from modules.session_manager import update_session_stats, register_session as _register_session
    if name != "unnamed":
        _register_session(SESSION_ID, name=name)

    resolved_cidr = cidr
    if resolved_cidr is None:
        net_info = get_network_info()
        write_log(make_entry("network_info", "local", "info", to_log_dict(net_info)))
        resolved_cidr = net_info.cidr_notation

    print(f"  Session: {SESSION_ID} | Network: {resolved_cidr}")
    print(f"  Scanning {resolved_cidr} ...")

    alive_hosts = scan_network(resolved_cidr, ports or COMMON_PORTS)

    for result in alive_hosts:
        write_log(make_entry("scanner", result.ip, "info", scanner_findings(result)))
        ports_str = ", ".join(str(p) for p in result.open_ports)
        print(f"  [ALIVE] {result.ip} | Ports: {ports_str}")
        for svc in result.services:
            if svc.service == "unknown" and svc.software == "":
                continue
            version_str = f" {svc.version}" if svc.version else ""
            print(f"  [SERVICE] {result.ip}:{svc.port} — {svc.service} | {svc.software}{version_str}")

    print(f"  Scan complete — {len(alive_hosts)} host(s) found.")

    analyses: list = []
    if ai:
        for result in alive_hosts:
            if not result.services:
                continue
            services_dict = [dataclasses.asdict(s) for s in result.services]
            analysis = analyse_host(SESSION_ID, result.ip, services_dict)
            if analysis.summary == "ollama unavailable":
                continue
            analyses.append(analysis)
            summary_preview = analysis.summary[:120]
            if len(analysis.summary) > 120:
                summary_preview += "..."
            print(f"  [AI] {result.ip} | Risk: {analysis.risk_level}")
            print(f"  [AI] Summary: {summary_preview}")
            for flag in analysis.flags:
                print(f"  [FLAG] {flag}")
            write_log(make_entry("ai_analyst", result.ip, analysis.risk_level, to_log_findings(analysis)))

    update_session_stats(
        session_id=SESSION_ID,
        cidr=resolved_cidr,
        alive_hosts=len(alive_hosts),
        total_services=sum(len(h.services) for h in alive_hosts),
        risk_high=sum(1 for a in analyses if a.risk_level == "high"),
        risk_medium=sum(1 for a in analyses if a.risk_level == "medium"),
        risk_low=sum(1 for a in analyses if a.risk_level == "low"),
        risk_info=sum(1 for a in analyses if a.risk_level == "info"),
    )

    if report:
        report_path = generate_report(SESSION_ID)
        print(f"  [REPORT] {report_path}")


def run_monitor(cidr: str | None, interval: int) -> None:
    from modules.monitor import start_monitor, stop_monitor, to_log_findings as monitor_findings, DeviceEvent

    resolved_cidr = cidr
    if resolved_cidr is None:
        net_info = get_network_info()
        resolved_cidr = net_info.cidr_notation

    print(f"[MONITOR] Watching: {resolved_cidr}")
    print(f"[MONITOR] Interval: {interval}s")
    print("[MONITOR] Press Ctrl+C to stop.")

    def on_event(event: DeviceEvent) -> None:
        entry = make_entry(
            tool="monitor",
            target=event.ip,
            severity="low" if event.event_type == "joined" else "info",
            findings=monitor_findings(event),
        )
        write_log(entry)

    state = start_monitor(resolved_cidr, interval, on_event)

    try:
        while state.running:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_monitor(state)


def run_osint(target: str) -> None:
    from modules.osint import gather, to_log_findings as osint_findings

    if not target:
        print("  [ERROR] Target cannot be empty.")
        return

    result = gather(target)

    whois_org = (
        result.whois_data.get("OrgName")
        or result.whois_data.get("org-name")
        or result.whois_data.get("organisation")
        or "unknown"
    )
    whois_country = (
        result.whois_data.get("Country")
        or result.whois_data.get("country")
        or "unknown"
    )
    a_records = result.dns_records.get("A", [])
    mx_records = result.dns_records.get("MX", [])

    print(f"  [OSINT] Target: {result.target} ({result.target_type})")
    print(f"  [OSINT] Organisation: {whois_org}")
    print(f"  [OSINT] Country: {whois_country}")
    print(f"  [OSINT] DNS A Records: {a_records}")
    print(f"  [OSINT] MX Present: {'yes' if mx_records else 'no'}")

    for rtype, values in result.dns_records.items():
        for value in values:
            print(f"  [DNS] {rtype}: {value}")

    isp = result.reputation.get("isp", "") or result.reputation.get("org", "")
    proxy = result.reputation.get("proxy", False)
    rep_display = f"{isp} [PROXY]" if (isp and proxy) else (isp or result.reputation.get("status", "unknown"))
    print(f"  [OSINT] Reputation: {rep_display}")
    print(f"  [OSINT] Summary: {result.intelligence_summary}")

    write_log(make_entry("osint", target, "info", osint_findings(result)))


def run_sessions() -> None:
    from modules.session_manager import list_sessions, format_sessions_table
    sessions = list_sessions()
    if not sessions:
        print("  No sessions recorded yet.")
        return
    print(format_sessions_table(sessions))


def _resolve_last_session() -> str | None:
    from modules.session_manager import get_last_session_id
    return get_last_session_id()


def run_report(session_id: str | None) -> None:
    resolved_id = session_id or _resolve_last_session()
    if resolved_id is None:
        print("  [ERROR] No session found in log.")
        return
    report_path = generate_report(resolved_id)
    print(f"  [REPORT] {report_path}")


def run_info() -> None:
    net_info = get_network_info()
    write_log(make_entry("network_info", "local", "info", to_log_dict(net_info)))
    rows: list[tuple[str, str]] = [
        ("Local IP",     net_info.local_ip),
        ("Interface",    net_info.active_interface),
        ("CIDR",         net_info.cidr_notation),
        ("Prefix",       f"/{net_info.prefix_length}"),
        ("Usable Hosts", str(net_info.usable_hosts)),
    ]
    label_width = max(len(r[0]) for r in rows) + 2
    separator = "─" * (label_width + 24)
    print(f"\n  {'Field':<{label_width}} Value")
    print(f"  {separator}")
    for label, value in rows:
        print(f"  {label:<{label_width}} {value}")
    print()


def run_menu() -> None:
    print(_BANNER)
    print(f"  Session: {SESSION_ID}")
    while True:
        print(_MENU)
        choice = input("\n  Select: ").strip()
        if choice == "1":
            run_scan(cidr=None, ports=None, ai=True, report=True)
        elif choice == "2":
            cidr = input("  Enter CIDR (e.g. 192.168.1.0/24): ").strip()
            if cidr:
                run_scan(cidr=cidr, ports=None, ai=True, report=True)
        elif choice == "3":
            run_info()
        elif choice == "4":
            run_report(session_id=None)
        elif choice == "6":
            target = input("  Enter IP or domain: ").strip()
            if target:
                run_osint(target)
        elif choice == "7":
            run_sessions()
        elif choice == "8":
            raw = input("  Scan interval in seconds [30]: ").strip()
            try:
                interval = int(raw) if raw else 30
            except ValueError as _:
                interval = 30
            run_monitor(None, interval)
        elif choice == "5":
            print("  Exiting MyScripts.")
            sys.exit(0)
        else:
            print("  Invalid choice.")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="myscripts",
        description="MyScripts Recon Suite",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--scan",     action="store_true", help="Run network scan pipeline")
    mode.add_argument("--report",   action="store_true", help="Generate HTML report")
    mode.add_argument("--info",     action="store_true", help="Show network info")
    mode.add_argument("--osint",    type=str, metavar="TARGET",     help="Run OSINT on an IP or domain")
    mode.add_argument("--sessions", action="store_true",             help="List all recorded sessions")
    mode.add_argument("--monitor",  action="store_true",             help="Start passive network monitor")
    parser.add_argument("--name",   type=str, metavar="NAME",  default="unnamed", help="Name this scan session")
    parser.add_argument("--cidr",      type=str,      metavar="CIDR",       help="Target CIDR (default: auto-detect)")
    parser.add_argument("--ports",     type=int,      metavar="PORT", nargs="+", help="Ports to scan")
    parser.add_argument("--session",   type=str,      metavar="SESSION_ID", help="Session ID for --report")
    parser.add_argument("--no-ai",     action="store_true",                 help="Skip AI analysis")
    parser.add_argument("--no-report", action="store_true",                 help="Skip report generation")
    parser.add_argument("--interval",  type=int, default=30, metavar="SECONDS", help="Monitor scan interval (default: 30)")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.scan:
        run_scan(
            cidr=args.cidr,
            ports=args.ports,
            ai=not args.no_ai,
            report=not args.no_report,
            name=args.name,
        )
    elif args.report:
        run_report(session_id=args.session)
    elif args.info:
        run_info()
    elif args.osint is not None:
        run_osint(args.osint)
    elif args.sessions:
        run_sessions()
    elif args.monitor:
        run_monitor(args.cidr, args.interval)
    else:
        run_menu()


if __name__ == "__main__":
    main()
