#!/usr/bin/env python3

import sys
import uuid
import argparse
from core.logger import log_scan_start

BANNER = """
╔══════════════════════════════════════╗
║         MyScripts Recon Suite        ║
║     Modular Reconnaissance Tool      ║
╚══════════════════════════════════════╝
"""

MENU = """
[1] Network Scanner
[2] OSINT Username Lookup
[3] Banner Grabber
[4] Analyze Log (Gemma 2B)
[5] Generate HTML Report
[6] DNS Enumeration
[7] WHOIS Lookup
[8] Network Monitor
[0] Exit
"""

def run_scanner(session_id):
    from modules.scanner import run
    target = input("  Enter target IP or CIDR: ").strip()
    if target:
        run(target=target, session_id=session_id)

def run_osint(session_id):
    from modules.osint_tool import run
    target = input("  Enter target username: ").strip()
    if target:
        run(target=target, session_id=session_id)

def run_banner(session_id):
    from modules.banner import run
    target = input("  Enter target IP[:port] (default port 80): ").strip()
    if target:
        run(target=target, session_id=session_id)

def run_analyzer(session_id):
    from core.analyzer import analyze_log
    result = analyze_log("scan.log")
    print(f"\n{result}\n")

def run_report(session_id):
    from report_generator import generate_report
    path = generate_report("scan.log")
    print(f"\n  [+] Report saved to: {path}\n")

def run_dns(session_id):
    from modules.dns import run
    target = input("  Enter domain (e.g. example.com): ").strip()
    if target:
        run(target=target, session_id=session_id)

def run_whois(session_id):
    from modules.whois_lookup import run
    target = input("  Enter domain (e.g. example.com): ").strip()
    if target:
        run(target=target, session_id=session_id)

def run_monitor(session_id):
    from modules.monitor import run
    subnet = input("  Enter subnet prefix (e.g. 192.168.0): ").strip()
    run(target=subnet, session_id=session_id)

ACTIONS = {
    "1": run_scanner,
    "2": run_osint,
    "3": run_banner,
    "4": run_analyzer,
    "5": run_report,
    "6": run_dns,
    "7": run_whois,
    "8": run_monitor,
}

def _parse_args():
    parser = argparse.ArgumentParser(
        prog="myscripts",
        description="MyScripts — Modular Reconnaissance & OSINT Suite",
    )
    parser.add_argument("--module", choices=["scanner", "dns", "whois", "osint", "banner", "monitor"], help="Module to run directly")
    parser.add_argument("--target", type=str, help="Target IP, CIDR, or domain")
    parser.add_argument("--subnet", type=str, help="Subnet prefix for monitor (e.g. 192.168.0)")
    parser.add_argument("--report", action="store_true", help="Generate HTML report")
    parser.add_argument("--analyze", action="store_true", help="Analyze log with Gemma 2B")
    return parser.parse_args()

def main():
    args = _parse_args()
    session_id = str(uuid.uuid4())[:8]

    if args.report:
        run_report(session_id)
        return

    if args.analyze:
        run_analyzer(session_id)
        return

    if args.module:
        if args.module == "scanner":
            if not args.target:
                print("[ERROR] --target required for scanner")
                return
            from modules.scanner import run
            run(target=args.target, session_id=session_id)

        elif args.module == "dns":
            if not args.target:
                print("[ERROR] --target required for dns")
                return
            from modules.dns import run
            run(target=args.target, session_id=session_id)

        elif args.module == "whois":
            if not args.target:
                print("[ERROR] --target required for whois")
                return
            from modules.whois_lookup import run
            run(target=args.target, session_id=session_id)

        elif args.module == "osint":
            if not args.target:
                print("[ERROR] --target required for osint")
                return
            from modules.osint_tool import run as osint_run
            osint_run(target=args.target, session_id=session_id)

        elif args.module == "banner":
            if not args.target:
                print("[ERROR] --target required for banner")
                return
            from modules.banner import run as banner_run
            banner_run(target=args.target, session_id=session_id)

        elif args.module == "monitor":
            subnet = args.subnet or args.target or "192.168.0"
            from modules.monitor import run
            run(target=subnet, session_id=session_id)
        return

    print(BANNER)
    print(f"  Session: {session_id}")
    while True:
        print(MENU)
        choice = input("Select tool: ").strip()
        if choice == "0":
            print("Exiting MyScripts.")
            sys.exit(0)
        elif choice in ACTIONS:
            log_scan_start("main", f"tool_selected={choice}", session_id)
            ACTIONS[choice](session_id)
        else:
            print("  [!] Invalid choice. Try again.")

if __name__ == "__main__":
    main()
