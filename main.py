#!/usr/bin/env python3

import sys
import uuid
from datetime import datetime, timezone
from core.logger import log_scan_start

_SESSION_ID = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

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
    from modules.osint_tool import main
    main()

def run_banner(session_id):
    from modules.banner import main
    main()

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

def main():
    session_id = str(uuid.uuid4())[:8]
    print(BANNER)
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
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
