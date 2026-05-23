#!/usr/bin/env python3

import sys
import uuid
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
[4] Analyze
[5] Report
[0] Exit
"""

def run_scanner(session_id):
    from modules.scanner import run
    run(session_id=session_id)

def run_osint(session_id):
    from modules.osint_tool import main
    main()

def run_banner(session_id):
    from modules.banner import main
    main()

def run_analyze(session_id):
    from core.analyzer import analyze_log
    result = analyze_log("scan.log")
    print(result)

def run_report(session_id):
    from report_generator import generate_report
    output = generate_report("scan.log")
    print(f"[+] Report written to {output}")

ACTIONS = {
    "1": run_scanner,
    "2": run_osint,
    "3": run_banner,
    "4": run_analyze,
    "5": run_report,
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
