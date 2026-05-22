#!/usr/bin/env python3

import sys
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
[0] Exit
"""

def run_scanner():
    from modules.scanner import main
    main()

def run_osint():
    from modules.osint_tool import main
    main()

def run_banner():
    from modules.banner import main
    main()

ACTIONS = {
    "1": run_scanner,
    "2": run_osint,
    "3": run_banner,
}

def main():
    print(BANNER)
    while True:
        print(MENU)
        choice = input("Select tool: ").strip()
        if choice == "0":
            print("Exiting MyScripts.")
            sys.exit(0)
        elif choice in ACTIONS:
            log_scan_start("main", f"tool_selected={choice}")
            ACTIONS[choice]()
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
