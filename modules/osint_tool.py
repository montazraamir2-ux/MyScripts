import requests
import threading
from core.logger import log_scan_start, log_profile_found, log_scan_error

_PLATFORMS = {
    "Instagram": "https://www.instagram.com/{}/",
    "GitHub": "https://github.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Telegram": "https://t.me/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "DockerHub": "https://hub.docker.com/u/{}",
    "Pinterest": "https://www.pinterest.com/{}",
    "Medium": "https://medium.com/@{}",
    "GitLab": "https://gitlab.com/{}",
    "Cracked.io": "https://cracked.io/{}"
}


def check_platform(username, platform_name, url_template, session_id=""):
    url = url_template.format(username)
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)

        if platform_name == "Instagram":
            if response.status_code == 200 and "Login" not in response.url and "/p/" not in response.url:
                log_profile_found("osint", platform_name, url, session_id)
                print(f"  [+] FOUND on {platform_name:<12} : {url}")
        else:
            if response.status_code == 200:
                log_profile_found("osint", platform_name, url, session_id)
                print(f"  [+] FOUND on {platform_name:<12} : {url}")

    except requests.RequestException as e:
        log_scan_error("osint", str(e), platform_name, session_id)


def run(target: str, session_id: str = "") -> None:
    if not target:
        print("  [!] Error: Username cannot be empty.")
        return

    log_scan_start("osint", target, session_id)
    print("=" * 60)
    print("       EXPANDED OSINT USERNAME RECONNAISSANCE TOOL")
    print("=" * 60)
    print(f"\n  Scanning for username: {target}")
    print("-" * 60)

    threads = []
    for platform_name, url_template in _PLATFORMS.items():
        t = threading.Thread(target=check_platform, args=(target, platform_name, url_template, session_id))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("-" * 60)
    print("Expanded OSINT Scan completed successfully.")


def main():
    username = input("Enter target username to scan: ").strip()
    run(username)


if __name__ == "__main__":
    main()
