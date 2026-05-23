import socket
from core.logger import log_scan_start, log_banner_grab, log_scan_error


def grab_banner(ip: str, port: int, timeout: int = 3) -> str | None:
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        response = s.recv(4096)
        return response.decode("utf-8", errors="ignore")
    except Exception as e:
        log_scan_error("banner", str(e), f"{ip}:{port}")
        return None
    finally:
        if s:
            s.close()


def run(target: str, session_id: str = "") -> None:
    parts = target.rsplit(":", 1)
    ip = parts[0]
    try:
        port = int(parts[1]) if len(parts) > 1 else 80
    except ValueError:
        port = 80

    log_scan_start("banner", f"{ip}:{port}", session_id)
    print(f"\n[Banner Grab] {ip}:{port}")
    print("-" * 50)

    banner = grab_banner(ip, port)
    if banner:
        log_banner_grab("banner", ip, port, banner, session_id)
        print(banner)
    else:
        print("  [!] No banner received.")

    print("-" * 50)


def main():
    print("=" * 50)
    print("         BANNER GRABBER")
    print("=" * 50)

    target_ip = input("Enter target IP: ").strip()
    target_port = input("Enter target port [80]: ").strip()
    try:
        target_port = int(target_port) if target_port else 80
    except ValueError:
        target_port = 80

    run(f"{target_ip}:{target_port}")


if __name__ == "__main__":
    main()
