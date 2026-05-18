import socket
from scan_logger import log_scan_start, log_banner_grab, log_scan_error

target_ip = "192.168.0.1"
target_port = 80

log_scan_start("banner", f"{target_ip}:{target_port}")
print(f"\n[Banner Grab] {target_ip}:{target_port}")
print("-" * 50)

s = None
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((target_ip, target_port))
    s.send(b"GET / HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n")
    response = s.recv(4096)
    decoded = response.decode("utf-8", errors="ignore")
    log_banner_grab(target_ip, target_port, decoded)
    print(decoded)
except Exception as e:
    log_scan_error(str(e), f"{target_ip}:{target_port}")
    print(f"  [!] Connection failed: {e}")
finally:
    if s:
        s.close()

print("-" * 50)
