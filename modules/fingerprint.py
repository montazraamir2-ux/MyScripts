import socket

TIMEOUT = 2.0

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "MSRPC",
    139: "NetBIOS", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"
GENERIC_PROBE = b"\r\n"

def _read_banner(sock: socket.socket) -> str | None:
    try:
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip() or None
    except Exception:
        return None

def _probe_http(sock: socket.socket) -> str | None:
    try:
        sock.send(HTTP_PROBE)
        return _read_banner(sock)
    except Exception:
        return None

def _probe_passive(sock: socket.socket) -> str | None:
    return _read_banner(sock)

def _probe_generic(sock: socket.socket) -> str | None:
    try:
        sock.send(GENERIC_PROBE)
        return _read_banner(sock)
    except Exception:
        return None

PROBE_STRATEGY = {
    21: _probe_passive,
    22: _probe_passive,
    23: _probe_passive,
    25: _probe_passive,
    80: _probe_http,
    443: _probe_http,
    8080: _probe_http,
    8443: _probe_http,
    110: _probe_passive,
}

def grab_banner(host: str, port: int) -> dict:
    result = {
        "port": port,
        "service": SERVICE_MAP.get(port, "unknown"),
        "banner": None
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, port))
            strategy = PROBE_STRATEGY.get(port, _probe_generic)
            result["banner"] = strategy(s)
    except Exception:
        pass
    return result

def fingerprint_host(host: str, open_ports: list[int]) -> list[dict]:
    return [grab_banner(host, port) for port in open_ports]
