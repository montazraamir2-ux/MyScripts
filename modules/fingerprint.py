from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass

BANNER_PATTERNS: dict[str, dict] = {
    r"SSH-(\S+)-([Dd]ropbear\S*)":   {"service": "SSH",     "software": "Dropbear",  "version_group": 1},
    r"SSH-(\S+)-OpenSSH_(\S+)":      {"service": "SSH",     "software": "OpenSSH",   "version_group": 2},
    r"^220.*FileZilla":              {"service": "FTP",     "software": "FileZilla"},
    r"^220.*FTP":                    {"service": "FTP",     "software": "unknown"},
    r"^Server: Apache/(\S+)":        {"service": "HTTP",    "software": "Apache",    "version_group": 1},
    r"^Server: nginx/(\S+)":         {"service": "HTTP",    "software": "nginx",     "version_group": 1},
    r"^HTTP/1\.[01] \d{3}":          {"service": "HTTP",    "software": "unknown"},
    r"^\+OK":                        {"service": "POP3",    "software": "unknown"},
    r"^\* OK.*Dovecot":              {"service": "IMAP",    "software": "Dovecot"},
    r"^220.*SMTP":                   {"service": "SMTP",    "software": "unknown"},
    r"^RFB (\S+)":                   {"service": "VNC",     "software": "unknown",   "version_group": 1},
    r"mysql_native_password":        {"service": "MySQL",   "software": "MySQL"},
    r"^\x15\x03":                    {"service": "TLS/SSL", "software": "unknown"},
}


@dataclass
class ServiceInfo:
    port: int
    protocol: str
    service: str
    software: str
    version: str
    raw_banner: str


def parse_banner(port: int, banner: str) -> ServiceInfo:
    for pattern, meta in BANNER_PATTERNS.items():
        match = re.search(pattern, banner, re.MULTILINE)
        if match:
            version = ""
            vgroup = meta.get("version_group")
            if vgroup is not None:
                try:
                    version = match.group(vgroup)
                except IndexError as _:
                    pass
            return ServiceInfo(
                port=port,
                protocol="TCP",
                service=meta["service"],
                software=meta.get("software", ""),
                version=version,
                raw_banner=banner,
            )
    return ServiceInfo(port=port, protocol="TCP", service="unknown", software="", version="", raw_banner=banner)


def fingerprint_host(ip: str, banners: dict[int, str]) -> list[ServiceInfo]:
    return [parse_banner(port, banner) for port, banner in banners.items()]


def to_log_findings(ip: str, services: list[ServiceInfo]) -> dict:
    return {
        "ip": ip,
        "services": [dataclasses.asdict(s) for s in services],
    }
