from __future__ import annotations

import ipaddress
import json
import random
import socket
import struct
import urllib.request
from dataclasses import dataclass

_MX = 15
_NS = 2
_TXT = 16
_CNAME = 5


@dataclass
class OsintResult:
    target: str
    target_type: str
    whois_data: dict
    dns_records: dict[str, list[str]]
    shodan_data: dict
    reputation: dict
    intelligence_summary: str


def detect_target_type(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError as _:
        return "domain"


def _encode_dns_name(domain: str) -> bytes:
    encoded = b""
    for label in domain.rstrip(".").split("."):
        encoded += bytes([len(label)]) + label.encode()
    return encoded + b"\x00"


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    end_offset = -1
    jumps = 0
    while offset < len(data) and jumps < 20:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if end_offset == -1:
                end_offset = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumps += 1
        else:
            labels.append(
                data[offset + 1: offset + 1 + length].decode("ascii", errors="replace")
            )
            offset += 1 + length
    return ".".join(labels), end_offset if end_offset != -1 else offset


def raw_dns_query(domain: str, record_type: int) -> list[str]:
    try:
        txn_id = random.randint(1, 65535)
        header = struct.pack(">HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)
        question = _encode_dns_name(domain) + struct.pack(">HH", record_type, 1)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(10)
            sock.sendto(header + question, ("8.8.8.8", 53))
            data, _ = sock.recvfrom(4096)

        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return []

        offset = 12
        _, offset = _decode_dns_name(data, offset)
        offset += 4

        results: list[str] = []
        for _ in range(ancount):
            if offset >= len(data):
                break
            _, offset = _decode_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset: offset + 10])
            offset += 10
            rdata_start = offset
            rdata = data[offset: offset + rdlength]
            offset += rdlength

            if rtype == 1 and len(rdata) == 4:
                results.append(socket.inet_ntoa(rdata))
            elif rtype in (2, 5):
                name, _ = _decode_dns_name(data, rdata_start)
                results.append(name)
            elif rtype == 15 and len(rdata) >= 3:
                pref = struct.unpack(">H", rdata[:2])[0]
                name, _ = _decode_dns_name(data, rdata_start + 2)
                results.append(f"{pref} {name}")
            elif rtype == 16:
                txt_offset = 0
                parts: list[str] = []
                while txt_offset < len(rdata):
                    txt_len = rdata[txt_offset]
                    txt_offset += 1
                    parts.append(
                        rdata[txt_offset: txt_offset + txt_len].decode("utf-8", errors="replace")
                    )
                    txt_offset += txt_len
                results.append("".join(parts))

        return results
    except Exception as _:
        return []


def query_whois(target: str) -> dict:
    def _raw(host: str, query: str) -> str:
        try:
            with socket.create_connection((host, 43), timeout=10) as s:
                s.sendall((query + "\r\n").encode())
                chunks: list[bytes] = []
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b"".join(chunks).decode("utf-8", errors="replace")
        except Exception as _:
            return ""

    try:
        response = _raw("whois.iana.org", target)
        if not response:
            return {}

        refer_server: str | None = None
        for line in response.splitlines():
            if line.lower().startswith("refer:"):
                refer_server = line.split(":", 1)[1].strip()
                break

        if refer_server:
            response = _raw(refer_server, target)
            if not response:
                return {}

        result: dict = {}
        for line in response.splitlines():
            if ":" not in line:
                continue
            if line.startswith(("%", "#", ";")):
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if key and value and key not in result:
                result[key] = value

        return result
    except Exception as _:
        return {}


def query_dns(domain: str) -> dict[str, list[str]]:
    empty: dict[str, list[str]] = {"A": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
    try:
        if detect_target_type(domain) == "ip":
            try:
                hostname, _, _ = socket.gethostbyaddr(domain)
                return {"PTR": [hostname]}
            except Exception as _:
                return {"PTR": []}

        a_records: list[str] = []
        try:
            seen: set[str] = set()
            for info in socket.getaddrinfo(domain, None, socket.AF_INET):
                ip = info[4][0]
                if ip not in seen:
                    seen.add(ip)
                    a_records.append(ip)
        except Exception as _:
            pass

        return {
            "A": a_records,
            "MX": raw_dns_query(domain, _MX),
            "NS": raw_dns_query(domain, _NS),
            "TXT": raw_dns_query(domain, _TXT),
            "CNAME": raw_dns_query(domain, _CNAME),
        }
    except Exception as _:
        return empty


def query_shodan(target: str, api_key: str = "") -> dict:
    if not api_key:
        return {"status": "no_api_key"}
    try:
        if detect_target_type(target) == "ip":
            url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
        else:
            url = f"https://api.shodan.io/dns/resolve?hostnames={target}&key={api_key}"
        with urllib.request.urlopen(urllib.request.Request(url), timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception as _:
        return {"status": "unavailable"}


def query_reputation(ip: str, abuseipdb_key: str = "") -> dict:
    try:
        if abuseipdb_key:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            req = urllib.request.Request(
                url,
                headers={"Key": abuseipdb_key, "Accept": "application/json"},
            )
        else:
            fields = "status,country,isp,org,proxy,hosting,query"
            url = f"https://ip-api.com/json/{ip}?fields={fields}"
            req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception as _:
        return {"status": "unavailable"}


def build_intelligence_summary(result: OsintResult) -> str:
    org = (
        result.whois_data.get("OrgName")
        or result.whois_data.get("org-name")
        or result.whois_data.get("organisation")
        or "unknown"
    )
    country = (
        result.whois_data.get("Country")
        or result.whois_data.get("country")
        or result.reputation.get("country")
        or result.reputation.get("countryCode")
        or "unknown"
    )
    a_count = len(result.dns_records.get("A", []))
    mx_records = result.dns_records.get("MX", [])

    parts = [f"Target {result.target} is registered to {org} in {country}."]

    if a_count:
        parts.append(f"Resolved to {a_count} A record(s).")

    parts.append(
        "Mail infrastructure detected via MX records."
        if mx_records
        else "No MX records detected."
    )

    shodan_status = result.shodan_data.get("status")
    if shodan_status == "no_api_key":
        parts.append("Shodan data unavailable — no API key provided.")
    elif shodan_status == "unavailable":
        parts.append("Shodan query failed.")
    elif shodan_status:
        parts.append("Shodan query returned an error.")
    else:
        parts.append("Shodan data retrieved.")

    if result.reputation.get("proxy"):
        parts.append("IP flagged as proxy/VPN.")
    if result.reputation.get("hosting"):
        parts.append("IP flagged as hosting/datacenter.")

    return " ".join(parts)


def gather(
    target: str,
    shodan_key: str = "",
    abuseipdb_key: str = "",
) -> OsintResult:
    target_type = detect_target_type(target)
    whois_data = query_whois(target)
    dns_records = query_dns(target)
    shodan_data = query_shodan(target, shodan_key)

    reputation_target = target
    if target_type == "domain":
        a_records = dns_records.get("A", [])
        if a_records:
            reputation_target = a_records[0]

    reputation = query_reputation(reputation_target, abuseipdb_key)

    result = OsintResult(
        target=target,
        target_type=target_type,
        whois_data=whois_data,
        dns_records=dns_records,
        shodan_data=shodan_data,
        reputation=reputation,
        intelligence_summary="",
    )
    result.intelligence_summary = build_intelligence_summary(result)
    return result


def to_log_findings(result: OsintResult) -> dict:
    return {
        "target": result.target,
        "target_type": result.target_type,
        "whois_org": result.whois_data.get(
            "OrgName", result.whois_data.get("org-name", "")
        ),
        "whois_country": result.whois_data.get(
            "Country", result.whois_data.get("country", "")
        ),
        "dns_a_records": result.dns_records.get("A", []),
        "dns_mx_present": len(result.dns_records.get("MX", [])) > 0,
        "shodan_status": result.shodan_data.get("status", "ok"),
        "reputation": result.reputation,
        "summary": result.intelligence_summary,
    }
