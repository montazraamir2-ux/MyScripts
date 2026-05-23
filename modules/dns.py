import dns.resolver
from core.logger import log_findings


_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def _query(target: str, record_type: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(target, record_type, lifetime=5)
        return [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def run(target: str, session_id: str) -> None:
    print(f"[DNS] Enumerating records for {target}")

    results = {}
    for record_type in _RECORD_TYPES:
        records = _query(target, record_type)
        if records:
            results[record_type] = records
            for r in records:
                print(f"  [{record_type}] {r}")

    if results:
        findings = [{"target": target, "dns_records": results}]
        log_findings("dns", session_id, findings)
        print(f"\n  [+] {sum(len(v) for v in results.values())} records found. Logged.")
    else:
        print("  [!] No DNS records found.")
