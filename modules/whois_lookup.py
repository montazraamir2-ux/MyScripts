import whois
from core.logger import log_findings


def run(target: str, session_id: str) -> None:
    print(f"[WHOIS] Looking up {target}")

    try:
        data = whois.whois(target)
    except Exception as e:
        print(f"  [!] WHOIS failed: {e}")
        return

    fields = {
        "registrar": data.registrar,
        "creation_date": str(data.creation_date),
        "expiration_date": str(data.expiration_date),
        "name_servers": data.name_servers,
        "emails": data.emails,
        "org": data.org,
        "country": data.country,
    }

    cleaned = {k: v for k, v in fields.items() if v and v != "None"}

    for k, v in cleaned.items():
        print(f"  [{k.upper()}] {v}")

    findings = [{"target": target, "whois": cleaned}]
    log_findings("whois", session_id, findings)
    print(f"\n  [+] WHOIS data logged.")
