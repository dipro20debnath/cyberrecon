"""Conservative heuristic risk indicators, not a vulnerability scanner."""

from __future__ import annotations

from typing import Any


SENSITIVE_PORTS = {21, 23, 25, 110, 143, 445, 3306, 5432, 6379, 9200, 27017}


def assess(results: dict[str, Any]) -> dict[str, Any]:
    score = 0
    indicators: list[dict[str, Any]] = []
    dns = results.get("modules", {}).get("dns", {})
    if dns.get("zone_transfer", {}).get("vulnerable"):
        score += 40
        indicators.append({"severity": "high", "name": "zone_transfer", "message": "Authoritative DNS server allowed AXFR"})

    posture = dns.get("posture", {}) if isinstance(dns, dict) else {}
    email = posture.get("email_authentication", {}) if isinstance(posture, dict) else {}
    if email.get("mail_enabled"):
        spf = email.get("spf", {}) if isinstance(email.get("spf"), dict) else {}
        dmarc = email.get("dmarc", {}) if isinstance(email.get("dmarc"), dict) else {}
        if not spf.get("present"):
            score += 5
            indicators.append({"severity": "low", "name": "spf_missing", "message": "Mail exchanger exists but no SPF record was detected"})
        if not dmarc.get("present"):
            score += 8
            indicators.append({"severity": "medium", "name": "dmarc_missing", "message": "Mail exchanger exists but no DMARC record was detected"})
        elif dmarc.get("policy") == "none":
            score += 3
            indicators.append({"severity": "low", "name": "dmarc_monitor_only", "message": "DMARC policy is set to p=none"})

    active = results.get("modules", {}).get("active", {})
    open_ports = [item.get("port") for item in active.get("ports", {}).get("ports", []) if item.get("state") == "open"]
    sensitive = sorted(set(open_ports) & SENSITIVE_PORTS)
    if sensitive:
        score += min(40, 10 * len(sensitive))
        indicators.append({"severity": "medium", "name": "sensitive_ports", "ports": sensitive})

    technology = results.get("modules", {}).get("technology", {})
    if technology.get("headers", {}).get("X-Powered-By"):
        score += 5
        indicators.append({"severity": "low", "name": "technology_disclosure", "message": "X-Powered-By header is exposed"})

    security = technology.get("security", {})
    security_findings = security.get("findings", [])
    if security_findings:
        score += min(25, sum(2 if item.get("severity") == "medium" else 1 for item in security_findings))
        indicators.append({"severity": "low", "name": "http_security_headers", "count": len(security_findings)})

    tls = results.get("modules", {}).get("tls", {})
    days_until_expiry = tls.get("certificate", {}).get("days_until_expiry")
    if isinstance(days_until_expiry, int) and days_until_expiry < 14:
        score += 15
        indicators.append({"severity": "medium", "name": "certificate_expiry", "days_until_expiry": days_until_expiry})

    score = min(100, score)
    severity = "low" if score < 20 else "medium" if score < 50 else "high" if score < 80 else "critical"
    return {
        "score": score,
        "severity": severity,
        "indicators": indicators,
        "method": "heuristic indicators only; validate findings manually",
    }
