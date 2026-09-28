"""DNS enumeration with explicit error reporting."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone
from dns import reversename

from cyberrecon.utils.validators import TargetValidationError, normalize_target


@dataclass
class DNSRecord:
    record_type: str
    name: str
    value: str
    ttl: int = 0


class DNSEnumerator:
    """Collect common DNS records without hiding resolver failures."""

    COMMON_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")

    def __init__(self, timeout: float = 10, resolver: Optional[dns.resolver.Resolver] = None):
        self.timeout = max(0.5, float(timeout))
        self.resolver = resolver or dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

    def enumerate(self, target: str) -> Dict[str, Any]:
        started = time.perf_counter()
        result: Dict[str, Any] = {
            "target": target,
            "records": {},
            "errors": [],
            "duration_ms": 0,
        }
        try:
            info = normalize_target(target)
        except TargetValidationError as exc:
            result["errors"].append(str(exc))
            return result

        result["target"] = info.value
        result["target_type"] = info.kind
        if info.is_ip:
            reverse_name = reversename.from_address(info.value)
            records = self._query_records(str(reverse_name), "PTR", result["errors"], name=info.value)
            if records:
                result["records"]["PTR"] = [asdict(record) for record in records]
        else:
            for record_type in self.COMMON_RECORD_TYPES:
                records = self._query_records(info.value, record_type, result["errors"])
                if records:
                    result["records"][record_type] = [asdict(record) for record in records]

        result["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        return result

    def _query_records(
        self,
        domain: str,
        record_type: str,
        errors: Optional[List[str]] = None,
        name: Optional[str] = None,
    ) -> List[DNSRecord]:
        records: List[DNSRecord] = []
        try:
            answers = self.resolver.resolve(domain, record_type)
            ttl = int(getattr(answers, "rrset", None).ttl) if getattr(answers, "rrset", None) else int(getattr(answers, "ttl", 0))
            for answer in answers:
                value = self._format_answer(answer, record_type)
                records.append(DNSRecord(record_type, name or domain, value, ttl))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return records
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            if errors is not None:
                errors.append(f"{record_type}: {type(exc).__name__}")
        except Exception as exc:  # Resolver backends can raise implementation-specific errors.
            if errors is not None:
                errors.append(f"{record_type}: {exc}")
        return records

    @staticmethod
    def _format_answer(answer: Any, record_type: str) -> str:
        if record_type == "MX":
            return f"{answer.exchange.to_text(omit_final_dot=True)} (priority {answer.preference})"
        if record_type == "TXT" and hasattr(answer, "strings"):
            return "".join(part.decode(errors="replace") for part in answer.strings)
        return str(answer).rstrip(".") if record_type in {"NS", "CNAME", "PTR"} else str(answer)

    def get_nameservers(self, domain: str) -> List[str]:
        return [record.value for record in self._query_records(domain, "NS")]

    def get_mail_servers(self, domain: str) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        try:
            answers = self.resolver.resolve(domain, "MX")
            for answer in answers:
                records.append({
                    "server": answer.exchange.to_text(omit_final_dot=True),
                    "priority": int(answer.preference),
                    "ttl": int(getattr(getattr(answers, "rrset", None), "ttl", 0)),
                })
        except Exception:
            return records
        return records

    def reverse_lookup(self, ip: str) -> Optional[str]:
        try:
            reverse_name = reversename.from_address(ip)
            answers = self.resolver.resolve(reverse_name, "PTR")
            return str(answers[0]).rstrip(".")
        except Exception:
            return None

    def check_zone_transfer(self, domain: str) -> Dict[str, Any]:
        """Check AXFR only when explicitly invoked by the caller."""

        result: Dict[str, Any] = {"vulnerable": False, "records": [], "errors": []}
        nameservers = self.get_nameservers(domain)
        if not nameservers:
            result["errors"].append("No authoritative nameserver records found")
            return result

        for nameserver in nameservers:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=self.timeout))
                result["vulnerable"] = True
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        result["records"].append({
                            "name": str(name),
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "data": [str(rdata) for rdata in rdataset],
                        })
                break
            except Exception as exc:
                result["errors"].append(f"{nameserver}: {exc}")
        return result
