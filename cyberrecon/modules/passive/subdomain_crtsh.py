"""Certificate Transparency subdomain discovery via crt.sh."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests

from cyberrecon.utils.validators import TargetValidationError, normalize_target


class CrtshSubdomainFinder:
    def __init__(self, timeout: float = 10, session: Optional[requests.Session] = None, user_agent: str = "CyberRecon-Pro/1.0"):
        self.timeout = max(0.5, float(timeout))
        self.base_url = "https://crt.sh"
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": user_agent, "Accept": "application/json"})

    def find_subdomains(self, target: str, wildcard: bool = True) -> Dict[str, Any]:
        started = time.perf_counter()
        result: Dict[str, Any] = {
            "target": target,
            "subdomains": [],
            "certificates": [],
            "count": 0,
            "error": None,
            "duration_ms": 0,
        }
        try:
            info = normalize_target(target)
            if info.is_ip:
                result["error"] = "Certificate Transparency lookup requires a domain target"
                return result
            url = f"{self.base_url}/?q={quote(f'%.{info.value}', safe='')}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, list):
                raise ValueError("crt.sh returned an unexpected JSON structure")

            discovered: set[str] = set()
            certificates = []
            suffix = f".{info.value}"
            for entry in payload:
                if not isinstance(entry, dict):
                    continue
                for item in str(entry.get("name_value", "")).splitlines():
                    name = item.strip().lower().rstrip(".")
                    if name.startswith("*."):
                        if not wildcard:
                            continue
                        name = name[2:]
                    if name == info.value or name.endswith(suffix):
                        discovered.add(name)
                certificates.append({
                    "id": entry.get("id"),
                    "issuer_name": entry.get("issuer_name"),
                    "common_name": entry.get("common_name"),
                    "entry_timestamp": entry.get("entry_timestamp"),
                    "not_before": entry.get("not_before"),
                    "not_after": entry.get("not_after"),
                    "serial_number": entry.get("serial_number"),
                })
            result["target"] = info.value
            result["subdomains"] = sorted(discovered)
            result["certificates"] = certificates
            result["count"] = len(discovered)
        except TargetValidationError as exc:
            result["error"] = str(exc)
        except requests.RequestException as exc:
            result["error"] = f"Network error: {exc}"
        except ValueError as exc:
            result["error"] = str(exc)
        finally:
            result["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        return result

    def get_certificate_details(self, cert_id: int) -> Dict[str, Any]:
        url = f"{self.base_url}/?id={int(cert_id)}"
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return {"cert_id": int(cert_id), "url": url, "status_code": response.status_code}
        except requests.RequestException as exc:
            return {"cert_id": int(cert_id), "url": url, "error": str(exc)}
