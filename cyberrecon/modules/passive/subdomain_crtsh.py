"""Certificate Transparency subdomain discovery via crt.sh."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests

from cyberrecon import DEFAULT_USER_AGENT
from cyberrecon.utils.validators import TargetValidationError, normalize_target
from cyberrecon.utils.http import JsonFileCache, JsonHttpClient


class CrtshSubdomainFinder:
    def __init__(self, timeout: float = 10, session: Optional[requests.Session] = None, user_agent: str = DEFAULT_USER_AGENT, retries: int = 2, rate_limit: float = 0.0, cache: Optional[JsonFileCache] = None):
        self.timeout = max(0.5, float(timeout))
        self.base_url = "https://crt.sh"
        self.session = session or requests.Session()
        self.client = JsonHttpClient(timeout=self.timeout, retries=retries, rate_limit=rate_limit, user_agent=user_agent, cache=cache, session=self.session)

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
            payload = self.client.get_json(url, cache_key=f"crtsh:{info.value}")
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
        except (requests.RequestException, RuntimeError) as exc:
            result["error"] = f"Network error: {exc}"
        except ValueError as exc:
            result["error"] = str(exc)
        finally:
            result["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        return result

    def get_certificate_details(self, cert_id: int) -> Dict[str, Any]:
        url = f"{self.base_url}/?id={int(cert_id)}"
        try:
            response = self.client.get_text(url, cache_key=f"crtsh:certificate:{int(cert_id)}")
            return {"cert_id": int(cert_id), "url": url, "status_code": response.get("status_code")}
        except (requests.RequestException, RuntimeError) as exc:
            return {"cert_id": int(cert_id), "url": url, "error": str(exc)}
