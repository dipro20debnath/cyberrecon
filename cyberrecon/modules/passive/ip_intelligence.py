"""Optional IP intelligence through ipinfo.io."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Iterable, Optional

import requests

from cyberrecon.utils.validators import TargetValidationError, normalize_target


class IPIntelligence:
    def __init__(self, token: Optional[str] = None, timeout: float = 10, session: Optional[requests.Session] = None):
        self.token = token
        self.timeout = max(0.5, float(timeout))
        self.session = session or requests.Session()

    def lookup(self, target: str) -> dict[str, Any]:
        result: dict[str, Any] = {"target": target, "ips": [], "records": [], "errors": []}
        try:
            info = normalize_target(target)
        except TargetValidationError as exc:
            result["errors"].append(str(exc))
            return result

        addresses = [info.value] if info.is_ip else self._resolve(info.value, result["errors"])
        result["target"] = info.value
        result["ips"] = addresses
        if not self.token:
            result["errors"].append("IP intelligence token is not configured (set CR_IPINFO_API_KEY)")
            return result

        for address in addresses:
            try:
                ipaddress.ip_address(address)
                response = self.session.get(
                    f"https://ipinfo.io/{address}/json",
                    params={"token": self.token},
                    timeout=self.timeout,
                )
                response.raise_for_status()
                payload = response.json()
                if isinstance(payload, dict):
                    result["records"].append(payload)
            except (requests.RequestException, ValueError) as exc:
                result["errors"].append(f"{address}: {exc}")
        return result

    @staticmethod
    def _resolve(domain: str, errors: list[str]) -> list[str]:
        try:
            values = {
                item[4][0]
                for item in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
            }
            return sorted(values)
        except socket.gaierror as exc:
            errors.append(f"DNS resolution failed: {exc}")
            return []
