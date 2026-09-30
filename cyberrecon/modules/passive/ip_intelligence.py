"""Optional IP intelligence through ipinfo.io."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from typing import Any, Iterable, Optional

import requests

from cyberrecon import DEFAULT_USER_AGENT
from cyberrecon.utils.http import JsonFileCache, JsonHttpClient
from cyberrecon.utils.validators import TargetValidationError, normalize_target


class IPIntelligence:
    def __init__(self, token: Optional[str | list[str]] = None, timeout: float = 10, session: Optional[requests.Session] = None, retries: int = 2, rate_limit: float = 0.0, cache: Optional[JsonFileCache] = None, user_agent: str = DEFAULT_USER_AGENT):
        if isinstance(token, list):
            self.tokens = self._normalize_tokens(token)
        else:
            self.tokens = self._normalize_tokens([token] if token else [])
        self.token = self.tokens[0] if self.tokens else None
        self.timeout = max(0.5, float(timeout))
        self.session = session or requests.Session()
        self.client = JsonHttpClient(timeout=self.timeout, retries=retries, rate_limit=rate_limit, user_agent=user_agent, cache=cache, session=self.session)

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
        if not self.tokens:
            result["errors"].append("IP intelligence token is not configured (set CR_IPINFO_API_KEY)")
            return result

        for address in addresses:
            try:
                ipaddress.ip_address(address)
            except ValueError as exc:
                result["errors"].append(f"{address}: {exc}")
                continue
            order = self._token_order(address)
            last_error: Optional[Exception] = None
            attempts = 0
            for position, token_index in enumerate(order):
                attempts += 1
                try:
                    payload = self.client.get_json(
                        f"https://ipinfo.io/{address}/json",
                        params={"token": self.tokens[token_index]},
                        cache_key=f"ipinfo:{address}",
                    )
                    if isinstance(payload, dict):
                        result["records"].append(payload)
                    last_error = None
                    break
                except (requests.RequestException, RuntimeError) as exc:
                    last_error = exc
                    if position == len(order) - 1 or not self._should_rotate(exc):
                        break
            result.setdefault("credential_rotation", {})[address] = {
                "key_count": len(self.tokens),
                "initial_key_slot": order[0] + 1,
                "attempts": attempts,
                "fallback_used": attempts > 1,
            }
            if last_error is not None:
                result["errors"].append(f"{address}: {self._redact_error(last_error)}")
        return result

    def _token_order(self, address: str) -> list[int]:
        digest = hashlib.sha256(address.encode("utf-8")).digest()
        start = int.from_bytes(digest[:8], "big") % len(self.tokens)
        return [(start + offset) % len(self.tokens) for offset in range(len(self.tokens))]

    @staticmethod
    def _normalize_tokens(values: list[Any]) -> list[str]:
        result: list[str] = []
        for value in values:
            normalized = str(value).strip()
            if normalized and normalized not in result:
                result.append(normalized)
        return result

    @staticmethod
    def _should_rotate(error: Exception) -> bool:
        message = str(error).lower()
        return bool(re.search(r"\b(401|403|429)\b", message)) or "rate limit" in message or "too many requests" in message

    def _redact_error(self, error: Exception) -> str:
        message = str(error)
        for token in self.tokens:
            message = message.replace(token, "[redacted]")
        return message

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
