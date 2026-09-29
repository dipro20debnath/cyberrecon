"""Optional external intelligence integrations.

All integrations are read-only lookups.  A missing key produces a skipped
result instead of an exception, so the core scanner remains useful offline.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Optional

from cyberrecon.config import Config
from cyberrecon.utils.http import JsonFileCache, JsonHttpClient
from cyberrecon.utils.validators import TargetValidationError, normalize_target


class ExternalIntelligence:
    def __init__(self, config: Config):
        cache_dir = config.config_path.parent / ".cache" / "intel"
        cache = JsonFileCache(cache_dir, ttl=int(config.get("settings.cache_ttl", 3600)))
        self.client = JsonHttpClient(
            timeout=config.timeout,
            retries=config.max_retries,
            rate_limit=config.rate_limit,
            user_agent=config.user_agent,
            cache=cache,
        )
        self.config = config
        self._active_keys: dict[str, str] = {}

    def collect(self, target: str) -> dict[str, Any]:
        result: dict[str, Any] = {"target": target, "sources": {}, "skipped": [], "credential_rotation": {}}
        try:
            info = normalize_target(target)
        except TargetValidationError as exc:
            result["error"] = str(exc)
            return result

        integrations = (
            ("virustotal", self._virustotal),
            ("urlscan", self._urlscan),
            ("securitytrails", self._securitytrails),
            ("shodan", self._shodan),
            ("censys", self._censys),
        )
        for name, function in integrations:
            keys = self.config.get_api_keys(name)
            if not keys:
                result["skipped"].append(f"{name}: API key not configured")
                continue
            try:
                if name in {"securitytrails", "urlscan"} and info.is_ip:
                    result["skipped"].append(f"{name}: domain target required")
                    continue
                if name in {"shodan", "censys"} and info.is_domain:
                    result["skipped"].append(f"{name}: IP target required")
                    continue
                order = self._key_order(name, info.value, len(keys))
                attempts = 0
                last_error: Optional[Exception] = None
                for position, key_index in enumerate(order):
                    self._active_keys[name] = keys[key_index]
                    attempts += 1
                    try:
                        result["sources"][name] = function(info.value)
                        last_error = None
                        break
                    except Exception as exc:
                        last_error = exc
                        if position == len(order) - 1 or not self._should_rotate(exc):
                            break
                if last_error is not None:
                    result["sources"][name] = {"error": str(last_error), "attempts": attempts}
                result["credential_rotation"][name] = {
                    "key_count": len(keys),
                    "initial_key_slot": order[0] + 1,
                    "attempts": attempts,
                    "fallback_used": attempts > 1,
                }
            except Exception as exc:
                result["sources"][name] = {"error": str(exc)}
            finally:
                self._active_keys.pop(name, None)
        return result

    @staticmethod
    def _key_order(service: str, target: str, count: int) -> list[int]:
        """Distribute targets deterministically, then provide ordered fallbacks."""

        if count < 1:
            return []
        digest = hashlib.sha256(f"{service}:{target}".encode("utf-8")).digest()
        start = int.from_bytes(digest[:8], "big") % count
        return [(start + offset) % count for offset in range(count)]

    @staticmethod
    def _should_rotate(error: Exception) -> bool:
        message = str(error).lower()
        return bool(re.search(r"\b(401|403|429)\b", message)) or "rate limit" in message or "too many requests" in message

    def _current_key(self, service: str) -> Optional[str]:
        active = self._active_keys.get(service)
        if active:
            return active
        keys = self.config.get_api_keys(service)
        return keys[0] if keys else None

    def _virustotal(self, target: str) -> Any:
        key = self._current_key("virustotal")
        kind = "domains" if not _looks_like_ip(target) else "ip_addresses"
        payload = self.client.get_json(
            f"https://www.virustotal.com/api/v3/{kind}/{target}",
            headers={"x-apikey": str(key), "accept": "application/json"},
            cache_key=f"virustotal:{kind}:{target}",
        )
        return _extract_data(payload)

    def _urlscan(self, target: str) -> Any:
        key = self._current_key("urlscan")
        payload = self.client.get_json(
            "https://urlscan.io/api/v1/search/",
            headers={"api-key": str(key), "accept": "application/json"},
            params={"q": f"domain:{target}", "size": 10},
            cache_key=f"urlscan:{target}",
        )
        return payload

    def _securitytrails(self, target: str) -> Any:
        key = self._current_key("securitytrails")
        return self.client.get_json(
            f"https://api.securitytrails.com/v1/domain/{target}/subdomains",
            headers={"APIKEY": str(key), "accept": "application/json"},
            cache_key=f"securitytrails:{target}",
        )

    def _shodan(self, target: str) -> Any:
        key = self._current_key("shodan")
        return self.client.get_json(
            f"https://api.shodan.io/shodan/host/{target}",
            params={"key": str(key), "minify": "true"},
            cache_key=f"shodan:{target}",
        )

    def _censys(self, target: str) -> Any:
        key = self._current_key("censys")
        return self.client.get_json(
            f"https://api.platform.censys.io/v3/global/asset/host/{target}",
            headers={"Authorization": f"Bearer {key}", "accept": "application/json"},
            cache_key=f"censys:{target}",
        )


def _looks_like_ip(value: str) -> bool:
    return ":" in value or all(part.isdigit() for part in value.split("."))


def _extract_data(payload: Any) -> Any:
    if isinstance(payload, dict) and "data" in payload:
        data = payload["data"]
        if isinstance(data, dict) and isinstance(data.get("attributes"), dict):
            return {"id": data.get("id"), "type": data.get("type"), "attributes": data["attributes"]}
        return data
    return payload
