"""Optional external intelligence integrations.

All integrations are read-only lookups.  A missing key produces a skipped
result instead of an exception, so the core scanner remains useful offline.
"""

from __future__ import annotations

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

    def collect(self, target: str) -> dict[str, Any]:
        result: dict[str, Any] = {"target": target, "sources": {}, "skipped": []}
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
            if not self.config.get_api_key(name):
                result["skipped"].append(f"{name}: API key not configured")
                continue
            try:
                if name in {"securitytrails", "urlscan"} and info.is_ip:
                    result["skipped"].append(f"{name}: domain target required")
                    continue
                if name in {"shodan", "censys"} and info.is_domain:
                    result["skipped"].append(f"{name}: IP target required")
                    continue
                result["sources"][name] = function(info.value)
            except Exception as exc:
                result["sources"][name] = {"error": str(exc)}
        return result

    def _virustotal(self, target: str) -> Any:
        key = self.config.get_api_key("virustotal")
        kind = "domains" if not _looks_like_ip(target) else "ip_addresses"
        payload = self.client.get_json(
            f"https://www.virustotal.com/api/v3/{kind}/{target}",
            headers={"x-apikey": str(key), "accept": "application/json"},
            cache_key=f"virustotal:{kind}:{target}",
        )
        return _extract_data(payload)

    def _urlscan(self, target: str) -> Any:
        key = self.config.get_api_key("urlscan")
        payload = self.client.get_json(
            "https://urlscan.io/api/v1/search/",
            headers={"api-key": str(key), "accept": "application/json"},
            params={"q": f"domain:{target}", "size": 10},
            cache_key=f"urlscan:{target}",
        )
        return payload

    def _securitytrails(self, target: str) -> Any:
        key = self.config.get_api_key("securitytrails")
        return self.client.get_json(
            f"https://api.securitytrails.com/v1/domain/{target}/subdomains",
            headers={"APIKEY": str(key), "accept": "application/json"},
            cache_key=f"securitytrails:{target}",
        )

    def _shodan(self, target: str) -> Any:
        key = self.config.get_api_key("shodan")
        return self.client.get_json(
            f"https://api.shodan.io/shodan/host/{target}",
            params={"key": str(key), "minify": "true"},
            cache_key=f"shodan:{target}",
        )

    def _censys(self, target: str) -> Any:
        key = self.config.get_api_key("censys")
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
