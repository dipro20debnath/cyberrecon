"""Collect low-impact public web metadata from standard discovery files."""

from __future__ import annotations

import re
from html import unescape
from typing import Any, Optional

import requests

from cyberrecon.utils.http import JsonFileCache, JsonHttpClient
from cyberrecon.utils.validators import TargetValidationError, normalize_target


class WebMetadataCollector:
    """Inspect security.txt, robots.txt and sitemap.xml with bounded GETs."""

    RESOURCE_PATHS = {
        "security.txt": ("/.well-known/security.txt", "/security.txt"),
        "robots.txt": ("/robots.txt",),
        "sitemap.xml": ("/sitemap.xml",),
    }

    def __init__(
        self,
        timeout: float = 10,
        session: Optional[requests.Session] = None,
        user_agent: str = "CyberRecon-Pro/1.0",
        retries: int = 2,
        rate_limit: float = 0.0,
        cache: Optional[JsonFileCache] = None,
    ):
        self.timeout = max(0.5, float(timeout))
        self.session = session or requests.Session()
        self.client = JsonHttpClient(
            timeout=self.timeout,
            retries=retries,
            rate_limit=rate_limit,
            user_agent=user_agent,
            cache=cache,
            session=self.session,
        )

    def collect(self, target: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "target": target,
            "resources": {},
            "robots": {"disallow": [], "allow": [], "sitemaps": []},
            "sitemap": {"locations": []},
            "security_txt": {},
            "errors": [],
        }
        try:
            info = normalize_target(target)
        except TargetValidationError as exc:
            result["errors"].append(str(exc))
            return result

        result["target"] = info.value
        for resource, paths in self.RESOURCE_PATHS.items():
            snapshot, error = self._fetch(info.value, resource, paths)
            if error:
                result["errors"].append(f"{resource}: {error}")
            if snapshot is None:
                result["resources"][resource] = {"available": False, "status_code": None, "url": None}
                continue

            text = str(snapshot.get("text", ""))
            status_code = snapshot.get("status_code")
            result["resources"][resource] = {
                "available": isinstance(status_code, int) and 200 <= status_code < 400,
                "status_code": status_code,
                "url": snapshot.get("url"),
                "content_type": self._content_type(snapshot.get("headers", {})),
                "bytes": len(text.encode("utf-8", errors="replace")),
                "line_count": len(text.splitlines()),
            }
            if resource == "robots.txt":
                result["robots"] = self._parse_robots(text)
            elif resource == "sitemap.xml":
                result["sitemap"] = self._parse_sitemap(text)
            else:
                result["security_txt"] = self._parse_security_txt(text)
        return result

    def _fetch(self, target: str, resource: str, paths: tuple[str, ...]) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        last_error: Optional[str] = None
        last_snapshot: Optional[dict[str, Any]] = None
        for path in paths:
            for scheme in ("https", "http"):
                url = f"{scheme}://{target}{path}"
                try:
                    snapshot = self.client.get_text(
                        url,
                        cache_key=f"web-metadata:{url}",
                        raise_for_status=False,
                    )
                    last_snapshot = snapshot
                    status_code = snapshot.get("status_code")
                    if isinstance(status_code, int) and 200 <= status_code < 400:
                        return snapshot, None
                except (requests.RequestException, RuntimeError) as exc:
                    last_error = str(exc)
        return last_snapshot, last_error

    @staticmethod
    def _content_type(headers: Any) -> Optional[str]:
        if not isinstance(headers, dict):
            return None
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                return str(value)
        return None

    @staticmethod
    def _parse_robots(text: str) -> dict[str, list[str]]:
        result = {"disallow": [], "allow": [], "sitemaps": []}
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            key, value = (part.strip() for part in line.split(":", 1))
            normalized = key.lower()
            if normalized == "disallow" and value:
                result["disallow"].append(value)
            elif normalized == "allow" and value:
                result["allow"].append(value)
            elif normalized == "sitemap" and value:
                result["sitemaps"].append(value)
        return {key: sorted(set(values))[:200] for key, values in result.items()}

    @staticmethod
    def _parse_sitemap(text: str) -> dict[str, list[str]]:
        locations = [unescape(value.strip()) for value in re.findall(r"<loc>\s*([^<]+?)\s*</loc>", text, re.I)]
        return {"locations": sorted(set(locations))[:500]}

    @staticmethod
    def _parse_security_txt(text: str) -> dict[str, Any]:
        fields: dict[str, list[str]] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, value = (part.strip() for part in line.split(":", 1))
            if key and value:
                fields.setdefault(key.lower(), []).append(value)
        return {key: values if len(values) > 1 else values[0] for key, values in sorted(fields.items())}
