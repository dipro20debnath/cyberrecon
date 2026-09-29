"""Collect low-impact public web metadata from standard discovery files."""

from __future__ import annotations

import hashlib
import re
from html import unescape
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests

from cyberrecon.utils.http import JsonFileCache, JsonHttpClient
from cyberrecon.utils.validators import TargetValidationError, normalize_target


class WebMetadataCollector:
    """Inspect public discovery files and same-origin favicon fingerprints."""

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
            "favicon": self._empty_favicon(),
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

        favicon, homepage = self._fetch_favicon(info.value)
        if favicon is not None and self._is_success(favicon.get("status_code")) and favicon.get("content"):
            result["favicon"] = self._fingerprint_favicon(favicon, homepage)
        return result

    @staticmethod
    def _empty_favicon() -> dict[str, Any]:
        return {
            "available": False,
            "source": None,
            "url": None,
            "status_code": None,
            "content_type": None,
            "format": None,
            "bytes": 0,
            "md5": None,
            "sha256": None,
            "mmh3": None,
        }

    def _fetch_favicon(self, target: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Try the conventional path, then a same-origin HTML-declared icon."""

        last_error: Optional[str] = None
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}/favicon.ico"
            try:
                snapshot = self.client.get_bytes(
                    url,
                    cache_key=f"web-metadata:binary:{url}",
                    raise_for_status=False,
                )
                if self._is_success(snapshot.get("status_code")) and snapshot.get("content"):
                    return snapshot, "favicon.ico"
            except (requests.RequestException, RuntimeError) as exc:
                last_error = str(exc)

        homepage, homepage_error = self._fetch(target, "homepage", ("/",))
        if homepage is None:
            return None, homepage_error or last_error
        href = self._parse_favicon_href(str(homepage.get("text", "")))
        if not href:
            return None, homepage_error or last_error
        page_url = str(homepage.get("url") or f"https://{target}/")
        icon_url = urljoin(page_url, href)
        parsed_icon = urlparse(icon_url)
        parsed_page = urlparse(page_url)
        if parsed_icon.scheme not in {"http", "https"} or parsed_icon.hostname != parsed_page.hostname:
            return None, "favicon link is not same-origin"
        try:
            snapshot = self.client.get_bytes(
                icon_url,
                cache_key=f"web-metadata:binary:{icon_url}",
                raise_for_status=False,
            )
        except (requests.RequestException, RuntimeError) as exc:
            return None, str(exc)
        if self._is_success(snapshot.get("status_code")) and snapshot.get("content"):
            return snapshot, f"html:{href}"
        return snapshot, homepage_error or last_error

    @staticmethod
    def _is_success(status_code: Any) -> bool:
        return isinstance(status_code, int) and 200 <= status_code < 400

    @staticmethod
    def _parse_favicon_href(text: str) -> Optional[str]:
        for tag in re.findall(r"<link\b[^>]*>", text, re.I):
            attributes = {
                key.lower(): unescape(value)
                for key, _, value in re.findall(r"([:\w-]+)\s*=\s*(['\"])(.*?)\2", tag, re.I)
            }
            rel = attributes.get("rel", "").lower().split()
            if attributes.get("href") and ("icon" in rel or any("icon" in token for token in rel)):
                return attributes["href"].strip()
        return None

    @classmethod
    def _fingerprint_favicon(cls, snapshot: dict[str, Any], source: Optional[str]) -> dict[str, Any]:
        content = bytes(snapshot.get("content", b"") or b"")
        return {
            "available": True,
            "source": source,
            "url": snapshot.get("url"),
            "status_code": snapshot.get("status_code"),
            "content_type": cls._content_type(snapshot.get("headers", {})),
            "format": cls._detect_image_format(content),
            "bytes": len(content),
            "md5": hashlib.md5(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
            "mmh3": cls._murmur3_32(content),
        }

    @staticmethod
    def _detect_image_format(content: bytes) -> Optional[str]:
        if content.startswith(b"\x00\x00\x01\x00"):
            return "ico"
        if content.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"
        if content.startswith((b"GIF87a", b"GIF89a")):
            return "gif"
        if content.startswith(b"\xff\xd8\xff"):
            return "jpeg"
        if content.startswith(b"RIFF") and content[8:12] == b"WEBP":
            return "webp"
        return "unknown"

    @staticmethod
    def _murmur3_32(content: bytes, seed: int = 0) -> int:
        """Return the signed x86_32 MurmurHash3 used by common favicon tooling."""

        hash_value = seed & 0xFFFFFFFF
        c1, c2 = 0xCC9E2D51, 0x1B873593
        rounded_end = len(content) & 0xFFFFFFFC
        for index in range(0, rounded_end, 4):
            block = int.from_bytes(content[index:index + 4], "little")
            block = (block * c1) & 0xFFFFFFFF
            block = ((block << 15) | (block >> 17)) & 0xFFFFFFFF
            block = (block * c2) & 0xFFFFFFFF
            hash_value ^= block
            hash_value = ((hash_value << 13) | (hash_value >> 19)) & 0xFFFFFFFF
            hash_value = (hash_value * 5 + 0xE6546B64) & 0xFFFFFFFF
        tail = content[rounded_end:]
        block = 0
        if len(tail) == 3:
            block ^= tail[2] << 16
        if len(tail) >= 2:
            block ^= tail[1] << 8
        if tail:
            block ^= tail[0]
            block = (block * c1) & 0xFFFFFFFF
            block = ((block << 15) | (block >> 17)) & 0xFFFFFFFF
            block = (block * c2) & 0xFFFFFFFF
            hash_value ^= block
        hash_value ^= len(content)
        hash_value ^= hash_value >> 16
        hash_value = (hash_value * 0x85EBCA6B) & 0xFFFFFFFF
        hash_value ^= hash_value >> 13
        hash_value = (hash_value * 0xC2B2AE35) & 0xFFFFFFFF
        hash_value ^= hash_value >> 16
        return hash_value if hash_value < 0x80000000 else hash_value - 0x100000000

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
