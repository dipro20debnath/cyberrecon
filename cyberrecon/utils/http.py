"""Rate-limited, retrying and optionally cached HTTP JSON requests."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any, Optional

import requests


class JsonFileCache:
    def __init__(self, directory: Optional[Path] = None, ttl: int = 3600):
        self.directory = directory
        self.ttl = max(0, int(ttl))
        self._lock = threading.Lock()
        if directory:
            directory.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Optional[Path]:
        if not self.directory:
            return None
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.directory / f"{digest}.json"

    def get(self, key: str) -> Any:
        path = self._path(key)
        if not path or not path.exists() or self.ttl == 0:
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if time.time() - float(payload["created_at"]) <= self.ttl:
                return payload["value"]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        return None

    def set(self, key: str, value: Any) -> None:
        path = self._path(key)
        if not path or self.ttl == 0:
            return
        payload = {"created_at": time.time(), "value": value}
        with self._lock:
            try:
                path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            except (OSError, TypeError):
                return


class RateLimiter:
    def __init__(self, minimum_interval: float = 0.0):
        self.minimum_interval = max(0.0, float(minimum_interval))
        self._last_request = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            delay = self.minimum_interval - (time.monotonic() - self._last_request)
            if delay > 0:
                time.sleep(delay)
            self._last_request = time.monotonic()


class JsonHttpClient:
    def __init__(
        self,
        timeout: float = 10,
        retries: int = 2,
        rate_limit: float = 0.0,
        user_agent: str = "CyberRecon-Pro/1.0",
        cache: Optional[JsonFileCache] = None,
        session: Optional[requests.Session] = None,
    ):
        self.timeout = max(0.5, float(timeout))
        self.retries = max(0, int(retries))
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": user_agent, "Accept": "application/json"})
        self.rate_limiter = RateLimiter(rate_limit)
        self.cache = cache

    def get_json(self, url: str, *, headers: Optional[dict[str, str]] = None, params: Optional[dict[str, Any]] = None, cache_key: Optional[str] = None) -> Any:
        key = cache_key or f"GET {url} {sorted((params or {}).items())}"
        if self.cache:
            cached = self.cache.get(key)
            if cached is not None:
                return cached

        response = self._request(url, headers=headers, params=params)
        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        if self.cache:
            self.cache.set(key, payload)
        return payload

    def get_text(self, url: str, *, headers: Optional[dict[str, str]] = None, params: Optional[dict[str, Any]] = None, cache_key: Optional[str] = None, raise_for_status: bool = True) -> dict[str, Any]:
        """Fetch a text response with the same retry/rate-limit/cache policy."""

        key = cache_key or f"TEXT {url} {sorted((params or {}).items())}"
        if self.cache:
            cached = self.cache.get(key)
            if isinstance(cached, dict) and "text" in cached:
                return cached

        response = self._request(url, headers=headers, params=params, raise_for_status=raise_for_status)
        payload = {
            "text": str(getattr(response, "text", "")),
            "status_code": getattr(response, "status_code", None),
            "url": str(getattr(response, "url", url)),
            "headers": dict(getattr(response, "headers", {}) or {}),
        }
        if self.cache:
            self.cache.set(key, payload)
        return payload

    def get_bytes(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, Any]] = None,
        cache_key: Optional[str] = None,
        raise_for_status: bool = True,
    ) -> dict[str, Any]:
        """Fetch binary content while preserving the shared retry/cache policy."""

        key = cache_key or f"BYTES {url} {sorted((params or {}).items())}"
        if self.cache:
            cached = self.cache.get(key)
            if isinstance(cached, dict) and "content_b64" in cached:
                try:
                    return {
                        **cached,
                        "content": base64.b64decode(str(cached["content_b64"]), validate=True),
                    }
                except (ValueError, TypeError):
                    pass

        response = self._request(url, headers=headers, params=params, raise_for_status=raise_for_status)
        content = bytes(getattr(response, "content", b"") or b"")
        payload = {
            "content": content,
            "status_code": getattr(response, "status_code", None),
            "url": str(getattr(response, "url", url)),
            "headers": dict(getattr(response, "headers", {}) or {}),
        }
        if self.cache:
            self.cache.set(key, {
                "content_b64": base64.b64encode(content).decode("ascii"),
                "status_code": payload["status_code"],
                "url": payload["url"],
                "headers": payload["headers"],
            })
        return payload

    def _request(self, url: str, *, headers: Optional[dict[str, str]] = None, params: Optional[dict[str, Any]] = None, raise_for_status: bool = True) -> requests.Response:
        last_error: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                self.rate_limiter.wait()
                response = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
                if raise_for_status:
                    response.raise_for_status()
                return response
            except (requests.RequestException, ValueError) as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(min(8.0, 0.5 * (2**attempt)))
        raise RuntimeError(str(last_error or "HTTP request failed"))
