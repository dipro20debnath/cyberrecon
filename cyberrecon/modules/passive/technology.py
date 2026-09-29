"""Low-impact HTTP technology fingerprinting."""

from __future__ import annotations

import re
from typing import Any, Optional

import requests

from cyberrecon.modules.passive.security import SecurityHeadersAuditor
from cyberrecon.utils.http import JsonFileCache, JsonHttpClient
from cyberrecon.utils.validators import TargetValidationError, normalize_target


class TechnologyDetector:
    SIGNATURES = {
        "WordPress": ("/wp-content/", "wp-includes", "wordpress"),
        "Drupal": ("drupal-settings-json", "sites/default/"),
        "Joomla": ("/media/system/js/", "joomla"),
        "React": ("data-reactroot", "_reactRootContainer", "react"),
        "Next.js": ("__next_data__", "_next/static"),
        "Vue.js": ("data-v-", "vue.js"),
        "Angular": ("ng-version", "angular.js"),
        "Bootstrap": ("bootstrap.min.css", "bootstrap.min.js"),
        "jQuery": ("jquery.min.js", "jquery.js"),
    }

    def __init__(self, timeout: float = 10, session: Optional[requests.Session] = None, user_agent: str = "CyberRecon-Pro/1.0", retries: int = 2, rate_limit: float = 0.0, cache: Optional[JsonFileCache] = None):
        self.timeout = max(0.5, float(timeout))
        self.session = session or requests.Session()
        self.client = JsonHttpClient(timeout=self.timeout, retries=retries, rate_limit=rate_limit, user_agent=user_agent, cache=cache, session=self.session)
        self.session.headers.update({"Accept": "text/html,application/xhtml+xml"})

    def detect(self, target: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "target": target,
            "url": None,
            "status_code": None,
            "final_url": None,
            "technologies": [],
            "headers": {},
            "security": {},
            "error": None,
        }
        try:
            info = normalize_target(target)
            host = info.value
            candidates = [f"https://{host}", f"http://{host}"]
        except TargetValidationError as exc:
            result["error"] = str(exc)
            return result

        response = None
        last_error: Optional[Exception] = None
        for url in candidates:
            try:
                response = self.client.get_text(url, cache_key=f"technology:{url}")
                break
            except (requests.RequestException, RuntimeError) as exc:
                last_error = exc
        if response is None:
            result["error"] = str(last_error or "HTTP request failed")
            return result

        body = str(response.get("text", ""))[:2_000_000]
        haystack = body.lower()
        detected: set[str] = set()
        for name, signatures in self.SIGNATURES.items():
            if any(signature.lower() in haystack for signature in signatures):
                detected.add(name)

        response_headers = response.get("headers", {})
        server = response_headers.get("Server")
        powered_by = response_headers.get("X-Powered-By")
        if server:
            detected.add(f"Server: {server}")
        if powered_by:
            detected.add(f"X-Powered-By: {powered_by}")

        generators = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
        detected.update(f"Generator: {generator}" for generator in generators)
        result.update({
            "url": candidates[0],
            "status_code": response.get("status_code"),
            "final_url": response.get("url"),
            "technologies": sorted(detected),
            "headers": {key: value for key, value in response_headers.items() if key.lower() in {"server", "x-powered-by", "content-type", "strict-transport-security"}},
            "security": SecurityHeadersAuditor.audit(response_headers, response.get("url", url)),
        })
        return result
