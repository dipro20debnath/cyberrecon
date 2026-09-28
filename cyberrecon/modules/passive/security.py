"""HTTP security-header and cookie posture analysis."""

from __future__ import annotations

from typing import Any, Mapping


class SecurityHeadersAuditor:
    REQUIRED = {
        "content-security-policy": ("medium", "Content-Security-Policy is missing"),
        "x-content-type-options": ("low", "X-Content-Type-Options is missing"),
        "x-frame-options": ("medium", "X-Frame-Options is missing"),
        "referrer-policy": ("low", "Referrer-Policy is missing"),
        "permissions-policy": ("low", "Permissions-Policy is missing"),
    }

    @classmethod
    def audit(cls, headers: Mapping[str, Any], final_url: str | None = None) -> dict[str, Any]:
        normalized = {str(key).lower(): str(value) for key, value in headers.items()}
        findings: list[dict[str, str]] = []
        present: dict[str, str] = {}
        for name, (severity, message) in cls.REQUIRED.items():
            if name == "x-frame-options" and "frame-ancestors" in normalized.get("content-security-policy", "").lower():
                present[name] = "satisfied by CSP frame-ancestors"
                continue
            if name in normalized:
                present[name] = normalized[name]
            else:
                findings.append({"severity": severity, "header": name, "message": message})

        is_https = bool(final_url and final_url.lower().startswith("https://"))
        if is_https and "strict-transport-security" not in normalized:
            findings.append({"severity": "medium", "header": "strict-transport-security", "message": "HSTS is missing on an HTTPS response"})
        if "server" in normalized:
            findings.append({"severity": "info", "header": "server", "message": "Server header is exposed"})
        if "x-powered-by" in normalized:
            findings.append({"severity": "low", "header": "x-powered-by", "message": "Technology disclosure header is exposed"})

        cookie_header = normalized.get("set-cookie", "")
        cookie_flags: dict[str, bool] = {}
        if cookie_header:
            cookie_flags = {
                "secure": "secure" in cookie_header.lower(),
                "httponly": "httponly" in cookie_header.lower(),
                "samesite": "samesite" in cookie_header.lower(),
            }
            for flag, present_flag in cookie_flags.items():
                if not present_flag:
                    findings.append({"severity": "medium", "header": "set-cookie", "message": f"Cookie is missing the {flag.capitalize()} flag"})

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        score = sum(severity_order[item["severity"]] for item in findings)
        return {
            "present": present,
            "findings": findings,
            "cookie_flags": cookie_flags,
            "score": score,
        }
