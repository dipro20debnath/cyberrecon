"""TLS certificate and protocol inspection."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Optional

from cyberrecon.utils.validators import TargetValidationError, normalize_target


class TLSInspector:
    def __init__(self, timeout: float = 10, context: Optional[ssl.SSLContext] = None):
        self.timeout = max(0.5, float(timeout))
        self.context = context or ssl.create_default_context()

    def inspect(self, target: str, port: int = 443) -> dict[str, Any]:
        result: dict[str, Any] = {
            "target": target,
            "port": int(port),
            "reachable": False,
            "certificate": {},
            "cipher": None,
            "tls_version": None,
            "error": None,
        }
        try:
            info = normalize_target(target)
        except TargetValidationError as exc:
            result["error"] = str(exc)
            return result

        try:
            with socket.create_connection((info.value, int(port)), timeout=self.timeout) as raw_socket:
                with self.context.wrap_socket(raw_socket, server_hostname=info.value) as tls_socket:
                    certificate = tls_socket.getpeercert()
                    result["reachable"] = True
                    result["tls_version"] = tls_socket.version()
                    result["cipher"] = tls_socket.cipher()
                    result["certificate"] = self._parse_certificate(certificate)
        except (OSError, ssl.SSLError, ValueError) as exc:
            result["error"] = str(exc)
        return result

    @staticmethod
    def _parse_certificate(certificate: dict[str, Any]) -> dict[str, Any]:
        if not certificate:
            return {}
        not_before = TLSInspector._parse_cert_time(certificate.get("notBefore"))
        not_after = TLSInspector._parse_cert_time(certificate.get("notAfter"))
        now = datetime.now(timezone.utc)
        parsed: dict[str, Any] = {
            "subject": TLSInspector._flatten_name(certificate.get("subject", ())),
            "issuer": TLSInspector._flatten_name(certificate.get("issuer", ())),
            "serial_number": certificate.get("serialNumber"),
            "version": certificate.get("version"),
            "san": [value for key, value in certificate.get("subjectAltName", ()) if key.lower() == "dns"],
            "not_before": not_before.isoformat() if not_before else certificate.get("notBefore"),
            "not_after": not_after.isoformat() if not_after else certificate.get("notAfter"),
        }
        if not_after:
            parsed["days_until_expiry"] = (not_after - now).days
        return parsed

    @staticmethod
    def _parse_cert_time(value: Any) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)
        except (TypeError, ValueError, OverflowError):
            return None

    @staticmethod
    def _flatten_name(value: Any) -> dict[str, str]:
        flattened: dict[str, str] = {}
        for item in value or ():
            for key, field_value in item:
                flattened[str(key)] = str(field_value)
        return flattened
