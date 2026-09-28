"""WHOIS lookup with JSON-safe and timezone-aware parsing."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import whois

from cyberrecon.utils.serialization import to_jsonable
from cyberrecon.utils.validators import TargetValidationError, normalize_target


class WHOISLookup:
    def lookup(self, target: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"target": target, "found": False, "data": {}, "error": None}
        try:
            info = normalize_target(target)
            if info.is_ip:
                result["error"] = "WHOIS lookup currently accepts domain targets only"
                return result
            record = whois.whois(info.value)
            result["target"] = info.value
            result["found"] = True
            result["data"] = self._parse_whois(record)
        except Exception as exc:
            result["error"] = str(exc)
        return result

    def _parse_whois(self, record: Any) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        fields = (
            "domain_name", "registrar", "creation_date", "expiration_date", "updated_date",
            "name_servers", "status", "emails", "dnssec", "org", "address", "city",
            "state", "zipcode", "country",
        )
        for field in fields:
            value = getattr(record, field, None)
            if value is not None:
                data[field] = to_jsonable(value)

        creation = self._first_datetime(getattr(record, "creation_date", None))
        if creation:
            now = datetime.now(timezone.utc)
            data["domain_age_days"] = max(0, (now - self._aware(creation)).days)
        return data

    @staticmethod
    def _first_datetime(value: Any) -> Optional[datetime]:
        if isinstance(value, datetime):
            return value
        if isinstance(value, (list, tuple)):
            return next((item for item in value if isinstance(item, datetime)), None)
        return None

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

    def get_registrar(self, domain: str) -> Optional[str]:
        result = self.lookup(domain)
        value = result.get("data", {}).get("registrar")
        return str(value) if value else None

    def is_expired(self, domain: str) -> Optional[bool]:
        try:
            info = normalize_target(domain)
            if info.is_ip:
                return None
            record = whois.whois(info.value)
            expiry = self._first_datetime(getattr(record, "expiration_date", None))
            return self._aware(expiry) < datetime.now(timezone.utc) if expiry else None
        except Exception:
            return None
