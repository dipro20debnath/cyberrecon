"""Input validation and safe target handling."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


class TargetValidationError(ValueError):
    """Raised when a scan target is invalid or not allowed."""


@dataclass(frozen=True)
class TargetInfo:
    value: str
    kind: str

    @property
    def is_domain(self) -> bool:
        return self.kind == "domain"

    @property
    def is_ip(self) -> bool:
        return self.kind == "ip"


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def normalize_target(raw: str) -> TargetInfo:
    """Normalize a domain/IP and reject shell/path-like input."""

    target = str(raw or "").strip().lower().rstrip(".")
    if not target or any(char.isspace() for char in target) or "/" in target or "\\" in target:
        raise TargetValidationError("Target must be a domain name or IP address")

    try:
        return TargetInfo(str(ipaddress.ip_address(target)), "ip")
    except ValueError:
        pass

    if len(target) > 253 or "." not in target:
        raise TargetValidationError("Target must be a fully-qualified domain name or IP address")

    try:
        ascii_domain = target.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetValidationError("Target contains invalid domain characters") from exc

    labels = ascii_domain.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise TargetValidationError("Target contains an invalid domain label")
    return TargetInfo(ascii_domain, "domain")


def is_private_or_local(target: str) -> bool:
    """Return whether an IP is private, loopback, link-local or unspecified."""

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return False
    return bool(address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified)


def is_allowed_active_target(target: TargetInfo, allowed_targets: list[str]) -> bool:
    """Match an active target against exact or ``*.example.com`` allowlists."""

    value = target.value.lower()
    for allowed in allowed_targets:
        candidate = allowed.strip().lower().rstrip(".")
        if candidate == value:
            return True
        if candidate.startswith("*.") and target.is_domain and value.endswith(candidate[1:]):
            return True
    return False


def safe_filename(value: str, fallback: str = "scan") -> str:
    """Create a filesystem-safe report stem."""

    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value)).strip("._")
    return (cleaned or fallback)[:180]
