"""CI-friendly policy gates for scan and baseline comparison results."""

from __future__ import annotations

from typing import Any


class PolicyError(ValueError):
    """Raised when a policy option is invalid."""


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def validate_fail_level(value: str) -> str:
    level = value.strip().lower()
    if level not in SEVERITY_RANK:
        raise PolicyError("Fail level must be low, medium, high or critical")
    return level


def evaluate_gate(results: dict[str, Any], fail_on: str = "", fail_on_change: bool = False) -> list[str]:
    """Return human-readable failure reasons; an empty list means pass."""

    reasons: list[str] = []
    if fail_on.strip():
        threshold = validate_fail_level(fail_on)
        risk = results.get("risk", {}) if isinstance(results.get("risk"), dict) else {}
        severity = str(risk.get("severity", "low")).lower()
        if SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK[threshold]:
            reasons.append(f"risk severity {severity} meets/exceeds {threshold} threshold")

    if fail_on_change:
        comparison = results.get("comparison", {}) if isinstance(results.get("comparison"), dict) else {}
        summary = comparison.get("summary", {}) if isinstance(comparison.get("summary"), dict) else {}
        if summary.get("has_changes"):
            reasons.append(
                f"baseline changed (+{summary.get('added', 0)} / -{summary.get('removed', 0)})"
            )
    return reasons
