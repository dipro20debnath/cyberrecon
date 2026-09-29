"""Scan history loading and filtering for operator-facing trend views."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cyberrecon.diffing import ComparisonError, discover_json_reports, load_json_report
from cyberrecon.utils.validators import TargetValidationError, normalize_target


class HistoryError(ValueError):
    """Raised when history filters are invalid."""


def collect_history(directory: Path, target: str = "", limit: int = 20) -> list[dict[str, Any]]:
    """Return valid JSON reports newest-first, optionally filtered by target."""

    if limit < 1 or limit > 500:
        raise HistoryError("History limit must be between 1 and 500")

    normalized_target = ""
    if target.strip():
        try:
            normalized_target = normalize_target(target).value
        except TargetValidationError as exc:
            raise HistoryError(str(exc)) from exc

    records: list[dict[str, Any]] = []
    for path in discover_json_reports(directory):
        try:
            report = load_json_report(path)
        except ComparisonError:
            continue
        report_target = str(report.get("target", ""))
        if normalized_target:
            try:
                if normalize_target(report_target).value != normalized_target:
                    continue
            except TargetValidationError:
                continue
        risk = report.get("risk", {}) if isinstance(report.get("risk"), dict) else {}
        comparison = report.get("comparison", {}) if isinstance(report.get("comparison"), dict) else {}
        summary = comparison.get("summary", {}) if isinstance(comparison.get("summary"), dict) else {}
        records.append({
            "path": path,
            "target": report_target,
            "completed_at": report.get("completed_at", report.get("started_at", "")),
            "mode": report.get("mode", "unknown"),
            "run_id": report.get("run_id", "-"),
            "risk_score": risk.get("score", "unknown"),
            "risk_severity": risk.get("severity", "unknown"),
            "duration_ms": report.get("duration_ms", report.get("telemetry", {}).get("total_duration_ms", "unknown") if isinstance(report.get("telemetry"), dict) else "unknown"),
            "errors": len(report.get("errors", [])) if isinstance(report.get("errors"), list) else 0,
            "changes": f"+{summary.get('added', 0)} / -{summary.get('removed', 0)}" if summary else "-",
        })
        if len(records) >= limit:
            break
    return records
