"""Compare reconnaissance reports for safe, repeatable change tracking."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from cyberrecon.utils.validators import normalize_target


class ComparisonError(ValueError):
    """Raised when reports cannot be compared safely."""


def discover_json_reports(directory: Path) -> list[Path]:
    """Return JSON reports newest-first without failing on an empty directory."""

    if not directory.exists():
        return []
    candidates = [path for path in directory.glob("*.json") if path.is_file()]
    return sorted(candidates, key=lambda path: path.stat().st_mtime, reverse=True)


def load_json_report(path: Path) -> dict[str, Any]:
    """Load and validate a JSON report from disk."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ComparisonError(f"Baseline/current report not found: {path}") from exc
    except OSError as exc:
        raise ComparisonError(f"Could not read report {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ComparisonError(f"Invalid JSON report {path}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ComparisonError(f"Report must contain a JSON object: {path}")
    if not payload.get("target"):
        raise ComparisonError(f"Report has no target: {path}")
    return payload


def _module(report: dict[str, Any], name: str) -> dict[str, Any]:
    modules = report.get("modules", {})
    value = modules.get(name, {}) if isinstance(modules, dict) else {}
    return value if isinstance(value, dict) else {}


def _sorted_strings(values: Iterable[Any]) -> list[str]:
    return sorted({str(value) for value in values if value is not None}, key=str.casefold)


def _dns_records(report: dict[str, Any]) -> list[dict[str, str]]:
    records = _module(report, "dns").get("records", {})
    if not isinstance(records, dict):
        return []
    normalized: dict[tuple[str, str, str], dict[str, str]] = {}
    for record_type, values in records.items():
        entries = values if isinstance(values, list) else [values]
        for entry in entries:
            if isinstance(entry, dict):
                value = entry.get("value", entry.get("data", ""))
                name = entry.get("name", "")
            else:
                value = entry
                name = ""
            item = {
                "type": str(record_type),
                "name": str(name),
                "value": str(value),
            }
            normalized[(item["type"], item["name"], item["value"])] = item
    return sorted(normalized.values(), key=lambda item: (item["type"], item["name"], item["value"]))


def _subdomains(report: dict[str, Any]) -> list[str]:
    values = _module(report, "subdomains").get("subdomains", [])
    return _sorted_strings(values if isinstance(values, list) else [])


def _technologies(report: dict[str, Any]) -> list[str]:
    values = _module(report, "technology").get("technologies", [])
    return _sorted_strings(values if isinstance(values, list) else [])


def _security_findings(report: dict[str, Any]) -> list[dict[str, str]]:
    security = _module(report, "technology").get("security", {})
    findings = security.get("findings", []) if isinstance(security, dict) else []
    normalized: dict[tuple[str, str, str], dict[str, str]] = {}
    for finding in findings if isinstance(findings, list) else []:
        if not isinstance(finding, dict):
            continue
        item = {
            "severity": str(finding.get("severity", "info")),
            "header": str(finding.get("header", "")),
            "message": str(finding.get("message", "")),
        }
        normalized[(item["severity"], item["header"], item["message"])] = item
    return sorted(normalized.values(), key=lambda item: (item["severity"], item["header"], item["message"]))


def _open_ports(report: dict[str, Any]) -> list[dict[str, Any]]:
    active = _module(report, "active")
    port_data = active.get("ports", {})
    values = port_data.get("ports", []) if isinstance(port_data, dict) else []
    normalized: dict[tuple[int, str], dict[str, Any]] = {}
    for entry in values if isinstance(values, list) else []:
        if not isinstance(entry, dict) or entry.get("state") != "open":
            continue
        try:
            port = int(entry.get("port"))
        except (TypeError, ValueError):
            continue
        service = str(entry.get("service", "unknown"))
        normalized[(port, service)] = {"port": port, "service": service}
    return [normalized[key] for key in sorted(normalized)]


def _web_paths(report: dict[str, Any]) -> list[dict[str, str]]:
    module = _module(report, "web_metadata")
    values: set[tuple[str, str]] = set()
    robots = module.get("robots", {})
    if isinstance(robots, dict):
        for category in ("disallow", "allow", "sitemaps"):
            entries = robots.get(category, [])
            for entry in entries if isinstance(entries, list) else []:
                values.add((f"robots:{category}", str(entry)))
    sitemap = module.get("sitemap", {})
    if isinstance(sitemap, dict):
        for entry in sitemap.get("locations", []) if isinstance(sitemap.get("locations", []), list) else []:
            values.add(("sitemap:location", str(entry)))
    security = module.get("security_txt", {})
    if isinstance(security, dict):
        for key, value in security.items():
            entries = value if isinstance(value, list) else [value]
            for entry in entries:
                values.add((f"security.txt:{key}", str(entry)))
    return [{"kind": kind, "value": value} for kind, value in sorted(values)]


def _set_diff(baseline: Iterable[Any], current: Iterable[Any]) -> dict[str, list[Any]]:
    before = set(baseline)
    after = set(current)
    return {"added": sorted(after - before), "removed": sorted(before - after)}


def _dict_diff(baseline: list[dict[str, Any]], current: list[dict[str, Any]], keys: tuple[str, ...]) -> dict[str, list[dict[str, Any]]]:
    def key(item: dict[str, Any]) -> tuple[Any, ...]:
        return tuple(item.get(field) for field in keys)

    before = {key(item): item for item in baseline}
    after = {key(item): item for item in current}
    added = [after[item] for item in sorted(set(after) - set(before))]
    removed = [before[item] for item in sorted(set(before) - set(after))]
    return {"added": added, "removed": removed}


def _number(value: Any) -> float | int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return int(number) if number.is_integer() else number


def _risk(report: dict[str, Any]) -> dict[str, Any]:
    risk = report.get("risk", {})
    risk = risk if isinstance(risk, dict) else {}
    return {
        "score": _number(risk.get("score")),
        "severity": str(risk.get("severity", "unknown")),
    }


def _tls_expiry(report: dict[str, Any]) -> float | int | None:
    certificate = _module(report, "tls").get("certificate", {})
    if not isinstance(certificate, dict):
        return None
    return _number(certificate.get("days_until_expiry"))


def _metadata(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "target": str(report.get("target", "")),
        "started_at": report.get("started_at"),
        "completed_at": report.get("completed_at"),
        "risk": _risk(report),
    }


def compare_reports(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON-safe comparison report for the same target."""

    try:
        baseline_target = normalize_target(str(baseline.get("target", ""))).value
        current_target = normalize_target(str(current.get("target", ""))).value
    except Exception as exc:  # validators expose several useful ValueError subclasses
        raise ComparisonError(f"Both reports must contain valid targets: {exc}") from exc
    if baseline_target != current_target:
        raise ComparisonError(f"Reports target different assets: {baseline_target} vs {current_target}")

    dns_before = _dns_records(baseline)
    dns_after = _dns_records(current)
    subdomains_before = _subdomains(baseline)
    subdomains_after = _subdomains(current)
    technologies_before = _technologies(baseline)
    technologies_after = _technologies(current)
    findings_before = _security_findings(baseline)
    findings_after = _security_findings(current)
    ports_before = _open_ports(baseline)
    ports_after = _open_ports(current)

    before_risk = _risk(baseline)
    after_risk = _risk(current)
    risk_delta = None
    if before_risk["score"] is not None and after_risk["score"] is not None:
        risk_delta = after_risk["score"] - before_risk["score"]

    before_tls = _tls_expiry(baseline)
    after_tls = _tls_expiry(current)
    tls_delta = None
    if before_tls is not None and after_tls is not None:
        tls_delta = after_tls - before_tls

    changes: dict[str, Any] = {
        "dns": _dict_diff(dns_before, dns_after, ("type", "name", "value")),
        "subdomains": _set_diff(subdomains_before, subdomains_after),
        "technologies": _set_diff(technologies_before, technologies_after),
        "security_findings": _dict_diff(findings_before, findings_after, ("severity", "header", "message")),
        "open_ports": _dict_diff(ports_before, ports_after, ("port", "service")),
        "web_paths": _dict_diff(_web_paths(baseline), _web_paths(current), ("kind", "value")),
        "risk": {
            "baseline": before_risk,
            "current": after_risk,
            "delta": risk_delta,
            "changed": risk_delta not in (None, 0),
        },
        "tls": {
            "baseline_days_until_expiry": before_tls,
            "current_days_until_expiry": after_tls,
            "delta_days": tls_delta,
            "changed": tls_delta not in (None, 0),
        },
    }
    added = sum(len(item.get("added", [])) for item in changes.values() if isinstance(item, dict) and "added" in item)
    removed = sum(len(item.get("removed", [])) for item in changes.values() if isinstance(item, dict) and "removed" in item)
    changes["summary"] = {
        "added": added,
        "removed": removed,
        "risk_changed": changes["risk"]["changed"],
        "tls_changed": changes["tls"]["changed"],
        "has_changes": bool(added or removed or changes["risk"]["changed"] or changes["tls"]["changed"]),
    }

    return {
        "tool": current.get("tool", "CyberRecon Pro"),
        "version": current.get("version"),
        "report_type": "comparison",
        "target": current_target,
        "mode": "comparison",
        "started_at": current.get("started_at"),
        "completed_at": current.get("completed_at"),
        "baseline": _metadata(baseline),
        "current": _metadata(current),
        "comparison": changes,
        "risk": current.get("risk", {}),
        "modules": current.get("modules", {}),
        "errors": current.get("errors", []),
    }
