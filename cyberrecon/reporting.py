"""Report writers for JSON, CSV and self-contained HTML output."""

from __future__ import annotations

import csv
import json
from html import escape
from pathlib import Path
from typing import Any

from cyberrecon.utils.serialization import to_jsonable
from cyberrecon.utils.validators import safe_filename


class ReportError(ValueError):
    """Raised when a report format is unsupported or cannot be written."""


def _flatten(value: Any, prefix: str = "") -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    value = to_jsonable(value)
    if isinstance(value, dict):
        for key, item in value.items():
            rows.extend(_flatten(item, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(value, list):
        rows.append((prefix, "list", json.dumps(value, ensure_ascii=False)))
    else:
        rows.append((prefix, type(value).__name__, "" if value is None else str(value)))
    return rows


def _badge(value: Any) -> str:
    text = str(value or "unknown").lower()
    css = text if text in {"low", "medium", "high", "critical", "info", "added", "removed", "changed"} else "neutral"
    return f'<span class="badge {css}">{escape(str(value or "unknown").upper())}</span>'


def _metric(label: str, value: Any, tone: str = "") -> str:
    return f'<div class="metric {escape(tone)}"><div class="metric-label">{escape(label)}</div><div class="metric-value">{escape(str(value))}</div></div>'


def _table(headers: list[str], rows: list[list[Any]], empty: str = "No data") -> str:
    if not rows:
        return f'<p class="muted">{escape(empty)}</p>'
    head = "".join(f"<th>{escape(str(item))}</th>" for item in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<div class=table-wrap><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def _module_section(title: str, content: str, anchor: str) -> str:
    return f'<section id="{escape(anchor)}"><h2>{escape(title)}</h2>{content}</section>'


def _render_dns(module: dict[str, Any]) -> str:
    rows: list[list[Any]] = []
    for record_type, records in module.get("records", {}).items():
        for record in records if isinstance(records, list) else []:
            if isinstance(record, dict):
                rows.append([escape(record_type), escape(str(record.get("value", ""))), escape(str(record.get("ttl", "")))])
            else:
                rows.append([escape(record_type), escape(str(record)), ""])
    errors = module.get("errors", [])
    error_html = f'<div class="callout warning">{escape("; ".join(map(str, errors)))}</div>' if errors else ""
    return error_html + _table(["Type", "Value", "TTL"], rows, "No DNS records returned")


def _render_whois(module: dict[str, Any]) -> str:
    data = module.get("data", {})
    fields = ("registrar", "creation_date", "expiration_date", "updated_date", "name_servers", "country", "domain_age_days")
    rows = [[escape(field.replace("_", " ").title()), escape(str(data[field]))] for field in fields if field in data]
    if module.get("error"):
        rows.append(["Error", escape(str(module["error"]))])
    return _table(["Field", "Value"], rows, "No WHOIS data returned")


def _render_subdomains(module: dict[str, Any]) -> str:
    domains = module.get("subdomains", [])
    count = module.get("count", len(domains) if isinstance(domains, list) else 0)
    items = "".join(f"<li>{escape(str(item))}</li>" for item in (domains[:100] if isinstance(domains, list) else []))
    more = f'<p class="muted">Showing first 100 of {escape(str(count))}.</p>' if count > 100 else ""
    return f'<div class="subdomain-count">{escape(str(count))} discovered</div><ul class="domain-list">{items or "<li class=muted>None discovered</li>"}</ul>{more}'


def _render_technology(module: dict[str, Any]) -> str:
    technologies = module.get("technologies", [])
    tech_html = " ".join(f'<span class="tag">{escape(str(item))}</span>' for item in technologies) or '<span class="muted">No technologies detected</span>'
    security = module.get("security", {})
    findings = security.get("findings", []) if isinstance(security, dict) else []
    finding_rows = [[_badge(item.get("severity")), escape(str(item.get("header", ""))), escape(str(item.get("message", "")))] for item in findings]
    return f'<div class="tag-list">{tech_html}</div><p>HTTP status: <strong>{escape(str(module.get("status_code", "unknown")))}</strong> | URL: <code>{escape(str(module.get("final_url") or module.get("url") or "unknown"))}</code></p><h3>Security findings</h3>{_table(["Severity", "Header", "Finding"], finding_rows, "No header findings")}'


def _render_tls(module: dict[str, Any]) -> str:
    certificate = module.get("certificate", {})
    rows = []
    for key in ("subject", "issuer", "not_before", "not_after", "days_until_expiry", "san"):
        if key in certificate:
            rows.append([escape(key.replace("_", " ").title()), escape(str(certificate[key]))])
    status = "Reachable" if module.get("reachable") else f'Unavailable: {module.get("error", "unknown error")}'
    return f'<p>Protocol: <strong>{escape(str(module.get("tls_version") or "unknown"))}</strong> | Cipher: <code>{escape(str(module.get("cipher") or "unknown"))}</code></p><p>Status: {_badge("info" if module.get("reachable") else "high")} {escape(status)}</p>{_table(["Certificate field", "Value"], rows, "No certificate details")}'


def _render_active(module: dict[str, Any]) -> str:
    ports = module.get("ports", {}).get("ports", []) if isinstance(module.get("ports"), dict) else []
    rows = [[escape(str(item.get("port"))), escape(str(item.get("service", "unknown"))), _badge("open" if item.get("state") == "open" else item.get("state"))] for item in ports if isinstance(item, dict)]
    open_count = module.get("ports", {}).get("open_count", 0) if isinstance(module.get("ports"), dict) else 0
    return f'<div class="callout info">{escape(str(open_count))} open ports found</div>{_table(["Port", "Service", "State"], rows, "No port data")}'


def _render_comparison(comparison: dict[str, Any]) -> str:
    """Render the high-signal changes between two reports."""

    summary = comparison.get("summary", {}) if isinstance(comparison.get("summary"), dict) else {}
    risk = comparison.get("risk", {}) if isinstance(comparison.get("risk"), dict) else {}
    tls = comparison.get("tls", {}) if isinstance(comparison.get("tls"), dict) else {}
    parts = [
        '<div class="metrics">' + "".join([
            _metric("Added", summary.get("added", 0), "low" if summary.get("added", 0) == 0 else "medium"),
            _metric("Removed", summary.get("removed", 0), "low" if summary.get("removed", 0) == 0 else "high"),
            _metric("Risk delta", risk.get("delta", "unknown"), "high" if isinstance(risk.get("delta"), (int, float)) and risk.get("delta", 0) > 0 else "low"),
            _metric("TLS days delta", tls.get("delta_days", "unknown"), "medium" if isinstance(tls.get("delta_days"), (int, float)) and tls.get("delta_days", 0) < 0 else "low"),
        ]) + "</div>"
    ]

    def change_rows(values: dict[str, Any], fields: list[str]) -> list[list[Any]]:
        rows: list[list[Any]] = []
        for label, css in (("Added", "added"), ("Removed", "removed")):
            for item in values.get(label.lower(), []) if isinstance(values, dict) else []:
                if isinstance(item, dict):
                    rows.append([_badge(css), *[escape(str(item.get(field, ""))) for field in fields]])
                else:
                    rows.append([_badge(css), escape(str(item))])
        return rows

    definitions = (
        ("DNS changes", "dns", ["type", "name", "value"], ["Change", "Type", "Name", "Value"]),
        ("Subdomain changes", "subdomains", [], ["Change", "Subdomain"]),
        ("Technology changes", "technologies", [], ["Change", "Technology"]),
        ("Security finding changes", "security_findings", ["severity", "header", "message"], ["Change", "Severity", "Header", "Finding"]),
        ("Open port changes", "open_ports", ["port", "service"], ["Change", "Port", "Service"]),
    )
    for title, key, fields, headers in definitions:
        values = comparison.get(key, {})
        rows = change_rows(values, fields)
        parts.append(f"<h3>{escape(title)}</h3>" + _table(headers, rows, "No changes detected"))

    baseline = comparison.get("risk", {}).get("baseline", {}) if isinstance(comparison.get("risk"), dict) else {}
    current = comparison.get("risk", {}).get("current", {}) if isinstance(comparison.get("risk"), dict) else {}
    parts.append(
        '<div class="callout info">Risk score: '
        f'{escape(str(baseline.get("score", "unknown")))} to {escape(str(current.get("score", "unknown")))}; '
        f'baseline severity {escape(str(baseline.get("severity", "unknown")))} to current severity '
        f'{escape(str(current.get("severity", "unknown")))}.</div>'
    )
    return "".join(parts)


def _write_html(path: Path, results: dict[str, Any]) -> None:
    safe = to_jsonable(results)
    target = str(safe.get("target", "Unknown target"))
    risk = safe.get("risk", {}) if isinstance(safe.get("risk"), dict) else {}
    modules = safe.get("modules", {}) if isinstance(safe.get("modules"), dict) else {}
    errors = safe.get("errors", [])
    score = risk.get("score", 0)
    severity = risk.get("severity", "low")
    cards = "".join([
        _metric("Target", target),
        _metric("Mode", safe.get("mode", "passive")),
        _metric("Risk score", f"{score}/100", str(severity)),
        _metric("Risk level", str(severity).upper(), str(severity)),
        _metric("Errors", len(errors), "high" if errors else "low"),
    ])
    sections = [f'<section class="hero"><div><p class="eyebrow">CYBERRECON PRO REPORT</p><h1>{escape(target)}</h1><p class="muted">Generated {escape(str(safe.get("completed_at", safe.get("started_at", ""))))}</p></div><div class="risk-ring {escape(str(severity))}"><strong>{escape(str(score))}</strong><span>/100</span></div></section>', f'<div class="metrics">{cards}</div>']

    if risk.get("indicators"):
        rows = [[_badge(item.get("severity")), escape(str(item.get("name", ""))), escape(str(item.get("message", item.get("ports", item.get("count", "")))))] for item in risk["indicators"]]
        sections.append(_module_section("Important findings", _table(["Severity", "Indicator", "Details"], rows), "findings"))
    if isinstance(safe.get("comparison"), dict):
        sections.append(_module_section("Changes since baseline", _render_comparison(safe["comparison"]), "comparison"))
    if errors:
        sections.append(_module_section("Scan errors", '<div class="callout danger">' + "<br>".join(escape(str(item)) for item in errors) + "</div>", "errors"))
    if "dns" in modules:
        sections.append(_module_section("DNS records", _render_dns(modules["dns"]), "dns"))
    if "whois" in modules:
        sections.append(_module_section("WHOIS intelligence", _render_whois(modules["whois"]), "whois"))
    if "subdomains" in modules:
        sections.append(_module_section("Certificate Transparency subdomains", _render_subdomains(modules["subdomains"]), "subdomains"))
    if "technology" in modules:
        sections.append(_module_section("Technology and HTTP security", _render_technology(modules["technology"]), "technology"))
    if "tls" in modules:
        sections.append(_module_section("TLS certificate", _render_tls(modules["tls"]), "tls"))
    if "active" in modules:
        sections.append(_module_section("Active reconnaissance", _render_active(modules["active"]), "active"))

    raw = escape(json.dumps(safe, indent=2, ensure_ascii=False, default=str))
    sections.append(f'<section><details><summary>Raw JSON data</summary><pre>{raw}</pre></details></section>')
    title = escape(target)
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberRecon - {title}</title>
<style>
:root{{--bg:#f3f6fb;--card:#fff;--ink:#152238;--muted:#64748b;--line:#dbe3ef;--blue:#2563eb;--green:#15803d;--yellow:#b45309;--red:#b91c1c;--purple:#7c3aed}}
*{{box-sizing:border-box}} body{{font:15px Inter,ui-sans-serif,system-ui,sans-serif;max-width:1280px;margin:0 auto;padding:28px;color:var(--ink);background:var(--bg)}}
h1{{margin:0;font-size:clamp(1.7rem,4vw,2.8rem);word-break:break-word}} h2{{margin-top:0;font-size:1.15rem}} h3{{font-size:1rem;margin-bottom:.6rem}} section,.metric{{background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:0 4px 18px #1e293b0b}} section{{margin:16px 0;padding:20px}} .hero{{display:flex;justify-content:space-between;gap:20px;align-items:center;background:linear-gradient(135deg,#172554,#2563eb);color:#fff;border:0}} .hero .muted{{color:#dbeafe}} .eyebrow{{font-size:.75rem;letter-spacing:.14em;opacity:.8}} .metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}} .metric{{padding:15px}} .metric-label{{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.05em}} .metric-value{{font-size:1.15rem;font-weight:700;margin-top:6px;word-break:break-word}} .metric.high .metric-value,.metric.critical .metric-value{{color:var(--red)}} .metric.medium .metric-value{{color:var(--yellow)}} .metric.low .metric-value{{color:var(--green)}} .risk-ring{{min-width:118px;height:118px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#ffffff22;border:7px solid #ffffff66}} .risk-ring strong{{font-size:2rem}} .risk-ring span{{font-size:.8rem}} .risk-ring.critical,.risk-ring.high{{border-color:#fecaca}} .risk-ring.medium{{border-color:#fde68a}} .risk-ring.low{{border-color:#bbf7d0}} .badge{{display:inline-block;border-radius:999px;padding:3px 8px;font-size:.7rem;font-weight:800;letter-spacing:.04em;background:#e2e8f0;color:#334155}} .badge.low{{background:#dcfce7;color:#166534}} .badge.medium{{background:#fef3c7;color:#92400e}} .badge.high,.badge.critical{{background:#fee2e2;color:#991b1b}} .badge.info{{background:#dbeafe;color:#1d4ed8}} .callout{{padding:12px 14px;border-radius:10px;margin:8px 0}} .callout.info{{background:#eff6ff;color:#1e40af}} .callout.warning{{background:#fffbeb;color:#92400e}} .callout.danger{{background:#fef2f2;color:#991b1b}} .muted{{color:var(--muted)}} .table-wrap{{overflow-x:auto}} table{{width:100%;border-collapse:collapse}} th,td{{padding:10px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}} th{{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}} code,pre{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}} code{{word-break:break-all}} pre{{white-space:pre-wrap;overflow:auto;background:#f8fafc;padding:14px;border-radius:10px;max-height:550px}} .tag-list{{display:flex;flex-wrap:wrap;gap:7px;margin:10px 0}} .tag{{padding:6px 10px;border-radius:8px;background:#ede9fe;color:#5b21b6;font-weight:600}} .subdomain-count{{font-size:1.6rem;font-weight:800;color:var(--blue)}} .domain-list{{columns:3;column-gap:25px;line-height:1.8;padding-left:20px}} details summary{{cursor:pointer;font-weight:700}} @media(max-width:700px){{body{{padding:14px}}.hero{{align-items:flex-start;flex-direction:column}}.domain-list{{columns:1}}}}
</style><style>.badge.added{{background:#dcfce7;color:#166534}} .badge.removed{{background:#fee2e2;color:#991b1b}} .badge.changed{{background:#fef3c7;color:#92400e}}</style></head><body>{''.join(sections)}</body></html>"""
    path.write_text(html, encoding="utf-8")


def write_report(results: dict[str, Any], output_dir: Path, target: str, fmt: str, suffix: str = "scan") -> Path:
    """Write a report and return its path."""

    fmt = fmt.lower().lstrip(".")
    if fmt not in {"json", "csv", "html"}:
        raise ReportError("Output format must be json, csv or html")
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{safe_filename(target)}_{safe_filename(suffix)}.{fmt}"
    safe_results = to_jsonable(results)

    if fmt == "json":
        path.write_text(json.dumps(safe_results, indent=2, ensure_ascii=False), encoding="utf-8")
    elif fmt == "csv":
        with path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(["field", "type", "value"])
            writer.writerows(_flatten(safe_results))
    else:
        _write_html(path, safe_results)
    return path
