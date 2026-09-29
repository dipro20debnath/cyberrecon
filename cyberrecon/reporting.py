"""Report writers for JSON, CSV, PDF, Markdown, SARIF and HTML output."""

from __future__ import annotations

import csv
import json
import re
import textwrap
from html import escape
from pathlib import Path
from typing import Any

from cyberrecon.utils.serialization import to_jsonable
from cyberrecon.utils.validators import safe_filename


class ReportError(ValueError):
    """Raised when a report format is unsupported or cannot be written."""


FINDING_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def validate_min_severity(value: str) -> str:
    """Validate a presentation-filter threshold and return its normalized value."""

    level = value.strip().lower()
    if level not in FINDING_SEVERITY_RANK:
        raise ReportError("Minimum severity must be info, low, medium, high or critical")
    return level


def filter_findings(results: dict[str, Any], minimum: str) -> dict[str, Any]:
    """Return a report view containing findings at or above ``minimum``.

    The risk score is deliberately preserved because it was calculated from the
    complete scan.  The metadata makes that distinction explicit to consumers.
    """

    level = validate_min_severity(minimum)
    safe = to_jsonable(results)
    threshold = FINDING_SEVERITY_RANK[level]
    if not isinstance(safe.get("risk"), dict):
        safe["risk"] = {}
    risk = safe["risk"]
    indicators = risk.get("indicators", []) if isinstance(risk.get("indicators"), list) else []
    technology = safe.get("modules", {}).get("technology", {}) if isinstance(safe.get("modules"), dict) else {}
    security = technology.get("security", {}) if isinstance(technology, dict) else {}
    header_findings = security.get("findings", []) if isinstance(security, dict) and isinstance(security.get("findings"), list) else []

    def included(item: Any) -> bool:
        if not isinstance(item, dict):
            return False
        return FINDING_SEVERITY_RANK.get(str(item.get("severity", "info")).lower(), 0) >= threshold

    filtered_indicators = [item for item in indicators if included(item)]
    filtered_headers = [item for item in header_findings if included(item)]
    safe.setdefault("risk", {})["indicators"] = filtered_indicators
    if isinstance(technology, dict) and isinstance(security, dict):
        security["findings"] = filtered_headers
    safe["finding_filter"] = {
        "minimum_severity": level,
        "total_findings": len(indicators) + len(header_findings),
        "included_findings": len(filtered_indicators) + len(filtered_headers),
        "excluded_findings": len(indicators) + len(header_findings) - len(filtered_indicators) - len(filtered_headers),
        "note": "Presentation filter only; risk score remains calculated from the complete scan",
    }
    return safe


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
    posture = module.get("posture", {}) if isinstance(module.get("posture"), dict) else {}
    dnssec = posture.get("dnssec", {}) if isinstance(posture.get("dnssec"), dict) else {}
    caa = posture.get("caa", {}) if isinstance(posture.get("caa"), dict) else {}
    email = posture.get("email_authentication", {}) if isinstance(posture.get("email_authentication"), dict) else {}
    spf = email.get("spf", {}) if isinstance(email.get("spf"), dict) else {}
    dmarc = email.get("dmarc", {}) if isinstance(email.get("dmarc"), dict) else {}
    posture_rows = [
        ["DNSSEC", _badge("info" if dnssec.get("status") == "deployed" else "medium" if dnssec.get("status") == "key_material_detected" else "neutral"), escape(str(dnssec.get("status", "unknown")))],
        ["CAA policy", _badge("info" if caa.get("present") else "neutral"), escape(", ".join(map(str, caa.get("issuers", []))) or ("Present" if caa.get("present") else "Not detected"))],
        ["SPF", _badge("info" if spf.get("present") else "high" if email.get("mail_enabled") else "neutral"), escape("Present" if spf.get("present") else "Not detected")],
        ["DMARC", _badge("info" if dmarc.get("present") and dmarc.get("policy") != "none" else "medium" if email.get("mail_enabled") else "neutral"), escape(str(dmarc.get("policy") or ("Present" if dmarc.get("present") else "Not detected")))],
    ]
    return error_html + _table(["Type", "Value", "TTL"], rows, "No DNS records returned") + "<h3>DNS security posture</h3>" + _table(["Control", "Status", "Details"], posture_rows, "No DNS posture data")


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


def _render_web_metadata(module: dict[str, Any]) -> str:
    resources = module.get("resources", {}) if isinstance(module.get("resources"), dict) else {}
    resource_rows = []
    for name in ("security.txt", "robots.txt", "sitemap.xml"):
        item = resources.get(name, {}) if isinstance(resources.get(name), dict) else {}
        available = bool(item.get("available"))
        resource_rows.append([
            _badge("info" if available else "neutral"),
            escape(name),
            escape(str(item.get("status_code", "not requested"))),
            escape(str(item.get("content_type") or "unknown")),
            escape(str(item.get("bytes", 0))),
            escape(str(item.get("url") or "-")),
        ])

    robots = module.get("robots", {}) if isinstance(module.get("robots"), dict) else {}
    robots_rows = []
    for category in ("disallow", "allow", "sitemaps"):
        values = robots.get(category, [])
        for value in values if isinstance(values, list) else []:
            robots_rows.append([escape(category.title()), escape(str(value))])

    sitemap = module.get("sitemap", {}) if isinstance(module.get("sitemap"), dict) else {}
    sitemap_rows = [[escape(str(value))] for value in sitemap.get("locations", []) if value]
    security = module.get("security_txt", {}) if isinstance(module.get("security_txt"), dict) else {}
    security_rows = [[escape(str(key).replace("_", " ").title()), escape(str(value))] for key, value in security.items()]
    favicon = module.get("favicon", {}) if isinstance(module.get("favicon"), dict) else {}
    favicon_rows = []
    if favicon.get("available"):
        for key in ("source", "url", "format", "bytes", "md5", "sha256", "mmh3"):
            if key in favicon:
                favicon_rows.append([escape(key.replace("_", " ").title()), escape(str(favicon[key] if favicon[key] is not None else "-"))])
    errors = module.get("errors", [])
    error_html = f'<div class="callout warning">{escape("; ".join(map(str, errors)))}</div>' if errors else ""
    return (
        error_html
        + _table(["Status", "Resource", "HTTP", "Content type", "Bytes", "URL"], resource_rows, "No web metadata resources")
        + "<h3>Robots directives</h3>"
        + _table(["Directive", "Value"], robots_rows, "No robots directives found")
        + "<h3>Sitemap locations</h3>"
        + _table(["URL"], sitemap_rows, "No sitemap locations found")
        + "<h3>Security.txt fields</h3>"
        + _table(["Field", "Value"], security_rows, "No security.txt fields found")
        + "<h3>Favicon fingerprint</h3>"
        + _table(["Field", "Value"], favicon_rows, "No favicon detected")
    )


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
        ("Web metadata changes", "web_paths", ["kind", "value"], ["Change", "Source", "Value"]),
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
        _metric("Run ID", safe.get("run_id", "-")),
        _metric("Duration", f'{safe.get("duration_ms", "-")} ms'),
        _metric("Risk score", f"{score}/100", str(severity)),
        _metric("Risk level", str(severity).upper(), str(severity)),
        _metric("Errors", len(errors), "high" if errors else "low"),
    ])
    sections = [f'<section class="hero"><div><p class="eyebrow">CYBERRECON PRO REPORT</p><h1>{escape(target)}</h1><p class="muted">Generated {escape(str(safe.get("completed_at", safe.get("started_at", ""))))}</p></div><div class="risk-ring {escape(str(severity))}"><strong>{escape(str(score))}</strong><span>/100</span></div></section>', f'<div class="metrics">{cards}</div>']

    finding_filter = safe.get("finding_filter") if isinstance(safe.get("finding_filter"), dict) else None
    if finding_filter:
        sections.append(
            '<div class="callout info">Finding filter: showing '
            f"{escape(str(finding_filter.get('included_findings', 0)))} of {escape(str(finding_filter.get('total_findings', 0)))} "
            f"findings at or above {escape(str(finding_filter.get('minimum_severity', 'info')).upper())}. "
            "The risk score remains based on the complete scan.</div>"
        )
    if risk.get("indicators"):
        rows = [[_badge(item.get("severity")), escape(str(item.get("name", ""))), escape(str(item.get("message", item.get("ports", item.get("count", "")))))] for item in risk["indicators"]]
        sections.append(_module_section("Important findings", _table(["Severity", "Indicator", "Details"], rows), "findings"))
    if isinstance(safe.get("comparison"), dict):
        sections.append(_module_section("Changes since baseline", _render_comparison(safe["comparison"]), "comparison"))
    if errors:
        sections.append(_module_section("Scan errors", '<div class="callout danger">' + "<br>".join(escape(str(item)) for item in errors) + "</div>", "errors"))
    telemetry = safe.get("telemetry", {}) if isinstance(safe.get("telemetry"), dict) else {}
    durations = telemetry.get("module_durations_ms", {}) if isinstance(telemetry.get("module_durations_ms"), dict) else {}
    statuses = telemetry.get("module_status", {}) if isinstance(telemetry.get("module_status"), dict) else {}
    if durations:
        telemetry_rows = [[escape(str(name)), escape(str(duration)), _badge("info" if statuses.get(name) == "ok" else "high")] for name, duration in durations.items()]
        sections.append(_module_section("Execution telemetry", _table(["Stage", "Duration (ms)", "Status"], telemetry_rows), "telemetry"))
    if "dns" in modules:
        sections.append(_module_section("DNS records", _render_dns(modules["dns"]), "dns"))
    if "whois" in modules:
        sections.append(_module_section("WHOIS intelligence", _render_whois(modules["whois"]), "whois"))
    if "subdomains" in modules:
        sections.append(_module_section("Certificate Transparency subdomains", _render_subdomains(modules["subdomains"]), "subdomains"))
    if "technology" in modules:
        sections.append(_module_section("Technology and HTTP security", _render_technology(modules["technology"]), "technology"))
    if "web_metadata" in modules:
        sections.append(_module_section("Public web metadata", _render_web_metadata(modules["web_metadata"]), "web-metadata"))
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


def _pdf_literal(value: Any) -> str:
    """Return safe PDF literal text using the built-in Helvetica encoding."""

    text = str(value if value is not None else "-").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = text.encode("latin-1", "replace").decode("latin-1")
    return "(" + text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ")"


def _pdf_lines(results: dict[str, Any]) -> list[tuple[str, str]]:
    """Build concise high-signal lines for the dependency-free PDF renderer."""

    safe = to_jsonable(results)
    target = safe.get("target", "Unknown target")
    risk = safe.get("risk", {}) if isinstance(safe.get("risk"), dict) else {}
    modules = safe.get("modules", {}) if isinstance(safe.get("modules"), dict) else {}
    errors = safe.get("errors", []) if isinstance(safe.get("errors"), list) else []
    lines: list[tuple[str, str]] = []

    def heading(value: Any) -> None:
        lines.append(("heading", str(value)))

    def body(value: Any) -> None:
        for line in textwrap.wrap(
            str(value if value is not None else "-"),
            width=92,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]:
            lines.append(("body", line))

    heading("Executive summary")
    body(f"Target: {target}")
    body(f"Mode: {safe.get('mode', 'passive')} | Run ID: {safe.get('run_id', '-')} | Duration: {safe.get('duration_ms', '-')} ms")
    body(f"Risk: {risk.get('score', 0)}/100 ({str(risk.get('severity', 'unknown')).upper()}) | Errors: {len(errors)}")
    body(f"Generated: {safe.get('completed_at', safe.get('started_at', '-'))}")
    finding_filter = safe.get("finding_filter") if isinstance(safe.get("finding_filter"), dict) else None
    if finding_filter:
        body(
            f"Finding filter: {finding_filter.get('included_findings', 0)} of {finding_filter.get('total_findings', 0)} "
            f"findings at or above {str(finding_filter.get('minimum_severity', 'info')).upper()}. "
            "Risk score uses the complete scan."
        )

    indicators = risk.get("indicators", []) if isinstance(risk.get("indicators"), list) else []
    if indicators:
        heading("Important findings")
        for item in indicators:
            if isinstance(item, dict):
                detail = item.get("message", item.get("ports", item.get("count", "")))
                body(f"[{str(item.get('severity', 'unknown')).upper()}] {item.get('name', 'indicator')}: {detail}")

    comparison = safe.get("comparison") if isinstance(safe.get("comparison"), dict) else None
    if comparison:
        summary = comparison.get("summary", {}) if isinstance(comparison.get("summary"), dict) else {}
        heading("Changes since baseline")
        body(f"Added: {summary.get('added', 0)} | Removed: {summary.get('removed', 0)}")
        change_labels = {
            "dns": "DNS",
            "subdomains": "Subdomains",
            "technologies": "Technologies",
            "security_findings": "Security findings",
            "open_ports": "Open ports",
            "web_paths": "Web metadata",
        }
        for key, label in change_labels.items():
            value = comparison.get(key, {})
            if not isinstance(value, dict):
                continue
            added = value.get("added", []) if isinstance(value.get("added"), list) else []
            removed = value.get("removed", []) if isinstance(value.get("removed"), list) else []
            if added or removed:
                body(f"{label}: +{len(added)} / -{len(removed)}")

    telemetry = safe.get("telemetry", {}) if isinstance(safe.get("telemetry"), dict) else {}
    durations = telemetry.get("module_durations_ms", {}) if isinstance(telemetry.get("module_durations_ms"), dict) else {}
    if durations:
        heading("Execution telemetry")
        statuses = telemetry.get("module_status", {}) if isinstance(telemetry.get("module_status"), dict) else {}
        for name, duration in durations.items():
            body(f"{name}: {duration} ms ({statuses.get(name, 'unknown')})")

    dns = modules.get("dns") if isinstance(modules.get("dns"), dict) else None
    if dns:
        records = dns.get("records", {}) if isinstance(dns.get("records"), dict) else {}
        heading("DNS intelligence")
        body("Record counts: " + ", ".join(f"{name}={len(values) if isinstance(values, list) else 0}" for name, values in records.items()) or "No records")
        posture = dns.get("posture", {}) if isinstance(dns.get("posture"), dict) else {}
        if posture:
            dnssec = posture.get("dnssec", {}) if isinstance(posture.get("dnssec"), dict) else {}
            caa = posture.get("caa", {}) if isinstance(posture.get("caa"), dict) else {}
            email = posture.get("email_authentication", {}) if isinstance(posture.get("email_authentication"), dict) else {}
            spf = email.get("spf", {}) if isinstance(email.get("spf"), dict) else {}
            dmarc = email.get("dmarc", {}) if isinstance(email.get("dmarc"), dict) else {}
            body(f"DNSSEC: {dnssec.get('status', 'unknown')} | CAA: {', '.join(map(str, caa.get('issuers', []))) or 'not detected'}")
            body(f"SPF: {'present' if spf.get('present') else 'not detected'} | DMARC: {dmarc.get('policy') or ('present' if dmarc.get('present') else 'not detected')}")

    whois = modules.get("whois") if isinstance(modules.get("whois"), dict) else None
    if whois and isinstance(whois.get("data"), dict):
        heading("WHOIS intelligence")
        for key in ("registrar", "creation_date", "expiration_date", "country", "domain_age_days"):
            if key in whois["data"]:
                body(f"{key.replace('_', ' ').title()}: {whois['data'][key]}")

    subdomains = modules.get("subdomains") if isinstance(modules.get("subdomains"), dict) else None
    if subdomains:
        values = subdomains.get("subdomains", []) if isinstance(subdomains.get("subdomains"), list) else []
        heading("Certificate Transparency subdomains")
        body(f"Discovered: {subdomains.get('count', len(values))}")
        for value in values[:20]:
            body(f"- {value}")
        if len(values) > 20:
            body(f"... and {len(values) - 20} more")

    technology = modules.get("technology") if isinstance(modules.get("technology"), dict) else None
    if technology:
        heading("Technology and HTTP security")
        technologies = technology.get("technologies", []) if isinstance(technology.get("technologies"), list) else []
        body(f"Technologies: {', '.join(map(str, technologies)) or 'none detected'}")
        security = technology.get("security", {}) if isinstance(technology.get("security"), dict) else {}
        for item in security.get("findings", []) if isinstance(security.get("findings"), list) else []:
            if isinstance(item, dict):
                body(f"[{str(item.get('severity', 'unknown')).upper()}] {item.get('header', 'header')}: {item.get('message', '')}")

    tls = modules.get("tls") if isinstance(modules.get("tls"), dict) else None
    if tls:
        heading("TLS certificate")
        certificate = tls.get("certificate", {}) if isinstance(tls.get("certificate"), dict) else {}
        body(f"Reachable: {tls.get('reachable', False)} | Protocol: {tls.get('tls_version', 'unknown')} | Cipher: {tls.get('cipher', 'unknown')}")
        for key in ("subject", "issuer", "not_after", "days_until_expiry"):
            if key in certificate:
                body(f"{key.replace('_', ' ').title()}: {certificate[key]}")

    active = modules.get("active") if isinstance(modules.get("active"), dict) else None
    if active:
        heading("Active reconnaissance")
        ports = active.get("ports", {}).get("ports", []) if isinstance(active.get("ports"), dict) else []
        body(f"Open ports: {active.get('ports', {}).get('open_count', 0) if isinstance(active.get('ports'), dict) else 0}")
        for item in ports:
            if isinstance(item, dict) and item.get("state") == "open":
                body(f"{item.get('port')}: {item.get('service', 'unknown')} (open)")

    if errors:
        heading("Scan errors")
        for error in errors:
            body(f"- {error}")

    web_metadata = modules.get("web_metadata") if isinstance(modules.get("web_metadata"), dict) else None
    favicon = web_metadata.get("favicon", {}) if isinstance(web_metadata, dict) and isinstance(web_metadata.get("favicon"), dict) else {}
    if favicon.get("available"):
        heading("Favicon fingerprint")
        body(f"Format: {favicon.get('format', 'unknown')} | Bytes: {favicon.get('bytes', 0)} | Source: {favicon.get('source', '-')}")
        body(f"SHA-256: {favicon.get('sha256', '-')} | MD5: {favicon.get('md5', '-')} | MMH3: {favicon.get('mmh3', '-')}")
    return lines


def _write_pdf(path: Path, results: dict[str, Any]) -> None:
    """Write a readable multi-page PDF without external runtime dependencies."""

    lines = _pdf_lines(results)
    page_capacity = 47
    pages = [lines[index:index + page_capacity] for index in range(0, len(lines), page_capacity)] or [[("body", "No report data")]]
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    ]
    page_start = 5
    content_start = page_start + len(pages)
    page_refs = " ".join(f"{page_start + index} 0 R" for index in range(len(pages)))
    objects[1] = f"<< /Type /Pages /Kids [{page_refs}] /Count {len(pages)} >>".encode("ascii")

    page_objects: list[bytes] = []
    content_objects: list[bytes] = []
    target = str(to_jsonable(results).get("target", "Unknown target"))
    for index, page_lines in enumerate(pages):
        stream_lines = [
            "q 0.09 0.14 0.33 rg 0 748 612 44 re f Q",
            f"BT /F2 16 Tf 1 1 1 rg 1 0 0 1 46 764 Tm {_pdf_literal('CYBERRECON PRO')} Tj ET",
            f"BT /F1 8 Tf 0.82 0.87 0.95 rg 1 0 0 1 46 752 Tm {_pdf_literal(target)} Tj ET",
        ]
        y = 725
        for kind, line in page_lines:
            if kind == "heading":
                stream_lines.append(f"BT /F2 12 Tf 0.09 0.14 0.33 rg 1 0 0 1 46 {y} Tm {_pdf_literal(line)} Tj ET")
                y -= 19
            else:
                stream_lines.append(f"BT /F1 9 Tf 0.12 0.16 0.22 rg 1 0 0 1 52 {y} Tm {_pdf_literal(line)} Tj ET")
                y -= 13
        stream_lines.extend([
            "0.85 0.88 0.93 RG 46 43 520 0.5 re S",
            f"BT /F1 8 Tf 0.39 0.45 0.55 rg 1 0 0 1 46 28 Tm {_pdf_literal(f'CyberRecon Pro | Page {index + 1} of {len(pages)}')} Tj ET",
        ])
        stream = ("\n".join(stream_lines) + "\n").encode("latin-1", "replace")
        content_objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"endstream")
        page_objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_start + index} 0 R >>".encode("ascii")
        )
    objects.extend(page_objects)
    objects.extend(content_objects)

    document = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(document))
        document.extend(f"{number} 0 obj\n".encode("ascii"))
        document.extend(obj)
        document.extend(b"\nendobj\n")
    xref_offset = len(document)
    document.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]:
        document.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    document.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
    path.write_bytes(document)


def _markdown_value(value: Any) -> str:
    return str(value if value is not None else "-").replace("|", "\\|").replace("\r", "").replace("\n", " ")


def _markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(_markdown_value(item) for item in headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(_markdown_value(item) for item in row) + " |" for row in rows)
    return lines


def _write_markdown(path: Path, results: dict[str, Any]) -> None:
    safe = to_jsonable(results)
    target = safe.get("target", "Unknown target")
    risk = safe.get("risk", {}) if isinstance(safe.get("risk"), dict) else {}
    lines = [
        "# CyberRecon Pro Report",
        "",
        f"**Target:** `{_markdown_value(target)}`  ",
        f"**Mode:** `{_markdown_value(safe.get('mode', 'passive'))}`  ",
        f"**Run ID:** `{_markdown_value(safe.get('run_id', '-'))}`  ",
        f"**Duration:** `{_markdown_value(safe.get('duration_ms', '-'))} ms`  ",
        f"**Generated:** `{_markdown_value(safe.get('completed_at', safe.get('started_at', '-')))}`",
        "",
        "## Risk summary",
        "",
    ]
    lines += _markdown_table(["Metric", "Value"], [["Score", f"{risk.get('score', 0)}/100"], ["Severity", risk.get("severity", "unknown")], ["Errors", len(safe.get("errors", []))]])
    finding_filter = safe.get("finding_filter") if isinstance(safe.get("finding_filter"), dict) else None
    if finding_filter:
        lines += ["", f"> Finding filter: showing **{finding_filter.get('included_findings', 0)}** of **{finding_filter.get('total_findings', 0)}** findings at or above **{finding_filter.get('minimum_severity', 'info').upper()}**. The risk score remains based on the complete scan."]
    indicators = risk.get("indicators", []) if isinstance(risk.get("indicators"), list) else []
    if indicators:
        lines += ["", "## Important findings", ""]
        lines += _markdown_table(["Severity", "Indicator", "Details"], [[item.get("severity", "unknown"), item.get("name", ""), item.get("message", item.get("ports", item.get("count", "")))] for item in indicators])

    modules = safe.get("modules", {}) if isinstance(safe.get("modules"), dict) else {}
    dns = modules.get("dns") if isinstance(modules.get("dns"), dict) else None
    if dns:
        lines += ["", "## DNS intelligence", ""]
        dns_rows = []
        for record_type, records in dns.get("records", {}).items() if isinstance(dns.get("records"), dict) else []:
            for record in records if isinstance(records, list) else []:
                if isinstance(record, dict):
                    dns_rows.append([record_type, record.get("name", ""), record.get("value", ""), record.get("ttl", "")])
        lines += _markdown_table(["Type", "Name", "Value", "TTL"], dns_rows)
        posture = dns.get("posture") if isinstance(dns.get("posture"), dict) else {}
        if posture:
            email = posture.get("email_authentication", {}) if isinstance(posture.get("email_authentication"), dict) else {}
            spf = email.get("spf", {}) if isinstance(email.get("spf"), dict) else {}
            dmarc = email.get("dmarc", {}) if isinstance(email.get("dmarc"), dict) else {}
            dnssec = posture.get("dnssec", {}) if isinstance(posture.get("dnssec"), dict) else {}
            caa = posture.get("caa", {}) if isinstance(posture.get("caa"), dict) else {}
            lines += ["", "### DNS security posture", ""]
            lines += _markdown_table(["Control", "Status"], [["DNSSEC", dnssec.get("status", "unknown")], ["CAA", ", ".join(caa.get("issuers", [])) or "Not detected"], ["SPF", "Present" if spf.get("present") else "Not detected"], ["DMARC", dmarc.get("policy") or ("Present" if dmarc.get("present") else "Not detected")]])

    web_metadata = modules.get("web_metadata") if isinstance(modules.get("web_metadata"), dict) else None
    favicon = web_metadata.get("favicon", {}) if isinstance(web_metadata, dict) and isinstance(web_metadata.get("favicon"), dict) else {}
    if favicon.get("available"):
        lines += ["", "## Favicon fingerprint", ""]
        lines += _markdown_table(
            ["Field", "Value"],
            [[key.replace("_", " ").title(), favicon.get(key, "-")] for key in ("source", "url", "format", "bytes", "md5", "sha256", "mmh3")],
        )

    comparison = safe.get("comparison") if isinstance(safe.get("comparison"), dict) else None
    if comparison:
        summary = comparison.get("summary", {}) if isinstance(comparison.get("summary"), dict) else {}
        lines += ["", "## Changes since baseline", "", f"Added: **{summary.get('added', 0)}**; Removed: **{summary.get('removed', 0)}**", ""]
        for key, value in comparison.items():
            if not isinstance(value, dict) or not (value.get("added") or value.get("removed")):
                continue
            lines += [f"### {key.replace('_', ' ').title()}", ""]
            rows = [["Added", item] for item in value.get("added", [])] + [["Removed", item] for item in value.get("removed", [])]
            lines += _markdown_table(["Change", "Value"], rows)

    if safe.get("errors"):
        lines += ["", "## Scan errors", ""]
        lines.extend(f"- {_markdown_value(error)}" for error in safe["errors"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sarif_level(severity: Any) -> str:
    return "error" if str(severity).lower() in {"high", "critical"} else "warning" if str(severity).lower() == "medium" else "note"


def _write_sarif(path: Path, results: dict[str, Any]) -> None:
    safe = to_jsonable(results)
    target = str(safe.get("target", "unknown"))
    uri = target if "://" in target else f"https://{target}"
    risk = safe.get("risk", {}) if isinstance(safe.get("risk"), dict) else {}
    findings: list[tuple[str, str, str, str]] = []

    for item in risk.get("indicators", []) if isinstance(risk.get("indicators"), list) else []:
        if not isinstance(item, dict):
            continue
        rule_id = f"risk.{item.get('name', 'indicator')}"
        details = item.get("message", item.get("ports", item.get("count", "")))
        findings.append((rule_id, str(item.get("severity", "low")), str(details), "heuristic risk indicator"))

    technology = safe.get("modules", {}).get("technology", {}) if isinstance(safe.get("modules"), dict) else {}
    security = technology.get("security", {}) if isinstance(technology, dict) else {}
    for item in security.get("findings", []) if isinstance(security, dict) and isinstance(security.get("findings"), list) else []:
        if not isinstance(item, dict):
            continue
        rule_id = f"http.{item.get('header', 'security-header')}"
        findings.append((rule_id, str(item.get("severity", "low")), str(item.get("message", "HTTP security finding")), "HTTP security header audit"))

    for error in safe.get("errors", []) if isinstance(safe.get("errors"), list) else []:
        findings.append(("scan.error", "high", str(error), "scan execution"))

    rules: dict[str, dict[str, Any]] = {}
    sarif_results = []
    for rule_id, severity, message, source in findings:
        normalized_id = re.sub(r"[^A-Za-z0-9_.-]", "-", rule_id)
        rules.setdefault(normalized_id, {"id": normalized_id, "shortDescription": {"text": normalized_id}, "properties": {"source": source}})
        sarif_results.append({
            "ruleId": normalized_id,
            "level": _sarif_level(severity),
            "message": {"text": message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
        })

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CyberRecon Pro", "version": str(safe.get("version", "unknown")), "rules": list(rules.values())}},
            "results": sarif_results,
            "properties": {"target": target, "run_id": safe.get("run_id"), "duration_ms": safe.get("duration_ms"), "risk_score": risk.get("score", 0), "risk_severity": risk.get("severity", "unknown")},
        }],
    }
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")


def write_report(results: dict[str, Any], output_dir: Path, target: str, fmt: str, suffix: str = "scan") -> Path:
    """Write a report and return its path."""

    fmt = fmt.lower().lstrip(".")
    fmt = {"markdown": "md"}.get(fmt, fmt)
    if fmt not in {"json", "csv", "html", "pdf", "md", "sarif"}:
        raise ReportError("Output format must be json, csv, html, pdf, md/markdown or sarif")
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
    elif fmt == "html":
        _write_html(path, safe_results)
    elif fmt == "pdf":
        _write_pdf(path, safe_results)
    elif fmt == "md":
        _write_markdown(path, safe_results)
    else:
        _write_sarif(path, safe_results)
    return path
