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


def _write_html(path: Path, results: dict[str, Any]) -> None:
    safe = to_jsonable(results)
    sections = []
    for name, value in safe.items():
        rendered = escape(json.dumps(value, indent=2, ensure_ascii=False, default=str))
        sections.append(f"<section><h2>{escape(str(name))}</h2><pre>{rendered}</pre></section>")
    title = escape(str(safe.get("target", "CyberRecon report")))
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberRecon - {title}</title>
<style>body{{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a;background:#f6f8fa}}
section{{background:#fff;border:1px solid #d0d7de;border-radius:8px;margin:1rem 0;padding:1rem}}
pre{{white-space:pre-wrap;overflow:auto;background:#f6f8fa;padding:1rem;border-radius:6px}}</style></head>
<body><h1>CyberRecon report</h1><p>Target: <strong>{title}</strong></p>{''.join(sections)}</body></html>"""
    path.write_text(html, encoding="utf-8")


def write_report(results: dict[str, Any], output_dir: Path, target: str, fmt: str) -> Path:
    """Write a report and return its path."""

    fmt = fmt.lower().lstrip(".")
    if fmt not in {"json", "csv", "html"}:
        raise ReportError("Output format must be json, csv or html")
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{safe_filename(target)}_scan.{fmt}"
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
