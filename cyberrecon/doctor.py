"""Deployment and scan-readiness diagnostics."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Any

from cyberrecon.config import Config


def _check(name: str, status: str, details: str) -> dict[str, str]:
    return {"name": name, "status": status, "details": details}


def run_diagnostics(config: Config) -> list[dict[str, str]]:
    """Return non-secret diagnostics suitable for terminal or JSON output."""

    checks: list[dict[str, str]] = []
    version = sys.version_info
    checks.append(_check("python", "ok" if version >= (3, 10) else "fail", f"{version.major}.{version.minor}.{version.micro}"))

    if config.config_path.exists():
        checks.append(_check("config", "ok", str(config.config_path)))
    else:
        checks.append(_check("config", "warn", f"Using defaults; file not found: {config.config_path}"))

    output_dir = config.output_dir
    if output_dir.exists() and output_dir.is_dir():
        writable = os.access(output_dir, os.W_OK)
        checks.append(_check("output", "ok" if writable else "fail", f"{output_dir} ({'writable' if writable else 'not writable'})"))
    else:
        checks.append(_check("output", "warn", f"Directory will be created on first report: {output_dir}"))

    dependency_modules = {
        "requests": "requests",
        "dnspython": "dns.resolver",
        "python-whois": "whois",
        "PyYAML": "yaml",
        "rich": "rich",
        "typer": "typer",
    }
    missing: list[str] = []
    for package, module in dependency_modules.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(package)
    checks.append(_check("dependencies", "fail" if missing else "ok", "Missing: " + ", ".join(missing) if missing else "All runtime dependencies import successfully"))

    configured_keys = [name for name in ("virustotal", "urlscan", "securitytrails", "shodan", "censys", "ipinfo") if config.get_api_key(name)]
    checks.append(_check("api_keys", "ok" if configured_keys else "warn", f"Configured optional providers: {len(configured_keys)}/6"))

    if config.active_enabled:
        if config.allowed_targets:
            checks.append(_check("active_scope", "ok", f"Active checks enabled for {len(config.allowed_targets)} allowlisted target(s)"))
        else:
            checks.append(_check("active_scope", "fail", "Active checks enabled but allowed_targets is empty"))
        missing_wordlists = []
        for key in ("wordlists.subdomains", "wordlists.dns", "wordlists.ports"):
            configured = config.get(key, "")
            path = config.config_path.parent / str(configured)
            if configured and not path.exists():
                missing_wordlists.append(str(path))
        checks.append(_check("wordlists", "fail" if missing_wordlists else "ok", "Missing: " + ", ".join(missing_wordlists) if missing_wordlists else "Configured active wordlists found"))
    else:
        checks.append(_check("active_scope", "ok", "Active checks disabled by configuration"))

    cache_dir = config.config_path.parent / ".cache"
    checks.append(_check("cache", "ok" if cache_dir.exists() or cache_dir.parent.exists() else "warn", str(cache_dir)))
    report_count = len(list(output_dir.glob("*.json"))) if output_dir.exists() else 0
    checks.append(_check("reports", "ok", f"{report_count} JSON report(s) available"))
    return checks


def diagnostics_summary(checks: list[dict[str, str]]) -> dict[str, int]:
    return {status: sum(item.get("status") == status for item in checks) for status in ("ok", "warn", "fail")}
