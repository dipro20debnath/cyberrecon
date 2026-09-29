"""Deployment and scan-readiness diagnostics."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Any

from cyberrecon.config import Config
from cyberrecon.integrations import ExternalIntelligence
from cyberrecon.modules.passive.ip_intelligence import IPIntelligence
from cyberrecon.utils.validators import TargetValidationError, normalize_target


API_PROVIDERS = ("virustotal", "urlscan", "securitytrails", "shodan", "censys", "ipinfo")


def _check(name: str, status: str, details: str) -> dict[str, str]:
    return {"name": name, "status": status, "details": details}


def run_diagnostics(config: Config, *, live_apis: bool = False, api_target: str = "example.com") -> list[dict[str, str]]:
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

    key_counts = {name: len(config.get_api_keys(name)) for name in ("virustotal", "urlscan", "securitytrails", "shodan", "censys", "ipinfo")}
    configured_keys = [name for name, count in key_counts.items() if count]
    total_slots = sum(key_counts.values())
    checks.append(_check("api_keys", "ok" if configured_keys else "warn", f"Configured optional providers: {len(configured_keys)}/6 ({total_slots} credential slot(s))"))

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
    if live_apis:
        checks.extend(_live_api_checks(config, api_target))
    return checks


def _live_api_checks(config: Config, target: str) -> list[dict[str, str]]:
    """Run opt-in, read-only provider checks without returning provider data."""

    configured = {name: len(config.get_api_keys(name)) for name in API_PROVIDERS}
    if not any(configured.values()):
        return [_check("api_live", "warn", "No optional API keys configured; nothing to validate")]
    try:
        normalize_target(target)
    except TargetValidationError as exc:
        return [_check("api_live", "fail", f"Invalid API validation target: {exc}")]

    checks: list[dict[str, str]] = []
    intelligence = ExternalIntelligence(config)
    result = intelligence.collect(target)
    sources = result.get("sources", {}) if isinstance(result.get("sources"), dict) else {}
    skipped = result.get("skipped", []) if isinstance(result.get("skipped"), list) else []
    rotation = result.get("credential_rotation", {}) if isinstance(result.get("credential_rotation"), dict) else {}

    for name in API_PROVIDERS[:-1]:
        if not configured[name]:
            continue
        target_skip = any(str(item).startswith(f"{name}:") and "target required" in str(item) for item in skipped)
        if target_skip:
            checks.append(_check(f"api_live.{name}", "warn", "Skipped: provider requires a different target type"))
            continue
        source = sources.get(name)
        if isinstance(source, dict) and source.get("error"):
            attempts = source.get("attempts", rotation.get(name, {}).get("attempts", 1))
            checks.append(_check(f"api_live.{name}", "fail", f"Provider request failed after {attempts} credential attempt(s)"))
            continue
        if name in sources:
            details = rotation.get(name, {}) if isinstance(rotation.get(name), dict) else {}
            slot = details.get("initial_key_slot", 1)
            attempts = details.get("attempts", 1)
            checks.append(_check(f"api_live.{name}", "ok", f"Read-only request succeeded via slot {slot} ({attempts} attempt(s))"))
        else:
            checks.append(_check(f"api_live.{name}", "fail", "Provider returned no result"))

    if configured["ipinfo"]:
        ip_result = IPIntelligence(
            config.get_api_keys("ipinfo"),
            timeout=config.timeout,
            retries=config.max_retries,
            rate_limit=config.rate_limit,
            user_agent=config.user_agent,
        ).lookup(target)
        errors = ip_result.get("errors", []) if isinstance(ip_result.get("errors"), list) else []
        records = ip_result.get("records", []) if isinstance(ip_result.get("records"), list) else []
        if records:
            checks.append(_check("api_live.ipinfo", "ok", f"Read-only request succeeded ({len(records)} record(s))"))
        elif errors:
            checks.append(_check("api_live.ipinfo", "fail", "Provider request failed; inspect provider status and key configuration"))
        else:
            checks.append(_check("api_live.ipinfo", "warn", "No IP intelligence record returned for target"))
    return checks


def diagnostics_summary(checks: list[dict[str, str]]) -> dict[str, int]:
    return {status: sum(item.get("status") == status for item in checks) for status in ("ok", "warn", "fail")}
