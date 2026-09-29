"""Scan orchestration for passive and explicitly authorized active checks."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Callable, Optional
from uuid import uuid4

from cyberrecon.config import Config
from cyberrecon.integrations import ExternalIntelligence
from cyberrecon.risk import assess
from cyberrecon.modules.active import PortScanner, SubdomainBruteForcer, require_active_authorization
from cyberrecon.modules.passive import DNSEnumerator, IPIntelligence, CrtshSubdomainFinder, TechnologyDetector, TLSInspector, WHOISLookup, WebMetadataCollector
from cyberrecon.utils.serialization import to_jsonable
from cyberrecon.utils.http import JsonFileCache
from cyberrecon.utils.validators import TargetValidationError, normalize_target


class ScanError(ValueError):
    """Raised when a scan request cannot be executed."""


ProgressCallback = Callable[[int, int, str], None]

PASSIVE_MODULES = ("dns", "whois", "subdomains", "ip_intelligence", "technology", "tls", "web_metadata", "external_intelligence")
ACTIVE_MODULES = ("active.ports", "active.subdomains", "active.zone_transfer", "active.screenshot")
MODULE_ALIASES = {"ports": "active.ports", "active_ports": "active.ports", "active_subdomains": "active.subdomains"}


class ReconScanner:
    def __init__(self, config: Config):
        self.config = config

    def scan(
        self,
        target: str,
        mode: str = "passive",
        confirm_active: bool = False,
        progress_callback: Optional[ProgressCallback] = None,
        only: Optional[str] = None,
        skip: Optional[str] = None,
    ) -> dict[str, Any]:
        mode = mode.lower().strip()
        if mode not in {"passive", "active", "full"}:
            raise ScanError("Mode must be passive, active or full")
        try:
            info = normalize_target(target)
        except TargetValidationError as exc:
            raise ScanError(str(exc)) from exc

        if mode in {"active", "full"}:
            require_active_authorization(info, self.config, confirm_active)

        stage_names = self._stage_names(info, mode, only=only, skip=skip)
        scan_started = perf_counter()
        total_stages = len(stage_names)
        completed_stages = 0
        self._emit_progress(progress_callback, completed_stages, total_stages, "Initializing scan")

        results: dict[str, Any] = {
            "tool": "CyberRecon Pro",
            "version": "1.9.0",
            "target": info.value,
            "target_type": info.kind,
            "mode": mode,
            "run_id": str(uuid4()),
            "scan_plan": {
                "stages": stage_names,
                "only": only or None,
                "skip": skip or None,
            },
            "started_at": datetime.now(timezone.utc).isoformat(),
            "modules": {},
            "errors": [],
            "telemetry": {"module_durations_ms": {}, "module_status": {}, "total_duration_ms": None},
        }

        http_cache = self._http_cache()
        passive_tasks = {
            "dns": lambda: DNSEnumerator(self.config.timeout).enumerate(info.value),
            "whois": lambda: WHOISLookup().lookup(info.value),
            "subdomains": lambda: CrtshSubdomainFinder(
                self.config.timeout,
                user_agent=self.config.user_agent,
                retries=self.config.max_retries,
                rate_limit=self.config.rate_limit,
                cache=http_cache,
            ).find_subdomains(info.value),
            "ip_intelligence": lambda: IPIntelligence(
                self.config.get_api_key("ipinfo"),
                self.config.timeout,
                retries=self.config.max_retries,
                rate_limit=self.config.rate_limit,
                cache=http_cache,
                user_agent=self.config.user_agent,
            ).lookup(info.value),
            "technology": lambda: TechnologyDetector(
                self.config.timeout,
                user_agent=self.config.user_agent,
                retries=self.config.max_retries,
                rate_limit=self.config.rate_limit,
                cache=http_cache,
            ).detect(info.value),
            "tls": lambda: TLSInspector(self.config.timeout).inspect(info.value),
            "web_metadata": lambda: WebMetadataCollector(
                self.config.timeout,
                user_agent=self.config.user_agent,
                retries=self.config.max_retries,
                rate_limit=self.config.rate_limit,
                cache=http_cache,
            ).collect(info.value),
            "external_intelligence": lambda: ExternalIntelligence(self.config).collect(info.value),
        }
        selected = set(stage_names)
        passive_tasks = {name: task for name, task in passive_tasks.items() if name in selected}

        if passive_tasks:
            with ThreadPoolExecutor(max_workers=min(len(passive_tasks), self.config.threads)) as pool:
                futures = {}
                future_started = {}
                for name, task in passive_tasks.items():
                    future = pool.submit(task)
                    futures[future] = name
                    future_started[future] = perf_counter()
                for future in as_completed(futures):
                    name = futures[future]
                    status = "ok"
                    try:
                        results["modules"][name] = future.result()
                    except Exception as exc:
                        results["modules"][name] = {"error": str(exc)}
                        results["errors"].append(f"{name}: {exc}")
                        status = "error"
                    self._record_timing(results["telemetry"], name, future_started[future], status)
                    completed_stages += 1
                    self._emit_progress(progress_callback, completed_stages, total_stages, f"{name.replace('_', ' ').title()} complete")

        if any(name.startswith("active.") for name in selected):
            active_started = perf_counter()
            try:
                active, completed_stages = self._run_active(
                    info.value,
                    progress_callback=progress_callback,
                    completed=completed_stages,
                    total=total_stages,
                    selected=selected,
                )
                results["modules"]["active"] = active
            except Exception:
                self._record_timing(results["telemetry"], "active", active_started, "error")
                raise
            else:
                self._record_timing(results["telemetry"], "active", active_started, "ok")

        risk_started = perf_counter()
        results["risk"] = assess(results)
        self._record_timing(results["telemetry"], "risk", risk_started, "ok")
        completed_stages += 1
        self._emit_progress(progress_callback, completed_stages, total_stages, "Risk assessment complete")
        results["completed_at"] = datetime.now(timezone.utc).isoformat()
        results["duration_ms"] = round((perf_counter() - scan_started) * 1000, 2)
        results["telemetry"]["total_duration_ms"] = results["duration_ms"]
        return to_jsonable(results)

    def _http_cache(self) -> JsonFileCache:
        cache_dir = self.config.config_path.parent / ".cache" / "http"
        return JsonFileCache(cache_dir, ttl=int(self.config.get("settings.cache_ttl", 3600)))

    def _stage_names(self, info: Any, mode: str, only: Optional[str] = None, skip: Optional[str] = None) -> list[str]:
        names = list(PASSIVE_MODULES)
        if info.is_ip:
            names.remove("subdomains")
        if mode in {"active", "full"}:
            names.append("active.ports")
            if info.is_domain:
                names.append("active.subdomains")
                if self.config.get("active.check_zone_transfer", False):
                    names.append("active.zone_transfer")
                if self.config.get("output.screenshots", False):
                    names.append("active.screenshot")
        available = set(names)
        requested = self._parse_module_selection(only, "--only")
        excluded = self._parse_module_selection(skip, "--skip")
        known = set(PASSIVE_MODULES) | set(ACTIVE_MODULES) | {"risk"}
        unknown = (requested | excluded) - known
        if unknown:
            raise ScanError(f"Unknown module(s): {', '.join(sorted(unknown))}")
        unavailable = requested - available - {"risk"}
        if unavailable:
            raise ScanError(
                f"Module(s) unavailable for mode/target/config: {', '.join(sorted(unavailable))}"
            )
        if requested:
            names = [name for name in names if name in requested]
        names = [name for name in names if name not in excluded]
        names.append("risk")
        return names

    @staticmethod
    def _parse_module_selection(value: Optional[str], option: str) -> set[str]:
        if not value:
            return set()
        selected: set[str] = set()
        for item in value.split(","):
            module = item.strip().lower().replace("-", "_")
            if not module:
                continue
            selected.add(MODULE_ALIASES.get(module, module))
        if not selected:
            raise ScanError(f"{option} requires at least one module name")
        return selected

    @staticmethod
    def _emit_progress(callback: Optional[ProgressCallback], completed: int, total: int, label: str) -> None:
        if callback:
            callback(completed, total, label)

    @staticmethod
    def _record_timing(telemetry: dict[str, Any], name: str, started: float, status: str) -> None:
        telemetry["module_durations_ms"][name] = round((perf_counter() - started) * 1000, 2)
        telemetry["module_status"][name] = status

    def _run_active(
        self,
        target: str,
        progress_callback: Optional[ProgressCallback] = None,
        completed: int = 0,
        total: int = 1,
        selected: Optional[set[str]] = None,
    ) -> tuple[dict[str, Any], int]:
        active: dict[str, Any] = {}
        target_info = normalize_target(target)
        selected = selected or set(ACTIVE_MODULES)
        if "active.ports" in selected:
            ports = self.config.get("active.ports", [])
            active["ports"] = PortScanner(self.config.timeout, self.config.threads).scan(target, ports)
            completed += 1
            self._emit_progress(progress_callback, completed, total, "Active port scan complete")
        if target_info.is_domain and "active.subdomains" in selected:
            wordlist = self.config.get("wordlists.subdomains", "wordlists/subdomains.txt")
            path = self.config.config_path.parent / str(wordlist)
            active["subdomains"] = SubdomainBruteForcer(self.config.timeout, self.config.threads).discover(target, path)
            completed += 1
            self._emit_progress(progress_callback, completed, total, "Active subdomain discovery complete")
        if target_info.is_domain and "active.zone_transfer" in selected:
            active["zone_transfer"] = DNSEnumerator(self.config.timeout).check_zone_transfer(target)
            completed += 1
            self._emit_progress(progress_callback, completed, total, "Zone transfer check complete")
        if "active.screenshot" in selected and target_info.is_domain:
            from cyberrecon.modules.screenshot import ScreenshotCapture
            screenshot_path = self.config.output_dir / "screenshots" / f"{target}.png"
            active["screenshot"] = ScreenshotCapture(int(self.config.timeout * 1000)).capture(target, screenshot_path)
            completed += 1
            self._emit_progress(progress_callback, completed, total, "Screenshot capture complete")
        return active, completed
