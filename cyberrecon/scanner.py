"""Scan orchestration for passive and explicitly authorized active checks."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from cyberrecon.config import Config
from cyberrecon.integrations import ExternalIntelligence
from cyberrecon.risk import assess
from cyberrecon.modules.active import PortScanner, SubdomainBruteForcer, require_active_authorization
from cyberrecon.modules.passive import DNSEnumerator, IPIntelligence, CrtshSubdomainFinder, TechnologyDetector, TLSInspector, WHOISLookup
from cyberrecon.utils.serialization import to_jsonable
from cyberrecon.utils.validators import TargetValidationError, normalize_target


class ScanError(ValueError):
    """Raised when a scan request cannot be executed."""


ProgressCallback = Callable[[int, int, str], None]


class ReconScanner:
    def __init__(self, config: Config):
        self.config = config

    def scan(
        self,
        target: str,
        mode: str = "passive",
        confirm_active: bool = False,
        progress_callback: Optional[ProgressCallback] = None,
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

        stage_names = self._stage_names(info, mode)
        total_stages = len(stage_names)
        completed_stages = 0
        self._emit_progress(progress_callback, completed_stages, total_stages, "Initializing scan")

        results: dict[str, Any] = {
            "tool": "CyberRecon Pro",
            "version": "1.3.0",
            "target": info.value,
            "target_type": info.kind,
            "mode": mode,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "modules": {},
            "errors": [],
        }

        passive_tasks = {
            "dns": lambda: DNSEnumerator(self.config.timeout).enumerate(info.value),
            "whois": lambda: WHOISLookup().lookup(info.value),
            "subdomains": lambda: CrtshSubdomainFinder(self.config.timeout, user_agent=self.config.user_agent).find_subdomains(info.value),
            "ip_intelligence": lambda: IPIntelligence(self.config.get_api_key("ipinfo"), self.config.timeout).lookup(info.value),
            "technology": lambda: TechnologyDetector(self.config.timeout, user_agent=self.config.user_agent).detect(info.value),
            "tls": lambda: TLSInspector(self.config.timeout).inspect(info.value),
            "external_intelligence": lambda: ExternalIntelligence(self.config).collect(info.value),
        }
        if info.is_ip:
            passive_tasks.pop("subdomains")

        with ThreadPoolExecutor(max_workers=min(len(passive_tasks), self.config.threads)) as pool:
            futures = {pool.submit(task): name for name, task in passive_tasks.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results["modules"][name] = future.result()
                except Exception as exc:
                    results["modules"][name] = {"error": str(exc)}
                    results["errors"].append(f"{name}: {exc}")
                completed_stages += 1
                self._emit_progress(progress_callback, completed_stages, total_stages, f"{name.replace('_', ' ').title()} complete")

        if mode in {"active", "full"}:
            active, completed_stages = self._run_active(
                info.value,
                progress_callback=progress_callback,
                completed=completed_stages,
                total=total_stages,
            )
            results["modules"]["active"] = active

        results["risk"] = assess(results)
        completed_stages += 1
        self._emit_progress(progress_callback, completed_stages, total_stages, "Risk assessment complete")
        results["completed_at"] = datetime.now(timezone.utc).isoformat()
        return to_jsonable(results)

    def _stage_names(self, info: Any, mode: str) -> list[str]:
        names = ["dns", "whois", "subdomains", "ip_intelligence", "technology", "tls", "external_intelligence"]
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
        names.append("risk")
        return names

    @staticmethod
    def _emit_progress(callback: Optional[ProgressCallback], completed: int, total: int, label: str) -> None:
        if callback:
            callback(completed, total, label)

    def _run_active(
        self,
        target: str,
        progress_callback: Optional[ProgressCallback] = None,
        completed: int = 0,
        total: int = 1,
    ) -> tuple[dict[str, Any], int]:
        active: dict[str, Any] = {}
        target_info = normalize_target(target)
        ports = self.config.get("active.ports", [])
        active["ports"] = PortScanner(self.config.timeout, self.config.threads).scan(target, ports)
        completed += 1
        self._emit_progress(progress_callback, completed, total, "Active port scan complete")
        if target_info.is_domain:
            wordlist = self.config.get("wordlists.subdomains", "wordlists/subdomains.txt")
            path = self.config.config_path.parent / str(wordlist)
            active["subdomains"] = SubdomainBruteForcer(self.config.timeout, self.config.threads).discover(target, path)
            completed += 1
            self._emit_progress(progress_callback, completed, total, "Active subdomain discovery complete")
            if self.config.get("active.check_zone_transfer", False):
                active["zone_transfer"] = DNSEnumerator(self.config.timeout).check_zone_transfer(target)
                completed += 1
                self._emit_progress(progress_callback, completed, total, "Zone transfer check complete")
        if self.config.get("output.screenshots", False) and normalize_target(target).is_domain:
            from cyberrecon.modules.screenshot import ScreenshotCapture
            screenshot_path = self.config.output_dir / "screenshots" / f"{target}.png"
            active["screenshot"] = ScreenshotCapture(int(self.config.timeout * 1000)).capture(target, screenshot_path)
            completed += 1
            self._emit_progress(progress_callback, completed, total, "Screenshot capture complete")
        return active, completed
