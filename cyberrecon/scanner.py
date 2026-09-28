"""Scan orchestration for passive and explicitly authorized active checks."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from cyberrecon.config import Config
from cyberrecon.integrations import ExternalIntelligence
from cyberrecon.risk import assess
from cyberrecon.modules.active import PortScanner, SubdomainBruteForcer, require_active_authorization
from cyberrecon.modules.passive import DNSEnumerator, IPIntelligence, CrtshSubdomainFinder, TechnologyDetector, WHOISLookup
from cyberrecon.utils.serialization import to_jsonable
from cyberrecon.utils.validators import TargetValidationError, normalize_target


class ScanError(ValueError):
    """Raised when a scan request cannot be executed."""


class ReconScanner:
    def __init__(self, config: Config):
        self.config = config

    def scan(self, target: str, mode: str = "passive", confirm_active: bool = False) -> dict[str, Any]:
        mode = mode.lower().strip()
        if mode not in {"passive", "active", "full"}:
            raise ScanError("Mode must be passive, active or full")
        try:
            info = normalize_target(target)
        except TargetValidationError as exc:
            raise ScanError(str(exc)) from exc

        if mode in {"active", "full"}:
            require_active_authorization(info, self.config, confirm_active)

        results: dict[str, Any] = {
            "tool": "CyberRecon Pro",
            "version": "1.1.0",
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

        if mode in {"active", "full"}:
            results["modules"]["active"] = self._run_active(info.value)

        results["risk"] = assess(results)
        results["completed_at"] = datetime.now(timezone.utc).isoformat()
        return to_jsonable(results)

    def _run_active(self, target: str) -> dict[str, Any]:
        active: dict[str, Any] = {}
        target_info = normalize_target(target)
        ports = self.config.get("active.ports", [])
        active["ports"] = PortScanner(self.config.timeout, self.config.threads).scan(target, ports)
        if target_info.is_domain:
            wordlist = self.config.get("wordlists.subdomains", "wordlists/subdomains.txt")
            path = self.config.config_path.parent / str(wordlist)
            active["subdomains"] = SubdomainBruteForcer(self.config.timeout, self.config.threads).discover(target, path)
            if self.config.get("active.check_zone_transfer", False):
                active["zone_transfer"] = DNSEnumerator(self.config.timeout).check_zone_transfer(target)
        if self.config.get("output.screenshots", False) and normalize_target(target).is_domain:
            from cyberrecon.modules.screenshot import ScreenshotCapture
            screenshot_path = self.config.output_dir / "screenshots" / f"{target}.png"
            active["screenshot"] = ScreenshotCapture(int(self.config.timeout * 1000)).capture(target, screenshot_path)
        return active
