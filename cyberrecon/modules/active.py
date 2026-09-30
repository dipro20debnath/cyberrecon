"""Guarded active reconnaissance primitives.

These functions do not run from the passive scanner.  The caller must enable
active mode, confirm authorization, and configure an explicit target allowlist.
"""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable

import dns.resolver

from cyberrecon.utils.validators import TargetInfo, TargetValidationError, is_private_or_local, normalize_target


class ActiveScanError(PermissionError):
    """Raised when an active scan is not explicitly authorized."""


def require_active_authorization(target: TargetInfo, config: Any, confirmed: bool) -> None:
    if not confirmed:
        raise ActiveScanError("Active mode requires --confirm-active")
    if not config.active_enabled:
        raise ActiveScanError("Active mode is disabled in config.yaml")
    allowed_targets = {str(item).strip().lower().rstrip(".") for item in config.allowed_targets}
    normalized_target = target.value.lower().rstrip(".")
    if normalized_target not in allowed_targets:
        allowed = any(
            item.startswith("*.")
            and target.is_domain
            and normalized_target != item[2:]
            and normalized_target.endswith(item[1:])
            for item in allowed_targets
        )
        if not allowed:
            raise ActiveScanError("Target is not present in active.allowed_targets")
    if target.is_ip and is_private_or_local(target.value) and not config.allow_private_targets:
        raise ActiveScanError("Private/local active targets require active.allow_private_targets=true")


class SubdomainBruteForcer:
    def __init__(self, timeout: float = 3, workers: int = 20, resolver: dns.resolver.Resolver | None = None):
        self.timeout = max(0.5, float(timeout))
        self.workers = max(1, min(int(workers), 100))
        self.resolver = resolver or dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

    def discover(self, domain: str, wordlist: str | Path) -> dict[str, Any]:
        target = normalize_target(domain)
        if not target.is_domain:
            raise TargetValidationError("Subdomain brute force requires a domain")
        words = self._read_words(wordlist)
        found: list[dict[str, Any]] = []
        lock = threading.Lock()

        def resolve(word: str) -> None:
            hostname = f"{word}.{target.value}"
            try:
                answers = self.resolver.resolve(hostname, "A")
                addresses = sorted({str(answer) for answer in answers})
                with lock:
                    found.append({"subdomain": hostname, "addresses": addresses})
            except Exception:
                return

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = [pool.submit(resolve, word) for word in words]
            for future in as_completed(futures):
                future.result()
        found.sort(key=lambda item: item["subdomain"])
        return {"target": target.value, "tested": len(words), "found": found, "count": len(found)}

    @staticmethod
    def _read_words(path: str | Path) -> list[str]:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Wordlist not found: {file_path}")
        words = {line.strip().lower() for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines()}
        return sorted(word for word in words if word and not word.startswith("#") and "." not in word)


class PortScanner:
    SERVICE_NAMES = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
        587: "submission", 993: "imaps", 995: "pop3s", 3306: "mysql",
        5432: "postgresql", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    }

    def __init__(self, timeout: float = 1.0, workers: int = 50):
        self.timeout = max(0.1, float(timeout))
        self.workers = max(1, min(int(workers), 100))

    def scan(self, target: str, ports: Iterable[int]) -> dict[str, Any]:
        info = normalize_target(target)
        values_set: set[int] = set()
        for port in ports:
            try:
                value = int(port)
            except (TypeError, ValueError):
                continue
            if 1 <= value <= 65535:
                values_set.add(value)
        values = sorted(values_set)
        if len(values) > 1000:
            raise ValueError("Port scan is limited to 1000 ports per request")

        def probe(port: int) -> dict[str, Any]:
            started = time.perf_counter()
            try:
                with socket.create_connection((info.value, port), timeout=self.timeout):
                    return {"port": port, "service": self.SERVICE_NAMES.get(port, "unknown"), "state": "open", "latency_ms": round((time.perf_counter() - started) * 1000, 2)}
            except (TimeoutError, socket.timeout):
                return {"port": port, "service": self.SERVICE_NAMES.get(port, "unknown"), "state": "filtered"}
            except OSError as exc:
                return {"port": port, "service": self.SERVICE_NAMES.get(port, "unknown"), "state": "closed", "error": str(exc)}

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            results = list(pool.map(probe, values))
        return {"target": info.value, "ports": results, "open_count": sum(item["state"] == "open" for item in results)}
