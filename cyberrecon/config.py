"""Configuration management for CyberRecon.

The configuration loader is deliberately defensive: an empty or partially
written YAML file must not turn into ``None`` and crash the CLI later.
"""

from __future__ import annotations

import copy
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


class ConfigError(ValueError):
    """Raised when a configuration file cannot be loaded or written."""


class Config:
    """Load, validate, merge and persist CyberRecon configuration."""

    DEFAULT_CONFIG: Dict[str, Any] = {
        "api_keys": {
            "virustotal": "",
            "securitytrails": "",
            "shodan": "",
            "censys": "",
            "urlscan": "",
            "ipinfo": "",
        },
        "wordlists": {
            "subdomains": "wordlists/subdomains.txt",
            "dns": "wordlists/dns-names.txt",
            "ports": "wordlists/top-ports.txt",
        },
        "settings": {
            "timeout": 10,
            "threads": 20,
            "rate_limit": 1.0,
            "max_retries": 2,
            "cache_ttl": 3600,
            "user_agent": "CyberRecon-Pro/1.0",
        },
        "output": {
            "default_format": "json",
            "save_directory": "reports",
            "screenshots": False,
        },
        "active": {
            "enabled": False,
            "allowed_targets": [],
            "allow_private_targets": False,
            "check_zone_transfer": False,
            "ports": [21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 5432, 6379, 8080, 8443],
        },
    }

    SECRET_KEY_PARTS = ("key", "token", "secret", "password")

    def __init__(self, config_path: str | os.PathLike[str] = "config.yaml"):
        self.config_path = Path(config_path).expanduser()
        self.config: Dict[str, Any] = self._load_config()

    @classmethod
    def defaults(cls) -> Dict[str, Any]:
        """Return an isolated copy of the default configuration."""

        return copy.deepcopy(cls.DEFAULT_CONFIG)

    def _load_config(self) -> Dict[str, Any]:
        """Load YAML and deep-merge it over defaults.

        Missing and empty files are treated as defaults.  We intentionally do
        not write during import or construction; only ``save``/``init`` writes
        to disk.
        """

        loaded: Any = {}
        if self.config_path.exists():
            try:
                with self.config_path.open("r", encoding="utf-8") as handle:
                    loaded = yaml.safe_load(handle) or {}
            except (OSError, yaml.YAMLError) as exc:
                raise ConfigError(f"Unable to load {self.config_path}: {exc}") from exc

        if not isinstance(loaded, dict):
            raise ConfigError("Configuration root must be a YAML mapping")

        return self._deep_merge(self.defaults(), loaded)

    @classmethod
    def _deep_merge(cls, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                base[key] = cls._deep_merge(base[key], value)
            else:
                base[key] = value
        return base

    def save(self) -> None:
        """Atomically persist the current configuration."""

        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(
                prefix=f".{self.config_path.name}.",
                suffix=".tmp",
                dir=str(self.config_path.parent),
                text=True,
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    yaml.safe_dump(self.config, handle, sort_keys=False, allow_unicode=True)
                os.replace(temp_name, self.config_path)
            except Exception:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
                raise
        except OSError as exc:
            raise ConfigError(f"Unable to save {self.config_path}: {exc}") from exc

    def get(self, key: str, default: Any = None) -> Any:
        """Read a dotted configuration key."""

        value: Any = self.config
        for part in key.split("."):
            if not isinstance(value, dict) or part not in value:
                return default
            value = value[part]
        return value

    def set(self, key: str, value: Any) -> None:
        """Set a dotted configuration key and persist it."""

        parts = [part.strip() for part in key.split(".") if part.strip()]
        if not parts:
            raise ConfigError("Configuration key cannot be empty")

        current = self.config
        for part in parts[:-1]:
            child = current.get(part)
            if child is None:
                child = {}
                current[part] = child
            if not isinstance(child, dict):
                raise ConfigError(f"Cannot nest configuration key below '{part}'")
            current = child
        current[parts[-1]] = self._coerce_value(value)
        self.save()

    @staticmethod
    def _coerce_value(value: Any) -> Any:
        if not isinstance(value, str):
            return value
        try:
            parsed = yaml.safe_load(value)
        except yaml.YAMLError:
            return value
        return value if parsed is None else parsed

    def get_api_key(self, service: str) -> Optional[str]:
        """Read the first configured API key for backward compatibility."""

        keys = self.get_api_keys(service)
        return keys[0] if keys else None

    def get_api_keys(self, service: str) -> list[str]:
        """Return configured provider keys in order, without exposing them."""

        prefix = service.upper()
        raw: Any = os.getenv(f"CR_{prefix}_API_KEYS")
        if raw is None:
            raw = os.getenv(f"CR_{prefix}_API_KEY")
        if raw is None:
            raw = self.get(f"api_keys.{service}", "")
        if isinstance(raw, str):
            values = raw.split(",") if "," in raw else [raw]
        elif isinstance(raw, (list, tuple, set)):
            values = list(raw)
        else:
            values = []
        result: list[str] = []
        for value in values:
            normalized = str(value).strip()
            if normalized and normalized not in result:
                result.append(normalized)
        return result

    def redacted(self) -> Dict[str, Any]:
        """Return a copy safe for terminal output and logs."""

        result = copy.deepcopy(self.config)

        def redact(mapping: Dict[str, Any]) -> None:
            for key, value in mapping.items():
                if isinstance(value, dict):
                    if key == "api_keys":
                        for secret_name, secret_value in value.items():
                            if secret_value:
                                value[secret_name] = "********"
                    else:
                        redact(value)
                elif any(part in key.lower() for part in self.SECRET_KEY_PARTS) and value:
                    mapping[key] = "********"

        redact(result)
        return result

    @property
    def threads(self) -> int:
        return max(1, int(self.get("settings.threads", 20)))

    @property
    def timeout(self) -> float:
        return max(0.5, float(self.get("settings.timeout", 10)))

    @property
    def rate_limit(self) -> float:
        return max(0.0, float(self.get("settings.rate_limit", 1.0)))

    @property
    def max_retries(self) -> int:
        return max(0, int(self.get("settings.max_retries", 2)))

    @property
    def user_agent(self) -> str:
        return str(self.get("settings.user_agent", "CyberRecon-Pro/1.0"))

    @property
    def output_dir(self) -> Path:
        path = Path(str(self.get("output.save_directory", "reports")))
        if not path.is_absolute():
            path = self.config_path.parent / path
        return path

    @property
    def active_enabled(self) -> bool:
        return bool(self.get("active.enabled", False))

    @property
    def allowed_targets(self) -> list[str]:
        value = self.get("active.allowed_targets", [])
        return [str(item).strip().lower() for item in value] if isinstance(value, list) else []

    @property
    def allow_private_targets(self) -> bool:
        return bool(self.get("active.allow_private_targets", False))


# Keep a convenient import for the CLI while avoiding writes at import time.
config = Config()
