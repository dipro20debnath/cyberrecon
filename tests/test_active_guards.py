import pytest

from cyberrecon.config import Config
from cyberrecon.modules.active import ActiveScanError, PortScanner, require_active_authorization
from cyberrecon.utils.validators import normalize_target


def test_active_requires_confirmation_and_allowlist(tmp_path):
    config = Config(tmp_path / "config.yaml")
    target = normalize_target("example.com")
    with pytest.raises(ActiveScanError):
        require_active_authorization(target, config, confirmed=False)


def test_active_allowlist_normalizes_dots_and_wildcards(tmp_path):
    config = Config(tmp_path / "config.yaml")
    config.config["active"]["enabled"] = True
    config.config["active"]["allowed_targets"] = ["example.com."]
    require_active_authorization(normalize_target("example.com"), config, confirmed=True)

    config.config["active"]["allowed_targets"] = ["*.example.com"]
    require_active_authorization(normalize_target("sub.example.com"), config, confirmed=True)
    with pytest.raises(ActiveScanError):
        require_active_authorization(normalize_target("example.com"), config, confirmed=True)
    with pytest.raises(ActiveScanError):
        require_active_authorization(normalize_target("evil-example.com"), config, confirmed=True)


def test_port_scanner_skips_invalid_port_values():
    result = PortScanner().scan("192.0.2.10", ["http", "", None, 0, 65536])
    assert result["ports"] == []
