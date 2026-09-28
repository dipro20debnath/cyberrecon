import pytest

from cyberrecon.config import Config
from cyberrecon.modules.active import ActiveScanError, require_active_authorization
from cyberrecon.utils.validators import normalize_target


def test_active_requires_confirmation_and_allowlist(tmp_path):
    config = Config(tmp_path / "config.yaml")
    target = normalize_target("example.com")
    with pytest.raises(ActiveScanError):
        require_active_authorization(target, config, confirmed=False)
