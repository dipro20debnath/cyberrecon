from pathlib import Path

import yaml

from cyberrecon import DEFAULT_USER_AGENT


def test_default_config_references_existing_active_assets():
    root = Path(__file__).resolve().parents[1]
    config = yaml.safe_load((root / "config.yaml").read_text(encoding="utf-8"))

    for relative_path in config["wordlists"].values():
        assert (root / relative_path).is_file(), relative_path


def test_checked_in_config_uses_current_user_agent():
    root = Path(__file__).resolve().parents[1]
    config = yaml.safe_load((root / "config.yaml").read_text(encoding="utf-8"))

    assert config["settings"]["user_agent"] == DEFAULT_USER_AGENT
