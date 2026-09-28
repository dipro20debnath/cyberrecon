from pathlib import Path

from cyberrecon.config import Config


def test_empty_config_is_repaired_in_memory_and_can_be_saved(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("", encoding="utf-8")

    config = Config(path)
    assert config.timeout == 10
    config.set("settings.timeout", "5")

    reloaded = Config(path)
    assert reloaded.timeout == 5


def test_redacted_config_does_not_expose_api_keys(tmp_path: Path):
    config = Config(tmp_path / "config.yaml")
    config.set("api_keys.ipinfo", "secret-token")

    assert config.redacted()["api_keys"]["ipinfo"] == "********"
