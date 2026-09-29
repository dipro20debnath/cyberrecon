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


def test_api_key_pool_supports_yaml_lists_and_environment_override(tmp_path: Path, monkeypatch):
    config = Config(tmp_path / "config.yaml")
    config.config["api_keys"]["virustotal"] = [" first-key ", "second-key", "second-key"]

    assert config.get_api_keys("virustotal") == ["first-key", "second-key"]
    assert config.get_api_key("virustotal") == "first-key"

    monkeypatch.setenv("CR_VIRUSTOTAL_API_KEYS", "env-a, env-b")
    assert config.get_api_keys("virustotal") == ["env-a", "env-b"]
