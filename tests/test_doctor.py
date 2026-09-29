from cyberrecon.config import Config
from cyberrecon.doctor import diagnostics_summary, run_diagnostics
import cyberrecon.doctor as doctor_module


def test_doctor_reports_ready_default_environment(tmp_path):
    config = Config(tmp_path / "config.yaml")
    config.save()
    config.output_dir.mkdir()

    checks = run_diagnostics(config)
    summary = diagnostics_summary(checks)
    names = {item["name"] for item in checks}

    assert {"python", "config", "dependencies", "active_scope", "reports"} <= names
    assert summary["fail"] == 0


def test_doctor_live_api_check_is_opt_in_and_redacts_provider_details(tmp_path, monkeypatch):
    config = Config(tmp_path / "config.yaml")
    config.config["api_keys"]["virustotal"] = ["secret-one", "secret-two"]
    config.config["api_keys"]["urlscan"] = ["secret-three"]

    class FakeIntelligence:
        def __init__(self, config):
            self.config = config

        def collect(self, target):
            return {
                "sources": {"virustotal": {"ok": True}, "urlscan": {"error": "401 secret-three", "attempts": 2}},
                "skipped": [],
                "credential_rotation": {"virustotal": {"initial_key_slot": 2, "attempts": 1}},
            }

    monkeypatch.setattr(doctor_module, "ExternalIntelligence", FakeIntelligence)
    checks = run_diagnostics(config, live_apis=True, api_target="example.com")
    statuses = {item["name"]: item for item in checks if item["name"].startswith("api_live.")}
    assert statuses["api_live.virustotal"]["status"] == "ok"
    assert statuses["api_live.urlscan"]["status"] == "fail"
    assert "secret" not in " ".join(item["details"] for item in statuses.values())


def test_doctor_live_api_without_keys_does_not_make_requests(tmp_path):
    config = Config(tmp_path / "config.yaml")
    checks = run_diagnostics(config, live_apis=True)
    live = next(item for item in checks if item["name"] == "api_live")
    assert live["status"] == "warn"
