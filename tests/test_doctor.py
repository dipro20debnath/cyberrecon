from cyberrecon.config import Config
from cyberrecon.doctor import diagnostics_summary, run_diagnostics


def test_doctor_reports_ready_default_environment(tmp_path):
    config = Config(tmp_path / "config.yaml")
    config.save()
    config.output_dir.mkdir()

    checks = run_diagnostics(config)
    summary = diagnostics_summary(checks)
    names = {item["name"] for item in checks}

    assert {"python", "config", "dependencies", "active_scope", "reports"} <= names
    assert summary["fail"] == 0
