import json

from typer.testing import CliRunner

import cyberrecon.cli as cli_module
from cyberrecon.cli import app


def test_scan_supports_fail_on_change(monkeypatch, tmp_path):
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps({
        "target": "example.com",
        "risk": {"score": 0, "severity": "low"},
        "modules": {"dns": {"records": {"A": [{"name": "example.com", "value": "192.0.2.1"}]}}},
    }), encoding="utf-8")
    current = {
        "target": "example.com",
        "mode": "passive",
        "risk": {"score": 0, "severity": "low"},
        "modules": {"dns": {"records": {"A": [{"name": "example.com", "value": "192.0.2.2"}]}}},
        "errors": [],
    }
    monkeypatch.setattr(cli_module, "_execute_scan", lambda *args, **kwargs: current)
    result = CliRunner().invoke(app, [
        "scan", "example.com", "--baseline", str(baseline_path), "--fail-on-change", "--output", "json",
    ])
    assert result.exit_code == 1
    assert "Quality gate failed" in result.stdout
