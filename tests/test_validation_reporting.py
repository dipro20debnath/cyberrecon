import json

import pytest

from cyberrecon.reporting import write_report
from cyberrecon.utils.validators import TargetValidationError, normalize_target


def test_target_normalization():
    assert normalize_target("Example.COM.").value == "example.com"
    assert normalize_target("192.0.2.10").kind == "ip"
    with pytest.raises(TargetValidationError):
        normalize_target("../etc/passwd")


def test_all_report_formats(tmp_path):
    data = {"target": "example.com", "modules": {"dns": {"records": {"A": ["192.0.2.10"]}}}}
    for fmt in ("json", "csv", "html"):
        path = write_report(data, tmp_path, "example.com", fmt)
        assert path.exists()
        assert path.suffix == f".{fmt}"
    assert json.loads((tmp_path / "example.com_scan.json").read_text(encoding="utf-8"))["target"] == "example.com"


def test_html_report_highlights_important_information(tmp_path):
    data = {
        "target": "example.com",
        "mode": "passive",
        "risk": {"score": 35, "severity": "medium", "indicators": [{"severity": "medium", "name": "certificate_expiry", "days_until_expiry": 5}]},
        "modules": {
            "tls": {"reachable": True, "tls_version": "TLSv1.3", "certificate": {"days_until_expiry": 5}},
            "technology": {"status_code": 200, "technologies": ["Nginx"], "security": {"findings": []}},
        },
    }
    path = write_report(data, tmp_path, "example.com", "html")
    html = path.read_text(encoding="utf-8")
    assert "Risk score" in html
    assert "Important findings" in html
    assert "TLS certificate" in html
    assert "certificate_expiry" in html
