import json

import pytest

from cyberrecon.reporting import filter_findings, write_report
from cyberrecon.utils.validators import TargetValidationError, normalize_target


def test_target_normalization():
    assert normalize_target("Example.COM.").value == "example.com"
    assert normalize_target("192.0.2.10").kind == "ip"
    with pytest.raises(TargetValidationError):
        normalize_target("../etc/passwd")


def test_all_report_formats(tmp_path):
    data = {"target": "example.com", "modules": {"dns": {"records": {"A": ["192.0.2.10"]}}}}
    for fmt in ("json", "csv", "html", "pdf", "md", "sarif"):
        path = write_report(data, tmp_path, "example.com", fmt)
        assert path.exists()
        assert path.suffix == f".{fmt}"
    assert json.loads((tmp_path / "example.com_scan.json").read_text(encoding="utf-8"))["target"] == "example.com"


def test_pdf_report_is_valid_basic_document(tmp_path):
    path = write_report({"target": "example.com", "risk": {"score": 12, "severity": "low"}}, tmp_path, "example.com", "pdf")
    content = path.read_bytes()
    assert content.startswith(b"%PDF-1.4")
    assert b"/Type /Catalog" in content
    assert content.rstrip().endswith(b"%%EOF")


def test_html_report_highlights_important_information(tmp_path):
    data = {
        "target": "example.com",
        "mode": "passive",
        "run_id": "run-123",
        "duration_ms": 12.5,
        "telemetry": {"module_durations_ms": {"tls": 4.2}, "module_status": {"tls": "ok"}},
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
    assert "Execution telemetry" in html


def test_sarif_report_contains_risk_results(tmp_path):
    data = {
        "target": "example.com",
        "version": "1.6.0",
        "risk": {"score": 25, "severity": "medium", "indicators": [{"name": "dmarc_missing", "severity": "medium", "message": "DMARC missing"}]},
        "modules": {"technology": {"security": {"findings": [{"severity": "high", "header": "CSP", "message": "Missing"}]}}},
    }
    path = write_report(data, tmp_path, "example.com", "sarif")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert {item["ruleId"] for item in payload["runs"][0]["results"]} == {"risk.dmarc_missing", "http.CSP"}


def test_markdown_report_contains_summary(tmp_path):
    path = write_report({"target": "example.com", "risk": {"score": 10, "severity": "low"}}, tmp_path, "example.com", "markdown")
    assert path.suffix == ".md"
    assert "# CyberRecon Pro Report" in path.read_text(encoding="utf-8")


def test_reports_include_favicon_fingerprint(tmp_path):
    data = {
        "target": "example.com",
        "modules": {
            "web_metadata": {
                "favicon": {
                    "available": True,
                    "source": "favicon.ico",
                    "format": "ico",
                    "sha256": "a" * 64,
                    "mmh3": -123,
                }
            }
        },
    }
    html = write_report(data, tmp_path, "example.com", "html").read_text(encoding="utf-8")
    markdown = write_report(data, tmp_path, "example.com", "md", suffix="favicon").read_text(encoding="utf-8")
    assert "Favicon fingerprint" in html
    assert "a" * 64 in html
    assert "Favicon fingerprint" in markdown
    assert "-123" in markdown


def test_finding_filter_preserves_risk_score_and_counts():
    data = {
        "target": "example.com",
        "risk": {
            "score": 75,
            "severity": "high",
            "indicators": [
                {"severity": "low", "name": "low-finding"},
                {"severity": "high", "name": "high-finding"},
            ],
        },
        "modules": {
            "technology": {
                "security": {
                    "findings": [
                        {"severity": "medium", "header": "CSP"},
                        {"severity": "critical", "header": "Cookie"},
                    ]
                }
            }
        },
    }
    filtered = filter_findings(data, "high")
    assert filtered["risk"]["score"] == 75
    assert [item["name"] for item in filtered["risk"]["indicators"]] == ["high-finding"]
    assert [item["header"] for item in filtered["modules"]["technology"]["security"]["findings"]] == ["Cookie"]
    assert filtered["finding_filter"]["included_findings"] == 2
    assert filtered["finding_filter"]["excluded_findings"] == 2
