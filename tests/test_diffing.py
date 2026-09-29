import pytest

from cyberrecon.diffing import ComparisonError, compare_reports, discover_json_reports
from cyberrecon.reporting import write_report


def _report(*, current: bool) -> dict:
    return {
        "target": "Example.COM.",
        "started_at": "2026-09-28T10:00:00Z",
        "completed_at": "2026-09-28T10:01:00Z",
        "risk": {"score": 20 if not current else 45, "severity": "low" if not current else "medium"},
        "modules": {
            "dns": {"records": {"A": [{"name": "example.com", "value": "192.0.2.10" if not current else "192.0.2.20"}]}},
            "subdomains": {"subdomains": ["www.example.com"] if not current else ["api.example.com"]},
            "technology": {
                "technologies": ["Nginx"] if not current else ["Apache"],
                "security": {"findings": [] if not current else [{"severity": "high", "header": "CSP", "message": "Missing"}]},
            },
            "active": {"ports": {"ports": [] if not current else [{"port": 8080, "service": "http-alt", "state": "open"}]}},
            "tls": {"certificate": {"days_until_expiry": 90 if not current else 12}},
            "web_metadata": {"robots": {"disallow": ["/old" if not current else "/new"], "allow": [], "sitemaps": []}, "sitemap": {"locations": []}, "security_txt": {}},
        },
    }


def test_compare_reports_detects_high_signal_changes():
    result = compare_reports(_report(current=False), _report(current=True))
    comparison = result["comparison"]

    assert result["target"] == "example.com"
    assert comparison["summary"]["has_changes"] is True
    assert comparison["risk"]["delta"] == 25
    assert comparison["tls"]["delta_days"] == -78
    assert comparison["open_ports"]["added"] == [{"port": 8080, "service": "http-alt"}]
    assert "www.example.com" in comparison["subdomains"]["removed"]
    assert comparison["web_paths"]["added"] == [{"kind": "robots:disallow", "value": "/new"}]


def test_compare_reports_rejects_different_targets():
    current = _report(current=True)
    current["target"] = "other.example"
    with pytest.raises(ComparisonError, match="different assets"):
        compare_reports(_report(current=False), current)


def test_comparison_html_contains_change_summary(tmp_path):
    comparison = compare_reports(_report(current=False), _report(current=True))
    path = write_report(comparison, tmp_path, "example.com", "html", suffix="comparison")
    html = path.read_text(encoding="utf-8")
    assert "Changes since baseline" in html
    assert "Open port changes" in html
    assert "Risk delta" in html


def test_discover_json_reports_returns_newest_first(tmp_path):
    older = tmp_path / "older.json"
    newer = tmp_path / "newer.json"
    older.write_text('{"target": "old.example"}', encoding="utf-8")
    newer.write_text('{"target": "new.example"}', encoding="utf-8")
    older.touch()
    newer.touch()
    assert discover_json_reports(tmp_path) == [newer, older]


def test_compare_reports_detects_favicon_fingerprint_change():
    baseline = _report(current=False)
    current = _report(current=True)
    baseline["modules"]["web_metadata"] = {"favicon": {"available": True, "format": "ico", "sha256": "old", "mmh3": 1}}
    current["modules"]["web_metadata"] = {"favicon": {"available": True, "format": "png", "sha256": "new", "mmh3": 2}}
    result = compare_reports(baseline, current)
    assert {item["kind"] for item in result["comparison"]["web_paths"]["added"]} == {"favicon:format", "favicon:mmh3", "favicon:sha256"}
