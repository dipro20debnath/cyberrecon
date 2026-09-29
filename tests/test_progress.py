import pytest

from cyberrecon.config import Config
from cyberrecon.scanner import ReconScanner, ScanError


class _DNS:
    def __init__(self, *args, **kwargs): pass
    def enumerate(self, target): return {"records": {}, "errors": []}


class _WHOIS:
    def lookup(self, target): return {"found": False, "data": {}}


class _CRT:
    def __init__(self, *args, **kwargs): pass
    def find_subdomains(self, target): return {"subdomains": [], "count": 0}


class _IP:
    def __init__(self, *args, **kwargs): pass
    def lookup(self, target): return {"ips": [], "records": [], "errors": []}


class _TECH:
    def __init__(self, *args, **kwargs): pass
    def detect(self, target): return {"technologies": [], "security": {"findings": []}}


class _TLS:
    def __init__(self, *args, **kwargs): pass
    def inspect(self, target): return {"reachable": False, "certificate": {}}


class _INTEL:
    def __init__(self, *args, **kwargs): pass
    def collect(self, target): return {"sources": {}, "skipped": []}


class _WEB:
    def __init__(self, *args, **kwargs): pass
    def collect(self, target): return {"resources": {}, "robots": {}, "sitemap": {}, "security_txt": {}, "errors": []}


def test_scanner_reports_monotonic_live_progress(tmp_path, monkeypatch):
    import cyberrecon.scanner as scanner_module

    monkeypatch.setattr(scanner_module, "DNSEnumerator", _DNS)
    monkeypatch.setattr(scanner_module, "WHOISLookup", _WHOIS)
    monkeypatch.setattr(scanner_module, "CrtshSubdomainFinder", _CRT)
    monkeypatch.setattr(scanner_module, "IPIntelligence", _IP)
    monkeypatch.setattr(scanner_module, "TechnologyDetector", _TECH)
    monkeypatch.setattr(scanner_module, "TLSInspector", _TLS)
    monkeypatch.setattr(scanner_module, "ExternalIntelligence", _INTEL)
    monkeypatch.setattr(scanner_module, "WebMetadataCollector", _WEB)

    events = []
    results = ReconScanner(Config(tmp_path / "config.yaml")).scan("example.com", progress_callback=lambda *event: events.append(event))
    assert results["target"] == "example.com"
    assert results["run_id"]
    assert results["duration_ms"] >= 0
    assert results["telemetry"]["module_status"]["risk"] == "ok"
    assert results["telemetry"]["total_duration_ms"] == results["duration_ms"]
    assert events[0][0] == 0
    assert events[-1][0] == events[-1][1]
    assert all(event[1] == events[-1][1] for event in events)
    assert all(current[0] >= previous[0] for previous, current in zip(events, events[1:]))


def test_scanner_supports_focused_module_selection(tmp_path, monkeypatch):
    import cyberrecon.scanner as scanner_module

    monkeypatch.setattr(scanner_module, "DNSEnumerator", _DNS)
    monkeypatch.setattr(scanner_module, "TLSInspector", _TLS)
    events = []
    results = ReconScanner(Config(tmp_path / "config.yaml")).scan(
        "example.com",
        only="dns,tls",
        skip="tls",
        progress_callback=lambda *event: events.append(event),
    )
    assert set(results["modules"]) == {"dns"}
    assert results["scan_plan"]["stages"] == ["dns", "risk"]
    assert events[-1][0] == events[-1][1] == 2


def test_scanner_rejects_active_module_in_passive_mode(tmp_path):
    with pytest.raises(ScanError, match="unavailable"):
        ReconScanner(Config(tmp_path / "config.yaml")).scan("example.com", only="active.ports")
