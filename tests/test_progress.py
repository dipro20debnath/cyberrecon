from cyberrecon.config import Config
from cyberrecon.scanner import ReconScanner


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


def test_scanner_reports_monotonic_live_progress(tmp_path, monkeypatch):
    import cyberrecon.scanner as scanner_module

    monkeypatch.setattr(scanner_module, "DNSEnumerator", _DNS)
    monkeypatch.setattr(scanner_module, "WHOISLookup", _WHOIS)
    monkeypatch.setattr(scanner_module, "CrtshSubdomainFinder", _CRT)
    monkeypatch.setattr(scanner_module, "IPIntelligence", _IP)
    monkeypatch.setattr(scanner_module, "TechnologyDetector", _TECH)
    monkeypatch.setattr(scanner_module, "TLSInspector", _TLS)
    monkeypatch.setattr(scanner_module, "ExternalIntelligence", _INTEL)

    events = []
    results = ReconScanner(Config(tmp_path / "config.yaml")).scan("example.com", progress_callback=lambda *event: events.append(event))
    assert results["target"] == "example.com"
    assert events[0][0] == 0
    assert events[-1][0] == events[-1][1]
    assert all(event[1] == events[-1][1] for event in events)
    assert all(current[0] >= previous[0] for previous, current in zip(events, events[1:]))
