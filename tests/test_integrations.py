import json

import requests

from cyberrecon.config import Config
from cyberrecon.integrations import ExternalIntelligence, _looks_like_ip
from cyberrecon.modules.passive.ip_intelligence import IPIntelligence


def test_external_intelligence_rotates_on_auth_failure_without_leaking_keys(tmp_path, monkeypatch):
    config = Config(tmp_path / "config.yaml")
    config.config["api_keys"]["virustotal"] = ["key-a", "key-b"]
    intelligence = ExternalIntelligence(config)
    calls = []

    def fake_virustotal(target):
        calls.append(intelligence._active_keys["virustotal"])
        if len(calls) == 1:
            raise RuntimeError("401 Client Error: Unauthorized")
        return {"status": "ok", "target": target}

    monkeypatch.setattr(intelligence, "_virustotal", fake_virustotal)
    result = intelligence.collect("example.com")

    assert result["sources"]["virustotal"]["status"] == "ok"
    assert len(calls) == 2
    rotation = result["credential_rotation"]["virustotal"]
    assert rotation["key_count"] == 2
    assert rotation["attempts"] == 2
    assert rotation["fallback_used"] is True
    assert "key-a" not in json.dumps(result)
    assert "key-b" not in json.dumps(result)


def test_external_intelligence_key_order_is_deterministic():
    first = ExternalIntelligence._key_order("virustotal", "example.com", 3)
    second = ExternalIntelligence._key_order("virustotal", "example.com", 3)
    assert first == second
    assert sorted(first) == [0, 1, 2]


def test_ip_detection_rejects_non_ip_numeric_strings():
    assert _looks_like_ip("192.0.2.10") is True
    assert _looks_like_ip("2001:db8::10") is True
    assert _looks_like_ip("1.0") is False
    assert _looks_like_ip("20260930") is False


def test_ip_intelligence_rotates_tokens_on_auth_failure():
    class Response:
        status_code = 200
        url = "https://ipinfo.io/192.0.2.10/json"
        headers = {"Content-Type": "application/json"}

        def raise_for_status(self):
            return None

        def json(self):
            return {"ip": "192.0.2.10", "country": "ZZ"}

    class Session:
        headers = {}

        def __init__(self):
            self.calls = 0

        def get(self, *args, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise requests.HTTPError("401 Client Error: Unauthorized token=secret-a")
            return Response()

    session = Session()
    result = IPIntelligence(["secret-a", "secret-b"], session=session, retries=0).lookup("192.0.2.10")
    rotation = result["credential_rotation"]["192.0.2.10"]
    assert result["records"][0]["ip"] == "192.0.2.10"
    assert rotation["attempts"] == 2
    assert rotation["fallback_used"] is True
    assert result["errors"] == []
