import requests

from cyberrecon.utils.http import JsonFileCache, JsonHttpClient


class _Response:
    status_code = 200
    url = "https://example.test/data"
    headers = {"Content-Type": "application/json"}
    text = "<html>ok</html>"

    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class _FlakySession:
    def __init__(self):
        self.headers = {}
        self.calls = 0

    def get(self, *args, **kwargs):
        self.calls += 1
        if self.calls == 1:
            raise requests.ConnectionError("temporary failure")
        return _Response({"ok": True})


class _CountingSession:
    def __init__(self):
        self.headers = {}
        self.calls = 0

    def get(self, *args, **kwargs):
        self.calls += 1
        return _Response({"calls": self.calls})


def test_json_http_client_retries_transient_failure():
    session = _FlakySession()
    client = JsonHttpClient(timeout=1, retries=1, session=session)

    assert client.get_json("https://example.test/data") == {"ok": True}
    assert session.calls == 2


def test_json_http_client_caches_json_and_text(tmp_path):
    cache = JsonFileCache(tmp_path / "cache", ttl=60)
    session = _CountingSession()
    client = JsonHttpClient(timeout=1, retries=0, cache=cache, session=session)

    assert client.get_json("https://example.test/data", cache_key="json-key") == {"calls": 1}
    assert client.get_json("https://example.test/data", cache_key="json-key") == {"calls": 1}
    assert session.calls == 1

    text = client.get_text("https://example.test/page", cache_key="text-key")
    assert text["text"] == "<html>ok</html>"
    assert text["status_code"] == 200
    assert isinstance(text["headers"], dict)
    assert session.calls == 2
