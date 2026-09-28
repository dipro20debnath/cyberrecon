from types import SimpleNamespace

from cyberrecon.modules.passive.dns_enum import DNSEnumerator
from cyberrecon.modules.passive.subdomain_crtsh import CrtshSubdomainFinder


class FakeSession:
    def __init__(self, payload):
        self.payload = payload
        self.headers = {}

    def get(self, *args, **kwargs):
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: self.payload,
            status_code=200,
        )


def test_crtsh_filters_to_requested_domain():
    session = FakeSession([
        {"name_value": "*.example.com\napi.example.com\nevil-example.com", "id": 1},
    ])
    result = CrtshSubdomainFinder(session=session).find_subdomains("example.com")
    assert result["subdomains"] == ["api.example.com", "example.com"]


def test_crtsh_can_exclude_wildcard_names():
    session = FakeSession([{"name_value": "*.example.com\napi.example.com", "id": 1}])
    result = CrtshSubdomainFinder(session=session).find_subdomains("example.com", wildcard=False)
    assert result["subdomains"] == ["api.example.com"]


def test_dns_invalid_target_is_reported():
    result = DNSEnumerator().enumerate("not a target")
    assert result["errors"]
