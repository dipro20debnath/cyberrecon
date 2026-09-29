from types import SimpleNamespace

from cyberrecon.modules.passive.dns_enum import DNSEnumerator
from cyberrecon.modules.passive.security import SecurityHeadersAuditor
from cyberrecon.modules.passive.subdomain_crtsh import CrtshSubdomainFinder
from cyberrecon.modules.passive.tls import TLSInspector


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


class FakeAnswers(list):
    rrset = SimpleNamespace(ttl=300)


class FakeDNSResolver:
    timeout = 0
    lifetime = 0

    def resolve(self, name, record_type):
        values = {
            ("example.com", "MX"): [SimpleNamespace(exchange=SimpleNamespace(to_text=lambda omit_final_dot=True: "mail.example.com"), preference=10)],
            ("example.com", "TXT"): [SimpleNamespace(strings=[b"v=spf1 -all"])],
            ("example.com", "CAA"): [SimpleNamespace(__str__=lambda self: '0 issue "letsencrypt.org"')],
            ("example.com", "DNSKEY"): [SimpleNamespace(__str__=lambda self: "256 3 13 key")],
            ("_dmarc.example.com", "TXT"): [SimpleNamespace(strings=[b"v=DMARC1; p=quarantine"])],
        }
        return FakeAnswers(values.get((name, record_type), []))


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


def test_dns_posture_detects_dnssec_caa_spf_and_dmarc():
    result = DNSEnumerator(resolver=FakeDNSResolver()).enumerate("example.com")
    posture = result["posture"]
    assert posture["dnssec"]["status"] == "key_material_detected"
    assert posture["caa"]["present"] is True
    assert posture["email_authentication"]["spf"]["present"] is True
    assert posture["email_authentication"]["dmarc"]["policy"] == "quarantine"


def test_security_audit_accepts_csp_frame_ancestors():
    result = SecurityHeadersAuditor.audit({
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
    }, "https://example.com")
    assert "x-frame-options" in result["present"]
    assert any(item["header"] == "strict-transport-security" for item in result["findings"])


def test_tls_invalid_target_is_reported_without_network():
    result = TLSInspector().inspect("not a target")
    assert result["error"]
