from cyberrecon.modules.passive.web_metadata import WebMetadataCollector


class _Response:
    def __init__(self, status_code, text, url):
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = {"Content-Type": "text/plain"}

    def raise_for_status(self):
        return None


class _Session:
    def __init__(self):
        self.headers = {}

    def get(self, url, **kwargs):
        if url.endswith("/.well-known/security.txt"):
            return _Response(200, "Contact: mailto:security@example.com\nExpires: 2027-01-01", url)
        if url.endswith("/robots.txt"):
            return _Response(200, "User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml", url)
        if url.endswith("/sitemap.xml"):
            return _Response(200, "<urlset><url><loc>https://example.com/</loc></url></urlset>", url)
        return _Response(404, "not found", url)


def test_web_metadata_collects_public_discovery_files():
    result = WebMetadataCollector(session=_Session(), retries=0).collect("example.com")

    assert result["resources"]["robots.txt"]["available"] is True
    assert "/admin" in result["robots"]["disallow"]
    assert result["sitemap"]["locations"] == ["https://example.com/"]
    assert result["security_txt"]["contact"] == "mailto:security@example.com"


def test_web_metadata_handles_missing_resources_without_failure():
    class EmptySession:
        headers = {}

        def get(self, url, **kwargs):
            return _Response(404, "", url)

    result = WebMetadataCollector(session=EmptySession(), retries=0).collect("example.com")
    assert result["errors"] == []
    assert result["resources"]["robots.txt"]["available"] is False
