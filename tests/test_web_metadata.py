from cyberrecon.modules.passive.web_metadata import WebMetadataCollector


class _Response:
    def __init__(self, status_code, text, url):
        self.status_code = status_code
        self.text = text
        self.content = text.encode()
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


def test_web_metadata_fingerprints_same_origin_declared_favicon():
    class FaviconSession:
        headers = {}

        def get(self, url, **kwargs):
            if url.endswith("/favicon.ico"):
                return _BinaryResponse(404, b"", url, "image/x-icon")
            if url.endswith("/"):
                return _BinaryResponse(200, b'<html><link rel="icon" href="/assets/site.ico"></html>', url, "text/html")
            if url.endswith("/assets/site.ico"):
                return _BinaryResponse(200, b"\x00\x00\x01\x00icon-bytes", url, "image/x-icon")
            return _BinaryResponse(404, b"", url, "text/plain")

    result = WebMetadataCollector(session=FaviconSession(), retries=0).collect("example.com")
    favicon = result["favicon"]
    assert favicon["available"] is True
    assert favicon["source"] == "html:/assets/site.ico"
    assert favicon["format"] == "ico"
    assert favicon["bytes"] == len(b"\x00\x00\x01\x00icon-bytes")
    assert len(favicon["sha256"]) == 64
    assert isinstance(favicon["mmh3"], int)
    assert WebMetadataCollector._murmur3_32(b"foo") == -156908512


class _BinaryResponse:
    def __init__(self, status_code, content, url, content_type):
        self.status_code = status_code
        self.content = content
        self.text = content.decode("latin-1", errors="replace")
        self.url = url
        self.headers = {"Content-Type": content_type}

    def raise_for_status(self):
        return None
