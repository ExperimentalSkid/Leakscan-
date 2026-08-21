from urllib.parse import urlsplit

import httpx
import pytest

from leakscan.http import SafeHTTPClient


@pytest.mark.asyncio
async def test_robots_server_error_defaults_to_disallow(app_config) -> None:
    app_config.crawl.respect_robots_txt = True
    requests: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(503, request=request)

    safe = SafeHTTPClient(app_config)
    await safe.client.aclose()
    safe.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        result = await safe.fetch_page("https://example.test/report")
    finally:
        await safe.client.aclose()

    assert requests == ["https://example.test/robots.txt"]
    assert "robots.txt unreachable" in result.blocked_reason


@pytest.mark.asyncio
async def test_missing_robots_file_allows_page_fetch(app_config) -> None:
    app_config.crawl.respect_robots_txt = True
    requests: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        if request.url.path == "/robots.txt":
            return httpx.Response(404, request=request)
        return httpx.Response(200, text="public page", request=request)

    safe = SafeHTTPClient(app_config)
    await safe.client.aclose()
    safe.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        result = await safe.fetch_page("https://example.test/report")
    finally:
        await safe.client.aclose()

    assert requests == ["https://example.test/robots.txt", "https://example.test/report"]
    assert result.status_code == 200


@pytest.mark.asyncio
async def test_robots_redirect_is_followed_and_rules_apply_to_original_host(app_config) -> None:
    app_config.crawl.respect_robots_txt = True
    requests: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        if request.url.path == "/robots.txt":
            return httpx.Response(302, headers={"Location": "/robots-policy.txt"}, request=request)
        if request.url.path == "/robots-policy.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /private\n", request=request)
        raise AssertionError("disallowed target must not be requested")

    safe = SafeHTTPClient(app_config)
    await safe.client.aclose()
    safe.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        result = await safe.fetch_page("https://example.test/private/report")
    finally:
        await safe.client.aclose()

    assert requests == ["https://example.test/robots.txt", "https://example.test/robots-policy.txt"]
    assert result.blocked_reason == "robots.txt disallows this URL"


@pytest.mark.asyncio
async def test_redirect_to_private_network_is_rejected_before_request(app_config, monkeypatch) -> None:
    app_config.safety.reject_private_networks = True
    requests: list[str] = []

    def fake_safe_url(url: str, *_args) -> tuple[bool, str]:
        if (urlsplit(url).hostname or "") == "127.0.0.1":
            return False, "non-public IP address is not permitted"
        return True, ""

    monkeypatch.setattr("leakscan.http.safe_url", fake_safe_url)

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"}, request=request)

    safe = SafeHTTPClient(app_config)
    await safe.client.aclose()
    safe.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        result = await safe.fetch_page("https://example.test/start")
    finally:
        await safe.client.aclose()

    assert requests == ["https://example.test/start"]
    assert "non-public" in result.blocked_reason
