import httpx
import pytest

from leakscan.http import SafeHTTPClient


class TrackingStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.iterations = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.iterations += 1
            yield chunk

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_archive_url_uses_head_and_never_iterates_body(app_config):
    stream = TrackingStream([b"archive bytes that must not be read"])
    methods = []

    async def handler(request):
        methods.append(request.method)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/x-7z-compressed", "Content-Length": "575000000"},
            stream=stream,
            request=request,
        )

    safe = SafeHTTPClient(app_config)
    await safe.client.aclose()
    safe.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        result = await safe.fetch_page("https://example.test/sample.7z")
    finally:
        await safe.client.aclose()
    assert methods == ["HEAD"]
    assert stream.iterations == 0
    assert result.body == b""
    assert result.is_binary


@pytest.mark.asyncio
async def test_unexpected_binary_is_aborted_after_first_small_chunk(app_config):
    stream = TrackingStream([b"7z\xbc\xaf'\x1c" + b"x" * 100, b"must-not-be-read"])

    async def handler(request):
        return httpx.Response(200, headers={"Content-Type": "application/octet-stream"}, stream=stream, request=request)

    safe = SafeHTTPClient(app_config)
    await safe.client.aclose()
    safe.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        result = await safe.fetch_page("https://example.test/download?id=1")
    finally:
        await safe.client.aclose()
    # Header classification aborts before any response chunk is consumed.
    assert stream.iterations == 0
    assert result.body == b""
    assert result.is_binary


@pytest.mark.asyncio
async def test_head_fallback_opens_range_get_without_reading_body(app_config):
    stream = TrackingStream([b"body must remain unread"])
    requests = []

    async def handler(request):
        requests.append((request.method, request.headers.get("range", "")))
        if request.method == "HEAD":
            return httpx.Response(405, request=request)
        return httpx.Response(
            206,
            headers={"Content-Type": "application/x-7z-compressed", "Content-Range": "bytes 0-0/500000000"},
            stream=stream,
            request=request,
        )

    safe = SafeHTTPClient(app_config)
    await safe.client.aclose()
    safe.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        result = await safe.probe_metadata("https://example.test/download")
    finally:
        await safe.client.aclose()
    assert requests == [("HEAD", ""), ("GET", "bytes=0-0")]
    assert stream.iterations == 0
    assert result.body == b""


@pytest.mark.asyncio
async def test_mislabeled_binary_is_stopped_after_bounded_sniff(app_config):
    first_chunk = b"7z\xbc\xaf'\x1c" + b"x" * (16384 - 6)
    stream = TrackingStream([first_chunk, b"must-not-be-read"])

    async def handler(request):
        return httpx.Response(200, headers={"Content-Type": "text/plain"}, stream=stream, request=request)

    safe = SafeHTTPClient(app_config)
    await safe.client.aclose()
    safe.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        result = await safe.fetch_page("https://example.test/download?id=2")
    finally:
        await safe.client.aclose()
    assert stream.iterations == 1
    assert result.is_binary
    assert result.body == b""


@pytest.mark.asyncio
async def test_redirect_to_archive_switches_from_get_to_head(app_config):
    archive_stream = TrackingStream([b"archive body must not be read"])
    requests = []

    async def handler(request):
        requests.append((request.method, str(request.url)))
        if request.url.path == "/landing":
            return httpx.Response(302, headers={"Location": "/files/sample.7z"}, request=request)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/x-7z-compressed", "Content-Length": "500000000"},
            stream=archive_stream,
            request=request,
        )

    safe = SafeHTTPClient(app_config)
    await safe.client.aclose()
    safe.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        result = await safe.fetch_page("https://example.test/landing")
    finally:
        await safe.client.aclose()
    assert requests == [
        ("GET", "https://example.test/landing"),
        ("HEAD", "https://example.test/files/sample.7z"),
    ]
    assert archive_stream.iterations == 0
    assert result.body == b""
    assert result.is_binary
