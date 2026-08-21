from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from leakscan.database import CaseDatabase
from leakscan.http import HostRateLimiter
from leakscan.models import SearchResult
from leakscan.providers.archive_org import ArchiveOrgProvider
from leakscan.providers.base import ProviderUnavailable, SearchProvider
from leakscan.providers.commoncrawl import CommonCrawlProvider
from leakscan.providers.urlscan import URLScanProvider
from leakscan.search import SearchEngine


class FakeProvider(SearchProvider):
    name = "fake"

    def __init__(self, behavior: Callable):
        self.behavior = behavior
        self.calls = 0

    def request_key(self, query: str) -> str:
        return query.split(":", 1)[0]

    async def search(self, client, query: str, limit: int):
        self.calls += 1
        return self.behavior(query)


class HTTPFakeProvider(FakeProvider):
    async def search(self, client, query: str, limit: int):
        self.calls += 1
        await client.get("https://provider.example/search", params={"q": query})
        return self.behavior(query)


def mock_transport() -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(200, json={}, request=request))


@pytest.mark.asyncio
async def test_provider_requests_honor_host_delay(monkeypatch) -> None:
    clock = [100.0]
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr("leakscan.http.monotonic", lambda: clock[0])
    monkeypatch.setattr("leakscan.http.asyncio.sleep", fake_sleep)
    limiter = HostRateLimiter(5)

    await limiter.wait("https://provider.example/search?q=one")
    await limiter.wait("https://provider.example/search?q=two")

    assert sleeps == [5.0]


@pytest.mark.asyncio
async def test_provider_specific_minimum_interval(monkeypatch) -> None:
    clock = [100.0]
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr("leakscan.providers.base.monotonic", lambda: clock[0])
    monkeypatch.setattr("leakscan.providers.base.asyncio.sleep", fake_sleep)
    provider = FakeProvider(lambda _query: [])
    provider.minimum_request_interval_seconds = 12

    await provider.wait_for_request_slot()
    await provider.wait_for_request_slot()

    assert sleeps == [12]


@pytest.mark.asyncio
async def test_rate_limit_opens_circuit_after_first_429(app_config) -> None:
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")

    def rate_limited(_query: str):
        raise ProviderUnavailable("rate limited", status_code=429, retry_after_seconds=120)

    provider = FakeProvider(rate_limited)
    engine = SearchEngine(app_config, database)
    engine.providers = {"fake": provider}
    try:
        await engine.run(["one:first", "two:second"], ["fake"])
        cooldown = database.get_provider_state("fake", "cooldown")
        assert provider.calls == 1
        assert cooldown is not None
        assert "until" in cooldown
        assert database.query_status("fake", "two:second") is None
    finally:
        database.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [401, 403])
async def test_access_denial_disables_provider_after_one_request(app_config, status_code: int) -> None:
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")

    def denied(_query: str):
        raise ProviderUnavailable("access denied", status_code=status_code)

    provider = FakeProvider(denied)
    engine = SearchEngine(app_config, database)
    engine.providers = {"fake": provider}
    try:
        await engine.run(["one:first", "two:second"], ["fake"])
        assert provider.calls == 1
        assert database.query_status("fake", "two:second") is None
    finally:
        database.close()


@pytest.mark.asyncio
async def test_equivalent_provider_requests_are_sent_once(app_config) -> None:
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    provider = HTTPFakeProvider(lambda _query: [])
    engine = SearchEngine(app_config, database, transport=mock_transport())
    engine.providers = {"fake": provider}
    try:
        await engine.run(["same:first", "same:second"], ["fake"])
        assert provider.calls == 1
        assert database.query_status("fake", "same:first") == "done"
        assert database.query_status("fake", "same:second") == "done"
    finally:
        database.close()


def test_archive_index_deduplicates_extension_variants() -> None:
    provider = ArchiveOrgProvider()
    assert provider.request_key('"Example Dataset.7z"') == provider.request_key('"Example Dataset.zip"')


@pytest.mark.parametrize("provider", [ArchiveOrgProvider(), CommonCrawlProvider()])
def test_archive_index_keeps_full_phrase_fingerprint(provider: SearchProvider) -> None:
    pattern = provider.request_key('"Example - National Customer Archive.7z"')

    assert pattern == "*example---national-customer-archive*"
    assert pattern != "*national*"


@pytest.mark.parametrize("provider", [ArchiveOrgProvider(), CommonCrawlProvider()])
def test_archive_index_skips_weak_single_word_fallback(provider: SearchProvider) -> None:
    assert provider.request_key('"National"') == ""


@pytest.mark.parametrize("provider", [ArchiveOrgProvider(), CommonCrawlProvider()])
def test_archive_index_preserves_object_identifier(provider: SearchProvider) -> None:
    assert provider.request_key('"Ab12Cd34Ef56Gh"') == "*ab12cd34ef56gh*"


@pytest.mark.parametrize("provider", [ArchiveOrgProvider(), CommonCrawlProvider()])
def test_archive_index_extracts_identifier_from_site_query(provider: SearchProvider) -> None:
    assert provider.request_key("site:example.test Ab12Cd34Ef56Gh") == "*ab12cd34ef56gh*"


@pytest.mark.asyncio
async def test_urlscan_escapes_reserved_characters_and_records_quota_reset(monkeypatch) -> None:
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    queries: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        queries.append(request.url.params["q"])
        return httpx.Response(
            200,
            json={"results": []},
            headers={"X-Rate-Limit-Remaining": "0", "X-Rate-Limit-Reset-After": "17"},
            request=request,
        )

    provider = URLScanProvider()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await provider.search(client, '"Example-Archive.7z"', 10)

    assert r"Example\-Archive.7z" in queries[0]
    assert "task.url" in queries[0]
    assert "filename" in queries[0]
    assert provider.consume_rate_limit_cooldown() == 17


@pytest.mark.asyncio
async def test_urlscan_authenticated_result_metadata_finds_correlated_request(monkeypatch) -> None:
    monkeypatch.setenv("URLSCAN_API_KEY", "free-account-key")
    paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        assert request.headers["api-key"] == "free-account-key"
        if request.url.path == "/api/v1/search/":
            return httpx.Response(200, json={"results": [{
                "_id": "01965552-2d9a-73e7-905a-5b370c722afa",
                "page": {"url": "https://listing.example/item", "title": "Example Archive"},
                "task": {"url": "https://listing.example/item", "time": "2025-01-02T03:04:05Z"},
            }]}, request=request)
        return httpx.Response(200, json={
            "task": {"time": "2025-01-02T03:04:05Z"},
            "data": {"requests": [{
                "request": {"request": {"url": "https://mirror.example/files/Example-Archive.7z"}},
                "response": {"response": {
                    "status": 200,
                    "mimeType": "application/x-7z-compressed",
                    "hash": "a" * 64,
                    "headers": [
                        {"name": "Content-Disposition", "value": 'attachment; filename="Example-Archive.7z"'},
                        {"name": "Content-Length", "value": "1234"},
                    ],
                }},
            }]},
        }, request=request)

    provider = URLScanProvider()
    provider.max_result_pages_per_query = 3
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await provider.search(client, '"Example-Archive.7z"', 10)

    assert paths == [
        "/api/v1/search/",
        "/api/v1/result/01965552-2d9a-73e7-905a-5b370c722afa/",
    ]
    assert results[0].url == "https://mirror.example/files/Example-Archive.7z"
    assert results[0].metadata["size"] == 1234
    assert results[0].metadata["archive_body_bytes_read"] == 0


@pytest.mark.asyncio
async def test_commoncrawl_404_means_no_captures() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/collinfo.json":
            return httpx.Response(200, json=[{
                "cdx-api": "https://index.commoncrawl.org/CC-MAIN-test-index"
            }], request=request)
        return httpx.Response(404, text="No Captures found", request=request)

    provider = CommonCrawlProvider()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await provider.search(client, '"Example Archive.7z"', 10)

    assert results == []


@pytest.mark.asyncio
async def test_urlscan_429_uses_provider_reset_header() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            headers={"X-Rate-Limit-Reset-After": "42"},
            request=request,
        )

    provider = URLScanProvider()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ProviderUnavailable) as raised:
            await provider.search(client, '"Example Archive.7z"', 10)

    assert raised.value.status_code == 429
    assert raised.value.retry_after_seconds == 42


@pytest.mark.asyncio
async def test_successful_final_quota_request_opens_persisted_cooldown(app_config) -> None:
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    provider = FakeProvider(lambda _query: [])
    provider._rate_limit_cooldown_seconds = 17
    engine = SearchEngine(app_config, database)
    engine.providers = {"fake": provider}
    try:
        await engine.run(["one:first", "two:second"], ["fake"])
        assert provider.calls == 1
        assert database.query_status("fake", "one:first") == "done"
        assert database.query_status("fake", "two:second") is None
        assert database.get_provider_state("fake", "cooldown") is not None
    finally:
        database.close()


@pytest.mark.asyncio
async def test_provider_request_budget_persists_across_pivot_rounds(app_config) -> None:
    app_config.search.max_queries_per_provider = 2
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    provider = HTTPFakeProvider(lambda _query: [])
    engine = SearchEngine(app_config, database, transport=mock_transport())
    engine.providers = {"fake": provider}
    try:
        await engine.run(["one:first", "two:second", "three:third"], ["fake"])
        await engine.run(["one:first", "two:second", "three:third", "four:fourth"], ["fake"])

        assert provider.calls == 2
        assert database.provider_request_count("fake") == 2
    finally:
        database.close()


@pytest.mark.asyncio
async def test_provider_stops_after_adaptive_plateau(app_config) -> None:
    app_config.search.max_queries_per_provider = 60
    app_config.search.minimum_queries_before_plateau = 3
    app_config.search.stop_after_stale_queries = 2
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    provider = HTTPFakeProvider(lambda _query: [])
    engine = SearchEngine(app_config, database, transport=mock_transport())
    engine.providers = {"fake": provider}
    try:
        await engine.run([f"query-{index}" for index in range(20)], ["fake"])

        assert provider.calls == 3
        assert database.provider_request_count("fake") == 3
    finally:
        database.close()


@pytest.mark.asyncio
async def test_duplicate_provider_records_enqueue_one_canonical_url(app_config) -> None:
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    provider = FakeProvider(lambda _query: [
        SearchResult(url="https://files.example/item/abc/", provider="fake"),
        SearchResult(url="https://files.example/item/abc", provider="fake"),
    ])
    engine = SearchEngine(app_config, database)
    engine.providers = {"fake": provider}
    try:
        await engine.run(["one:first"], ["fake"])

        assert database.queue_counts() == {"pending": 1}
        assert len(list(database.iter_findings())) == 2
    finally:
        database.close()


@pytest.mark.asyncio
async def test_new_candidate_is_processed_before_search_continues(app_config, monkeypatch) -> None:
    calls: list[int] = []

    async def fake_run_pending(crawler, _http) -> int:
        calls.append(crawler.database.queue_counts().get("pending", 0))
        return 0

    monkeypatch.setattr("leakscan.search.Crawler.run_pending", fake_run_pending)
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    provider = FakeProvider(lambda _query: [
        SearchResult(url="https://files.example/item/new", provider="fake")
    ])
    engine = SearchEngine(app_config, database)
    engine.providers = {"fake": provider}
    try:
        await engine.run(["one:first"], ["fake"], verify_immediately=True)

        assert calls == [1]
    finally:
        database.close()


def test_urlscan_skips_bare_hash_queries() -> None:
    provider = URLScanProvider()

    assert provider.request_key(f'"{"a" * 64}"') == ""
