from __future__ import annotations

import csv
import sqlite3
from urllib.parse import parse_qs

import httpx
import pytest

from leakscan.database import CaseDatabase
from leakscan.models import SearchResult
from leakscan.providers import build_providers
from leakscan.providers.archive_org_items import ArchiveOrgItemsProvider
from leakscan.providers.arquivo_pt import ArquivoPtProvider
from leakscan.providers.base import ProviderUnavailable, SearchProvider
from leakscan.providers.gdelt import GDELTProvider
from leakscan.providers.hybrid_analysis import HybridAnalysisProvider
from leakscan.providers.leakix import LeakIXProvider
from leakscan.providers.mojeek import MojeekProvider
from leakscan.providers.searxng import SearXNGProvider
from leakscan.reporting import export_reports, prepare_output
from leakscan.search import SearchEngine


@pytest.mark.asyncio
async def test_arquivo_pt_maps_original_and_archive_urls() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["q"] == '"Example Dataset.7z"'
        return httpx.Response(200, json={"response_items": [{
            "title": "Example Dataset",
            "originalURL": "https://files.example/Example-Dataset.7z",
            "linkToArchive": "https://arquivo.pt/wayback/20250101000000/https://files.example/Example-Dataset.7z",
            "tstamp": "20250101000000",
            "digest": "digest-1",
            "snippet": "Found <em>Example Dataset.7z</em> in an old listing.",
        }]}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await ArquivoPtProvider().search(client, '"Example Dataset.7z"', 10)

    assert results[0].url == "https://files.example/Example-Dataset.7z"
    assert results[0].source_url.startswith("https://arquivo.pt/wayback/")
    assert results[0].excerpt == "Found Example Dataset.7z in an old listing."


@pytest.mark.asyncio
async def test_archive_org_items_searches_uploaded_item_metadata() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["output"] == "json"
        assert "identifier" in request.url.params.get_list("fl[]")
        return httpx.Response(200, json={"response": {"docs": [{
            "identifier": "example-dataset-item",
            "title": "Example Dataset",
            "description": "Archive item containing Example Dataset.7z",
            "mediatype": "data",
            "publicdate": "2025-01-02T03:04:05Z",
        }]}}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await ArchiveOrgItemsProvider().search(client, '"Example Dataset.7z"', 10)

    assert results[0].url == "https://archive.org/details/example-dataset-item"
    assert results[0].record_id == "example-dataset-item"


@pytest.mark.asyncio
async def test_gdelt_results_are_labelled_supporting_news_references() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"articles": [{
            "url": "https://news.example/report",
            "title": "Example Dataset investigation",
            "seendate": "20250102T030405Z",
            "domain": "news.example",
            "language": "English",
            "sourcecountry": "United Kingdom",
        }]}, request=request)

    provider = GDELTProvider()
    assert provider.request_key(f'"{"a" * 64}"') == ""
    assert provider.request_key('"https://files.example/item"') == ""
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await provider.search(client, '"Example Dataset" leak', 10)

    assert results[0].reference_kind == "news_report"
    assert results[0].url == "https://news.example/report"


@pytest.mark.asyncio
async def test_searxng_requires_operator_endpoint_and_maps_results(monkeypatch) -> None:
    monkeypatch.delenv("SEARXNG_URL", raising=False)
    provider = SearXNGProvider()
    assert provider.available() == (False, "requires operator-supplied SEARXNG_URL")
    monkeypatch.setenv("SEARXNG_URL", "https://search.example/base")

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/base/search"
        assert request.url.params["format"] == "json"
        assert request.url.params["safesearch"] == "0"
        return httpx.Response(200, json={"results": [{
            "url": "https://files.example/item",
            "title": "Example Dataset",
            "content": "Public <b>listing</b>",
            "engine": "example-engine",
        }]}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await provider.search(client, '"Example Dataset"', 10)

    assert results[0].excerpt == "Public listing"


@pytest.mark.asyncio
async def test_mojeek_maps_documented_json_response(monkeypatch) -> None:
    monkeypatch.setenv("MOJEEK_API_KEY", "test-key")

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["fmt"] == "json"
        assert request.url.params["safe"] == "0"
        return httpx.Response(200, json={"response": {
            "status": "OK",
            "results": [{
                "url": "https://files.example/item",
                "title": "Example Dataset",
                "desc": "Independent web result",
                "date": "Tue Jan 02 03:04:05 2025",
            }],
        }}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await MojeekProvider().search(client, '"Example Dataset"', 10)

    assert results[0].title == "Example Dataset"


@pytest.mark.asyncio
async def test_hybrid_analysis_uses_metadata_search_only(monkeypatch) -> None:
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "test-key")
    requests: list[tuple[str, str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        assert request.headers["api-key"] == "test-key"
        if request.url.path.endswith("/search/terms"):
            form = parse_qs(request.content.decode())
            assert form["filename"] == ["Example Dataset.7z"]
            return httpx.Response(200, json=[{"result": [{
                "sha256": "b" * 64,
                "submit_name": "Example Dataset.7z",
                "environment_id": 160,
                "analysis_start_time": "2025-01-02T03:04:05Z",
                "type": "7zip",
                "size": 1234,
            }]}], request=request)
        return httpx.Response(200, json={
            "sha256s": ["c" * 64],
            "reports": [{"id": "report-1", "environment_id": 160, "verdict": "no specific threat"}],
        }, request=request)

    provider = HybridAnalysisProvider()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        filename_results = await provider.search(client, '"Example Dataset.7z"', 10)
        hash_results = await provider.search(client, f'"{"a" * 64}"', 10)

    assert requests == [
        ("POST", "/api/v2/search/terms"),
        ("GET", "/api/v2/search/hash"),
    ]
    assert filename_results[0].reference_kind == "analysis_artifact"
    assert hash_results[0].url == f"https://hybrid-analysis.com/sample/{'c' * 64}"
    assert all("download" not in path for _method, path in requests)


@pytest.mark.asyncio
async def test_leakix_maps_web_exposure_and_honors_rate_limit_header(monkeypatch) -> None:
    monkeypatch.setenv("LEAKIX_API_KEY", "test-key")
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 2:
            return httpx.Response(429, headers={"x-limited-for": "344ms"}, request=request)
        return httpx.Response(200, json=[{
            "event_type": "leak",
            "event_source": "DirectoryListingPlugin",
            "event_fingerprint": "event-1",
            "host": "files.example",
            "port": "443",
            "protocol": "https",
            "time": "2025-01-02T03:04:05Z",
            "http": {"url": "/public/", "title": "Example Dataset listing"},
            "summary": "Found Example Dataset.7z",
            "leak": {"dataset": {"files": 1, "rows": 0, "size": 1234}},
        }], request=request)

    provider = LeakIXProvider()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await provider.search(client, '"Example Dataset.7z"', 10)
        with pytest.raises(ProviderUnavailable) as raised:
            await provider.search(client, '"Example Dataset.zip"', 10)

    assert results[0].url == "https://files.example/public/"
    assert raised.value.retry_after_seconds == pytest.approx(0.344)


class SupportingReferenceProvider(SearchProvider):
    name = "supporting"

    async def search(self, client, query: str, limit: int):
        return [SearchResult(
            url="https://news.example/example-dataset",
            title="Example Dataset.7z",
            provider=self.name,
            query=query,
            reference_kind="news_report",
        )]


@pytest.mark.asyncio
async def test_supporting_reference_is_not_a_target_candidate(app_config) -> None:
    prepare_output(app_config)
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    engine = SearchEngine(app_config, database)
    engine.providers = {"supporting": SupportingReferenceProvider()}
    try:
        await engine.run(['"Example Dataset.7z"'], ["supporting"])
        queued = database.claim_pending(1)[0]
        assert queued["reference_kind"] == "news_report"
        database.mark_url(queued["normalized_url"], "done")
        export_reports(app_config, database)
    finally:
        database.close()

    with (app_config.output_dir / "candidate_urls.csv").open(encoding="utf-8-sig", newline="") as handle:
        assert list(csv.DictReader(handle)) == []
    with (app_config.output_dir / "supporting_references.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["reference_type"] == "news_report"


def test_resumable_database_migrates_reference_kind_column(tmp_path) -> None:
    path = tmp_path / "old.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("""CREATE TABLE url_queue (
        normalized_url TEXT PRIMARY KEY, original_url TEXT NOT NULL, referrer_url TEXT,
        source TEXT, query_text TEXT, depth INTEGER NOT NULL, priority INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
        last_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    )""")
    connection.commit()
    connection.close()

    database = CaseDatabase(path)
    try:
        columns = {row["name"] for row in database.connection.execute("PRAGMA table_info(url_queue)")}
    finally:
        database.close()
    assert "reference_kind" in columns


def test_provider_registry_contains_expanded_sources() -> None:
    assert {
        "archive_org_items", "archive_org_files", "arquivo_pt", "gdelt", "searxng", "mojeek",
        "github_releases", "gitlab_assets", "huggingface", "kaggle", "hybrid_analysis", "leakix",
    } <= set(build_providers())
