from __future__ import annotations

import httpx
import pytest

from leakscan.database import CaseDatabase
from leakscan.providers.archive_org import ArchiveOrgProvider
from leakscan.providers.archive_org_files import ArchiveOrgFilesProvider
from leakscan.providers.archive_org_items import ArchiveOrgItemsProvider
from leakscan.providers.gdelt import GDELTProvider
from leakscan.providers.github_releases import GitHubReleasesProvider
from leakscan.providers.gitlab_assets import GitLabAssetsProvider
from leakscan.providers.huggingface import HuggingFaceProvider
from leakscan.providers.kaggle import KaggleProvider
from leakscan.search import SearchEngine


@pytest.mark.asyncio
async def test_archive_org_file_manifest_emits_file_metadata_without_payload_request() -> None:
    paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/advancedsearch.php":
            return httpx.Response(200, json={"response": {"numFound": 1, "docs": [{
                "identifier": "example-item",
                "title": "Example item",
                "publicdate": "2025-01-02T03:04:05Z",
            }]}}, request=request)
        return httpx.Response(200, json={"files": [{
            "name": "Example Dataset.7z",
            "size": "1234",
            "format": "7-Zip",
            "source": "original",
            "md5": "a" * 32,
            "sha1": "b" * 40,
        }]}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await ArchiveOrgFilesProvider().search(client, '"Example Dataset.7z"', 10)

    assert paths == ["/advancedsearch.php", "/metadata/example-item"]
    assert results[0].url.endswith("/download/example-item/Example%20Dataset.7z")
    assert results[0].metadata["file_size"] == "1234"
    assert results[0].metadata["hashes"]["md5"] == "a" * 32


@pytest.mark.asyncio
async def test_huggingface_searches_repository_metadata_without_resolver_download(monkeypatch) -> None:
    monkeypatch.setenv("HF_TOKEN", "test-token")
    paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        assert request.headers["authorization"] == "Bearer test-token"
        if request.url.path == "/api/datasets":
            return httpx.Response(200, json=[{
                "id": "owner/example-data",
                "sha": "abc123",
                "lastModified": "2025-01-02T03:04:05Z",
                "siblings": [{"rfilename": "Example Dataset.7z", "size": 1234}],
            }], request=request)
        return httpx.Response(200, json=[], request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await HuggingFaceProvider().search(client, '"Example Dataset.7z"', 10)

    assert paths == ["/api/datasets", "/api/models", "/api/spaces"]
    assert all("resolve" not in path for path in paths)
    assert results[0].metadata["repository_id"] == "owner/example-data"
    assert "/blob/abc123/Example%20Dataset.7z" in results[0].url


@pytest.mark.asyncio
async def test_kaggle_searches_file_lists_without_download() -> None:
    paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/api/v1/datasets/list":
            return httpx.Response(200, json=[{
                "ref": "owner/example-data",
                "title": "Example data",
                "lastUpdated": "2025-01-02T03:04:05Z",
            }], request=request)
        return httpx.Response(200, json={
            "datasetFiles": [{"name": "Example Dataset.7z", "totalBytes": 1234}]
        }, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await KaggleProvider().search(client, '"Example Dataset.7z"', 10)

    assert paths == ["/api/v1/datasets/list", "/api/v1/datasets/list/owner/example-data"]
    assert all("download" not in path for path in paths)
    assert results[0].metadata["file_name"] == "Example Dataset.7z"
    assert "select=Example+Dataset.7z" in results[0].url


@pytest.mark.asyncio
async def test_github_release_asset_metadata(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/search/repositories":
            return httpx.Response(200, json={"total_count": 1, "items": [{
                "full_name": "owner/repository",
                "html_url": "https://github.com/owner/repository",
            }]}, request=request)
        return httpx.Response(200, json=[{
            "id": 7,
            "tag_name": "v1",
            "html_url": "https://github.com/owner/repository/releases/tag/v1",
            "published_at": "2025-01-02T03:04:05Z",
            "assets": [{
                "id": 8,
                "name": "Example Dataset.7z",
                "size": 1234,
                "digest": f"sha256:{'a' * 64}",
                "browser_download_url": (
                    "https://github.com/owner/repository/releases/download/v1/Example.Dataset.7z"
                ),
            }],
        }], request=request)

    provider = GitHubReleasesProvider()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await provider.search(client, '"Example Dataset.7z"', 10)

    assert results[0].metadata["digest"] == f"sha256:{'a' * 64}"
    assert results[0].source_url.endswith("/releases/tag/v1")


@pytest.mark.asyncio
async def test_gitlab_release_and_package_file_metadata() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v4/projects":
            data = [{"id": 24, "path_with_namespace": "owner/repository"}]
        elif path.endswith("/releases"):
            data = [{
                "tag_name": "v1",
                "released_at": "2025-01-02T03:04:05Z",
                "_links": {"self": "https://gitlab.com/owner/repository/-/releases/v1"},
                "assets": {"links": [{
                    "name": "Example Dataset.7z",
                    "direct_asset_url": "https://gitlab.com/owner/repository/-/releases/v1/downloads/example.7z",
                }]},
            }]
        elif path.endswith("/packages"):
            data = [{"id": 9, "name": "example", "version": "1", "package_type": "generic"}]
        else:
            data = [{
                "id": 10,
                "file_name": "Example Dataset.7z",
                "size": 1234,
                "file_sha256": "a" * 64,
            }]
        return httpx.Response(200, json=data, request=request)

    provider = GitLabAssetsProvider()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await provider.search(client, '"Example Dataset.7z"', 10)

    assert {result.metadata["catalog"] for result in results} == {
        "gitlab_release", "gitlab_package"
    }
    package = next(result for result in results if result.metadata["catalog"] == "gitlab_package")
    assert package.metadata["file_sha256"] == "a" * 64


def test_source_aware_query_capabilities() -> None:
    archive = ArchiveOrgProvider()
    news = GDELTProvider()
    assert archive.accepts_query('"Example Dataset.7z"')
    assert archive.accepts_query("site:example.test Ab12Cd34Ef56Gh")
    assert not archive.accepts_query('"Example Dataset" leak')
    assert news.accepts_query('"Example Dataset" leak')
    assert not news.accepts_query(f'"{"a" * 64}"')


@pytest.mark.asyncio
async def test_actual_http_requests_are_counted_and_bound_pagination(app_config) -> None:
    app_config.search.max_queries_per_provider = 2
    app_config.search.max_result_pages_per_query = 5
    app_config.search.results_per_query = 2

    async def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        return httpx.Response(200, json={"response": {
            "numFound": 100,
            "docs": [
                {"identifier": f"item-{page}-a", "title": "Example Dataset"},
                {"identifier": f"item-{page}-b", "title": "Example Dataset"},
            ],
        }}, request=request)

    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    engine = SearchEngine(app_config, database, transport=httpx.MockTransport(handler))
    engine.providers = {"archive_org_items": ArchiveOrgItemsProvider()}
    try:
        await engine.run(['"Example Dataset.7z"'], ["archive_org_items"])
        assert database.provider_request_count("archive_org_items") == 2
        assert database.query_status("archive_org_items", '"Example Dataset.7z"') == "pending"
    finally:
        database.close()
