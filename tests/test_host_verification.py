import httpx
import pytest

from leakscan.bootstrap import CatalogBootstrapper
from leakscan.config import SeedConfig
from leakscan.crawler import Crawler
from leakscan.database import CaseDatabase
from leakscan.host_verifiers import (
    host_metadata_classification,
    host_verification_request,
    reference_route_classification,
)
from leakscan.http import SafeHTTPClient
from leakscan.models import FetchResult, Finding
from leakscan.reporting import _candidate_summaries
from leakscan.utils.time import utc_now


def test_pixeldrain_landing_url_maps_to_official_metadata_endpoint() -> None:
    request = host_verification_request("https://pixeldrain.com/u/NYdQVUGS")

    assert request is not None
    assert request.provider == "pixeldrain"
    assert request.object_id == "NYdQVUGS"
    assert request.url == "https://pixeldrain.com/api/file/NYdQVUGS/info"


@pytest.mark.asyncio
async def test_pixeldrain_metadata_verifies_file_without_archive_body(app_config) -> None:
    requested_urls: list[str] = []
    payload = {
        "success": True,
        "id": "NYdQVUGS",
        "name": "Example Dataset.7z",
        "size": 549_040_000,
        "mime_type": "application/x-7z-compressed",
        "hash_sha256": "a" * 64,
        "date_upload": "2026-01-01T00:00:00Z",
        "availability": "",
        "can_download": True,
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(200, json=payload, request=request)

    safe = SafeHTTPClient(app_config)
    await safe.client.aclose()
    safe.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        fetch = await safe.probe_metadata("https://pixeldrain.com/u/NYdQVUGS")
    finally:
        await safe.client.aclose()

    assert requested_urls == ["https://pixeldrain.com/api/file/NYdQVUGS/info"]
    assert fetch.body == b""
    assert fetch.verification_point["method"] == "pixeldrain_api"
    assert fetch.verification_point["metadata"]["hash_sha256"] == "a" * 64
    assert fetch.verification_point["metadata_body_bytes_read"] > 0

    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    try:
        finding = Crawler(app_config, database)._record_metadata_finding(
            {
                "normalized_url": "https://pixeldrain.com/u/NYdQVUGS",
                "original_url": "https://pixeldrain.com/u/NYdQVUGS",
                "referrer_url": "https://index.example/result/1",
                "source": "urlscan",
                "query_text": '"Example Dataset.7z"',
                "depth": 0,
                "priority": 160,
                "created_at": utc_now(),
            },
            fetch,
        )
    finally:
        database.close()

    summary = _candidate_summaries([finding], app_config.scoring.likely_threshold)[0]
    assert finding.classification == "CONFIRMED_METADATA_ONLY"
    assert finding.filename == "Example Dataset.7z"
    assert finding.normalized_size_bytes == 549_040_000
    assert finding.hashes[0]["value"] == "a" * 64
    assert summary["current_status"] == "LIVE_METADATA_ONLY"
    assert summary["verification_method"] == "pixeldrain_api"
    assert summary["host_object_id"] == "NYdQVUGS"
    assert summary["verified_sha256"] == "a" * 64
    assert summary["target_identity_confirmed"] is True


def test_weak_search_fragment_does_not_confirm_unrelated_live_archive(app_config) -> None:
    url = "https://archive.org/compress/ijds-v11n12-01"
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    try:
        database.record_finding(Finding(
            timestamp_utc=utc_now(),
            discovery_method="search_result",
            source="archive_org_items",
            candidate_url=url,
            normalized_url=url,
            score=55,
            score_reasons=[
                {"points": 35, "reason": "keyword_fragment", "evidence": "National Social Security Fund"},
                {"points": 20, "reason": "archive_reference", "evidence": "zip"},
            ],
            classification="UNVERIFIED",
        ))
        finding = Crawler(app_config, database)._record_metadata_finding(
            {
                "normalized_url": url,
                "original_url": url,
                "referrer_url": "https://archive.org/details/ijds-v11n12-01",
                "source": "archive_org_items",
                "query_text": '"National Social Security Fund"',
                "depth": 0,
                "priority": 55,
                "created_at": utc_now(),
            },
            FetchResult(
                original_url=url,
                final_url=url,
                status_code=200,
                headers={
                    "content-type": "application/zip",
                    "content-disposition": 'attachment; filename="ijds-v11n12-01.zip"',
                    "content-length": "123456",
                },
            ),
        )
    finally:
        database.close()

    assert finding.classification == "UNVERIFIED"
    assert finding.verification_point["file_metadata_confirmed"] is True
    assert finding.verification_point["target_identity_confirmed"] is False


@pytest.mark.parametrize(
    ("status_code", "metadata", "expected"),
    [
        (404, {"success": False, "value": "not_found"}, "DEAD"),
        (451, {}, "TAKEN_DOWN"),
        (200, {"success": True, "availability": "captcha", "can_download": False}, "LIVE_RESTRICTED"),
        (200, {"success": True, "abuse_type": "dmca", "can_download": False}, "TAKEN_DOWN"),
        (200, {"success": True, "abuse_type": "pending", "can_download": True}, "CONFIRMED_METADATA_ONLY"),
    ],
)
def test_host_metadata_distinguishes_dead_restricted_and_taken_down(
    status_code: int,
    metadata: dict,
    expected: str,
) -> None:
    assert host_metadata_classification("pixeldrain", status_code, metadata) == expected


def test_biteblob_html_routes_do_not_claim_a_live_file() -> None:
    assert reference_route_classification(
        "https://biteblob.com/Information/object-id", 200, "text/html; charset=utf-8"
    ) == "LISTING_LIVE"
    assert reference_route_classification(
        "https://biteblob.com/Download/object-id/", 200, "text/html"
    ) == "DOWNLOAD_ROUTE_LIVE"
    assert reference_route_classification(
        "https://biteblob.com/Download/object-id", 200, "application/octet-stream"
    ) == ""
    assert reference_route_classification(
        "https://biteblob.com/Information/object-id",
        200,
        "text/html",
        "Link Unauthorized; Reported as abuse material. No download available.",
    ) == "TAKEN_DOWN"


@pytest.mark.asyncio
async def test_catalog_bootstrap_preserves_biteblob_abuse_notice_as_takedown(
    app_config,
    monkeypatch,
) -> None:
    seed = SeedConfig(
        url="https://biteblob.com/Information/abcDEF123/#Example%20Dataset.7z",
        source="biteblob",
        adapter="biteblob",
    )
    app_config.case.seeds = [seed]

    class FakeHTTP:
        async def fetch_page(self, url: str) -> FetchResult:
            return FetchResult(
                original_url=url,
                final_url=url,
                status_code=200,
                headers={"content-type": "text/html"},
                body=(
                    b"<html><body><h1>Link Unauthorized</h1>"
                    b"<p>Reported as abuse material. No download available.</p>"
                    b"<p>Example Dataset.7z</p></body></html>"
                ),
            )

    async def no_domain_lookup(*_args):
        return [], {}, ""

    monkeypatch.setattr("leakscan.bootstrap.inspect_domain", no_domain_lookup)
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    try:
        await CatalogBootstrapper(app_config, database)._process_seed(seed, FakeHTTP())
        findings = list(database.iter_findings())
    finally:
        database.close()

    assert findings[-1].classification == "TAKEN_DOWN"
