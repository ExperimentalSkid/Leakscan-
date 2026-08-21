from __future__ import annotations

import httpx
import pytest

from leakscan.crawler import Crawler
from leakscan.database import CaseDatabase
from leakscan.http import SafeHTTPClient
from leakscan.models import FetchResult
from leakscan.utils.urls import normalize_url


class InvalidBodyLengthError(Exception):
    pass


@pytest.mark.asyncio
async def test_http2_body_length_error_retries_once_over_http1(app_config, monkeypatch) -> None:
    safe = SafeHTTPClient(app_config)
    fallback = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, request=request)
    ))
    safe._http1_client = fallback
    primary = safe.client
    calls: list[str] = []

    async def fake_fetch(url: str, client: httpx.AsyncClient) -> FetchResult:
        calls.append("primary" if client is primary else "http1")
        if client is primary:
            raise InvalidBodyLengthError("declared body length did not match")
        return FetchResult(
            original_url=url,
            final_url=url,
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"ok",
        )

    monkeypatch.setattr(safe, "_fetch_page_once", fake_fetch)
    try:
        result = await safe.fetch_page("https://example.test/page")
    finally:
        await safe.__aexit__()

    assert calls == ["primary", "http1"]
    assert result.status_code == 200


@pytest.mark.asyncio
async def test_unexpected_candidate_failure_is_isolated_and_recorded(app_config) -> None:
    class BrokenHTTP:
        async def fetch_page(self, _url: str) -> FetchResult:
            raise RuntimeError("malformed remote response")

    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    url = "https://broken.example/item/abcDEF123"
    try:
        database.enqueue_url(
            url,
            normalize_url(url),
            source="test",
            query='"abcDEF123"',
            priority=100,
        )
        processed = await Crawler(app_config, database).run_pending(BrokenHTTP())
        row = database.connection.execute(
            "SELECT status, last_error FROM url_queue WHERE normalized_url=?",
            (normalize_url(url),),
        ).fetchone()
        findings = list(database.iter_findings())
    finally:
        database.close()

    assert processed == 1
    assert row["status"] == "failed"
    assert "RuntimeError" in row["last_error"]
    assert findings[-1].classification == "UNKNOWN"
