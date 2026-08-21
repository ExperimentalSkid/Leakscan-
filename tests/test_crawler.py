import pytest

from leakscan.crawler import Crawler
from leakscan.database import CaseDatabase
from leakscan.models import FetchResult
from leakscan.scoring import classify
from leakscan.utils.time import utc_now
from leakscan.utils.urls import normalize_url


@pytest.mark.asyncio
async def test_relevant_page_title_does_not_enqueue_unrelated_navigation(app_config):
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    try:
        crawler = Crawler(app_config, database)
        url = "https://reports.example/report/abcDEF123"
        now = utc_now()
        item = {
            "normalized_url": normalize_url(url),
            "original_url": url,
            "referrer_url": "",
            "source": "test",
            "query_text": '"abcDEF123"',
            "depth": 0,
            "priority": 100,
            "created_at": now,
        }
        body = b"""
        <html><head><title>Report abcDEF123</title></head><body>
          <a href="/about">About</a>
          <a href="/privacy">Privacy</a>
          <a href="https://catalog.example/Information/abcDEF123">Matching report</a>
        </body></html>
        """
        await crawler._record_page_finding(
            item,
            FetchResult(
                original_url=url, final_url=url, status_code=200,
                headers={"content-type": "text/html"}, body=body,
            ),
            depth=0,
        )
        rows = database.connection.execute("SELECT normalized_url FROM url_queue").fetchall()
        assert [row["normalized_url"] for row in rows] == [
            "https://catalog.example/Information/abcDEF123"
        ]
    finally:
        database.close()


def test_nonstandard_provider_block_status_is_blocked(app_config):
    assert classify(100, app_config, status_code=999) == "BLOCKED"
