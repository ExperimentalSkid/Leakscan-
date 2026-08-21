"""Independent provider orchestration and search-result ingestion."""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

import httpx

from .config import AppConfig
from .database import CaseDatabase
from .models import Finding
from .providers import build_providers
from .scoring import classify, score_candidate
from .utils.time import utc_now
from .utils.urls import filename_from_url, normalize_url

LOG = logging.getLogger(__name__)


class SearchEngine:
    def __init__(self, config: AppConfig, database: CaseDatabase):
        self.config = config
        self.database = database
        self.providers = build_providers()

    async def run(self, queries: list[str], provider_names: list[str] | None = None) -> int:
        names = provider_names or self.config.search.providers
        total = 0
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.crawl.timeout_seconds),
            follow_redirects=True,
            headers={"User-Agent": self.config.crawl.user_agent},
        ) as client:
            for name in names:
                provider = self.providers.get(name)
                if provider is None:
                    LOG.warning("[PROVIDER] unknown provider %s", name)
                    continue
                provider.safe_search = self.config.search.safe_search
                available, reason = provider.available()
                if not available:
                    LOG.info("[SKIP] %s %s", name, reason)
                    continue
                unfinished = [query for query in queries if self.database.query_status(name, query) != "done"]
                provider_queries = (
                    unfinished[: self.config.search.max_queries_per_provider]
                    if self.config.search.max_queries_per_provider > 0
                    else unfinished
                )
                for query in provider_queries:
                    self.database.add_query(name, query)
                    LOG.info('[SEARCH:%s] %s', name, query)
                    try:
                        results = await provider.search(client, query, self.config.search.results_per_query)
                    except Exception as exc:  # noqa: BLE001 - one provider must not stop other providers.
                        error = f"{type(exc).__name__}: {exc}"
                        self.database.finish_query(name, query, 0, error)
                        LOG.warning("[PROVIDER:%s] %s", name, error)
                        continue
                    count = 0
                    for result in results:
                        normalized = normalize_url(result.url)
                        if not normalized:
                            continue
                        score = score_candidate(
                            self.config, normalized, title=result.title, context=result.excerpt,
                            filename=filename_from_url(normalized),
                            fingerprints=self.database.pivot_map(),
                        )
                        now = utc_now()
                        finding = Finding(
                            timestamp_utc=now, source=name, query=query, discovery_method="search_result",
                            source_url=result.url, candidate_url=result.url, referrer_url="",
                            domain=(urlsplit(normalized).hostname or ""), filename=filename_from_url(normalized),
                            page_title=result.title, context_excerpt=result.excerpt[:1000], depth=0,
                            score=score.score, score_reasons=score.reasons,
                            classification=classify(score.score, self.config), first_seen=now, last_checked="",
                            notes="Provider metadata is a third-party/index observation; URL not yet fetched.",
                            original_url=result.url, normalized_url=normalized,
                        )
                        self.database.record_finding(finding)
                        self.database.enqueue_url(
                            result.url, normalized, source=name, query=query, depth=0, priority=score.score
                        )
                        LOG.info("[FOUND] %s score=%s", normalized, score.score)
                        count += 1
                    self.database.finish_query(name, query, count)
                    total += count
        return total
