"""Independent provider orchestration and search-result ingestion."""

from __future__ import annotations

import logging
from contextlib import AsyncExitStack
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx

from .config import AppConfig
from .crawler import Crawler
from .database import CaseDatabase
from .http import HostRateLimiter, SafeHTTPClient
from .models import Finding
from .providers import build_providers
from .providers.base import ProviderUnavailable
from .scoring import score_candidate
from .utils.time import utc_now
from .utils.urls import filename_from_url, normalize_url

LOG = logging.getLogger(__name__)


class SearchEngine:
    def __init__(self, config: AppConfig, database: CaseDatabase):
        self.config = config
        self.database = database
        self.providers = build_providers()

    async def run(
        self,
        queries: list[str],
        provider_names: list[str] | None = None,
        *,
        verify_immediately: bool = False,
    ) -> int:
        names = provider_names or self.config.search.providers
        total = 0
        rate_limiter = HostRateLimiter(self.config.crawl.per_host_delay_seconds)
        crawler = Crawler(self.config, self.database) if verify_immediately else None
        async with AsyncExitStack() as stack:
            client = await stack.enter_async_context(httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.crawl.timeout_seconds),
                follow_redirects=True,
                headers={"User-Agent": self.config.crawl.user_agent},
                event_hooks={"request": [rate_limiter.on_request]},
            ))
            verifier_http = (
                await stack.enter_async_context(SafeHTTPClient(self.config))
                if verify_immediately
                else None
            )
            for name in names:
                provider = self.providers.get(name)
                if provider is None:
                    LOG.warning("[PROVIDER] unknown provider %s", name)
                    continue
                provider.safe_search = self.config.search.safe_search
                provider.archive_extensions = self.config.safety.archive_extensions
                available, reason = provider.available()
                if not available:
                    LOG.info("[SKIP] %s %s", name, reason)
                    continue
                cooldown = self.database.get_provider_state(name, "cooldown")
                if cooldown and _future_timestamp(cooldown.get("until", "")):
                    LOG.warning(
                        "[SKIP:%s] provider cooldown until %s (%s)",
                        name,
                        cooldown.get("until", "unknown"),
                        cooldown.get("reason", "rate limited"),
                    )
                    continue
                if cooldown:
                    self.database.clear_provider_state(name, "cooldown")
                request_budget = self.config.search.max_queries_per_provider
                requests_used = self.database.provider_request_count(name)
                requests_remaining = max(0, request_budget - requests_used) if request_budget > 0 else None
                if requests_remaining == 0:
                    LOG.info("[SKIP:%s] provider request budget exhausted (%s)", name, request_budget)
                    continue
                unfinished = [query for query in queries if self.database.query_status(name, query) != "done"]
                request_groups: dict[str, list[str]] = {}
                for query in unfinished:
                    request_key = provider.request_key(query)
                    if not request_key:
                        continue
                    request_groups.setdefault(request_key, []).append(query)
                grouped_queries = list(request_groups.values())
                if requests_remaining is not None:
                    grouped_queries = grouped_queries[:requests_remaining]
                if grouped_queries:
                    LOG.info(
                        "[PLAN:%s] request_groups=%s persistent_budget=%s used=%s",
                        name,
                        len(grouped_queries),
                        request_budget if request_budget > 0 else "unlimited",
                        requests_used,
                    )
                consecutive_failures = 0
                provider_new = 0
                provider_duplicates = 0
                for request_number, equivalent_queries in enumerate(grouped_queries, start=1):
                    query = equivalent_queries[0]
                    for equivalent in equivalent_queries:
                        self.database.add_query(name, equivalent)
                    LOG.info('[SEARCH:%s %s/%s] %s', name, request_number, len(grouped_queries), query)
                    try:
                        self.database.increment_provider_request_count(name)
                        results = await provider.search(client, query, self.config.search.results_per_query)
                    except Exception as exc:  # noqa: BLE001 - circuit breaker isolates provider failures.
                        error = f"{type(exc).__name__}: {exc}"
                        for equivalent in equivalent_queries:
                            self.database.finish_query(name, equivalent, 0, error)
                        LOG.warning("[PROVIDER:%s] %s", name, error)
                        status_code = _status_code(exc)
                        if status_code == 429:
                            seconds = max(
                                _retry_after(exc) or 0,
                                self.config.search.provider_rate_limit_cooldown_seconds,
                            )
                            until = datetime.now(UTC) + timedelta(seconds=seconds)
                            self.database.set_provider_state(name, "cooldown", {
                                "until": until.isoformat().replace("+00:00", "Z"),
                                "reason": error,
                            })
                            LOG.warning("[CIRCUIT:%s] rate limited; provider paused for %.0f seconds", name, seconds)
                            break
                        if status_code in {202, 401, 403, 451}:
                            LOG.warning("[CIRCUIT:%s] access denied; provider disabled for this run", name)
                            break
                        consecutive_failures += 1
                        if consecutive_failures >= self.config.search.provider_failure_threshold:
                            LOG.warning(
                                "[CIRCUIT:%s] disabled after %s consecutive failures",
                                name,
                                consecutive_failures,
                            )
                            break
                        continue
                    consecutive_failures = 0
                    count = 0
                    newly_enqueued = 0
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
                        detection_point = {
                            "provider": name,
                            "query": query,
                            "detected_at": now,
                            "provider_observed_at": result.published,
                            "record_url": result.source_url,
                            "record_id": result.record_id,
                            "candidate_url": normalized,
                        }
                        finding = Finding(
                            timestamp_utc=now, source=name, query=query, discovery_method="search_result",
                            source_url=result.source_url or result.url, candidate_url=result.url, referrer_url="",
                            domain=(urlsplit(normalized).hostname or ""), filename=filename_from_url(normalized),
                            page_title=result.title, context_excerpt=result.excerpt[:1000], depth=0,
                            score=score.score, score_reasons=score.reasons,
                            classification=(
                                "UNVERIFIED"
                                if score.score >= self.config.scoring.likely_threshold
                                else "REFERENCE_ONLY"
                            ),
                            first_seen=result.published or now, last_checked="",
                            notes="Provider metadata is a third-party/index observation; URL not yet fetched.",
                            original_url=result.url, normalized_url=normalized,
                            detection_point=detection_point,
                        )
                        self.database.record_finding(finding)
                        added = self.database.enqueue_url(
                            result.url, normalized, source=name, query=query, depth=0, priority=score.score
                        )
                        if added:
                            newly_enqueued += 1
                            provider_new += 1
                            LOG.info("[NEW] %s score=%s", normalized, score.score)
                        else:
                            provider_duplicates += 1
                            LOG.debug("[SEEN] duplicate provider observation %s", normalized)
                        count += 1
                    for equivalent in equivalent_queries:
                        self.database.finish_query(name, equivalent, count)
                    total += count
                    if newly_enqueued and crawler is not None and verifier_http is not None:
                        LOG.info("[VERIFY-NOW] processing %s newly unique candidate(s)", newly_enqueued)
                        await crawler.run_pending(verifier_http)
                    cooldown_seconds = provider.consume_rate_limit_cooldown()
                    if cooldown_seconds is not None:
                        seconds = cooldown_seconds or self.config.search.provider_rate_limit_cooldown_seconds
                        until = datetime.now(UTC) + timedelta(seconds=seconds)
                        self.database.set_provider_state(name, "cooldown", {
                            "until": until.isoformat().replace("+00:00", "Z"),
                            "reason": "provider quota exhausted after successful request",
                        })
                        LOG.warning(
                            "[CIRCUIT:%s] quota exhausted; provider paused for %.0f seconds",
                            name,
                            seconds,
                        )
                        break
                if provider_new or provider_duplicates:
                    LOG.info(
                        "[OBSERVATIONS:%s] new=%s duplicate_records=%s",
                        name,
                        provider_new,
                        provider_duplicates,
                    )
        return total


def _status_code(exc: Exception) -> int | None:
    if isinstance(exc, ProviderUnavailable):
        return exc.status_code
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code
    return None


def _retry_after(exc: Exception) -> float | None:
    if isinstance(exc, ProviderUnavailable):
        return exc.retry_after_seconds
    return None


def _future_timestamp(value: str) -> bool:
    if not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed > datetime.now(UTC)
