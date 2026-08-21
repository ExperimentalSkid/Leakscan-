"""Explicit re-verification of candidate URLs using metadata-only probes."""

from __future__ import annotations

import logging

from .config import AppConfig
from .crawler import Crawler
from .database import CaseDatabase
from .http import SafeHTTPClient
from .utils.urls import looks_like_archive_url, normalize_url

LOG = logging.getLogger(__name__)


async def verify_candidates(
    config: AppConfig,
    database: CaseDatabase,
    *,
    skip_checked: bool = False,
) -> int:
    crawler = Crawler(config, database)
    candidates: dict[str, dict] = {}
    checked: set[str] = set()
    for finding in database.iter_findings():
        url = finding.final_url or finding.normalized_url or finding.candidate_url
        if not url:
            continue
        normalized = normalize_url(url)
        if finding.last_checked and finding.discovery_method != "search_result":
            checked.add(normalized)
        if (
            finding.score >= config.scoring.likely_threshold
            or looks_like_archive_url(url, config.safety.archive_extensions)
            or finding.classification == "CONFIRMED_METADATA_ONLY"
        ):
            candidates[normalized] = {
                "normalized_url": normalized, "original_url": finding.original_url or url,
                "referrer_url": finding.referrer_url, "source": finding.source,
                "query_text": finding.query, "depth": finding.depth,
                "priority": finding.score, "created_at": finding.first_seen,
            }
    count = 0
    async with SafeHTTPClient(config) as http:
        for url, item in candidates.items():
            if skip_checked and url in checked:
                continue
            LOG.info("[VERIFY] %s", url)
            fetch = await http.probe_metadata(url)
            if fetch.error or fetch.blocked_reason:
                crawler._record_failure(item, fetch)
            else:
                crawler._record_metadata_finding(item, fetch)
            count += 1
    return count
