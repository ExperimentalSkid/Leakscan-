"""Bounded recursive discovery and evidence preservation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from urllib.parse import urlsplit

from .config import AppConfig
from .database import CaseDatabase
from .domains import inspect_domain, parent_domain
from .http import SafeHTTPClient
from .models import FetchResult, Finding
from .parser import context_excerpt, parse_page
from .scoring import classify, score_candidate, size_matches, target_size_ranges
from .utils.time import utc_now
from .utils.urls import (
    content_headers_indicate_binary,
    filename_from_url,
    hostname_for,
    looks_like_archive_url,
    normalize_url,
)

LOG = logging.getLogger(__name__)


class Crawler:
    def __init__(self, config: AppConfig, database: CaseDatabase):
        self.config = config
        self.database = database
        self.pages_dir = config.output_dir / "evidence" / "pages"
        self.metadata_dir = config.output_dir / "evidence" / "metadata"
        self.pages_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        self._inspected_domains: set[str] = set()
        self._size_ranges = target_size_ranges(
            config.case.reported_sizes, config.scoring.size_tolerance_fraction
        )

    async def run(self) -> int:
        self.database.reset_active()
        processed = 0
        async with SafeHTTPClient(self.config) as http:
            while self.database.visited_count() < self.config.crawl.max_pages:
                remaining = self.config.crawl.max_pages - self.database.visited_count()
                batch = self.database.claim_pending(min(self.config.crawl.concurrency, remaining))
                if not batch:
                    break
                await asyncio.gather(*(self._process(item, http) for item in batch))
                processed += len(batch)
        return processed

    async def _process(self, item: dict, http: SafeHTTPClient) -> None:
        url = item["normalized_url"]
        depth = int(item["depth"])
        host = hostname_for(url)
        if depth > self.config.crawl.max_depth:
            self.database.mark_url(url, "blocked", "maximum depth exceeded")
            return
        if self.database.domain_visit_count(host) > self.config.crawl.max_pages_per_domain:
            self.database.mark_url(url, "blocked", "maximum pages per domain exceeded")
            return
        LOG.info("[CRAWL] %s", url)
        fetch = await http.fetch_page(url)
        if host and host not in self._inspected_domains:
            self._inspected_domains.add(host)
            await self._record_domain(url)
        if fetch.error and fetch.status_code is None:
            self._record_failure(item, fetch)
            self.database.mark_url(url, "failed", fetch.error)
            LOG.warning("[FAILED] %s %s", url, fetch.error)
            return
        if fetch.blocked_reason:
            self._record_failure(item, fetch)
            self.database.mark_url(url, "blocked", fetch.blocked_reason)
            LOG.info("[BLOCKED] %s %s", url, fetch.blocked_reason)
            return
        if fetch.final_url and normalize_url(fetch.final_url) != url:
            self.database.add_relationship(url, normalize_url(fetch.final_url), "redirect_alias", json.dumps(fetch.redirect_chain))
        if fetch.is_binary or looks_like_archive_url(fetch.final_url or url, self.config.safety.archive_extensions):
            self._record_metadata_finding(item, fetch)
            self.database.mark_url(url, "done")
            return
        await self._record_page_finding(item, fetch, depth)
        self.database.mark_url(url, "done")

    async def _record_domain(self, url: str) -> None:
        parts = urlsplit(url)
        host = parts.hostname or ""
        addresses, tls, error = await inspect_domain(host, parts.scheme, min(self.config.crawl.timeout_seconds, 10))
        self.database.upsert_domain(
            host, parent_domain(host), addresses, "RESOLVED" if addresses else "UNRESOLVED",
            error=error, tls=tls,
        )

    def _record_failure(self, item: dict, fetch: FetchResult) -> None:
        now = utc_now()
        blocked = bool(fetch.blocked_reason) or fetch.status_code in {401, 403, 429, 451}
        finding = Finding(
            timestamp_utc=now, source=item["source"], query=item["query_text"],
            discovery_method="crawl_error", source_url=item["original_url"],
            candidate_url=item["original_url"], final_url=fetch.final_url,
            referrer_url=item["referrer_url"], domain=hostname_for(fetch.final_url or item["normalized_url"]),
            status_code=fetch.status_code, depth=item["depth"], score=item["priority"],
            response_headers=fetch.headers,
            classification=classify(item["priority"], self.config, fetch.status_code, blocked=blocked),
            first_seen=item["created_at"], last_checked=now,
            notes=fetch.blocked_reason or fetch.error, original_url=item["original_url"],
            normalized_url=item["normalized_url"], redirect_chain=fetch.redirect_chain,
        )
        self.database.record_finding(finding)

    def _record_metadata_finding(self, item: dict, fetch: FetchResult) -> Finding:
        now = utc_now()
        final_url = fetch.final_url or item["normalized_url"]
        headers = fetch.headers
        disposition = headers.get("content-disposition", "")
        content_type = headers.get("content-type", "")
        length_text = headers.get("content-length", "")
        size_bytes = int(length_text) if length_text.isdigit() else None
        filename = _filename_from_disposition(disposition) or filename_from_url(final_url)
        scored = score_candidate(
            self.config, final_url, filename=filename, size_bytes=size_bytes,
            content_type=content_type, content_disposition=disposition,
            fingerprints=self.database.pivot_map(),
        )
        header_binary = content_headers_indicate_binary(headers, self.config.safety.archive_extensions)
        non_html_archive = (
            looks_like_archive_url(final_url, self.config.safety.archive_extensions)
            and bool(size_bytes)
            and "text/html" not in content_type.lower()
        )
        confirmed = header_binary or non_html_archive
        blocked = fetch.status_code in {401, 403, 429, 451}
        classification = classify(
            scored.score, self.config, fetch.status_code, blocked=blocked,
            metadata_archive_confirmed=confirmed,
        )
        metadata = {
            "timestamp_utc": now, "requested_url": item["original_url"], "final_url": final_url,
            "status_code": fetch.status_code, "headers": headers,
            "redirect_chain": fetch.redirect_chain, "body_bytes_read": 0,
            "classification": classification,
        }
        digest = hashlib.sha256(final_url.encode("utf-8")).hexdigest()
        evidence_path = self.metadata_dir / f"{digest}.json"
        evidence_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
        finding = Finding(
            timestamp_utc=now, source=item["source"], query=item["query_text"],
            discovery_method="metadata_only_probe", source_url=item["original_url"],
            candidate_url=item["original_url"], final_url=final_url, referrer_url=item["referrer_url"],
            domain=hostname_for(final_url), status_code=fetch.status_code, filename=filename,
            reported_size=length_text, normalized_size_bytes=size_bytes, content_type=content_type,
            content_disposition=disposition, response_headers=headers, redirect_chain=fetch.redirect_chain,
            depth=item["depth"], score=scored.score, score_reasons=scored.reasons,
            classification=classification, first_seen=item["created_at"], last_checked=now,
            notes="Metadata-only probe; response body was not consumed.",
            original_url=item["original_url"], normalized_url=item["normalized_url"],
            evidence_path=str(evidence_path),
        )
        self.database.record_finding(finding)
        label = "CANDIDATE" if classification not in {"DEAD", "BLOCKED"} else classification
        LOG.info("[%s] %s status=%s score=%s body=0", label, final_url, fetch.status_code, scored.score)
        return finding

    async def _record_page_finding(self, item: dict, fetch: FetchResult, depth: int) -> None:
        final_url = fetch.final_url or item["normalized_url"]
        parsed = parse_page(fetch.body, final_url, fetch.headers.get("content-type", ""))
        size_values = set(self.config.case.reported_sizes) | self.database.pivot_map().get("size", set())
        current_size_ranges = target_size_ranges(list(size_values), self.config.scoring.size_tolerance_fraction)
        matching_size = next(
            (entry for entry in parsed.sizes if size_matches(entry.get("bytes"), current_size_ranges)),
            parsed.sizes[0] if parsed.sizes else None,
        )
        expected_names = self.database.pivot_map().get("filename", set()) | set(self.config.case.filenames)
        filename = next(
            (name for name in parsed.filenames if any(expected.lower() in name.lower() for expected in expected_names)),
            parsed.filenames[0] if parsed.filenames else filename_from_url(final_url),
        )
        excerpt = context_excerpt(
            parsed.text,
            [
                *self.config.case.item_ids,
                *self.config.case.filenames,
                *self.config.case.distinctive_phrases,
                *self.config.case.aliases,
            ],
        )
        scored = score_candidate(
            self.config, final_url, title=parsed.title, context=excerpt, filename=filename,
            size_bytes=matching_size.get("bytes") if matching_size else None,
            content_type=fetch.headers.get("content-type", ""), hashes=parsed.hashes,
            fingerprints=self.database.pivot_map(),
        )
        now = utc_now()
        evidence_hash = ""
        evidence_path = ""
        if scored.score > 0 and fetch.body:
            evidence_hash = hashlib.sha256(fetch.body).hexdigest()
            path = self.pages_dir / f"{evidence_hash}.html"
            if not path.exists():
                path.write_bytes(fetch.body)
            evidence_path = str(path)
            metadata_path = self.metadata_dir / f"{evidence_hash}.json"
            metadata_path.write_text(json.dumps({
                "timestamp_utc": now,
                "kind": "html_or_text_evidence",
                "requested_url": item["original_url"],
                "final_url": final_url,
                "status_code": fetch.status_code,
                "headers": fetch.headers,
                "redirect_chain": fetch.redirect_chain,
                "canonical_url": parsed.canonical_url,
                "extracted": {
                    "filenames": parsed.filenames,
                    "sizes": parsed.sizes,
                    "hashes": parsed.hashes,
                    "dates": parsed.dates,
                    "links": parsed.links,
                    "link_contexts": parsed.link_contexts,
                },
                "body_bytes_read": len(fetch.body),
                "truncated": fetch.truncated,
            }, indent=2, ensure_ascii=False), encoding="utf-8")
        blocked = fetch.status_code in {401, 403, 429, 451}
        finding = Finding(
            timestamp_utc=now, source=item["source"], query=item["query_text"],
            discovery_method="recursive_html_fetch", source_url=item["original_url"],
            candidate_url=item["original_url"], final_url=final_url, referrer_url=item["referrer_url"],
            domain=hostname_for(final_url), status_code=fetch.status_code, filename=filename,
            reported_size=matching_size.get("original", "") if matching_size else "",
            normalized_size_bytes=matching_size.get("bytes") if matching_size else None,
            content_type=fetch.headers.get("content-type", ""), response_headers=fetch.headers,
            hashes=parsed.hashes, dates=parsed.dates, redirect_chain=fetch.redirect_chain,
            page_title=parsed.title, canonical_url=parsed.canonical_url, context_excerpt=excerpt,
            depth=depth, score=scored.score, score_reasons=scored.reasons,
            classification=classify(scored.score, self.config, fetch.status_code, blocked=blocked),
            first_seen=item["created_at"], last_checked=now,
            notes="HTML/text evidence observed directly." + (" Response truncated at configured ceiling." if fetch.truncated else ""),
            original_url=item["original_url"], normalized_url=item["normalized_url"],
            evidence_sha256=evidence_hash, evidence_path=evidence_path,
        )
        self.database.record_finding(finding)
        canonical = normalize_url(parsed.canonical_url) if parsed.canonical_url else ""
        if canonical and canonical != normalize_url(final_url):
            self.database.add_relationship(final_url, canonical, "same_content_reference", "HTML canonical URL")
        if scored.score >= self.config.scoring.likely_threshold:
            for hash_item in parsed.hashes:
                if not _hash_is_contextual(parsed.text, hash_item["value"], self.database.pivot_map()):
                    continue
                added = self.database.add_pivot("hash", hash_item["value"], final_url, f"contextual_{hash_item['algorithm']}")
                if added:
                    LOG.info("[PIVOT] discovered %s %s", hash_item["algorithm"], hash_item["value"])
            for name in parsed.filenames:
                name_score = score_candidate(
                    self.config, "", filename=name, fingerprints=self.database.pivot_map()
                )
                if name_score.score >= 70:
                    self.database.add_pivot("filename", name, final_url, "contextual")
            for size in parsed.sizes:
                if size_matches(size.get("bytes"), current_size_ranges):
                    self.database.add_pivot("size", size["original"], final_url, "contextual")
        if depth >= self.config.crawl.max_depth:
            return
        for link in parsed.links:
            normalized = normalize_url(link, final_url)
            if not normalized:
                continue
            link_context = parsed.link_contexts.get(link, "")
            link_score = score_candidate(
                self.config, normalized, context=link_context, fingerprints=self.database.pivot_map()
            )
            same_host = hostname_for(normalized) == hostname_for(final_url)
            archive = looks_like_archive_url(normalized, self.config.safety.archive_extensions)
            action_link = (
                same_host
                and scored.score >= self.config.scoring.likely_threshold
                and any(term in link_context.lower() for term in ("download", "mirror", "file", "archive"))
            )
            if archive or link_score.score > 0 or action_link:
                added = self.database.enqueue_url(
                    link, normalized, referrer_url=final_url, source=item["source"], query=item["query_text"],
                    depth=depth + 1, priority=link_score.score,
                )
                if not added:
                    self.database.add_relationship(final_url, normalized, "duplicate_listing", "rediscovered link")


def _filename_from_disposition(value: str) -> str:
    match = re.search(r"filename\*?=(?:UTF-8''|\")?([^\";]+)", value, flags=re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _hash_is_contextual(text: str, digest: str, fingerprints: dict[str, set[str]], radius: int = 1000) -> bool:
    lowered = text.lower()
    position = lowered.find(digest.lower())
    if position < 0:
        return False
    window = lowered[max(0, position - radius) : position + len(digest) + radius]
    needles = set().union(
        fingerprints.get("item_id", set()),
        fingerprints.get("filename", set()),
        fingerprints.get("phrase", set()),
        fingerprints.get("alias", set()),
    )
    return any(needle.lower() in window for needle in needles if needle)
