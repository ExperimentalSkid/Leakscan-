"""Catalog-first seed enrichment before broad search begins."""

from __future__ import annotations

import hashlib
import json
import logging
from urllib.parse import unquote, urlsplit

from .catalogs import adapter_for
from .config import AppConfig, initial_fingerprints
from .database import CaseDatabase
from .domains import inspect_domain, parent_domain
from .host_verifiers import reference_route_classification
from .http import SafeHTTPClient
from .models import Finding
from .parser import context_excerpt, parse_page
from .scoring import classify, has_case_correlation, score_candidate
from .utils.time import utc_now
from .utils.urls import filename_from_url, hostname_for, normalize_url

LOG = logging.getLogger(__name__)


class CatalogBootstrapper:
    def __init__(self, config: AppConfig, database: CaseDatabase):
        self.config = config
        self.database = database
        self.pages_dir = config.output_dir / "evidence" / "pages"
        self.metadata_dir = config.output_dir / "evidence" / "metadata"
        self.pages_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

    def register_case_fingerprints(self) -> None:
        for kind, values in initial_fingerprints(self.config.case).items():
            if kind in {"exclusion", "artifact_hash"}:
                continue
            for value in values:
                self.database.add_pivot(kind, value, str(self.config.case_path), "operator_supplied")
        for artifact in self.config.case.artifacts:
            source_url = artifact.report_url or artifact.subject_url or str(self.config.case_path)
            for item in artifact.hashes:
                value = item.get("value", "").strip().casefold()
                if value:
                    self.database.add_pivot(
                        "artifact_hash",
                        value,
                        source_url,
                        f"operator_supplied:{artifact.artifact_type}",
                    )
            if artifact.report_url:
                normalized = normalize_url(artifact.report_url)
                self.database.enqueue_url(
                    artifact.report_url,
                    normalized,
                    referrer_url=artifact.subject_url,
                    source=artifact.source,
                    query="operator-supplied artifact report",
                    depth=0,
                    priority=40,
                )

    async def run(self) -> int:
        self.register_case_fingerprints()
        count = 0
        async with SafeHTTPClient(self.config) as http:
            for seed in self.config.case.seeds:
                if await self._process_seed(seed, http):
                    count += 1
        return count

    async def _process_seed(self, seed, http: SafeHTTPClient) -> bool:
        normalized = normalize_url(seed.url)
        added = self.database.enqueue_url(
            seed.url, normalized, source=seed.source, query="catalog bootstrap", depth=0, priority=1000
        )
        if not added:
            status = self.database.connection.execute(
                "SELECT status FROM url_queue WHERE normalized_url=?", (normalized,)
            ).fetchone()
            if status and status["status"] == "done":
                LOG.info("[CATALOG] already bootstrapped %s", normalized)
                return False
        LOG.info("[CATALOG] %s", seed.url)
        fetch = await http.fetch_page(seed.url)
        now = utc_now()
        if fetch.error or fetch.blocked_reason or not fetch.body:
            blocked = bool(fetch.blocked_reason) or fetch.status_code in {401, 403, 429, 451}
            self.database.record_finding(Finding(
                timestamp_utc=now, source=seed.source, query="catalog bootstrap",
                discovery_method="catalog_bootstrap_error", source_url=seed.url,
                candidate_url=seed.url, final_url=fetch.final_url, domain=hostname_for(fetch.final_url or normalized),
                status_code=fetch.status_code, depth=0, score=0,
                classification=classify(0, self.config, fetch.status_code, blocked=blocked),
                first_seen=now, last_checked=now, notes=fetch.blocked_reason or fetch.error or "No HTML/text body returned",
                original_url=seed.url, normalized_url=normalized, redirect_chain=fetch.redirect_chain,
            ))
            self.database.mark_url(normalized, "blocked" if blocked else "failed", fetch.blocked_reason or fetch.error)
            return False

        adapter = adapter_for(seed)
        parsed_page = parse_page(
            fetch.body,
            fetch.final_url or normalized,
            fetch.headers.get("content-type", ""),
        )
        record = adapter.parse(fetch.body, fetch.final_url or normalized, fetch.headers.get("content-type", ""), self.config)
        seed_fragment = unquote(urlsplit(seed.url).fragment)
        if seed_fragment and any(seed_fragment.lower().endswith(ext.lower()) for ext in self.config.safety.archive_extensions):
            record.filenames = list(dict.fromkeys([seed_fragment, *record.filenames]))
        for value in record.item_ids:
            self.database.add_pivot("item_id", value, record.source_url, "catalog_observed")
        for value in record.filenames:
            self.database.add_pivot("filename", value, record.source_url, "catalog_observed")
        for item in record.sizes:
            self.database.add_pivot("size", item["original"], record.source_url, "catalog_observed")
        for item in record.hashes:
            self.database.add_pivot("hash", item["value"], record.source_url, "catalog_observed")
        for value in record.dates:
            self.database.add_pivot("date", value, record.source_url, "catalog_observed")
        for value in record.accounts:
            self.database.add_pivot("account", value, record.source_url, "catalog_observed")
        host = hostname_for(record.source_url)
        if host:
            self.database.add_pivot("domain", host, record.source_url, "catalog_observed")
            parts = urlsplit(record.source_url)
            addresses, tls, domain_error = await inspect_domain(
                host, parts.scheme, min(self.config.crawl.timeout_seconds, 10)
            )
            self.database.upsert_domain(
                host, parent_domain(host), addresses, "RESOLVED" if addresses else "UNRESOLVED",
                error=domain_error, tls=tls,
            )

        excerpt = context_excerpt(
            " ".join([record.title, *record.fields.values(), *record.filenames]),
            [*self.config.case.item_ids, *self.config.case.filenames, *self.config.case.distinctive_phrases],
        )
        primary_size = record.sizes[0] if record.sizes else {}
        primary_filename = record.filenames[0] if record.filenames else filename_from_url(record.source_url)
        scored = score_candidate(
            self.config, record.source_url, title=record.title, context=excerpt,
            filename=primary_filename, size_bytes=primary_size.get("bytes"), hashes=record.hashes,
            fingerprints=self.database.pivot_map(),
        )
        evidence_hash = hashlib.sha256(fetch.body).hexdigest()
        page_path = self.pages_dir / f"{evidence_hash}.html"
        if not page_path.exists():
            page_path.write_bytes(fetch.body)
        metadata_path = self.metadata_dir / f"{evidence_hash}.json"
        metadata_path.write_text(json.dumps({
            "timestamp_utc": now,
            "kind": "catalog_listing",
            "adapter": adapter.name,
            "requested_url": seed.url,
            "final_url": record.source_url,
            "status_code": fetch.status_code,
            "headers": fetch.headers,
            "redirect_chain": fetch.redirect_chain,
            "extracted": {
                "item_ids": record.item_ids, "filenames": record.filenames, "sizes": record.sizes,
                "hashes": record.hashes, "dates": record.dates, "accounts": record.accounts,
                "fields": record.fields,
            },
            "body_bytes_read": len(fetch.body),
            "body_kind": "html_or_text_catalog_page",
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        finding = Finding(
            timestamp_utc=now, source=seed.source, query="catalog bootstrap",
            discovery_method="catalog_metadata_bootstrap", source_url=seed.url,
            candidate_url=seed.url, final_url=record.source_url, domain=host,
            status_code=fetch.status_code, filename=primary_filename,
            reported_size=primary_size.get("original", ""), normalized_size_bytes=primary_size.get("bytes"),
            content_type=fetch.headers.get("content-type", ""), hashes=record.hashes,
            dates=record.dates, accounts=record.accounts,
            response_headers=fetch.headers,
            redirect_chain=fetch.redirect_chain, page_title=record.title, context_excerpt=excerpt,
            depth=0, score=scored.score, score_reasons=scored.reasons,
            classification=reference_route_classification(
                record.source_url,
                fetch.status_code,
                fetch.headers.get("content-type", ""),
                parsed_page.text,
            ) or classify(scored.score, self.config, fetch.status_code),
            first_seen=now, last_checked=now,
            notes=f"Directly observed public catalog metadata via {adapter.name}; archive body not requested.",
            original_url=seed.url, normalized_url=normalized, evidence_sha256=evidence_hash,
            evidence_path=str(page_path),
        )
        self.database.record_finding(finding)
        for link in record.links:
            normalized_link = normalize_url(link, record.source_url)
            if not normalized_link:
                continue
            link_score = score_candidate(
                self.config, normalized_link, title=record.title, fingerprints=self.database.pivot_map()
            )
            if has_case_correlation(link_score):
                self.database.enqueue_url(
                    link, normalized_link, referrer_url=record.source_url, source=seed.source,
                    query="catalog bootstrap", depth=1, priority=link_score.score,
                )
        self.database.mark_url(normalized, "done")
        LOG.info(
            "[FINGERPRINTS] %s ids=%d filenames=%d sizes=%d hashes=%d accounts=%d",
            adapter.name, len(record.item_ids), len(record.filenames), len(record.sizes),
            len(record.hashes), len(record.accounts),
        )
        return True
