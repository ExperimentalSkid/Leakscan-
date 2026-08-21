"""Deterministic evidence exports and analyst-facing Markdown reports."""

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .config import AppConfig, generate_queries, keyword_variants_for_values
from .database import CaseDatabase
from .models import Finding
from .utils.time import utc_now
from .utils.urls import normalize_url

CSV_FIELDS = [
    "timestamp_utc", "source", "query", "discovery_method", "source_url", "candidate_url",
    "final_url", "referrer_url", "domain", "status_code", "filename", "reported_size",
    "normalized_size_bytes", "content_type", "content_disposition", "response_headers", "hashes", "dates", "accounts",
    "redirect_chain", "page_title", "canonical_url", "context_excerpt", "depth", "score", "score_reasons", "classification",
    "first_seen", "last_checked", "notes", "original_url", "normalized_url",
    "evidence_sha256", "evidence_path", "relation", "detection_point", "verification_point",
]

CANDIDATE_FIELDS = [
    "candidate_url", "current_status", "current_http_status", "filename", "maximum_score",
    "observation_count", "first_detected_at", "detection_provider", "detection_query",
    "detection_record_url", "detection_record_id", "provider_observed_at", "last_checked",
    "verification_method", "verification_url", "host_object_id", "verified_at",
    "verified_filename", "verified_size_bytes", "verified_sha256", "availability",
    "current_evidence_path", "sources", "referrer_url",
]

ARTIFACT_REFERENCE_FIELDS = [
    "reference_url", "artifact_type", "current_status", "current_http_status",
    "sources", "detection_query", "last_checked", "observation_count",
]

SUPPORTING_REFERENCE_FIELDS = [
    "reference_url", "reference_type", "current_status", "current_http_status",
    "sources", "detection_query", "last_checked", "observation_count",
]


def prepare_output(config: AppConfig) -> None:
    for path in (
        config.output_dir,
        config.output_dir / "evidence" / "pages",
        config.output_dir / "evidence" / "metadata",
        config.output_dir / "reports",
    ):
        path.mkdir(parents=True, exist_ok=True)
    (config.output_dir / "queries.txt").write_text(
        "\n".join(generate_queries(config)) + "\n", encoding="utf-8"
    )
    write_case_readme(config)


def write_manifest(
    config: AppConfig,
    command: str,
    providers: list[str],
    dry_run: bool,
    provider_availability: dict[str, str] | None = None,
    database: CaseDatabase | None = None,
) -> None:
    manifest = {
        "schema_version": 1,
        "generated_at_utc": utc_now(),
        "tool_version": __version__,
        "command": command,
        "dry_run": dry_run,
        "configuration": config.as_manifest_dict(),
        "selected_providers": providers,
        "provider_availability": provider_availability or {},
        "state": database.stats() if database else {},
        "archive_body_download_enabled": False,
    }
    (config.output_dir / "run_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _csv_value(value: Any) -> Any:
    if isinstance(value, list | dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return value


def _write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key, "")) for key in fieldnames})


def export_reports(config: AppConfig, database: CaseDatabase) -> None:
    findings = list(database.iter_findings())
    dictionaries = [finding.to_dict() for finding in findings]
    with (config.output_dir / "findings.jsonl").open("w", encoding="utf-8") as handle:
        for row in dictionaries:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    _write_csv(config.output_dir / "findings.csv", dictionaries, CSV_FIELDS)

    artifact_report_types, artifact_hash_types = _artifact_maps(config)
    candidates = _candidate_summaries(
        findings,
        config.scoring.likely_threshold,
        artifact_report_types,
        artifact_hash_types,
    )
    artifact_references = _artifact_reference_summaries(
        findings,
        artifact_report_types,
        artifact_hash_types,
    )
    supporting_references = _supporting_reference_summaries(findings)
    _write_csv(config.output_dir / "candidate_urls.csv", candidates, CANDIDATE_FIELDS)
    _write_csv(config.output_dir / "detection_points.csv", candidates, CANDIDATE_FIELDS)
    _write_csv(
        config.output_dir / "artifact_references.csv",
        artifact_references,
        ARTIFACT_REFERENCE_FIELDS,
    )
    _write_csv(
        config.output_dir / "supporting_references.csv",
        supporting_references,
        SUPPORTING_REFERENCE_FIELDS,
    )
    domains = []
    for row in database.iter_domains():
        row["ip_addresses"] = row.pop("ip_addresses_json", "[]")
        row["tls"] = row.pop("tls_json", "{}")
        domains.append(row)
    _write_csv(
        config.output_dir / "domains.csv", domains,
        ["hostname", "parent_domain", "ip_addresses", "asn", "tls", "first_seen", "last_checked", "status", "error"],
    )
    hash_rows_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    confidence_rank = {
        "unresolved": 0,
        "contextual": 1,
        "artifact_report_observed": 1,
        "operator_supplied_artifact": 2,
        "host_metadata_verified": 3,
    }
    for artifact in config.case.artifacts:
        source_url = artifact.report_url or artifact.subject_url
        for item in artifact.hashes:
            key = (item.get("algorithm", ""), item.get("value", "").casefold(), source_url)
            hash_rows_by_key[key] = {
                "algorithm": key[0],
                "hash": key[1],
                "source_url": key[2],
                "confidence": "operator_supplied_artifact",
                "artifact_type": artifact.artifact_type,
                "observed_at": artifact.observed_at,
            }
    for finding in findings:
        for item in finding.hashes:
            key = (item.get("algorithm", ""), item.get("value", ""), finding.final_url or finding.source_url)
            method = str(finding.verification_point.get("method", ""))
            confidence = (
                "artifact_report_observed"
                if item.get("artifact_type")
                else "host_metadata_verified"
                if method.endswith("_api") and finding.classification in {
                    "CONFIRMED_METADATA_ONLY", "LIVE_RESTRICTED", "TAKEN_DOWN"
                }
                else "contextual" if finding.score >= config.scoring.likely_threshold else "unresolved"
            )
            row = {
                "algorithm": key[0], "hash": key[1], "source_url": key[2],
                "confidence": confidence,
                "artifact_type": item.get("artifact_type", ""),
                "observed_at": finding.timestamp_utc,
            }
            existing = hash_rows_by_key.get(key)
            if existing is None or confidence_rank[confidence] > confidence_rank[existing["confidence"]]:
                hash_rows_by_key[key] = row
    hash_rows = list(hash_rows_by_key.values())
    _write_csv(
        config.output_dir / "hashes.csv",
        hash_rows,
        ["algorithm", "hash", "artifact_type", "source_url", "confidence", "observed_at"],
    )

    redirect_rows = []
    for finding in findings:
        for hop_number, hop in enumerate(finding.redirect_chain, start=1):
            redirect_rows.append({
                "source_url": finding.source_url, "hop": hop_number, "url": hop.get("url", ""),
                "status_code": hop.get("status_code", ""), "location": hop.get("location", ""),
                "observed_at": finding.timestamp_utc,
            })
    _write_csv(
        config.output_dir / "redirects.csv", redirect_rows,
        ["source_url", "hop", "url", "status_code", "location", "observed_at"],
    )
    dead = [
        row for row in candidates
        if row["current_status"] in {"DEAD", "HISTORICAL_DEAD", "TAKEN_DOWN", "BLOCKED"}
    ]
    _write_csv(
        config.output_dir / "dead_links.csv", dead,
        [
            "candidate_url", "current_http_status", "current_status", "last_checked",
            "detection_provider", "detection_record_url", "verification_method",
            "verification_url", "host_object_id", "current_evidence_path",
        ],
    )
    _write_discovery_report(config, database, findings)
    _write_analyst_summary(config, database, findings)
    _write_overview(
        config,
        database,
        findings,
        candidates,
        artifact_references,
        supporting_references,
    )
    query_records = database.iter_queries()
    (config.output_dir / "queries.txt").write_text(
        "\n".join(
            f"{item['provider']}\t{item['status']}\t{item['query_text']}"
            for item in query_records
        ) + ("\n" if query_records else ""),
        encoding="utf-8",
    )


def _display_url(finding: Finding) -> str:
    return finding.final_url or finding.normalized_url or finding.candidate_url or finding.source_url


def _write_overview(
    config: AppConfig,
    database: CaseDatabase,
    findings: list[Finding],
    candidates: list[dict[str, Any]],
    artifact_references: list[dict[str, Any]],
    supporting_references: list[dict[str, Any]],
) -> None:
    """Write the short operator dashboard used immediately after a scan."""
    statuses = Counter(item["current_status"] for item in candidates)
    references = [
        item for item in candidates
        if item["current_status"] in {
            "CURRENT_REFERENCE_ONLY", "LISTING_LIVE", "DOWNLOAD_ROUTE_LIVE"
        }
    ]
    taken_down = [item for item in candidates if item["current_status"] == "TAKEN_DOWN"]
    dead = [
        item for item in candidates
        if item["current_status"] in {"DEAD", "HISTORICAL_DEAD"}
    ]
    unresolved = [
        item for item in candidates
        if item["current_status"] in {"UNVERIFIED", "UNKNOWN", "BLOCKED"}
    ]
    query_records = database.iter_queries()
    query_statuses = Counter(item["status"] for item in query_records)
    provider_requests = database.stats().get("provider_requests", {})
    providers_queried = sorted({item["provider"] for item in query_records})
    candidate_domains = sorted({
        (urlsplit(item["candidate_url"]).hostname or "").casefold()
        for item in candidates
        if urlsplit(item["candidate_url"]).hostname
    })
    keyword_sources = [
        *config.case.filenames,
        *config.case.distinctive_phrases,
        *config.case.aliases,
        *config.case.translated_descriptors,
    ]
    keyword_fragments = keyword_variants_for_values(
        keyword_sources,
        config.safety.archive_extensions,
    )
    counts = {
        "raw_observations": len(findings),
        "unique_candidates": len(candidates),
        "live_metadata_only": statuses["LIVE_METADATA_ONLY"],
        "live_restricted": statuses["LIVE_RESTRICTED"],
        "current_reference_pages": len(references),
        "taken_down": len(taken_down),
        "dead_or_historical": len(dead),
        "unresolved_or_blocked": len(unresolved),
        "artifact_references": len(artifact_references),
        "supporting_references": len(supporting_references),
        "domains": len(candidate_domains),
        "provider_requests": sum(int(value) for value in provider_requests.values()),
    }
    payload = {
        "generated_at_utc": utc_now(),
        "case": config.case.name,
        "bottom_line": _overview_bottom_line(counts),
        "counts": counts,
        "status_counts": dict(sorted(statuses.items())),
        "providers": {
            "queried": providers_queried,
            "requests": provider_requests,
            "query_statuses": dict(sorted(query_statuses.items())),
        },
        "search_inputs": {
            "filenames": config.case.filenames,
            "item_ids": config.case.item_ids,
            "unverified_search_hashes": config.case.search_hashes,
            "phrases": config.case.distinctive_phrases,
            "aliases": config.case.aliases,
            "actor_aliases": config.case.actor_aliases,
            "derived_keyword_fragments": keyword_fragments,
        },
        "candidate_domains": candidate_domains,
        "top_candidates": _overview_sort(candidates)[:15],
    }
    (config.output_dir / "overview.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    lines = [
        f"# Scan overview: {config.case.name}", "",
        f"Generated: `{payload['generated_at_utc']}`", "",
        "## Bottom line", "",
        payload["bottom_line"], "",
        "## What the scan caught", "",
        f"- Confirmed live through file metadata: **{counts['live_metadata_only']}**",
        f"- Confirmed by host metadata but access-restricted: **{counts['live_restricted']}**",
        f"- Current listings/reference/download pages, not proof of a live file: **{counts['current_reference_pages']}**",
        f"- Taken down: **{counts['taken_down']}**",
        f"- Dead or historical: **{counts['dead_or_historical']}**",
        f"- Unresolved or blocked: **{counts['unresolved_or_blocked']}**",
        f"- Unique target candidates: **{counts['unique_candidates']}**",
        f"- Raw observations retained: **{counts['raw_observations']}**", "",
        "## Strongest detection points", "",
    ]
    strongest = _overview_sort(candidates)[:15]
    if strongest:
        lines.extend(_overview_candidate_line(item) for item in strongest)
    else:
        lines.append("No case-correlated target candidate was recorded.")
    lines.extend([
        "", "## Search coverage", "",
        f"- Providers queried: {', '.join(f'`{value}`' for value in providers_queried) or 'None'}",
        f"- Actual provider requests: **{counts['provider_requests']}**",
        f"- Query states: {', '.join(f'`{key}` {value}' for key, value in sorted(query_statuses.items())) or 'None'}",
        f"- Candidate domains: {', '.join(f'`{value}`' for value in candidate_domains) or 'None'}",
        f"- Supporting analysis/news references: **{counts['supporting_references']}**",
        f"- Labelled artifact references: **{counts['artifact_references']}**", "",
        "## Search fingerprints used", "",
        f"- Filenames: {', '.join(f'`{value}`' for value in config.case.filenames) or 'Not supplied'}",
        f"- Object IDs: {', '.join(f'`{value}`' for value in config.case.item_ids) or 'Not supplied'}",
        f"- Phrases and aliases: {', '.join(f'`{value}`' for value in [*config.case.distinctive_phrases, *config.case.aliases]) or 'Not supplied'}",
        f"- Derived multi-word fragments: {', '.join(f'`{value}`' for value in keyword_fragments) or 'None'}", "",
        "Derived fragments are bounded multi-word queries. Single-word filename fragments are not searched.", "",
        "## Open these next", "",
        "- `candidate_urls.csv` — one row per unique candidate and its current state.",
        "- `detection_points.csv` — provider, exact query, record URL, verification method, and timestamps.",
        "- `reports/analyst_summary.md` — concise evidentiary summary.",
        "- `reports/discovery_report.md` — complete methodology, queries, relationships, and limitations.",
        "- `overview.json` — machine-readable copy of this dashboard.", "",
    ])
    overview_text = "\n".join(lines)
    (config.output_dir / "overview.md").write_text(overview_text, encoding="utf-8")
    (config.output_dir / "reports" / "overview.md").write_text(overview_text, encoding="utf-8")


def _overview_bottom_line(counts: dict[str, int]) -> str:
    live_count = counts["live_metadata_only"] + counts["live_restricted"]
    if live_count:
        return (
            f"The scan found **{live_count}** currently host-confirmed file object(s). "
            "Review the detection and verification points before any takedown action."
        )
    if counts["current_reference_pages"]:
        return (
            "No live file object was confirmed. The scan found "
            f"**{counts['current_reference_pages']}** current listing/reference page(s), which are leads only."
        )
    if counts["taken_down"] or counts["dead_or_historical"]:
        return (
            "No live file object was confirmed. The available target-correlated locations are "
            "taken down, dead, or historical."
        )
    if counts["unresolved_or_blocked"]:
        return (
            "No live file object was confirmed. "
            f"**{counts['unresolved_or_blocked']}** candidate(s) remain unresolved or blocked."
        )
    return "No case-correlated target candidate was found in this run."


def _overview_sort(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    priority = {
        "LIVE_METADATA_ONLY": 0,
        "LIVE_RESTRICTED": 1,
        "TAKEN_DOWN": 2,
        "LISTING_LIVE": 3,
        "DOWNLOAD_ROUTE_LIVE": 4,
        "CURRENT_REFERENCE_ONLY": 5,
        "UNVERIFIED": 6,
        "BLOCKED": 7,
        "UNKNOWN": 8,
        "HISTORICAL_DEAD": 9,
        "DEAD": 10,
    }
    return sorted(
        candidates,
        key=lambda item: (
            priority.get(item["current_status"], 99),
            -int(item["maximum_score"]),
            item["candidate_url"],
        ),
    )


def _overview_candidate_line(item: dict[str, Any]) -> str:
    filename = item.get("verified_filename") or item.get("filename")
    name = f" — `{filename}`" if filename else ""
    provider = item.get("detection_provider") or "unknown provider"
    query = f"; query `{item['detection_query']}`" if item.get("detection_query") else ""
    checked = f"; checked `{item['last_checked']}`" if item.get("last_checked") else ""
    return (
        f"- `{item['current_status']}`{name} — <{item['candidate_url']}>; "
        f"score {item['maximum_score']}; detected by `{provider}`{query}{checked}."
    )


def _candidate_key(finding: Finding) -> str:
    return finding.normalized_url or finding.candidate_url or finding.final_url or finding.original_url


def _artifact_maps(config: AppConfig) -> tuple[dict[str, str], dict[str, str]]:
    report_types = {
        normalize_url(artifact.report_url): artifact.artifact_type
        for artifact in config.case.artifacts
        if artifact.report_url
    }
    hash_types = {
        item.get("value", "").casefold(): artifact.artifact_type
        for artifact in config.case.artifacts
        for item in artifact.hashes
        if item.get("value")
    }
    return report_types, hash_types


def _finding_artifact_type(
    finding: Finding,
    report_types: dict[str, str],
    hash_types: dict[str, str],
) -> str:
    for value in (
        finding.normalized_url,
        finding.final_url,
        finding.candidate_url,
        finding.original_url,
    ):
        normalized = normalize_url(value) if value else ""
        if normalized in report_types:
            return report_types[normalized]

    strong_target_reasons = {
        "exact_item_id",
        "exact_filename",
        "filename_similarity_above_threshold",
        "known_hash_match",
    }
    if any(item.get("reason") in strong_target_reasons for item in finding.score_reasons):
        return ""
    query = finding.query.casefold()
    for digest, artifact_type in hash_types.items():
        if digest and digest in query:
            return f"{artifact_type}:derived_reference"
    return ""


def _finding_supporting_reference_type(finding: Finding) -> str:
    prefix = "supporting_reference:"
    return finding.relation[len(prefix):] if finding.relation.startswith(prefix) else ""


def _candidate_summaries(
    findings: list[Finding],
    likely_threshold: int,
    artifact_report_types: dict[str, str] | None = None,
    artifact_hash_types: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    report_types = artifact_report_types or {}
    hash_types = artifact_hash_types or {}
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        if (
            _finding_artifact_type(finding, report_types, hash_types)
            or _finding_supporting_reference_type(finding)
        ):
            continue
        key = _candidate_key(finding)
        if key:
            grouped.setdefault(key, []).append(finding)

    output: list[dict[str, Any]] = []
    for url, observations in grouped.items():
        maximum_score = max((item.score for item in observations), default=0)
        if maximum_score < likely_threshold:
            continue
        direct = [
            item for item in observations
            if item.discovery_method != "search_result" and (item.last_checked or item.status_code is not None)
        ]
        current = max(direct, key=lambda item: item.last_checked or item.timestamp_utc) if direct else None
        indexed = [item for item in observations if item.discovery_method == "search_result"]
        detection = min(indexed or observations, key=lambda item: item.timestamp_utc or item.first_seen)
        point = detection.detection_point or _legacy_detection_point(detection)
        verification = current.verification_point if current else {}
        host_metadata = verification.get("metadata", {})
        current_status = _current_candidate_status(current, bool(indexed))
        filename = next(
            (item.filename for item in ([current] if current else []) + observations if item and item.filename),
            "",
        )
        output.append({
            "candidate_url": url,
            "current_status": current_status,
            "current_http_status": current.status_code if current else "",
            "filename": filename,
            "maximum_score": maximum_score,
            "observation_count": len(observations),
            "first_detected_at": point.get("detected_at") or detection.first_seen or detection.timestamp_utc,
            "detection_provider": point.get("provider") or detection.source,
            "detection_query": point.get("query") or detection.query,
            "detection_record_url": point.get("record_url") or detection.source_url,
            "detection_record_id": point.get("record_id", ""),
            "provider_observed_at": point.get("provider_observed_at", ""),
            "last_checked": current.last_checked if current else "",
            "verification_method": verification.get("method", ""),
            "verification_url": verification.get("endpoint", ""),
            "host_object_id": verification.get("object_id", ""),
            "verified_at": verification.get("verified_at", current.last_checked if current else ""),
            "verified_filename": host_metadata.get("name", current.filename if current else ""),
            "verified_size_bytes": host_metadata.get(
                "size", current.normalized_size_bytes if current else ""
            ),
            "verified_sha256": host_metadata.get("hash_sha256", ""),
            "availability": host_metadata.get("availability", ""),
            "current_evidence_path": current.evidence_path if current else "",
            "sources": sorted({item.source for item in observations if item.source}),
            "referrer_url": current.referrer_url if current else detection.referrer_url,
        })
    return sorted(output, key=lambda item: (-int(item["maximum_score"]), item["candidate_url"]))


def _artifact_reference_summaries(
    findings: list[Finding],
    report_types: dict[str, str],
    hash_types: dict[str, str],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[Finding]] = {
        (url, artifact_type): [] for url, artifact_type in report_types.items()
    }
    for finding in findings:
        artifact_type = _finding_artifact_type(finding, report_types, hash_types)
        if not artifact_type:
            continue
        key = normalize_url(_candidate_key(finding))
        if key:
            grouped.setdefault((key, artifact_type), []).append(finding)

    output: list[dict[str, Any]] = []
    for (url, artifact_type), observations in grouped.items():
        direct = [
            item for item in observations
            if item.discovery_method != "search_result" and (item.last_checked or item.status_code is not None)
        ]
        current = max(direct, key=lambda item: item.last_checked or item.timestamp_utc) if direct else None
        indexed = any(item.discovery_method == "search_result" for item in observations)
        detection = min(observations, key=lambda item: item.timestamp_utc or item.first_seen) if observations else None
        output.append({
            "reference_url": url,
            "artifact_type": artifact_type,
            "current_status": _current_candidate_status(current, indexed) if observations else "NOT_OBSERVED",
            "current_http_status": current.status_code if current else "",
            "sources": sorted({item.source for item in observations if item.source}),
            "detection_query": detection.query if detection else "operator-supplied artifact report",
            "last_checked": current.last_checked if current else "",
            "observation_count": len(observations),
        })
    return sorted(output, key=lambda item: (item["artifact_type"], item["reference_url"]))


def _supporting_reference_summaries(findings: list[Finding]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        reference_type = _finding_supporting_reference_type(finding)
        key = normalize_url(_candidate_key(finding))
        if reference_type and key:
            grouped.setdefault((key, reference_type), []).append(finding)

    output: list[dict[str, Any]] = []
    for (url, reference_type), observations in grouped.items():
        direct = [
            item for item in observations
            if item.discovery_method != "search_result" and (item.last_checked or item.status_code is not None)
        ]
        current = max(direct, key=lambda item: item.last_checked or item.timestamp_utc) if direct else None
        indexed = any(item.discovery_method == "search_result" for item in observations)
        detection = min(observations, key=lambda item: item.timestamp_utc or item.first_seen)
        output.append({
            "reference_url": url,
            "reference_type": reference_type,
            "current_status": _current_candidate_status(current, indexed),
            "current_http_status": current.status_code if current else "",
            "sources": sorted({item.source for item in observations if item.source}),
            "detection_query": detection.query,
            "last_checked": current.last_checked if current else "",
            "observation_count": len(observations),
        })
    return sorted(output, key=lambda item: (item["reference_type"], item["reference_url"]))


def _legacy_detection_point(finding: Finding) -> dict[str, str]:
    point = {
        "provider": finding.source,
        "query": finding.query,
        "detected_at": finding.first_seen or finding.timestamp_utc,
        "provider_observed_at": "",
        "record_url": finding.source_url,
        "record_id": "",
    }
    if finding.source == "urlscan":
        match = re.search(r"urlscan result ([0-9a-f-]{20,})", finding.context_excerpt, re.IGNORECASE)
        if match:
            point["record_id"] = match.group(1)
            point["record_url"] = f"https://urlscan.io/result/{match.group(1)}/"
    return point


def _current_candidate_status(current: Finding | None, has_index_reference: bool) -> str:
    if current is None:
        return "UNVERIFIED"
    if current.classification == "TAKEN_DOWN" or current.status_code == 451:
        return "TAKEN_DOWN"
    if current.classification == "DEAD" or current.status_code in {404, 410}:
        return "HISTORICAL_DEAD" if has_index_reference else "DEAD"
    if current.classification == "BLOCKED" or current.status_code in {401, 403, 429, 999}:
        return "BLOCKED"
    if current.classification == "LIVE_RESTRICTED":
        return "LIVE_RESTRICTED"
    if current.classification == "CONFIRMED_METADATA_ONLY":
        return "LIVE_METADATA_ONLY"
    if current.classification == "LISTING_LIVE":
        return "LISTING_LIVE"
    if current.classification == "DOWNLOAD_ROUTE_LIVE":
        return "DOWNLOAD_ROUTE_LIVE"
    if current.status_code is not None and 200 <= current.status_code < 400:
        return "CURRENT_REFERENCE_ONLY"
    return "UNKNOWN"


def _candidate_line(item: dict[str, Any]) -> str:
    detection = f"detected by `{item['detection_provider']}`"
    if item["first_detected_at"]:
        detection += f" at `{item['first_detected_at']}`"
    query = f"; query `{item['detection_query']}`" if item["detection_query"] else ""
    record = f"; record <{item['detection_record_url']}>" if item["detection_record_url"] else ""
    record_id = f" (`{item['detection_record_id']}`)" if item["detection_record_id"] else ""
    checked = f"; checked `{item['last_checked']}`" if item["last_checked"] else ""
    status = f"; HTTP {item['current_http_status']}" if item["current_http_status"] != "" else ""
    verification = (
        f"; verified via `{item['verification_method']}`"
        if item["verification_method"]
        else ""
    )
    object_id = f"; object `{item['host_object_id']}`" if item["host_object_id"] else ""
    return (
        f"- <{item['candidate_url']}> — `{item['current_status']}`{status}; "
        f"score {item['maximum_score']}; {detection}{query}{record}{record_id}"
        f"{verification}{object_id}{checked}."
    )


def _artifact_line(item: dict[str, Any]) -> str:
    status = item["current_status"]
    http_status = f"; HTTP {item['current_http_status']}" if item["current_http_status"] != "" else ""
    checked = f"; checked `{item['last_checked']}`" if item["last_checked"] else ""
    return (
        f"- <{item['reference_url']}> — `{item['artifact_type']}`; "
        f"status `{status}`{http_status}{checked}."
    )


def _supporting_reference_line(item: dict[str, Any]) -> str:
    status = item["current_status"]
    http_status = f"; HTTP {item['current_http_status']}" if item["current_http_status"] != "" else ""
    checked = f"; checked `{item['last_checked']}`" if item["last_checked"] else ""
    return (
        f"- <{item['reference_url']}> — `{item['reference_type']}`; "
        f"status `{status}`{http_status}{checked}."
    )


def _write_discovery_report(config: AppConfig, database: CaseDatabase, findings: list[Finding]) -> None:
    case = config.case
    artifact_report_types, artifact_hash_types = _artifact_maps(config)
    candidates = _candidate_summaries(
        findings,
        config.scoring.likely_threshold,
        artifact_report_types,
        artifact_hash_types,
    )
    artifact_references = _artifact_reference_summaries(
        findings,
        artifact_report_types,
        artifact_hash_types,
    )
    supporting_references = _supporting_reference_summaries(findings)
    classifications = Counter(item["current_status"] for item in candidates)
    providers = sorted({finding.source for finding in findings if finding.source})
    confirmed = [
        item for item in candidates
        if item["current_status"] in {"LIVE_METADATA_ONLY", "LIVE_RESTRICTED"}
    ]
    current_references = [
        item for item in candidates
        if item["current_status"] in {"CURRENT_REFERENCE_ONLY", "LISTING_LIVE", "DOWNLOAD_ROUTE_LIVE"}
    ]
    unresolved = [item for item in candidates if item["current_status"] in {"UNVERIFIED", "UNKNOWN", "BLOCKED"}]
    dead = [item for item in candidates if item["current_status"] in {"DEAD", "HISTORICAL_DEAD"}]
    taken_down = [item for item in candidates if item["current_status"] == "TAKEN_DOWN"]
    hashes = {(item.get("algorithm", ""), item.get("value", "")) for finding in findings for item in finding.hashes}
    hashes.update(
        (item.get("algorithm", ""), item.get("value", ""))
        for artifact in case.artifacts
        for item in artifact.hashes
    )
    query_records = database.iter_queries()
    lines = [
        f"# Discovery report: {case.name}", "",
        f"Generated: `{utc_now()}`", "",
        "## 1. Target definition", "",
        f"- Item IDs: {', '.join(f'`{value}`' for value in case.item_ids) or 'Not supplied'}",
        f"- Reported filenames: {', '.join(f'`{value}`' for value in case.filenames) or 'Not supplied'}",
        f"- Unverified search hashes: {', '.join(f'`{value}`' for value in case.search_hashes) or 'Not supplied'}",
        f"- Reported sizes: {', '.join(f'`{value}`' for value in case.reported_sizes) or 'Not supplied'}",
        f"- Actor aliases: {', '.join(f'`{value}`' for value in case.actor_aliases) or 'Not supplied'}",
        f"- Incident terms: {', '.join(f'`{value}`' for value in case.incident_terms) or 'Not supplied'}",
        f"- Public channel previews: {', '.join(f'<{value}>' for value in case.public_channels) or 'Not supplied'}",
        *(f"- Seed listing: <{seed.url}> (`{seed.adapter}` adapter)" for seed in case.seeds), "",
        *(
            f"- Labelled `{artifact.artifact_type}` reference: <{artifact.report_url}> "
            f"(subject <{artifact.subject_url}>)"
            for artifact in case.artifacts
        ), "",
        "The target definition consists of operator-supplied search fingerprints and optional seed pages. It is not, by itself, proof that an archive is currently available. Unverified search hashes are discovery pivots only and are not treated as archive hashes.", "",
        "## 2. Methodology", "",
        "Independent search providers were queried with exact identifiers, filename mutations, descriptive fragments, and discovered hash pivots. Relevant public HTML/text pages were retrieved within configured bounds. Recognized file hosts were checked through public metadata APIs; other archive-like URLs used headers-only requests or bodyless range fallbacks.", "",
        "## 3. Search providers used", "",
        *(f"- `{provider}`" for provider in providers),
        "", "## 4. Provider query records", "",
        *(
            f"- `{item['provider']}` `{item['status']}` — `{item['query_text']}`"
            for item in query_records
        ),
        "", "## 5. Confirmed public references and metadata-only archive candidates", "",
    ]
    if confirmed:
        lines.extend(_candidate_line(item) for item in confirmed)
    else:
        lines.append("No file met the strict current live-metadata criteria in this run.")
    lines.extend(["", "## 6. Current reference pages", ""])
    if current_references:
        lines.extend(_candidate_line(item) for item in current_references)
    else:
        lines.append("No current HTML/reference page was directly observed.")
    lines.extend(["", "## 7. Supporting artifact references", ""])
    if artifact_references:
        lines.extend(_artifact_line(item) for item in artifact_references)
    else:
        lines.append("No labelled sandbox or analysis artifact reference was recorded.")
    lines.extend(["", "## 8. Provider-discovered supporting references", ""])
    if supporting_references:
        lines.extend(_supporting_reference_line(item) for item in supporting_references)
    else:
        lines.append("No provider-discovered supporting reference was recorded.")
    lines.extend(["", "## 9. Duplicate and mirror relationships", ""])
    relationships = database.iter_relationships()
    if relationships:
        lines.extend(
            f"- `{item['relation']}`: {item['left_url']} → {item['right_url']}"
            for item in relationships
        )
    else:
        lines.append("No duplicate or redirect relationship was recorded.")
    lines.extend(["", "## 10. Domains involved", ""])
    domains = database.iter_domains()
    lines.extend(
        f"- `{item['hostname']}` — {item['status']}; last checked {item['last_checked']}"
        for item in domains
    ) if domains else lines.append("No domain metadata was collected.")
    lines.extend(["", "## 11. Hashes found", ""])
    lines.extend(
        f"- `{algorithm.upper()}` `{value}` (see `hashes.csv` for provenance)"
        for algorithm, value in sorted(hashes)
    ) if hashes else lines.append("No cryptographic hash was extracted from a relevant page or host API.")
    lines.extend(["", "## 12. Dead, historical, and taken-down references", ""])
    lines.extend(_candidate_line(item) for item in dead) if dead else lines.append("No dead or historical reference was recorded.")
    lines.extend(_candidate_line(item) for item in taken_down)
    timeline = sorted((finding.timestamp_utc, _display_url(finding), finding.discovery_method) for finding in findings)
    lines.extend(["", "## 13. Timeline", ""])
    lines.extend(f"- `{timestamp}` — `{method}` — {url}" for timestamp, url, method in timeline[:500]) if timeline else lines.append("No observations recorded.")
    lines.extend([
        "", "## 14. Unresolved candidates", "",
        f"Unresolved unique candidates: **{len(unresolved)}**. Review `candidate_urls.csv`, `detection_points.csv`, and preserved evidence paths for handoff.", "",
        *(_candidate_line(item) for item in unresolved), "",
        "## 15. Limitations", "",
        "Search coverage depends on public indexing, provider availability, API credentials, rate limits, robots directives, and configured crawl bounds. Third-party statements remain attributed claims. A metadata-only confirmation establishes only the observed HTTP response metadata at the recorded time; it does not validate archive contents or ownership.", "",
        "## Unique candidate status totals", "",
        *(f"- `{name}`: {count}" for name, count in sorted(classifications.items())), "",
        f"Raw observations preserved: **{len(findings)}**.", "",
    ])
    (config.output_dir / "reports" / "discovery_report.md").write_text("\n".join(lines), encoding="utf-8")


def _write_analyst_summary(config: AppConfig, database: CaseDatabase, findings: list[Finding]) -> None:
    artifact_report_types, artifact_hash_types = _artifact_maps(config)
    candidates = _candidate_summaries(
        findings,
        config.scoring.likely_threshold,
        artifact_report_types,
        artifact_hash_types,
    )
    artifact_references = _artifact_reference_summaries(
        findings,
        artifact_report_types,
        artifact_hash_types,
    )
    supporting_references = _supporting_reference_summaries(findings)
    counts = Counter(item["current_status"] for item in candidates)
    provider_requests = database.stats().get("provider_requests", {})
    provider_request_total = sum(provider_requests.values())
    highest = candidates[:10]
    lines = [
        f"# Analyst summary: {config.case.name}", "",
        f"Generated: `{utc_now()}`", "",
        "## Bottom line", "",
        (
            f"The run preserved **{len(findings)} observations** across "
            f"**{len({item.domain for item in findings if item.domain})} domains**. "
            f"Provider search requests: **{provider_request_total}**; "
            f"Unique candidates: **{len(candidates)}**; "
            f"supporting artifact references: **{len(artifact_references)}**; "
            f"provider-discovered supporting references: **{len(supporting_references)}**; "
            f"live metadata-only files: **{counts['LIVE_METADATA_ONLY']}**; "
            f"live but restricted files: **{counts['LIVE_RESTRICTED']}**; "
            f"taken down: **{counts['TAKEN_DOWN']}**; "
            f"current reference pages: **{counts['CURRENT_REFERENCE_ONLY']}**; "
            f"live listing pages: **{counts['LISTING_LIVE']}**; "
            f"responsive download routes with unverified payloads: **{counts['DOWNLOAD_ROUTE_LIVE']}**; "
            f"historical/dead: **{counts['HISTORICAL_DEAD'] + counts['DEAD']}**; "
            f"unverified/unknown/blocked: **{counts['UNVERIFIED'] + counts['UNKNOWN'] + counts['BLOCKED']}**."
        ), "",
        "## Highest-scoring unique candidates and detection points", "",
    ]
    lines.extend(_candidate_line(item) for item in highest) if highest else lines.append("No candidates recorded.")
    lines.extend(["", "## Supporting artifact references", ""])
    if artifact_references:
        lines.extend(_artifact_line(item) for item in artifact_references)
    else:
        lines.append("No labelled sandbox or analysis artifact reference was recorded.")
    lines.extend(["", "## Provider-discovered supporting references", ""])
    if supporting_references:
        lines.extend(_supporting_reference_line(item) for item in supporting_references[:20])
    else:
        lines.append("No provider-discovered supporting reference was recorded.")
    lines.extend([
        "", "## Evidentiary cautions", "",
        "- Search-result snippets and third-party page claims are references, not independent confirmation.",
        "- Only `LIVE_METADATA_ONLY` means a current response established file-like metadata without reading the archive body.",
        "- `LIVE_RESTRICTED` means host-native metadata confirms the object but access is restricted.",
        "- `TAKEN_DOWN` means the host reports legal/abuse removal or returned HTTP 451.",
        "- `CURRENT_REFERENCE_ONLY` means a current HTML/reference page exists; it does not prove the archive payload is live.",
        "- `LISTING_LIVE` means a host information/listing page responds; it does not prove the archive payload is live.",
        "- `DOWNLOAD_ROUTE_LIVE` means a download-labelled HTML route responds, but no file metadata was established.",
        "- `HISTORICAL_DEAD` means an index detected the candidate but the latest direct check returned `404` or `410`.",
        "- Review timestamps, redirect chains, headers, and preserved page hashes before a takedown submission.", "",
    ])
    (config.output_dir / "reports" / "analyst_summary.md").write_text("\n".join(lines), encoding="utf-8")


def write_case_readme(config: AppConfig) -> None:
    item_ids = ", ".join(f"`{value}`" for value in config.case.item_ids) or "Not supplied"
    filenames = ", ".join(f"`{value}`" for value in config.case.filenames) or "Not supplied"
    search_hashes = ", ".join(f"`{value}`" for value in config.case.search_hashes) or "Not supplied"
    seeds = "\n".join(f"- <{seed.url}> (`{seed.adapter}` adapter)" for seed in config.case.seeds) or "- Not supplied"
    text = f"""# Case {config.case.name}

This directory contains resumable state and evidence exports for public-reference discovery relating to:

- Item IDs: {item_ids}
- Filenames: {filenames}
- Unverified search hashes: {search_hashes}
- Seed listings:
{seeds}

`state.sqlite3` is the authoritative resumable state. CSV/JSONL and Markdown files are regenerated with the `report` command. HTML/text evidence is content-addressed by SHA-256. Metadata JSON records explicitly include `body_bytes_read: 0` for archive probes.

Facts directly observed by HTTP, third-party statements, and analyst inferences are distinguished in the finding fields and reports. Use the timestamps and preserved response metadata when preparing a service-provider or search-index takedown request.
"""
    (config.output_dir / "README.md").write_text(text, encoding="utf-8")
