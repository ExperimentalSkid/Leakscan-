"""Deterministic evidence exports and analyst-facing Markdown reports."""

from __future__ import annotations

import csv
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .config import AppConfig, generate_queries
from .database import CaseDatabase
from .models import Finding
from .utils.time import utc_now

CSV_FIELDS = [
    "timestamp_utc", "source", "query", "discovery_method", "source_url", "candidate_url",
    "final_url", "referrer_url", "domain", "status_code", "filename", "reported_size",
    "normalized_size_bytes", "content_type", "content_disposition", "response_headers", "hashes", "dates", "accounts",
    "redirect_chain", "page_title", "canonical_url", "context_excerpt", "depth", "score", "score_reasons", "classification",
    "first_seen", "last_checked", "notes", "original_url", "normalized_url",
    "evidence_sha256", "evidence_path", "relation",
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
        "tool_version": "1.0.0",
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
    if isinstance(value, (list, dict)):
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

    candidates = [
        row for row in dictionaries
        if row["score"] >= config.scoring.likely_threshold
        or row["classification"] == "CONFIRMED_METADATA_ONLY"
    ]
    _write_csv(
        config.output_dir / "candidate_urls.csv", candidates,
        ["candidate_url", "final_url", "domain", "status_code", "filename", "reported_size",
         "normalized_size_bytes", "content_type", "content_disposition", "score", "score_reasons",
         "classification", "last_checked", "source", "referrer_url", "evidence_path"],
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
    hash_rows = []
    seen_hash_rows: set[tuple[str, str, str]] = set()
    for finding in findings:
        for item in finding.hashes:
            key = (item.get("algorithm", ""), item.get("value", ""), finding.final_url or finding.source_url)
            if key in seen_hash_rows:
                continue
            seen_hash_rows.add(key)
            hash_rows.append({
                "algorithm": key[0], "hash": key[1], "source_url": key[2],
                "confidence": "contextual" if finding.score >= config.scoring.likely_threshold else "unresolved",
                "observed_at": finding.timestamp_utc,
            })
    _write_csv(config.output_dir / "hashes.csv", hash_rows, ["algorithm", "hash", "source_url", "confidence", "observed_at"])

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
    dead = [row for row in dictionaries if row["classification"] in {"DEAD", "BLOCKED"}]
    _write_csv(
        config.output_dir / "dead_links.csv", dead,
        ["candidate_url", "final_url", "status_code", "classification", "last_checked", "source", "notes"],
    )
    _write_discovery_report(config, database, findings)
    _write_analyst_summary(config, database, findings)
    (config.output_dir / "queries.txt").write_text(
        "\n".join(generate_queries(config, database.pivot_map())) + "\n", encoding="utf-8"
    )


def _display_url(finding: Finding) -> str:
    return finding.final_url or finding.normalized_url or finding.candidate_url or finding.source_url


def _write_discovery_report(config: AppConfig, database: CaseDatabase, findings: list[Finding]) -> None:
    case = config.case
    classifications = Counter(finding.classification for finding in findings)
    providers = sorted({finding.source for finding in findings if finding.source})
    confirmed = _unique_findings(findings, "CONFIRMED_METADATA_ONLY")
    likely = _unique_findings(findings, "LIKELY")
    dead = [finding for finding in findings if finding.classification in {"DEAD", "BLOCKED"}]
    hashes = {(item.get("algorithm", ""), item.get("value", "")) for finding in findings for item in finding.hashes}
    lines = [
        f"# Discovery report: {case.name}", "",
        f"Generated: `{utc_now()}`", "",
        "## 1. Target definition", "",
        f"- Item IDs: {', '.join(f'`{value}`' for value in case.item_ids) or 'Not supplied'}",
        f"- Reported filenames: {', '.join(f'`{value}`' for value in case.filenames) or 'Not supplied'}",
        f"- Reported sizes: {', '.join(f'`{value}`' for value in case.reported_sizes) or 'Not supplied'}",
        *(f"- Seed listing: <{seed.url}> (`{seed.adapter}` adapter)" for seed in case.seeds), "",
        "The target definition is operator-supplied seed information. It is not, by itself, proof that an archive is currently available.", "",
        "## 2. Methodology", "",
        "Independent search providers were queried with exact identifiers, filename mutations, descriptive fragments, and discovered hash pivots. Relevant public HTML/text pages were retrieved within configured bounds. Archive-like URLs were checked with headers-only requests; fallback range requests were opened without consuming the body.", "",
        "## 3. Search providers used", "",
        *(f"- `{provider}`" for provider in providers),
        "", "## 4. Exact queries", "",
        *(f"- `{query}`" for query in generate_queries(config, database.pivot_map())),
        "", "## 5. Confirmed public references and metadata-only archive candidates", "",
    ]
    if confirmed:
        lines.extend(
            f"- Direct observation: [{item.filename or _display_url(item)}]({_display_url(item)}) — HTTP {item.status_code}; score {item.score}; archive response body not read."
            for item in confirmed
        )
    else:
        lines.append("No candidate met the strict `CONFIRMED_METADATA_ONLY` criteria in this run.")
    lines.extend(["", "## 6. Candidate hosting URLs", ""])
    if likely:
        lines.extend(
            f"- {_display_url(item)} — `{item.classification}`, score {item.score}, source `{item.source}`."
            for item in likely
        )
    else:
        lines.append("No unresolved candidate exceeded the configured likely threshold.")
    lines.extend(["", "## 7. Duplicate and mirror relationships", ""])
    relationships = database.iter_relationships()
    if relationships:
        lines.extend(
            f"- `{item['relation']}`: {item['left_url']} → {item['right_url']}"
            for item in relationships
        )
    else:
        lines.append("No duplicate or redirect relationship was recorded.")
    lines.extend(["", "## 8. Domains involved", ""])
    domains = database.iter_domains()
    lines.extend(
        f"- `{item['hostname']}` — {item['status']}; last checked {item['last_checked']}"
        for item in domains
    ) if domains else lines.append("No domain metadata was collected.")
    lines.extend(["", "## 9. Hashes found", ""])
    lines.extend(f"- `{algorithm.upper()}` `{value}` (contextual observation)" for algorithm, value in sorted(hashes)) if hashes else lines.append("No cryptographic hash was extracted from a relevant page.")
    lines.extend(["", "## 10. Dead and historical references", ""])
    lines.extend(f"- {_display_url(item)} — `{item.classification}` / HTTP {item.status_code}." for item in dead) if dead else lines.append("No dead or blocked references were recorded.")
    timeline = sorted((finding.timestamp_utc, _display_url(finding), finding.discovery_method) for finding in findings)
    lines.extend(["", "## 11. Timeline", ""])
    lines.extend(f"- `{timestamp}` — `{method}` — {url}" for timestamp, url, method in timeline[:500]) if timeline else lines.append("No observations recorded.")
    lines.extend([
        "", "## 12. Unresolved candidates", "",
        f"Unresolved likely candidates: **{len(likely)}**. Review `candidate_urls.csv` and the preserved evidence paths for handoff.", "",
        "## 13. Limitations", "",
        "Search coverage depends on public indexing, provider availability, API credentials, rate limits, robots directives, and configured crawl bounds. Third-party statements remain attributed claims. A metadata-only confirmation establishes only the observed HTTP response metadata at the recorded time; it does not validate archive contents or ownership.", "",
        "## Classification totals", "",
        *(f"- `{name}`: {count}" for name, count in sorted(classifications.items())), "",
    ])
    (config.output_dir / "reports" / "discovery_report.md").write_text("\n".join(lines), encoding="utf-8")


def _unique_findings(findings: list[Finding], classification: str) -> list[Finding]:
    output: dict[str, Finding] = {}
    for finding in findings:
        if finding.classification != classification:
            continue
        output.setdefault(_display_url(finding), finding)
    return list(output.values())


def _write_analyst_summary(config: AppConfig, database: CaseDatabase, findings: list[Finding]) -> None:
    counts = Counter(finding.classification for finding in findings)
    highest = sorted(findings, key=lambda item: item.score, reverse=True)[:10]
    lines = [
        f"# Analyst summary: {config.case.name}", "",
        f"Generated: `{utc_now()}`", "",
        "## Bottom line", "",
        (
            f"The run preserved **{len(findings)} observations** across "
            f"**{len({item.domain for item in findings if item.domain})} domains**. "
            f"Strict metadata-only confirmations: **{counts['CONFIRMED_METADATA_ONLY']}**; "
            f"unresolved likely candidates: **{counts['LIKELY']}**; "
            f"dead/blocked: **{counts['DEAD'] + counts['BLOCKED']}**."
        ), "",
        "## Highest-scoring observations", "",
    ]
    lines.extend(
        f"- Score **{item.score}** — `{item.classification}` — {_display_url(item)}"
        for item in highest
    ) if highest else lines.append("No observations recorded.")
    lines.extend([
        "", "## Evidentiary cautions", "",
        "- Search-result snippets and third-party page claims are references, not independent confirmation.",
        "- `CONFIRMED_METADATA_ONLY` means HTTP metadata was observed without reading an archive body.",
        "- Review timestamps, redirect chains, headers, and preserved page hashes before a takedown submission.", "",
    ])
    (config.output_dir / "reports" / "analyst_summary.md").write_text("\n".join(lines), encoding="utf-8")


def write_case_readme(config: AppConfig) -> None:
    item_ids = ", ".join(f"`{value}`" for value in config.case.item_ids) or "Not supplied"
    filenames = ", ".join(f"`{value}`" for value in config.case.filenames) or "Not supplied"
    seeds = "\n".join(f"- <{seed.url}> (`{seed.adapter}` adapter)" for seed in config.case.seeds)
    text = f"""# Case {config.case.name}

This directory contains resumable state and evidence exports for public-reference discovery relating to:

- Item IDs: {item_ids}
- Filenames: {filenames}
- Seed listings:
{seeds}

`state.sqlite3` is the authoritative resumable state. CSV/JSONL and Markdown files are regenerated with the `report` command. HTML/text evidence is content-addressed by SHA-256. Metadata JSON records explicitly include `body_bytes_read: 0` for archive probes.

Facts directly observed by HTTP, third-party statements, and analyst inferences are distinguished in the finding fields and reports. Use the timestamps and preserved response metadata when preparing a service-provider or search-index takedown request.
"""
    (config.output_dir / "README.md").write_text(text, encoding="utf-8")
