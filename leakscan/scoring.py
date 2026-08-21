"""Transparent, case-driven relevance scoring and candidate classification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rapidfuzz.fuzz import ratio

from .config import AppConfig, initial_fingerprints
from .parser import normalize_size
from .utils.urls import filename_from_url, looks_like_archive_url


@dataclass(slots=True)
class ScoreResult:
    score: int
    reasons: list[dict[str, Any]]


def target_size_ranges(reported_sizes: str | list[str], tolerance: float) -> list[tuple[int, int]]:
    import re

    values = [reported_sizes] if isinstance(reported_sizes, str) else reported_sizes
    ranges: list[tuple[int, int]] = []
    for reported_size in values:
        match = re.match(r"\s*(\d+(?:[.,]\d+)?)\s*([kmgt]i?b|bytes?)\s*$", reported_size, re.IGNORECASE)
        if not match:
            continue
        number, unit = match.groups()
        normalized_values = {normalize_size(number, unit)}
        if unit.lower() == "mb":
            normalized_values.add(normalize_size(number, "MiB"))
        for value in normalized_values:
            if value is not None:
                ranges.append((round(value * (1 - tolerance)), round(value * (1 + tolerance))))
    return list(dict.fromkeys(ranges))


def size_matches(size_bytes: int | None, ranges: list[tuple[int, int]]) -> bool:
    return size_bytes is not None and any(low <= size_bytes <= high for low, high in ranges)


def _merge_fingerprints(config: AppConfig, fingerprints: dict[str, set[str]] | None) -> dict[str, set[str]]:
    values = initial_fingerprints(config.case)
    for kind, entries in (fingerprints or {}).items():
        values.setdefault(kind, set()).update(entry for entry in entries if entry)
    return values


def score_candidate(
    config: AppConfig,
    url: str,
    title: str = "",
    context: str = "",
    filename: str = "",
    size_bytes: int | None = None,
    content_type: str = "",
    content_disposition: str = "",
    hashes: list[dict[str, str]] | None = None,
    fingerprints: dict[str, set[str]] | None = None,
) -> ScoreResult:
    values = _merge_fingerprints(config, fingerprints)
    combined = f"{url} {title} {context} {filename} {content_disposition}"
    lowered = combined.lower()
    reasons: list[dict[str, Any]] = []

    def add(points: int, reason: str, evidence: str = "") -> None:
        reasons.append({"points": points, "reason": reason, "evidence": evidence[:240]})

    matching_ids = [value for value in values["item_id"] if value.lower() in lowered]
    if matching_ids:
        add(100, "exact_item_id", matching_ids[0])

    matching_names = [value for value in values["filename"] if value.lower() in lowered]
    if matching_names:
        add(90, "exact_filename", matching_names[0])
    else:
        observed_name = filename or filename_from_url(url)
        if observed_name and values["filename"]:
            expected, similarity = max(
                (
                    (
                        expected,
                        max(
                            ratio(expected.lower(), observed_name.lower()),
                            ratio(Path(expected).stem.lower(), Path(observed_name).stem.lower()),
                        ),
                    )
                    for expected in values["filename"]
                ),
                key=lambda item: item[1],
            )
            if similarity >= config.scoring.filename_similarity_threshold:
                add(70, "filename_similarity_above_threshold", f"{similarity:.1f}%: {observed_name} ≈ {expected}")

    matching_phrases = [value for value in values["phrase"] if value.lower() in lowered]
    if matching_phrases:
        add(50, "distinctive_phrase", matching_phrases[0])
    matching_aliases = [value for value in values["alias"] if value.lower() in lowered]
    if matching_aliases:
        add(30, "case_alias", matching_aliases[0])
    matching_accounts = [value for value in values["account"] if value.lower() in lowered]
    if matching_accounts:
        add(25, "catalog_account", matching_accounts[0])

    if looks_like_archive_url(url, config.safety.archive_extensions) or any(
        extension.lower() in lowered for extension in config.safety.archive_extensions
    ):
        add(20, "archive_reference", filename_from_url(url) or "archive extension")

    size_values = list(values["size"])
    if size_matches(size_bytes, target_size_ranges(size_values, config.scoring.size_tolerance_fraction)):
        add(40, "approximate_size_match", str(size_bytes))

    if "attachment" in content_disposition.lower() or any(
        extension.lower() in content_disposition.lower() for extension in config.safety.archive_extensions
    ):
        add(30, "archive_like_content_disposition", content_disposition)

    observed_hashes = {item.get("value", "").lower() for item in hashes or []}
    known_hashes = {value.lower() for value in values["hash"]}
    matching_hashes = observed_hashes & known_hashes
    if matching_hashes:
        add(100, "known_hash_match", min(matching_hashes))

    exclusions = [value for value in values["exclusion"] if value.lower() in lowered]
    if exclusions:
        add(-50, "case_exclusion_term", exclusions[0])

    return ScoreResult(score=sum(item["points"] for item in reasons), reasons=reasons)


def classify(
    score: int,
    config: AppConfig,
    status_code: int | None = None,
    blocked: bool = False,
    metadata_archive_confirmed: bool = False,
) -> str:
    if status_code == 451:
        return "TAKEN_DOWN"
    if blocked or status_code in {401, 403, 429, 999}:
        return "BLOCKED"
    if status_code in {404, 410}:
        return "DEAD"
    if status_code is not None and status_code >= 500:
        return "UNKNOWN"
    if metadata_archive_confirmed and status_code is not None and 200 <= status_code < 400:
        return "CONFIRMED_METADATA_ONLY"
    if score >= config.scoring.likely_threshold:
        return "LIKELY"
    if score > 0:
        return "REFERENCE_ONLY"
    return "UNKNOWN"
