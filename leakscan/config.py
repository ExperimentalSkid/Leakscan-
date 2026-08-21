"""Generic settings, case loading, and fingerprint-driven query generation."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import yaml

from . import __version__


@dataclass(slots=True)
class SeedConfig:
    url: str
    source: str = "catalog"
    adapter: str = "auto"


@dataclass(slots=True)
class ArtifactReferenceConfig:
    source: str
    artifact_type: str
    subject_url: str = ""
    report_url: str = ""
    observed_at: str = ""
    hashes: list[dict[str, str]] = field(default_factory=list)
    notes: str = ""


@dataclass(slots=True)
class CaseConfig:
    name: str
    seeds: list[SeedConfig]
    item_ids: list[str] = field(default_factory=list)
    filenames: list[str] = field(default_factory=list)
    reported_sizes: list[str] = field(default_factory=list)
    distinctive_phrases: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    translated_descriptors: list[str] = field(default_factory=list)
    exclusion_terms: list[str] = field(default_factory=list)
    artifacts: list[ArtifactReferenceConfig] = field(default_factory=list)

    @property
    def primary_seed_url(self) -> str:
        return self.seeds[0].url if self.seeds else ""


@dataclass(slots=True)
class CrawlConfig:
    max_depth: int = 3
    max_pages_per_domain: int = 100
    max_pages: int = 5000
    concurrency: int = 10
    timeout_seconds: float = 15.0
    retry_count: int = 2
    retry_backoff_seconds: float = 1.0
    per_host_delay_seconds: float = 1.0
    max_html_bytes: int = 2 * 1024 * 1024
    max_redirects: int = 10
    respect_robots_txt: bool = True
    user_agent: str = "Leakscan/{version}"


@dataclass(slots=True)
class SearchConfig:
    providers: list[str] = field(default_factory=list)
    results_per_query: int = 20
    max_queries_per_provider: int = 15
    max_pivot_rounds: int = 20
    max_pivots_per_round: int = 50
    provider_failure_threshold: int = 2
    provider_rate_limit_cooldown_seconds: int = 300
    safe_search: str = "off"
    intent_terms: list[str] = field(default_factory=lambda: ["leak", "breach", "dump", "mirror", "download"])


@dataclass(slots=True)
class ScoringConfig:
    likely_threshold: int = 50
    high_confidence_threshold: int = 90
    filename_similarity_threshold: int = 95
    size_tolerance_fraction: float = 0.08


@dataclass(slots=True)
class SafetyConfig:
    archive_extensions: list[str] = field(default_factory=lambda: [
        ".7z", ".zip", ".rar", ".tar", ".gz", ".bz2", ".xz",
        ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".zst", ".zipx",
        ".7z.001", ".part01.rar", ".001",
    ])
    allowed_schemes: list[str] = field(default_factory=lambda: ["http", "https"])
    reject_private_networks: bool = True


@dataclass(slots=True)
class AppConfig:
    case: CaseConfig
    crawl: CrawlConfig
    search: SearchConfig
    scoring: ScoringConfig
    safety: SafetyConfig
    output_dir: Path
    settings_path: Path
    case_path: Path

    def as_manifest_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        result = asdict(self)
        result["output_dir"] = str(self.output_dir)
        result["settings_path"] = str(self.settings_path)
        result["case_path"] = str(self.case_path)
        return result


def load_config(
    settings_path: str | Path,
    case_path: str | Path,
    output_dir: str | Path | None = None,
) -> AppConfig:
    resolved_settings = Path(settings_path).expanduser().resolve()
    resolved_case = Path(case_path).expanduser().resolve()
    with resolved_settings.open("r", encoding="utf-8") as handle:
        settings = yaml.safe_load(handle) or {}
    with resolved_case.open("r", encoding="utf-8") as handle:
        raw_case = dict((yaml.safe_load(handle) or {}).get("case", {}))
    seeds = [SeedConfig(**item) for item in raw_case.pop("seeds", [])]
    artifacts = [ArtifactReferenceConfig(**item) for item in raw_case.pop("artifacts", [])]
    case = CaseConfig(seeds=seeds, artifacts=artifacts, **raw_case)
    if not case.seeds:
        raise ValueError("case file must define at least one public seed URL")
    if not (case.item_ids or case.filenames or case.distinctive_phrases):
        raise ValueError("case file must define at least one identifying fingerprint")
    default_output = resolved_case.parent.parent / f"case_{_safe_case_name(case.name)}"
    crawl = CrawlConfig(**settings.get("crawl", {}))
    crawl.user_agent = _render_user_agent(crawl.user_agent)
    return AppConfig(
        case=case,
        crawl=crawl,
        search=SearchConfig(**settings.get("search", {})),
        scoring=ScoringConfig(**settings.get("scoring", {})),
        safety=SafetyConfig(**settings.get("safety", {})),
        output_dir=Path(output_dir).expanduser().resolve() if output_dir else default_output.resolve(),
        settings_path=resolved_settings,
        case_path=resolved_case,
    )


def _render_user_agent(template: str) -> str:
    user_agent = template.replace("{version}", __version__)
    contact = re.sub(r"[\x00-\x1f\x7f]+", "", os.getenv("LEAKSCAN_CONTACT", "")).strip()[:200]
    if not contact:
        return user_agent
    if user_agent.endswith(")"):
        return f"{user_agent[:-1]}; contact={contact})"
    return f"{user_agent} contact={contact}"


def _safe_case_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "unnamed"


def load_dotenv(path: str | Path) -> None:
    """Load a simple .env file without overriding existing environment values."""
    env_path = Path(path)
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"").strip("'"))


def initial_fingerprints(case: CaseConfig) -> dict[str, set[str]]:
    return {
        "item_id": {value for value in case.item_ids if value},
        "filename": {value for value in case.filenames if value},
        "size": {value for value in case.reported_sizes if value},
        "phrase": {value for value in case.distinctive_phrases if value},
        "alias": {value for value in [*case.aliases, *case.translated_descriptors] if value},
        "exclusion": {value for value in case.exclusion_terms if value},
        "hash": set(),
        "artifact_hash": {
            item.get("value", "")
            for artifact in case.artifacts
            for item in artifact.hashes
            if item.get("value")
        },
        "account": set(),
        "domain": {(urlsplit(seed.url).hostname or "").lower() for seed in case.seeds},
    }


def filename_variants(filename: str, archive_extensions: list[str]) -> list[str]:
    lowered = filename.casefold()
    matched_suffix = next(
        (
            extension
            for extension in sorted(archive_extensions, key=len, reverse=True)
            if lowered.endswith(extension.casefold())
        ),
        "",
    )
    stem = filename[:-len(matched_suffix)] if matched_suffix else Path(filename).stem
    variants = [
        filename,
        stem,
        quote(filename),
        filename.replace(" ", "_"),
        filename.replace(" ", "-"),
        re.sub(r"[^\w\s.-]", "", filename),
        filename.lower(),
        filename.upper(),
    ]
    for extension in archive_extensions:
        variants.append(stem + extension)
    return list(dict.fromkeys(value for value in variants if value))


def generate_queries(config: AppConfig, fingerprints: dict[str, set[str]] | None = None) -> list[str]:
    values = initial_fingerprints(config.case)
    for kind, entries in (fingerprints or {}).items():
        values.setdefault(kind, set()).update(entry for entry in entries if entry)
    queries: list[str] = []
    deferred_filename_variants: list[str] = []
    deferred_intent_queries: list[str] = []
    for filename in sorted(values["filename"]):
        variants = filename_variants(filename, config.safety.archive_extensions)
        stem = variants[1] if len(variants) > 1 else Path(filename).stem
        extension_variants = {stem + extension for extension in config.safety.archive_extensions}
        strong_variants = [
            variant
            for variant in variants
            if variant == filename or variant not in extension_variants
        ]
        for variant in strong_variants:
            queries.append(f'"{variant}"')
        deferred_filename_variants.extend(
            f'"{variant}"' for variant in variants if variant not in strong_variants
        )
        for term in config.search.intent_terms:
            deferred_intent_queries.append(f'"{stem}" {term}')
    for item_id in sorted(values["item_id"]):
        queries.append(f'"{item_id}"')
        for filename in sorted(values["filename"]):
            suffix = Path(filename).suffix.lstrip(".")
            if suffix:
                queries.append(f'"{item_id}" "{suffix}"')
    queries.extend(f'"{digest}"' for digest in sorted(values["hash"] | values["artifact_hash"]))
    queries.extend(f'"{seed.url.split("#", 1)[0]}"' for seed in config.case.seeds)
    queries.extend(
        f'"{artifact.report_url}"'
        for artifact in config.case.artifacts
        if artifact.report_url
    )
    for phrase in sorted(values["phrase"] | values["alias"]):
        queries.append(f'"{phrase}"')
        for term in config.search.intent_terms:
            deferred_intent_queries.append(f'"{phrase}" {term}')
    queries.extend(f'"{account}"' for account in sorted(values["account"]))
    for domain in sorted(values["domain"]):
        queries.extend(f"site:{domain} {item_id}" for item_id in sorted(values["item_id"]))
    for size in sorted(values["size"]):
        anchors = sorted(values["alias"] | values["phrase"])
        if anchors:
            queries.extend(f'"{anchor}" "{size}"' for anchor in anchors[:5])
        else:
            queries.append(f'"{size}"')
    queries.extend(deferred_filename_variants)
    queries.extend(deferred_intent_queries)
    return list(dict.fromkeys(queries))
