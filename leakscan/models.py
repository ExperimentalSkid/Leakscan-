"""Shared data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class SearchResult:
    url: str
    title: str = ""
    excerpt: str = ""
    provider: str = ""
    query: str = ""
    published: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CatalogRecord:
    source_url: str
    source_name: str
    adapter: str
    title: str = ""
    item_ids: list[str] = field(default_factory=list)
    filenames: list[str] = field(default_factory=list)
    sizes: list[dict[str, Any]] = field(default_factory=list)
    hashes: list[dict[str, str]] = field(default_factory=list)
    dates: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedPage:
    title: str = ""
    text: str = ""
    links: list[str] = field(default_factory=list)
    link_contexts: dict[str, str] = field(default_factory=dict)
    canonical_url: str = ""
    hashes: list[dict[str, str]] = field(default_factory=list)
    sizes: list[dict[str, Any]] = field(default_factory=list)
    dates: list[str] = field(default_factory=list)
    filenames: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FetchResult:
    original_url: str
    final_url: str = ""
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)
    body: bytes = b""
    error: str = ""
    blocked_reason: str = ""
    is_binary: bool = False
    truncated: bool = False


@dataclass(slots=True)
class Finding:
    timestamp_utc: str = ""
    source: str = ""
    query: str = ""
    discovery_method: str = ""
    source_url: str = ""
    candidate_url: str = ""
    final_url: str = ""
    referrer_url: str = ""
    domain: str = ""
    status_code: int | None = None
    filename: str = ""
    reported_size: str = ""
    normalized_size_bytes: int | None = None
    content_type: str = ""
    content_disposition: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    hashes: list[dict[str, str]] = field(default_factory=list)
    dates: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)
    page_title: str = ""
    canonical_url: str = ""
    context_excerpt: str = ""
    depth: int = 0
    score: int = 0
    score_reasons: list[dict[str, Any]] = field(default_factory=list)
    classification: str = "UNKNOWN"
    first_seen: str = ""
    last_checked: str = ""
    notes: str = ""
    original_url: str = ""
    normalized_url: str = ""
    evidence_sha256: str = ""
    evidence_path: str = ""
    relation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Finding:
        fields = cls.__dataclass_fields__
        return cls(**{key: item for key, item in value.items() if key in fields})
