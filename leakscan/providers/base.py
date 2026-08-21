"""Provider interface and response helpers."""

from __future__ import annotations

import asyncio
import os
import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from time import monotonic
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

import httpx

from ..models import SearchBatch, SearchResult

if TYPE_CHECKING:
    from ..config import AppConfig

DEFAULT_ARCHIVE_EXTENSIONS = (
    ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".7z.001", ".zip.001",
    ".part1.rar", ".part01.rar", ".7z", ".zip", ".zipx", ".rar", ".tar",
    ".gz", ".bz2", ".xz", ".tgz", ".tbz2", ".txz", ".zst", ".tzst",
    ".cab", ".iso", ".001",
)


class ProviderUnavailable(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds


class ProviderRequestBudgetExhausted(RuntimeError):
    """Raised before transmission when the persistent provider budget is exhausted."""


class SearchProvider(ABC):
    name = "base"
    api_key_env = ""
    safe_search = "off"
    archive_extensions: list[str] | tuple[str, ...] = DEFAULT_ARCHIVE_EXTENSIONS
    minimum_request_interval_seconds = 0.0
    _rate_limit_cooldown_seconds: float | None = None
    _last_request_started_at: float | None = None
    max_result_pages_per_query = 1
    _requests_remaining: Callable[[], int | None] | None = None

    # Query families are deliberately generic. Providers can opt into only the
    # shapes their native index handles well instead of receiving every global
    # mutation generated for a case.
    query_capabilities: frozenset[str] | None = None

    def configure(self, config: AppConfig) -> None:
        """Bind case/runtime context for providers that need case-scoped sources."""
        self.config = config

    def available(self) -> tuple[bool, str]:
        if self.api_key_env and not os.getenv(self.api_key_env):
            return False, f"requires {self.api_key_env}"
        return True, ""

    def request_key(self, query: str) -> str:
        """Return the provider-level request identity used for deduplication."""
        return " ".join(query.casefold().split())

    def accepts_query(self, query: str) -> bool:
        return self.query_capabilities is None or classify_query(query, self.archive_extensions) in self.query_capabilities

    def can_make_request(self) -> bool:
        if self._rate_limit_cooldown_seconds is not None:
            return False
        remaining = self._requests_remaining() if self._requests_remaining is not None else None
        return remaining is None or remaining > 0

    def bind_request_budget(self, remaining: Callable[[], int | None] | None) -> None:
        self._requests_remaining = remaining

    def consume_rate_limit_cooldown(self) -> float | None:
        seconds = self._rate_limit_cooldown_seconds
        self._rate_limit_cooldown_seconds = None
        return seconds

    async def wait_for_request_slot(self) -> None:
        """Apply a provider-specific minimum interval before an actual HTTP request."""
        if self.minimum_request_interval_seconds > 0 and self._last_request_started_at is not None:
            elapsed = monotonic() - self._last_request_started_at
            delay = self.minimum_request_interval_seconds - elapsed
            if delay > 0:
                await asyncio.sleep(delay)
        self._last_request_started_at = monotonic()

    @abstractmethod
    async def search(
        self, client: httpx.AsyncClient, query: str, limit: int
    ) -> list[SearchResult] | SearchBatch:
        raise NotImplementedError

    async def get_json(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        response = await client.get(url, params=params, headers=headers)
        return self._response_json(response)

    async def post_json(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        response = await client.post(url, data=data, headers=headers)
        return self._response_json(response)

    def _response_json(self, response: httpx.Response) -> Any:
        reset_after = max(
            (
                value for value in (
                    _retry_after_seconds(response.headers.get("x-rate-limit-reset-after", "")),
                    _retry_after_seconds(response.headers.get("x-limited-for", "")),
                )
                if value is not None
            ),
            default=None,
        )
        if response.is_success and response.headers.get("x-rate-limit-remaining", "").strip() == "0":
            self._rate_limit_cooldown_seconds = reset_after if reset_after is not None else 0.0
        if response.status_code in {401, 403, 429}:
            retry_after = _retry_after_seconds(response.headers.get("retry-after", ""))
            raise ProviderUnavailable(
                f"HTTP {response.status_code}: provider denied or rate-limited request",
                status_code=response.status_code,
                retry_after_seconds=max(
                    (value for value in (retry_after, reset_after) if value is not None),
                    default=None,
                ),
            )
        if response.status_code >= 500:
            raise ProviderUnavailable(
                f"HTTP {response.status_code}: provider service error",
                status_code=response.status_code,
            )
        response.raise_for_status()
        return response.json()


def _retry_after_seconds(value: str) -> float | None:
    if not value:
        return None
    lowered = value.strip().casefold()
    try:
        if lowered.endswith("ms"):
            return max(0.0, float(lowered[:-2]) / 1000)
        if lowered.endswith("s"):
            return max(0.0, float(lowered[:-1]))
        return max(0.0, float(lowered))
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        return max(0.0, (retry_at - datetime.now(UTC)).total_seconds())


def is_probable_hash(query: str) -> str:
    value = query.strip().strip('"').lower()
    if len(value) in {32, 40, 64, 128} and all(character in "0123456789abcdef" for character in value):
        return value
    return ""


def classify_query(query: str, extensions: list[str] | tuple[str, ...]) -> str:
    """Classify a generated query so native providers receive useful query shapes."""
    cleaned = " ".join(query.strip().split())
    literal = unquote(cleaned.strip('"')).strip()
    if is_probable_hash(cleaned):
        return "hash"
    if re.search(r"(?i)https?://", literal):
        return "url"
    if cleaned.casefold().startswith("site:"):
        return "site"
    quoted = re.findall(r'"([^\"]+)"', cleaned)
    if len(quoted) >= 2 and any(re.fullmatch(r"(?i)\d+(?:\.\d+)?\s*(?:bytes?|[kmgt]i?b)", item) for item in quoted):
        return "size"
    lowered = literal.casefold()
    if any(lowered.endswith(extension.casefold()) for extension in extensions):
        return "filename"
    if re.search(r"(?i)(?:\.part\d+\.rar|\.7z\.\d{3}|\.zip\.\d{3}|\.\d{3})$", literal):
        return "filename"
    if re.search(r'"\s+[A-Za-z][A-Za-z0-9_-]*$', cleaned):
        return "intent"
    if " " not in literal and len(literal) >= 8 and re.fullmatch(r"[A-Za-z0-9_.:-]+", literal):
        return "identifier"
    return "phrase"


def query_anchor(query: str) -> str:
    """Return the strongest literal portion of a generated query for a native API."""
    quoted = re.findall(r'"([^\"]+)"', query)
    if quoted:
        return unquote(quoted[0]).strip()
    cleaned = re.sub(r"(?i)^site:\S+\s+", "", query).strip()
    return unquote(cleaned).strip('"').strip()


def metadata_name_matches(name: str, query: str) -> bool:
    """Conservative filename/path match used before a catalog record becomes a candidate."""
    anchor = query_anchor(query)
    if not anchor or not name:
        return False
    normalized_anchor = re.sub(r"[^a-z0-9]+", " ", anchor.casefold()).strip()
    normalized_name = re.sub(r"[^a-z0-9]+", " ", unquote(name).casefold()).strip()
    if not normalized_anchor or not normalized_name:
        return False
    return normalized_anchor in normalized_name


def strip_archive_suffix(value: str, extensions: list[str] | tuple[str, ...]) -> str:
    lowered = value.casefold()
    suffix = next(
        (
            extension
            for extension in sorted(extensions, key=len, reverse=True)
            if lowered.endswith(extension.casefold())
        ),
        "",
    )
    if suffix:
        return value[:-len(suffix)]
    return re.sub(r"(?i)(?:\.part\d+\.rar|\.(?:7z|zip)\.\d{3}|\.\d{3})$", "", value)


def archive_index_pattern(query: str, extensions: list[str] | tuple[str, ...]) -> str:
    """Build a target-specific URL wildcard without falling back to a broad word."""
    cleaned = query.replace('"', "").strip()
    url_match = re.search(r"https?://([^\s]+)", cleaned)
    if url_match:
        return url_match.group(1).rstrip("/") + "*"

    quoted_match = re.search(r'"([^\"]+)"', query)
    fingerprint = unquote(quoted_match.group(1) if quoted_match else query).strip()
    fingerprint = strip_archive_suffix(fingerprint, extensions).strip()

    if quoted_match and any(character.isspace() for character in fingerprint):
        slug = re.sub(r"\s+", "-", fingerprint)
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "", slug).strip(".-_")
        if len(slug) >= 12 and "-" in slug:
            return f"*{slug}*"

    tokens = [
        strip_archive_suffix(token, extensions)
        for token in re.findall(r"[A-Za-z0-9_.-]{6,}", fingerprint)
    ]
    strong_tokens = [
        token
        for token in tokens
        if token and (
            is_probable_hash(token)
            or (len(token) >= 12 and any(separator in token for separator in "_-."))
            or (
                len(token) >= 12
                and any(character.isalpha() for character in token)
                and any(character.isdigit() for character in token)
            )
        )
    ]
    return f"*{max(strong_tokens, key=len)}*" if strong_tokens else ""
