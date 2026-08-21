"""Provider interface and response helpers."""

from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import unquote

import httpx

from ..models import SearchResult

DEFAULT_ARCHIVE_EXTENSIONS = (
    ".tar.gz", ".tar.bz2", ".7z.001", ".part01.rar", ".7z", ".zip", ".zipx",
    ".rar", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz2", ".zst", ".001",
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


class SearchProvider(ABC):
    name = "base"
    api_key_env = ""
    safe_search = "off"
    archive_extensions: list[str] | tuple[str, ...] = DEFAULT_ARCHIVE_EXTENSIONS
    _rate_limit_cooldown_seconds: float | None = None

    def available(self) -> tuple[bool, str]:
        if self.api_key_env and not os.getenv(self.api_key_env):
            return False, f"requires {self.api_key_env}"
        return True, ""

    def request_key(self, query: str) -> str:
        """Return the provider-level request identity used for deduplication."""
        return " ".join(query.casefold().split())

    def consume_rate_limit_cooldown(self) -> float | None:
        seconds = self._rate_limit_cooldown_seconds
        self._rate_limit_cooldown_seconds = None
        return seconds

    @abstractmethod
    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
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
        reset_after = _retry_after_seconds(response.headers.get("x-rate-limit-reset-after", ""))
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
    try:
        return max(0.0, float(value))
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
    return re.sub(r"(?i)(?:\.part\d+\.rar|\.7z\.\d{3}|\.\d{3})$", "", value)


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
