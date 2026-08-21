"""Provider interface and response helpers."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Any

import httpx

from ..models import SearchResult


class ProviderUnavailable(RuntimeError):
    pass


class SearchProvider(ABC):
    name = "base"
    api_key_env = ""
    safe_search = "off"

    def available(self) -> tuple[bool, str]:
        if self.api_key_env and not os.getenv(self.api_key_env):
            return False, f"requires {self.api_key_env}"
        return True, ""

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
        if response.status_code in {401, 403, 429}:
            raise ProviderUnavailable(f"HTTP {response.status_code}: provider denied or rate-limited request")
        response.raise_for_status()
        return response.json()


def is_probable_hash(query: str) -> str:
    value = query.strip().strip('"').lower()
    if len(value) in {32, 40, 64, 128} and all(character in "0123456789abcdef" for character in value):
        return value
    return ""
