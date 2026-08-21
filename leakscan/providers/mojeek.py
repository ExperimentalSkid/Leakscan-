"""Mojeek independent web-search API provider."""

from __future__ import annotations

import os

import httpx

from ..models import SearchResult
from .base import ProviderUnavailable, SearchProvider


class MojeekProvider(SearchProvider):
    name = "mojeek"
    api_key_env = "MOJEEK_API_KEY"

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        endpoint = os.getenv("MOJEEK_SEARCH_ENDPOINT", "https://api.mojeek.com/search")
        data = await self.get_json(
            client,
            endpoint,
            params={
                "api_key": os.environ["MOJEEK_API_KEY"],
                "q": query,
                "t": min(limit, 100),
                "fmt": "json",
                "safe": 0 if self.safe_search.casefold() == "off" else 1,
                "date": 1,
                "cdate": 1,
                "size": 1,
                "tlen": 127,
                "dlen": 511,
            },
        )
        response = data.get("response", {})
        if not str(response.get("status", "")).startswith("OK"):
            raise ProviderUnavailable(f"Mojeek API error: {response.get('status', 'unknown response')}")
        return [
            SearchResult(
                url=item.get("url", ""),
                title=item.get("title", ""),
                excerpt=item.get("desc", ""),
                provider=self.name,
                query=query,
                published=item.get("date", "") or item.get("cdate", ""),
                metadata=item,
            )
            for item in response.get("results", [])[:limit]
            if item.get("url")
        ]
