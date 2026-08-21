"""Brave Search API provider."""

from __future__ import annotations

import os

import httpx

from ..models import SearchResult
from .base import SearchProvider


class BraveProvider(SearchProvider):
    name = "brave"
    api_key_env = "BRAVE_API_KEY"

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        data = await self.get_json(
            client,
            "https://api.search.brave.com/res/v1/web/search",
            params={"q": query, "count": min(limit, 20), "safesearch": self.safe_search, "extra_snippets": "true"},
            headers={"Accept": "application/json", "X-Subscription-Token": os.environ["BRAVE_API_KEY"]},
        )
        return [
            SearchResult(
                url=item.get("url", ""), title=item.get("title", ""),
                excerpt=" ".join([item.get("description", ""), *item.get("extra_snippets", [])]),
                provider=self.name, query=query,
            )
            for item in data.get("web", {}).get("results", [])[:limit]
            if item.get("url")
        ]
