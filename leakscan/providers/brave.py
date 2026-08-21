"""Brave Search API provider."""

from __future__ import annotations

import os

import httpx

from ..models import SearchBatch, SearchResult
from .base import SearchProvider


class BraveProvider(SearchProvider):
    name = "brave"
    api_key_env = "BRAVE_API_KEY"

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        page_size = min(limit, 20)
        output: list[SearchResult] = []
        pages_fetched = 0
        for page in range(self.max_result_pages_per_query):
            if not self.can_make_request():
                return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            data = await self.get_json(
                client,
                "https://api.search.brave.com/res/v1/web/search",
                params={
                    "q": query,
                    "count": page_size,
                    "offset": page,
                    "safesearch": self.safe_search,
                    "extra_snippets": "true",
                },
                headers={"Accept": "application/json", "X-Subscription-Token": os.environ["BRAVE_API_KEY"]},
            )
            pages_fetched += 1
            items = data.get("web", {}).get("results", [])
            output.extend(
                SearchResult(
                    url=item.get("url", ""), title=item.get("title", ""),
                    excerpt=" ".join([item.get("description", ""), *item.get("extra_snippets", [])]),
                    provider=self.name, query=query, metadata=item,
                )
                for item in items if item.get("url")
            )
            if len(items) < page_size or not data.get("query", {}).get("more_results_available", True):
                break
        return SearchBatch(output, pages_fetched=pages_fetched)
