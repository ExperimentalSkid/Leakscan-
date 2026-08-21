"""Operator-configured SearXNG metasearch provider."""

from __future__ import annotations

import os

import httpx
from bs4 import BeautifulSoup

from ..models import SearchBatch, SearchResult
from .base import SearchProvider


class SearXNGProvider(SearchProvider):
    name = "searxng"

    def available(self) -> tuple[bool, str]:
        if not os.getenv("SEARXNG_URL"):
            return False, "requires operator-supplied SEARXNG_URL"
        return True, ""

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        endpoint = os.environ["SEARXNG_URL"].rstrip("/")
        if not endpoint.endswith("/search"):
            endpoint += "/search"
        headers = {"Accept": "application/json"}
        if os.getenv("SEARXNG_BEARER_TOKEN"):
            headers["Authorization"] = f"Bearer {os.environ['SEARXNG_BEARER_TOKEN']}"
        safe_search = {"off": 0, "moderate": 1, "strict": 2}.get(self.safe_search.casefold(), 0)
        output: list[SearchResult] = []
        pages_fetched = 0
        for page in range(1, self.max_result_pages_per_query + 1):
            if not self.can_make_request():
                return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            data = await self.get_json(
                client,
                endpoint,
                params={"q": query, "format": "json", "safesearch": safe_search, "pageno": page},
                headers=headers,
            )
            pages_fetched += 1
            items = data.get("results", [])
            for item in items[:limit]:
                url = item.get("url", "")
                if not url:
                    continue
                output.append(SearchResult(
                    url=url,
                    title=item.get("title", ""),
                    excerpt=BeautifulSoup(item.get("content", ""), "html.parser").get_text(" ", strip=True),
                    provider=self.name,
                    query=query,
                    published=item.get("publishedDate", ""),
                    record_id=str(item.get("engine", "")),
                    metadata=item,
                ))
            if not items:
                break
        return SearchBatch(output, pages_fetched=pages_fetched)
