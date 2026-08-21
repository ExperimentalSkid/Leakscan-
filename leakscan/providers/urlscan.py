"""urlscan.io public search API provider."""

from __future__ import annotations

import os

import httpx

from ..models import SearchResult
from .base import SearchProvider


class URLScanProvider(SearchProvider):
    name = "urlscan"

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        headers = {}
        if os.getenv("URLSCAN_API_KEY"):
            headers["api-key"] = os.environ["URLSCAN_API_KEY"]
        cleaned = query.replace('"', "").strip()
        urlscan_query = f'page.url:"{cleaned}" OR page.title:"{cleaned}"'
        data = await self.get_json(
            client, "https://urlscan.io/api/v1/search/",
            params={"q": urlscan_query, "size": min(limit, 100)}, headers=headers,
        )
        output = []
        for item in data.get("results", [])[:limit]:
            page = item.get("page", {})
            task = item.get("task", {})
            url = page.get("url") or task.get("url")
            if url:
                output.append(SearchResult(
                    url=url, title=page.get("title", ""),
                    excerpt=f"urlscan result {item.get('_id', '')}; domain {page.get('domain', '')}",
                    provider=self.name, query=query, published=task.get("time", ""), metadata=item,
                ))
        return output
