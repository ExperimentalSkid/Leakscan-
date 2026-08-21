"""Common Crawl URL-index discovery provider."""

from __future__ import annotations

import json
import re

import httpx

from ..models import SearchResult
from .base import ProviderUnavailable, SearchProvider


class CommonCrawlProvider(SearchProvider):
    name = "commoncrawl"
    _index_url = ""

    async def _latest_index(self, client: httpx.AsyncClient) -> str:
        if self._index_url:
            return self._index_url
        data = await self.get_json(client, "https://index.commoncrawl.org/collinfo.json")
        if not data:
            raise ProviderUnavailable("Common Crawl returned no indexes")
        self._index_url = data[0]["cdx-api"]
        return self._index_url

    @staticmethod
    def _pattern(query: str) -> str:
        cleaned = query.replace('"', "").strip()
        url_match = re.search(r"https?://([^\s]+)", cleaned)
        if url_match:
            return url_match.group(1).rstrip("/") + "*"
        tokens = re.findall(r"[A-Za-z0-9_.-]{6,}", cleaned)
        if not tokens:
            return ""
        return "*" + max(tokens, key=len) + "*"

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        pattern = self._pattern(query)
        if not pattern:
            return []
        index_url = await self._latest_index(client)
        response = await client.get(
            index_url,
            params={"url": pattern, "output": "json", "filter": "status:200", "collapse": "urlkey", "pageSize": limit},
        )
        if response.status_code == 400:
            return []
        response.raise_for_status()
        results: list[SearchResult] = []
        for line in response.text.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = item.get("url", "")
            if url:
                results.append(SearchResult(
                    url=url, title="Common Crawl indexed URL", excerpt=f"Captured {item.get('timestamp', '')}",
                    provider=self.name, query=query, published=item.get("timestamp", ""), metadata=item,
                ))
            if len(results) >= limit:
                break
        return results
