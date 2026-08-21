"""Common Crawl URL-index discovery provider."""

from __future__ import annotations

import json

import httpx

from ..models import SearchResult
from .base import ProviderUnavailable, SearchProvider, archive_index_pattern


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

    def _pattern(self, query: str) -> str:
        return archive_index_pattern(query, self.archive_extensions)

    def request_key(self, query: str) -> str:
        return self._pattern(query).casefold()

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
                    provider=self.name, query=query, published=item.get("timestamp", ""),
                    source_url=index_url, record_id=item.get("digest", ""), metadata=item,
                ))
            if len(results) >= limit:
                break
        return results
