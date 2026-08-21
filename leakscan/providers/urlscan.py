"""urlscan.io public search API provider."""

from __future__ import annotations

import os

import httpx

from ..models import SearchResult
from .base import SearchProvider, is_probable_hash

URLSCAN_RESERVED = set(r'+-=><!(){}[]^"~*?:\\/')


def escape_urlscan_query(value: str) -> str:
    """Escape Elasticsearch query-string reserved characters for a quoted literal."""
    return "".join(f"\\{character}" if character in URLSCAN_RESERVED else character for character in value)


class URLScanProvider(SearchProvider):
    name = "urlscan"

    def request_key(self, query: str) -> str:
        if is_probable_hash(query):
            return ""
        return query.replace('"', "").strip().casefold()

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        headers = {}
        if os.getenv("URLSCAN_API_KEY"):
            headers["api-key"] = os.environ["URLSCAN_API_KEY"]
        cleaned = " ".join(query.replace('"', "").split())
        escaped = escape_urlscan_query(cleaned)
        urlscan_query = f'(page.url:"{escaped}" OR task.url:"{escaped}" OR page.title:"{escaped}")'
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
                record_id = str(item.get("_id", ""))
                output.append(SearchResult(
                    url=url, title=page.get("title", ""),
                    excerpt=f"urlscan result {record_id}; domain {page.get('domain', '')}",
                    provider=self.name, query=query, published=task.get("time", ""),
                    source_url=f"https://urlscan.io/result/{record_id}/" if record_id else "",
                    record_id=record_id, metadata=item,
                ))
        return output
