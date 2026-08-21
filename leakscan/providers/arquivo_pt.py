"""Arquivo.pt full-text historical web-search provider."""

from __future__ import annotations

import httpx
from bs4 import BeautifulSoup

from ..models import SearchBatch, SearchResult
from .base import SearchProvider


class ArquivoPtProvider(SearchProvider):
    name = "arquivo_pt"
    query_capabilities = frozenset({"filename", "identifier", "phrase", "intent", "url"})

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        page_size = min(limit, 50)
        output: list[SearchResult] = []
        pages_fetched = 0
        for page in range(self.max_result_pages_per_query):
            if not self.can_make_request():
                return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            data = await self.get_json(
                client,
                "https://arquivo.pt/textsearch",
                params={"q": query, "maxItems": page_size, "offset": page * page_size},
            )
            pages_fetched += 1
            items = data.get("response_items", [])
            for item in items:
                url = item.get("originalURL", "")
                if not url:
                    continue
                output.append(SearchResult(
                    url=url,
                    title=item.get("title", ""),
                    excerpt=BeautifulSoup(item.get("snippet", ""), "html.parser").get_text(" ", strip=True),
                    provider=self.name,
                    query=query,
                    published=item.get("tstamp", ""),
                    source_url=item.get("linkToArchive", ""),
                    record_id=item.get("digest", ""),
                    metadata=item,
                ))
            if len(items) < page_size:
                break
        return SearchBatch(output, pages_fetched=pages_fetched)
