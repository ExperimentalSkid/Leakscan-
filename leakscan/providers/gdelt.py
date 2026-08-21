"""GDELT DOC 2.0 global news-reference discovery provider."""

from __future__ import annotations

import re

import httpx

from ..models import SearchResult
from .base import SearchProvider, is_probable_hash


class GDELTProvider(SearchProvider):
    name = "gdelt"
    query_capabilities = frozenset({"identifier", "phrase", "intent"})

    def request_key(self, query: str) -> str:
        cleaned = " ".join(query.split())
        literal = cleaned.strip('"')
        if is_probable_hash(cleaned) or re.match(r"(?i)^https?://", literal):
            return ""
        return cleaned.casefold()

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        data = await self.get_json(
            client,
            "https://api.gdeltproject.org/api/v2/doc/doc",
            params={
                "query": query,
                "mode": "artlist",
                "maxrecords": min(limit, 250),
                "format": "json",
                "sort": "HybridRel",
            },
        )
        output: list[SearchResult] = []
        for item in data.get("articles", [])[:limit]:
            url = item.get("url", "")
            if not url:
                continue
            context = "; ".join(part for part in (
                item.get("domain", ""),
                item.get("language", ""),
                item.get("sourcecountry", ""),
            ) if part)
            output.append(SearchResult(
                url=url,
                title=item.get("title", ""),
                excerpt=f"GDELT news reference: {context}" if context else "GDELT news reference",
                provider=self.name,
                query=query,
                published=item.get("seendate", ""),
                record_id=item.get("url", ""),
                reference_kind="news_report",
                metadata=item,
            ))
        return output
