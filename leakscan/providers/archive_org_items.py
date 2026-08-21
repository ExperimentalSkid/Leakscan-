"""Internet Archive uploaded-item metadata search provider."""

from __future__ import annotations

from typing import Any

import httpx

from ..models import SearchBatch, SearchResult
from .base import SearchProvider


def _text(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(str(item) for item in value)
    return str(value or "")


class ArchiveOrgItemsProvider(SearchProvider):
    name = "archive_org_items"
    query_capabilities = frozenset({"filename", "identifier", "phrase", "intent"})

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        page_size = min(limit, 50)
        output: list[SearchResult] = []
        pages_fetched = 0
        for page in range(1, self.max_result_pages_per_query + 1):
            if not self.can_make_request():
                return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            data = await self.get_json(
                client,
                "https://archive.org/advancedsearch.php",
                params={
                    "q": query,
                    "fl[]": [
                        "identifier", "title", "description", "date", "publicdate",
                        "addeddate", "mediatype", "downloads",
                    ],
                    "rows": page_size,
                    "page": page,
                    "output": "json",
                },
            )
            pages_fetched += 1
            response = data.get("response", {})
            documents = response.get("docs", [])
            for item in documents:
                identifier = _text(item.get("identifier"))
                if not identifier:
                    continue
                details_url = f"https://archive.org/details/{identifier}"
                description = _text(item.get("description"))
                context = "; ".join(part for part in (
                    description,
                    f"media type {_text(item.get('mediatype'))}" if item.get("mediatype") else "",
                    f"downloads {_text(item.get('downloads'))}" if item.get("downloads") is not None else "",
                ) if part)
                output.append(SearchResult(
                    url=details_url,
                    title=_text(item.get("title")) or identifier,
                    excerpt=context[:1000],
                    provider=self.name,
                    query=query,
                    published=_text(item.get("publicdate") or item.get("date") or item.get("addeddate")),
                    source_url=details_url,
                    record_id=identifier,
                    metadata=item,
                ))
            total = int(response.get("numFound", 0) or 0)
            if len(documents) < page_size or page * page_size >= total:
                break
        return SearchBatch(output, pages_fetched=pages_fetched)
