"""Internet Archive CDX discovery provider."""

from __future__ import annotations

import re

import httpx

from ..models import SearchResult
from .base import SearchProvider


class ArchiveOrgProvider(SearchProvider):
    name = "archive_org"

    @staticmethod
    def _pattern(query: str) -> str:
        cleaned = query.replace('"', "").strip()
        match = re.search(r"https?://([^\s]+)", cleaned)
        if match:
            return match.group(1).rstrip("/") + "*"
        tokens = re.findall(r"[A-Za-z0-9_.-]{6,}", cleaned)
        return "*" + max(tokens, key=len) + "*" if tokens else ""

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        pattern = self._pattern(query)
        if not pattern:
            return []
        data = await self.get_json(
            client,
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": pattern, "output": "json", "fl": "timestamp,original,statuscode,mimetype,digest",
                "filter": "statuscode:200", "collapse": "urlkey", "limit": limit,
            },
        )
        if not isinstance(data, list) or len(data) < 2:
            return []
        headers = data[0]
        output = []
        for row in data[1:]:
            item = dict(zip(headers, row, strict=False))
            original = item.get("original", "")
            timestamp = item.get("timestamp", "")
            if original:
                output.append(SearchResult(
                    url=original, title="Internet Archive historical URL",
                    excerpt=f"Archived {timestamp}; MIME {item.get('mimetype', '')}",
                    provider=self.name, query=query, published=timestamp, metadata=item,
                ))
        return output
