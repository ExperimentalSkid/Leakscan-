"""LeakIX public-exposure index provider."""

from __future__ import annotations

import os
from urllib.parse import urlencode

import httpx

from ..models import SearchBatch, SearchResult
from .base import SearchProvider


class LeakIXProvider(SearchProvider):
    name = "leakix"
    api_key_env = "LEAKIX_API_KEY"
    query_capabilities = frozenset({"filename", "identifier", "phrase", "url"})

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        headers = {"api-key": os.environ["LEAKIX_API_KEY"], "Accept": "application/json"}
        output: list[SearchResult] = []
        pages_fetched = 0
        for page in range(self.max_result_pages_per_query):
            if not self.can_make_request():
                return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            data = await self.get_json(
                client,
                "https://leakix.net/search",
                params={"q": query, "scope": "leak", "page": page},
                headers=headers,
            )
            pages_fetched += 1
            items = data if isinstance(data, list) else []
            search_url = f"https://leakix.net/search?{urlencode({'q': query, 'scope': 'leak', 'page': page})}"
            for item in items:
                url = self._event_url(item)
                if not url:
                    continue
                http_data = item.get("http", {}) or {}
                leak = item.get("leak", {}) or {}
                dataset = leak.get("dataset", {}) or {}
                summary = str(item.get("summary", ""))[:1000]
                dataset_details = ", ".join(
                    f"{name}={dataset[name]}" for name in ("files", "rows", "size") if dataset.get(name)
                )
                excerpt = "; ".join(value for value in (summary, dataset_details) if value)
                output.append(SearchResult(
                    url=url,
                    title=http_data.get("title", "") or f"LeakIX {item.get('event_source', 'exposure')} record",
                    excerpt=excerpt,
                    provider=self.name,
                    query=query,
                    published=item.get("time", ""),
                    source_url=search_url,
                    record_id=item.get("event_fingerprint", ""),
                    metadata={
                        "event_type": item.get("event_type"),
                        "event_source": item.get("event_source"),
                        "event_fingerprint": item.get("event_fingerprint"),
                        "host": item.get("host"),
                        "ip": item.get("ip"),
                        "port": item.get("port"),
                        "protocol": item.get("protocol"),
                        "time": item.get("time"),
                        "leak": leak,
                    },
                ))
            if len(items) < limit:
                break
        return SearchBatch(output, pages_fetched=pages_fetched)

    @staticmethod
    def _event_url(item: dict) -> str:
        protocol = str(item.get("protocol", "")).casefold()
        if protocol not in {"http", "https"}:
            return ""
        host = item.get("host") or item.get("ip")
        if not host:
            return ""
        port = str(item.get("port", ""))
        authority = str(host)
        if port and not ((protocol == "http" and port == "80") or (protocol == "https" and port == "443")):
            authority = f"{authority}:{port}"
        http_data = item.get("http", {}) or {}
        path = str(http_data.get("url") or http_data.get("root") or "/")
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{protocol}://{authority}{path}"
