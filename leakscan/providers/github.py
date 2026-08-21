"""GitHub public code-search provider."""

from __future__ import annotations

import os

import httpx

from ..models import SearchBatch, SearchResult
from .base import ProviderUnavailable, SearchProvider


class GitHubProvider(SearchProvider):
    name = "github"
    api_key_env = "GITHUB_TOKEN"
    query_capabilities = frozenset({"filename", "identifier", "hash", "url", "phrase"})

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if os.getenv("GITHUB_TOKEN"):
            headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
        page_size = min(limit, 100)
        output: list[SearchResult] = []
        pages_fetched = 0
        for page in range(1, self.max_result_pages_per_query + 1):
            if not self.can_make_request():
                return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            response = await client.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": page_size, "page": page},
                headers=headers,
            )
            if response.status_code in {401, 403, 422, 429}:
                raise ProviderUnavailable(
                    f"HTTP {response.status_code}: GitHub code search requires a suitable token/rate limit",
                    status_code=response.status_code,
                )
            response.raise_for_status()
            data = response.json()
            pages_fetched += 1
            items = data.get("items", [])
            output.extend(
                SearchResult(
                    url=item.get("html_url", ""), title=item.get("name", ""),
                    excerpt=f"Repository: {item.get('repository', {}).get('full_name', '')}",
                    provider=self.name, query=query, metadata=item,
                )
                for item in items if item.get("html_url")
            )
            if len(items) < page_size or len(output) >= min(int(data.get("total_count", 0) or 0), 1000):
                break
        return SearchBatch(output, pages_fetched=pages_fetched)
