"""GitHub public code-search provider."""

from __future__ import annotations

import os

import httpx

from ..models import SearchResult
from .base import ProviderUnavailable, SearchProvider


class GitHubProvider(SearchProvider):
    name = "github"
    api_key_env = "GITHUB_TOKEN"

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if os.getenv("GITHUB_TOKEN"):
            headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
        response = await client.get(
            "https://api.github.com/search/code", params={"q": query, "per_page": min(limit, 100)}, headers=headers
        )
        if response.status_code in {401, 403, 422, 429}:
            raise ProviderUnavailable(f"HTTP {response.status_code}: GitHub code search requires a suitable token/rate limit")
        response.raise_for_status()
        data = response.json()
        return [
            SearchResult(
                url=item.get("html_url", ""), title=item.get("name", ""),
                excerpt=f"Repository: {item.get('repository', {}).get('full_name', '')}",
                provider=self.name, query=query, metadata=item,
            )
            for item in data.get("items", [])[:limit] if item.get("html_url")
        ]
