"""DuckDuckGo public HTML search provider."""

from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlsplit

import httpx
from bs4 import BeautifulSoup

from ..models import SearchResult
from .base import ProviderUnavailable, SearchProvider


class DuckDuckGoProvider(SearchProvider):
    name = "duckduckgo"

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        response = await client.get("https://html.duckduckgo.com/html/", params={"q": query})
        if response.status_code in {202, 403, 429}:
            raise ProviderUnavailable(f"HTTP {response.status_code}: interactive verification or rate limit")
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        output: list[SearchResult] = []
        for result in soup.select(".result"):
            anchor = result.select_one("a.result__a")
            if anchor is None or not anchor.get("href"):
                continue
            url = str(anchor["href"])
            query_string = parse_qs(urlsplit(url).query)
            if "uddg" in query_string:
                url = unquote(query_string["uddg"][0])
            excerpt_node = result.select_one(".result__snippet")
            output.append(SearchResult(
                url=url,
                title=anchor.get_text(" ", strip=True),
                excerpt=excerpt_node.get_text(" ", strip=True) if excerpt_node else "",
                provider=self.name,
                query=query,
            ))
            if len(output) >= limit:
                break
        return output
