"""Commercial and public intelligence search APIs."""

from __future__ import annotations

import os

import httpx

from ..models import SearchBatch, SearchResult
from .base import SearchProvider, is_probable_hash


class BingProvider(SearchProvider):
    name = "bing"
    api_key_env = "BING_API_KEY"

    def available(self) -> tuple[bool, str]:
        return False, "retired by Microsoft on 2025-08-11"

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        endpoint = os.getenv("BING_SEARCH_ENDPOINT", "https://api.bing.microsoft.com/v7.0/search")
        data = await self.get_json(
            client, endpoint, params={"q": query, "count": min(limit, 50), "responseFilter": "Webpages"},
            headers={"Ocp-Apim-Subscription-Key": os.environ["BING_API_KEY"]},
        )
        return [
            SearchResult(url=item.get("url", ""), title=item.get("name", ""), excerpt=item.get("snippet", ""),
                         provider=self.name, query=query, published=item.get("dateLastCrawled", ""), metadata=item)
            for item in data.get("webPages", {}).get("value", [])[:limit] if item.get("url")
        ]


class GoogleProvider(SearchProvider):
    name = "google"

    def available(self) -> tuple[bool, str]:
        missing = [name for name in ("GOOGLE_API_KEY", "GOOGLE_CSE_ID") if not os.getenv(name)]
        return (not missing, f"requires {', '.join(missing)}" if missing else "")

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        output: list[SearchResult] = []
        pages_fetched = 0
        for page in range(self.max_result_pages_per_query):
            if not self.can_make_request():
                return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            start = 1 + page * 10
            if start > 91:
                break
            data = await self.get_json(client, "https://www.googleapis.com/customsearch/v1", params={
                "key": os.environ["GOOGLE_API_KEY"], "cx": os.environ["GOOGLE_CSE_ID"],
                "q": query, "start": start, "num": min(10, limit), "safe": self.safe_search,
            })
            pages_fetched += 1
            for item in data.get("items", []):
                output.append(SearchResult(
                    url=item.get("link", ""), title=item.get("title", ""), excerpt=item.get("snippet", ""),
                    provider=self.name, query=query, metadata=item,
                ))
            if not data.get("queries", {}).get("nextPage"):
                break
        return SearchBatch(output, pages_fetched=pages_fetched)


class GitLabProvider(SearchProvider):
    name = "gitlab"
    api_key_env = "GITLAB_TOKEN"
    query_capabilities = frozenset({"filename", "identifier", "hash", "url", "phrase"})

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        cleaned = query.replace('"', "").strip()
        page_size = min(limit, 100)
        output: list[SearchResult] = []
        pages_fetched = 0
        for page in range(1, self.max_result_pages_per_query + 1):
            if not self.can_make_request():
                return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            data = await self.get_json(
                client, "https://gitlab.com/api/v4/search",
                params={"scope": "blobs", "search": cleaned, "per_page": page_size, "page": page},
                headers={"PRIVATE-TOKEN": os.environ["GITLAB_TOKEN"]},
            )
            pages_fetched += 1
            output.extend(
                SearchResult(
                    url=item.get("url", ""), title=item.get("filename", ""),
                    excerpt=item.get("data", "")[:500], provider=self.name, query=query, metadata=item,
                )
                for item in data if item.get("url")
            )
            if len(data) < page_size:
                break
        return SearchBatch(output, pages_fetched=pages_fetched)


class VirusTotalProvider(SearchProvider):
    name = "virustotal"
    api_key_env = "VIRUSTOTAL_API_KEY"
    query_capabilities = frozenset({"hash"})

    def request_key(self, query: str) -> str:
        return is_probable_hash(query)

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        digest = is_probable_hash(query)
        if not digest:
            return []
        data = await self.get_json(
            client, f"https://www.virustotal.com/api/v3/files/{digest}",
            headers={"x-apikey": os.environ["VIRUSTOTAL_API_KEY"]},
        )
        attributes = data.get("data", {}).get("attributes", {})
        output = []
        for name in attributes.get("names", [])[:limit]:
            output.append(SearchResult(
                url=f"https://www.virustotal.com/gui/file/{digest}", title=name,
                excerpt=f"VirusTotal public intelligence for {digest}", provider=self.name,
                query=query, metadata={"hash": digest, "name": name},
            ))
        return output


class OTXProvider(SearchProvider):
    name = "otx"
    query_capabilities = frozenset({"hash"})

    def request_key(self, query: str) -> str:
        return is_probable_hash(query)

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        digest = is_probable_hash(query)
        if not digest:
            return []
        headers = {"X-OTX-API-KEY": os.environ["OTX_API_KEY"]} if os.getenv("OTX_API_KEY") else {}
        data = await self.get_json(
            client, f"https://otx.alienvault.com/api/v1/indicators/file/{digest}/general", headers=headers
        )
        return [
            SearchResult(
                url=f"https://otx.alienvault.com/indicator/file/{digest}",
                title=pulse.get("name", "OTX pulse"), excerpt=pulse.get("description", "")[:500],
                provider=self.name, query=query, published=pulse.get("created", ""), metadata=pulse,
            )
            for pulse in data.get("pulse_info", {}).get("pulses", [])[:limit]
        ]
